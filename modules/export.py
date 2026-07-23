"""
M.S.J Export Engine
====================
Export captured packets in multiple formats:
  - PCAP (standard libpcap format)
  - JSON (structured packet data)
  - CSV (flat table for spreadsheet import)
  - HEX dump (raw hex + ASCII side-by-side)
  - TXT log (human-readable log file)

Supports both real-time streaming export and batch export.

Creator: M.S.J
"""

import os
import json
import csv
import time
import threading
from datetime import datetime
from typing import List, Optional, TextIO
from pathlib import Path

from scapy.all import wrpcap, Packet

from modules.dissect import PacketInfo


class PCAPExporter:
    """Export packets to standard PCAP format."""

    def __init__(self, filename: str, append: bool = False, auto_flush: bool = True):
        self.filename = filename
        self.append = append
        self.auto_flush = auto_flush
        self._packet_buffer = []
        self._lock = threading.Lock()
        self._write_count = 0

        # Ensure directory exists
        Path(filename).parent.mkdir(parents=True, exist_ok=True)

    def write(self, pkt: Packet, info: PacketInfo = None):
        """Write a single Scapy packet to PCAP."""
        with self._lock:
            self._packet_buffer.append(pkt)

        if self.auto_flush and len(self._packet_buffer) >= 10:
            self.flush()

    def write_batch(self, packets: List[Packet]):
        """Write multiple packets at once."""
        with self._lock:
            self._packet_buffer.extend(packets)
        if self.auto_flush and len(self._packet_buffer) >= 10:
            self.flush()

    def flush(self):
        """Flush buffered packets to disk."""
        with self._lock:
            if not self._packet_buffer:
                return
            try:
                if self._write_count == 0 and not self.append:
                    wrpcap(self.filename, self._packet_buffer)
                else:
                    wrpcap(self.filename, self._packet_buffer, append=True)
                self._write_count += len(self._packet_buffer)
                self._packet_buffer = []
            except Exception as e:
                print(f"[PCAP Export Error] {e}")

    def close(self):
        """Flush remaining packets and close."""
        self.flush()

    @property
    def total_written(self) -> int:
        return self._write_count


class JSONExporter:
    """Export packet metadata as JSON (line-by-line or array)."""

    def __init__(self, filename: str, array_format: bool = False):
        self.filename = filename
        self.array_format = array_format
        self._file: Optional[TextIO] = None
        self._write_count = 0
        self._first_entry = True

        Path(filename).parent.mkdir(parents=True, exist_ok=True)

    def open(self):
        """Open the JSON output file."""
        self._file = open(self.filename, 'w', encoding='utf-8')
        if self.array_format:
            self._file.write('[\n')
            self._first_entry = True
        return self

    def write(self, pkt: Packet = None, info: PacketInfo = None):
        """Write a single packet info as JSON.
           Accepts both single-arg (info) and dual-arg (pkt, info) forms."""
        if info is None and pkt is not None and hasattr(pkt, 'protocol'):
            info = pkt  # Single-arg call: write(info)
        if info is None:
            return
        if not self._file:
            self.open()

        data = info.to_dict() if hasattr(info, 'to_dict') else info.__dict__
        # Remove non-serializable items
        data.pop('raw_packet', None)

        line = json.dumps(data, indent=2, default=str)

        if self.array_format:
            if not self._first_entry:
                self._file.write(',\n')
            self._first_entry = False
            self._file.write(line)
        else:
            self._file.write(line + '\n')

        self._write_count += 1

    def write_batch(self, infos: List[PacketInfo]):
        """Write multiple packet infos."""
        for info in infos:
            self.write(info)

    def close(self):
        """Finalize and close JSON file."""
        if self._file:
            if self.array_format:
                self._file.write('\n]')
            self._file.close()

    @property
    def total_written(self) -> int:
        return self._write_count


class CSVExporter:
    """Export packet metadata as CSV (flat format for spreadsheet analysis)."""

    def __init__(self, filename: str):
        self.filename = filename
        self._file: Optional[TextIO] = None
        self._writer = None
        self._write_count = 0
        self._fields = [
            'id', 'timestamp', 'protocol', 'length',
            'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'src_mac', 'dst_mac',
            'tcp_flags', 'http_method', 'http_uri', 'http_status',
            'dns_query', 'dns_type',
            'arp_op', 'arp_src_ip', 'arp_dst_ip',
            'icmp_type', 'icmp_code',
            'tls_sni', 'dhcp_message_type',
            'tags'
        ]

        Path(filename).parent.mkdir(parents=True, exist_ok=True)

    def open(self):
        """Open CSV file and write header."""
        self._file = open(self.filename, 'w', newline='', encoding='utf-8')
        self._writer = csv.DictWriter(self._file, fieldnames=self._fields, extrasaction='ignore')
        self._writer.writeheader()
        return self

    def write(self, pkt: Packet = None, info: PacketInfo = None):
        """Write a single packet as CSV row.
           Accepts both single-arg (info) and dual-arg (pkt, info) forms."""
        if info is None and pkt is not None and hasattr(pkt, 'protocol'):
            info = pkt  # Single-arg call: write(info)
        if info is None:
            return
        if not self._writer:
            self.open()

        row = {
            'id': info.id,
            'timestamp': info.timestamp_str,
            'protocol': info.protocol,
            'length': info.length,
            'src_ip': info.src_ip,
            'dst_ip': info.dst_ip,
            'src_port': info.src_port,
            'dst_port': info.dst_port,
            'src_mac': info.src_mac,
            'dst_mac': info.dst_mac,
            'tcp_flags': info.tcp_flags,
            'http_method': info.http_method,
            'http_uri': info.http_uri,
            'http_status': info.http_status,
            'dns_query': info.dns_query,
            'dns_type': info.dns_type,
            'arp_op': info.arp_op,
            'arp_src_ip': info.arp_src_ip,
            'arp_dst_ip': info.arp_dst_ip,
            'icmp_type': info.icmp_type,
            'icmp_code': info.icmp_code,
            'tls_sni': info.tls_sni,
            'dhcp_message_type': info.dhcp_message_type,
            'tags': ';'.join(info.tags)
        }
        self._writer.writerow(row)
        self._write_count += 1

    def write_batch(self, infos: List[PacketInfo]):
        """Write multiple packets."""
        for info in infos:
            self.write(info)

    def close(self):
        """Close CSV file."""
        if self._file:
            self._file.close()

    @property
    def total_written(self) -> int:
        return self._write_count


class HexDumpExporter:
    """Export raw packet hex dumps with ASCII representation."""

    def __init__(self, filename: str, include_ascii: bool = True, bytes_per_line: int = 16):
        self.filename = filename
        self.include_ascii = include_ascii
        self.bytes_per_line = bytes_per_line
        self._write_count = 0
        self._file = None

        Path(filename).parent.mkdir(parents=True, exist_ok=True)

    def open(self):
        """Open the hex dump file for writing."""
        if not self._file:
            self._file = open(self.filename, 'a', encoding='utf-8')

    def _format_hex_line(self, data: bytes, offset: int) -> str:
        """Format a single line of hex dump."""
        hex_part = ' '.join(f'{b:02x}' for b in data[:self.bytes_per_line])
        # Pad hex part
        hex_part = hex_part.ljust(self.bytes_per_line * 3 - 1)

        if self.include_ascii:
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:self.bytes_per_line])
            return f"{offset:08x}  {hex_part}  |{ascii_part}|"
        else:
            return f"{offset:08x}  {hex_part}"

    def write(self, pkt: Packet, info: PacketInfo = None):
        """Write a packet as hex dump."""
        raw = bytes(pkt)

        if self._file:
            # Header
            if info:
                self._file.write(f"\n--- Packet #{info.id} | {info.timestamp_str} | "
                                 f"{info.protocol} | {info.length} bytes ---\n")
                self._file.write(f"    {info.src_ip or info.src_mac}:{info.src_port or ''} -> "
                                 f"{info.dst_ip or info.dst_mac}:{info.dst_port or ''}\n")
            else:
                self._file.write(f"\n--- Packet | {len(raw)} bytes ---\n")

            # Hex dump
            for i in range(0, len(raw), self.bytes_per_line):
                chunk = raw[i:i + self.bytes_per_line]
                self._file.write(self._format_hex_line(chunk, i) + '\n')

            self._file.write('\n')
            self._file.flush()

        self._write_count += 1

    def close(self):
        """Close the hex dump file."""
        if self._file:
            self._file.close()
            self._file = None

    def write_batch(self, packets: list):
        """Write multiple packets."""
        for pkt, info in packets:
            self.write(pkt, info)

    @property
    def total_written(self) -> int:
        return self._write_count


class TXTLogExporter:
    """Export packets as human-readable log entries."""

    def __init__(self, filename: str):
        self.filename = filename
        self._write_count = 0
        self._file = None

        Path(filename).parent.mkdir(parents=True, exist_ok=True)

    def open(self):
        """Open the log file for writing."""
        if not self._file:
            self._file = open(self.filename, 'a', encoding='utf-8')

    def write(self, pkt, info: PacketInfo = None):
        """Write a packet as log entry."""
        summary = info.summary() if info else f"[Packet #{id(pkt):x}] {len(bytes(pkt))} bytes"
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {summary}\n"

        if self._file:
            self._file.write(line)
            self._file.flush()
        self._write_count += 1

    def close(self):
        """Close the log file."""
        if self._file:
            self._file.close()
            self._file = None

    def write_batch(self, packets: list):
        """Write multiple packets."""
        for pkt, info in packets:
            self.write(pkt, info)

    @property
    def total_written(self) -> int:
        return self._write_count


class MultiExporter:
    """
    Simultaneous export to multiple formats.
    Routes all packets through every configured exporter.
    """

    def __init__(self):
        self.exporters = []

    def add(self, exporter):
        """Add an exporter to the pipeline."""
        self.exporters.append(exporter)
        return self

    def open(self):
        """Open all exporters that support open()."""
        for exp in self.exporters:
            try:
                if hasattr(exp, 'open'):
                    exp.open()
            except Exception:
                pass
        return self

    def write(self, pkt, info: PacketInfo = None):
        """Write packet to all exporters."""
        for exp in self.exporters:
            try:
                if isinstance(exp, (PCAPExporter,)):
                    exp.write(pkt)
                elif isinstance(exp, (HexDumpExporter,)):
                    exp.write(pkt, info)
                elif isinstance(exp, (TXTLogExporter,)):
                    exp.write(pkt, info)
                else:
                    exp.write(info)
            except Exception as e:
                print(f"[Export Error] {type(exp).__name__}: {e}")

    def write_batch(self, packets: list):
        """Write multiple packets to all exporters."""
        for pkt, info in packets:
            self.write(pkt, info)

    def close(self):
        """Close all exporters."""
        for exp in self.exporters:
            try:
                exp.close()
            except Exception:
                pass

    def get_stats(self) -> dict:
        """Get aggregate export statistics."""
        return {
            'exporters': len(self.exporters),
            'totals': {type(e).__name__: getattr(e, 'total_written', 0) for e in self.exporters}
        }
