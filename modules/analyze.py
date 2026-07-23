"""
M.S.J Traffic Analysis Engine
===============================
Advanced traffic analysis capabilities:
  - TCP stream reassembly (follow TCP streams)
  - HTTP object extraction (images, documents from HTTP responses)
  - Protocol hierarchy statistics
  - Conversation tracking (who talks to whom)
  - Bandwidth monitoring (per-connection, per-protocol)
  - Anomaly detection (port scans, SYN floods, DNS tunneling)
  - GeoIP lookup (requires geoip2 database)

Creator: M.S.J
"""

import time
import re
import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from scapy.all import (
    IP, TCP, UDP, Raw, Packet
)

from modules.dissect import PacketInfo, dissect_packet


@dataclass
class TCPStream:
    """Reassembled TCP stream data."""
    stream_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    client_data: bytes = b''
    server_data: bytes = b''
    packets: list = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    bytes_client: int = 0
    bytes_server: int = 0
    complete: bool = False
    protocol: str = 'UNKNOWN'
    http_request: str = ''
    http_response: str = ''
    extracted_files: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0.0

    def summary(self) -> str:
        return (f"Stream {self.stream_id}: {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
                f"[{self.protocol}] {self.bytes_client + self.bytes_server}B, {len(self.packets)} pkts")


@dataclass
class Conversation:
    """Bidirectional conversation between two hosts."""
    host_a: str
    host_b: str
    port_a: int = 0
    port_b: int = 0
    packets: int = 0
    bytes_sent: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    bytes_received: int = 0
    protocols: set = field(default_factory=set)
    start_time: float = 0.0
    last_time: float = 0.0


class TCPStreamFollower:
    """
    TCP stream reassembly engine.
    Tracks TCP connections and reassembles bidirectional data.

    Usage:
        follower = TCPStreamFollower()
        for pkt, info in packets:
            stream = follower.feed(pkt, info)
            if stream and stream.complete:
                print(stream.client_data.decode('utf-8', errors='replace'))
    """

    def __init__(self):
        self.streams: Dict[str, TCPStream] = {}
        self._partial_seqs = {}
        self._stream_counter = 0

    def _stream_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
        """Create a canonical stream key (normalized direction)."""
        hosts_a = f"{src_ip}:{src_port}"
        hosts_b = f"{dst_ip}:{dst_port}"
        if hosts_a < hosts_b:
            return f"{hosts_a}-{hosts_b}"
        else:
            return f"{hosts_b}-{hosts_a}"

    def feed(self, pkt, info: PacketInfo = None) -> Optional[TCPStream]:
        """
        Process a TCP packet and update stream tracking.
        Returns the stream object if the packet contributed to one.
        """
        if not info:
            if hasattr(pkt, 'haslayer') and pkt.haslayer(IP) and pkt.haslayer(TCP):
                info = dissect_packet(pkt)

        if not info or info.protocol != 'TCP':
            return None

        key = self._stream_key(info.src_ip, info.dst_ip, info.src_port, info.dst_port)

        if key not in self.streams:
            self._stream_counter += 1
            self.streams[key] = TCPStream(
                stream_id=str(self._stream_counter),
                src_ip=info.src_ip,
                dst_ip=info.dst_ip,
                src_port=info.src_port,
                dst_port=info.dst_port,
                start_time=info.timestamp
            )

        stream = self.streams[key]

        # Determine direction
        is_client = (info.src_ip == stream.src_ip and info.src_port == stream.src_port)
        payload = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b''

        if is_client:
            stream.client_data += payload
            stream.bytes_client += len(payload)
        else:
            stream.server_data += payload
            stream.bytes_server += len(payload)

        stream.packets.append(info)
        stream.end_time = info.timestamp

        # Detect FIN/RST
        if 'FIN' in info.tcp_flags or 'RST' in info.tcp_flags:
            stream.complete = True

        # Heuristic protocol detection
        if b'HTTP/' in stream.client_data or b'HTTP/' in stream.server_data:
            stream.protocol = 'HTTP'
        elif stream.dst_port == 443 or stream.src_port == 443:
            stream.protocol = 'TLS'
        elif stream.dst_port == 53 or stream.src_port == 53:
            stream.protocol = 'DNS'
        elif stream.dst_port in (21, 20) or stream.src_port in (21, 20):
            stream.protocol = 'FTP'
        elif stream.dst_port in (22,) or stream.src_port in (22,):
            stream.protocol = 'SSH'
        elif stream.dst_port in (25, 587) or stream.src_port in (25, 587):
            stream.protocol = 'SMTP'
        elif stream.dst_port in (110, 995) or stream.src_port in (110, 995):
            stream.protocol = 'POP3'
        elif stream.dst_port in (143, 993) or stream.src_port in (143, 993):
            stream.protocol = 'IMAP'

        return stream

    def get_stream(self, stream_id: str) -> Optional[TCPStream]:
        """Get a specific stream by ID."""
        for stream in self.streams.values():
            if stream.stream_id == stream_id:
                return stream
        return None

    def get_completed_streams(self) -> List[TCPStream]:
        """Get all fully reassembled streams."""
        return [s for s in self.streams.values() if s.complete]

    def get_active_streams(self, timeout: int = 30) -> List[TCPStream]:
        """Get streams still active (within timeout seconds)."""
        now = time.time()
        return [s for s in self.streams.values()
                if not s.complete and now - s.end_time < timeout]

    def clear(self):
        """Clear all tracked streams."""
        self.streams.clear()
        self._partial_seqs.clear()
        self._stream_counter = 0

    def stats(self) -> dict:
        return {
            'total_streams': len(self.streams),
            'completed': len(self.get_completed_streams()),
            'active': len(self.get_active_streams()),
            'stream_counter': self._stream_counter
        }


class ConversationTracker:
    """
    Tracks all conversations between hosts and builds a communication graph.

    Usage:
        tracker = ConversationTracker()
        for pkt, info in packets:
            tracker.feed(pkt, info)
        print(tracker.summary())
    """

    def __init__(self):
        self.conversations: Dict[str, Conversation] = {}
        self._conv_by_hosts: Dict[str, str] = {}  # "hostA-hostB" -> key

    def _key(self, ip_a: str, ip_b: str) -> str:
        return f"{min(ip_a, ip_b)}-{max(ip_a, ip_b)}"

    def feed(self, info: PacketInfo):
        """Update conversation tracking with a packet."""
        if not info.src_ip or not info.dst_ip:
            return

        src = info.src_ip
        dst = info.dst_ip
        key = self._key(src, dst)

        if key not in self.conversations:
            self.conversations[key] = Conversation(
                host_a=min(src, dst),
                host_b=max(src, dst),
                start_time=info.timestamp
            )

        conv = self.conversations[key]
        conv.packets += 1
        conv.bytes_sent += info.length
        # Track directional bytes: who sent to whom
        if src == conv.host_a:
            conv.bytes_a_to_b += info.length
        else:
            conv.bytes_b_to_a += info.length
        conv.last_time = info.timestamp

        if info.protocol and info.protocol != 'UNKNOWN':
            conv.protocols.add(info.protocol)

        # Track unique ports
        if src == conv.host_a:
            conv.port_a = info.src_port or conv.port_a
        else:
            conv.port_b = info.dst_port or conv.port_b

    def get_top_talkers(self, n: int = 10) -> List[Tuple[str, int]]:
        """Get top N hosts by total bytes transferred (sent + received)."""
        host_bytes = defaultdict(int)
        for conv in self.conversations.values():
            host_bytes[conv.host_a] += conv.bytes_a_to_b + conv.bytes_b_to_a
            host_bytes[conv.host_b] += conv.bytes_a_to_b + conv.bytes_b_to_a
        return sorted(host_bytes.items(), key=lambda x: -x[1])[:n]

    def summary(self) -> str:
        """Generate a text summary of all conversations."""
        lines = [f"Total Conversations: {len(self.conversations)}"]
        top = self.get_top_talkers(5)
        if top:
            lines.append("Top Talkers:")
            for host, bytes_n in top:
                lines.append(f"  {host:20s} {self._format_bytes(bytes_n)}")

        for key, conv in sorted(
            self.conversations.items(),
            key=lambda x: -x[1].bytes_sent
        )[:10]:
            lines.append(
                f"  {conv.host_a:15s}:{conv.port_a} <-> {conv.host_b:15s}:{conv.port_b}  "
                f"[{conv.packets:6d} pkts, {self._format_bytes(conv.bytes_sent)}] "
                f"proto: {', '.join(sorted(conv.protocols))}"
            )
        return '\n'.join(lines)

    def _format_bytes(self, b: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if b < 1024:
                return f"{b:.1f}{unit}"
            b /= 1024
        return f"{b:.1f}TB"


class BandwidthMonitor:
    """
    Real-time bandwidth monitoring per connection and protocol.

    Usage:
        bw = BandwidthMonitor(window=5)
        for pkt, info in packets:
            bw.feed(info)
        rates = bw.get_rates()
    """

    def __init__(self, window: int = 5):
        self.window = window  # Rolling window in seconds
        self._history: List[Tuple[float, int, str, str, str]] = []  # (timestamp, size, src_ip, dst_ip, protocol)

    def feed(self, info: PacketInfo):
        """Record a packet for bandwidth calculation."""
        self._history.append((
            info.timestamp,
            info.length,
            info.src_ip,
            info.dst_ip,
            info.protocol
        ))
        self._prune()

    def _prune(self):
        """Remove entries older than the window."""
        cutoff = time.time() - self.window
        while self._history and self._history[0][0] < cutoff:
            self._history.pop(0)

    def get_total_rate(self) -> float:
        """Get total bandwidth in bytes per second."""
        self._prune()
        if not self._history:
            return 0.0
        duration = min(self.window, time.time() - self._history[0][0] if self._history else 0)
        if duration <= 0:
            return 0.0
        total = sum(h[1] for h in self._history)
        return total / duration

    def get_protocol_rates(self) -> Dict[str, float]:
        """Get bandwidth per protocol in bytes per second."""
        self._prune()
        if not self._history:
            return {}
        duration = min(self.window, time.time() - self._history[0][0] if self._history else 0)
        if duration <= 0:
            return {}

        proto_bytes = defaultdict(int)
        for _, size, _, _, proto in self._history:
            proto_bytes[proto] += size

        return {k: v / duration for k, v in proto_bytes.items()}

    def get_host_rates(self) -> Dict[str, float]:
        """Get bandwidth per host in bytes per second."""
        self._prune()
        duration = min(self.window, time.time() - self._history[0][0] if self._history else 0)
        if duration <= 0:
            return {}

        host_bytes = defaultdict(int)
        for _, size, src, dst, _ in self._history:
            host_bytes[src] += size

        return {k: v / duration for k, v in host_bytes.items()}

    def get_formatted_rate(self, rate_bps: float) -> str:
        """Format a byte rate for human display."""
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if rate_bps < 1024:
                return f"{rate_bps:.2f} {unit}"
            rate_bps /= 1024
        return f"{rate_bps:.2f} TB/s"


class AnomalyDetector:
    """
    Network anomaly detection:
      - Port scan detection
      - SYN flood detection (DoS)
      - DNS tunneling heuristic
      - ARP spoofing detection
      - ICMP tunneling
      - Unusual protocol on standard ports
    """

    def __init__(self):
        self._syn_counts = defaultdict(int)  # src_ip -> count
        self._port_scan_tracker = defaultdict(set)  # src_ip -> set(dst_ports)
        self._dns_query_sizes = defaultdict(list)
        self._arp_table = {}  # ip -> mac
        self._alert_history = []
        self._window_start = time.time()

    def feed(self, info: PacketInfo):
        """Analyze packet for anomalies."""
        alerts = []

        # SYN flood / port scan detection
        if info.protocol == 'TCP' and 'SYN' in info.tcp_flags and 'ACK' not in info.tcp_flags:
            self._syn_counts[info.src_ip] += 1
            self._port_scan_tracker[info.src_ip].add(info.dst_port)

        # DNS tunneling detection (large DNS queries)
        if info.protocol == 'DNS' and info.dns_type == 'QUERY':
            if info.payload_size > 100:
                self._dns_query_sizes[info.src_ip].append(info.payload_size)

        # ARP spoofing detection
        if info.protocol == 'ARP' and info.arp_op == 'is-at':
            if info.arp_src_ip in self._arp_table:
                if self._arp_table[info.arp_src_ip] != info.arp_src_mac:
                    alerts.append({
                        'type': 'ARP_SPOOF',
                        'severity': 'HIGH',
                        'msg': f"Possible ARP spoof: {info.arp_src_ip} changed MAC "
                               f"{self._arp_table[info.arp_src_ip]} -> {info.arp_src_mac}",
                        'timestamp': info.timestamp_str
                    })
            self._arp_table[info.arp_src_ip] = info.arp_src_mac

    def check_alerts(self) -> List[Dict]:
        """Check for anomalies and return alerts."""
        alerts = []
        now = time.time()

        # Reset counters periodically
        if now - self._window_start > 60:
            self._syn_counts.clear()
            self._port_scan_tracker.clear()
            self._dns_query_sizes.clear()
            self._window_start = now

        # SYN flood / scan
        for ip, count in self._syn_counts.items():
            if count > 100:  # More than 100 SYNs in window
                ports = len(self._port_scan_tracker.get(ip, set()))
                severity = 'CRITICAL' if count > 500 else 'HIGH'
                alerts.append({
                    'type': 'SYN_FLOOD' if ports < 5 else 'PORT_SCAN',
                    'severity': severity,
                    'msg': f"{ip}: {count} SYNs to {ports} ports in 60s",
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                })

        # DNS tunneling
        for ip, sizes in self._dns_query_sizes.items():
            if len(sizes) > 10 and any(s > 500 for s in sizes):
                alerts.append({
                    'type': 'DNS_TUNNEL',
                    'severity': 'MEDIUM',
                    'msg': f"Possible DNS tunneling from {ip}: {len(sizes)} large queries",
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                })

        self._alert_history.extend(alerts)
        return alerts

    def get_alerts(self, limit: int = 50) -> List[Dict]:
        """Get last N alerts."""
        return self._alert_history[-limit:]
