"""
M.S.J Packet Capture Engine
===========================
Dual-backend capture: Scapy (full dissection) + Raw Socket (low-level stealth).
Supports promiscuous mode, BPF filtering, live capture, and offline PCAP reading.

Creator: M.S.J
"""

import os
import sys
import time
import socket
import struct
import threading
import queue
from datetime import datetime
from typing import Optional, Callable

from scapy.all import (
    conf, wrpcap, rdpcap, AsyncSniffer,
    IP, TCP, UDP, ICMP, ARP, Ether, Raw, DNS,
    DHCP, BOOTP, IPv6
)

from modules.dissect import PacketInfo, dissect_packet


class CaptureEngine:
    """
    Core packet capture engine with dual backend support.

    Backends:
        'scapy'  - Full Scapy-based capture with protocol dissection
        'raw'    - Raw socket capture for stealth/low-level access

    Modes:
        'live'   - Real-time packet capture from interface
        'offline' - Read from saved PCAP file
    """

    def __init__(self, interface: str = None, backend: str = 'scapy',
                 filter_bpf: str = None, promisc: bool = True,
                 packet_queue: queue.Queue = None,
                 callback: Callable = None):
        self.interface = interface or self._default_iface()
        self.backend = backend.lower()
        self.filter_bpf = filter_bpf
        self.promisc = promisc
        self.packet_queue = packet_queue or queue.Queue()
        self.callback = callback

        self._running = False
        self._sniffer = None
        self._raw_socket = None
        self._capture_thread = None
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = None
        self.stats = {
            'total': 0,
            'tcp': 0, 'udp': 0, 'icmp': 0,
            'arp': 0, 'dns': 0, 'http': 0,
            'dhcp': 0, 'other': 0,
            'ipv4': 0, 'ipv6': 0,
            'bytes': 0
        }

        self._verify_interface()

    @staticmethod
    def _default_iface() -> str:
        """Find the best active capture interface, skipping loopback."""
        try:
            from modules.iface import InterfaceDiscovery
            disc = InterfaceDiscovery()
            best = disc.default_interface()
            if best:
                return best
            # Fallback: any interface with an IP that isn't loopback
            for i in disc.all():
                if i.name != 'lo' and (i.ipv4 or i.ipv6):
                    return i.name
        except Exception:
            pass
        # Last resort: use Scapy's default, but not loopback
        iface = conf.iface
        if iface == 'lo':
            # Dig deeper — try to find a non-loopback interface from netifaces
            try:
                import netifaces
                for name in netifaces.interfaces():
                    if name != 'lo':
                        addrs = netifaces.ifaddresses(name)
                        if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
                            return name
            except Exception:
                pass
        return iface

    def _verify_interface(self):
        """Verify the capture interface exists and is accessible."""
        try:
            import netifaces
            ifaces = netifaces.interfaces()
            if self.interface not in ifaces and self.backend == 'scapy':
                # Try to find it
                for iface in ifaces:
                    if self.interface in iface:
                        self.interface = iface
                        break
        except Exception:
            pass

    def _scapy_packet_handler(self, pkt):
        """Handle packets from Scapy sniffer."""
        try:
            self.packet_count += 1
            self.byte_count += len(pkt)
            self.stats['total'] = self.packet_count
            self.stats['bytes'] = self.byte_count

            # Dissect the packet
            info = dissect_packet(pkt)
            if info:
                proto = info.protocol.lower()
                if proto in self.stats:
                    self.stats[proto] += 1
                elif proto in ('tcp', 'udp'):
                    self.stats[proto] += 1
                else:
                    self.stats['other'] += 1

                if info.ip_version == 4:
                    self.stats['ipv4'] += 1
                elif info.ip_version == 6:
                    self.stats['ipv6'] += 1

                info.id = self.packet_count

            self.packet_queue.put((pkt, info))

            if self.callback:
                self.callback(pkt, info)

        except Exception as e:
            # Silently handle malformed packets
            pass

    def _raw_socket_capture(self):
        """Raw socket capture thread - captures at L2 or L3."""
        try:
            # Try L2 raw socket (AF_PACKET) for full ethernet frames
            raw_sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003)
            )
            if self.interface:
                raw_sock.bind((self.interface, 0))
            if self.promisc:
                raw_sock.setsockopt(socket.SOL_SOCKET, 0x01, 1)  # SO_PROMISCUOUS
        except Exception:
            # Fall back to L3 raw socket (AF_INET)
            try:
                raw_sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_RAW,
                    socket.IPPROTO_TCP
                )
                raw_sock.setsockopt(socket.IPPROTO_IP, 2, 1)  # IP_HDRINCL
            except PermissionError:
                print("[!] Raw socket requires root/admin privileges")
                return

        raw_sock.settimeout(1.0)
        self._raw_socket = raw_sock

        while self._running:
            try:
                data, addr = raw_sock.recvfrom(65535)
                self.packet_count += 1
                self.byte_count += len(data)
                self.stats['total'] = self.packet_count
                self.stats['bytes'] = self.byte_count

                # Create a minimal Scapy packet for dissection
                pkt = None
                info = None
                try:
                    pkt = Ether(data)
                    info = dissect_packet(pkt)
                    if info:
                        info.id = self.packet_count
                        proto = info.protocol.lower()
                        if proto in self.stats:
                            self.stats[proto] += 1
                        else:
                            self.stats['other'] += 1
                    self.packet_queue.put((pkt, info))
                except Exception:
                    self.packet_queue.put((data, None))

                if self.callback:
                    self.callback(pkt if pkt is not None else data,
                                  info if info is not None else None)

            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue

    def _check_raw_permissions(self):
        """Quick pre-flight: try opening a raw socket to detect PermissionError early."""
        import errno
        test_sock = None
        try:
            test_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            if self.interface:
                test_sock.bind((self.interface, 0))
        except PermissionError:
            raise PermissionError(
                f"Raw socket access denied on '{self.interface}'.\n"
                "  Run with:  sudo python3 main.py live\n"
                "  Or grant CAP_NET_RAW:  sudo setcap cap_net_raw+ep $(which python3)"
            )
        except OSError as e:
            if e.errno == errno.EPERM:
                raise PermissionError(
                    f"Raw socket access denied on '{self.interface}'.\n"
                    "  Run with:  sudo python3 main.py live\n"
                    "  Or grant CAP_NET_RAW:  sudo setcap cap_net_raw+ep $(which python3)"
                )
            # Other OS errors (e.g. interface not found) – let start() handle them
        finally:
            if test_sock:
                try:
                    test_sock.close()
                except Exception:
                    pass

    def start(self):
        """Start packet capture."""
        if self._running:
            return

        # Pre-flight: bail early if we can't open raw sockets
        if self.backend in ('scapy', 'raw'):
            self._check_raw_permissions()

        self._running = True
        self.start_time = datetime.now()

        if self.backend == 'scapy':
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._scapy_packet_handler,
                filter=self.filter_bpf,
                store=False,
                promisc=self.promisc,
                started_callback=lambda: None
            )
            self._sniffer.start()
        elif self.backend == 'raw':
            self._capture_thread = threading.Thread(
                target=self._raw_socket_capture,
                daemon=True
            )
            self._capture_thread.start()

        return self

    def stop(self):
        """Stop packet capture."""
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop(join=False)
            except (PermissionError, OSError) as e:
                self._sniffer = None  # sniffer died in background; don't re-raise on cleanup
            except Exception:
                self._sniffer = None
        if self._raw_socket:
            try:
                self._raw_socket.close()
            except Exception:
                pass

    def get_snapshot(self):
        """Get a snapshot of current packets from queue (non-blocking)."""
        packets = []
        while not self.packet_queue.empty():
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets

    def get_stats(self):
        """Get current capture statistics."""
        return {
            **self.stats,
            'uptime': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            'interface': self.interface,
            'backend': self.backend,
            'running': self._running
        }

    def export_pcap(self, filename: str, packets: list = None):
        """Export captured packets to PCAP file."""
        if packets:
            scapy_packets = [p[0] for p in packets if hasattr(p[0], 'haslayer')]
            if scapy_packets:
                wrpcap(filename, scapy_packets)
                return True
        return False

    def read_pcap(self, filename: str):
        """Read packets from a PCAP file for offline analysis."""
        packets = rdpcap(filename)
        for pkt in packets:
            self._scapy_packet_handler(pkt)
        return packets


# Alias for easy import
PacketCapture = CaptureEngine
