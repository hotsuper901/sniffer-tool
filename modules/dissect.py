"""
M.S.J Protocol Dissector
========================
Deep packet inspection engine. Dissects L2-L7 protocols:
  Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, DHCP, HTTP, TLS (handshake detect)

Extracts: MAC addresses, IPs, ports, flags, sequence numbers, payload data,
DNS queries/responses, HTTP requests/responses, DHCP options, TLS SNI.

Creator: M.S.J
"""

import re
import struct
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
    DHCP, BOOTP, Raw, Padding, Dot11, Dot11Beacon, Dot11Elt,
    Packet, rdpcap, wrpcap
)


@dataclass
class PacketInfo:
    """Normalized packet metadata and dissection results."""
    id: int = 0
    timestamp: float = 0.0
    timestamp_str: str = ''
    length: int = 0
    protocol: str = 'UNKNOWN'
    protocol_stack: list = field(default_factory=list)

    # L2
    src_mac: str = ''
    dst_mac: str = ''
    ether_type: int = 0

    # L3
    ip_version: int = 0
    src_ip: str = ''
    dst_ip: str = ''
    ttl: int = 0
    tos: int = 0

    # L4
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: str = ''
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_window: int = 0
    udp_length: int = 0

    # L7
    http_method: str = ''
    http_uri: str = ''
    http_host: str = ''
    http_user_agent: str = ''
    http_content_type: str = ''
    http_status: int = 0
    http_cookie: str = ''
    http_payload: str = ''

    dns_query: str = ''
    dns_response: list = field(default_factory=list)
    dns_type: str = ''
    dns_id: int = 0

    dhcp_hostname: str = ''
    dhcp_requested_ip: str = ''
    dhcp_server_id: str = ''
    dhcp_message_type: str = ''

    arp_op: str = ''
    arp_src_ip: str = ''
    arp_dst_ip: str = ''
    arp_src_mac: str = ''
    arp_dst_mac: str = ''

    icmp_type: int = 0
    icmp_code: int = 0

    tls_sni: str = ''
    tls_version: str = ''

    # WiFi
    wifi_channel: int = 0
    wifi_ssid: str = ''
    wifi_bssid: str = ''
    wifi_signal: int = 0

    # Raw
    payload_hex: str = ''
    payload_text: str = ''
    payload_size: int = 0

    # Tags for filtering
    tags: list = field(default_factory=list)

    # Full packet reference (weak ref semantics)
    raw_packet: object = None

    def summary(self) -> str:
        """Human-readable one-line summary."""
        parts = [f"[{self.id:06d}]"]
        parts.append(f"{self.timestamp_str}")
        parts.append(f"[{self.protocol:^6}]")

        if self.protocol == 'ARP':
            parts.append(f"{self.arp_op}: {self.arp_src_ip}->{self.arp_dst_ip}")
        elif self.protocol == 'DNS':
            parts.append(f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}")
            parts.append(f"QRY: {self.dns_query}")
        elif self.protocol == 'HTTP':
            if self.http_method:
                parts.append(f"{self.http_method} {self.http_uri}")
            elif self.http_status:
                parts.append(f"HTTP {self.http_status}")
            parts.append(f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}")
        elif self.protocol == 'TLS':
            parts.append(f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}")
            if self.tls_sni:
                parts.append(f"SNI: {self.tls_sni}")
        elif self.protocol in ('TCP', 'UDP'):
            parts.append(f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}")
            if self.tcp_flags and self.protocol == 'TCP':
                parts.append(f"[{self.tcp_flags}]")
        elif self.protocol == 'ICMP':
            parts.append(f"{self.src_ip} -> {self.dst_ip}")
            parts.append(f"Type={self.icmp_type} Code={self.icmp_code}")
        else:
            parts.append(f"{self.src_ip or self.src_mac} -> {self.dst_ip or self.dst_mac}")

        parts.append(f"({self.length}B)")
        return ' '.join(parts)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON export."""
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_') and k != 'raw_packet'}


# Protocol fingerprints for detection
HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'}
HTTP_PORTS = {80, 8080, 8000, 8888}
DNS_PORT = 53
DHCP_PORTS = {67, 68}
TLS_PORTS = {443, 8443, 465, 993, 995, 990, 989}
TLS_HANDSHAKE_CONTENT_TYPE = 0x16
TLS_ALERT_CONTENT_TYPE = 0x15


def tcp_flags_to_str(flags: int) -> str:
    """Convert TCP flags integer to human-readable string."""
    flag_chars = []
    if flags & 0x01: flag_chars.append('FIN')
    if flags & 0x02: flag_chars.append('SYN')
    if flags & 0x04: flag_chars.append('RST')
    if flags & 0x08: flag_chars.append('PSH')
    if flags & 0x10: flag_chars.append('ACK')
    if flags & 0x20: flag_chars.append('URG')
    if flags & 0x40: flag_chars.append('ECE')
    if flags & 0x80: flag_chars.append('CWR')
    return '|'.join(flag_chars) if flag_chars else '.'


def dissect_http(payload: bytes, info: PacketInfo, src_port: int, dst_port: int) -> bool:
    """Dissect HTTP request/response from raw payload."""
    if not payload:
        return False

    try:
        text = payload.decode('utf-8', errors='replace')
    except Exception:
        return False

    # Check for HTTP request
    first_line = text.split('\r\n')[0] if '\r\n' in text else text.split('\n')[0]
    parts = first_line.split(' ')

    if len(parts) >= 2 and parts[0] in HTTP_METHODS:
        info.http_method = parts[0]
        info.http_uri = parts[1]
        info.protocol = 'HTTP'
        info.tags.append('http_request')

        # Extract headers
        headers_text = text[text.find('\n')+1:]
        header_end = headers_text.find('\n\n')
        if header_end == -1:
            header_end = len(headers_text)
        header_section = headers_text[:header_end]

        for line in header_section.split('\n'):
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                if key == 'host':
                    info.http_host = value
                elif key == 'user-agent':
                    info.http_user_agent = value
                elif key == 'content-type':
                    info.http_content_type = value
                elif key == 'cookie':
                    info.http_cookie = value

        # Payload after headers
        body_start = text.find('\n\n')
        if body_start != -1:
            info.http_payload = text[body_start+2:]

        return True

    # Check for HTTP response
    elif len(parts) >= 2 and parts[0].startswith('HTTP/'):
        try:
            info.http_status = int(parts[1])
        except ValueError:
            pass
        info.protocol = 'HTTP'
        info.tags.append('http_response')

        headers_text = text[text.find('\n')+1:]
        header_end = headers_text.find('\n\n')
        if header_end == -1:
            header_end = len(headers_text)

        for line in headers_text[:header_end].split('\n'):
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                if key == 'content-type':
                    info.http_content_type = value
                elif key == 'set-cookie':
                    info.http_cookie = value

        body_start = text.find('\n\n')
        if body_start != -1:
            info.http_payload = text[body_start+2:]

        return True

    return False


def dissect_tls(payload: bytes, info: PacketInfo) -> bool:
    """Detect TLS handshake and extract SNI from ClientHello."""
    if not payload or len(payload) < 1:
        return False

    # TLS record layer: content type (1) + version (2) + length (2)
    content_type = payload[0]
    if content_type not in (TLS_HANDSHAKE_CONTENT_TYPE, TLS_ALERT_CONTENT_TYPE):
        return False

    if content_type == TLS_HANDSHAKE_CONTENT_TYPE and len(payload) >= 5:
        tls_version_code = struct.unpack('>H', payload[1:3])[0] if len(payload) >= 3 else 0
        version_map = {
            0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'
        }
        info.tls_version = version_map.get(tls_version_code, f'0x{tls_version_code:04x}')
        info.protocol = 'TLS'
        info.tags.append('tls')

        # Parse handshake for ClientHello to extract SNI
        # Handshake struct: type(1) + length(3) + version(2) + random(32) + session(1+var) + cipher(2+var) + comp(1+var) + ext(2+var)
        if len(payload) >= 6:
            hs_type = payload[5]
            if hs_type == 0x01:  # ClientHello
                info.tags.append('tls_client_hello')
                try:
                    # Skip past fixed fields to extensions
                    offset = 43  # random (32) + session header length manual calc
                    if len(payload) > offset + 1:
                        session_len = payload[offset]
                        offset += 1 + session_len
                        if len(payload) > offset + 1:
                            cipher_len = struct.unpack('>H', payload[offset:offset+2])[0]
                            offset += 2 + cipher_len
                            if len(payload) > offset + 1:
                                comp_len = payload[offset]
                                offset += 1 + comp_len
                                # Extensions start here
                                if len(payload) > offset + 1:
                                    ext_total_len = struct.unpack('>H', payload[offset:offset+2])[0]
                                    offset += 2
                                    ext_end = offset + ext_total_len
                                    while offset + 4 < ext_end:
                                        ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
                                        ext_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
                                        offset += 4
                                        if ext_type == 0x0000:  # SNI
                                            if offset + 3 < ext_end:
                                                sni_list_len = struct.unpack('>H', payload[offset:offset+2])[0]
                                                offset += 2
                                                if offset < ext_end and len(payload) > offset + 1:
                                                    sni_entry_type = payload[offset]
                                                    offset += 1
                                                    sni_entry_len = struct.unpack('>H', payload[offset:offset+2])[0]
                                                    offset += 2
                                                    sni_name = payload[offset:offset+sni_entry_len].decode('utf-8', errors='replace')
                                                    info.tls_sni = sni_name
                                                    info.tags.append(f'sni:{sni_name}')
                                                    break
                                        offset += ext_len
                except Exception:
                    pass  # Malformed TLS
        return True

    if content_type == TLS_ALERT_CONTENT_TYPE:
        info.protocol = 'TLS'
        info.tags.append('tls_alert')
        return True

    return False



def dissect_packet(pkt) -> Optional[PacketInfo]:
    """
    Main dissection function. Takes a Scapy packet and returns structured PacketInfo.
    Handles Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, DHCP, HTTP, TLS.
    """
    info = PacketInfo()
    info.raw_packet = pkt
    raw_ts = pkt.time if hasattr(pkt, 'time') and pkt.time else time.time()
    info.timestamp = float(raw_ts)
    info.timestamp_str = datetime.fromtimestamp(info.timestamp).strftime('%H:%M:%S.%f')[:12]
    info.length = len(pkt) if hasattr(pkt, '__len__') else 0

    # --- L2: Ethernet ---
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        info.src_mac = eth.src
        info.dst_mac = eth.dst
        info.ether_type = eth.type
        info.protocol_stack.append('Ethernet')

    # --- L2: ARP ---
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info.protocol = 'ARP'
        info.protocol_stack.append('ARP')
        info.arp_op = 'who-has' if arp.op == 1 else 'is-at' if arp.op == 2 else f'op_{arp.op}'
        info.arp_src_ip = arp.psrc
        info.arp_dst_ip = arp.pdst
        info.arp_src_mac = arp.hwsrc
        info.arp_dst_mac = arp.hwdst
        info.src_ip = arp.psrc
        info.dst_ip = arp.pdst
        info.tags.append(f'arp_{info.arp_op}')
        return info

    # --- L3: IPv4 ---
    if pkt.haslayer(IP):
        ip = pkt[IP]
        info.src_ip = ip.src
        info.dst_ip = ip.dst
        info.ttl = ip.ttl
        info.tos = ip.tos
        info.ip_version = 4
        info.protocol_stack.append('IPv4')

    # --- L3: IPv6 ---
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        info.src_ip = ip6.src
        info.dst_ip = ip6.dst
        info.ip_version = 6
        info.protocol_stack.append('IPv6')

    # --- L4: TCP ---
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info.src_port = tcp.sport
        info.dst_port = tcp.dport
        info.tcp_seq = tcp.seq
        info.tcp_ack = tcp.ack
        info.tcp_window = tcp.window
        info.tcp_flags = tcp_flags_to_str(tcp.flags)
        info.protocol = 'TCP'
        info.protocol_stack.append('TCP')
        info.tags.append('tcp')

        # Check for application layer
        payload = bytes(tcp.payload) if tcp.payload else b''

        if payload:
            # HTTP detection
            if info.dst_port in HTTP_PORTS or info.src_port in HTTP_PORTS:
                if dissect_http(payload, info, info.src_port, info.dst_port):
                    pass  # HTTP set protocol

            # TLS detection (usually port-based but also content-based)
            if info.protocol == 'TCP':  # Only if not already identified
                if info.dst_port in TLS_PORTS or info.src_port in TLS_PORTS:
                    dissect_tls(payload, info)

            # Generic payload capture
            info.payload_size = len(payload)
            info.payload_hex = payload.hex()[:200]
            try:
                info.payload_text = payload.decode('utf-8', errors='replace')[:500]
            except Exception:
                info.payload_text = repr(payload)[:500]

            # If still unknown, try content-based detection
            if info.protocol == 'TCP':
                # Try HTTP on any port
                if dissect_http(payload, info, info.src_port, info.dst_port):
                    pass
                elif dissect_tls(payload, info):
                    pass

        return info

    # --- L4: UDP ---
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        info.src_port = udp.sport
        info.dst_port = udp.dport
        info.udp_length = udp.len
        info.protocol = 'UDP'
        info.protocol_stack.append('UDP')

        payload = bytes(udp.payload) if udp.payload else b''

        # DNS detection
        if info.dst_port == DNS_PORT or info.src_port == DNS_PORT:
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                info.protocol = 'DNS'
                info.tags.append('dns')
                info.dns_id = dns.id

                if dns.qr == 0:  # Query
                    info.dns_type = 'QUERY'
                    info.tags.append('dns_query')
                    if dns.haslayer(DNSQR):
                        qd = dns[DNSQR]
                        info.dns_query = qd.qname.decode('utf-8', errors='replace') if isinstance(qd.qname, bytes) else str(qd.qname)
                        # Strip trailing dot
                        if info.dns_query.endswith('.'):
                            info.dns_query = info.dns_query[:-1]
                else:  # Response
                    info.dns_type = 'RESPONSE'
                    info.tags.append('dns_response')
                    if info.dns_query == '' and dns.haslayer(DNSQR):
                        qd = dns[DNSQR]
                        info.dns_query = qd.qname.decode('utf-8', errors='replace') if isinstance(qd.qname, bytes) else str(qd.qname)
                        if info.dns_query.endswith('.'):
                            info.dns_query = info.dns_query[:-1]

                    ancount = dns.ancount or 0
                    if ancount > 0:
                        for i in range(ancount):
                            try:
                                rr = dns.an[i]
                                if hasattr(rr, 'rdata'):
                                    rdata = rr.rdata
                                    if isinstance(rdata, bytes):
                                        rdata = rdata.decode('utf-8', errors='replace')
                                    info.dns_response.append(str(rdata))
                            except (IndexError, AttributeError):
                                pass

        # DHCP detection
        elif (info.dst_port in DHCP_PORTS or info.src_port in DHCP_PORTS) and pkt.haslayer(DHCP):
            try:
                dhcp = pkt[DHCP]
                info.protocol = 'DHCP'
                info.tags.append('dhcp')
                for opt in dhcp.options:
                    if isinstance(opt, tuple):
                        if opt[0] == 'message-type':
                            msg_types = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST',
                                         4: 'DECLINE', 5: 'ACK', 6: 'NAK',
                                         7: 'RELEASE', 8: 'INFORM'}
                            info.dhcp_message_type = msg_types.get(opt[1], str(opt[1]))
                        elif opt[0] == 'hostname':
                            info.dhcp_hostname = opt[1].decode('utf-8', errors='replace') if isinstance(opt[1], bytes) else str(opt[1])
                        elif opt[0] == 'requested_addr':
                            info.dhcp_requested_ip = opt[1]
                        elif opt[0] == 'server_id':
                            info.dhcp_server_id = opt[1]
            except Exception:
                pass

        # Generic payload
        if payload:
            info.payload_size = len(payload)
            info.payload_hex = payload.hex()[:200]
            try:
                info.payload_text = payload.decode('utf-8', errors='replace')[:500]
            except Exception:
                info.payload_text = repr(payload)[:500]

        return info

    # --- L4: ICMP ---
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        info.protocol = 'ICMP'
        info.protocol_stack.append('ICMP')
        info.icmp_type = icmp.type
        info.icmp_code = icmp.code
        info.tags.append(f'icmp_{icmp.type}_{icmp.code}')

        # ICMP type names
        icmp_types = {
            0: 'Echo Reply', 3: 'Dest Unreachable', 4: 'Source Quench',
            5: 'Redirect', 8: 'Echo Request', 11: 'Time Exceeded',
            12: 'Parameter Problem', 13: 'Timestamp', 14: 'Timestamp Reply'
        }
        tag_name = icmp_types.get(icmp.type, f'type_{icmp.type}')
        # Remove old generic tag
        info.tags = [t for t in info.tags if not t.startswith('icmp_')]
        info.tags.append(f'icmp_{tag_name.lower().replace(" ", "_")}')

        return info

    # --- Unknown / Other ---
    if not info.protocol_stack:
        info.protocol = 'OTHER'
        info.protocol_stack.append('Unknown')

    return info
