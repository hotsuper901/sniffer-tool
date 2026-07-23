"""
M.S.J Packet Filter Engine
===========================
Flexible packet filtering system supporting:
  - BPF-style expressions (decoded from tcpdump format)
  - Protocol-based filters (tcp, udp, icmp, arp, dns, http, dhcp)
  - IP/port matching (src/dst, ranges, CIDR)
  - MAC address matching
  - Flag matching (TCP SYN, ACK, etc.)
  - Compound boolean expressions (AND, OR, NOT)
  - Regex matching on payload

Designed for both live capture filtering and post-capture analysis.

Creator: M.S.J
"""

import re
import ipaddress
from typing import Callable, List, Optional, Any
from dataclasses import dataclass, field

from modules.dissect import PacketInfo


@dataclass
class FilterRule:
    """A single filter rule expression."""
    field: str          # e.g., 'protocol', 'src_ip', 'dst_port', 'tcp_flags'
    operator: str       # '==', '!=', 'in', 'contains', 'regex', '>', '<', '>=', '<='
    value: Any          # The value to compare against
    negate: bool = False

    def match(self, info: PacketInfo) -> bool:
        """Check if a packet matches this rule."""
        val = self._get_field_value(info)
        if val is None:
            return False

        result = self._compare(val)
        return not result if self.negate else result

    def _get_field_value(self, info: PacketInfo) -> Any:
        """Extract field value from packet info."""
        field_map = {
            'protocol': info.protocol,
            'proto': info.protocol,
            'src_ip': info.src_ip,
            'dst_ip': info.dst_ip,
            'src_port': info.src_port,
            'dst_port': info.dst_port,
            'port': info.src_port or info.dst_port,
            'src_mac': info.src_mac,
            'dst_mac': info.dst_mac,
            'mac': info.src_mac or info.dst_mac,
            'length': info.length,
            'len': info.length,
            'ttl': info.ttl,
            'tcp_flags': info.tcp_flags,
            'flags': info.tcp_flags,
            'http_method': info.http_method,
            'http_uri': info.http_uri,
            'http_status': info.http_status,
            'http_host': info.http_host,
            'dns_query': info.dns_query,
            'dns_type': info.dns_type,
            'arp_op': info.arp_op,
            'icmp_type': info.icmp_type,
            'icmp_code': info.icmp_code,
            'tls_sni': info.tls_sni,
            'dhcp_msg': info.dhcp_message_type,
            'payload': info.payload_text,
            'payload_hex': info.payload_hex,
            'tags': info.tags,
        }
        return field_map.get(self.field.lower())

    def _compare(self, val: Any) -> bool:
        """Compare extracted value against rule value."""
        try:
            if self.operator == '==':
                if isinstance(val, str) and isinstance(self.value, str):
                    return val.lower() == self.value.lower()
                return val == self.value
            elif self.operator == '!=':
                if isinstance(val, str) and isinstance(self.value, str):
                    return val.lower() != self.value.lower()
                return val != self.value
            elif self.operator == 'in':
                if isinstance(val, str):
                    # Check each value — supports plain strings and CIDR subnets
                    for v in self.value:
                        if isinstance(v, str):
                            if '/' in v:
                                try:
                                    net = ipaddress.IPv4Network(v, strict=False)
                                    if ipaddress.IPv4Address(val) in net:
                                        return True
                                except (ValueError, TypeError):
                                    pass
                            elif val.lower() == v.lower():
                                return True
                    return False
                return val in self.value
            elif self.operator == 'contains':
                if isinstance(val, str):
                    return self.value.lower() in val.lower()
                return False
            elif self.operator == 'regex':
                if isinstance(val, str):
                    return bool(re.search(self.value, val, re.IGNORECASE))
                return False
            elif self.operator in ('>', '<', '>=', '<='):
                if isinstance(val, (int, float)) and isinstance(self.value, (int, float)):
                    if self.operator == '>': return val > self.value
                    if self.operator == '<': return val < self.value
                    if self.operator == '>=': return val >= self.value
                    if self.operator == '<=': return val <= self.value
                return False
        except (TypeError, ValueError, AttributeError):
            return False
        return False


class PacketFilter:
    """
    Multi-rule packet filter. Supports compound filtering with AND/OR/NOT logic.

    Usage:
        f = PacketFilter()
        f.add_rule('protocol', '==', 'HTTP')
        f.add_rule('dst_port', '==', 443)
        if f.matches(info): ...
    """

    def __init__(self):
        self.rules: List[FilterRule] = []
        self._custom_filters: List[Callable] = []

    def add_rule(self, field: str, operator: str, value: Any, negate: bool = False):
        """Add a filter rule."""
        self.rules.append(FilterRule(field=field, operator=operator, value=value, negate=negate))

    def add_custom(self, func: Callable[[PacketInfo], bool]):
        """Add a custom filter function."""
        self._custom_filters.append(func)

    def clear(self):
        """Remove all rules."""
        self.rules.clear()
        self._custom_filters.clear()

    def matches(self, info: PacketInfo) -> bool:
        """Check if packet matches ALL rules (AND logic)."""
        if not self.rules and not self._custom_filters:
            return True

        for rule in self.rules:
            if not rule.match(info):
                return False

        for func in self._custom_filters:
            if not func(info):
                return False

        return True

    @classmethod
    def parse_bpf(cls, bpf_str: str) -> 'PacketFilter':
        """
        Parse a simplified BPF-like expression into a PacketFilter.
        Supports: 'tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'dhcp',
                  'port 80', 'src port 80', 'dst port 80',
                  'host 192.168.1.1', 'src host ...', 'dst host ...',
                  'net 192.168.1.0/24',
                  'and', 'or', 'not'
        """
        pf = cls()
        tokens = bpf_str.split()

        i = 0
        negate = False
        while i < len(tokens):
            token = tokens[i].lower()

            if token == 'not':
                negate = True
                i += 1
                continue

            if token in ('tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'dhcp', 'tls'):
                pf.add_rule('protocol', '==', token.upper(), negate=negate)

            elif token == 'port' and i + 1 < len(tokens):
                try:
                    port = int(tokens[i + 1])
                    pf.add_rule('port', '==', port, negate=negate)
                    i += 1
                except ValueError:
                    pass

            elif token == 'src' and i + 2 < len(tokens):
                qualifier = tokens[i + 1].lower()
                value = tokens[i + 2]
                if qualifier == 'port':
                    pf.add_rule('src_port', '==', int(value), negate=negate)
                    i += 2
                elif qualifier == 'host':
                    pf.add_rule('src_ip', '==', value, negate=negate)
                    i += 2
                elif qualifier == 'mac':
                    pf.add_rule('src_mac', '==', value, negate=negate)
                    i += 2

            elif token == 'dst' and i + 2 < len(tokens):
                qualifier = tokens[i + 1].lower()
                value = tokens[i + 2]
                if qualifier == 'port':
                    pf.add_rule('dst_port', '==', int(value), negate=negate)
                    i += 2
                elif qualifier == 'host':
                    pf.add_rule('dst_ip', '==', value, negate=negate)
                    i += 2
                elif qualifier == 'mac':
                    pf.add_rule('dst_mac', '==', value, negate=negate)
                    i += 2

            elif token == 'host' and i + 1 < len(tokens):
                pf.add_rule('src_ip', '==', tokens[i + 1], negate=negate)
                i += 1

            elif token == 'net' and i + 1 < len(tokens):
                # CIDR matching - store as 'in' with CIDR prefix
                cidr = tokens[i + 1]
                pf.add_rule('src_ip', 'in', [cidr], negate=negate)
                i += 1

            elif token in ('and', 'or'):
                # Default is AND (all rules must match)
                # OR support is limited with current architecture
                pass
            else:
                pass

            # Reset negate after consuming a filter token (not after 'not'/'and'/'or')
            negate = False
            i += 1

        return pf


# Predefined common filters
def filter_http() -> PacketFilter:
    f = PacketFilter()
    f.add_rule('protocol', '==', 'HTTP')
    return f

def filter_dns() -> PacketFilter:
    f = PacketFilter()
    f.add_rule('protocol', '==', 'DNS')
    return f

def filter_syn() -> PacketFilter:
    f = PacketFilter()
    f.add_rule('tcp_flags', 'contains', 'SYN')
    return f

def filter_credentials() -> PacketFilter:
    """Filter for packets likely containing credentials."""
    f = PacketFilter()

    def _has_creds(info: PacketInfo) -> bool:
        if 'password' in info.payload_text.lower():
            return True
        if 'login' in info.payload_text.lower():
            return True
        if 'authenticate' in info.payload_text.lower():
            return True
        if 'token' in info.payload_text.lower():
            return True
        if 'authorization' in info.payload_text.lower():
            return True
        return False

    f.add_custom(_has_creds)
    return f
