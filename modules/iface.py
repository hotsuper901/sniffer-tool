"""
M.S.J Interface Discovery & Categorization
===========================================
Intelligent network interface enumeration with type detection.
Categorizes physical, virtual, tunnel, cellular, loopback, bridge,
WiFi, and special-purpose interfaces. Works on Linux, Android, macOS.

Interfaces are classified by name pattern and capability probing.
Shows IP addresses, netmasks, MAC addresses, and operational status.

Creator: M.S.J
"""

import os
import sys
import socket
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import netifaces


# ── Interface Type Constants ──────────────────────────────────
class IFaceType:
    LOOPBACK       = 'loopback'
    ETHERNET       = 'ethernet'
    WIFI           = 'wifi'
    WIFI_P2P       = 'wifi_p2p'
    CELLULAR       = 'cellular'
    BRIDGE         = 'bridge'
    BOND           = 'bond'
    VLAN           = 'vlan'
    TUNNEL_IP      = 'tunnel_ip'
    TUNNEL_GRE     = 'tunnel_gre'
    TUNNEL_VTI     = 'tunnel_vti'
    TUN_TAP        = 'tun_tap'
    VIRTUAL        = 'virtual'
    DUMMY          = 'dummy'
    IFB            = 'ifb'
    UNKNOWN        = 'unknown'


# ── Interface name → type pattern table ───────────────────────
# Ordered: more specific patterns checked first
IFACE_TYPE_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (r'^lo$',                        IFaceType.LOOPBACK,    'Loopback'),
    (r'^dummy\d*$',                  IFaceType.DUMMY,       'Dummy'),
    (r'^ifb\d+$',                    IFaceType.IFB,         'IFB (Traffic Ctrl)'),
    # WiFi
    (r'^wlan\d+$',                   IFaceType.WIFI,        'WiFi'),
    (r'^wifi\d+$',                   IFaceType.WIFI,        'WiFi'),
    (r'^ath\d+$',                    IFaceType.WIFI,        'WiFi (Atheros)'),
    (r'^phy\d+$',                    IFaceType.WIFI,        'WiFi PHY'),
    (r'^p2p\d+$',                    IFaceType.WIFI_P2P,    'WiFi Direct'),
    # Cellular / Modem (Android / Qualcomm)
    (r'^ccmni\d+$',                  IFaceType.CELLULAR,    'Cellular (CCMNI)'),
    (r'^rmnet\d+$',                  IFaceType.CELLULAR,    'Cellular (RMNET)'),
    (r'^rmnet_usb\d+$',              IFaceType.CELLULAR,    'Cellular (RMNET USB)'),
    (r'^wwan\d+$',                   IFaceType.CELLULAR,    'Cellular (WWAN)'),
    (r'^rndis\d+$',                  IFaceType.CELLULAR,    'Cellular (RNDIS)'),
    # Ethernet
    (r'^eth\d+$',                    IFaceType.ETHERNET,    'Ethernet'),
    (r'^en[pxso]\d+',               IFaceType.ETHERNET,    'Ethernet (Predictable)'),
    # Bridge / Bond
    (r'^br\d+$',                     IFaceType.BRIDGE,      'Bridge'),
    (r'^br-[a-f0-9]+$',             IFaceType.BRIDGE,      'Bridge (Docker)'),
    (r'^bond\d+$',                   IFaceType.BOND,        'Bond'),
    (r'^team\d+$',                   IFaceType.BOND,        'Team'),
    # Tunnels - IP/GRE/VTI/SIT
    (r'^tunl\d+$',                   IFaceType.TUNNEL_IP,   'IP-IP Tunnel'),
    (r'^gre\d+$',                    IFaceType.TUNNEL_GRE,  'GRE Tunnel'),
    (r'^gretap\d+$',                 IFaceType.TUNNEL_GRE,  'GRE Tap'),
    (r'^erspan\d+$',                 IFaceType.TUNNEL_GRE,  'ERSPAN Tunnel'),
    (r'^ip_vti\d+$',                 IFaceType.TUNNEL_VTI,  'IPsec VTI'),
    (r'^ip6_vti\d+$',                IFaceType.TUNNEL_VTI,  'IPv6 IPsec VTI'),
    (r'^sit\d+$',                    IFaceType.TUNNEL_IP,   'SIT Tunnel (6in4)'),
    (r'^ip6tnl\d+$',                 IFaceType.TUNNEL_IP,   'IPv6 Tunnel'),
    (r'^ip6gre\d+$',                 IFaceType.TUNNEL_GRE,  'IPv6 GRE'),
    # TUN/TAP
    (r'^tun\d+$',                    IFaceType.TUN_TAP,     'TUN'),
    (r'^tap\d+$',                    IFaceType.TUN_TAP,     'TAP'),
    # Virtual
    (r'^veth[a-f0-9]+$',            IFaceType.VIRTUAL,     'Virtual (veth)'),
    (r'^docker\d+$',                 IFaceType.VIRTUAL,     'Docker'),
    (r'^virbr\d+$',                  IFaceType.VIRTUAL,     'libvirt Bridge'),
    (r'^vboxnet\d+$',                IFaceType.VIRTUAL,     'VirtualBox'),
    (r'^vmnet\d+$',                  IFaceType.VIRTUAL,     'VMware'),
    (r'^lxcbr\d+$',                  IFaceType.VIRTUAL,     'LXC Bridge'),
]


@dataclass
class InterfaceInfo:
    """Structured information about a single network interface."""
    name: str
    iface_type: str = IFaceType.UNKNOWN
    type_label: str = 'Unknown'
    flags: str = ''
    is_up: bool = False
    is_running: bool = False
    is_loopback: bool = False
    is_multicast: bool = False
    is_broadcast: bool = False
    is_promisc: bool = False
    mac: str = ''
    ipv4_addresses: List[Dict[str, str]] = field(default_factory=list)
    ipv6_addresses: List[Dict[str, str]] = field(default_factory=list)
    mtu: int = 0
    index: int = 0
    speed: int = 0
    stats: Dict[str, int] = field(default_factory=dict)

    @property
    def ipv4(self) -> str:
        if self.ipv4_addresses:
            return self.ipv4_addresses[0].get('addr', '')
        return ''

    @property
    def netmask(self) -> str:
        if self.ipv4_addresses:
            return self.ipv4_addresses[0].get('netmask', '')
        return ''

    @property
    def ipv6(self) -> str:
        if self.ipv6_addresses:
            # Prefer global unicast (starts with 2 or 3)
            for a in self.ipv6_addresses:
                addr = a.get('addr', '')
                if addr and not addr.startswith('fe80'):
                    return addr
            return self.ipv6_addresses[0].get('addr', '')
        return ''

    @property
    def cidr_ipv4(self) -> str:
        """Return IPv4 in CIDR notation e.g. '192.168.1.5/24'."""
        ip = self.ipv4
        nm = self.netmask
        if ip and nm:
            try:
                bits = sum(bin(int(x)).count('1') for x in nm.split('.'))
                return f"{ip}/{bits}"
            except Exception:
                return ip
        return ip

    @property
    def status_icon(self) -> str:
        if self.is_up and self.is_running:
            return '●'
        elif self.is_up:
            return '◐'
        return '○'

    @property
    def status_text(self) -> str:
        if self.is_up and self.is_running:
            return 'UP'
        elif self.is_up:
            return 'UP (no carrier)'
        return 'DOWN'


class InterfaceDiscovery:
    """
    Discover and categorize all network interfaces on the system.
    Uses netifaces for cross-platform address/flag retrieval and
    /proc/net/dev or /sys/class/net for Linux stats.
    """

    def __init__(self):
        self._interfaces: Dict[str, InterfaceInfo] = {}
        self._scan()

    def _scan(self):
        """Full interface discovery scan."""
        self._interfaces.clear()

        # Get all interface names from netifaces
        try:
            iface_names = netifaces.interfaces()
        except Exception:
            iface_names = []

        for name in iface_names:
            info = InterfaceInfo(name=name)

            # ── Type classification ──
            info.iface_type, info.type_label = self._classify(name)

            # ── Get addresses (IPv4, IPv6, MAC) ──
            try:
                addrs = netifaces.ifaddresses(name)
                if netifaces.AF_LINK in addrs:
                    link = addrs[netifaces.AF_LINK]
                    if link:
                        info.mac = link[0].get('addr', '')
                        info.index = link[0].get('index', 0)
                        info.flags = link[0].get('flags', '')
                        info.is_up = 'UP' in info.flags if info.flags else False
                        info.is_running = 'RUNNING' in info.flags if info.flags else False
                        info.is_loopback = 'LOOPBACK' in info.flags if info.flags else False
                        info.is_multicast = 'MULTICAST' in info.flags if info.flags else False
                        info.is_broadcast = 'BROADCAST' in info.flags if info.flags else False
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        info.ipv4_addresses.append({
                            'addr': addr_info.get('addr', ''),
                            'netmask': addr_info.get('netmask', ''),
                            'broadcast': addr_info.get('broadcast', ''),
                        })
                if netifaces.AF_INET6 in addrs:
                    for addr_info in addrs[netifaces.AF_INET6]:
                        info.ipv6_addresses.append({
                            'addr': addr_info.get('addr', '').split('%')[0],
                            'netmask': addr_info.get('netmask', ''),
                        })
            except Exception:
                pass

            # ── Get MTU ──
            info.mtu = self._get_mtu(name)

            # ── Get speed / stats from sysfs ──
            info.speed = self._get_speed(name)
            info.stats = self._get_stats(name)

            self._interfaces[name] = info

    def _classify(self, name: str) -> Tuple[str, str]:
        """Classify interface by name pattern. Returns (type, label)."""
        for pattern, itype, label in IFACE_TYPE_PATTERNS:
            if re.match(pattern, name):
                return itype, label
        return IFaceType.UNKNOWN, 'Unknown'

    def _get_mtu(self, name: str) -> int:
        """Read MTU from /sys/class/net/<name>/mtu."""
        try:
            with open(f'/sys/class/net/{name}/mtu', 'r') as f:
                return int(f.read().strip())
        except Exception:
            return 0

    def _get_speed(self, name: str) -> int:
        """Read interface speed from /sys/class/net/<name>/speed."""
        try:
            with open(f'/sys/class/net/{name}/speed', 'r') as f:
                val = f.read().strip()
                return int(val) if val.isdigit() and int(val) > 0 else 0
        except Exception:
            return 0

    def _get_stats(self, name: str) -> Dict[str, int]:
        """Read RX/TX bytes and packets from /proc/net/dev or sysfs."""
        stats = {}
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if name + ':' in line:
                        parts = line.split()
                        if len(parts) >= 10:
                            stats['rx_bytes'] = int(parts[1]) if parts[1].isdigit() else 0
                            stats['rx_packets'] = int(parts[2]) if parts[2].isdigit() else 0
                            stats['tx_bytes'] = int(parts[9]) if parts[9].isdigit() else 0
                            stats['tx_packets'] = int(parts[10]) if parts[10].isdigit() else 0
                        break
        except Exception:
            pass
        return stats

    # ── Query API ─────────────────────────────────────────

    def all(self) -> List[InterfaceInfo]:
        """Return all interfaces sorted by type then name."""
        type_order = {
            IFaceType.ETHERNET: 0, IFaceType.WIFI: 1, IFaceType.WIFI_P2P: 2,
            IFaceType.CELLULAR: 3, IFaceType.BRIDGE: 4, IFaceType.BOND: 5,
            IFaceType.VLAN: 6, IFaceType.TUNNEL_IP: 7, IFaceType.TUNNEL_GRE: 8,
            IFaceType.TUNNEL_VTI: 9, IFaceType.TUN_TAP: 10, IFaceType.VIRTUAL: 11,
            IFaceType.DUMMY: 12, IFaceType.IFB: 13, IFaceType.LOOPBACK: 14,
            IFaceType.UNKNOWN: 99,
        }
        return sorted(
            self._interfaces.values(),
            key=lambda i: (type_order.get(i.iface_type, 99), i.name)
        )

    def get(self, name: str) -> Optional[InterfaceInfo]:
        """Get a specific interface by name. Supports partial matching."""
        if name in self._interfaces:
            return self._interfaces[name]
        # Partial match
        for iface in self._interfaces:
            if name in iface:
                return self._interfaces[iface]
        return None

    def by_type(self, itype: str) -> List[InterfaceInfo]:
        """Get all interfaces of a specific type."""
        return [i for i in self._interfaces.values() if i.iface_type == itype]

    def active(self) -> List[InterfaceInfo]:
        """Get only interfaces that are UP and have an IP address.
           On systems where flags aren't reported (e.g., Android via netifaces),
           any interface with an IP is considered active."""
        return [
            i for i in self._interfaces.values()
            if i.is_up and (i.ipv4 or i.ipv6)
        ] or [
            # Fallback: if no interfaces report as UP (flags parsing failed),
            # treat any non-loopback with an IP as active
            i for i in self._interfaces.values()
            if i.name != 'lo' and (i.ipv4 or i.ipv6)
        ]

    def default_interface(self) -> Optional[str]:
        """Guess the best default capture interface."""
        # Prefer active WiFi or Ethernet
        for itype in (IFaceType.WIFI, IFaceType.ETHERNET, IFaceType.CELLULAR):
            actives = [i for i in self.by_type(itype) if i.is_up and i.is_running and (i.ipv4 or i.ipv6)]
            if actives:
                return actives[0].name
        # Fallback: any non-loopback with an IP (flags may be unavailable)
        for i in self.all():
            if i.name != 'lo' and (i.ipv4 or i.ipv6):
                if i.iface_type in (IFaceType.WIFI, IFaceType.ETHERNET, IFaceType.CELLULAR):
                    return i.name
        # Broader fallback: any active non-loopback
        for i in self.active():
            if i.iface_type != IFaceType.LOOPBACK:
                return i.name
        return None

    def stats_summary(self) -> Dict[str, int]:
        """Get summary counts by interface type."""
        counts = {}
        for i in self._interfaces.values():
            t = i.iface_type
            counts[t] = counts.get(t, 0) + 1
        counts['total'] = len(self._interfaces)
        return counts

    def refresh(self):
        """Re-scan all interfaces."""
        self._scan()


# ── Rich Display Helpers ──────────────────────────────────────

def rich_iface_table(discovery: InterfaceDiscovery, console=None) -> any:
    """
    Build a Rich Table of all interfaces. Returns a Table object.
    Usage:
        from rich.console import Console
        c = Console()
        c.print(rich_iface_table(InterfaceDiscovery()))
    """
    try:
        from rich.table import Table
        from rich.text import Text
        from rich import box
    except ImportError:
        return None

    table = Table(
        title='Network Interfaces',
        box=box.ROUNDED,
        border_style='bright_cyan',
        title_style='bold bright_cyan',
        padding=(0, 1),
    )
    table.add_column('#', style='grey50', width=3, justify='right')
    table.add_column('Interface', style='bright_white')
    table.add_column('Type', style='cyan')
    table.add_column('Status', style='bold')
    table.add_column('IPv4', style='bright_green')
    table.add_column('MAC', style='yellow')

    for idx, iface in enumerate(discovery.all(), 1):
        status_style = 'bright_green' if iface.is_up and iface.is_running else 'yellow' if iface.is_up else 'red'
        status_text = Text(f"{iface.status_icon} {iface.status_text}", style=status_style)

        ip = iface.cidr_ipv4 or (iface.ipv6 and iface.ipv6[:20] + '…') or '—'
        ip_style = 'green' if iface.ipv4 else 'grey50'

        mac = iface.mac or '—'
        mac_style = 'yellow' if iface.mac else 'grey50'

        table.add_row(
            str(idx),
            iface.name,
            iface.type_label,
            status_text,
            f'[{ip_style}]{ip}[/]',
            f'[{mac_style}]{mac}[/]',
        )

    summary = discovery.stats_summary()
    table.caption = f'{summary["total"]} interfaces — {summary.get("ethernet",0)} eth, {summary.get("wifi",0)} wifi, {summary.get("cellular",0)} cellular, {summary.get("loopback",0)} loopback'
    table.caption_style = 'grey50'

    return table


def rich_iface_detail(iface: InterfaceInfo, console=None) -> any:
    """Build a Rich Panel with detailed info about one interface."""
    try:
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich import box
    except ImportError:
        return None

    t = Table(show_header=False, box=None, padding=(0, 1))
    t.add_column('Key', style='cyan', no_wrap=True)
    t.add_column('Value', style='white')

    t.add_row('Name', Text(iface.name, style='bold bright_white'))
    t.add_row('Type', f'{iface.type_label} ({iface.iface_type})')
    t.add_row('Status', Text(
        f'{iface.status_icon} {iface.status_text}',
        style='bright_green' if iface.is_up else 'red'
    ))
    t.add_row('MAC', iface.mac or '—')
    t.add_row('MTU', str(iface.mtu) if iface.mtu else '—')
    if iface.speed:
        t.add_row('Speed', f'{iface.speed} Mbps')

    if iface.flags:
        t.add_row('Flags', iface.flags)

    if iface.ipv4_addresses:
        t.add_section()
        t.add_row('[bold]IPv4[/]', '')
        for a in iface.ipv4_addresses:
            t.add_row('  Address', a.get('addr', '—'))
            t.add_row('  Netmask', a.get('netmask', '—'))
            t.add_row('  Broadcast', a.get('broadcast', '—'))

    if iface.ipv6_addresses:
        t.add_section()
        t.add_row('[bold]IPv6[/]', '')
        for a in iface.ipv6_addresses:
            t.add_row('  Address', a.get('addr', '—'))

    if iface.stats:
        t.add_section()
        t.add_row('[bold]Stats[/]', '')
        for k in ('rx_bytes', 'rx_packets', 'tx_bytes', 'tx_packets'):
            if k in iface.stats:
                val = iface.stats[k]
                label = k.replace('_', ' ').title()
                # Humanize bytes
                if 'bytes' in k:
                    h = _human_bytes(val)
                    t.add_row(f'  {label}', f'{val:,} ({h})')
                else:
                    t.add_row(f'  {label}', f'{val:,}')

    return Panel(t, title=f'[bold cyan]{iface.name}[/]', border_style='bright_cyan', box=box.ROUNDED)


def _human_bytes(b: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} PB'


# ── Quick CLI helper ──────────────────────────────────────────

def list_interfaces(console=None, detail: str = None):
    """Print all interfaces to console. If detail is an interface name, show detail."""
    from rich.console import Console
    c = console or Console()
    disc = InterfaceDiscovery()

    if detail:
        iface = disc.get(detail)
        if iface:
            from rich.panel import Panel
            c.print()
            c.print(rich_iface_detail(iface))
            c.print()
        else:
            c.print(Panel(
                f'[red]Interface not found: [bold]{detail}[/bold][/]',
                border_style='red', box=box_type()
            ))
        return

    c.print()
    c.print(rich_iface_table(disc))
    c.print()

    # Show active default
    default = disc.default_interface()
    if default:
        from rich.panel import Panel
        c.print(Panel(
            f'[green]Default capture interface:[/] [bold bright_green]{default}[/]',
            border_style='green',
            box=box_type(),
        ))


def box_type():
    try:
        from rich import box
        return box.ROUNDED
    except ImportError:
        return None
