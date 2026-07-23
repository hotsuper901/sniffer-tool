"""
M.S.J Menu HUD — Compact v3.1
==============================
Clean interactive menu with pyfiglet + Rich.
No clutter, no giant banners, everything fits on screen.
Creator: M.S.J
"""

import os, sys, time
import base64
from datetime import datetime
from typing import Optional, Callable
from io import StringIO

import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.style import Style
from rich.align import Align
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.rule import Rule

from modules import __version__, __creator__
from modules.capture import CaptureEngine
from modules.dissect import dissect_packet, PacketInfo
from modules.filter import PacketFilter
from modules.export import (
    PCAPExporter, JSONExporter, CSVExporter,
    HexDumpExporter, TXTLogExporter, MultiExporter
)
from modules.display import SnifferDisplay, PacketPrinter
from modules.analyze import (
    TCPStreamFollower, ConversationTracker,
    BandwidthMonitor, AnomalyDetector
)
from modules.creds import CredentialHarvester, Credential
from modules.mitm import MITMConfig, ARPSpoofer, DNSSpoofer, ConnectionHijacker
from modules.iface import InterfaceDiscovery, rich_iface_table, rich_iface_detail

# ─── Constants ────────────────────────────────────────────────
MENU_FONT = 'standard'    # compact header (5 lines)
SUB_FONT  = 'small'       # mode section headers

MODE_ICONS = {
    'live':'📡','mitm':'🎭','offline':'📂','harvest':'🔑','scan':'🔍','test':'🧪'
}

# ─── Helpers ──────────────────────────────────────────────────
def _fig(text: str, font: str = MENU_FONT, width: int = 100) -> str:
    try:
        return pyfiglet.figlet_format(text, font=font, width=width).rstrip('\n')
    except:
        return text.upper() + '\n' + '-' * len(text)


class MenuHUD:
    """Clean, compact interactive menu system."""

    def __init__(self, console: Console = None):
        self.console = console or Console()
        self.running = True
        self.selected_mode = None
        self._w = min(self.console.width or 100, 110)

    # ─── Splash ───────────────────────────────────────────
    def show_splash(self, duration: float = 0.6):
        c = self.console; c.clear()
        art = _fig('M . S . J', font=MENU_FONT, width=self._w)
        splash = Text(); splash.append(art, style='bold bright_cyan')
        splash.append(f'\n  v{__version__} · {__creator__} · "See the wires, hear the whispers"\n',
                       style='bright_yellow')
        c.print(Panel(Align.center(splash), border_style='bright_cyan',
                       box=box.ROUNDED, padding=(0, 2)))
        time.sleep(duration)
        c.clear()

    # ─── Interface Browser ─────────────────────────────────
    def _browse_interfaces(self, allow_select: bool = True) -> Optional[str]:
        """Display a categorized interface table. Returns selected iface name or None."""
        c = self.console; c.clear()
        art = _fig('INTERFACES', font=SUB_FONT, width=self._w)
        c.print(Panel(Align.center(Text(art, style='bold bright_cyan')),
                       border_style='bright_cyan', box=box.ROUNDED))
        c.print()

        disc = InterfaceDiscovery()
        tbl = rich_iface_table(disc)
        if tbl:
            c.print(tbl)

        c.print()
        if allow_select:
            foot = Text.assemble(
                (' [D] Detail  ', 'cyan'),
                (' [S] Select  ', 'green'),
                (' [R] Refresh  ', 'yellow'),
                (' [Q] Back  ', 'red'),
            )
            c.print(Panel(foot, border_style='grey50', box=box.HORIZONTALS, padding=(0, 1)))

            choice = Prompt.ask('[bold cyan]Action[/]',
                                choices=['d','D','s','S','r','R','q','Q'],
                                default='q', show_choices=False)

            if choice.lower() == 'q':
                return None
            elif choice.lower() == 'r':
                disc.refresh()
                return self._browse_interfaces(allow_select=True)  # Recursive refresh
            elif choice.lower() == 'd':
                self._browse_interfaces(allow_select=False)
                detail_name = Prompt.ask('[cyan]Interface name for details[/]', default='')
                if detail_name:
                    iface = disc.get(detail_name)
                    if iface:
                        c.clear()
                        art = _fig('DETAIL', font=SUB_FONT, width=self._w)
                        c.print(Panel(Align.center(Text(art, style='bold bright_cyan')),
                                       border_style='bright_cyan', box=box.ROUNDED))
                        c.print(rich_iface_detail(iface))
                        c.print()
                        Prompt.ask('[grey50]Enter to return[/]')
                    else:
                        c.print(Panel(f'[red]Not found: {detail_name}[/]', border_style='red'))
                        Prompt.ask('[grey50]Enter to continue[/]')
                return self._browse_interfaces(allow_select=True)
            elif choice.lower() == 's':
                import netifaces
                ifaces = netifaces.interfaces()
                default = disc.default_interface()
                c.print(f'[grey50]  Available: {", ".join(ifaces[:8])}...[/]' if len(ifaces) > 8 else f'[grey50]  Available: {", ".join(ifaces)}[/]')
                sel = Prompt.ask('[bold cyan]Select interface[/]',
                                 default=default or (ifaces[0] if ifaces else ''))
                if sel in ifaces:
                    return sel
                # Partial match
                for iface in ifaces:
                    if sel in iface:
                        return iface
                c.print(f'[red]Interface [bold]{sel}[/] not found[/]')
                return default or (ifaces[0] if ifaces else None)
        else:
            Prompt.ask('[grey50]Enter to return[/]')

        return None

    def _pick_interface(self, prompt: str = 'Interface') -> str:
        """Show interface browser, then let user pick. Returns interface name."""
        c = self.console
        disc = InterfaceDiscovery()
        default = disc.default_interface()

        import netifaces
        ifaces = netifaces.interfaces()

        # Free-form input — type an interface name, 'browse', or 'list'
        c.print(f'[grey50]  (type interface name, "browse", or "list")[/]')
        choice = Prompt.ask(f'[cyan]{prompt}[/]', default=default or (ifaces[0] if ifaces else ''))

        if choice.lower() == 'browse':
            sel = self._browse_interfaces(allow_select=True)
            return sel or default or (ifaces[0] if ifaces else '')
        if choice.lower() == 'list':
            show_all = self._browse_interfaces(allow_select=False)
            c.print()
            choice2 = Prompt.ask(f'[cyan]{prompt}[/]', default=default or (ifaces[0] if ifaces else ''))
            if choice2.lower() == 'browse':
                sel = self._browse_interfaces(allow_select=True)
                return sel or default or (ifaces[0] if ifaces else '')
            if choice2 in ifaces:
                return choice2
            # Partial match
            for iface in ifaces:
                if choice2 in iface:
                    return iface
            c.print(f'[red]Interface [bold]{choice2}[/] not found, using default[/]')
            return default or (ifaces[0] if ifaces else '')

        # Direct name — validate
        if choice in ifaces:
            return choice
        # Partial match
        for iface in ifaces:
            if choice in iface:
                return iface
        c.print(f'[red]Interface [bold]{choice}[/] not found, using default[/]')
        return default or (ifaces[0] if ifaces else '')

    # ─── Main Menu ────────────────────────────────────────
    def main_menu(self) -> Optional[str]:
        c = self.console
        while self.running:
            c.clear()

            # ── Compact header ──
            art = _fig('M . S . J', font=MENU_FONT, width=self._w)
            header = Text()
            header.append(art, style='bold bright_cyan')
            header.append(f'  v{__version__} · {__creator__} · Network Suite\n', style='yellow')
            c.print(Panel(Align.center(header), border_style='bright_cyan',
                           box=box.ROUNDED, padding=(0, 1)))

            # ── Mode grid — compact 3-column ──
            modes = [
                ('1', '📡 LIVE', 'green', 'Real-time packet sniffing with Rich TUI'),
                ('2', '🎭 MITM', 'red', 'ARP + DNS spoofing attack suite'),
                ('3', '📂 PCAP', 'yellow', 'Offline analysis of capture files'),
                ('4', '🔑 CRED', 'magenta', 'Passive credential harvesting'),
                ('5', '🔍 SCAN', 'blue', 'Host discovery + recon'),
                ('6', '🧪 TEST', 'cyan', 'Full diagnostic suite'),
            ]

            # 3-column grid
            grid = Table.grid(padding=(0, 1), pad_edge=True)
            grid.add_column(ratio=1); grid.add_column(ratio=1); grid.add_column(ratio=1)

            row = []
            for key, title, color, hint in modes:
                content = Text()
                content.append(f' [{key}] ', style=f'bold white on {color}')
                content.append(f' {title} ', style=f'bold white')
                content.append(f'\n  ', style='grey30')
                content.append(hint, style='grey70')
                pnl = Panel(content, border_style=color, box=box.ROUNDED, padding=(0, 1))
                row.append(pnl)
                if len(row) == 3:
                    grid.add_row(*row); row = []

            c.print(grid)
            c.print()

            # ── Footer ──
            foot = Text.assemble(
                (' [Q] Quit  ', 'bold red'),
                (' [1-6] Select mode  ', 'grey50'),
                (' [7] Config  ', 'grey50'),
            )
            c.print(Panel(foot, border_style='grey35', box=box.ROUNDED, padding=(0, 1)))

            # ── Input ──
            choice = Prompt.ask('[bold cyan]Select[/]', 
                                choices=['1','2','3','4','5','6','7','q','Q'],
                                default='1', show_choices=False)

            if choice.lower() == 'q':
                self.running = False; return None
            elif choice == '7':
                self._config_menu(); continue
            else:
                mp = {'1':'live','2':'mitm','3':'offline','4':'harvest','5':'scan','6':'test'}
                sel = mp.get(choice)
                if sel == 'test':
                    self.tools_test(); continue
                self.selected_mode = sel; return sel
        return None

    # ─── Config Menu ──────────────────────────────────────
    def _config_menu(self):
        c = self.console; c.clear()
        art = _fig('CONFIG', font=SUB_FONT, width=self._w)
        c.print(Panel(Align.center(Text(art, style='bold grey70')),
                       border_style='grey50', box=box.ROUNDED))
        c.print()
        tbl = Table(box=box.SIMPLE); tbl.add_column('Setting', style='cyan')
        tbl.add_column('Value', style='white'); tbl.add_column('Desc', style='grey50')
        tbl.add_row('backend', 'scapy', 'Capture backend'); tbl.add_row('promisc', 'true', 'Promiscuous mode')
        tbl.add_row('output_dir', '.', 'Export directory'); tbl.add_row('iface', 'auto', 'Default interface')
        c.print(Panel(tbl, title='Current Settings', border_style='cyan', box=box.ROUNDED))
        c.print()
        # View or pick interface
        sel = self._pick_interface(prompt='Interface (type name or "browse")')
        if sel:
            c.print(Panel(f'[green]Selected:[/] [bold]{sel}[/]', border_style='green'))
        c.print(); Prompt.ask('[grey50]Enter to return[/]')

    # ─── Mode Config Submenus ─────────────────────────────
    def configure_mode(self, mode: str) -> dict:
        if mode == 'live':    return self._cfg_live()
        if mode == 'mitm':    return self._cfg_mitm()
        if mode == 'offline': return self._cfg_offline()
        if mode == 'harvest': return self._cfg_harvest()
        if mode == 'scan':    return self._cfg_scan()
        return {}

    def _cfg_live(self) -> dict:
        c = self.console; c.clear()
        art = _fig('LIVE', font=SUB_FONT, width=self._w)
        c.print(Panel(Align.center(Text(art, style='bold bright_green')),
                       border_style='bright_green', box=box.ROUNDED))
        c.print()
        iface = self._pick_interface(prompt='Interface (type name or "browse")')
        flt   = Prompt.ask('[cyan]BPF Filter[/]', default='')
        be    = Prompt.ask('[cyan]Backend[/]', choices=['scapy','raw'], default='scapy')
        c.print()
        ep = Confirm.ask('[yellow]Export PCAP?[/]', default=False)
        ej = Confirm.ask('[yellow]Export JSON?[/]', default=False)
        ec = Confirm.ask('[yellow]Export CSV?[/]', default=False)
        prefix = ''
        if ep or ej or ec:
            prefix = Prompt.ask('[yellow]Prefix[/]', default='msj_capture')
        lim = IntPrompt.ask('[cyan]Packet limit[/] (0=∞)', default=0)
        return {
            'interface': iface, 'filter': flt or None, 'backend': be,
            'export_pcap': f'{prefix}.pcap' if ep else None,
            'export_json': f'{prefix}.json' if ej else None,
            'export_csv':  f'{prefix}.csv'  if ec else None,
            'packets': lim
        }

    def _cfg_mitm(self) -> dict:
        c = self.console; c.clear()
        art = _fig('MITM', font=SUB_FONT, width=self._w)
        c.print(Panel(Align.center(Text(art, style='bold red')),
                       border_style='red', box=box.ROUNDED))
        c.print()
        if os.geteuid() != 0:
            c.print(Panel('[red bold]MITM needs root — run with sudo[/]', border_style='red', box=box.ROUNDED))
            Prompt.ask('[grey50]Enter to return[/]'); return {'_cancel': True}
        iface = self._pick_interface(prompt='Interface (type name or "browse")')
        target  = Prompt.ask('[cyan]Target IP[/]')
        gateway = Prompt.ask('[cyan]Gateway IP[/]')
        dns = {}
        if Confirm.ask('[yellow]DNS spoofing?[/]', default=False):
            c.print('[grey50]domain=ip (empty to finish)[/]')
            while True:
                r = Prompt.ask('[yellow]  Rule[/]', default='')
                if not r: break
                if '=' in r:
                    dom, ip = r.split('=', 1); dns[dom.strip()] = ip.strip()
                    c.print(f'  [green]+ {dom.strip()} → {ip.strip()}[/]')
        return {
            'interface': iface, 'target': target, 'gateway': gateway,
            'dns_spoof': ','.join(f'{k}={v}' for k,v in dns.items()) if dns else None
        }

    def _cfg_offline(self) -> dict:
        c = self.console; c.clear()
        art = _fig('PCAP', font=SUB_FONT, width=self._w)
        c.print(Panel(Align.center(Text(art, style='bold yellow')),
                       border_style='bright_yellow', box=box.ROUNDED))
        c.print()
        while True:
            path = Prompt.ask('[cyan]PCAP file path[/]')
            if os.path.exists(path): break
            c.print(f'[red]Not found: {path}[/]')
            if not Confirm.ask('[yellow]Retry?[/]', default=True): return {'_cancel': True}
        return {'pcap': path}

    def _cfg_harvest(self) -> dict:
        c = self.console; c.clear()
        art = _fig('HARVEST', font=SUB_FONT, width=self._w)
        c.print(Panel(Align.center(Text(art, style='bold magenta')),
                       border_style='bright_magenta', box=box.ROUNDED))
        c.print()
        iface = self._pick_interface(prompt='Interface (type name or "browse")')
        out   = Prompt.ask('[yellow]Output prefix[/]', default='msj_creds')
        return {'interface': iface, 'output': out, 'backend': 'scapy'}

    def _cfg_scan(self) -> dict:
        c = self.console; c.clear()
        art = _fig('SCAN', font=SUB_FONT, width=self._w)
        c.print(Panel(Align.center(Text(art, style='bold blue')),
                       border_style='bright_blue', box=box.ROUNDED))
        c.print()
        iface = self._pick_interface(prompt='Interface (type name or "browse")')
        return {'interface': iface}

    # ─── Diagnostic Test Suite ────────────────────────────
    def tools_test(self):
        c = self.console; c.clear()
        art = _fig('TOOLS TEST', font=SUB_FONT, width=self._w)
        c.print(Panel(Align.center(Text(art, style='bold cyan')),
                       border_style='bright_cyan', box=box.ROUNDED))
        c.print(); c.print('[yellow]Running diagnostic suite...[/]'); c.print()

        results = []; all_ok = True

        def run_test(name: str, func: Callable):
            nonlocal all_ok
            try:
                r = func()
                ok = r if isinstance(r, bool) else True
                results.append((name, 'PASS' if ok else 'FAIL', 'bright_green' if ok else 'bright_red'))
                if not ok: all_ok = False
            except Exception as e:
                results.append((name, f'ERROR: {e}', 'bright_red')); all_ok = False

        with Progress(SpinnerColumn('dots','cyan'), TextColumn('{task.description}'),
                      BarColumn(style='cyan', complete_style='green'), console=c) as prog:
            task = prog.add_task('[cyan]Testing...', total=100)

            # 1. Imports
            def t_imports():
                from modules.capture import CaptureEngine
                from modules.dissect import dissect_packet, PacketInfo, tcp_flags_to_str
                from modules.filter import PacketFilter
                from modules.export import PCAPExporter, JSONExporter, CSVExporter, HexDumpExporter, TXTLogExporter, MultiExporter
                from modules.display import SnifferDisplay, PacketPrinter
                from modules.analyze import TCPStreamFollower, ConversationTracker, BandwidthMonitor, AnomalyDetector
                from modules.creds import CredentialHarvester, Credential
                return True
            run_test('All imports', t_imports); prog.update(task, advance=10)

            # 2. Capture engine
            prog.update(task, description='[cyan]Capture engine...')
            run_test('CaptureEngine init', lambda: bool(CaptureEngine(backend='scapy').get_stats()))
            prog.update(task, advance=10)

            # 3. Protocol dissectors
            prog.update(task, description='[cyan]Dissectors...')
            def t_tcp():
                from scapy.all import IP, TCP, Ether
                pkt = Ether()/IP(src='1.1.1.1',dst='2.2.2.2')/TCP(sport=80,dport=12345,flags='S')
                info = dissect_packet(pkt)
                return info and info.protocol == 'TCP'
            run_test('TCP dissect', t_tcp)

            def t_http():
                from scapy.all import IP, TCP, Ether, Raw
                pkt = Ether()/IP(src='1.1.1.1',dst='2.2.2.2')/TCP(sport=40000,dport=80,flags='PA')/Raw(load=b'GET / HTTP/1.1\r\nHost: x.com\r\n\r\n')
                info = dissect_packet(pkt)
                return info and info.protocol == 'HTTP' and info.http_method == 'GET'
            run_test('HTTP dissect', t_http)

            def t_dns():
                from scapy.all import IP, UDP, Ether, DNS, DNSQR
                pkt = Ether()/IP()/UDP(sport=54321,dport=53)/DNS(id=1,qr=0,qd=DNSQR(qname='test.com'))
                info = dissect_packet(pkt)
                return info and info.protocol == 'DNS'
            run_test('DNS dissect', t_dns)

            def t_arp():
                from scapy.all import Ether, ARP
                pkt = Ether()/ARP(op=1,psrc='10.0.0.1',pdst='10.0.0.2')
                info = dissect_packet(pkt)
                return info and info.protocol == 'ARP'
            run_test('ARP dissect', t_arp)
            prog.update(task, advance=15)

            # 4. Filters
            prog.update(task, description='[cyan]Filter engine...')
            def t_filter():
                f = PacketFilter(); f.add_rule('protocol','==','TCP')
                return f.matches(PacketInfo(protocol='TCP')) and not f.matches(PacketInfo(protocol='UDP'))
            run_test('Basic filter', t_filter)
            prog.update(task, advance=5)

            # 5. Exporters
            prog.update(task, description='[cyan]Export engines...')
            def t_pcap():
                import tempfile
                from scapy.all import IP, TCP, Ether
                pkt = Ether()/IP()/TCP()
                f = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False); f.close()
                exp = PCAPExporter(f.name); exp.write(pkt); exp.close()
                ok = os.path.getsize(f.name) > 0; os.unlink(f.name); return ok
            run_test('PCAP export', t_pcap)

            def t_json():
                import tempfile
                f = tempfile.NamedTemporaryFile(suffix='.json', delete=False); f.close()
                exp = JSONExporter(f.name); exp.open(); exp.write(PacketInfo(id=1,protocol='TCP')); exp.close()
                ok = os.path.getsize(f.name) > 0; os.unlink(f.name); return ok
            run_test('JSON export', t_json)

            def t_csv():
                import tempfile
                f = tempfile.NamedTemporaryFile(suffix='.csv', delete=False); f.close()
                exp = CSVExporter(f.name); exp.open(); exp.write(PacketInfo(id=1,protocol='UDP')); exp.close()
                ok = os.path.getsize(f.name) > 0; os.unlink(f.name); return ok
            run_test('CSV export', t_csv)

            def t_multi():
                import tempfile
                from scapy.all import IP, TCP, Ether
                f1 = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False); f1.close()
                f2 = tempfile.NamedTemporaryFile(suffix='.txt', delete=False); f2.close()
                m = MultiExporter(); m.add(PCAPExporter(f1.name)); m.add(TXTLogExporter(f2.name))
                pkt = Ether()/IP()/TCP(); m.write(pkt, PacketInfo(id=1,protocol='TCP')); m.close()
                ok = os.path.getsize(f1.name) > 0; os.unlink(f1.name); os.unlink(f2.name); return ok
            run_test('Multi export', t_multi)
            prog.update(task, advance=15)

            # 6. Analysis
            prog.update(task, description='[cyan]Analysis...')
            run_test('TCPStreamFollower', lambda: isinstance(TCPStreamFollower().stats(), dict))
            def t_convo():
                ct = ConversationTracker(); ct.feed(PacketInfo(protocol='TCP',src_ip='1.1.1.1',dst_ip='2.2.2.2',length=100))
                return len(ct.conversations) == 1
            run_test('ConversationTracker', t_convo)
            run_test('BandwidthMonitor', lambda: isinstance(BandwidthMonitor(window=2).get_protocol_rates(), dict))
            run_test('AnomalyDetector', lambda: isinstance(AnomalyDetector().check_alerts(), list))
            prog.update(task, advance=10)

            # 7. Credentials
            prog.update(task, description='[cyan]Credential harvester...')
            run_test('CredHarvester init', lambda: CredentialHarvester().get_stats()['total'] == 0)
            def t_auth():
                h = CredentialHarvester()
                auth = base64.b64encode(b'testuser:testpass').decode()
                creds = h.analyze(PacketInfo(protocol='HTTP', payload_text=f'Authorization: Basic {auth}'))
                return any(c.type == 'basic_auth' for c in creds)
            run_test('Basic Auth', t_auth)
            def t_post():
                h = CredentialHarvester()
                creds = h.analyze(PacketInfo(protocol='HTTP', http_method='POST',
                    http_payload='user=admin&pass=secret', http_host='x.com'))
                return any(c.type == 'http_form' for c in creds)
            run_test('HTTP POST', t_post)
            def t_api():
                h = CredentialHarvester()
                creds = h.analyze(PacketInfo(protocol='HTTP', payload_text='GET /?key=sk-abc123 HTTP/1.1'))
                return any(c.type == 'api_key' for c in creds)
            run_test('API key', t_api)
            def t_jwt():
                h = CredentialHarvester()
                jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc'
                creds = h.analyze(PacketInfo(protocol='HTTP', payload_text=f'Bearer {jwt}'))
                return any(c.type == 'jwt' for c in creds)
            run_test('JWT', t_jwt)
            def t_cc():
                h = CredentialHarvester()
                creds = h.analyze(PacketInfo(protocol='TCP', payload_text='4111-1111-1111-1111'))
                return any(c.type == 'cc_number' for c in creds)
            run_test('Credit card', t_cc)
            prog.update(task, advance=15)

            # 8. MITM
            prog.update(task, description='[cyan]MITM module...')
            run_test('MITMConfig', lambda: MITMConfig(interface='eth0',target_ip='10.0.0.1',gateway_ip='10.0.0.254').target_ip == '10.0.0.1')
            def t_dns_s():
                d = DNSSpoofer(spoof_table={'test.com':'10.0.0.1'})
                return d._matches('test.com') == '10.0.0.1'
            run_test('DNSSpoofer', t_dns_s)
            def t_dns_w():
                d = DNSSpoofer(spoof_table={'*.x.com':'10.0.0.5'})
                return d._matches('sub.x.com') == '10.0.0.5'
            run_test('DNS wildcard', t_dns_w)
            prog.update(task, advance=10)

            # 9. Display
            prog.update(task, description='[cyan]Display...')
            run_test('SnifferDisplay', lambda: SnifferDisplay().max_feed == 500)
            run_test('PacketPrinter', lambda: PacketPrinter().packet_count == 0)
            prog.update(task, advance=10)

            prog.update(task, description='[green]Complete!', completed=100)

        # ── Results ──
        c.print(); c.print(Rule('Results', style='bright_cyan')); c.print()
        tbl = Table(box=box.ROUNDED, border_style='grey50', padding=(0,1))
        tbl.add_column('#', style='grey50', width=3)
        tbl.add_column('Test', style='white'); tbl.add_column('Result', style='bold')
        passed = 0; total = 0
        for i,(name,res,style) in enumerate(results,1):
            icon = '✓' if res == 'PASS' else '✗'
            clr = 'bright_green' if res == 'PASS' else 'bright_red'
            if res == 'PASS': passed += 1; total += 1
            elif res.startswith('ERROR'): total += 1
            else: total += 1
            tbl.add_row(str(total), name, f'[{clr}]{icon} {res}[/]')
        c.print(tbl); c.print()

        fail = total - passed
        c.print(Panel(
            Text.assemble(
                f'\n  ✓ {passed}/{total} passed',
                f'\n  ✗ {fail} failed' if fail > 0 else '\n  ✗ 0 failures',
                f'\n  {"ALL SYSTEMS OK" if all_ok else "ISSUES DETECTED"}\n'
            ),
            title='Summary',
            border_style='bright_green' if all_ok else 'bright_red', box=box.ROUNDED
        ))
        c.print()
        try: Prompt.ask('[grey50]Enter to return[/]')
        except: pass
        return all_ok


# ─── Quick Test Runner ────────────────────────────────────────
class TestRunner:
    @staticmethod
    def run_all(console=None, interactive=False) -> bool:
        return MenuHUD(console).tools_test()

    @staticmethod
    def quick_check() -> bool:
        try:
            import pyfiglet
            from rich.console import Console
            from modules.capture import CaptureEngine
            from modules.dissect import dissect_packet, PacketInfo
            from modules.filter import PacketFilter
            from modules.export import PCAPExporter, JSONExporter, CSVExporter
            from modules.display import SnifferDisplay
            from modules.analyze import TCPStreamFollower, ConversationTracker
            from modules.creds import CredentialHarvester
            from modules.mitm import MITMConfig, DNSSpoofer, ConnectionHijacker
            return True
        except ImportError:
            return False
