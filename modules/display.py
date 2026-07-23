"""
M.S.J Live Display Engine
===========================
Rich-based terminal UI for real-time packet visualization.

Features:
  - Live scrolling packet feed (color-coded by protocol)
  - Statistics panel (packet counts, bandwidth, protocol breakdown)
  - Connection tracking table
  - Credential alert display
  - Filter input bar
  - MITM status panel
  - Keyboard controls (pause, filter, export, quit)

Creator: M.S.J
"""

import sys
import select
try:
    import termios
    import tty
except ImportError:
    termios = None
    tty = None
import time
import threading
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Optional, List, Tuple, Deque

from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.console import Console, Group
from rich.columns import Columns
from rich import box
from rich.align import Align
from rich.progress import BarColumn, Progress, TextColumn
from rich.style import Style
from rich.syntax import Syntax
from rich.prompt import Prompt

from modules.dissect import PacketInfo
from modules.filter import PacketFilter
from modules.analyze import BandwidthMonitor, ConversationTracker, AnomalyDetector
from modules.creds import CredentialHarvester, Credential


# Protocol color scheme
PROTOCOL_STYLES = {
    'TCP': Style(color='bright_blue'),
    'UDP': Style(color='bright_green'),
    'HTTP': Style(color='bright_yellow'),
    'DNS': Style(color='bright_magenta'),
    'ARP': Style(color='bright_cyan'),
    'ICMP': Style(color='bright_red'),
    'DHCP': Style(color='green'),
    'TLS': Style(color='dark_orange'),
    'FTP': Style(color='orange1'),
    'SMTP': Style(color='purple'),
    'IMAP': Style(color='plum1'),
    'POP3': Style(color='pink1'),
    'SSH': Style(color='grey70'),
    'OTHER': Style(color='grey50'),
    'UNKNOWN': Style(color='grey35'),
}

TAG_STYLES = {
    'http_request': Style(color='yellow'),
    'http_response': Style(color='green'),
    'dns_query': Style(color='magenta'),
    'dns_response': Style(color='bright_magenta'),
    'arp_who-has': Style(color='cyan'),
    'arp_is-at': Style(color='bright_cyan'),
    'syn': Style(color='red'),
    'tcp': Style(color='blue'),
    'tls_client_hello': Style(color='dark_orange'),
    'credential': Style(color='red', bold=True),
    'alert': Style(color='red', bold=True, reverse=True),
}


class SnifferDisplay:
    """
    Rich-based live packet display. Runs in its own thread.

    Layout:
    ┌──────────────────────────────────────────────────┐
    │  Packet Feed (scrolls)          │ Stats Panel    │
    │                                  │                │
    │  [1] TCP 192.168.1.1:80 -> ...   │ Packets: 1,234 │
    │  [2] DNS query: google.com       │ Bandwidth: ... │
    │  [3] HTTP GET /index.html        │                │
    │  ...                             │ Connections    │
    │                                  │ Alerts         │
    ├──────────────────────────────────────────────────┤
    │  Filter: [________________]  Status: RUNNING     │
    └──────────────────────────────────────────────────┘
    """

    def __init__(self, console: Console = None, max_feed: int = 500):
        self.console = console or Console()
        self.max_feed = max_feed

        # Packet storage
        self.packet_feed: Deque[Tuple[PacketInfo, str]] = deque(maxlen=max_feed)
        self._feed_lock = threading.Lock()

        # Modules
        self.bandwidth = BandwidthMonitor(window=5)
        self.conversations = ConversationTracker()
        self.anomaly = AnomalyDetector()
        self.cred_harvester = CredentialHarvester()
        self.captured_creds: Deque[Credential] = deque(maxlen=50)

        # State
        self.filter_str = ''
        self.filter_obj = PacketFilter()
        self.paused = False
        self.packet_count = 0
        self._stats_cache = {}
        self._update_interval = 0.5  # seconds
        self._last_update = 0
        self._capture_start = 0.0     # set when run() begins — drives live uptime counter
        self._live: Optional[Live] = None
        self.status_text = 'INITIALIZING'
        self.status_style = Style(color='yellow')

        # MITM status display
        self.mitm_active = False
        self.mitm_target = ''
        self.mitm_gateway = ''
        self.mitm_packets_spoofed = 0

        # Credential callback
        self.cred_harvester.on_credential(self._on_credential)

        # ── Keyboard input state ──
        self._quit_requested = False
        self._filter_mode = False       # True when user is typing a filter string
        self._filter_buffer = ''        # Accumulated keystrokes during filter input
        self._active = False            # True while run() is displaying (block add_packet on shutdown)
        self._fd = sys.stdin.fileno()
        self._old_term = None
        self._input_enabled = True      # Falls back to False if terminal can't do raw mode

    def _on_credential(self, cred: Credential):
        """Callback when credential is harvested."""
        self.captured_creds.append(cred)

    def add_packet(self, pkt, info: PacketInfo):
        """Add a packet to the display queue."""
        if not self._active:
            return
        if self.paused:
            return

        if not info:
            return

        # Apply filter
        if self.filter_str and not self.filter_obj.matches(info):
            return

        self.packet_count += 1

        # Feed analysis modules
        self.conversations.feed(info)
        self.bandwidth.feed(info)
        self.anomaly.feed(info)

        # Check for credentials
        creds = self.cred_harvester.analyze(info)
        has_cred = len(creds) > 0

        # Format packet summary
        summary = info.summary()

        # Protocol coloring
        style = PROTOCOL_STYLES.get(info.protocol, PROTOCOL_STYLES['OTHER'])
        styled_summary = Text(summary, style=style)

        # Add credential marker
        if has_cred:
            styled_summary = Text('[!] ', style=Style(color='red', bold=True)) + styled_summary

        # Check for alerts
        alerts = self.anomaly.check_alerts()

        with self._feed_lock:
            self.packet_feed.append((info, styled_summary))

        if alerts:
            for alert in alerts:
                alert_text = Text(
                    f"[ALERT][{alert['severity']}] {alert['msg']}",
                    style=TAG_STYLES.get('alert', Style(color='red', bold=True))
                )
                with self._feed_lock:
                    self.packet_feed.append((None, alert_text))

    def _build_layout(self) -> Layout:
        """Build the main layout."""
        layout = Layout()

        layout.split_column(
            Layout(name='main', ratio=4),
            Layout(name='footer', ratio=1)
        )

        layout['main'].split_row(
            Layout(name='feed', ratio=3),
            Layout(name='sidebar', ratio=1)
        )

        return layout

    def _render_feed(self) -> Panel:
        """Render the live packet feed panel."""
        with self._feed_lock:
            # Show last N packets (scroll follows bottom)
            items = list(self.packet_feed)
            display_items = items[-min(self.max_feed, 50):]

        if not display_items:
            content = Text("Waiting for packets...", style='grey50')
        else:
            content = Group(*[item[1] for item in display_items])

        title = f"📡 Packet Feed ({'PAUSED' if self.paused else 'LIVE'}) [{len(display_items)} shown]"

        return Panel(
            content,
            title=title,
            border_style='bright_blue' if not self.paused else 'yellow',
            box=box.ROUNDED,
            padding=(0, 1)
        )

    def _render_stats(self) -> Panel:
        """Render the statistics sidebar."""
        stats = self._stats_cache
        now = time.time()

        # Update stats cache periodically
        if now - self._last_update > self._update_interval:
            stats = {
                'pkts': self.packet_count,
                'uptime': timedelta(seconds=int(time.time() - self._capture_start)) if self._capture_start else timedelta(0),
                'bw': self.bandwidth.get_formatted_rate(self.bandwidth.get_total_rate()),
                'proto_rates': self.bandwidth.get_protocol_rates(),
            }
            # Get proto counts from capture engine if available
            if hasattr(self, 'engine_stats'):
                stats.update(self.engine_stats)
            self._stats_cache = stats
            self._last_update = now

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column('Key', style='cyan', no_wrap=True)
        table.add_column('Value', style='white')

        table.add_row('Packets', str(stats.get('pkts', 0)))
        table.add_row('Bandwidth', stats.get('bw', '0 B/s'))
        table.add_row('Uptime', str(stats.get('uptime', '0:00:00')))

        # Protocol breakdown
        table.add_section()
        table.add_row('[bold underline]Protocols[/]', '[bold underline]Count[/]')
        for proto in ['TCP', 'UDP', 'HTTP', 'DNS', 'ARP', 'ICMP', 'TLS', 'DHCP']:
            count = stats.get(proto.lower(), 0)
            if count > 0:
                style = PROTOCOL_STYLES.get(proto, Style())
                table.add_row(
                    Text(proto, style=style),
                    str(count)
                )

        # Bandwidth per protocol
        proto_rates = stats.get('proto_rates', {})
        if proto_rates:
            table.add_section()
            table.add_row('[bold underline]BW by Proto[/]', '[bold underline]Rate[/]')
            for proto, rate in sorted(proto_rates.items(), key=lambda x: -x[1])[:5]:
                if rate > 0:
                    bw = self.bandwidth.get_formatted_rate(rate)
                    table.add_row(proto, bw)

        # Credential stats
        cred_stats = self.cred_harvester.get_stats()
        if cred_stats.get('total', 0) > 0:
            table.add_section()
            table.add_row('[bold red underline]Credentials[/]', f'[red]{cred_stats["total"]}[/]')
            for ctype, count in cred_stats.items():
                if count > 0 and ctype != 'total' and count > 0:
                    table.add_row(f'  {ctype}', str(count))

        # MITM status
        if self.mitm_active:
            table.add_section()
            table.add_row('[bold red underline]MITM ACTIVE[/]', '[red]⚠[/]')
            table.add_row('  Target', self.mitm_target)
            table.add_row('  Gateway', self.mitm_gateway)
            table.add_row('  Spoofed', str(self.mitm_packets_spoofed))

        return Panel(
            Align.center(table),
            title='📊 Statistics',
            border_style='bright_green',
            box=box.ROUNDED,
            padding=(0, 1)
        )

    def _render_creds(self) -> Panel:
        """Render recent credential captures panel."""
        if not self.captured_creds:
            return Panel(
                Text("No credentials captured yet", style='grey50'),
                title='🔑 Credentials',
                border_style='red',
                box=box.ROUNDED
            )

        content = []
        for cred in list(self.captured_creds)[-10:]:
            text = Text()
            text.append(f"[{cred.type}] ", style='red bold')
            if cred.hostname:
                text.append(f"{cred.hostname} ", style='yellow')
            if cred.username:
                text.append(f"{cred.username}:", style='bright_white')
                text.append(f"{cred.password}", style='bright_red')
            if not cred.username and cred.raw_data:
                text.append(f"{cred.raw_data[:60]}", style='grey70')
            content.append(text)

        return Panel(
            Group(*content),
            title=f'🔑 Credentials ({len(self.captured_creds)})',
            border_style='red',
            box=box.ROUNDED
        )

    def _render_alerts(self) -> Panel:
        """Render anomaly alerts panel."""
        alerts = self.anomaly.get_alerts(5)
        if not alerts:
            return Panel(
                Text("No anomalies detected", style='grey50'),
                title='🚨 Alerts',
                border_style='bright_red',
                box=box.ROUNDED
            )

        content = []
        for alert in reversed(alerts):
            severity_style = {
                'LOW': Style(color='yellow'),
                'MEDIUM': Style(color='orange1'),
                'HIGH': Style(color='red'),
                'CRITICAL': Style(color='red', bold=True, reverse=True),
            }.get(alert['severity'], Style(color='white'))

            text = Text()
            text.append(f"[{alert['severity']}] ", style=severity_style)
            text.append(alert['msg'][:80], style='white')
            content.append(text)

        return Panel(
            Group(*content),
            title=f'🚨 Alerts ({len(alerts)})',
            border_style='bright_red',
            box=box.ROUNDED
        )

    def _render_sidebar(self) -> Group:
        """Render the full sidebar (stats + creds + alerts)."""
        return Group(
            self._render_stats(),
            self._render_creds(),
            self._render_alerts()
        )

    def _render_footer(self) -> Panel:
        """Render the footer with filter and status."""
        status_color = {
            'RUNNING': 'green',
            'PAUSED': 'yellow',
            'STOPPED': 'red',
            'ERROR': 'red bold',
            'INITIALIZING': 'yellow'
        }.get(self.status_text.split(':')[0].strip(), 'white')

        text = Text()
        if self._filter_mode:
            text.append(f" Filter: ", style='cyan bold')
            text.append(f"{self._filter_buffer}_", style='yellow bold')
            text.append(f"  [Enter] apply  [Esc] cancel", style='grey70')
        else:
            text.append(f" Filter: ", style='cyan bold')
            filter_display = self.filter_str if self.filter_str else '(none - show all)'
            text.append(filter_display, style='yellow')
        text.append(f"  │  Status: {self.status_text}", style=status_color)
        text.append(f"  │  Packets: {self.packet_count}", style='green')
        text.append(f"  │  [Q]uit [P]ause [F]ilter [C]lear", style='grey50')

        return Panel(
            text,
            border_style='grey50',
            box=box.HORIZONTALS,
            padding=(0, 1)
        )

    # ── Terminal raw-mode helpers ──────────────────────────
    def _set_raw_mode(self):
        """Switch terminal to raw (character-at-a-time, no echo) for keyboard input."""
        if not sys.stdin.isatty() or termios is None or tty is None:
            self._input_enabled = False
            return
        try:
            self._old_term = termios.tcgetattr(self._fd)
            tty.setraw(self._fd)
        except Exception:
            self._input_enabled = False

    def _restore_term(self):
        """Restore original terminal settings."""
        if self._old_term is not None and termios is not None:
            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_term)
            except Exception:
                pass
            self._old_term = None

    # ── Keyboard input ─────────────────────────────────────
    def _check_input(self) -> bool:
        """Non-blocking check for a keypress on stdin. Returns True if quit was triggered."""
        if not self._input_enabled:
            return False
        try:
            if select.select([sys.stdin], [], [], 0)[0]:
                ch = sys.stdin.read(1)
                return self._process_key(ch)
        except (OSError, ValueError, IOError):
            self._input_enabled = False
        return False

    def _process_key(self, key: str) -> bool:
        """Route a single keypress. Returns True if the run() loop should exit."""
        # ── Filter-input mode: collect characters, Enter = apply, Esc = cancel ──
        if self._filter_mode:
            if key in ('\r', '\n'):                         # Enter — apply filter
                self._apply_filter()
                self._filter_mode = False
                self._filter_buffer = ''
                self.status_text = 'RUNNING' if not self.paused else 'PAUSED'
            elif key == '\x1b':                              # Escape — cancel
                self._filter_mode = False
                self._filter_buffer = ''
                self.status_text = 'RUNNING' if not self.paused else 'PAUSED'
            elif key in ('\x7f', '\b', '\x08'):              # Backspace
                self._filter_buffer = self._filter_buffer[:-1]
                self.status_text = f'FILTER: {self._filter_buffer}_'
            elif len(key) == 1 and ord(key) >= 32:           # Printable
                self._filter_buffer += key
                self.status_text = f'FILTER: {self._filter_buffer}_'
            return False

        # ── Normal mode ──
        if key.lower() == 'q' or key == '\x1b':              # q or Esc = quit
            self._quit_requested = True
            return True
        elif key.lower() == 'p' or key == ' ':               # p or Space = toggle pause
            self.paused = not self.paused
            self.status_text = 'PAUSED' if self.paused else 'RUNNING'
        elif key.lower() == 'f':                             # f = enter filter-input mode
            self._filter_mode = True
            self._filter_buffer = ''
            self.status_text = 'FILTER: _'
        elif key.lower() == 'c':                             # c = clear feed + filter
            with self._feed_lock:
                self.packet_feed.clear()
            self.captured_creds.clear()
            self.anomaly = AnomalyDetector()
            self.filter_str = ''
            self.filter_obj.clear()
            self.status_text = 'RUNNING' if not self.paused else 'PAUSED'
        return False

    def _apply_filter(self):
        """Parse the accumulated filter buffer into a PacketFilter and apply it."""
        raw = self._filter_buffer.strip()
        self.filter_str = raw
        if raw:
            self.filter_obj = PacketFilter.parse_bpf(raw)
        else:
            self.filter_obj.clear()

    def process_input(self, key: str):
        """Public API — kept for external callers. Delegates to _process_key."""
        return self._process_key(key)

    # ── Main display loop ─────────────────────────────────
    def run(self, stop_event: threading.Event = None):
        """
        Run the Rich Live display loop in the current thread.
        Blocks until the user presses 'q', Escape, or stop_event is set.
        """
        self._active = True
        self._capture_start = time.time()
        self._quit_requested = False
        self.status_text = 'RUNNING'
        self.status_style = Style(color='green')

        layout = Layout()
        layout.split_column(
            Layout(name='main', ratio=4),
            Layout(name='footer', ratio=1)
        )
        layout['main'].split_row(
            Layout(name='feed', ratio=3),
            Layout(name='sidebar', ratio=1)
        )

        self._set_raw_mode()
        try:
            with Live(layout, console=self.console, refresh_per_second=10, screen=True) as live:
                self._live = live
                while not (stop_event and stop_event.is_set()) and not self._quit_requested:
                    try:
                        layout['feed'].update(self._render_feed())
                        layout['sidebar'].update(self._render_sidebar())
                        layout['footer'].update(self._render_footer())
                    except Exception:
                        pass

                    if self._check_input():
                        if stop_event:
                            stop_event.set()
                        break

                    time.sleep(0.04)

                # Show final state briefly before exiting
                self.status_text = 'STOPPED'
                self.status_style = Style(color='red')
                try:
                    layout['footer'].update(self._render_footer())
                except Exception:
                    pass
        finally:
            self._restore_term()

        self._active = False
        self._live = None

    def stop(self):
        """Stop the display (safety net — Live is already stopped when run() exits)."""
        self._active = False
        self.status_text = 'STOPPED'
        self._quit_requested = True
        if self._live:
            try:
                self._live.stop()
            except Exception:
                pass
        self._live = None


class PacketPrinter:
    """
    Simple text-based packet printer (for non-TUI mode).
    Prints packet summaries to stdout with color.
    """

    def __init__(self, console: Console = None):
        self.console = console or Console()
        self.packet_count = 0
        self.filter_obj = PacketFilter()
        self.filter_str = ''

    def print_packet(self, pkt, info: PacketInfo):
        """Print a single packet to console."""
        if not info:
            return

        if self.filter_str and not self.filter_obj.matches(info):
            return

        self.packet_count += 1
        summary = info.summary()
        style = PROTOCOL_STYLES.get(info.protocol, PROTOCOL_STYLES['OTHER'])
        self.console.print(summary, style=style)

    def print_stats(self, stats: dict):
        """Print capture statistics."""
        table = Table(title='Capture Statistics', box=box.ROUNDED)
        table.add_column('Metric', style='cyan')
        table.add_column('Value', style='white')

        for key, value in stats.items():
            if isinstance(value, (int, float, str)):
                table.add_row(str(key), str(value))

        self.console.print(table)

    def print_credential(self, cred: Credential):
        """Print a captured credential."""
        text = Text()
        text.append(f"[!] CREDENTIAL: ", style='red bold')
        text.append(str(cred), style='yellow')
        self.console.print(text)
