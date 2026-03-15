# alexa-attack

> **Educational use only.**  All tests documented here were performed on
> equipment I own in an isolated lab environment.  Do **not** run this tool
> on networks or devices you do not own or have explicit written permission
> to test.

---

## Overview

`Alexa_ARP_MITM.py` is a Python 3 tool that demonstrates a classic
ARP-cache-poisoning (man-in-the-middle) attack between an Amazon Echo
(Alexa) device and its default gateway.  Once in place, all traffic is
forwarded through the host running the script and saved to a `.pcap` file
for later analysis.  Optionally, the script can drop Alexa's outbound
Internet traffic via an `iptables` rule.

### What it does

1. **ARP poisoning** – sends gratuitous ARP replies to both the Alexa
   device and the gateway, redirecting their traffic through this host.
2. **Packet capture** – writes every intercepted packet to a PCAP file
   that can be opened in Wireshark or analysed with `tshark`.
3. **Optional Internet block** – installs an `iptables FORWARD DROP` rule
   so Alexa cannot reach the Internet while the attack is active.
4. **Graceful cleanup** – on `Ctrl-C` or `SIGTERM` the script restores
   both ARP caches, removes the iptables rule, and disables IP forwarding.

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | Tested on 3.11 |
| [Scapy](https://scapy.net/) | `pip install scapy` |
| Linux with `iptables` | Tested on Kali / Ubuntu |
| `sudo` / root | Required for raw-socket access |

```bash
pip install scapy
```

---

## Usage

```
sudo python3 Alexa_ARP_MITM.py [OPTIONS]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--alexa-ip IP` | `172.20.10.14` | IP address of the Alexa device |
| `--gateway-ip IP` | `172.20.10.1` | IP address of the default gateway |
| `--interface`, `-i` | `wlan0` | Network interface for spoofing & sniffing |
| `--pcap FILE` | `alexa_mitm.pcap` | Output file for captured packets |
| `--no-drop` | *(not set)* | Skip the iptables Internet-block rule |
| `--spoof-interval SEC` | `2.0` | Seconds between ARP spoof packets |
| `--verbose`, `-v` | *(not set)* | Enable debug-level log output |

### Examples

**Basic run with default IPs:**
```bash
sudo python3 Alexa_ARP_MITM.py
```

**Custom IPs and interface:**
```bash
sudo python3 Alexa_ARP_MITM.py \
    --alexa-ip 192.168.1.50 \
    --gateway-ip 192.168.1.1 \
    --interface eth0 \
    --pcap capture.pcap
```

**Capture only (do not drop Internet traffic):**
```bash
sudo python3 Alexa_ARP_MITM.py --no-drop
```

**Show all available options:**
```bash
python3 Alexa_ARP_MITM.py --help
```

---

## How to inspect captured traffic

```bash
# Live summary while the attack is running
tshark -r alexa_mitm.pcap

# Open in Wireshark for full protocol dissection
wireshark alexa_mitm.pcap
```

---

## Disclaimer

This repository is for **educational and research purposes only**.
The author is not responsible for any misuse.  Always obtain proper
authorisation before testing any network or device.

