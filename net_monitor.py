#!/usr/bin/env python3
"""
net-monitor — Real-time network traffic & connection monitor
Author : Noxa (Valentin Lagarde)
Usage  : python3 net_monitor.py
         python3 net_monitor.py --connections
         python3 net_monitor.py --interval 2
"""

import argparse
import time
import socket
import os
from datetime import datetime

try:
    import psutil
except ImportError:
    print("[!] psutil not installed. Run: pip install psutil")
    raise SystemExit(1)

SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite backdoor",
    6666: "IRC / backdoor",
    6667: "IRC",
    9001: "Tor relay",
    9050: "Tor SOCKS",
    65535: "Common test port",
}

KNOWN_PROCESSES = {"chrome", "firefox", "python", "python3", "node", "java", "sshd", "nginx", "apache2"}


def bytes_to_human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def get_interface_stats() -> dict:
    counters = psutil.net_io_counters(pernic=True)
    return counters


def get_connections() -> list[dict]:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            entry = {
                "proto":  "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-",
                "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
                "status": c.status,
                "pid":    c.pid,
                "proc":   "",
                "rport":  c.raddr.port if c.raddr else 0,
                "flag":   "",
            }
            if c.pid:
                try:
                    proc = psutil.Process(c.pid)
                    entry["proc"] = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            if entry["rport"] in SUSPICIOUS_PORTS:
                entry["flag"] = f"⚠ {SUSPICIOUS_PORTS[entry['rport']]}"

            conns.append(entry)
    except psutil.AccessDenied:
        print("[!] Run as root/admin for full connection list")
    return conns


def monitor_bandwidth(interval: float, count: int) -> None:
    RED   = "\033[91m"
    GRN   = "\033[92m"
    CYN   = "\033[96m"
    YEL   = "\033[93m"
    DIM   = "\033[37m"
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    prev = psutil.net_io_counters()
    iteration = 0

    print(f"\n{BOLD}{'─'*70}{RESET}")
    print(f"  {'INTERFACE':<20} {'↓ RECV/s':<14} {'↑ SENT/s':<14} {'TOTAL ↓':<14} {'TOTAL ↑'}")
    print(f"{'─'*70}{RESET}")

    while count == 0 or iteration < count:
        time.sleep(interval)
        curr = psutil.net_io_counters()

        recv_rate = (curr.bytes_recv - prev.bytes_recv) / interval
        sent_rate = (curr.bytes_sent - prev.bytes_sent) / interval

        recv_color = RED if recv_rate > 1_000_000 else GRN
        sent_color = RED if sent_rate > 1_000_000 else CYN

        ts = datetime.now().strftime("%H:%M:%S")
        print(
            f"  {DIM}{ts}{RESET}  "
            f"{recv_color}{bytes_to_human(recv_rate):<14}{RESET}"
            f"{sent_color}{bytes_to_human(sent_rate):<14}{RESET}"
            f"{DIM}{bytes_to_human(curr.bytes_recv):<14}{bytes_to_human(curr.bytes_sent)}{RESET}"
        )
        prev = curr
        iteration += 1


def print_connections(conns: list[dict]) -> None:
    RED   = "\033[91m"
    YEL   = "\033[93m"
    GRN   = "\033[92m"
    DIM   = "\033[37m"
    RESET = "\033[0m"

    established = [c for c in conns if c["status"] == "ESTABLISHED"]
    listening   = [c for c in conns if c["status"] == "LISTEN"]
    flagged     = [c for c in conns if c["flag"]]

    print(f"\n  Total connections : {len(conns)}")
    print(f"  Established       : {len(established)}")
    print(f"  Listening         : {len(listening)}")
    if flagged:
        print(f"  {RED}Suspicious ports  : {len(flagged)}{RESET}")

    print(f"\n  {'PROTO':<6} {'LOCAL':<24} {'REMOTE':<24} {'STATUS':<14} {'PROCESS':<16} NOTE")
    print(f"  {'─'*100}")
    for c in sorted(conns, key=lambda x: (x["status"], x["laddr"])):
        color = RED if c["flag"] else (YEL if c["status"] == "LISTEN" else DIM)
        flag  = f"  {RED}{c['flag']}{RESET}" if c["flag"] else ""
        print(
            f"  {color}{c['proto']:<6} {c['laddr']:<24} {c['raddr']:<24} "
            f"{c['status']:<14} {c['proc']:<16}{RESET}{flag}"
        )


def main():
    parser = argparse.ArgumentParser(description="Network traffic & connection monitor (educational)")
    parser.add_argument("--connections", action="store_true", help="Show active connections")
    parser.add_argument("--bandwidth",   action="store_true", help="Monitor bandwidth (default mode)")
    parser.add_argument("--interval",    type=float, default=1.0,  help="Refresh interval in seconds")
    parser.add_argument("--count",       type=int,   default=0,    help="Number of samples (0 = infinite)")
    args = parser.parse_args()

    print(f"[*] Network Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if args.connections:
        print("[*] Fetching active connections ...")
        conns = get_connections()
        print_connections(conns)
    else:
        print(f"[*] Monitoring bandwidth (interval: {args.interval}s) — Ctrl+C to stop\n")
        try:
            monitor_bandwidth(args.interval, args.count)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
