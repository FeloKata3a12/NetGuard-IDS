"""
NetGuard – CLI Entry Point
Run:  sudo python main.py [--iface eth0] [--filter tcp]
"""

import argparse
import datetime
import sys
import threading
import time

from core.detector import IntrusionDetector
from core.logger   import log_alert, log_traffic

try:
    from scapy.all import sniff, conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
}

detector = IntrusionDetector()


def packet_callback(packet):
    traffic, alert = detector.analyze_packet(packet)

    if traffic:
        detector.traffic_log.append(traffic)
        try:
            log_traffic(traffic)
        except Exception:
            pass

    if alert:
        detector.alerts.append(alert)
        detector.blocked_ips.add(alert["src_ip"])
        color = SEVERITY_COLOR.get(alert["severity"], YELLOW)
        ts    = datetime.datetime.now().strftime("%H:%M:%S")
        print(
            f"{color}{BOLD}[{ts}] ⚠  [{alert['severity']}] {alert['type']}"
            f" | {alert['src_ip']} → {alert['dst_ip']}:{alert['port']}"
            f" | {alert['message']}{RESET}"
        )
        try:
            log_alert(alert)
        except Exception:
            pass


def start_sniffing(iface: str, pkt_filter: str):
    print(f"{CYAN}[*] Sniffing on interface: {iface}  filter: \"{pkt_filter}\"{RESET}")
    try:
        sniff(prn=packet_callback, store=False, filter=pkt_filter, iface=iface)
    except PermissionError:
        print(f"{RED}[!] Permission denied – run as root / sudo{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[!] Sniff error: {e}{RESET}")
        sys.exit(1)


def stats_thread():
    """Print a stats line every 30 seconds."""
    while True:
        time.sleep(30)
        s = detector.get_stats()
        print(
            f"{CYAN}[STATS] Packets={s['total_packets']}  "
            f"Alerts={s['total_alerts']}  "
            f"Attackers={s['unique_attackers']}{RESET}"
        )


def main():
    parser = argparse.ArgumentParser(description="NetGuard IDS")
    parser.add_argument("--iface",  default="eth0",       help="Network interface (default: eth0)")
    parser.add_argument("--filter", default="tcp or udp or icmp", help="BPF filter string")
    args = parser.parse_args()

    if not SCAPY_OK:
        print(f"{RED}[!] Scapy is not installed. Run: pip install scapy{RESET}")
        sys.exit(1)

    banner = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════════╗
║        🛡️  NetGuard – Network Intrusion Detection System         ║
║                     Version 2.0  |  by NetGuard                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Detects: SYN Flood · Port Scan · Brute Force                    ║
║           Nmap -sN/-sF/-sX · ICMP Flood · UDP Flood              ║
╚══════════════════════════════════════════════════════════════════╝
{RESET}"""
    print(banner)

    # Stats thread
    t_stats = threading.Thread(target=stats_thread, daemon=True)
    t_stats.start()

    # Sniff (blocking)
    try:
        start_sniffing(args.iface, args.filter)
    except KeyboardInterrupt:
        s = detector.get_stats()
        print(f"\n{GREEN}[+] NetGuard stopped.")
        print(f"    Total packets : {s['total_packets']}")
        print(f"    Total alerts  : {s['total_alerts']}")
        print(f"    Unique attackers: {s['unique_attackers']}{RESET}\n")


if __name__ == "__main__":
    main()
