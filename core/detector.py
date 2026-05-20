"""
NetGuard – Core Intrusion Detector
Handles all attack-detection logic in a thread-safe way.
"""

import time
import threading
from collections import defaultdict, deque
from detection.rules import (
    SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW,
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW,
    BRUTE_FORCE_PORTS, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW,
    NMAP_FIN_FLAGS, NMAP_NULL_FLAGS, NMAP_XMAS_FLAGS,
    ICMP_FLOOD_THRESHOLD, ICMP_FLOOD_WINDOW,
    UDP_FLOOD_THRESHOLD, UDP_FLOOD_WINDOW,
    SEVERITY,
)

try:
    from scapy.all import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class IntrusionDetector:
    """
    Thread-safe IDS engine.
    Call analyze_packet(pkt) for each captured packet.
    All alerts are appended to self.alerts (list of dicts).
    All packets are logged to self.traffic_log.
    """

    def __init__(self):
        self.lock = threading.Lock()

        # ── Per-IP time-windowed counters ─────────────────────────────────────
        # syn_packets[ip]  → deque of timestamps
        self.syn_packets   : dict[str, deque] = defaultdict(deque)
        # port_scan[ip]    → deque of (timestamp, port) tuples
        self.port_scan     : dict[str, deque] = defaultdict(deque)
        # brute_force[ip]  → deque of timestamps
        self.brute_force   : dict[str, deque] = defaultdict(deque)
        # icmp_packets[ip] → deque of timestamps
        self.icmp_packets  : dict[str, deque] = defaultdict(deque)
        # udp_packets[ip]  → deque of timestamps
        self.udp_packets   : dict[str, deque] = defaultdict(deque)

        # ── Shared logs (Dashboard reads these directly) ──────────────────────
        self.alerts      : list[dict] = []
        self.traffic_log : list[dict] = []

        # ── Stats ─────────────────────────────────────────────────────────────
        self.total_packets = 0
        self.blocked_ips   : set[str] = set()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def analyze_packet(self, packet) -> tuple[dict | None, dict | None]:
        """
        Analyse one packet.
        Returns (traffic_entry, alert) — either can be None.
        Caller is responsible for appending to self.alerts / self.traffic_log.
        """
        if not SCAPY_AVAILABLE:
            return None, None

        with self.lock:
            self.total_packets += 1
            now     = time.time()
            alert   = None
            traffic = None

            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst

                # ── TCP ───────────────────────────────────────────────────────
                if TCP in packet:
                    dport = packet[TCP].dport
                    flags = int(packet[TCP].flags)

                    traffic = {
                        "time":   self._ts(), "src": src, "dst": dst,
                        "proto":  "TCP",      "port": dport,
                        "flags":  str(packet[TCP].flags), "length": len(packet),
                    }

                    # 1. Nmap NULL scan
                    if flags == NMAP_NULL_FLAGS:
                        alert = self._make_alert("NMAP_NULL", src, dst, dport,
                                                 "Nmap NULL scan (-sN): no TCP flags")

                    # 2. Nmap FIN scan
                    elif flags == NMAP_FIN_FLAGS:
                        alert = self._make_alert("NMAP_FIN", src, dst, dport,
                                                 "Nmap FIN scan (-sF): only FIN flag set")

                    # 3. Nmap Xmas scan
                    elif flags == NMAP_XMAS_FLAGS:
                        alert = self._make_alert("NMAP_XMAS", src, dst, dport,
                                                 "Nmap Xmas scan (-sX): FIN+PSH+URG")

                    else:
                        # 4. SYN Flood  (SYN set, ACK not set)
                        if (flags & 0x002) and not (flags & 0x010):
                            self._window_add(self.syn_packets[src], now)
                            self._window_expire(self.syn_packets[src], now, SYN_FLOOD_WINDOW)
                            if len(self.syn_packets[src]) >= SYN_FLOOD_THRESHOLD:
                                alert = self._make_alert("SYN_FLOOD", src, dst, dport,
                                    f"SYN Flood: {len(self.syn_packets[src])} SYNs/{SYN_FLOOD_WINDOW}s")
                                self.syn_packets[src].clear()

                        # 5. Port Scan
                        self.port_scan[src].append((now, dport))
                        self._window_expire_tuples(self.port_scan[src], now, PORT_SCAN_WINDOW)
                        unique_ports = len({p for _, p in self.port_scan[src]})
                        if unique_ports >= PORT_SCAN_THRESHOLD and not alert:
                            alert = self._make_alert("PORT_SCAN", src, dst, dport,
                                f"Port Scan: {unique_ports} ports/{PORT_SCAN_WINDOW}s")
                            self.port_scan[src].clear()

                        # 6. Brute Force
                        if dport in BRUTE_FORCE_PORTS:
                            self._window_add(self.brute_force[src], now)
                            self._window_expire(self.brute_force[src], now, BRUTE_FORCE_WINDOW)
                            if len(self.brute_force[src]) >= BRUTE_FORCE_THRESHOLD and not alert:
                                alert = self._make_alert("BRUTE_FORCE", src, dst, dport,
                                    f"Brute Force port {dport}: {len(self.brute_force[src])} attempts/{BRUTE_FORCE_WINDOW}s")
                                self.brute_force[src].clear()

                # ── UDP ───────────────────────────────────────────────────────
                elif UDP in packet:
                    dport   = packet[UDP].dport
                    traffic = {"time": self._ts(), "src": src, "dst": dst,
                               "proto": "UDP", "port": dport, "flags": "-", "length": len(packet)}
                    self._window_add(self.udp_packets[src], now)
                    self._window_expire(self.udp_packets[src], now, UDP_FLOOD_WINDOW)
                    if len(self.udp_packets[src]) >= UDP_FLOOD_THRESHOLD:
                        alert = self._make_alert("UDP_FLOOD", src, dst, dport,
                            f"UDP Flood: {len(self.udp_packets[src])} pkts/{UDP_FLOOD_WINDOW}s")
                        self.udp_packets[src].clear()

                # ── ICMP ──────────────────────────────────────────────────────
                elif ICMP in packet:
                    traffic = {"time": self._ts(), "src": src, "dst": dst,
                               "proto": "ICMP", "port": "-", "flags": "-", "length": len(packet)}
                    self._window_add(self.icmp_packets[src], now)
                    self._window_expire(self.icmp_packets[src], now, ICMP_FLOOD_WINDOW)
                    if len(self.icmp_packets[src]) >= ICMP_FLOOD_THRESHOLD:
                        alert = self._make_alert("ICMP_FLOOD", src, dst, "-",
                            f"ICMP Flood: {len(self.icmp_packets[src])} pkts/{ICMP_FLOOD_WINDOW}s")
                        self.icmp_packets[src].clear()

            return traffic, alert

    def get_stats(self) -> dict:
        with self.lock:
            return {
                "total_packets":   self.total_packets,
                "total_alerts":    len(self.alerts),
                "unique_attackers": len({a["src_ip"] for a in self.alerts}),
                "blocked_ips":     len(self.blocked_ips),
            }

    def get_recent_alerts(self, n: int = 50) -> list[dict]:
        with self.lock:
            return list(self.alerts[-n:])

    def get_recent_traffic(self, n: int = 100) -> list[dict]:
        with self.lock:
            return list(self.traffic_log[-n:])

    def clear(self):
        with self.lock:
            self.alerts.clear()
            self.traffic_log.clear()
            self.total_packets = 0
            self.blocked_ips.clear()

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _ts() -> str:
        return time.strftime("%H:%M:%S")

    @staticmethod
    def _window_add(d: deque, ts: float):
        d.append(ts)

    @staticmethod
    def _window_expire(d: deque, now: float, window: float):
        while d and now - d[0] > window:
            d.popleft()

    @staticmethod
    def _window_expire_tuples(d: deque, now: float, window: float):
        while d and now - d[0][0] > window:
            d.popleft()

    def _make_alert(self, attack_type: str, src: str, dst: str,
                    port, message: str) -> dict:
        return {
            "time":        self._ts(),
            "type":        attack_type,
            "severity":    SEVERITY.get(attack_type, "MEDIUM"),
            "src_ip":      src,
            "dst_ip":      dst,
            "port":        port,
            "message":     message,
        }
