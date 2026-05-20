"""
NetGuard Detection Rules
Thresholds and signatures for all attack types
"""

# ─── SYN Flood ────────────────────────────────────────────────────────────────
SYN_FLOOD_THRESHOLD     = 100   # SYN packets per IP per window
SYN_FLOOD_WINDOW        = 5     # seconds

# ─── Port Scan ────────────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD     = 15    # distinct ports per IP per window
PORT_SCAN_WINDOW        = 10    # seconds

# ─── Brute Force ──────────────────────────────────────────────────────────────
BRUTE_FORCE_PORTS       = {21, 22, 23, 25, 110, 143, 3306, 3389, 5900, 8080}
BRUTE_FORCE_THRESHOLD   = 10    # connection attempts per IP per window
BRUTE_FORCE_WINDOW      = 10    # seconds

# ─── Nmap Stealth Scans (FIN / NULL / Xmas) ───────────────────────────────────
# FIN scan  : only FIN flag set          → flags == 0x001
# NULL scan : no flags set               → flags == 0x000
# Xmas scan : FIN + PSH + URG set        → flags == 0x029
NMAP_FIN_FLAGS  = 0x001
NMAP_NULL_FLAGS = 0x000
NMAP_XMAS_FLAGS = 0x029         # FIN(1) + PSH(8) + URG(32) = 41 = 0x29

# ─── ICMP Flood ───────────────────────────────────────────────────────────────
ICMP_FLOOD_THRESHOLD    = 50    # ICMP packets per IP per window
ICMP_FLOOD_WINDOW       = 5     # seconds

# ─── UDP Flood ────────────────────────────────────────────────────────────────
UDP_FLOOD_THRESHOLD     = 200   # UDP packets per IP per window
UDP_FLOOD_WINDOW        = 5     # seconds

# ─── Severity mapping ─────────────────────────────────────────────────────────
SEVERITY = {
    "SYN_FLOOD":    "CRITICAL",
    "PORT_SCAN":    "HIGH",
    "BRUTE_FORCE":  "HIGH",
    "NMAP_FIN":     "MEDIUM",
    "NMAP_NULL":    "MEDIUM",
    "NMAP_XMAS":    "MEDIUM",
    "ICMP_FLOOD":   "HIGH",
    "UDP_FLOOD":    "HIGH",
}
