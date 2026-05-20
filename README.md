<div align="center">

# 🛡️ NetGuard IDS
### Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-00897B?style=for-the-badge)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

Real-time network intrusion detection system that monitors live traffic,
detects attacks, geolocates attackers on a world map, and displays everything
on a live dashboard.

</div>

---

## ✨ Features

- 🔍 **Real-time packet analysis** — TCP, UDP, ICMP
- 🚨 **8 attack detectors** — SYN Flood, Port Scan, Brute Force, Nmap stealth scans, ICMP/UDP Flood
- 🌍 **GeoIP World Map** — attacker locations visualized on an interactive globe
- 📊 **Live Dashboard** — charts, alerts table, traffic log, auto-refresh
- 💾 **Persistent logging** — JSON + CSV export
- 📄 **HTML Report** — one-click professional report generation
- ⚙️ **Tunable thresholds** — edit `detection/rules.py` to adjust sensitivity

---

## 🔍 Detected Attacks

| Attack | Detection Logic | Severity |
|---|---|---|
| **SYN Flood** | ≥ 100 SYN-only packets from same IP / 5s | 🔴 CRITICAL |
| **Port Scan** | ≥ 15 distinct ports from same IP / 10s | 🟠 HIGH |
| **Brute Force** | ≥ 10 connections to auth ports (SSH/FTP/RDP…) / 10s | 🟠 HIGH |
| **Nmap -sN** (NULL scan) | TCP packet with no flags set | 🟡 MEDIUM |
| **Nmap -sF** (FIN scan) | TCP packet with only FIN flag | 🟡 MEDIUM |
| **Nmap -sX** (Xmas scan) | TCP with FIN + PSH + URG flags | 🟡 MEDIUM |
| **ICMP Flood** | ≥ 50 ICMP packets from same IP / 5s | 🟠 HIGH |
| **UDP Flood** | ≥ 200 UDP packets from same IP / 5s | 🟠 HIGH |

**Brute Force monitored ports:** FTP(21), SSH(22), Telnet(23), SMTP(25), POP3(110), IMAP(143), MySQL(3306), RDP(3389), VNC(5900), HTTP-Alt(8080)

---

## 📁 Project Structure

```
NetGuard/
├── main.py                 ← CLI mode (terminal output)
├── dashboard.py            ← Streamlit web dashboard
├── download_geodb.py       ← GeoLite2 DB downloader
├── requirements.txt
│
├── core/
│   ├── detector.py         ← Detection engine (thread-safe)
│   ├── geoip.py            ← GeoIP resolver (local DB + HTTP fallback)
│   └── logger.py           ← JSON + CSV logging
│
├── detection/
│   └── rules.py            ← All thresholds & signatures (edit me!)
│
├── data/
│   └── GeoLite2-City.mmdb  ← (optional) local geo database
│
├── logs/                   ← Auto-created: alerts.json, alerts.csv, traffic.csv
└── report/
    └── generator.py        ← HTML report generator
```

---

## 🚀 Installation & Setup

### 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/NetGuard.git
cd NetGuard
```

### 2 — Install dependencies

```bash
pip install -r requirements.txt
```

> On Kali / Debian if you get an error:
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

### 3 — (Optional) Set up GeoIP local database

Without this step the system still works using the free **ip-api.com** API automatically.
For offline use or higher accuracy, get the local database:

1. Register for free at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)
2. Copy your license key, then run:

```bash
python download_geodb.py --key YOUR_LICENSE_KEY
```

This downloads `GeoLite2-City.mmdb` (~70 MB) into the `data/` folder.

---

## ▶️ Usage

> **Root / sudo is required** for raw packet capture.

### Option A — Web Dashboard (recommended)

```bash
sudo streamlit run dashboard.py
```

Open your browser at **http://localhost:8501**

1. Set the correct **Network Interface** in the sidebar (e.g. `eth0`, `wlan0`)
2. Click **▶ Start**
3. Watch alerts appear in real-time

**Find your interface name:**
```bash
ip link show
```

### Option B — CLI / Terminal mode

```bash
sudo python main.py --iface eth0
sudo python main.py --iface wlan0 --filter "tcp or udp or icmp"
```

---

## 🧪 Testing the Detections

You can verify NetGuard is working by running these from another machine (or terminal):

```bash
# Port Scan detection
nmap -sS TARGET_IP

# Nmap stealth scans
nmap -sN TARGET_IP      # NULL scan
nmap -sF TARGET_IP      # FIN scan
nmap -sX TARGET_IP      # Xmas scan

# SYN Flood simulation (hping3)
sudo hping3 -S --flood -p 80 TARGET_IP

# ICMP Flood
sudo hping3 --icmp --flood TARGET_IP
```

> ⚠️ Only test on networks and machines you own or have permission to test.

---

## ⚙️ Tuning Thresholds

Edit `detection/rules.py` to adjust sensitivity:

```python
SYN_FLOOD_THRESHOLD  = 100   # lower = more sensitive
PORT_SCAN_THRESHOLD  = 15
BRUTE_FORCE_THRESHOLD = 10
ICMP_FLOOD_THRESHOLD = 50
UDP_FLOOD_THRESHOLD  = 200
```

---

## 📊 Dashboard Overview

| Section | Description |
|---|---|
| **Metrics bar** | Live counts: packets, alerts, unique attackers, flagged IPs |
| **Alerts Timeline** | Histogram of alerts over time, colored by severity |
| **Attack Types** | Donut chart — distribution of attack categories |
| **Top Attacking IPs** | Horizontal bar chart of most active sources |
| **🌍 World Map** | Interactive scatter-geo map of attacker locations |
| **Recent Alerts** | Filterable table with severity, type, IP, message |
| **Traffic Log** | Raw packet log filterable by protocol |
| **Reports** | Generate & download HTML report / CSV exports |

---

## 🛠️ Tech Stack

| Library | Purpose |
|---|---|
| [Scapy](https://scapy.net/) | Live packet capture & analysis |
| [Streamlit](https://streamlit.io/) | Web dashboard framework |
| [Plotly](https://plotly.com/python/) | Interactive charts & world map |
| [pandas](https://pandas.pydata.org/) | Data manipulation |
| [geoip2](https://github.com/maxmind/GeoIP2-python) | Local GeoIP database reader |
| [requests](https://requests.readthedocs.io/) | HTTP fallback for GeoIP |

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">
Built with Python 🐍 | For educational & defensive security purposes only
</div>
# NetGuard-IDS
