"""
NetGuard – Logger
Persists alerts and traffic to disk (JSON + CSV).
"""

import csv
import json
import os
import time
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

ALERTS_JSON  = LOG_DIR / "alerts.json"
ALERTS_CSV   = LOG_DIR / "alerts.csv"
TRAFFIC_CSV  = LOG_DIR / "traffic.csv"

_ALERT_FIELDS   = ["time", "type", "severity", "src_ip", "dst_ip", "port", "message"]
_TRAFFIC_FIELDS = ["time", "src", "dst", "proto", "port", "flags", "length"]


def _ensure_csv(path: Path, fieldnames: list[str]):
    if not path.exists():
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()


def log_alert(alert: dict):
    """Append one alert to alerts.json and alerts.csv."""
    # JSON
    existing = []
    if ALERTS_JSON.exists():
        try:
            existing = json.loads(ALERTS_JSON.read_text())
        except Exception:
            existing = []
    existing.append(alert)
    ALERTS_JSON.write_text(json.dumps(existing, indent=2))

    # CSV
    _ensure_csv(ALERTS_CSV, _ALERT_FIELDS)
    with open(ALERTS_CSV, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_ALERT_FIELDS, extrasaction="ignore")
        writer.writerow(alert)


def log_traffic(entry: dict):
    """Append one traffic entry to traffic.csv."""
    _ensure_csv(TRAFFIC_CSV, _TRAFFIC_FIELDS)
    with open(TRAFFIC_CSV, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_TRAFFIC_FIELDS, extrasaction="ignore")
        writer.writerow(entry)


def load_alerts() -> list[dict]:
    if ALERTS_JSON.exists():
        try:
            return json.loads(ALERTS_JSON.read_text())
        except Exception:
            return []
    return []


def clear_logs():
    for p in [ALERTS_JSON, ALERTS_CSV, TRAFFIC_CSV]:
        if p.exists():
            p.unlink()
