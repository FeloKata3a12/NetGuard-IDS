"""
NetGuard – Report Generator
Generates a styled HTML report from logged alerts.
"""

import json
from pathlib import Path
from datetime import datetime
from core.logger import load_alerts

try:
    from core.geoip import geolocate
    _GEO_OK = True
except Exception:
    _GEO_OK = False

REPORT_DIR = Path(__file__).parent.parent / "report"
REPORT_DIR.mkdir(exist_ok=True)


def generate_html_report() -> Path:
    alerts = load_alerts()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out_path = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    severity_color = {
        "CRITICAL": "#ff2d55",
        "HIGH":     "#ff9f0a",
        "MEDIUM":   "#ffd60a",
        "LOW":      "#30d158",
    }

    rows = ""
    for a in reversed(alerts):
        color = severity_color.get(a.get("severity", "LOW"), "#888")
        geo_str = ""
        if _GEO_OK:
            try:
                geo = geolocate(a.get("src_ip", ""))
                if geo["country"] not in ("Private", "Unknown"):
                    geo_str = f"{geo['country']} / {geo['city']}"
            except Exception:
                pass
        rows += f"""
        <tr>
            <td>{a.get('time','')}</td>
            <td><span class="badge" style="background:{color}">{a.get('severity','')}</span></td>
            <td>{a.get('type','')}</td>
            <td>{a.get('src_ip','')}</td>
            <td style="color:#8b949e;font-size:.85em">{geo_str}</td>
            <td>{a.get('dst_ip','')}</td>
            <td>{a.get('port','')}</td>
            <td>{a.get('message','')}</td>
        </tr>"""

    stats = {
        "total":    len(alerts),
        "critical": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
        "high":     sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "medium":   sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
        "ips":      len({a.get("src_ip") for a in alerts}),
    }

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetGuard Report – {now}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:20px; }}
  h1   {{ color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:10px; }}
  .stats {{ display:flex; gap:20px; margin:20px 0; }}
  .stat-card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px 24px; text-align:center; }}
  .stat-card .num {{ font-size:2em; font-weight:bold; color:#58a6ff; }}
  .stat-card .lbl {{ font-size:.85em; color:#8b949e; }}
  table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
  th    {{ background:#161b22; color:#8b949e; padding:10px; text-align:left; border-bottom:1px solid #30363d; }}
  td    {{ padding:9px 10px; border-bottom:1px solid #21262d; font-size:.9em; }}
  tr:hover td {{ background:#161b22; }}
  .badge {{ padding:3px 8px; border-radius:4px; font-size:.8em; font-weight:bold; color:#000; }}
  .ts {{ color:#8b949e; font-size:.85em; margin-top:30px; }}
</style>
</head>
<body>
<h1>🛡️ NetGuard – Intrusion Detection Report</h1>
<p>Generated: {now}</p>

<div class="stats">
  <div class="stat-card"><div class="num">{stats['total']}</div><div class="lbl">Total Alerts</div></div>
  <div class="stat-card"><div class="num" style="color:#ff2d55">{stats['critical']}</div><div class="lbl">Critical</div></div>
  <div class="stat-card"><div class="num" style="color:#ff9f0a">{stats['high']}</div><div class="lbl">High</div></div>
  <div class="stat-card"><div class="num" style="color:#ffd60a">{stats['medium']}</div><div class="lbl">Medium</div></div>
  <div class="stat-card"><div class="num">{stats['ips']}</div><div class="lbl">Unique Attacker IPs</div></div>
</div>

<table>
  <thead>
    <tr><th>Time</th><th>Severity</th><th>Type</th><th>Src IP</th><th>Location</th><th>Dst IP</th><th>Port</th><th>Message</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>

<p class="ts">NetGuard IDS – Auto-generated report</p>
</body>
</html>"""

    out_path.write_text(html)
    return out_path
