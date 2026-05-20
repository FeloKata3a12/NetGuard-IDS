"""
NetGuard – Streamlit Dashboard  (v2.1 – fixed ScriptRunContext + alert detection)
Run:  sudo streamlit run dashboard.py
"""

import sys, time, threading, queue
from pathlib import Path
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.express as px

sys.path.insert(0, str(Path(__file__).parent))

from core.detector  import IntrusionDetector
from core.logger    import log_alert, log_traffic, clear_logs, ALERTS_CSV, TRAFFIC_CSV
from core.geoip     import geolocate_many, db_status
from report.generator import generate_html_report

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="NetGuard IDS", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
html, body, [class*="css"] { font-family:'Rajdhani',sans-serif; background:#0a0e17; color:#c9d1d9; }
.main { background:#0a0e17; }
section[data-testid="stSidebar"] { background:#0d1117; border-right:1px solid #1f2937; }
.ng-header {
    background:linear-gradient(135deg,#0d1f3c 0%,#0a0e17 60%,#0d1f3c 100%);
    border:1px solid #1e3a5f; border-radius:12px; padding:20px 30px;
    margin-bottom:20px; box-shadow:0 0 40px #1a3a6440;
}
.ng-header h1 {
    font-family:'Share Tech Mono',monospace; font-size:2em; margin:0;
    color:#58a6ff; text-shadow:0 0 20px #58a6ff88; letter-spacing:2px;
}
.ng-header p { margin:4px 0 0 0; color:#8b949e; font-size:.95em; }
.ng-status-dot { width:11px; height:11px; border-radius:50%; display:inline-block; margin-right:6px; vertical-align:middle; }
.dot-green { background:#30d158; box-shadow:0 0 8px #30d158; animation:pulse 1.5s infinite; }
.dot-red   { background:#ff2d55; box-shadow:0 0 8px #ff2d55; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.metric-card { background:#0d1117; border:1px solid #1e3a5f; border-radius:10px; padding:16px 20px; text-align:center; }
.metric-card .mc-val { font-family:'Share Tech Mono',monospace; font-size:2.2em; font-weight:700; line-height:1; }
.metric-card .mc-lbl { color:#8b949e; font-size:.85em; margin-top:6px; }
.section-title {
    font-family:'Share Tech Mono',monospace; color:#58a6ff; font-size:.95em;
    letter-spacing:2px; border-bottom:1px solid #1e3a5f;
    padding-bottom:6px; margin:18px 0 10px 0; text-transform:uppercase;
}
</style>
""", unsafe_allow_html=True)

# ── Global shared objects (module-level, survive reruns) ──────────────────────
# We keep detector + queues at module level so the background thread
# can write to them without ever touching st.session_state.
if "_ng_detector" not in st.__dict__:
    st._ng_detector      = IntrusionDetector()
    st._ng_alert_q       = queue.Queue()   # thread → main: new alerts
    st._ng_traffic_q     = queue.Queue()   # thread → main: new traffic rows
    st._ng_monitoring    = False
    st._ng_sniff_error   = None
    st._ng_iface         = "eth0"

detector : IntrusionDetector = st._ng_detector

# ── Drain queues into detector's lists (called each rerun) ────────────────────
def _drain_queues():
    while not st._ng_alert_q.empty():
        try:
            a = st._ng_alert_q.get_nowait()
            detector.alerts.append(a)
            detector.blocked_ips.add(a["src_ip"])
            try: log_alert(a)
            except Exception: pass
        except queue.Empty:
            break
    while not st._ng_traffic_q.empty():
        try:
            t = st._ng_traffic_q.get_nowait()
            detector.traffic_log.append(t)
            try: log_traffic(t)
            except Exception: pass
        except queue.Empty:
            break
    # keep bounded
    if len(detector.traffic_log) > 2000:
        detector.traffic_log = detector.traffic_log[-2000:]

_drain_queues()

# ── Background sniff function (NO st calls here!) ─────────────────────────────
def _sniff_worker(iface: str, pkt_filter: str):
    """Runs in daemon thread – never touches Streamlit APIs."""
    try:
        from scapy.all import sniff

        def cb(pkt):
            traffic, alert = detector.analyze_packet(pkt)
            if traffic:
                st._ng_traffic_q.put(traffic)
            if alert:
                st._ng_alert_q.put(alert)

        sniff(prn=cb, store=False, filter=pkt_filter, iface=iface)

    except Exception as e:
        st._ng_sniff_error = str(e)
        st._ng_monitoring  = False

# ── Session state (lightweight – only UI state) ───────────────────────────────
if "refresh_rate" not in st.session_state:
    st.session_state.refresh_rate = 3

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ NetGuard")
    st.markdown("---")

    iface      = st.text_input("Network Interface", value=st._ng_iface)
    pkt_filter = st.text_input("BPF Filter", value="tcp or udp or icmp")

    col_a, col_b = st.columns(2)
    start_btn = col_a.button("▶ Start", use_container_width=True, type="primary")
    stop_btn  = col_b.button("⏹ Stop",  use_container_width=True)

    st.markdown("---")
    st.session_state.refresh_rate = st.slider("Auto-refresh (sec)", 1, 10, st.session_state.refresh_rate)

    st.markdown("---")
    if st.button("📊 Generate Report", use_container_width=True):
        try:
            path = generate_html_report()
            st.success(f"Saved: {path.name}")
            st.download_button("⬇ Download", open(path,"rb"), file_name=path.name, mime="text/html")
        except Exception as e:
            st.error(f"Error: {e}")

    if st.button("🗑 Clear Logs", use_container_width=True):
        with detector.lock:
            detector.alerts.clear()
            detector.traffic_log.clear()
            detector.total_packets = 0
            detector.blocked_ips.clear()
        clear_logs()
        st.success("Cleared.")

    st.markdown("---")
    if Path(ALERTS_CSV).exists():
        st.download_button("⬇ Alerts CSV",  open(ALERTS_CSV,"rb"),  "alerts.csv",  "text/csv", use_container_width=True)
    if Path(TRAFFIC_CSV).exists():
        st.download_button("⬇ Traffic CSV", open(TRAFFIC_CSV,"rb"), "traffic.csv", "text/csv", use_container_width=True)

    # ── Interface helper ──────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("**Available interfaces:**")
    try:
        import subprocess
        ifaces = subprocess.check_output(["ip","-o","link","show"], text=True)
        for line in ifaces.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 2:
                name = parts[1].strip().split("@")[0]
                if name != "lo":
                    st.code(name, language=None)
    except Exception:
        st.caption("Run `ip link show` to list interfaces")

# ── Start / Stop ──────────────────────────────────────────────────────────────
if start_btn and not st._ng_monitoring:
    st._ng_sniff_error = None
    st._ng_iface       = iface
    st._ng_monitoring  = True
    t = threading.Thread(target=_sniff_worker, args=(iface, pkt_filter), daemon=True)
    t.start()
    st.toast(f"▶ Monitoring started on {iface}", icon="🛡️")

if stop_btn:
    st._ng_monitoring = False
    st.toast("⏹ Monitoring stopped", icon="🔴")

# ── Header ────────────────────────────────────────────────────────────────────
dot  = "dot-green" if st._ng_monitoring else "dot-red"
text = f"MONITORING · {st._ng_iface}" if st._ng_monitoring else "IDLE"

st.markdown(f"""
<div class="ng-header">
  <h1>🛡️ NETGUARD IDS</h1>
  <p><span class="ng-status-dot {dot}"></span>{text}
     &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>""", unsafe_allow_html=True)

if st._ng_sniff_error:
    st.error(f"⚠️ Sniff error: {st._ng_sniff_error}  "
             f"— Make sure you're running with **sudo** and the interface name is correct.")

# ── Metrics ───────────────────────────────────────────────────────────────────
stats        = detector.get_stats()
alerts_data  = detector.get_recent_alerts(500)
traffic_data = detector.get_recent_traffic(200)

def metric_card(col, val, label, color="#58a6ff"):
    col.markdown(f"""<div class="metric-card">
      <div class="mc-val" style="color:{color}">{val}</div>
      <div class="mc-lbl">{label}</div></div>""", unsafe_allow_html=True)

c1,c2,c3,c4,c5 = st.columns(5)
metric_card(c1, stats["total_packets"],    "Total Packets",     "#58a6ff")
metric_card(c2, stats["total_alerts"],     "Total Alerts",      "#ff9f0a")
metric_card(c3, stats["unique_attackers"], "Unique Attackers",  "#ff2d55")
metric_card(c4, stats["blocked_ips"],      "Flagged IPs",       "#ff2d55")
metric_card(c5, len(traffic_data),         "Traffic Log",       "#30d158")

st.markdown("<br>", unsafe_allow_html=True)

# ── Charts ────────────────────────────────────────────────────────────────────
cl, cr = st.columns([1.4, 1])

with cl:
    st.markdown('<div class="section-title">⚡ Alerts Timeline</div>', unsafe_allow_html=True)
    if alerts_data:
        df_a = pd.DataFrame(alerts_data)
        cmap = {"CRITICAL":"#ff2d55","HIGH":"#ff9f0a","MEDIUM":"#ffd60a","LOW":"#30d158"}
        fig  = px.histogram(df_a, x="time", color="severity",
                            color_discrete_map=cmap, barmode="stack", template="plotly_dark")
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=0,r=0,t=10,b=0), height=240,
                          legend=dict(orientation="h",yanchor="bottom",y=1.02),
                          xaxis_title="", yaxis_title="Alerts")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alerts yet — start monitoring.")

with cr:
    st.markdown('<div class="section-title">🥧 Attack Types</div>', unsafe_allow_html=True)
    if alerts_data:
        df_a  = pd.DataFrame(alerts_data)
        types = df_a["type"].value_counts().reset_index()
        types.columns = ["type","count"]
        fig2  = px.pie(types, names="type", values="count", template="plotly_dark",
                       color_discrete_sequence=px.colors.sequential.Blues_r)
        fig2.update_traces(textinfo="label+percent", hole=0.4)
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                           margin=dict(l=0,r=0,t=10,b=0), height=240, showlegend=False)
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No data yet.")

if alerts_data:
    st.markdown('<div class="section-title">🎯 Top Attacking IPs</div>', unsafe_allow_html=True)
    df_a    = pd.DataFrame(alerts_data)
    top_ips = df_a["src_ip"].value_counts().head(10).reset_index()
    top_ips.columns = ["ip","count"]
    fig3 = px.bar(top_ips, x="count", y="ip", orientation="h", template="plotly_dark",
                  color="count", color_continuous_scale=["#1e3a5f","#ff2d55"])
    fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                       margin=dict(l=0,r=0,t=10,b=0), height=220,
                       yaxis=dict(autorange="reversed"),
                       xaxis_title="Alert Count", yaxis_title="", coloraxis_showscale=False)
    st.plotly_chart(fig3, use_container_width=True)

# ── GeoIP World Map ───────────────────────────────────────────────────────────
st.markdown('<div class="section-title">🌍 Attacker World Map</div>', unsafe_allow_html=True)

# DB status badge
st.caption(db_status())

if alerts_data:
    df_a    = pd.DataFrame(alerts_data)
    all_ips = df_a["src_ip"].unique().tolist()

    with st.spinner("Resolving IPs..."):
        geo_map = geolocate_many(all_ips)

    # Build geo dataframe
    rows = []
    for ip, geo in geo_map.items():
        if geo["country"] in ("Private", "Unknown"):
            continue
        count = int(df_a[df_a["src_ip"] == ip].shape[0])
        rows.append({
            "ip":      ip,
            "country": geo["country"],
            "city":    geo["city"],
            "lat":     geo["lat"],
            "lon":     geo["lon"],
            "isp":     geo["isp"],
            "alerts":  count,
        })

    if rows:
        df_geo = pd.DataFrame(rows)

        # ── World scatter map ─────────────────────────────────────────────────
        fig_map = px.scatter_geo(
            df_geo,
            lat="lat", lon="lon",
            size="alerts",
            color="alerts",
            hover_name="ip",
            hover_data={"country": True, "city": True, "isp": True,
                        "alerts": True, "lat": False, "lon": False},
            color_continuous_scale=["#1e3a5f", "#ff9f0a", "#ff2d55"],
            size_max=40,
            template="plotly_dark",
            projection="natural earth",
        )
        fig_map.update_geos(
            bgcolor="#0a0e17",
            landcolor="#0d1f3c",
            oceancolor="#060b14",
            showocean=True,
            showland=True,
            showcountries=True,
            countrycolor="#1e3a5f",
            showcoastlines=True,
            coastlinecolor="#1e3a5f",
            lakecolor="#060b14",
        )
        fig_map.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=10, b=0),
            height=420,
            coloraxis_colorbar=dict(
                title="Alerts",
                tickfont=dict(color="#8b949e"),
                titlefont=dict(color="#8b949e"),
            ),
        )
        st.plotly_chart(fig_map, use_container_width=True)

        # ── Geo table ─────────────────────────────────────────────────────────
        with st.expander("📋 IP Geolocation Details", expanded=False):
            # Country summary
            country_summary = (
                df_geo.groupby(["country", "country_code" if "country_code" in df_geo else "country"])
                .agg(ips=("ip","count"), total_alerts=("alerts","sum"))
                .sort_values("total_alerts", ascending=False)
                .reset_index()
            )

            col_geo1, col_geo2 = st.columns([1, 1.5])
            with col_geo1:
                st.markdown("**Attacks by Country**")
                # Add flag emoji using country from geo_map
                country_rows = []
                for _, row in country_summary.iterrows():
                    country_rows.append({
                        "Country": row["country"],
                        "IPs": int(row["ips"]),
                        "Alerts": int(row["total_alerts"]),
                    })
                st.dataframe(pd.DataFrame(country_rows),
                             use_container_width=True, hide_index=True)

            with col_geo2:
                st.markdown("**Full IP Details**")
                st.dataframe(
                    df_geo[["ip","country","city","isp","alerts"]].sort_values("alerts", ascending=False),
                    use_container_width=True, hide_index=True,
                )
    else:
        st.info("All detected IPs are private/local — no geo data to display.")
else:
    st.info("No alerts yet — start monitoring to see attacker locations.")

# ── Alerts table ──────────────────────────────────────────────────────────────
st.markdown('<div class="section-title">🚨 Recent Alerts</div>', unsafe_allow_html=True)
sev_filter = st.multiselect("Filter by severity",
    ["CRITICAL","HIGH","MEDIUM","LOW"], default=["CRITICAL","HIGH","MEDIUM","LOW"])

if alerts_data:
    df_show = pd.DataFrame(alerts_data[::-1])
    df_show = df_show[df_show["severity"].isin(sev_filter)]
    if not df_show.empty:
        st.dataframe(df_show[["time","severity","type","src_ip","dst_ip","port","message"]],
                     use_container_width=True, hide_index=True, height=300)
    else:
        st.info("No alerts match selected filters.")
else:
    st.info("No alerts yet.")

# ── Traffic log ───────────────────────────────────────────────────────────────
with st.expander("📡 Live Traffic Log", expanded=False):
    proto_filter = st.multiselect("Filter by protocol",
        ["TCP","UDP","ICMP"], default=["TCP","UDP","ICMP"])
    if traffic_data:
        df_t = pd.DataFrame(traffic_data[::-1])
        df_t = df_t[df_t["proto"].isin(proto_filter)]
        if not df_t.empty:
            st.dataframe(df_t, use_container_width=True, hide_index=True, height=300)
        else:
            st.info("No traffic matches selected filters.")
    else:
        st.info("No traffic captured yet.")

# ── Auto-refresh ──────────────────────────────────────────────────────────────
if st._ng_monitoring:
    time.sleep(st.session_state.refresh_rate)
    st.rerun()
