"""
NIDS Live Dashboard — Streamlit
================================
Real-time network intrusion monitoring dashboard.
Polls the primary backend every 2 seconds for live attack data.

Run:
    pip install streamlit plotly requests
    streamlit run dashboard.py
"""

import time
import math
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime
import streamlit as st

# ── CONFIG ──────────────────────────────────────────────────────────────────
BACKEND_URL  = "http://localhost:3000"
REFRESH_SEC  = 2
MAX_HISTORY  = 60   # keep 60 data-points in time-series charts

# ── PAGE SETUP ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NIDS · Live Threat Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── CUSTOM CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');

  /* ── Global ── */
  html, body, [class*="css"] {
    background-color: #050A0F !important;
    color: #C9D1D9 !important;
    font-family: 'Space Grotesk', sans-serif !important;
  }
  .block-container { padding: 1.5rem 2rem !important; max-width: 100% !important; }
  .stApp { background: #050A0F; }

  /* ── Header ── */
  .nids-header {
    display: flex; align-items: center; gap: 16px;
    margin-bottom: 2rem;
    border-bottom: 1px solid #1C2A3A;
    padding-bottom: 1.2rem;
  }
  .nids-title {
    font-size: 1.6rem; font-weight: 700; letter-spacing: 0.08em;
    color: #E6EDF3; font-family: 'JetBrains Mono', monospace;
  }
  .nids-subtitle {
    font-size: 0.78rem; color: #6E8098; letter-spacing: 0.1em;
    font-family: 'JetBrains Mono', monospace; text-transform: uppercase;
  }
  .live-dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: #39D353; box-shadow: 0 0 10px #39D353;
    display: inline-block; margin-right: 6px;
    animation: pulse 1.5s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; box-shadow: 0 0 8px #39D353; }
    50%      { opacity: 0.5; box-shadow: 0 0 20px #39D353; }
  }

  /* ── Status Banner ── */
  .status-banner {
    border-radius: 10px; padding: 1.2rem 1.8rem;
    display: flex; align-items: center; gap: 14px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700; font-size: 1.1rem; letter-spacing: 0.04em;
    margin-bottom: 1.5rem;
  }
  .status-attack {
    background: linear-gradient(135deg, #1A0A0A, #2D0F0F);
    border: 1px solid #FF4444; color: #FF6B6B;
    box-shadow: 0 0 30px rgba(255, 68, 68, 0.15);
  }
  .status-normal {
    background: linear-gradient(135deg, #0A1A0A, #0F2D0F);
    border: 1px solid #39D353; color: #5BDA72;
    box-shadow: 0 0 30px rgba(57, 211, 83, 0.1);
  }
  .status-icon { font-size: 1.8rem; }

  /* ── Metric Cards ── */
  .metric-card {
    background: #0D1117; border: 1px solid #1C2A3A;
    border-radius: 10px; padding: 1.2rem 1.4rem;
    position: relative; overflow: hidden;
  }
  .metric-card::before {
    content: ''; position: absolute; top: 0; left: 0;
    right: 0; height: 2px;
  }
  .metric-card.red::before   { background: linear-gradient(90deg, #FF4444, transparent); }
  .metric-card.green::before { background: linear-gradient(90deg, #39D353, transparent); }
  .metric-card.blue::before  { background: linear-gradient(90deg, #58A6FF, transparent); }
  .metric-card.amber::before { background: linear-gradient(90deg, #F0883E, transparent); }
  .metric-label {
    font-size: 0.72rem; color: #6E8098; letter-spacing: 0.12em;
    text-transform: uppercase; font-family: 'JetBrains Mono', monospace;
    margin-bottom: 0.4rem;
  }
  .metric-value {
    font-size: 2.2rem; font-weight: 700; line-height: 1;
    font-family: 'JetBrains Mono', monospace;
  }
  .metric-value.red   { color: #FF6B6B; }
  .metric-value.green { color: #3ECC54; }
  .metric-value.blue  { color: #79C0FF; }
  .metric-value.amber { color: #F0883E; }
  .metric-sub {
    font-size: 0.75rem; color: #4A6078; margin-top: 0.3rem;
    font-family: 'JetBrains Mono', monospace;
  }

  /* ── Section Title ── */
  .section-title {
    font-size: 0.72rem; color: #6E8098; letter-spacing: 0.15em;
    text-transform: uppercase; font-family: 'JetBrains Mono', monospace;
    margin: 1.4rem 0 0.8rem;
    display: flex; align-items: center; gap: 8px;
  }
  .section-title::after {
    content: ''; flex: 1; height: 1px; background: #1C2A3A;
  }

  /* ── Attack Log Table ── */
  .log-row {
    display: grid;
    grid-template-columns: 140px 110px 90px 90px 90px 1fr;
    gap: 8px; padding: 0.55rem 0.8rem;
    border-radius: 6px; margin-bottom: 3px;
    font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
    align-items: center;
  }
  .log-row.header {
    background: transparent; color: #6E8098;
    font-size: 0.68rem; letter-spacing: 0.1em;
    text-transform: uppercase; border-bottom: 1px solid #1C2A3A;
    padding-bottom: 0.5rem; margin-bottom: 6px;
  }
  .log-row.attack {
    background: rgba(255, 68, 68, 0.06);
    border: 1px solid rgba(255, 68, 68, 0.15);
  }
  .log-row.normal {
    background: rgba(57, 211, 83, 0.04);
    border: 1px solid rgba(57, 211, 83, 0.08);
  }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 0.7rem; font-weight: 600; letter-spacing: 0.08em;
  }
  .badge-attack { background: rgba(255,68,68,0.2); color: #FF6B6B; }
  .badge-normal { background: rgba(57,211,83,0.15); color: #39D353; }

  /* ── Probability Bar ── */
  .prob-bar-bg {
    height: 6px; background: #1C2A3A; border-radius: 3px;
    overflow: hidden; margin-top: 4px;
  }
  .prob-bar-fill {
    height: 100%; border-radius: 3px;
    transition: width 0.4s ease;
  }

  /* ── Footer ── */
  .nids-footer {
    margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #1C2A3A;
    font-size: 0.72rem; color: #3A5068;
    font-family: 'JetBrains Mono', monospace; text-align: center;
  }

  /* ── Streamlit overrides ── */
  .stMetric { background: transparent !important; }
  div[data-testid="metric-container"] { background: transparent !important; }
  .stPlotlyChart { border: 1px solid #1C2A3A; border-radius: 10px; overflow: hidden; }
  footer { display: none !important; }
  #MainMenu { display: none !important; }
  header { display: none !important; }
</style>
""", unsafe_allow_html=True)


# ── SESSION STATE ─────────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []          # list of (timestamp, attack_count, normal_count, rate)
if "last_attack_time" not in st.session_state:
    st.session_state.last_attack_time = None


# ── DATA FETCHERS ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=REFRESH_SEC)
def fetch_stats():
    try:
        r = requests.get(f"{BACKEND_URL}/api/v1/stats", timeout=3)
        return r.json() if r.ok else None
    except Exception:
        return None

@st.cache_data(ttl=REFRESH_SEC)
def fetch_attacks():
    try:
        r = requests.get(f"{BACKEND_URL}/api/v1/attacks", timeout=3)
        return r.json() if r.ok else []
    except Exception:
        return []

@st.cache_data(ttl=REFRESH_SEC)
def fetch_health():
    try:
        r = requests.get(f"{BACKEND_URL}/api/v1/health", timeout=2)
        return r.json() if r.ok else None
    except Exception:
        return None


# ── HELPER: colour for probability ───────────────────────────────────────────
def prob_color(p: float) -> str:
    if p is None: return "#4A6078"
    if p >= 0.7:  return "#FF4444"
    if p >= 0.4:  return "#F0883E"
    return "#39D353"

def format_prob(p) -> str:
    return f"{p*100:.1f}%" if p is not None else "N/A"


# ── CHARTS ───────────────────────────────────────────────────────────────────
CHART_BG   = "#050A0F"
CHART_GRID = "#1C2A3A"
FONT_COLOR = "#6E8098"
PLOT_FONT  = dict(family="JetBrains Mono, monospace", color=FONT_COLOR)

def make_gauge(probability: float, is_attack: bool) -> go.Figure:
    color = "#FF4444" if is_attack else "#39D353"
    val   = (probability or 0) * 100
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=val,
        number={"suffix": "%", "font": {"size": 36, "color": color, "family": "JetBrains Mono"}},
        gauge={
            "axis":     {"range": [0, 100], "tickcolor": FONT_COLOR,
                         "tickfont": {"size": 10, "color": FONT_COLOR}},
            "bar":      {"color": color, "thickness": 0.22},
            "bgcolor":  "#0D1117",
            "bordercolor": "#1C2A3A",
            "steps": [
                {"range": [0,  40],  "color": "rgba(57,211,83,0.08)"},
                {"range": [40, 70],  "color": "rgba(240,136,62,0.08)"},
                {"range": [70, 100], "color": "rgba(255,68,68,0.10)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.85,
                "value": val,
            },
        },
    ))
    fig.update_layout(
        paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
        margin=dict(l=20, r=20, t=30, b=10),
        height=220,
        font=PLOT_FONT,
    )
    return fig


def make_traffic_chart(history: list) -> go.Figure:
    if not history:
        return go.Figure()

    times     = [h["ts"] for h in history]
    attacks   = [h["attacks"] for h in history]
    normals   = [h["normal"] for h in history]
    rates     = [h["rate"] for h in history]

    fig = make_subplots(
        rows=2, cols=1,
        shared_xaxes=True,
        row_heights=[0.65, 0.35],
        vertical_spacing=0.06,
    )

    # Flow breakdown
    fig.add_trace(go.Scatter(
        x=times, y=attacks, name="ATTACK",
        fill="tozeroy", fillcolor="rgba(255,68,68,0.12)",
        line=dict(color="#FF4444", width=1.5),
        mode="lines",
    ), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=times, y=normals, name="NORMAL",
        fill="tozeroy", fillcolor="rgba(57,211,83,0.07)",
        line=dict(color="#39D353", width=1.5),
        mode="lines",
    ), row=1, col=1)

    # Attack rate
    fig.add_trace(go.Scatter(
        x=times, y=rates, name="Attack Rate %",
        line=dict(color="#F0883E", width=1.5, dash="dot"),
        mode="lines",
    ), row=2, col=1)

    fig.update_layout(
        paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
        font=PLOT_FONT, legend=dict(
            orientation="h", x=0, y=1.05,
            font=dict(size=11, color=FONT_COLOR),
            bgcolor="rgba(0,0,0,0)",
        ),
        margin=dict(l=10, r=10, t=10, b=10),
        height=320,
        hovermode="x unified",
    )
    for row in (1, 2):
        fig.update_xaxes(gridcolor=CHART_GRID, zerolinecolor=CHART_GRID,
                         showgrid=True, row=row, col=1)
        fig.update_yaxes(gridcolor=CHART_GRID, zerolinecolor=CHART_GRID,
                         showgrid=True, row=row, col=1)
    return fig


def make_srcip_chart(records: list) -> go.Figure:
    if not records:
        return go.Figure()

    attack_records = [r for r in records if r.get("prediction") == "ATTACK"]
    if not attack_records:
        # Show all sources if no attacks
        attack_records = records

    ip_counts = {}
    for r in attack_records:
        ip = r.get("source_ip", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    sorted_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    ips, counts = zip(*sorted_ips) if sorted_ips else ([], [])

    colors = ["#FF4444" if c == max(counts) else "#C0392B" for c in counts]

    fig = go.Figure(go.Bar(
        x=list(counts), y=list(ips),
        orientation="h",
        marker_color=colors,
        marker_line_width=0,
        text=[str(c) for c in counts],
        textposition="inside",
        textfont=dict(color="white", size=11, family="JetBrains Mono"),
    ))
    fig.update_layout(
        paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
        font=PLOT_FONT, height=240,
        margin=dict(l=10, r=10, t=10, b=10),
        yaxis=dict(autorange="reversed", gridcolor=CHART_GRID),
        xaxis=dict(gridcolor=CHART_GRID),
    )
    return fig


def make_proto_donut(records: list) -> go.Figure:
    if not records:
        return go.Figure()

    protos = {}
    for r in records:
        p = r.get("features", {}).get("proto", "unknown") or "unknown"
        protos[p] = protos.get(p, 0) + 1

    labels = list(protos.keys())
    values = list(protos.values())
    colors = ["#58A6FF", "#39D353", "#F0883E", "#FF4444", "#9B59B6"]

    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        hole=0.62,
        marker=dict(colors=colors[:len(labels)], line=dict(color=CHART_BG, width=2)),
        textfont=dict(family="JetBrains Mono", size=11),
        textinfo="label+percent",
    ))
    fig.update_layout(
        paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
        font=PLOT_FONT, height=240,
        margin=dict(l=10, r=10, t=10, b=10),
        showlegend=False,
    )
    return fig


# ── ATTACK LOG ROW ────────────────────────────────────────────────────────────
def render_log_row(r: dict, header=False):
    if header:
        st.markdown("""
        <div class="log-row header">
          <span>Timestamp</span><span>Source IP</span>
          <span>Prediction</span><span>Probability</span>
          <span>State</span><span>Bytes ↑ / ↓</span>
        </div>""", unsafe_allow_html=True)
        return

    pred   = r.get("prediction", "NORMAL")
    prob   = r.get("attack_probability")
    ts_raw = r.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z","")).strftime("%H:%M:%S.%f")[:-3]
    except Exception:
        ts = ts_raw[:19]

    src_ip = r.get("source_ip", "—")
    feats  = r.get("features", {})
    sbytes = feats.get("sbytes", 0) or 0
    dbytes = feats.get("dbytes", 0) or 0
    spkts  = feats.get("spkts", 0) or 0

    badge_cls  = "badge-attack" if pred == "ATTACK" else "badge-normal"
    row_cls    = "attack" if pred == "ATTACK" else "normal"
    prob_str   = format_prob(prob)
    prob_val   = (prob or 0) * 100
    bar_color  = prob_color(prob)
    state_str  = "—"   # state not stored in record currently

    st.markdown(f"""
    <div class="log-row {row_cls}">
      <span style="color:#6E8098">{ts}</span>
      <span style="color:#79C0FF">{src_ip}</span>
      <span><span class="badge {badge_cls}">{pred}</span></span>
      <span style="color:{bar_color}">{prob_str}</span>
      <span style="color:#6E8098">{spkts}pkts</span>
      <span style="color:#C9D1D9">{sbytes:,}B / {dbytes:,}B</span>
    </div>
    """, unsafe_allow_html=True)


# ── MAIN RENDER ───────────────────────────────────────────────────────────────
def render():
    # ── Header ────────────────────────────────────────────────────────────────
    now_str = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    st.markdown(f"""
    <div class="nids-header">
      <div>
        <div class="nids-title">🛡️ &nbsp;NIDS · THREAT MONITOR</div>
        <div class="nids-subtitle">
          <span class="live-dot"></span>
          LIVE · UNSW-NB15 MODEL · {now_str}
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    # ── Fetch data ────────────────────────────────────────────────────────────
    stats   = fetch_stats()
    records = fetch_attacks()
    health  = fetch_health()

    # ── Connection guard ──────────────────────────────────────────────────────
    if stats is None:
        st.error("⚠️  Cannot reach backend at `http://localhost:3000`.  "
                 "Make sure `node index.js` is running.")
        st.stop()

    # ── Build history point ───────────────────────────────────────────────────
    total   = stats.get("total_flows", 0)
    attacks = stats.get("attacks_detected", 0)
    normal  = stats.get("normal_flows", 0)
    rate    = float(stats.get("attack_rate_pct", 0))

    hist_point = {
        "ts":      datetime.now().strftime("%H:%M:%S"),
        "attacks": attacks,
        "normal":  normal,
        "rate":    rate,
    }
    st.session_state.history.append(hist_point)
    if len(st.session_state.history) > MAX_HISTORY:
        st.session_state.history.pop(0)

    # ── Current status ────────────────────────────────────────────────────────
    recent_attacks = [r for r in records[:10] if r.get("prediction") == "ATTACK"]
    is_under_attack = len(recent_attacks) >= 3
    latest_prob  = records[0].get("attack_probability") if records else None
    if records and records[0].get("prediction") == "ATTACK":
        st.session_state.last_attack_time = datetime.now().strftime("%H:%M:%S")

    if is_under_attack:
        st.markdown(f"""
        <div class="status-banner status-attack">
          <span class="status-icon">🔴</span>
          <div>
            <div>ATTACK DETECTED — SERVER IS UNDER THREAT</div>
            <div style="font-size:0.75rem;font-weight:400;margin-top:4px;color:#C04040">
              {attacks} malicious flows detected in session
            </div>
          </div>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="status-banner status-normal">
          <span class="status-icon">🟢</span>
          <div>
            <div>SYSTEM NORMAL — NO ACTIVE THREATS DETECTED</div>
            <div style="font-size:0.75rem;font-weight:400;margin-top:4px;color:#2A8040">
              {total} flows monitored · last update {now_str}
            </div>
          </div>
        </div>""", unsafe_allow_html=True)

    # ── Top row: metrics + gauge ──────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns([1, 1, 1, 1, 1.4])

    with col1:
        st.markdown(f"""
        <div class="metric-card blue">
          <div class="metric-label">Total Flows</div>
          <div class="metric-value blue">{total:,}</div>
          <div class="metric-sub">session total</div>
        </div>""", unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card red">
          <div class="metric-label">Attacks Detected</div>
          <div class="metric-value red">{attacks:,}</div>
          <div class="metric-sub">malicious flows</div>
        </div>""", unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card green">
          <div class="metric-label">Normal Flows</div>
          <div class="metric-value green">{normal:,}</div>
          <div class="metric-sub">clean traffic</div>
        </div>""", unsafe_allow_html=True)

    with col4:
        rate_color = "red" if rate > 50 else ("amber" if rate > 20 else "green")
        st.markdown(f"""
        <div class="metric-card {rate_color}">
          <div class="metric-label">Attack Rate</div>
          <div class="metric-value {rate_color}">{rate:.1f}%</div>
          <div class="metric-sub">of all traffic</div>
        </div>""", unsafe_allow_html=True)

    with col5:
        gauge_prob = latest_prob if latest_prob is not None else (0.85 if is_under_attack else 0.05)
        st.plotly_chart(
        make_gauge(gauge_prob, is_under_attack),
        use_container_width=True,
        config={"displayModeBar": False},
        key="gauge_chart"
        )
        st.plotly_chart(
         make_traffic_chart(st.session_state.history),
         use_container_width=True,
         config={"displayModeBar": False},
         key="traffic_chart"
        ) 

    # ── Traffic chart + source IPs ────────────────────────────────────────────
    st.markdown('<div class="section-title">Traffic Timeline</div>', unsafe_allow_html=True)
    colA, colB = st.columns([2.2, 1])

    with colA:
        st.plotly_chart(
            make_traffic_chart(st.session_state.history),
            use_container_width=True, config={"displayModeBar": False},
             key="traffic_chart_main"
        )

    with colB:
        st.markdown('<div class="section-title">Top Source IPs (Attacks)</div>',
                    unsafe_allow_html=True)
        st.plotly_chart(
            make_srcip_chart(records),
            use_container_width=True, config={"displayModeBar": False}
        )

    # ── Protocol breakdown + health ───────────────────────────────────────────
    colC, colD = st.columns([1, 2])

    with colC:
        st.markdown('<div class="section-title">Protocol Mix</div>', unsafe_allow_html=True)
        st.plotly_chart(
            make_proto_donut(records),
            use_container_width=True, config={"displayModeBar": False}
        )

    with colD:
        st.markdown('<div class="section-title">Service Health</div>', unsafe_allow_html=True)
        if health:
            ml_ok = health.get("ml_service", "unreachable") not in ("unreachable",)
            be_ok = health.get("backend", "") == "ok"
            log_n = health.get("log_size", 0)
            st.markdown(f"""
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-top:0.5rem">
              <div class="metric-card {'green' if be_ok else 'red'}">
                <div class="metric-label">Backend</div>
                <div class="metric-value {'green' if be_ok else 'red'}" style="font-size:1.4rem">
                  {'● ONLINE' if be_ok else '● OFFLINE'}
                </div>
                <div class="metric-sub">localhost:3000</div>
              </div>
              <div class="metric-card {'green' if ml_ok else 'amber'}">
                <div class="metric-label">ML Service</div>
                <div class="metric-value {'green' if ml_ok else 'amber'}" style="font-size:1.4rem">
                  {'● ONLINE' if ml_ok else '● OFFLINE'}
                </div>
                <div class="metric-sub">localhost:3002</div>
              </div>
              <div class="metric-card blue">
                <div class="metric-label">Log Buffer</div>
                <div class="metric-value blue" style="font-size:1.4rem">{log_n:,}</div>
                <div class="metric-sub">flows in memory</div>
              </div>
            </div>
            """, unsafe_allow_html=True)

        # Last attack detail
        if st.session_state.last_attack_time:
            st.markdown(
                f"<div style='font-family:JetBrains Mono;font-size:0.78rem;color:#6E8098;"
                f"margin-top:0.8rem'>Last attack flow: "
                f"<span style='color:#FF6B6B'>{st.session_state.last_attack_time}</span></div>",
                unsafe_allow_html=True
            )

    # ── Live attack log ───────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Live Flow Log (last 20)</div>',
                unsafe_allow_html=True)
    render_log_row(None, header=True)
    for r in records[:20]:
        render_log_row(r)

    # ── Footer ────────────────────────────────────────────────────────────────
    ml_status = health.get("ml_service", "—") if health else "—"
    st.markdown(f"""
    <div class="nids-footer">
      MODEL: UNSW-NB15 · Autoencoder + SGD Classifier &nbsp;|&nbsp;
      ML SERVICE: {ml_status} &nbsp;|&nbsp;
      REFRESH: every {REFRESH_SEC}s &nbsp;|&nbsp;
      AGENT: Port 8080 &nbsp;|&nbsp;
      PIPELINE: Scapy → Feature Extractor → Express → Model Service
    </div>""", unsafe_allow_html=True)


# ── AUTO-REFRESH LOOP ─────────────────────────────────────────────────────────
render()
time.sleep(REFRESH_SEC)
st.rerun()