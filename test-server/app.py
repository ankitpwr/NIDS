"""
app.py  —  NIDS Test Server (College Project)
Full website: landing page + login + signup modal + IP-blocked page.
Same structure, routes, and mitigation integration as the original.

Routes
──────────────────────────────────────────────────────────────────────────────
  GET  /                      → Full NIDS website (home → login → blocked)
  GET  /login                 → Login page (also reachable via navbar)
  GET  /blocked               → Custom 403 blocked page (served on hard-block)

  GET/POST  /api/v1/google/auth   → Primary auth endpoint (main attack target)
  GET       /api/v1/user          → Mock user JSON
  GET       /api/v1/data          → Mock records (HTTP-flood target)
  GET       /health               → Health check (whitelisted from mitigation)

  GET   /mitigation/stats         → Config + Redis counters
  GET   /mitigation/blocked       → Currently blocked IPs + TTL
  POST  /mitigation/block         → Manually block an IP  { ip, reason, ttl }
  POST  /mitigation/unblock       → Remove a block        { ip }
──────────────────────────────────────────────────────────────────────────────
"""

from flask import Flask, request, jsonify, render_template_string, make_response
import time

from mitigation import (
    mitigation_before_request,
    block_ip, unblock_ip,
    list_blocked_ips,
    get_mitigation_stats,
)

app = Flask(__name__)


# ─── REAL-IP EXTRACTION ───────────────────────────────────────────────────────

def get_real_ip() -> str:
    """
    Priority: Cloudflare → X-Forwarded-For → direct remote_addr.
    Identical to the primary Node server's IP extraction.
    """
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


@app.before_request
def capture_real_ip():
    request.real_ip = get_real_ip()
    print(f"[TestServer] {request.method} {request.path}  ip={request.real_ip}")


app.before_request(mitigation_before_request)


# ─── HTML PAGES ───────────────────────────────────────────────────────────────
#
# All pages are rendered from a single Python string so the project stays
# self-contained (no templates folder needed).  The JavaScript inside handles
# routing between Home / Login / Blocked entirely client-side; Flask only
# serves the shell on GET / and GET /login.
#
# Credentials (demo only — no database):
#   username: admin
#   password: admin123

PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NIDS — Network Intrusion Detection System</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:      #0A0F1E;
      --bg2:     #0F1629;
      --bg3:     #151D35;
      --border:  rgba(255,255,255,0.08);
      --accent:  #4F8EF7;
      --green:   #10B981;
      --red:     #EF4444;
      --amber:   #F59E0B;
      --text1:   #F0F4FF;
      --text2:   #8892A4;
      --text3:   #4B5563;
      --card:    rgba(255,255,255,0.04);
    }

    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text1);
      min-height: 100vh;
    }

    /* ── UTILITIES ── */
    .badge {
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      display: inline-block;
    }
    .badge-green { background: rgba(16,185,129,0.15); color: var(--green); }
    .badge-red   { background: rgba(239,68,68,0.15);  color: var(--red);   }
    .badge-amber { background: rgba(245,158,11,0.15); color: var(--amber); }
    .badge-blue  { background: rgba(79,142,247,0.15); color: var(--accent);}

    /* ── PAGES ── */
    .page { display: none; }
    .page.active { display: block; }

    /* ── NAV ── */
    nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 36px;
      height: 60px;
      border-bottom: 1px solid var(--border);
      background: var(--bg2);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .nav-logo {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 17px;
      font-weight: 700;
      color: var(--text1);
      cursor: pointer;
    }
    .nav-logo-icon {
      width: 30px; height: 30px;
      background: #185FA5;
      border-radius: 7px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
    }
    .nav-links { display: flex; align-items: center; gap: 4px; }
    .nav-links a {
      font-size: 14px;
      color: var(--text2);
      padding: 6px 14px;
      border-radius: 7px;
      cursor: pointer;
      text-decoration: none;
      transition: color .15s, background .15s;
    }
    .nav-links a:hover { background: rgba(255,255,255,0.05); color: var(--text1); }
    .btn-nav-login {
      padding: 7px 18px;
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 7px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity .15s;
    }
    .btn-nav-login:hover { opacity: .88; }

    /* ── HERO ── */
    .hero {
      text-align: center;
      padding: 80px 24px 60px;
      border-bottom: 1px solid var(--border);
    }
    .hero-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(79,142,247,0.1);
      border: 1px solid rgba(79,142,247,0.25);
      color: var(--accent);
      font-size: 12px;
      padding: 5px 14px;
      border-radius: 20px;
      margin-bottom: 24px;
    }
    .hero h1 {
      font-size: 40px;
      font-weight: 800;
      max-width: 680px;
      margin: 0 auto 16px;
      line-height: 1.2;
    }
    .hero p {
      font-size: 16px;
      color: var(--text2);
      max-width: 560px;
      margin: 0 auto 32px;
      line-height: 1.7;
    }
    .hero-btns { display: flex; gap: 12px; justify-content: center; }
    .btn-primary {
      padding: 11px 28px;
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity .15s;
    }
    .btn-primary:hover { opacity: .88; }
    .btn-outline {
      padding: 11px 28px;
      background: transparent;
      color: var(--text2);
      border: 1px solid rgba(255,255,255,0.12);
      border-radius: 8px;
      font-size: 14px;
      cursor: pointer;
      transition: border-color .15s, color .15s;
    }
    .btn-outline:hover { border-color: rgba(255,255,255,0.25); color: var(--text1); }

    /* ── SECTIONS ── */
    section { padding: 60px 36px; max-width: 1000px; margin: 0 auto; }
    .section-label {
      font-size: 12px;
      font-weight: 600;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: .08em;
      margin-bottom: 8px;
    }
    .section-title {
      font-size: 26px;
      font-weight: 800;
      margin-bottom: 8px;
    }
    .section-sub {
      font-size: 15px;
      color: var(--text2);
      line-height: 1.7;
      max-width: 600px;
      margin-bottom: 32px;
    }
    .divider { border: none; border-top: 1px solid var(--border); }

    /* ── ABOUT CARDS ── */
    .about-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }
    .about-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px;
    }
    .about-icon {
      font-size: 24px;
      margin-bottom: 12px;
    }
    .about-card h3 { font-size: 15px; font-weight: 700; margin-bottom: 6px; }
    .about-card p  { font-size: 13px; color: var(--text2); line-height: 1.6; }

    /* ── OBJECTIVES ── */
    .obj-list {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 12px;
    }
    .obj-item {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      align-items: flex-start;
      gap: 12px;
    }
    .obj-num {
      background: rgba(79,142,247,0.15);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      width: 26px; height: 26px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .obj-item p { font-size: 13px; color: var(--text2); line-height: 1.5; }

    /* ── TECHNOLOGY CARDS ── */
    .tech-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 14px;
    }
    .tech-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 16px;
      display: flex;
      align-items: center;
      gap: 12px;
      transition: border-color .2s;
    }
    .tech-card:hover { border-color: rgba(79,142,247,0.3); }
    .tech-icon {
      width: 38px; height: 38px;
      background: rgba(79,142,247,0.1);
      border-radius: 9px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      flex-shrink: 0;
    }
    .tech-card span { font-size: 13px; font-weight: 600; }

    /* ── FEATURES ── */
    .feat-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 14px;
    }
    .feat-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
    }
    .feat-card .feat-icon { font-size: 22px; margin-bottom: 10px; }
    .feat-card h3 { font-size: 14px; font-weight: 700; margin-bottom: 5px; }
    .feat-card p  { font-size: 12px; color: var(--text2); line-height: 1.55; }

    /* ── TEAM ── */
    .team-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 16px;
    }
    .team-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px 16px;
      text-align: center;
    }
    .avatar {
      width: 52px; height: 52px;
      border-radius: 50%;
      background: rgba(79,142,247,0.15);
      color: var(--accent);
      font-size: 18px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 12px;
    }
    .team-card h3 { font-size: 14px; font-weight: 700; }
    .team-card p  { font-size: 12px; color: var(--text3); margin-top: 3px; }

    /* ── FOOTER ── */
    footer {
      background: var(--bg2);
      border-top: 1px solid var(--border);
      text-align: center;
      padding: 20px;
      font-size: 13px;
      color: var(--text3);
    }

    /* ── LOGIN PAGE ── */
    .login-wrap {
      min-height: calc(100vh - 60px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px 24px;
    }
    .login-card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
    }
    .login-icon {
      width: 52px; height: 52px;
      background: rgba(79,142,247,0.12);
      border: 1px solid rgba(79,142,247,0.25);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
      margin: 0 auto 18px;
    }
    .login-card h2   { font-size: 22px; font-weight: 800; text-align: center; margin-bottom: 6px; }
    .login-card .sub { font-size: 13px; color: var(--text2); text-align: center; margin-bottom: 28px; }

    .field { margin-bottom: 16px; }
    .field label {
      display: block;
      font-size: 13px;
      color: var(--text2);
      margin-bottom: 6px;
    }
    .field input {
      width: 100%;
      padding: 10px 14px;
      background: var(--bg3);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 8px;
      color: var(--text1);
      font-size: 14px;
      outline: none;
      transition: border-color .15s;
    }
    .field input:focus { border-color: var(--accent); }

    .btn-full {
      width: 100%;
      padding: 11px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity .15s;
    }
    .btn-blue   { background: var(--accent); color: #fff; border: none; margin-bottom: 10px; }
    .btn-blue:hover { opacity: .88; }
    .btn-ghost  {
      background: transparent;
      color: var(--text2);
      border: 1px solid rgba(255,255,255,0.1);
    }
    .btn-ghost:hover { background: rgba(255,255,255,0.05); color: var(--text1); }

    .msg {
      padding: 11px 14px;
      border-radius: 8px;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }
    .msg.success { background: rgba(16,185,129,0.12); color: var(--green); border: 1px solid rgba(16,185,129,0.25); }
    .msg.error   { background: rgba(239,68,68,0.12);  color: var(--red);   border: 1px solid rgba(239,68,68,0.25);  }

    .demo-hint {
      font-size: 12px;
      color: var(--text3);
      text-align: center;
      margin-top: 14px;
    }

    /* ── SIGNUP MODAL ── */
    #modal-signup {
      display: none;
      position: fixed;
      inset: 0;
      z-index: 9999;
      background: rgba(0,0,0,0.8);
      align-items: center;
      justify-content: center;
    }
    #modal-signup.open { display: flex; }
    .modal-box {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 36px;
      width: 92%;
      max-width: 420px;
      max-height: 90vh;
      overflow-y: auto;
    }
    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
    }
    .modal-header h3 { font-size: 20px; font-weight: 800; }
    .close-btn {
      background: none;
      border: none;
      color: var(--text2);
      font-size: 22px;
      cursor: pointer;
      padding: 2px 6px;
      border-radius: 6px;
    }
    .close-btn:hover { background: rgba(255,255,255,0.06); color: var(--text1); }

    /* ── BLOCKED PAGE ── */
    #page-blocked {
      background: #080808;
      min-height: 100vh;
    }
    .blocked-wrap {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 40px 24px;
    }
    .blocked-card { text-align: center; max-width: 460px; }
    .blocked-icon {
      width: 80px; height: 80px;
      background: rgba(239,68,68,0.1);
      border: 1px solid rgba(239,68,68,0.3);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 34px;
      margin: 0 auto 22px;
    }
    .blocked-card h2 { font-size: 28px; font-weight: 800; color: var(--red); margin-bottom: 10px; }
    .blocked-card p  { font-size: 14px; color: #888; line-height: 1.7; margin-bottom: 24px; }
    .blocked-detail {
      background: rgba(239,68,68,0.06);
      border: 1px solid rgba(239,68,68,0.2);
      border-radius: 10px;
      padding: 16px 20px;
      text-align: left;
      margin-bottom: 28px;
    }
    .blocked-row {
      display: flex;
      justify-content: space-between;
      font-size: 13px;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.04);
    }
    .blocked-row:last-child { border-bottom: none; }
    .blocked-row .k { color: var(--text3); }
    .blocked-row .v { font-family: 'Courier New', monospace; color: #FCA5A5; font-weight: 600; }
    .btn-blocked {
      padding: 11px 30px;
      background: var(--red);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity .15s;
    }
    .btn-blocked:hover { opacity: .85; }

    /* ── BLOCK POPUP BANNER (shown before redirect) ── */
    #block-popup {
      display: none;
      position: fixed;
      top: 70px;
      left: 50%;
      transform: translateX(-50%);
      z-index: 9000;
      background: #0F1629;
      border: 1px solid rgba(239,68,68,0.5);
      border-radius: 10px;
      padding: 14px 20px;
      max-width: 460px;
      width: 90%;
      display: none;
      align-items: center;
      gap: 12px;
    }
    #block-popup.show { display: flex; }
    .popup-icon { font-size: 20px; flex-shrink: 0; }
    .popup-text { font-size: 13px; color: var(--text2); flex: 1; }
    .popup-text strong { color: var(--red); }
    .popup-close {
      background: none;
      border: none;
      color: var(--text3);
      font-size: 18px;
      cursor: pointer;
      flex-shrink: 0;
    }

    @media (max-width: 640px) {
      .hero h1  { font-size: 28px; }
      nav       { padding: 0 16px; }
      section   { padding: 40px 16px; }
      .login-card { padding: 28px 20px; }
    }
  </style>
</head>
<body>

<!-- ═══════════════════════════════════════════════════════════════════════════
     BLOCK POPUP — appears when mitigation intercepts a browser request
     ═══════════════════════════════════════════════════════════════════════ -->
<div id="block-popup">
  <span class="popup-icon">🛡️</span>
  <p class="popup-text">
    <strong>Access Blocked</strong> — NIDS has flagged your IP.
    Redirecting to the blocked page…
  </p>
  <button class="popup-close" onclick="document.getElementById('block-popup').classList.remove('show')">✕</button>
</div>


<!-- ═══════════════════════════════════════════════════════════════════════════
     HOME PAGE
     ═══════════════════════════════════════════════════════════════════════ -->
<div id="page-home" class="page active">

  <nav>
    <div class="nav-logo" onclick="showPage('home')">
      <div class="nav-logo-icon">🛡</div>
      NIDS
    </div>
    <div class="nav-links">
      <a onclick="scrollToSection('about-sec')">About NIDS</a>
      <a onclick="scrollToSection('tech-sec')">Technologies</a>
      <a onclick="scrollToSection('team-sec')">Team</a>
      <button class="btn-nav-login" onclick="showPage('login')">Login</button>
    </div>
  </nav>

  <!-- Hero -->
  <div class="hero">
    <div class="hero-pill">🔍 Real-time threat detection</div>
    <h1>Network Intrusion Detection System (NIDS)</h1>
    <p>A project that monitors network traffic and detects malicious activities using machine learning and network analysis techniques.</p>
    <div class="hero-btns">
      <button class="btn-primary" onclick="showPage('login')">Get started</button>
      <button class="btn-outline" onclick="scrollToSection('about-sec')">Learn more</button>
    </div>
  </div>

  <!-- About NIDS -->
  <section id="about-sec">
    <div class="section-label">About</div>
    <div class="section-title">What is a Network Intrusion Detection System?</div>
    <div class="section-sub">
      NIDS passively monitors all network traffic, extracts flow-level features,
      and classifies each connection as Normal or Attack — without interrupting
      legitimate users.
    </div>
    <div class="about-grid">
      <div class="about-card">
        <div class="about-icon">📡</div>
        <h3>Continuous monitoring</h3>
        <p>Passively captures packets on the network interface and assembles them into flows for analysis.</p>
      </div>
      <div class="about-card">
        <div class="about-icon">↔️</div>
        <h3>Normal vs. malicious</h3>
        <p>Normal traffic follows predictable patterns. Attacks show anomalous volumes, port scans, or known exploit signatures.</p>
      </div>
      <div class="about-card">
        <div class="about-icon">🧠</div>
        <h3>ML-based detection</h3>
        <p>A binary XGBoost classifier, trained on UNSW-NB15, achieves 94.53 % accuracy and 99.19 % AUC-ROC.</p>
      </div>
      <div class="about-card">
        <div class="about-icon">🔒</div>
        <h3>Why NIDS matters</h3>
        <p>Cyber attacks cost organisations billions yearly. NIDS reduces detection latency from days to milliseconds.</p>
      </div>
    </div>
  </section>

  <hr class="divider">

  <!-- Objectives -->
  <section id="obj-sec">
    <div class="section-label">Objectives</div>
    <div class="section-title">What this system aims to do</div>
    <div class="obj-list">
      <div class="obj-item"><div class="obj-num">1</div><p>Monitor incoming and outgoing network traffic in real time</p></div>
      <div class="obj-item"><div class="obj-num">2</div><p>Detect suspicious network behaviour and flow anomalies</p></div>
      <div class="obj-item"><div class="obj-num">3</div><p>Identify and classify intrusion attempts automatically</p></div>
      <div class="obj-item"><div class="obj-num">4</div><p>Generate security alerts and notify administrators by email</p></div>
      <div class="obj-item"><div class="obj-num">5</div><p>Improve overall network security posture continuously</p></div>
    </div>
  </section>

  <hr class="divider">

  <!-- Technologies — populated from /api/v1/data -->
  <section id="tech-sec">
    <div class="section-label">Technologies</div>
    <div class="section-title">Built with</div>
    <div class="tech-grid" id="tech-grid">
      <p style="font-size:13px;color:var(--text3)">Loading…</p>
    </div>
  </section>

  <hr class="divider">

  <!-- Features -->
  <section id="feat-sec">
    <div class="section-label">Features</div>
    <div class="section-title">System capabilities</div>
    <div class="feat-grid">
      <div class="feat-card">
        <div class="feat-icon">📈</div>
        <h3>Real-time monitoring</h3>
        <p>Live packet capture via Scapy with sub-second flow assembly.</p>
      </div>
      <div class="feat-card">
        <div class="feat-icon">⚠️</div>
        <h3>Threat detection</h3>
        <p>XGBoost flags attack flows with 94.53 % accuracy on UNSW-NB15.</p>
      </div>
      <div class="feat-card">
        <div class="feat-icon">🔬</div>
        <h3>Traffic analysis</h3>
        <p>42 flow-level features aligned with the UNSW-NB15 benchmark.</p>
      </div>
      <div class="feat-card">
        <div class="feat-icon">🔔</div>
        <h3>Alert generation</h3>
        <p>Email alerts via Nodemailer when an attack flow is detected.</p>
      </div>
      <div class="feat-card">
        <div class="feat-icon">🖥</div>
        <h3>Dashboard</h3>
        <p>React dashboard with live traffic charts and blocked IP management.</p>
      </div>
    </div>
  </section>

  <hr class="divider">

  <!-- Team — populated from /api/v1/user -->
  <section id="team-sec">
    <div class="section-label">Team</div>
    <div class="section-title">Meet the team</div>
    <div class="team-grid" id="team-grid">
      <p style="font-size:13px;color:var(--text3)">Loading…</p>
    </div>
  </section>

  <footer>
    <p>NIDS — Network Intrusion Detection System &nbsp;·&nbsp; College project &nbsp;·&nbsp; 2024</p>
  </footer>

</div> <!-- /page-home -->


<!-- ═══════════════════════════════════════════════════════════════════════════
     LOGIN PAGE
     ═══════════════════════════════════════════════════════════════════════ -->
<div id="page-login" class="page">

  <nav>
    <div class="nav-logo" onclick="showPage('home')">
      <div class="nav-logo-icon">🛡</div>
      NIDS
    </div>
    <div class="nav-links">
      <a onclick="showPage('home')">← Back to home</a>
    </div>
  </nav>

  <div class="login-wrap">
    <div class="login-card">
      <div class="login-icon">🔐</div>
      <h2>Welcome back</h2>
      <p class="sub">Sign in to access the NIDS dashboard</p>

      <div id="login-msg" class="msg"></div>

      <div class="field">
        <label for="uname">Username</label>
        <input type="text" id="uname" placeholder="Enter your username" />
      </div>
      <div class="field">
        <label for="upass">Password</label>
        <input type="password" id="upass" placeholder="Enter your password" />
      </div>

      <button class="btn-full btn-blue" onclick="doLogin()">Login</button>
      <button class="btn-full btn-ghost" onclick="openSignup()">Sign Up</button>

      <p class="demo-hint">Demo credentials: &nbsp;<code>admin</code> / <code>admin123</code></p>
    </div>
  </div>

</div> <!-- /page-login -->


<!-- ═══════════════════════════════════════════════════════════════════════════
     BLOCKED PAGE  (served when mitigation hard-blocks an IP)
     ═══════════════════════════════════════════════════════════════════════ -->
<div id="page-blocked" class="page">
  <div class="blocked-wrap">
    <div class="blocked-card">
      <div class="blocked-icon">🚫</div>
      <h2>Access Blocked</h2>
      <p>
        The Network Intrusion Detection System has intercepted and blocked this
        request due to suspicious activity originating from your IP address.
      </p>
      <div class="blocked-detail">
        <div class="blocked-row"><span class="k">Your IP</span>       <span class="v" id="b-ip">—</span></div>
        <div class="blocked-row"><span class="k">Status</span>        <span class="v" id="b-status">HTTP 403 Forbidden</span></div>
        <div class="blocked-row"><span class="k">Reason</span>        <span class="v" id="b-reason">—</span></div>
      </div>
      <p style="font-size:13px;color:#555;margin-bottom:20px;">
        If you believe this is a mistake, contact your network administrator
        to request removal from the block-list.
      </p>
      <button class="btn-blocked" onclick="showPage('home')">Return to home</button>
    </div>
  </div>
</div> <!-- /page-blocked -->


<!-- ═══════════════════════════════════════════════════════════════════════════
     SIGNUP MODAL
     ═══════════════════════════════════════════════════════════════════════ -->
<div id="modal-signup">
  <div class="modal-box">
    <div class="modal-header">
      <h3>Create account</h3>
      <button class="close-btn" onclick="closeSignup()">✕</button>
    </div>

    <div id="signup-msg" class="msg"></div>

    <div class="field"><label>Full name</label>        <input type="text"     id="s-name"  placeholder="Your full name" /></div>
    <div class="field"><label>Username</label>         <input type="text"     id="s-user"  placeholder="Choose a username" /></div>
    <div class="field"><label>Email</label>            <input type="email"    id="s-email" placeholder="your@email.com" /></div>
    <div class="field"><label>Password</label>         <input type="password" id="s-pass"  placeholder="Create a password" /></div>
    <div class="field"><label>Confirm password</label> <input type="password" id="s-pass2" placeholder="Repeat your password" /></div>

    <button class="btn-full btn-blue" onclick="doSignup()">Create account</button>
  </div>
</div>


<script>
  // ── Page routing ──────────────────────────────────────────────────────────
  function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById('page-' + name).classList.add('active');
    document.getElementById('modal-signup').classList.remove('open');
    window.scrollTo(0, 0);

    // Sync URL so /login bookmark works
    if (name === 'login')   history.pushState({}, '', '/login');
    else if (name === 'home') history.pushState({}, '', '/');
  }

  function scrollToSection(id) {
    showPage('home');
    setTimeout(() => {
      const el = document.getElementById(id);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);
  }

  // Check URL on first load so /login works as a direct link
  if (window.location.pathname === '/login') showPage('login');

  // ── Login — hits /api/v1/google/auth (POST) ──────────────────────────────
  async function doLogin() {
    const u   = document.getElementById('uname').value.trim();
    const p   = document.getElementById('upass').value.trim();
    const btn = document.querySelector('#page-login .btn-blue');

    if (!u || !p) { showMsg('login-msg', 'Please enter username and password.', 'error'); return; }

    // Basic credential check before hitting the network
    if (u !== 'admin' || p !== 'admin123') {
      showMsg('login-msg', 'Invalid username or password.', 'error');
      return;
    }

    // Credentials correct — fire the real auth endpoint
    btn.textContent = 'Signing in…';
    btn.disabled    = true;

    try {
      const res = await fetch('/api/v1/google/auth', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body:    JSON.stringify({ username: u }),
      });

      if (res.status === 200) {
        showMsg('login-msg', 'Login successful! Welcome to NIDS.', 'success');
        setTimeout(() => alert('Welcome to the NIDS Dashboard\\n(Dashboard not yet implemented in this prototype.)'), 900);

      } else if (res.status === 429) {
        // Rate-limited by mitigation layer
        let reason = 'Too Many Requests';
        try { reason = (await res.json()).error || reason; } catch {}
        showMsg('login-msg', 'Too many requests — you have been rate-limited.', 'error');
        showBlockedUI(429, reason);

      } else if (res.status === 403) {
        // Hard-blocked by mitigation layer
        let reason = 'Forbidden';
        try { reason = (await res.json()).reason || reason; } catch {}
        showMsg('login-msg', 'Your IP has been blocked by NIDS.', 'error');
        showBlockedUI(403, reason);

      } else {
        showMsg('login-msg', 'Server error (' + res.status + '). Please try again.', 'error');
      }

    } catch (err) {
      showMsg('login-msg', 'Network error: ' + err.message, 'error');
    } finally {
      btn.textContent = 'Login';
      btn.disabled    = false;
    }
  }

  // ── Signup ────────────────────────────────────────────────────────────────
  function openSignup() {
    document.getElementById('signup-msg').style.display = 'none';
    document.getElementById('modal-signup').classList.add('open');
  }

  function closeSignup() {
    document.getElementById('modal-signup').classList.remove('open');
  }

  function doSignup() {
    const name  = document.getElementById('s-name').value.trim();
    const user  = document.getElementById('s-user').value.trim();
    const email = document.getElementById('s-email').value.trim();
    const p1    = document.getElementById('s-pass').value;
    const p2    = document.getElementById('s-pass2').value;

    if (!name || !user || !email || !p1) {
      showMsg('signup-msg', 'Please fill in all fields.', 'error'); return;
    }
    if (p1 !== p2) {
      showMsg('signup-msg', 'Passwords do not match.', 'error'); return;
    }
    showMsg('signup-msg', 'Account created successfully (Demo Mode).', 'success');
    setTimeout(closeSignup, 2200);
  }

  // Close signup modal on backdrop click
  document.getElementById('modal-signup').addEventListener('click', function(e) {
    if (e.target === this) closeSignup();
  });

  // ── Block popup + blocked page ────────────────────────────────────────────
  function showBlockedUI(status, reason) {
    // 1. Show sticky banner first
    const popup = document.getElementById('block-popup');
    popup.classList.add('show');

    // 2. After 1.5 s, redirect to the full blocked page
    setTimeout(() => {
      popup.classList.remove('show');
      document.getElementById('b-ip').textContent     = '(your IP)';
      document.getElementById('b-status').textContent = 'HTTP ' + status;
      document.getElementById('b-reason').textContent = reason || 'blocked';
      showPage('blocked');
    }, 1500);
  }

  // ── Utility ───────────────────────────────────────────────────────────────
  function showMsg(id, text, type) {
    const el = document.getElementById(id);
    el.textContent  = text;
    el.className    = 'msg ' + type;
    el.style.display = 'block';
  }

  // ── Load tech stack from /api/v1/data ─────────────────────────────────────
  async function loadTech() {
    try {
      const res  = await fetch('/api/v1/data', { headers: { 'Accept': 'application/json' } });

      // Blocked / rate-limited — show popup then redirect
      if (res.status === 403 || res.status === 429) {
        let reason = res.status === 403 ? 'Forbidden' : 'Too Many Requests';
        try { const d = await res.json(); reason = d.reason || d.error || reason; } catch {}
        showBlockedUI(res.status, reason);
        return;
      }

      const data = await res.json();
      const grid = document.getElementById('tech-grid');
      grid.innerHTML = data.technologies.map(t => `
        <div class="tech-card">
          <div class="tech-icon">${t.icon}</div>
          <span>${t.name}</span>
        </div>`).join('');
    } catch (err) {
      document.getElementById('tech-grid').innerHTML =
        `<p style="font-size:13px;color:var(--red)">Failed to load: ${err.message}</p>`;
    }
  }

  // ── Load team members from /api/v1/user ───────────────────────────────────
  async function loadTeam() {
    try {
      const res  = await fetch('/api/v1/user', { headers: { 'Accept': 'application/json' } });

      if (res.status === 403 || res.status === 429) {
        let reason = res.status === 403 ? 'Forbidden' : 'Too Many Requests';
        try { const d = await res.json(); reason = d.reason || d.error || reason; } catch {}
        showBlockedUI(res.status, reason);
        return;
      }

      const data = await res.json();
      const grid = document.getElementById('team-grid');
      grid.innerHTML = data.team.map(m => `
        <div class="team-card">
          <div class="avatar">${m.initials}</div>
          <h3>${m.name}</h3>
          <p>${m.role}</p>
        </div>`).join('');
    } catch (err) {
      document.getElementById('team-grid').innerHTML =
        `<p style="font-size:13px;color:var(--red)">Failed to load: ${err.message}</p>`;
    }
  }

  // Populate both sections as soon as the page loads
  loadTech();
  loadTeam();
</script>
</body>
</html>
"""

# Blocked page HTML — returned by mitigation on hard block / rate-limit for
# browser requests (text/html Accept header).  Overrides the default JSON body.

BLOCKED_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Access Denied — NIDS</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #080808;
      color: #f0f4ff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px 24px;
    }}
    .card {{ text-align: center; max-width: 460px; }}
    .icon {{
      width: 80px; height: 80px;
      background: rgba(239,68,68,0.1);
      border: 1px solid rgba(239,68,68,0.35);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 34px;
      margin: 0 auto 22px;
    }}
    h2 {{ font-size: 28px; font-weight: 800; color: #EF4444; margin-bottom: 10px; }}
    .sub {{ font-size: 14px; color: #666; line-height: 1.7; margin-bottom: 26px; }}
    .detail {{
      background: rgba(239,68,68,0.06);
      border: 1px solid rgba(239,68,68,0.2);
      border-radius: 10px;
      padding: 16px 20px;
      text-align: left;
      margin-bottom: 28px;
    }}
    .row {{
      display: flex;
      justify-content: space-between;
      font-size: 13px;
      padding: 7px 0;
      border-bottom: 1px solid rgba(255,255,255,0.04);
    }}
    .row:last-child {{ border-bottom: none; }}
    .k {{ color: #4B5563; }}
    .v {{ font-family: 'Courier New', monospace; color: #FCA5A5; font-weight: 600; }}
    .note {{ font-size: 13px; color: #444; margin-bottom: 20px; }}
    .btn {{
      padding: 11px 30px;
      background: #EF4444;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
    }}
    .btn:hover {{ opacity: .85; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h2>Access Blocked</h2>
    <p class="sub">
      The Network Intrusion Detection System has intercepted and blocked
      this request due to suspicious activity from your IP address.
    </p>
    <div class="detail">
      <div class="row"><span class="k">Your IP</span>  <span class="v">{ip}</span></div>
      <div class="row"><span class="k">Status</span>   <span class="v">HTTP {status}</span></div>
      <div class="row"><span class="k">Reason</span>   <span class="v">{reason}</span></div>
    </div>
    <p class="note">
      If you believe this is a mistake, contact your network administrator
      to request removal from the block-list.
    </p>
    <button class="btn" onclick="location.href='/'">Return to home</button>
  </div>
</body>
</html>
"""


# ─── REAL-IP EXTRACTION ───────────────────────────────────────────────────────

def get_real_ip() -> str:
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


@app.before_request
def capture_real_ip():
    request.real_ip = get_real_ip()
    print(f"[TestServer] {request.method} {request.path}  ip={request.real_ip}")


app.before_request(mitigation_before_request)


# ─── ROUTES ───────────────────────────────────────────────────────────────────

# ── Website pages ──

@app.route("/", methods=["GET"])
def index():
    """Serve the full NIDS website (home page active by default)."""
    return render_template_string(PAGE_HTML)


@app.route("/login", methods=["GET"])
def login_page():
    """
    Direct-link entry point for the login page.
    Renders the same shell; client-side JS activates the login page from the URL.
    """
    return render_template_string(PAGE_HTML)


@app.route("/blocked", methods=["GET"])
def blocked_page():
    """
    Standalone blocked page — linked to from mitigation.py's HTML response.
    Useful when the user refreshes after being blocked.
    """
    ip     = getattr(request, "real_ip", None) or request.remote_addr
    return make_response(
        BLOCKED_HTML.format(ip=ip, status=403, reason="auto:rate_limit or manual"),
        403,
    )


# ── API endpoints (Table 7.6) ──

@app.route("/api/v1/google/auth", methods=["GET", "POST"])
def google_auth():
    """Primary auth endpoint — main attack target in experiments."""
    time.sleep(0.01)   # simulate ~10 ms auth latency
    return jsonify({"status": "ok", "message": "auth endpoint reached"})


@app.route("/api/v1/user", methods=["GET"])
def get_user():
    """Returns the NIDS project team members — rendered on the home page team section."""
    return jsonify({
        "team": [
            {"name": "Kartik",   "initials": "KA", "role": "Developer"},
            {"name": "Ankit",    "initials": "AN", "role": "Developer"},
            {"name": "Panwan",   "initials": "PA", "role": "Developer"},
            {"name": "Karan",    "initials": "KR", "role": "Developer"},
            {"name": "Ayushman", "initials": "AY", "role": "Developer"},
        ]
    })


@app.route("/api/v1/data", methods=["GET"])
def get_data():
    """Returns the NIDS tech stack — rendered on the home page technologies section."""
    return jsonify({
        "technologies": [
            {"name": "Python",          "icon": "🐍"},
            {"name": "JavaScript",      "icon": "JS"},
            {"name": "Flask",           "icon": "🌶"},
            {"name": "Node.js",         "icon": "⬡"},
            {"name": "Redis",           "icon": "🗄"},
            {"name": "UNSW-NB15 Dataset","icon": "📊"},
        ]
    })


@app.route("/health", methods=["GET"])
def health():
    """Health check — whitelisted from mitigation."""
    return jsonify({"status": "ok"})


# ── Mitigation management (Table 7.6) ──

@app.route("/mitigation/stats", methods=["GET"])
def mitigation_stats():
    """Return mitigation config + live Redis counters."""
    return jsonify(get_mitigation_stats())


@app.route("/mitigation/blocked", methods=["GET"])
def mitigation_blocked():
    """Return a list of all currently blocked IPs with TTL and reason."""
    return jsonify({"blocked_ips": list_blocked_ips()})


@app.route("/mitigation/block", methods=["POST"])
def mitigation_block():
    """
    Manually block an IP.
    Body: { "ip": "x.x.x.x", "reason": "manual", "ttl": 3600 }
    """
    data   = request.get_json() or {}
    ip     = data.get("ip")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    block_ip(ip, data.get("reason", "manual"), int(data.get("ttl", 3600)))
    return jsonify({"blocked": True, "ip": ip})


@app.route("/mitigation/unblock", methods=["POST"])
def mitigation_unblock():
    """
    Remove an IP from the block-list.
    Body: { "ip": "x.x.x.x" }
    """
    data = request.get_json() or {}
    ip   = data.get("ip")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    unblock_ip(ip)
    return jsonify({"unblocked": True, "ip": ip})


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[NIDS Test Server] Starting on http://0.0.0.0:8080")
    print("[NIDS Test Server] Pages   : /   /login   /blocked")
    print("[NIDS Test Server] API     : /api/v1/google/auth   /api/v1/user   /api/v1/data")
    print("[NIDS Test Server] Health  : /health")
    print("[NIDS Test Server] Mitig.  : /mitigation/stats   /mitigation/blocked")
    print("[NIDS Test Server]           /mitigation/block   /mitigation/unblock")
    app.run(host="0.0.0.0", port=8080, debug=False)