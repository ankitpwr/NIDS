import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  ShieldAlert,
  ShieldOff,
  ShieldCheck,
  Zap,
  Lock,
  Unlock,
  Activity,
} from "lucide-react";

// ── CONFIG — point at your test-server ───────────────────────────────────────
const TEST_SERVER = "https://test.sketch.qzz.io";
const POLL_MS = 2000;

// ─────────────────────────────────────────────────────────────────────────────
//  MitigationPanel
//  Drop this anywhere in NidsDashboard — it self-polls and self-toggles.
// ─────────────────────────────────────────────────────────────────────────────

export function MitigationPanel() {
  const [enabled, setEnabled] = useState(true);
  const [toggling, setToggling] = useState(false);
  const [stats, setStats] = useState(null);
  const [blockedCount, setBlockedCount] = useState(0);
  const [lastToggle, setLastToggle] = useState(null); // "ON" | "OFF"
  const [flashState, setFlashState] = useState(null); // for ring flash

  // Demo mode: which endpoint to fire at
  const [demoMode, setDemoMode] = useState("protected"); // "protected" | "unprotected"
  const [fireCount, setFireCount] = useState({ ok: 0, blocked: 0 });
  const firingRef = useRef(false);
  const fireTimerRef = useRef(null);

  // ── Poll mitigation/status every 2 s ─────────────────────────────────────
  const poll = useCallback(async () => {
    try {
      const res = await fetch(`${TEST_SERVER}/mitigation/status`);
      if (!res.ok) return;
      const data = await res.json();
      setEnabled(data.enabled);
      setStats(data.stats || {});
      setBlockedCount(data.blocked_count ?? 0);
    } catch (_) {}
  }, []);

  useEffect(() => {
    poll();
    const id = setInterval(poll, POLL_MS);
    return () => clearInterval(id);
  }, [poll]);

  // ── Toggle handler ────────────────────────────────────────────────────────
  const handleToggle = async () => {
    if (toggling) return;
    setToggling(true);
    try {
      const res = await fetch(`${TEST_SERVER}/mitigation/toggle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !enabled }),
      });
      if (res.ok) {
        const data = await res.json();
        setEnabled(data.enabled);
        setLastToggle(data.enabled ? "ON" : "OFF");
        setFlashState(data.enabled ? "on" : "off");
        setTimeout(() => setFlashState(null), 800);
      }
    } catch (_) {}
    setToggling(false);
  };

  // ── Live fire demo (sends 1 req/300ms to chosen endpoint) ─────────────────
  const startFiring = () => {
    if (firingRef.current) return;
    firingRef.current = true;
    const endpoint =
      demoMode === "protected"
        ? `${TEST_SERVER}/api/v1/google/auth`
        : `${TEST_SERVER}/api/v1/unprotected`;

    const fire = async () => {
      if (!firingRef.current) return;
      try {
        const r = await fetch(endpoint, { method: "GET" });
        setFireCount((prev) => ({
          ok: r.status === 200 ? prev.ok + 1 : prev.ok,
          blocked: r.status === 403 ? prev.blocked + 1 : prev.blocked,
        }));
      } catch (_) {}
      if (firingRef.current) {
        fireTimerRef.current = setTimeout(fire, 300);
      }
    };
    fire();
  };

  const stopFiring = () => {
    firingRef.current = false;
    clearTimeout(fireTimerRef.current);
  };

  const resetFire = () => {
    stopFiring();
    setFireCount({ ok: 0, blocked: 0 });
  };

  useEffect(() => () => stopFiring(), []);

  // ── Derived values ────────────────────────────────────────────────────────
  const totalFire = fireCount.ok + fireCount.blocked;
  const blockPct =
    totalFire > 0 ? Math.round((fireCount.blocked / totalFire) * 100) : 0;
  const allowPct = 100 - blockPct;
  const rateLimit = stats?.total_rate_limited || 0;
  const totalBlocked =
    stats?.requests_blocked_total || stats?.total_blocked || 0;
  const totalAllowed = stats?.total_allowed || 0;

  const accentOn = "#00E87A";
  const accentOff = "#FF2D55";
  const accent = enabled ? accentOn : accentOff;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=JetBrains+Mono:wght@300;400;500;700&display=swap');

        .mit-panel {
          background: #050F1C;
          border: 1px solid #0D2137;
          border-radius: 10px;
          overflow: hidden;
          position: relative;
          font-family: 'JetBrains Mono', monospace;
        }

        .mit-panel::before, .mit-panel::after {
          content: '';
          position: absolute;
          width: 8px; height: 8px;
          border-style: solid;
          z-index: 10;
        }
        .mit-panel::before { top:0; left:0; border-color: var(--mit-accent); border-width: 1.5px 0 0 1.5px; }
        .mit-panel::after  { bottom:0; right:0; border-color: var(--mit-accent); border-width: 0 1.5px 1.5px 0; }

        .mit-header {
          padding: 13px 16px 11px;
          border-bottom: 1px solid #0D2137;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }

        .mit-header-left {
          display: flex; align-items: center; gap: 8px;
        }

        .mit-label {
          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: 0.25em;
          color: #4E7A9C;
        }

        /* ── Toggle Switch ── */
        .mit-toggle-wrap {
          display: flex; align-items: center; gap: 10px;
        }

        .mit-toggle-text {
          font-size: 9px;
          font-weight: 700;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          transition: color 0.3s;
          min-width: 28px;
        }

        .mit-switch {
          position: relative;
          width: 44px; height: 24px;
          cursor: pointer;
          user-select: none;
        }

        .mit-switch input { display: none; }

        .mit-switch-track {
          position: absolute; inset: 0;
          border-radius: 12px;
          border: 1px solid;
          transition: background 0.3s, border-color 0.3s;
        }

        .mit-switch-track.on {
          background: rgba(0,232,122,0.15);
          border-color: rgba(0,232,122,0.4);
        }

        .mit-switch-track.off {
          background: rgba(255,45,85,0.1);
          border-color: rgba(255,45,85,0.3);
        }

        .mit-switch-thumb {
          position: absolute;
          top: 3px; left: 3px;
          width: 16px; height: 16px;
          border-radius: 50%;
          transition: transform 0.3s cubic-bezier(.34,1.56,.64,1), background 0.3s, box-shadow 0.3s;
        }

        .mit-switch-thumb.on {
          transform: translateX(20px);
          background: #00E87A;
          box-shadow: 0 0 10px rgba(0,232,122,0.7);
        }

        .mit-switch-thumb.off {
          transform: translateX(0);
          background: #FF2D55;
          box-shadow: 0 0 8px rgba(255,45,85,0.5);
        }

        /* flash ring on toggle */
        .mit-switch-ring {
          position: absolute;
          inset: -4px;
          border-radius: 16px;
          border: 2px solid;
          animation: ringFlash 0.5s ease-out forwards;
          pointer-events: none;
        }

        @keyframes ringFlash {
          0%   { opacity: 1; transform: scale(1);    }
          100% { opacity: 0; transform: scale(1.15); }
        }

        /* ── Body ── */
        .mit-body { padding: 14px 16px; }

        /* ── Stats Row ── */
        .mit-stats {
          display: grid;
          grid-template-columns: 1fr 1fr 1fr;
          gap: 8px;
          margin-bottom: 14px;
        }

        .mit-stat {
          background: #081525;
          border: 1px solid #0D2137;
          border-radius: 6px;
          padding: 9px 10px;
          text-align: center;
        }

        .mit-stat-val {
          font-family: 'Rajdhani', sans-serif;
          font-size: 20px;
          font-weight: 700;
          line-height: 1;
        }

        .mit-stat-lbl {
          font-size: 7px;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          color: #2A4A66;
          margin-top: 3px;
        }

        /* ── Demo Mode ── */
        .mit-demo-section {
          background: #081525;
          border: 1px solid #0D2137;
          border-radius: 8px;
          padding: 12px 14px;
          margin-bottom: 12px;
        }

        .mit-demo-title {
          font-size: 8px;
          text-transform: uppercase;
          letter-spacing: 0.25em;
          color: #2A4A66;
          margin-bottom: 10px;
        }

        .mit-endpoint-toggle {
          display: flex;
          gap: 6px;
          margin-bottom: 12px;
        }

        .mit-ep-btn {
          flex: 1;
          padding: 7px 0;
          border-radius: 5px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 8px;
          font-weight: 700;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          cursor: pointer;
          border: 1px solid;
          transition: all 0.2s;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 5px;
        }

        .mit-ep-btn.active-prot {
          background: rgba(0,207,255,0.12);
          border-color: rgba(0,207,255,0.4);
          color: #00CFFF;
        }

        .mit-ep-btn.active-unprot {
          background: rgba(255,176,32,0.12);
          border-color: rgba(255,176,32,0.4);
          color: #FFB020;
        }

        .mit-ep-btn.inactive {
          background: transparent;
          border-color: #0D2137;
          color: #2A4A66;
        }

        .mit-ep-btn:hover:not(.active-prot):not(.active-unprot) {
          border-color: #163352;
          color: #4E7A9C;
        }

        /* fire button */
        .mit-fire-row {
          display: flex; gap: 6px; margin-bottom: 10px;
        }

        .mit-fire-btn {
          flex: 1;
          padding: 8px;
          border-radius: 5px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 8px;
          font-weight: 700;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          cursor: pointer;
          border: 1px solid;
          transition: all 0.2s;
        }

        .mit-fire-btn.fire {
          background: rgba(255,45,85,0.12);
          border-color: rgba(255,45,85,0.35);
          color: #FF2D55;
        }
        .mit-fire-btn.fire:hover {
          background: rgba(255,45,85,0.2);
        }
        .mit-fire-btn.fire.firing {
          background: rgba(255,45,85,0.2);
          border-color: rgba(255,45,85,0.6);
          animation: btnPulse 0.8s ease-in-out infinite;
        }

        @keyframes btnPulse {
          0%,100% { box-shadow: 0 0 0 0 rgba(255,45,85,0); }
          50%      { box-shadow: 0 0 0 4px rgba(255,45,85,0.15); }
        }

        .mit-fire-btn.stop {
          background: rgba(255,176,32,0.1);
          border-color: rgba(255,176,32,0.3);
          color: #FFB020;
        }

        .mit-fire-btn.reset {
          background: rgba(78,122,156,0.08);
          border-color: #0D2137;
          color: #4E7A9C;
        }

        /* result bar */
        .mit-result-bar-wrap {
          display: flex;
          height: 6px;
          border-radius: 3px;
          overflow: hidden;
          background: #0D2137;
          margin-bottom: 8px;
        }

        .mit-result-bar-ok {
          background: #00E87A;
          box-shadow: 1px 0 6px rgba(0,232,122,0.5);
          transition: width 0.4s ease;
        }

        .mit-result-bar-blocked {
          background: #FF2D55;
          box-shadow: 1px 0 6px rgba(255,45,85,0.5);
          transition: width 0.4s ease;
        }

        .mit-result-counts {
          display: flex;
          justify-content: space-between;
          font-size: 9px;
          color: #4E7A9C;
        }

        .mit-count-ok      { color: #00E87A; font-weight: 700; }
        .mit-count-blocked { color: #FF2D55; font-weight: 700; }

        /* ── Status chip ── */
        .mit-status-chip {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 5px 10px;
          border-radius: 4px;
          font-size: 8px;
          font-weight: 700;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          border: 1px solid;
          transition: all 0.3s;
        }

        .mit-status-chip.on {
          background: rgba(0,232,122,0.08);
          border-color: rgba(0,232,122,0.25);
          color: #00E87A;
        }
        .mit-status-chip.off {
          background: rgba(255,45,85,0.08);
          border-color: rgba(255,45,85,0.25);
          color: #FF2D55;
        }

        .mit-status-dot {
          width: 5px; height: 5px;
          border-radius: 50%;
        }
        .on .mit-status-dot  { background: #00E87A; box-shadow: 0 0 6px #00E87A; animation: dotPulse 1.5s infinite; }
        .off .mit-status-dot { background: #FF2D55; }

        @keyframes dotPulse {
          0%,100% { opacity: 1; }
          50%      { opacity: 0.4; }
        }

        /* ── Proof badge ── */
        .mit-proof {
          margin-top: 10px;
          padding: 8px 12px;
          border-radius: 6px;
          border: 1px dashed;
          font-size: 8px;
          letter-spacing: 0.12em;
          line-height: 1.6;
          color: #4E7A9C;
          transition: border-color 0.3s, background 0.3s;
        }

        .mit-proof.active {
          border-color: rgba(0,207,255,0.25);
          background: rgba(0,207,255,0.04);
          color: #00CFFF;
        }
      `}</style>

      <div className="mit-panel" style={{ "--mit-accent": accent }}>
        {/* Header */}
        <div className="mit-header">
          <div className="mit-header-left">
            {enabled ? (
              <ShieldCheck size={13} style={{ color: accentOn }} />
            ) : (
              <ShieldOff size={13} style={{ color: accentOff }} />
            )}
            <span className="mit-label">Mitigation Engine</span>
          </div>

          <div className="mit-toggle-wrap">
            <span
              className="mit-toggle-text"
              style={{ color: enabled ? accentOn : accentOff }}
            >
              {enabled ? "ON" : "OFF"}
            </span>

            <div
              className="mit-switch"
              onClick={handleToggle}
              title={`Click to turn mitigation ${enabled ? "OFF" : "ON"}`}
            >
              <div className={`mit-switch-track ${enabled ? "on" : "off"}`} />
              <div className={`mit-switch-thumb ${enabled ? "on" : "off"}`} />
              {flashState && (
                <div
                  className="mit-switch-ring"
                  style={{
                    borderColor: flashState === "on" ? accentOn : accentOff,
                  }}
                />
              )}
            </div>

            <div className={`mit-status-chip ${enabled ? "on" : "off"}`}>
              <div className="mit-status-dot" />
              {enabled ? "ACTIVE" : "BYPASSED"}
            </div>
          </div>
        </div>

        {/* Body */}
        <div className="mit-body">
          {/* Stats */}
          <div className="mit-stats">
            <div className="mit-stat">
              <div className="mit-stat-val" style={{ color: "#FF2D55" }}>
                {Number(totalBlocked).toLocaleString()}
              </div>
              <div className="mit-stat-lbl">Blocked</div>
            </div>
            <div className="mit-stat">
              <div className="mit-stat-val" style={{ color: "#FFB020" }}>
                {Number(rateLimit).toLocaleString()}
              </div>
              <div className="mit-stat-lbl">Rate Ltd</div>
            </div>
            <div className="mit-stat">
              <div className="mit-stat-val" style={{ color: "#00CFFF" }}>
                {blockedCount}
              </div>
              <div className="mit-stat-lbl">IPs Blocked</div>
            </div>
          </div>

          {/* Live fire demo section */}
          <div className="mit-demo-section">
            <div className="mit-demo-title">⚡ Live Demo — Send Requests</div>

            {/* Endpoint selector */}
            <div className="mit-endpoint-toggle">
              <button
                className={`mit-ep-btn ${demoMode === "protected" ? "active-prot" : "inactive"}`}
                onClick={() => {
                  resetFire();
                  setDemoMode("protected");
                }}
              >
                <Lock size={9} />
                Protected
              </button>
              <button
                className={`mit-ep-btn ${demoMode === "unprotected" ? "active-unprot" : "inactive"}`}
                onClick={() => {
                  resetFire();
                  setDemoMode("unprotected");
                }}
              >
                <Unlock size={9} />
                Unprotected
              </button>
            </div>

            {/* Endpoint path display */}
            <div
              style={{
                fontSize: 8,
                color: "#2A4A66",
                letterSpacing: "0.1em",
                marginBottom: 10,
                fontFamily: "JetBrains Mono",
                padding: "4px 6px",
                background: "#050F1C",
                borderRadius: 4,
                border: "1px solid #0A1A2A",
              }}
            >
              →{" "}
              {demoMode === "protected"
                ? "/api/v1/google/auth"
                : "/api/v1/unprotected"}
            </div>

            {/* Fire buttons */}
            <div className="mit-fire-row">
              <button
                className={`mit-fire-btn fire ${firingRef.current ? "firing" : ""}`}
                onClick={startFiring}
                disabled={firingRef.current}
              >
                <Activity
                  size={9}
                  style={{ display: "inline", marginRight: 4 }}
                />
                Fire Requests
              </button>
              <button className="mit-fire-btn stop" onClick={stopFiring}>
                Stop
              </button>
              <button className="mit-fire-btn reset" onClick={resetFire}>
                Reset
              </button>
            </div>

            {/* Result bar */}
            {totalFire > 0 && (
              <>
                <div className="mit-result-bar-wrap">
                  <div
                    className="mit-result-bar-ok"
                    style={{ width: `${allowPct}%` }}
                  />
                  <div
                    className="mit-result-bar-blocked"
                    style={{ width: `${blockPct}%` }}
                  />
                </div>
                <div className="mit-result-counts">
                  <span>
                    <span className="mit-count-ok">✓ {fireCount.ok}</span>
                    <span style={{ color: "#2A4A66", margin: "0 4px" }}>
                      passed
                    </span>
                  </span>
                  <span>
                    <span style={{ color: "#2A4A66", margin: "0 4px" }}>
                      blocked
                    </span>
                    <span className="mit-count-blocked">
                      {fireCount.blocked} ✕
                    </span>
                  </span>
                </div>
              </>
            )}
          </div>

          {/* Proof badge */}
          <div
            className={`mit-proof ${fireCount.blocked > 0 && enabled ? "active" : ""}`}
          >
            {enabled
              ? fireCount.blocked > 0
                ? `✓ ${fireCount.blocked}/${totalFire} requests intercepted by rate limiter — 403 Forbidden returned to attacker`
                : "Rate limiter armed · slide toggle OFF to compare unprotected behaviour"
              : "⚠ Mitigation disabled · all requests pass through · ML will flag as ATTACK but NO blocking occurs"}
          </div>
        </div>
      </div>
    </>
  );
}
