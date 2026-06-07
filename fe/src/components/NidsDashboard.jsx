import React from "react";
import { ShieldAlert, Activity, Server, Zap, Globe, Wifi } from "lucide-react";
import { useNidsData } from "../hooks/useNidsData";
import { StatusBanner } from "./dashboard/StatusBanner";
import { MetricCard } from "./dashboard/MetricCard";
import { TrafficChart } from "./dashboard/TrafficChart";
import { SourceIpsChart } from "./dashboard/SourceIpsChart";
import { ProtocolChart } from "./dashboard/ProtocolChart";
import { LiveLogTable } from "./dashboard/LiveLogTable";
import { AttackProbabilityChart } from "./dashboard/AttackProbabilityChart";

export function NidsDashboard() {
  const { stats, records, history, health, isUnderAttack } = useNidsData();

  const attackRate = parseFloat(stats.attack_rate_pct) || 0;

  return (
    <>
      {/* Google Fonts */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@300;400;500;700&display=swap');

        :root {
          --bg-base:    #010B14;
          --bg-card:    #050F1C;
          --bg-card2:   #081525;
          --border:     #0D2137;
          --border-hi:  #163352;
          --cyan:       #00CFFF;
          --cyan-dim:   #007FA6;
          --cyan-glow:  rgba(0,207,255,0.12);
          --red:        #FF2D55;
          --red-dim:    #8B0020;
          --red-glow:   rgba(255,45,85,0.15);
          --green:      #00E87A;
          --green-dim:  #006638;
          --green-glow: rgba(0,232,122,0.12);
          --amber:      #FFB020;
          --amber-glow: rgba(255,176,32,0.12);
          --text-1:     #D8EAF8;
          --text-2:     #4E7A9C;
          --text-3:     #243B52;
        }

        * { box-sizing: border-box; margin: 0; }

        body, html { background: var(--bg-base); }

        .nids-root {
          min-height: 100vh;
          background: var(--bg-base);
          background-image:
            linear-gradient(rgba(0,207,255,0.025) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,207,255,0.025) 1px, transparent 1px);
          background-size: 40px 40px;
          font-family: 'JetBrains Mono', monospace;
          color: var(--text-1);
          padding: 20px 24px 32px;
        }

        /* ── Header ─────────────────────────────────── */
        .nids-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding-bottom: 20px;
          margin-bottom: 20px;
          border-bottom: 1px solid var(--border);
        }

        .nids-header-left { display: flex; flex-direction: column; gap: 6px; }

        .nids-title {
          display: flex;
          align-items: center;
          gap: 12px;
          font-family: 'Rajdhani', sans-serif;
          font-size: 22px;
          font-weight: 700;
          letter-spacing: 0.15em;
          color: var(--text-1);
        }

        .nids-title svg { color: var(--cyan); filter: drop-shadow(0 0 8px var(--cyan)); }

        .nids-subtitle {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 10px;
          letter-spacing: 0.25em;
          color: var(--text-2);
          text-transform: uppercase;
        }

        .pulse-dot {
          width: 7px; height: 7px;
          border-radius: 50%;
          background: var(--green);
          box-shadow: 0 0 10px var(--green);
          animation: pulseDot 2s ease-in-out infinite;
        }

        @keyframes pulseDot {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(0.8); }
        }

        .nids-header-right {
          display: flex; gap: 16px;
        }

        .header-stat {
          text-align: right;
        }

        .header-stat-label {
          font-size: 9px;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          color: var(--text-3);
        }

        .header-stat-value {
          font-size: 13px;
          font-weight: 700;
          color: var(--cyan);
        }

        /* ── Metric Grid ────────────────────────────── */
        .metrics-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 12px;
          margin-bottom: 20px;
        }

        /* ── Charts Row ─────────────────────────────── */
        .charts-row {
          display: grid;
          grid-template-columns: 1fr 340px;
          gap: 14px;
          margin-bottom: 14px;
        }

        /* ── Bottom Row ─────────────────────────────── */
        .bottom-row {
          display: grid;
          grid-template-columns: 200px 260px 1fr;
          gap: 14px;
          margin-bottom: 14px;
        }

        /* ── Card ───────────────────────────────────── */
        .card {
          background: var(--bg-card);
          border: 1px solid var(--border);
          border-radius: 10px;
          overflow: hidden;
          position: relative;
          transition: border-color 0.25s, box-shadow 0.25s;
        }

        .card:hover {
          border-color: var(--border-hi);
          box-shadow: 0 0 0 1px var(--border-hi), 0 8px 32px rgba(0,0,0,0.4);
        }

        /* corner ticks */
        .card::before, .card::after {
          content: '';
          position: absolute;
          width: 8px; height: 8px;
          border-color: var(--cyan-dim);
          border-style: solid;
          opacity: 0.5;
          transition: opacity 0.25s;
          z-index: 10;
        }
        .card::before { top: 0; left: 0; border-width: 1px 0 0 1px; }
        .card::after  { bottom: 0; right: 0; border-width: 0 1px 1px 0; }
        .card:hover::before, .card:hover::after { opacity: 1; }

        .card-header {
          padding: 14px 18px 10px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid var(--border);
        }

        .card-title {
          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: 0.25em;
          color: var(--text-2);
          font-family: 'JetBrains Mono', monospace;
        }

        .card-body { padding: 16px 18px; }
        .card-body-chart { padding: 12px 8px 8px; }

        /* ── Footer ─────────────────────────────────── */
        .nids-footer {
          margin-top: 20px;
          padding-top: 16px;
          border-top: 1px solid var(--border);
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 20px;
          font-size: 9px;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          color: var(--text-3);
        }

        .nids-footer-sep { opacity: 0.3; }

        .footer-ml-status {
          color: var(--green);
        }

        @media (max-width: 1100px) {
          .charts-row { grid-template-columns: 1fr; }
          .bottom-row  { grid-template-columns: 1fr 1fr; }
          .bottom-row .log-card { grid-column: span 2; }
        }

        @media (max-width: 720px) {
          .metrics-grid { grid-template-columns: 1fr 1fr; }
          .bottom-row { grid-template-columns: 1fr; }
          .bottom-row .log-card { grid-column: auto; }
        }
      `}</style>

      <div className="nids-root">
        {/* Header */}
        <header className="nids-header">
          <div className="nids-header-left">
            <h1 className="nids-title">
              <ShieldAlert size={22} />
              NIDS · THREAT MONITOR
            </h1>
            <div className="nids-subtitle">
              <span className="pulse-dot" />
              LIVE — UNSW-NB15 MODEL
            </div>
          </div>
          <div className="nids-header-right">
            <div className="header-stat">
              <div className="header-stat-label">ML Service</div>
              <div className="header-stat-value">
                {health.ml_service || "—"}
              </div>
            </div>
            <div className="header-stat">
              <div className="header-stat-label">Agent Port</div>
              <div className="header-stat-value">:8080</div>
            </div>
          </div>
        </header>

        {/* Status Banner */}
        <StatusBanner
          isUnderAttack={isUnderAttack}
          attacksDetected={stats.attacks_detected}
          totalFlows={stats.total_flows}
        />

        {/* Metric Cards */}
        <div className="metrics-grid">
          <MetricCard
            title="Total Flows"
            value={stats.total_flows.toLocaleString()}
            sub="session total"
            icon={<Activity size={15} />}
            color="cyan"
          />
          <MetricCard
            title="Attacks Detected"
            value={stats.attacks_detected.toLocaleString()}
            sub="malicious flows"
            icon={<Zap size={15} />}
            color="red"
          />
          <MetricCard
            title="Normal Flows"
            value={stats.normal_flows.toLocaleString()}
            sub="clean traffic"
            icon={<Globe size={15} />}
            color="green"
          />
          <MetricCard
            title="Attack Rate"
            value={`${stats.attack_rate_pct}%`}
            sub="of all traffic"
            icon={<Server size={15} />}
            color={attackRate > 20 ? "amber" : "green"}
          />
        </div>

        {/* Charts Row */}
        <div className="charts-row">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Traffic Timeline</span>
              <Wifi size={12} style={{ color: "var(--text-3)" }} />
            </div>
            <div className="card-body-chart" style={{ height: 240 }}>
              <TrafficChart data={history} />
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Top Source IPs</span>
            </div>
            <div className="card-body-chart" style={{ height: 240 }}>
              <AttackProbabilityChart
                records={records}
                attackRate={attackRate}
              />
            </div>
          </div>
        </div>

        {/* Bottom Row */}
        <div className="bottom-row">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Protocol Mix</span>
            </div>
            <div
              className="card-body-chart"
              style={{
                height: 220,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <ProtocolChart records={records} />
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Attack Probability</span>
            </div>
            <div
              className="card-body-chart"
              style={{
                height: 220,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SourceIpsChart records={records} />
            </div>
          </div>

          <div className="card log-card">
            <div className="card-header">
              <span className="card-title">Live Flow Log</span>
              <span
                style={{
                  fontSize: 9,
                  color: "var(--text-3)",
                  letterSpacing: "0.1em",
                }}
              >
                LAST 20
              </span>
            </div>
            <div style={{ overflowX: "auto" }}>
              <LiveLogTable records={records.slice(0, 20)} />
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="nids-footer">
          <span>MODEL · UNSW-NB15</span>
          <span className="nids-footer-sep">|</span>
          <span className="footer-ml-status">
            ML SERVICE · {health.ml_service || "CONNECTED"}
          </span>
          <span className="nids-footer-sep">|</span>
          <span>AGENT · PORT 8080</span>
        </footer>
      </div>
    </>
  );
}
