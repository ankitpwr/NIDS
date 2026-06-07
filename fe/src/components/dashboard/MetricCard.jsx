import React from "react";

export function MetricCard({ title, value, sub, icon, color }) {
  const palette = {
    cyan: {
      accent: "#00CFFF",
      glow: "rgba(0,207,255,0.14)",
      dim: "#003E50",
      bar: "#00CFFF",
    },
    red: {
      accent: "#FF2D55",
      glow: "rgba(255,45,85,0.14)",
      dim: "#4A0016",
      bar: "#FF2D55",
    },
    green: {
      accent: "#00E87A",
      glow: "rgba(0,232,122,0.14)",
      dim: "#003D22",
      bar: "#00E87A",
    },
    amber: {
      accent: "#FFB020",
      glow: "rgba(255,176,32,0.14)",
      dim: "#4A3300",
      bar: "#FFB020",
    },
  };

  const c = palette[color] || palette.cyan;

  return (
    <>
      <style>{`
        .metric-card {
          background: #050F1C;
          border: 1px solid #0D2137;
          border-radius: 10px;
          padding: 18px 20px 16px;
          position: relative;
          overflow: hidden;
          cursor: default;
          transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
        }

        .metric-card:hover {
          transform: translateY(-2px);
          border-color: #163352;
        }

        .metric-card-accent-bar {
          position: absolute;
          top: 0; left: 0; right: 0;
          height: 2px;
          transition: opacity 0.2s;
        }

        .metric-card-glow {
          position: absolute;
          top: -40px; right: -20px;
          width: 120px; height: 120px;
          border-radius: 50%;
          opacity: 0;
          transition: opacity 0.3s ease;
          pointer-events: none;
        }

        .metric-card:hover .metric-card-glow { opacity: 1; }

        .metric-card-corner {
          position: absolute;
          width: 8px; height: 8px;
          border-style: solid;
          border-color: transparent;
          opacity: 0;
          transition: opacity 0.25s;
        }
        .metric-card:hover .metric-card-corner { opacity: 1; }
        .metric-corner-tl { top: 0; left: 0; border-width: 1.5px 0 0 1.5px; }
        .metric-corner-br { bottom: 0; right: 0; border-width: 0 1.5px 1.5px 0; }

        .metric-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 12px;
        }

        .metric-title {
          font-family: 'JetBrains Mono', monospace;
          font-size: 9px;
          letter-spacing: 0.22em;
          text-transform: uppercase;
          color: #4E7A9C;
        }

        .metric-icon {
          opacity: 0.5;
          transition: opacity 0.2s;
        }
        .metric-card:hover .metric-icon { opacity: 1; }

        .metric-value {
          font-family: 'Rajdhani', sans-serif;
          font-size: 32px;
          font-weight: 700;
          line-height: 1;
          letter-spacing: 0.02em;
          color: #D8EAF8;
          margin-bottom: 8px;
          transition: color 0.2s;
        }
        .metric-card:hover .metric-value { color: #fff; }

        .metric-sub {
          font-family: 'JetBrains Mono', monospace;
          font-size: 9px;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: #243B52;
        }

        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@700&family=JetBrains+Mono:wght@400&display=swap');
      `}</style>

      <div
        className="metric-card"
        style={{ boxShadow: `0 0 0 0px ${c.accent}` }}
        onMouseEnter={(e) =>
          (e.currentTarget.style.boxShadow = `0 4px 24px rgba(0,0,0,0.5), inset 0 0 0 1px ${c.glow.replace("0.14", "0.08")}`)
        }
        onMouseLeave={(e) => (e.currentTarget.style.boxShadow = "none")}
      >
        {/* Top accent bar */}
        <div
          className="metric-card-accent-bar"
          style={{
            background: `linear-gradient(90deg, ${c.accent}, transparent)`,
          }}
        />

        {/* Corner glow */}
        <div
          className="metric-card-glow"
          style={{
            background: `radial-gradient(circle, ${c.glow} 0%, transparent 70%)`,
          }}
        />

        {/* Corner ticks */}
        <div
          className="metric-card-corner metric-corner-tl"
          style={{ borderColor: c.accent }}
        />
        <div
          className="metric-card-corner metric-corner-br"
          style={{ borderColor: c.accent }}
        />

        <div className="metric-header">
          <span className="metric-title">{title}</span>
          <span className="metric-icon" style={{ color: c.accent }}>
            {icon}
          </span>
        </div>

        <div className="metric-value">{value}</div>
        <div className="metric-sub">{sub}</div>
      </div>
    </>
  );
}
