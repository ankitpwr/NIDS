import React from "react";

export function LiveLogTable({ records }) {
  if (!records || records.length === 0) {
    return (
      <div
        style={{
          padding: "32px 0",
          textAlign: "center",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: "#243B52",
          letterSpacing: "0.15em",
          textTransform: "uppercase",
        }}
      >
        Awaiting flow data…
      </div>
    );
  }

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&display=swap');

        .log-table { width: 100%; border-collapse: collapse; font-family: 'JetBrains Mono', monospace; }

        .log-table thead tr {
          border-bottom: 1px solid #0D2137;
        }

        .log-table thead th {
          padding: 8px 14px;
          font-size: 8px;
          letter-spacing: 0.25em;
          text-transform: uppercase;
          color: #2A4A66;
          font-weight: 500;
          text-align: left;
          white-space: nowrap;
        }

        .log-row {
          border-bottom: 1px solid #0A1A2A;
          transition: background 0.15s;
        }

        .log-row:hover { background: rgba(13,33,55,0.6) !important; }
        .log-row:last-child { border-bottom: none; }

        .log-row.is-attack {
          background: rgba(255,45,85,0.04);
          border-left: 2px solid rgba(255,45,85,0.4);
          animation: rowFlash 0.5s ease-out;
        }

        @keyframes rowFlash {
          0%   { background: rgba(255,45,85,0.12); }
          100% { background: rgba(255,45,85,0.04); }
        }

        .log-table td {
          padding: 7px 14px;
          font-size: 11px;
          white-space: nowrap;
        }

        .log-time   { color: #2A4A66; font-size: 10px; }
        .log-ip     { color: #00CFFF; }
        .log-bytes  { color: #4E7A9C; font-size: 10px; }
        .log-proto  { color: #4E7A9C; font-size: 10px; text-transform: uppercase; }

        .badge {
          display: inline-block;
          padding: 2px 8px;
          border-radius: 3px;
          font-size: 8px;
          font-weight: 700;
          letter-spacing: 0.15em;
          text-transform: uppercase;
        }

        .badge-attack {
          background: rgba(255,45,85,0.15);
          color: #FF2D55;
          border: 1px solid rgba(255,45,85,0.3);
        }

        .badge-normal {
          background: rgba(0,232,122,0.08);
          color: #00E87A;
          border: 1px solid rgba(0,232,122,0.2);
        }

        .prob-bar-wrap {
          display: flex;
          align-items: center;
          gap: 7px;
        }

        .prob-bar-bg {
          flex: 1;
          height: 3px;
          background: #0D2137;
          border-radius: 2px;
          min-width: 50px;
          overflow: hidden;
        }

        .prob-bar-fill {
          height: 100%;
          border-radius: 2px;
          transition: width 0.3s ease;
        }

        .prob-value {
          font-size: 10px;
          font-weight: 600;
          min-width: 38px;
          text-align: right;
        }
      `}</style>

      <table className="log-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source IP</th>
            <th>Status</th>
            <th>Prob</th>
            <th>Bytes ↑/↓</th>
            <th>Proto</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r, i) => {
            const isAttack = r.prediction === "ATTACK";
            const timeStr = new Date(r.timestamp)
              .toISOString()
              .substring(11, 23);
            const prob = r.attack_probability ?? null;
            const probPct = prob !== null ? Math.round(prob * 100) : null;
            const probColor = isAttack ? "#FF2D55" : "#00E87A";

            return (
              <tr key={i} className={`log-row ${isAttack ? "is-attack" : ""}`}>
                <td className="log-time">{timeStr}</td>
                <td className="log-ip">{r.source_ip || "—"}</td>
                <td>
                  <span
                    className={`badge ${isAttack ? "badge-attack" : "badge-normal"}`}
                  >
                    {isAttack ? "● ATTACK" : "✓ NORMAL"}
                  </span>
                </td>
                <td>
                  {probPct !== null ? (
                    <div className="prob-bar-wrap">
                      <div className="prob-bar-bg">
                        <div
                          className="prob-bar-fill"
                          style={{
                            width: `${probPct}%`,
                            background: probColor,
                            boxShadow: `0 0 4px ${probColor}80`,
                          }}
                        />
                      </div>
                      <span className="prob-value" style={{ color: probColor }}>
                        {probPct}%
                      </span>
                    </div>
                  ) : (
                    <span style={{ color: "#243B52" }}>—</span>
                  )}
                </td>
                <td className="log-bytes">
                  {r.features?.sbytes ?? 0}B / {r.features?.dbytes ?? 0}B
                </td>
                <td className="log-proto">{r.features?.proto || "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}
