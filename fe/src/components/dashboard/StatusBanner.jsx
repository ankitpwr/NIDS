import React, { useEffect, useRef } from "react";
import { ShieldAlert, ShieldCheck } from "lucide-react";

export function StatusBanner({ isUnderAttack, attacksDetected, totalFlows }) {
  const bannerRef = useRef(null);

  useEffect(() => {
    const el = bannerRef.current;
    if (!el) return;
    el.style.opacity = "0";
    el.style.transform = "translateY(-6px)";
    requestAnimationFrame(() => {
      el.style.transition = "opacity 0.4s ease, transform 0.4s ease";
      el.style.opacity = "1";
      el.style.transform = "translateY(0)";
    });
  }, [isUnderAttack]);

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=JetBrains+Mono:wght@400&display=swap');

        .status-banner {
          border-radius: 10px;
          border: 1px solid;
          padding: 14px 20px;
          margin-bottom: 18px;
          display: flex;
          align-items: center;
          gap: 16px;
          position: relative;
          overflow: hidden;
        }

        .status-banner.attack {
          background: rgba(255,45,85,0.06);
          border-color: rgba(255,45,85,0.3);
          box-shadow: 0 0 40px rgba(255,45,85,0.1), inset 0 0 60px rgba(255,45,85,0.03);
        }

        .status-banner.normal {
          background: rgba(0,232,122,0.04);
          border-color: rgba(0,232,122,0.2);
          box-shadow: 0 0 30px rgba(0,232,122,0.06);
        }

        /* Animated scan line on attack */
        .status-banner.attack::after {
          content: '';
          position: absolute;
          top: 0; left: -100%;
          width: 60%; height: 100%;
          background: linear-gradient(90deg, transparent, rgba(255,45,85,0.06), transparent);
          animation: bannerScan 3s linear infinite;
        }

        @keyframes bannerScan {
          0%   { left: -60%; }
          100% { left: 120%; }
        }

        .status-icon-wrap {
          position: relative;
          flex-shrink: 0;
        }

        .status-icon-wrap.attack svg  { color: #FF2D55; filter: drop-shadow(0 0 12px rgba(255,45,85,0.8)); }
        .status-icon-wrap.normal svg  { color: #00E87A; filter: drop-shadow(0 0 10px rgba(0,232,122,0.7)); }

        .status-icon-ring {
          position: absolute;
          inset: -6px;
          border-radius: 50%;
          border: 1px solid;
          animation: ringPulse 2s ease-in-out infinite;
        }

        .attack .status-icon-ring { border-color: rgba(255,45,85,0.4); }
        .normal .status-icon-ring { border-color: rgba(0,232,122,0.3); }

        @keyframes ringPulse {
          0%, 100% { transform: scale(1); opacity: 1; }
          50%       { transform: scale(1.3); opacity: 0; }
        }

        .status-text { flex: 1; }

        .status-heading {
          font-family: 'Rajdhani', sans-serif;
          font-size: 16px;
          font-weight: 700;
          letter-spacing: 0.12em;
          text-transform: uppercase;
        }

        .attack .status-heading  { color: #FF2D55; }
        .normal .status-heading  { color: #00E87A; }

        .status-sub {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          letter-spacing: 0.08em;
          color: #4E7A9C;
          margin-top: 4px;
        }

        .status-badge {
          font-family: 'JetBrains Mono', monospace;
          font-size: 9px;
          letter-spacing: 0.2em;
          padding: 5px 12px;
          border-radius: 4px;
          text-transform: uppercase;
          font-weight: 700;
          flex-shrink: 0;
        }

        .attack .status-badge  {
          background: rgba(255,45,85,0.15);
          color: #FF2D55;
          border: 1px solid rgba(255,45,85,0.3);
          animation: badgeBlink 1.2s ease-in-out infinite;
        }

        .normal .status-badge  {
          background: rgba(0,232,122,0.1);
          color: #00E87A;
          border: 1px solid rgba(0,232,122,0.2);
        }

        @keyframes badgeBlink {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.5; }
        }
      `}</style>

      <div
        ref={bannerRef}
        className={`status-banner ${isUnderAttack ? "attack" : "normal"}`}
      >
        <div
          className={`status-icon-wrap ${isUnderAttack ? "attack" : "normal"}`}
        >
          <div className="status-icon-ring" />
          {isUnderAttack ? (
            <ShieldAlert size={28} />
          ) : (
            <ShieldCheck size={28} />
          )}
        </div>

        <div className="status-text">
          <div className="status-heading">
            {isUnderAttack
              ? "Attack Detected — System Under Threat"
              : "System Normal — No Active Threats"}
          </div>
          <div className="status-sub">
            {isUnderAttack
              ? `${attacksDetected.toLocaleString()} malicious flows flagged this session`
              : `${totalFlows.toLocaleString()} flows monitored · all traffic within normal parameters`}
          </div>
        </div>

        <div className="status-badge">
          {isUnderAttack ? "● THREAT ACTIVE" : "● SECURE"}
        </div>
      </div>
    </>
  );
}
