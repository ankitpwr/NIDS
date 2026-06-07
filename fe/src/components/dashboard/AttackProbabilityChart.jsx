import React, { useMemo } from "react";
import {
  RadialBarChart,
  RadialBar,
  PolarGrid,
  PolarAngleAxis,
  ResponsiveContainer,
} from "recharts";

/**
 * Shadcn-style Radial Chart — Stacked
 * Shows Normal% (outer ring) and Attack% (inner ring) as two stacked radial bars.
 * Derives values from recent records or falls back to attackRate prop.
 */
export function AttackProbabilityChart({ records, attackRate }) {
  const { attackPct, normalPct, avgProb } = useMemo(() => {
    if (records && records.length > 0) {
      const recent = records.slice(0, 50);
      const attacks = recent.filter((r) => r.prediction === "ATTACK");
      const ap = Math.round((attacks.length / recent.length) * 100);
      const probs = attacks.map((r) => r.attack_probability || 0);
      const avg =
        probs.length > 0
          ? probs.reduce((a, b) => a + b, 0) / probs.length
          : attackRate / 100;
      return {
        attackPct: ap,
        normalPct: 100 - ap,
        avgProb: Math.round(avg * 100),
      };
    }
    return {
      attackPct: attackRate,
      normalPct: 100 - attackRate,
      avgProb: attackRate,
    };
  }, [records, attackRate]);

  // Two radial bars — outer = Normal, inner = Attack
  const chartData = [
    { name: "Normal", value: normalPct, fill: "#00E87A" },
    { name: "Attack", value: attackPct, fill: "#FF2D55" },
  ];

  const threatLevel =
    attackPct >= 60
      ? "CRITICAL"
      : attackPct >= 30
        ? "HIGH"
        : attackPct >= 10
          ? "MEDIUM"
          : "LOW";

  const threatColor =
    attackPct >= 60
      ? "#FF2D55"
      : attackPct >= 30
        ? "#FFB020"
        : attackPct >= 10
          ? "#FFB020"
          : "#00E87A";

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      {/* Radial chart */}
      <div style={{ position: "relative", width: 160, height: 160 }}>
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            data={chartData}
            innerRadius={30}
            outerRadius={72}
            startAngle={90}
            endAngle={-270}
            barSize={14}
          >
            <PolarGrid
              gridType="circle"
              radialLines={false}
              stroke="none"
              polarRadius={[38, 60]}
              style={{ opacity: 0.15 }}
            />
            <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
            <RadialBar
              dataKey="value"
              cornerRadius={7}
              background={{ fill: "#0D2137" }}
            />
          </RadialBarChart>
        </ResponsiveContainer>

        {/* Centre overlay */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            pointerEvents: "none",
          }}
        >
          <span
            style={{
              fontFamily: "'Rajdhani', sans-serif",
              fontSize: 26,
              fontWeight: 700,
              lineHeight: 1,
              color: threatColor,
              filter: `drop-shadow(0 0 10px ${threatColor}80)`,
              transition: "color 0.4s",
            }}
          >
            {avgProb}%
          </span>
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 7,
              letterSpacing: "0.2em",
              color: "#4E7A9C",
              textTransform: "uppercase",
              marginTop: 2,
            }}
          >
            prob
          </span>
        </div>
      </div>

      {/* Legend rows */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 6,
          marginTop: 10,
          width: "100%",
          padding: "0 20px",
        }}
      >
        {[
          { label: "Attack", value: attackPct, color: "#FF2D55" },
          { label: "Normal", value: normalPct, color: "#00E87A" },
        ].map((item) => (
          <div
            key={item.label}
            style={{ display: "flex", alignItems: "center", gap: 8 }}
          >
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: item.color,
                flexShrink: 0,
                boxShadow: `0 0 6px ${item.color}`,
              }}
            />
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                color: "#4E7A9C",
                letterSpacing: "0.12em",
                flex: 1,
                textTransform: "uppercase",
              }}
            >
              {item.label}
            </span>
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                color: item.color,
                fontWeight: 700,
              }}
            >
              {item.value}%
            </span>
          </div>
        ))}
      </div>

      {/* Threat level badge */}
      <div
        style={{
          marginTop: 10,
          padding: "4px 12px",
          borderRadius: 4,
          background: `${threatColor}18`,
          border: `1px solid ${threatColor}40`,
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 9,
          letterSpacing: "0.2em",
          color: threatColor,
          textTransform: "uppercase",
          fontWeight: 700,
        }}
      >
        THREAT · {threatLevel}
      </div>
    </div>
  );
}
