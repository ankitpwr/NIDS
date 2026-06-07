import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null;

  return (
    <div
      style={{
        background: "#050F1C",
        border: "1px solid #0D2137",
        borderRadius: 6,
        padding: "10px 14px",
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 11,
        boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
      }}
    >
      <div
        style={{
          color: "#4E7A9C",
          fontSize: 9,
          letterSpacing: "0.2em",
          marginBottom: 8,
          textTransform: "uppercase",
        }}
      >
        {label}
      </div>
      {payload.map((p, i) => (
        <div
          key={i}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 4,
          }}
        >
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: p.color,
              display: "inline-block",
              boxShadow: `0 0 6px ${p.color}`,
            }}
          />
          <span
            style={{
              color: "#4E7A9C",
              textTransform: "uppercase",
              fontSize: 9,
              letterSpacing: "0.1em",
            }}
          >
            {p.name}
          </span>
          <span
            style={{
              color: p.color,
              fontWeight: 700,
              marginLeft: "auto",
              paddingLeft: 16,
            }}
          >
            {p.value}
          </span>
        </div>
      ))}
    </div>
  );
};

export function TrafficChart({ data }) {
  if (!data || data.length === 0) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: "#243B52",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          letterSpacing: "0.15em",
          textTransform: "uppercase",
        }}
      >
        Awaiting flow data…
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={data}
        margin={{ top: 8, right: 8, left: -24, bottom: 0 }}
      >
        <defs>
          <linearGradient id="gradAttack" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#FF2D55" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#FF2D55" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00E87A" stopOpacity={0.15} />
            <stop offset="100%" stopColor="#00E87A" stopOpacity={0} />
          </linearGradient>
          <filter id="glowRed">
            <feGaussianBlur stdDeviation="2" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <CartesianGrid
          strokeDasharray="3 3"
          stroke="#0D2137"
          vertical={false}
        />

        <XAxis
          dataKey="time"
          stroke="transparent"
          tick={{
            fill: "#2A4A66",
            fontSize: 9,
            fontFamily: "'JetBrains Mono', monospace",
            letterSpacing: "0.1em",
          }}
          tickLine={false}
        />
        <YAxis
          stroke="transparent"
          tick={{
            fill: "#2A4A66",
            fontSize: 9,
            fontFamily: "'JetBrains Mono', monospace",
          }}
          tickLine={false}
          width={30}
        />

        <Tooltip content={<CustomTooltip />} />

        <Area
          type="monotone"
          dataKey="normal"
          name="Normal"
          stroke="#00E87A"
          strokeWidth={1.5}
          fillOpacity={1}
          fill="url(#gradNormal)"
        />
        <Area
          type="monotone"
          dataKey="attacks"
          name="Attack"
          stroke="#FF2D55"
          strokeWidth={2}
          fillOpacity={1}
          fill="url(#gradAttack)"
          filter="url(#glowRed)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
