import React, { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={{
        background: "#050F1C",
        border: "1px solid #0D2137",
        borderRadius: 6,
        padding: "8px 14px",
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 11,
        boxShadow: "0 8px 24px rgba(0,0,0,0.6)",
      }}
    >
      <div
        style={{
          color: "#4E7A9C",
          fontSize: 9,
          letterSpacing: "0.18em",
          marginBottom: 4,
          textTransform: "uppercase",
        }}
      >
        Source IP
      </div>
      <div style={{ color: "#FF2D55", fontWeight: 700 }}>
        {payload[0]?.payload?.ip}
      </div>
      <div style={{ color: "#4E7A9C", fontSize: 9, marginTop: 4 }}>
        <span style={{ color: "#D8EAF8" }}>{payload[0]?.value}</span> flows
      </div>
    </div>
  );
};

export function SourceIpsChart({ records }) {
  const chartData = useMemo(() => {
    if (!records || records.length === 0) return [];
    const counts = {};
    const attacks = records.filter((r) => r.prediction === "ATTACK");
    const target = attacks.length > 0 ? attacks : records;
    target.forEach((r) => {
      const ip = r.source_ip || "unknown";
      counts[ip] = (counts[ip] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [records]);

  if (!chartData.length) {
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

  const maxCount = Math.max(...chartData.map((d) => d.count));

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart
        data={chartData}
        layout="vertical"
        margin={{ top: 4, right: 20, left: 4, bottom: 4 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="#0D2137"
          horizontal={false}
          vertical={true}
        />
        <XAxis type="number" hide />
        <YAxis
          dataKey="ip"
          type="category"
          width={90}
          tick={{
            fill: "#4E7A9C",
            fontSize: 10,
            fontFamily: "'JetBrains Mono', monospace",
          }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          content={<CustomTooltip />}
          cursor={{ fill: "rgba(13,33,55,0.5)" }}
        />
        <Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={12}>
          {chartData.map((entry, i) => {
            const intensity = 0.4 + 0.6 * (entry.count / maxCount);
            const r = Math.round(255 * intensity);
            const g = Math.round(45 * intensity);
            const b = Math.round(85 * intensity);
            return (
              <Cell
                key={`cell-${i}`}
                fill={i === 0 ? "#FF2D55" : `rgba(${r},${g},${b},0.85)`}
                style={{
                  filter:
                    i === 0
                      ? "drop-shadow(0 0 6px rgba(255,45,85,0.6))"
                      : "none",
                }}
              />
            );
          })}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
