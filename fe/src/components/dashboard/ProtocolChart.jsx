import React, { useMemo } from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

const COLORS = [
  "#00CFFF",
  "#00E87A",
  "#FFB020",
  "#FF2D55",
  "#9B59B6",
  "#26C6DA",
];

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  return (
    <div
      style={{
        background: "#050F1C",
        border: "1px solid #0D2137",
        borderRadius: 6,
        padding: "8px 12px",
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 11,
        boxShadow: "0 6px 20px rgba(0,0,0,0.6)",
      }}
    >
      <span
        style={{
          color: "#4E7A9C",
          textTransform: "uppercase",
          fontSize: 9,
          letterSpacing: "0.15em",
        }}
      >
        {name}
      </span>
      <span style={{ color: "#D8EAF8", marginLeft: 10, fontWeight: 700 }}>
        {value}
      </span>
    </div>
  );
};

const CenterLabel = ({ viewBox, total }) => {
  const { cx, cy } = viewBox;
  return (
    <>
      <text
        x={cx}
        y={cy - 6}
        textAnchor="middle"
        fontFamily="'Rajdhani', sans-serif"
        fontSize={22}
        fontWeight={700}
        fill="#D8EAF8"
      >
        {total}
      </text>
      <text
        x={cx}
        y={cy + 10}
        textAnchor="middle"
        fontFamily="'JetBrains Mono', monospace"
        fontSize={8}
        letterSpacing={3}
        fill="#4E7A9C"
        textTransform="uppercase"
      >
        FLOWS
      </text>
    </>
  );
};

export function ProtocolChart({ records }) {
  const { chartData, total } = useMemo(() => {
    if (!records || records.length === 0) return { chartData: [], total: 0 };
    const protos = {};
    records.forEach((r) => {
      const p = (r.features?.proto || "other").toLowerCase();
      protos[p] = (protos[p] || 0) + 1;
    });
    const data = Object.entries(protos)
      .map(([name, value]) => ({ name: name.toUpperCase(), value }))
      .sort((a, b) => b.value - a.value);
    return { chartData: data, total: records.length };
  }, [records]);

  if (!chartData.length) {
    return (
      <div
        style={{
          color: "#243B52",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          letterSpacing: "0.15em",
          textTransform: "uppercase",
          textAlign: "center",
        }}
      >
        No data yet…
      </div>
    );
  }

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 12,
      }}
    >
      <ResponsiveContainer width="100%" height={140}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={44}
            outerRadius={62}
            paddingAngle={3}
            dataKey="value"
            stroke="none"
            labelLine={false}
          >
            {chartData.map((_, i) => (
              <Cell
                key={`cell-${i}`}
                fill={COLORS[i % COLORS.length]}
                style={{
                  filter: `drop-shadow(0 0 5px ${COLORS[i % COLORS.length]}80)`,
                  cursor: "pointer",
                }}
              />
            ))}
            <label
              content={(props) => <CenterLabel {...props} total={total} />}
              position="center"
            />
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>

      {/* Legend */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          justifyContent: "center",
          gap: "6px 14px",
          padding: "0 10px",
        }}
      >
        {chartData.slice(0, 5).map((entry, i) => (
          <div
            key={entry.name}
            style={{ display: "flex", alignItems: "center", gap: 5 }}
          >
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: COLORS[i % COLORS.length],
                display: "inline-block",
                boxShadow: `0 0 6px ${COLORS[i % COLORS.length]}`,
              }}
            />
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 9,
                color: "#4E7A9C",
                letterSpacing: "0.12em",
              }}
            >
              {entry.name}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
