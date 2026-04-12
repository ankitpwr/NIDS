import express from "express";

const app = express();
app.use(express.json());

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const ML_SERVICE_URL = "http://localhost:3002/predict"; // model service
const PORT = 3000;

// ─── IN-MEMORY STORE ─────────────────────────────────────────────────────────
// Replace with Prisma + PostgreSQL when ready.
// Shape of each record stays the same — just swap:
//   attackLog.push(record)   →  await prisma.attack.create({ data: record })
//   [...attackLog].reverse() →  await prisma.attack.findMany({ orderBy: { timestamp: "desc" } })
const attackLog = [];

// ─── ROUTE: POST /api/v1/ingest ───────────────────────────────────────────────
// This route:
//   1. Forwards the features to the ML service
//   2. Stores the prediction result
//   3. Returns the prediction to the agent (just for its console log)
app.post("/api/v1/ingest", async (req, res) => {
  const payload = req.body;

  if (!payload || typeof payload !== "object") {
    return res.status(400).json({ error: "Invalid payload" });
  }

  console.log(
    "[Backend] Received flow from agent:",
    JSON.stringify(payload).slice(0, 120),
  );

  let result = null;

  try {
    const mlRes = await fetch(ML_SERVICE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!mlRes.ok) {
      const errText = await mlRes.text();
      console.error(`[ML] HTTP ${mlRes.status}:`, errText.slice(0, 200));
      // Still store the flow, just without a prediction
    } else {
      result = await mlRes.json();
      console.log("[ML Response]:", result);
    }
  } catch (err) {
    console.error("[ML Error]:", err.message);
  }

  // ── Store the record regardless of ML outcome ──────────────────────────────
  const record = {
    timestamp: new Date().toISOString(),
    source_ip: payload.srcip ?? "unknown",
    prediction: result?.prediction === 1 ? "ATTACK" : "NORMAL",
    attack_probability: result?.attack_probability ?? null,
    ml_available: result !== null,
    features: {
      dur: payload.dur,
      spkts: payload.spkts,
      dpkts: payload.dpkts,
      sbytes: payload.sbytes,
      dbytes: payload.dbytes,
      rate: payload.rate,
      proto: payload.proto,
    },
  };

  attackLog.push(record);

  // Keep memory bounded (last 10 000 flows)
  if (attackLog.length > 10_000) attackLog.shift();

  return res.json({
    stored: true,
    prediction: record.prediction,
    attack_probability: record.attack_probability,
  });
});

// ─── ROUTE: GET /api/v1/attacks ───────────────────────────────────────────────
// Frontend calls this to populate the alert table and traffic chart.
// Returns last 100 records, newest first.
app.get("/api/v1/attacks", (req, res) => {
  const recent = [...attackLog].reverse().slice(0, 100);
  return res.json(recent);
});

// ─── ROUTE: GET /api/v1/stats ─────────────────────────────────────────────────
// Frontend calls this for the summary panel (total flows, attack count, rate).
app.get("/api/v1/stats", (req, res) => {
  const total = attackLog.length;
  const attacks = attackLog.filter((r) => r.prediction === "ATTACK").length;

  return res.json({
    total_flows: total,
    attacks_detected: attacks,
    normal_flows: total - attacks,
    attack_rate_pct: total > 0 ? ((attacks / total) * 100).toFixed(1) : "0.0",
  });
});

// ─── ROUTE: GET /api/v1/health ────────────────────────────────────────────────
app.get("/api/v1/health", async (req, res) => {
  let mlStatus = "unreachable";
  try {
    const r = await fetch("http://localhost:3002/health");
    const ml = await r.json();
    mlStatus = ml.status || "ok";
  } catch {
    mlStatus = "unreachable";
  }

  return res.json({
    backend: "ok",
    ml_service: mlStatus,
    log_size: attackLog.length,
  });
});

// ─── START ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[Backend] Running on http://localhost:${PORT}`);
  console.log(
    `[Backend] Forwarding predictions to ML service at ${ML_SERVICE_URL}`,
  );
  console.log(
    `[Backend] Frontend API → GET /api/v1/attacks | GET /api/v1/stats`,
  );
});
