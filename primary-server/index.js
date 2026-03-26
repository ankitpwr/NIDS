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
// Agent calls this with a fully-computed CICIDS feature vector.
// This route:
//   1. Forwards the features to the ML service
//   2. Stores the prediction result
//   3. Returns the prediction to the agent (just for its console log)
app.post("/api/v1/ingest", async (req, res) => {
  const f = req.body;

  if (!f || typeof f !== "object") {
    return res.status(400).json({ error: "Invalid payload" });
  }

  try {
    // ✅ Normalize (important for ML consistency)
    const payload = {
      duration: f.duration || 0,
      total_packets: f.total_packets || 0,
      forward_packets: f.forward_packets || 0,
      reverse_packets: f.reverse_packets || 0,
      total_bytes: f.total_bytes || 0,
      forward_bytes: f.forward_bytes || 0,
      reverse_bytes: f.reverse_bytes || 0,

      min_packet_size: f.min_packet_size || 0,
      max_packet_size: f.max_packet_size || 0,
      avg_packet_size: f.avg_packet_size || 0,
      forward_avg_packet_size: f.forward_avg_packet_size || 0,
      reverse_avg_packet_size: f.reverse_avg_packet_size || 0,

      packets_per_second: f.packets_per_second || 0,
      bytes_per_second: f.bytes_per_second || 0,
      forward_packets_per_second: f.forward_packets_per_second || 0,
      reverse_packets_per_second: f.reverse_packets_per_second || 0,

      tcp_flags_count: f.tcp_flags_count || 0,
      syn_count: f.syn_count || 0,
      fin_count: f.fin_count || 0,
      rst_count: f.rst_count || 0,
      ack_count: f.ack_count || 0,

      src_port: f.src_port || 0,
      dst_port: f.dst_port || 0,
      protocol: f.protocol || 0,

      forward_ttl: f.forward_ttl || 0,
      reverse_ttl: f.reverse_ttl || 0,

      tcp_window_size_forward: f.tcp_window_size_forward || 0,
      tcp_window_size_reverse: f.tcp_window_size_reverse || 0,

      is_bidirectional: f.is_bidirectional || 0,
      connection_state: f.connection_state || "INT",
    };

    console.log("\n[Backend] Flow received:");
    console.log(payload);

    // 🔥 Forward to ML service
    // const mlRes = await fetch("http://localhost:3002/predict", {
    //   method: "POST",
    //   headers: {
    //     "Content-Type": "application/json",
    //   },
    //   body: JSON.stringify(payload),
    // });

    // const result = await mlRes.json();

    // console.log("[ML Response]:", result);

    return res.json({
      ok: true,
      // prediction: result,
    });
  } catch (err) {
    console.error("[Backend Error]", err.message);
    return res.status(500).json({ error: "ML forwarding failed" });
  }
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
