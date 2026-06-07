import "dotenv/config";
import express from "express";
import Redis from "ioredis";
import cors from "cors";
import nodemailer from "nodemailer";

const app = express();
app.use(express.json());
const options = {
  origin: ["http://localhost:5173", "https://orbitfrontend.sketch.qzz.io"],
};
app.use(cors(options));

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const ML_SERVICE_URL = "http://localhost:3002/predict";
const PORT = 3000;

// Initialize Redis client (defaults to localhost:6379)
const redis = new Redis();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const EMAIL_COOLDOWN_SECONDS = 300;
const ADMIN_EMAIL = "ankitpanwar2787@gmail.com"; // Who receives the alert

redis.on("connect", () => console.log("[Redis] Connected successfully"));
redis.on("error", (err) => console.error("[Redis] Error:", err));

// ─── ROUTE: POST /api/v1/ingest ───────────────────────────────────────────────
app.post("/api/v1/ingest", async (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== "object")
    return res.status(400).json({ error: "Invalid payload" });

  let result = null;
  try {
    const mlRes = await fetch(ML_SERVICE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (mlRes.ok) result = await mlRes.json();
  } catch (err) {
    console.error("[ML Error]:", err.message);
  }

  const record = {
    timestamp: new Date().toISOString(),
    source_ip: payload.real_ip ?? payload.srcip ?? "unknown",
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

  await redis.lpush("nids:logs", JSON.stringify(record));
  await redis.ltrim("nids:logs", 0, 99);
  await redis.incr("nids:stats:total_flows");

  if (record.prediction === "ATTACK") {
    await redis.incr("nids:stats:attacks");

    // <-- 3. Anti-Spam Notification Logic -->
    // Try to set the lock. 'NX' = Only set if it doesn't exist. 'EX' = Expire in X seconds.
    const lockAcquired = await redis.set(
      "nids:lock:email_alert",
      "locked",
      "EX",
      EMAIL_COOLDOWN_SECONDS,
      "NX",
    );

    if (lockAcquired === "OK") {
      console.log(
        `[Notification] Attack detected from ${record.source_ip}. Sending email alert...`,
      );

      const mailOptions = {
        from: process.env.EMAIL_USER || "your-email@gmail.com",
        to: ADMIN_EMAIL,
        subject: `⚠️ CRITICAL: NIDS Attack Detected from ${record.source_ip}`,
        text:
          `An attack has been detected on your network.\n\n` +
          `Details:\n` +
          `- Source IP: ${record.source_ip}\n` +
          `- Time: ${record.timestamp}\n` +
          `- Probability: ${record.attack_probability !== null ? (record.attack_probability * 100).toFixed(1) + "%" : "N/A"}\n` +
          `- Protocol: ${record.features.proto}\n\n` +
          `Note: Further email alerts are paused for the next ${EMAIL_COOLDOWN_SECONDS / 60} minutes to prevent spam.\n\n` +
          `Please check your NIDS Dashboard immediately.`,
      };

      // Send asynchronously so we don't slow down the ingestion response
      transporter.sendMail(mailOptions).catch((err) => {
        console.error("[Nodemailer Error]: Failed to send alert email:", err);
        // Optional: If email fails, delete the lock so it tries again next time
        // redis.del("nids:lock:email_alert");
      });
    }
  }

  return res.json({
    stored: true,
    prediction: record.prediction,
    attack_probability: record.attack_probability,
  });
});

app.get("/api/v1/attacks", async (req, res) => {
  const logs = await redis.lrange("nids:logs", 0, -1);
  const parsedLogs = logs.map((log) => JSON.parse(log));
  return res.json(parsedLogs);
});

app.get("/api/v1/stats", async (req, res) => {
  const [totalStr, attacksStr] = await redis.mget(
    "nids:stats:total_flows",
    "nids:stats:attacks",
  );

  const total = parseInt(totalStr || "0", 10);
  const attacks = parseInt(attacksStr || "0", 10);
  const normal = total - attacks;
  const attackRate = total > 0 ? ((attacks / total) * 100).toFixed(1) : "0.0";

  return res.json({
    total_flows: total,
    attacks_detected: attacks,
    normal_flows: normal,
    attack_rate_pct: attackRate,
  });
});

app.listen(PORT, () =>
  console.log(`[Backend] Running on http://localhost:${PORT}`),
);
