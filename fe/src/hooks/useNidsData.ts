import { useState, useEffect, useMemo } from "react";

const BACKEND_URL = "https://orbitbackend.sketch.qzz.io/api/v1";
const REFRESH_MS = 2000;
const MAX_HISTORY = 60;

export function useNidsData() {
  const [stats, setStats] = useState({
    total_flows: 0,
    attacks_detected: 0,
    normal_flows: 0,
    attack_rate_pct: "0.0",
  });
  const [records, setRecords] = useState<any[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [health, setHealth] = useState({
    backend: "ok",
    ml_service: "ok",
    log_size: 0,
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, attacksRes] = await Promise.all([
          fetch(`${BACKEND_URL}/stats`),
          fetch(`${BACKEND_URL}/attacks`),
        ]);

        if (statsRes.ok) {
          const newStats = await statsRes.json();
          setStats(newStats);

          setHistory((prev) => {
            const newPoint = {
              time: new Date().toLocaleTimeString("en-US", { hour12: false }),
              attacks: newStats.attacks_detected,
              normal: newStats.normal_flows,
              rate: parseFloat(newStats.attack_rate_pct),
            };
            const updated = [...prev, newPoint];
            return updated.length > MAX_HISTORY ? updated.slice(1) : updated;
          });
        }

        if (attacksRes.ok) {
          setRecords(await attacksRes.json());
        }
      } catch (error) {
        console.error("Error fetching NIDS data", error);
        setHealth((h) => ({ ...h, backend: "error" }));
      }
    };

    fetchData();
    const interval = setInterval(fetchData, REFRESH_MS);
    return () => clearInterval(interval);
  }, []);

  // Determine if under attack (3+ attacks in last 10 seconds)
  const isUnderAttack = useMemo(() => {
    const now = Date.now();
    let recentAttacks = 0;
    for (const r of records.slice(0, 15)) {
      if (
        r.prediction === "ATTACK" &&
        now - new Date(r.timestamp).getTime() <= 10000
      ) {
        recentAttacks++;
      }
    }
    return recentAttacks >= 3;
  }, [records]);

  return { stats, records, history, health, isUnderAttack };
}
