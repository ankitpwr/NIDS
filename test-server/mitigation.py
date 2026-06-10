"""
mitigation.py  —  Redis-backed IP rate limiting + block-list for Flask test-server.

Uses the SAME Redis instance and SAME key schema as primary-server/mitigation.js
so both servers share one block-list automatically.

Redis key schema (identical to Node side)
──────────────────────────────────────────────────────────────────────────────
  nids:rate:{ip}         ZSET    sliding window timestamps (ms)
  nids:blocked:{ip}      STRING  "manual" | "auto:rate_limit" | "auto:ml_attack"
  nids:mitigation:stats  HASH    total_blocked, total_rate_limited, total_allowed
──────────────────────────────────────────────────────────────────────────────

Install dependency:
    pip install redis
"""

import time
import redis as redis_lib
from flask import request, jsonify
from flask import make_response

# ─── CONFIG ──────────────────────────────────────────────────────────────────

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB   = 0

WINDOW_MS        = 60_000   # 1 minute sliding window (milliseconds, same as Node)
MAX_REQUESTS     = 80       # max requests per window per IP
AUTO_BLOCK_TTL   = 3600     # seconds — how long an auto-block lasts
ESCALATE_AFTER   = 3        # rate-limit trips before auto-escalation to block

WHITELIST = {
    "127.0.0.1",
    "::1",
    "localhost",
}

# ─── REDIS CONNECTION ─────────────────────────────────────────────────────────

r = redis_lib.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True,   # always get strings back, not bytes
)

try:
    r.ping()
    print("[Mitigation] Redis connected successfully")
except redis_lib.ConnectionError:
    print("[Mitigation] WARNING: Redis not reachable — mitigation will be skipped")
    r = None


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _redis_ok() -> bool:
    """Guard: if Redis is down, fail open (don't block legitimate traffic)."""
    return r is not None


def check_rate_limit(ip: str) -> dict:
    """
    Sliding-window rate limiter using Redis ZSET — identical logic to Node side.

    Each request adds its timestamp (ms) to a sorted set.
    Old entries outside the window are pruned atomically.

    Returns: { allowed: bool, remaining: int, count: int }
    """
    key  = f"nids:rate:{ip}"
    now  = int(time.time() * 1000)          # milliseconds, same as Date.now()
    from_ms = now - WINDOW_MS

    pipe = r.pipeline()
    pipe.zremrangebyscore(key, "-inf", from_ms)   # remove expired
    pipe.zadd(key, {str(now): now})               # add current request
    pipe.zcount(key, "-inf", "+inf")              # count in window
    pipe.pexpire(key, WINDOW_MS)                  # auto-cleanup key
    results = pipe.execute()

    count   = results[2]
    allowed = count <= MAX_REQUESTS

    return {
        "allowed":   allowed,
        "remaining": max(0, MAX_REQUESTS - count),
        "count":     count,
    }


def get_block_reason(ip: str):
    """Return block reason string if IP is blocked, else None."""
    return r.get(f"nids:blocked:{ip}")


def block_ip(ip: str, reason: str = "manual", ttl: int = AUTO_BLOCK_TTL):
    """
    Block an IP in Redis.
    ttl=0 means permanent (no expiry).
    Same key format as Node: nids:blocked:{ip}
    """
    key = f"nids:blocked:{ip}"
    if ttl > 0:
        r.setex(key, ttl, reason)
    else:
        r.set(key, reason)

    r.hincrby("nids:mitigation:stats", "total_blocked", 1)
    print(f"[Mitigation] BLOCKED  ip={ip}  reason={reason}  ttl={ttl}s")


def unblock_ip(ip: str):
    """Remove a block — e.g. false positive review."""
    r.delete(f"nids:blocked:{ip}")
    print(f"[Mitigation] UNBLOCKED  ip={ip}")


def list_blocked_ips() -> list:
    """
    Scan Redis for all blocked IPs.
    Uses SCAN (not KEYS) so it's safe on large datasets.
    """
    blocked = []
    cursor  = 0

    while True:
        cursor, keys = r.scan(cursor, match="nids:blocked:*", count=100)
        for key in keys:
            reason = r.get(key)
            ttl    = r.ttl(key)
            blocked.append({
                "ip":         key.replace("nids:blocked:", ""),
                "reason":     reason,
                "expires_in": ttl if ttl > 0 else None,   # -1 = permanent
            })
        if cursor == 0:
            break

    return blocked


def _record_trip(ip: str):
    """
    Track how many times this IP has been rate-limited.
    Auto-escalate to a hard block after ESCALATE_AFTER trips.
    Uses Redis INCR so the counter persists across restarts.
    """
    trip_key = f"nids:rate_trips:{ip}"
    trips    = r.incr(trip_key)
    r.expire(trip_key, AUTO_BLOCK_TTL)   # reset counter after block window

    if trips >= ESCALATE_AFTER:
        block_ip(ip, reason=f"auto:rate_limit_x{trips}", ttl=AUTO_BLOCK_TTL)


# ─── MAIN CHECK ──────────────────────────────────────────────────────────────

def check(ip: str):
    """
    Run all mitigation checks for an IP.
    Returns (status_code, response_dict) if request should be rejected,
    or None if request is allowed.
    """
    # If Redis is down — fail open, never block legitimate traffic
    if not _redis_ok():
        return None

    if ip in WHITELIST:
        r.hincrby("nids:mitigation:stats", "total_allowed", 1)
        return None

    # ── 1. Hard block check (O(1) GET) ───────────────────────────────────────
    reason = get_block_reason(ip)
    if reason:
        r.hincrby("nids:mitigation:stats", "requests_blocked_total", 1)
        print(f"[Mitigation] REJECTED  ip={ip}  reason={reason}")
        return (403, {"error": "Forbidden", "reason": reason})

    # ── 2. Sliding-window rate limit ─────────────────────────────────────────
    rl = check_rate_limit(ip)
    if not rl["allowed"]:
        r.hincrby("nids:mitigation:stats", "total_rate_limited", 1)
        print(f"[Mitigation] RATE-LIMITED  ip={ip}  count={rl['count']}")
        _record_trip(ip)
        return (429, {
            "error":       "Too Many Requests",
            "retry_after": WINDOW_MS // 1000,
        })

    r.hincrby("nids:mitigation:stats", "total_allowed", 1)
    return None


# ─── FLASK HOOK ──────────────────────────────────────────────────────────────

def mitigation_before_request():
    """
    Register as:  app.before_request(mitigation_before_request)
    Runs AFTER capture_real_ip() so request.real_ip is already set.
    """
    ip = getattr(request, "real_ip", None) or request.remote_addr

    result = check(ip)
    if result:
        status_code, body = result
        
        # ── NEW: Serve visual HTML block page to browsers, JSON to APIs ──
        if "text/html" in request.headers.get("Accept", ""):
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied - NIDS</title>
                <style>
                    body {{ background-color: #1a1a1a; color: white; font-family: monospace; text-align: center; padding-top: 100px; }}
                    .alert {{ color: #ff4c4c; font-size: 48px; margin-bottom: 10px; }}
                    .details {{ background: #333; padding: 20px; display: inline-block; border-left: 5px solid #ff4c4c; text-align: left; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="alert">⚠️ ACCESS BLOCKED</div>
                <p>The Network Intrusion Detection System (NIDS) has intercepted and blocked this request.</p>
                <div class="details">
                    <p><strong>Your IP:</strong> {ip}</p>
                    <p><strong>Status Code:</strong> HTTP {status_code}</p>
                    <p><strong>Reason:</strong> {body.get('reason') or body.get('error')}</p>
                </div>
            </body>
            </html>
            """
            resp = make_response(html, status_code)
        else:
            resp = jsonify(body)
            resp.status_code = status_code

        resp.headers["X-RateLimit-Limit"]  = str(MAX_REQUESTS)
        resp.headers["X-RateLimit-Window"] = str(WINDOW_MS // 1000)
        resp.headers["Retry-After"]        = str(WINDOW_MS // 1000)
        return resp


# ─── STATS ───────────────────────────────────────────────────────────────────

def get_mitigation_stats() -> dict:
    stats = r.hgetall("nids:mitigation:stats") if _redis_ok() else {}
    return {
        "config": {
            "window_seconds": WINDOW_MS // 1000,
            "max_requests":   MAX_REQUESTS,
            "block_ttl":      AUTO_BLOCK_TTL,
            "storage":        "redis",
        },
        "stats":         stats,
        "blocked_count": len(list_blocked_ips()) if _redis_ok() else -1,
    }