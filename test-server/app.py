from flask import Flask, request, jsonify
import time
import requests as http_client
import threading

# ── NEW: mitigation layer ────────────────────────────────────────────────────
from mitigation import mitigation_before_request, block_ip, unblock_ip, list_blocked_ips, get_mitigation_stats

# ─────────────────────────────────────────────────────────────────────────────
# TEST SERVER
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
AGENT_HINT_URL = "http://localhost:9000/ip-hint"


# ─── REAL-IP EXTRACTION ───────────────────────────────────────────────────────

def get_real_ip() -> str:
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr


# ─── AGENT NOTIFICATION ───────────────────────────────────────────────────────

def _post_hint(real_ip: str, path: str, method: str):
    try:
        http_client.post(
            AGENT_HINT_URL,
            json={
                "real_ip":   real_ip,
                "path":      path,
                "method":    method,
                "timestamp": time.time(),
            },
            timeout=0.5,
        )
    except Exception:
        pass


def notify_agent(real_ip: str, path: str, method: str):
    t = threading.Thread(target=_post_hint, args=(real_ip, path, method), daemon=True)
    t.start()


# ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
# Order matters:
#   1. capture_real_ip  — sets request.real_ip  (used by mitigation)
#   2. mitigation       — blocks / rate-limits using request.real_ip

@app.before_request
def capture_real_ip():
    request.real_ip = get_real_ip()
    notify_agent(request.real_ip, request.path, request.method)
    print(f"[TestServer] {request.method} {request.path}  real_ip={request.real_ip}  raw_addr={request.remote_addr}")

# ADD this line right after ↑
app.before_request(mitigation_before_request)


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/api/v1/google/auth", methods=["GET", "POST"])
def google_auth():
    time.sleep(0.01)
    return jsonify({"status": "ok", "message": "auth endpoint reached"})


@app.route("/api/v1/user", methods=["GET"])
def get_user():
    return jsonify({"id": 1, "name": "Test User", "email": "test@example.com"})


@app.route("/api/v1/data", methods=["GET"])
def get_data():
    return jsonify({"records": [1, 2, 3, 4, 5]})


@app.route("/health", methods=["GET"])
def health():
    # Health check is exempt — mitigation middleware skips it because
    # 127.0.0.1 is in WHITELIST; external health checks should come from a
    # trusted monitoring IP you add to WHITELIST in mitigation.py.
    return jsonify({"status": "ok"})


# ─── MITIGATION MANAGEMENT ROUTES ─────────────────────────────────────────────
@app.route("/mitigation/stats", methods=["GET"])
def mitigation_stats():
    return jsonify(get_mitigation_stats())

@app.route("/mitigation/blocked", methods=["GET"])
def mitigation_blocked():
    return jsonify({"blocked_ips": list_blocked_ips()})

@app.route("/mitigation/block", methods=["POST"])
def mitigation_block():
    data   = request.get_json() or {}
    ip     = data.get("ip")
    reason = data.get("reason", "manual")
    ttl    = int(data.get("ttl", 3600))
    if not ip:
        return jsonify({"error": "ip required"}), 400
    block_ip(ip, reason, ttl)
    return jsonify({"blocked": True, "ip": ip})

@app.route("/mitigation/unblock", methods=["POST"])
def mitigation_unblock():
    data = request.get_json() or {}
    ip   = data.get("ip")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    unblock_ip(ip)
    return jsonify({"unblocked": True, "ip": ip})


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[Test Server] Running on port 8080")
    print("[Test Server] Real IPs extracted from CF-Connecting-IP / X-Forwarded-For")
    print("[Test Server] IP hints pushed to agent on", AGENT_HINT_URL)
    print("[Test Server] Mitigation: rate limit 80 req/60s, auto-block after 3 violations")
    app.run(host="0.0.0.0", port=8080)