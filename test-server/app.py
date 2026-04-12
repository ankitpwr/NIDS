from flask import Flask, request, jsonify
import time

# ─────────────────────────────────────────────────────────────────────────────
# TEST SERVER
# This is just a normal web server simulating a real application being attacked.
# It has zero knowledge of the agent, ML service, or primary backend.
# The agent runs separately and sniffs packets arriving at THIS server's port.
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)


@app.route("/api/v1/google/auth", methods=["GET", "POST"])
def google_auth():
    # The endpoint an attacker would hammer (DDoS, brute force, etc.)
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
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print("[Test Server] Running on port 8080")
    print("[Test Server] Simulate an attack by flooding /api/v1/google/auth")
    app.run(host="0.0.0.0", port=8080)