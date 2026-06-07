#!/usr/bin/env python3
import time
import threading
import requests
from queue import Queue, Empty
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list, get_if_addr

# ── NEW: lightweight HTTP server to receive real-IP hints from the test server
from http.server import HTTPServer, BaseHTTPRequestHandler
import json as _json

# ─────────────────────────────────────────────────────────────────────────────
# INTERFACE DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def find_lan_interface() -> str | None:
    """Return the first interface with a private LAN IP, or None."""
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip.startswith(("192.168.", "10.", "172.")):
                return iface
        except Exception:
            continue
    return None

LAN_IFACE      = find_lan_interface()
LOOPBACK_IFACE = r"\Device\NPF_Loopback"  # localhost traffic on Windows

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
TARGET_PORT   = 8080
FLOW_TIMEOUT  = 1
MAX_FLOW_PKTS = 50
WINDOW_SIZE   = 20
BACKEND_URL   = "http://localhost:3000/api/v1/ingest"
RECENT_WINDOW = 1

# Port this agent listens on for real-IP hints from the test server
HINT_PORT     = 9000
# How long (seconds) a cached real-IP hint is considered valid
HINT_TTL      = 5.0

CT_CAPS = {
    "ct_state_ttl":     10,
    "ct_dst_ltm":       10,
    "ct_src_dport_ltm": 10,
    "ct_dst_sport_ltm": 10,
    "ct_dst_src_ltm":   15,
    "ct_src_ltm":       12,
    "ct_srv_src":       15,
    "ct_srv_dst":       15,
}

# ─────────────────────────────────────────────────────────────────────────────
# REAL-IP HINT CACHE
# ─────────────────────────────────────────────────────────────────────────────
# The test server posts {real_ip, timestamp, path, method} here whenever it
# handles a request that came through Cloudflare Tunnel.  We keep a short
# list of recent hints; when we flush a loopback flow (src == 127.0.0.1) we
# substitute the most-recently-seen real IP.
#
# Why this works:
#   - Each HTTP request through the tunnel causes exactly ONE hint + ONE flow.
#   - The hint arrives at roughly the same time as the packets, so the most
#     recent un-consumed hint belongs to the current flow.
#   - HINT_TTL evicts stale hints so we never wrongly tag unrelated traffic.

_hint_lock  = threading.Lock()
_hint_cache: list[dict] = []   # [{real_ip, timestamp, path, method}, ...]


def store_hint(hint: dict):
    """Called from the hint HTTP server thread."""
    with _hint_lock:
        _hint_cache.append(hint)
        # Evict hints older than HINT_TTL
        cutoff = time.time() - HINT_TTL
        _hint_cache[:] = [h for h in _hint_cache if h["timestamp"] >= cutoff]


def pop_latest_hint() -> str | None:
    """
    Return and remove the most recent cached real IP, or None if the cache is
    empty / all hints are expired.
    Called from the flow-processor thread when flushing a 127.0.0.1 flow.
    """
    with _hint_lock:
        cutoff = time.time() - HINT_TTL
        valid  = [h for h in _hint_cache if h["timestamp"] >= cutoff]
        if not valid:
            _hint_cache.clear()
            return None
        # Take the newest hint
        valid.sort(key=lambda h: h["timestamp"], reverse=True)
        best = valid[0]
        _hint_cache.remove(best)
        return best["real_ip"]


# ─────────────────────────────────────────────────────────────────────────────
# HINT HTTP SERVER  (runs in its own daemon thread)
# ─────────────────────────────────────────────────────────────────────────────

class _HintHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/ip-hint":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            hint   = _json.loads(body)
            hint.setdefault("timestamp", time.time())
            store_hint(hint)
            print(f"[Hint] Received real_ip={hint.get('real_ip')} path={hint.get('path')}")
        except Exception as e:
            print(f"[Hint] Parse error: {e}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    # Silence the default access log noise
    def log_message(self, *_):
        pass


def run_hint_server():
    server = HTTPServer(("127.0.0.1", HINT_PORT), _HintHandler)
    print(f"[Agent] Hint server listening on 127.0.0.1:{HINT_PORT}/ip-hint")
    server.serve_forever()


# ─────────────────────────────────────────────────────────────────────────────
# SHARED STATE
# ─────────────────────────────────────────────────────────────────────────────
recent_dst_flows = defaultdict(list)
recent_src_flows = defaultdict(list)
recent_state_ttl = defaultdict(list)

packet_queue = Queue(maxsize=10_000)
active_flows: dict = {}
running = True

_seen_lock    = threading.Lock()
_seen_packets = {}   # {dedup_key: expiry_time}
_DEDUP_TTL    = 0.5  # seconds


# ─────────────────────────────────────────────────────────────────────────────
# STARTUP SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

def selftest_interface(iface: str, label: str) -> bool:
    ok = True
    try:
        sniff(iface=iface, count=1, timeout=3, store=False)
        print(f"  [✓] {label}: {iface}")
    except PermissionError:
        print(f"  [✗] {label}: PERMISSION DENIED — run as Administrator")
        ok = False
    except Exception as e:
        print(f"  [✗] {label}: {e}")
        ok = False
    return ok


def run_selftests() -> bool:
    print("\n[Agent] ── Interface self-test ──────────────────────────────")
    lo_ok  = selftest_interface(LOOPBACK_IFACE, "Loopback ")
    lan_ok = True
    if LAN_IFACE:
        lan_ok = selftest_interface(LAN_IFACE, f"WiFi/LAN  (IP: {get_if_addr(LAN_IFACE)})")
    else:
        print("  [!] No LAN interface found — only loopback will be sniffed")
    print("[Agent] ────────────────────────────────────────────────────\n")
    return lo_ok


# ─────────────────────────────────────────────────────────────────────────────
# COUNTER HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def count_recent(flow_dict, key, now, feature_name) -> int:
    times = [t for t in flow_dict[key] if now - t < RECENT_WINDOW]
    flow_dict[key] = times
    return min(len(times), CT_CAPS.get(feature_name, 15))


def remember(flow_dict, key, now):
    flow_dict[key].append(now)


# ─────────────────────────────────────────────────────────────────────────────
# TTL SNAPPING
# ─────────────────────────────────────────────────────────────────────────────
_KNOWN_STTL = [0, 31, 62, 254]
_KNOWN_DTTL = [0, 29, 60, 252]

def _snap_ttl(raw: int, known: list) -> int:
    return raw if raw in known else min(known, key=lambda v: abs(v - raw))


# ─────────────────────────────────────────────────────────────────────────────
# PACKET HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_ports(pkt):
    if pkt.haslayer(TCP): return pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP): return pkt[UDP].sport, pkt[UDP].dport
    return None, None


def flow_key(pkt):
    ip = pkt[IP]
    src_ip, dst_ip = ip.src, ip.dst
    src_port, dst_port = get_ports(pkt)
    proto = ip.proto
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, proto), True
    return (dst_ip, src_ip, dst_port, src_port, proto), False


def compute_tcp_state(flow) -> str:
    all_pkts = flow["fwd"] + flow["rev"]
    has_syn    = any(p.haslayer(TCP) and (int(p[TCP].flags) & 0x02) for p in all_pkts)
    has_fin    = any(p.haslayer(TCP) and (int(p[TCP].flags) & 0x01) for p in all_pkts)
    has_rst    = any(p.haslayer(TCP) and (int(p[TCP].flags) & 0x04) for p in all_pkts)
    has_synack = any(p.haslayer(TCP) and (int(p[TCP].flags) & 0x12) == 0x12 for p in all_pkts)
    if has_rst:                    return "RST"
    if has_fin:                    return "FIN"
    if has_syn and not has_synack: return "INT"
    if has_syn and has_synack:     return "CON"
    return "INT"


def avg_interarrival(packets):
    if len(packets) < 2: return 0.0
    times = [float(p.time) for p in packets]
    return sum(t2-t1 for t1,t2 in zip(times, times[1:])) / (len(times)-1)


def jitter(packets):
    if len(packets) < 3: return 0.0
    times = [float(p.time) for p in packets]
    diffs = [t2-t1 for t1,t2 in zip(times, times[1:])]
    avg = sum(diffs)/len(diffs)
    return sum(abs(d-avg) for d in diffs)/len(diffs)


def estimate_rtt(flow):
    syn = synack = None
    for p in flow["fwd"] + flow["rev"]:
        if p.haslayer(TCP):
            flags = int(p[TCP].flags)
            if (flags & 0x02) and not (flags & 0x10): syn = float(p.time)
            elif flags & 0x12: synack = float(p.time); break
    return (synack - syn) if syn and synack else 0.0


def get_ttl(packets):
    for p in packets:
        if p.haslayer(IP): return p[IP].ttl
    return 0


def get_win(packets):
    for p in packets:
        if p.haslayer(TCP): return p[TCP].window
    return 0


def get_tcp_seq(packets):
    for p in packets:
        if p.haslayer(TCP): return p[TCP].seq
    return 0


def get_payload_bytes(packets):
    return sum(len(p[Raw].load) for p in packets if p.haslayer(Raw))


def count_http_methods(packets):
    count = 0
    for p in packets:
        if p.haslayer(Raw):
            if bytes(p[Raw].load)[:3] in (b"GET", b"POS", b"PUT", b"DEL", b"HEA"):
                count += 1
    return count


def proto_name(ip_proto: int) -> str:
    return {6: "tcp", 17: "udp", 1: "icmp"}.get(ip_proto, str(ip_proto))


# ─────────────────────────────────────────────────────────────────────────────
# DEDUPLICATION
# ─────────────────────────────────────────────────────────────────────────────

def is_duplicate(pkt) -> bool:
    try:
        ip = pkt[IP]
        sp, dp = get_ports(pkt)
        # Round timestamp to 10ms bucket — same packet on two interfaces
        # will have nearly identical timestamps
        t_bucket  = round(float(pkt.time) * 100)
        dedup_key = (ip.src, ip.dst, sp, dp, t_bucket)
    except Exception:
        return False

    now = time.time()
    with _seen_lock:
        expired = [k for k, exp in _seen_packets.items() if now > exp]
        for k in expired:
            del _seen_packets[k]
        if dedup_key in _seen_packets:
            return True
        _seen_packets[dedup_key] = now + _DEDUP_TTL
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CAPTURE — one function, called once per interface in its own thread
# ─────────────────────────────────────────────────────────────────────────────

def capture_on(iface: str, label: str):
    print(f"[Agent] [{label}] Capture started on {iface}")

    def handler(pkt):
        if not pkt.haslayer(IP):
            return
        sp, dp = get_ports(pkt)
        if sp != TARGET_PORT and dp != TARGET_PORT:
            return
        if is_duplicate(pkt):
            return
        if not packet_queue.full():
            packet_queue.put(pkt)

    try:
        sniff(
            iface=iface,
            prn=handler,
            store=False,
            filter=f"tcp port {TARGET_PORT}",
        )
    except PermissionError:
        print(f"[Agent] [{label}] PERMISSION DENIED — must run as Administrator")
    except Exception as e:
        print(f"[Agent] [{label}] Capture error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# PROCESS
# ─────────────────────────────────────────────────────────────────────────────

def process_packets():
    print("[Agent] Flow processor started")
    window, last_time = [], time.time()
    while running:
        try:
            pkt = packet_queue.get(timeout=0.2)
            window.append(pkt)
        except Empty:
            pass
        if window and (len(window) >= WINDOW_SIZE or time.time() - last_time > 0.5):
            process_window(window)
            window, last_time = [], time.time()


def process_window(packets):
    now = time.time()
    for pkt in packets:
        try:
            key, forward = flow_key(pkt)
        except Exception:
            continue
        if key not in active_flows:
            active_flows[key] = {
                "start": float(pkt.time),
                "last":  float(pkt.time),
                "fwd":   [],
                "rev":   [],
            }
        flow = active_flows[key]
        (flow["fwd"] if forward else flow["rev"]).append(pkt)
        flow["last"] = float(pkt.time)
    flush_flows(now)


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(key, flow) -> dict:
    src_ip, dst_ip, src_port, dst_port, ip_proto = key
    now = time.time()

    # ── Real-IP substitution ──────────────────────────────────────────────────
    # When traffic arrives through Cloudflare Tunnel, every packet comes from
    # 127.0.0.1 at the TCP level.  The test server pushes the real client IP
    # (from CF-Connecting-IP) to our hint cache; we swap it in here so that
    # the ML model and dashboard see the actual attacker/client IP.
    reported_src_ip = src_ip
    if src_ip == "127.0.0.1":
        hint_ip = pop_latest_hint()
        if hint_ip:
            reported_src_ip = hint_ip
            print(f"[Agent] Loopback flow — substituting srcip {src_ip} → {reported_src_ip}")

    fwd, rev     = flow["fwd"], flow["rev"]
    duration     = max(flow["last"] - flow["start"], 0.001)
    spkts        = len(fwd)
    dpkts        = len(rev)
    sbytes       = sum(len(p) for p in fwd)
    dbytes       = sum(len(p) for p in rev)
    http_n       = count_http_methods(fwd)
    rtt          = estimate_rtt(flow)
    sttl_snapped = _snap_ttl(get_ttl(fwd), _KNOWN_STTL)
    dttl_snapped = _snap_ttl(get_ttl(rev), _KNOWN_DTTL)
    state        = compute_tcp_state(flow)

    service_key      = (dst_ip, TARGET_PORT)
    state_ttl_key    = (dst_ip, state, sttl_snapped)
    ct_dst_sport_ltm = count_recent(
        recent_dst_flows, (dst_ip, TARGET_PORT), now, "ct_dst_sport_ltm"
    )

    features = {
        "dur":    duration,
        "spkts":  spkts,
        "dpkts":  dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate":   (spkts + dpkts) / duration,

        "sttl": sttl_snapped,
        "dttl": dttl_snapped,

        "sload": sbytes / duration,
        "dload": dbytes / duration,
        "sloss": 0,
        "dloss": 0,

        "sinpkt": avg_interarrival(fwd),
        "dinpkt": avg_interarrival(rev),
        "sjit":   jitter(fwd),
        "djit":   jitter(rev),

        "stcpb": get_tcp_seq(fwd),
        "dtcpb": get_tcp_seq(rev),

        "tcprtt": rtt,
        "synack": rtt,
        "ackdat": rtt / 2,

        "smean": sbytes / spkts if spkts else 0,
        "dmean": dbytes / dpkts if dpkts else 0,
        "response_body_len": get_payload_bytes(rev),

        "ct_state_ttl":     count_recent(recent_state_ttl, state_ttl_key,       now, "ct_state_ttl"),
        "ct_dst_ltm":       count_recent(recent_dst_flows, dst_ip,              now, "ct_dst_ltm"),
        "ct_src_dport_ltm": count_recent(recent_src_flows, (src_ip, dst_port),  now, "ct_src_dport_ltm"),
        "ct_dst_sport_ltm": ct_dst_sport_ltm,
        "ct_dst_src_ltm":   count_recent(recent_dst_flows, (dst_ip, src_ip),    now, "ct_dst_src_ltm"),
        "ct_flw_http_mthd": http_n,
        "ct_src_ltm":       count_recent(recent_src_flows, src_ip,              now, "ct_src_ltm"),
        "ct_srv_src":       count_recent(recent_src_flows, service_key,         now, "ct_srv_src"),
        "ct_srv_dst":       count_recent(recent_dst_flows, service_key,         now, "ct_srv_dst"),

        "proto":           proto_name(ip_proto),
        "service":         "http" if TARGET_PORT in (src_port, dst_port) else "-",
        "state":           state,
        "swin":            255 if get_win(fwd) > 0 else 0,
        "dwin":            255 if get_win(rev) > 0 else 0,
        "trans_depth":     min(http_n, 2),
        "is_ftp_login":    0,
        "ct_ftp_cmd":      0,
        "is_sm_ips_ports": 0,

        # srcip  = raw packet IP (used by ML model and counter tracking)
        #          stays as 127.0.0.1 for Cloudflare tunnel traffic
        # real_ip = best available display IP: CF-Connecting-IP when hint
        #           resolved, else falls back to raw packet srcip
        #           backend prefers real_ip for source_ip stored in Redis
        "srcip":   src_ip,
        "real_ip": reported_src_ip,
    }

    remember(recent_dst_flows, dst_ip, now)
    remember(recent_src_flows, src_ip, now)
    remember(recent_src_flows, (src_ip, dst_port), now)
    remember(recent_dst_flows, (dst_ip, TARGET_PORT), now)
    remember(recent_dst_flows, (dst_ip, src_ip), now)
    remember(recent_src_flows, service_key, now)
    remember(recent_state_ttl, state_ttl_key, now)

    return features


# ─────────────────────────────────────────────────────────────────────────────
# FLUSH
# ─────────────────────────────────────────────────────────────────────────────

def flush_flows(now: float):
    remove = []
    for key, flow in active_flows.items():
        total = len(flow["fwd"]) + len(flow["rev"])
        idle  = (time.time() - flow["last"]) > FLOW_TIMEOUT
        big   = total >= MAX_FLOW_PKTS
        if (idle or big) and total >= 1:
            data = extract_features(key, flow)
            send_to_backend(data)
            remove.append(key)
    for k in remove:
        del active_flows[k]


# ─────────────────────────────────────────────────────────────────────────────
# SEND
# ─────────────────────────────────────────────────────────────────────────────

def send_to_backend(data: dict):
    try:
        print(
            f"[Flow] src={data['srcip']} proto={data['proto']} "
            f"spkts={data['spkts']} state={data['state']} "
            f"ct_state_ttl={data['ct_state_ttl']} "
            f"ct_srv_dst={data['ct_srv_dst']} "
            f"ct_src_ltm={data['ct_src_ltm']} "
            f"ct_dst_sport_ltm={data['ct_dst_sport_ltm']}"
        )
        r = requests.post(BACKEND_URL, json=data, timeout=3)
        print(f"[Backend] -> {r.status_code} {r.text[:120]}")
    except Exception as e:
        print(f"[Error] {e}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("[Agent] NIDS starting — dual-interface mode")
    print(f"[Agent] Loopback : {LOOPBACK_IFACE}")
    print(f"[Agent] WiFi/LAN : {LAN_IFACE or 'NOT FOUND'}")
    print(f"[Agent] Port     : {TARGET_PORT}")
    print(f"[Agent] Backend  : {BACKEND_URL}")
    print(f"[Agent] Hint srv : 127.0.0.1:{HINT_PORT}/ip-hint")
    print("=" * 60)

    if not run_selftests():
        print("\n[Agent] FATAL: Cannot sniff — check Npcap and run as Administrator")
        print("[Agent] HOW TO FIX: Close this window, search PowerShell,")
        print("        right-click → 'Run as administrator', then run agent.py again")
        return

    threads = []

    # ── Hint HTTP server — receives real IPs from the test server ─────────
    t_hint = threading.Thread(target=run_hint_server, daemon=True, name="hint-server")
    threads.append(t_hint)

    # ── Always sniff loopback (Cloudflare tunnel + self-traffic on Windows)
    t_lo = threading.Thread(
        target=capture_on,
        args=(LOOPBACK_IFACE, "LO"),
        daemon=True,
        name="capture-loopback",
    )
    threads.append(t_lo)

    # ── Also sniff WiFi/LAN if available (same-network direct traffic) ────
    if LAN_IFACE:
        t_lan = threading.Thread(
            target=capture_on,
            args=(LAN_IFACE, "LAN"),
            daemon=True,
            name="capture-lan",
        )
        threads.append(t_lan)
    else:
        print("[Agent] WARNING: No LAN interface — remote-device traffic won't be captured")

    # ── Flow processor ────────────────────────────────────────────────────
    t_proc = threading.Thread(target=process_packets, daemon=True, name="processor")
    threads.append(t_proc)

    for t in threads:
        t.start()

    print(f"\n[Agent] {len(threads)} threads running. Send traffic to port {TARGET_PORT}.")
    print("[Agent] Loopback flows will have their srcip substituted from hint cache.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        global running
        running = False
        print("\n[Agent] Stopped.")


if __name__ == "__main__":
    main()