#!/usr/bin/env python3
import time
import threading
import requests
from queue import Queue, Empty
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list, get_if_addr

# ─────────────────────────────────────────────────────────────────────────────
# INTERFACE DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────




# Loops through all interfaces
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

LAN_IFACE = find_lan_interface()
LOOPBACK_IFACE = r"\Device\NPF_Loopback" #  localhost → localhost (Local traffic does NOT go through WiFi it goes through loopback driver)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
TARGET_PORT   = 8080
FLOW_TIMEOUT  = 1
MAX_FLOW_PKTS = 50
WINDOW_SIZE   = 20
BACKEND_URL   = "http://localhost:3000/api/v1/ingest"
RECENT_WINDOW = 1

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
_DEDUP_TTL    = 0.5  # seconds — drop duplicate within 500ms


# ─────────────────────────────────────────────────────────────────────────────
# STARTUP SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

def selftest_interface(iface: str, label: str) -> bool:
    """
    Try to sniff 1 packet on `iface` for up to 3 seconds.
    Returns True if the interface is usable (even if 0 packets arrive —
    absence of packets ≠ broken; a PermissionError means broken).
    """
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
    return lo_ok  # loopback working is the minimum requirement


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

#Extract TCP/UDP ports
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
        t_bucket = round(float(pkt.time) * 100)
        dedup_key = (ip.src, ip.dst, sp, dp, t_bucket)
    except Exception:
        return False

    now = time.time()
    with _seen_lock:
        # Evict expired entries
        expired = [k for k, exp in _seen_packets.items() if now > exp]
        for k in expired:
            del _seen_packets[k]

        if dedup_key in _seen_packets:
            return True   # duplicate — already queued from the other interface
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
        # Listen to network interface, capture the packets for tcp port 8080 and for each packet call handler()
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
            pkt = packet_queue.get(timeout=0.2) # Takes packet from queue and wait for 0.2 seconds
            window.append(pkt) # Add packet to window
        except Empty:
            pass
        if window and (len(window) >= WINDOW_SIZE or time.time() - last_time > 0.5): #Process window when 20 packet or 0.5 passed
            process_window(window) #Send window for flow building
            window, last_time = [], time.time()

# creating flow form packet window.
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

    service_key   = (dst_ip, TARGET_PORT)
    state_ttl_key = (dst_ip, state, sttl_snapped)
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

        "srcip": src_ip,
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

# check which flow is ready to send
def flush_flows(now: float):
    remove = []
    for key, flow in active_flows.items(): # key: -  (src_ip, dst_ip, src_port, dst_port, proto)
        total = len(flow["fwd"]) + len(flow["rev"])
        idle  = (time.time() - flow["last"]) > FLOW_TIMEOUT
        big   = total >= MAX_FLOW_PKTS
        if (idle or big) and total >= 1:
            data = extract_features(key, flow) # extract ml feature from flow
            send_to_backend(data) # send to node js backend
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
    print("=" * 60)

    # ── Self-test before starting capture threads ──────────────────────────
    if not run_selftests():
        print("\n[Agent] FATAL: Cannot sniff — check Npcap and run as Administrator")
        print("[Agent] HOW TO FIX: Close this window, search PowerShell,")
        print("        right-click → 'Run as administrator', then run agent.py again")
        return

    threads = []

    # ── Always sniff loopback (self-traffic on Windows goes here) ──────────
    t_lo = threading.Thread(
        target=capture_on,
        args=(LOOPBACK_IFACE, "LO"),
        daemon=True,
        name="capture-loopback",
    )
    threads.append(t_lo)

    # ── Also sniff WiFi/LAN if available (remote device traffic) ──────────
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

    # ── Flow processor ─────────────────────────────────────────────────────
    t_proc = threading.Thread(target=process_packets, daemon=True, name="processor")
    threads.append(t_proc)

    for t in threads:
        t.start()

    print(f"\n[Agent] {len(threads)} threads running. Send traffic to port {TARGET_PORT}.")
    print("[Agent] You should see [Flow] lines appear within a second of each request.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        global running
        running = False
        print("\n[Agent] Stopped.")


if __name__ == "__main__":
    main()