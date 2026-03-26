#!/usr/bin/env python3

"""
UPGRADED NIDS AGENT (Based on GitHub Architecture)
- Multi-threaded (capture + processing)
- Uses queue (no packet loss)
- Flow-based aggregation
- OPTIONAL port filtering (e.g., only 8080)
- Sends data to your Node.js backend (NO ML dependency)
"""

import time
import threading
import requests
from queue import Queue, Empty
from scapy.all import sniff, IP, TCP, UDP

# ================= CONFIG =================
INTERFACE =  r"\Device\NPF_Loopback"   # change if needed
TARGET_PORT = 8080     # 🔥 ONLY monitor this port
FLOW_TIMEOUT = 5
WINDOW_SIZE = 50       # process after 50 packets
BACKEND_URL = "http://localhost:3000/api/v1/ingest"

# =========================================

packet_queue = Queue(maxsize=10000)
active_flows = {}
running = True

# ============ CAPTURE THREAD ==============
def capture_packets():
    print("[Agent] Starting packet capture...")

    def handler(packet):
        global running
        if not running:
            return False

        try:
            if not packet.haslayer(IP):
                return

            # Extract ports
            src_port, dst_port = None, None
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # 🔥 FILTER ONLY TARGET PORT
            if TARGET_PORT not in [src_port, dst_port]:
                return

            if not packet_queue.full():
                packet_queue.put(packet)

        except Exception as e:
            pass

    sniff(iface=INTERFACE, prn=handler, store=False)


# ============ FLOW PROCESSING =============
def process_packets():
    print("[Agent] Starting flow processor...")

    window_packets = []
    last_time = time.time()

    while running:
        try:
            packet = packet_queue.get(timeout=1)
            window_packets.append(packet)

        except Empty:
            pass

        # Process conditions
        if (len(window_packets) >= WINDOW_SIZE or 
            (time.time() - last_time) > FLOW_TIMEOUT):

            if window_packets:
                process_window(window_packets)
                window_packets = []
                last_time = time.time()


def process_window(packets):
    current_time = time.time()

    for packet in packets:
        try:
            ip = packet[IP]
            src_ip, dst_ip = ip.src, ip.dst
            protocol = ip.proto

            # ports
            src_port, dst_port = 0, 0
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # normalize flow key (bidirectional)
            if (src_ip, src_port) < (dst_ip, dst_port):
                key = (src_ip, dst_ip, src_port, dst_port, protocol)
                forward = True
            else:
                key = (dst_ip, src_ip, dst_port, src_port, protocol)
                forward = False

            if key not in active_flows:
                active_flows[key] = {
                    "start": packet.time,
                    "last": current_time,
                    "fwd": [],
                    "rev": []
                }

            flow = active_flows[key]

            if forward:
                flow["fwd"].append(packet)
            else:
                flow["rev"].append(packet)

            flow["last"] = current_time

        except:
            continue

    # flush completed flows
    flush_flows(current_time)


def flush_flows(now):
    remove_keys = []

    for key, flow in active_flows.items():
        idle = now - flow["last"]

        if idle > FLOW_TIMEOUT:
            total_packets = len(flow["fwd"]) + len(flow["rev"])

            if total_packets >= 2:
                data = extract_features(key, flow)
                send_to_backend(data)

            remove_keys.append(key)

    for k in remove_keys:
        del active_flows[k]


# ============ FEATURE EXTRACTION ==========
def extract_features(key, flow):
    fwd = flow["fwd"]
    rev = flow["rev"]
    all_packets = fwd + rev

    duration = flow["last"] - flow["start"]
    if duration <= 0:
        duration = 0.001

    forward_packets = len(fwd)
    reverse_packets = len(rev)
    total_packets = forward_packets + reverse_packets

    forward_bytes = sum(len(p) for p in fwd)
    reverse_bytes = sum(len(p) for p in rev)
    total_bytes = forward_bytes + reverse_bytes

    # packet sizes
    sizes = [len(p) for p in all_packets]
    min_size = min(sizes) if sizes else 0
    max_size = max(sizes) if sizes else 0
    avg_size = sum(sizes)/len(sizes) if sizes else 0

    fwd_sizes = [len(p) for p in fwd]
    rev_sizes = [len(p) for p in rev]

    fwd_avg = sum(fwd_sizes)/len(fwd_sizes) if fwd_sizes else 0
    rev_avg = sum(rev_sizes)/len(rev_sizes) if rev_sizes else 0

    # timing
    pps = total_packets / duration
    bps = total_bytes / duration
    fwd_pps = forward_packets / duration
    rev_pps = reverse_packets / duration

    # TCP flags
    syn = fin = rst = ack = 0
    flag_set = set()

    for p in all_packets:
        if p.haslayer(TCP):
            flags = p[TCP].flags
            flag_set.add(flags)
            if flags & 0x02: syn += 1
            if flags & 0x01: fin += 1
            if flags & 0x04: rst += 1
            if flags & 0x10: ack += 1

    # TTL
    def get_ttl(packets):
        for p in packets:
            if p.haslayer(IP):
                return p[IP].ttl
        return 64

    # Window size
    def get_win(packets):
        for p in packets:
            if p.haslayer(TCP):
                return p[TCP].window
        return 0

    return {
        "duration": duration,
        "total_packets": total_packets,
        "forward_packets": forward_packets,
        "reverse_packets": reverse_packets,
        "total_bytes": total_bytes,
        "forward_bytes": forward_bytes,
        "reverse_bytes": reverse_bytes,

        "min_packet_size": min_size,
        "max_packet_size": max_size,
        "avg_packet_size": avg_size,
        "forward_avg_packet_size": fwd_avg,
        "reverse_avg_packet_size": rev_avg,

        "packets_per_second": pps,
        "bytes_per_second": bps,
        "forward_packets_per_second": fwd_pps,
        "reverse_packets_per_second": rev_pps,

        "tcp_flags_count": len(flag_set),
        "syn_count": syn,
        "fin_count": fin,
        "rst_count": rst,
        "ack_count": ack,

        "src_port": key[2],
        "dst_port": key[3],
        "protocol": key[4],

        "forward_ttl": get_ttl(fwd),
        "reverse_ttl": get_ttl(rev),

        "tcp_window_size_forward": get_win(fwd),
        "tcp_window_size_reverse": get_win(rev),

        "is_bidirectional": 1 if forward_packets > 0 and reverse_packets > 0 else 0,
        "connection_state": "CON" if reverse_packets > 0 else "INT",

        # meta (useful for dashboard)
        "_meta": {
            "src_ip": key[0],
            "dst_ip": key[1]
        }
    }


# ============ BACKEND =====================
def send_to_backend(data):
    try:
        print(f"[Flow] {data}")
        requests.post(BACKEND_URL, json=data, timeout=2)
    except Exception as e:
        print("[Error sending]", e)


# ============ MAIN ========================
def main():
    print("[Agent] Production-style NIDS started")
    print(f"[Agent] Monitoring ONLY port {TARGET_PORT}")

    t1 = threading.Thread(target=capture_packets, daemon=True)
    t2 = threading.Thread(target=process_packets, daemon=True)

    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        global running
        running = False
        print("\n[Agent] Stopping...")


if __name__ == "__main__":
    main()
