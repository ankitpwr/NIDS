import socket, threading, time, datetime

TCP_PROBE_PORT = 8081   # separate port — run scanner against this too
RECV_TIMEOUT   = 0.3    # wait this long for the client to send data
LOG_PREFIX     = "[TCP-Probe]"


def _handle_client(conn: socket.socket, addr: tuple):
    ip, port = addr
    ts = datetime.datetime.utcnow().isoformat()
    try:
        conn.settimeout(RECV_TIMEOUT)
        try:
            data = conn.recv(512)
        except socket.timeout:
            data = b""

        # Classify the connection type
        if not data:
            kind = "BARE_CONNECT"       # pure port scan — no payload
        elif data.startswith(b"GET ") or data.startswith(b"POST ") or data.startswith(b"HEAD "):
            kind = "HTTP_PROBE"         # scanner that sends HTTP
        else:
            kind = f"RAW_PAYLOAD({len(data)}B)"  # custom payload

        print(f"{LOG_PREFIX} {ts}  {kind}  src={ip}:{port}")

        # Send back a minimal response so the scanner knows the port is open
        try:
            if kind == "HTTP_PROBE":
                conn.sendall(
                    b"HTTP/1.0 403 Forbidden\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            else:
                conn.sendall(b"\x00")   # 1-byte ACK for raw scanners
        except Exception:
            pass

    finally:
        conn.close()


def _tcp_listener_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TCP_PROBE_PORT))
    srv.listen(128)
    print(f"{LOG_PREFIX} TCP probe listener active on port {TCP_PROBE_PORT}")

    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=_handle_client, args=(conn, addr), daemon=True
            )
            t.start()
        except Exception as e:
            print(f"{LOG_PREFIX} Listener error: {e}")
            time.sleep(0.1)


def start_tcp_listener():
    """Call once before app.run() — starts listener in a daemon thread."""
    t = threading.Thread(target=_tcp_listener_thread, daemon=True)
    t.start()