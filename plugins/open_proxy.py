import socket


PROXY_PORTS = {3128, 8080, 8081, 8000, 8888}


def _send_request(target, port, payload, timeout=2.0):
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            return sock.recv(512).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _probe_proxy(target, port, timeout=2.0):
    connect_payload = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    get_payload = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"

    connect_resp = _send_request(target, port, connect_payload, timeout=timeout)
    get_resp = _send_request(target, port, get_payload, timeout=timeout)

    connect_open = "200 connection established" in connect_resp.lower()
    get_open = any(code in get_resp for code in (" 200 ", " 301 ", " 302 "))
    return connect_open or get_open, connect_resp or get_resp


def run(target, open_ports, services):
    findings = []
    for port in open_ports:
        if port not in PROXY_PORTS:
            continue
        open_proxy, sample = _probe_proxy(target, port)
        if open_proxy:
            findings.append(
                {
                    "port": port,
                    "details": "Potential open proxy (CONNECT accepted).",
                    "severity": "High",
                    "sample": sample.splitlines()[0] if sample else "",
                }
            )

    if not findings:
        return {"severity": "Safe", "details": "No open proxy behavior detected."}
    return {"severity": "High", "findings": findings}
