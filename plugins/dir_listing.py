import socket
import ssl


HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 8088}
HTTPS_PORTS = {443, 444, 8443}


def _fetch_root(target, port, timeout=2.0):
    req = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            conn = sock
            if port in HTTPS_PORTS:
                context = ssl.create_default_context()
                conn = context.wrap_socket(sock, server_hostname=target)
            conn.sendall(req)
            chunks = []
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 8192:
                    break
            data = b"".join(chunks).decode("utf-8", errors="ignore")
            return data
    except Exception:
        return ""


def run(target, open_ports, services):
    findings = []
    for port in open_ports:
        if port not in HTTP_PORTS and port not in HTTPS_PORTS:
            continue
        body = _fetch_root(target, port)
        lowered = body.lower()
        if "index of /" in lowered or "parent directory" in lowered:
            findings.append(
                {
                    "port": port,
                    "details": "Open directory listing detected on web root.",
                    "severity": "Medium",
                }
            )

    if not findings:
        return {"severity": "Safe", "details": "No open directory listings detected."}
    return {"severity": "Medium", "findings": findings}
