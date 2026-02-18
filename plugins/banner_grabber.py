import socket
import ssl
from typing import List


def _grab(target, port, timeout=1.5):
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in {80, 8080, 8000, 443, 8443}:
                sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
            data = sock.recv(256)
            return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _grab_tls_meta(target, port, timeout=2.0):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls:
                cert = tls.getpeercert()
                cn = None
                for part in cert.get("subject", []):
                    for key, value in part:
                        if key.lower() == "commonname":
                            cn = value
                            break
                return f"TLS {tls.version()} cert_cn={cn or 'unknown'}"
    except Exception:
        return ""


def _banner_hints(banner: str) -> List[str]:
    text = banner.lower()
    hints = []
    if "openssh_7." in text:
        hints.append("Older OpenSSH branch detected; validate patch level.")
    if "apache/2.2" in text or "apache/2.4.49" in text:
        hints.append("Potentially outdated Apache version disclosed.")
    if "nginx/1.1" in text or "nginx/1.0" in text:
        hints.append("Potentially outdated nginx version disclosed.")
    return hints


def run(target, open_ports, services):
    findings = []
    hints = []
    for port in open_ports[:40]:
        banner = _grab(target, port)
        if not banner and port in {443, 444, 8443, 993, 995, 465}:
            banner = _grab_tls_meta(target, port)
        if banner:
            findings.append({"port": port, "banner": banner[:220], "severity": "Low"})
            hints.extend(_banner_hints(banner))

    if not findings:
        return {"severity": "Safe", "details": "No banners captured."}

    severity = "Medium" if hints else "Low"
    result = {"severity": severity, "findings": findings}
    if hints:
        result["details"] = "; ".join(sorted(set(hints)))
    return result
