import re
import socket
import ssl

from .services import get_service_info

TLS_PORTS = {443, 444, 465, 636, 8443, 993, 995}
WEB_PORTS = {80, 81, 443, 444, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888}

_SERVICE_MATCH_RULES = [
    {
        "pattern": re.compile(r"(?i)openssh[_/\- ]?([0-9][0-9a-zA-Z\.\-p]*)"),
        "name": "SSH",
        "description": "Secure shell service",
        "risk": "Low",
        "confidence": "high",
    },
    {
        "pattern": re.compile(r"(?i)\b220[ -].*ftp"),
        "name": "FTP",
        "description": "File transfer service",
        "risk": "Medium",
        "confidence": "high",
    },
    {
        "pattern": re.compile(r"(?i)^http/1\.[01] \d{3}"),
        "name": "HTTP",
        "description": "Web service",
        "risk": "Low",
        "confidence": "high",
    },
    {
        "pattern": re.compile(r"(?i)\bserver:\s*nginx/?([0-9.]+)?"),
        "name": "HTTP",
        "description": "Nginx web server",
        "risk": "Low",
        "confidence": "high",
    },
    {
        "pattern": re.compile(r"(?i)\bserver:\s*apache/?([0-9.]+)?"),
        "name": "HTTP",
        "description": "Apache web server",
        "risk": "Low",
        "confidence": "high",
    },
    {
        "pattern": re.compile(r"(?i)\bredis\b|^\+pong|^-err"),
        "name": "Redis",
        "description": "In-memory data store",
        "risk": "High",
        "confidence": "medium",
    },
    {
        "pattern": re.compile(r"(?i)\bmysql\b|^\x0a[0-9]\.[0-9]"),
        "name": "MySQL",
        "description": "Database service",
        "risk": "High",
        "confidence": "medium",
    },
    {
        "pattern": re.compile(r"(?i)\bpostgresql\b"),
        "name": "PostgreSQL",
        "description": "Database service",
        "risk": "Medium",
        "confidence": "medium",
    },
    {
        "pattern": re.compile(r"(?i)\bimap"),
        "name": "IMAP",
        "description": "Mail access protocol",
        "risk": "Low",
        "confidence": "medium",
    },
    {
        "pattern": re.compile(r"(?i)\bpop3"),
        "name": "POP3",
        "description": "Mail retrieval service",
        "risk": "Medium",
        "confidence": "medium",
    },
    {
        "pattern": re.compile(r"(?i)\besmtp|\bsmtp"),
        "name": "SMTP",
        "description": "Mail transfer service",
        "risk": "Low",
        "confidence": "medium",
    },
]

_PROBE_DEFS = [
    {
        "name": "NULL",
        "payload": b"",
        "rarity": 1,
        "ports": None,
        "read_timeout_scale": 1.0,
    },
    {
        "name": "HTTP_GET",
        "payload_builder": lambda target: (
            f"GET / HTTP/1.0\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode()
        ),
        "rarity": 1,
        "ports": WEB_PORTS,
        "read_timeout_scale": 1.0,
    },
    {
        "name": "SMTP_EHLO",
        "payload": b"EHLO netrecon.local\r\n",
        "rarity": 3,
        "ports": {25, 465, 587},
        "read_timeout_scale": 1.0,
    },
    {
        "name": "FTP_HELP",
        "payload": b"HELP\r\n",
        "rarity": 3,
        "ports": {21},
        "read_timeout_scale": 1.0,
    },
    {
        "name": "POP3_CAPA",
        "payload": b"CAPA\r\n",
        "rarity": 4,
        "ports": {110, 995},
        "read_timeout_scale": 1.0,
    },
    {
        "name": "IMAP_CAPA",
        "payload": b"A001 CAPABILITY\r\n",
        "rarity": 4,
        "ports": {143, 993},
        "read_timeout_scale": 1.0,
    },
    {
        "name": "REDIS_INFO",
        "payload": b"*1\r\n$4\r\nINFO\r\n",
        "rarity": 3,
        "ports": {6379},
        "read_timeout_scale": 1.0,
    },
    {
        "name": "GENERIC_TEXT",
        "payload": b"\r\n",
        "rarity": 8,
        "ports": None,
        "read_timeout_scale": 0.8,
    },
]


def _tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _normalize_banner(blob):
    if not blob:
        return ""
    return blob.decode("utf-8", errors="ignore").strip()


def _match_service(text, port):
    if not text:
        return None

    for rule in _SERVICE_MATCH_RULES:
        matched = rule["pattern"].search(text)
        if not matched:
            continue

        service = get_service_info(port, banner=text)
        service["name"] = rule["name"]
        service["description"] = rule["description"]
        service["risk"] = rule["risk"]
        service["confidence"] = rule["confidence"]

        version = None
        if matched.groups():
            version = matched.group(1)
        if version:
            service["version"] = str(version)
        return service
    return None


def _select_probes(port, intensity):
    score = max(0, min(9, int(intensity)))
    selected = []
    for item in _PROBE_DEFS:
        ports = item.get("ports")
        rarity = int(item.get("rarity", 5))
        if item["name"] == "NULL":
            selected.append(item)
            continue
        probable = ports is None or port in ports
        if probable and rarity <= (score + 1):
            selected.append(item)
        elif score >= 8 and rarity <= score:
            selected.append(item)
    return selected


def _probe_once(target, port, timeout, probe_name, payload, use_tls=False):
    read_size = 2048
    conn_timeout = max(0.2, float(timeout))
    sock = None

    try:
        sock = socket.create_connection((target, port), timeout=conn_timeout)
        sock.settimeout(conn_timeout)
        conn = sock
        if use_tls:
            ctx = _tls_context()
            conn = ctx.wrap_socket(sock, server_hostname=target)
            conn.settimeout(conn_timeout)

        if payload:
            conn.sendall(payload)

        data = conn.recv(read_size)
        banner = _normalize_banner(data)
        return {
            "probe": probe_name,
            "banner": banner,
            "error": None,
            "tls": bool(use_tls),
        }
    except Exception as exc:
        return {
            "probe": probe_name,
            "banner": "",
            "error": str(exc),
            "tls": bool(use_tls),
        }
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def probe_service_signature(target, port, timeout=1.2, intensity=5, request_host=None):
    chosen = _select_probes(port, intensity)
    header_host = request_host or target
    best_banner = ""
    best_error = None
    probe_trace = []
    matched_service = None
    matched_probe = None

    for probe in chosen:
        name = probe["name"]
        payload = probe.get("payload")
        builder = probe.get("payload_builder")
        if builder is not None:
            payload = builder(header_host)

        scale = float(probe.get("read_timeout_scale", 1.0))
        per_probe_timeout = max(0.2, float(timeout) * scale)
        use_tls = port in TLS_PORTS and name in {"NULL", "HTTP_GET"}

        result = _probe_once(
            target=target,
            port=port,
            timeout=per_probe_timeout,
            probe_name=name,
            payload=payload or b"",
            use_tls=use_tls,
        )
        probe_trace.append(
            {
                "probe": result["probe"],
                "tls": result["tls"],
                "ok": not bool(result["error"]),
                "error": result["error"],
            }
        )

        if result["banner"]:
            if len(result["banner"]) > len(best_banner):
                best_banner = result["banner"]
            service = _match_service(result["banner"], port)
            if service:
                matched_service = service
                matched_probe = name
                break
        elif result["error"] and best_error is None:
            best_error = result["error"]

    service_info = matched_service or get_service_info(port, banner=best_banner)
    service_info.setdefault("confidence", "low")
    service_info["detected_by"] = matched_probe or "port_fingerprint"
    service_info["probe_intensity"] = max(0, min(9, int(intensity)))

    return {
        "service": service_info,
        "banner": best_banner,
        "error": best_error,
        "probe_trace": probe_trace,
    }
