import asyncio

from core.banners import async_http_probes


SECURITY_HEADERS = {
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "strict-transport-security",
    "referrer-policy",
}
HTTP_PORTS = {80, 81, 443, 444, 8000, 8008, 8080, 8081, 8088, 8443, 8888}
TLS_PORTS = {443, 444, 8443}


def _parse_headers(raw_text):
    header_part = raw_text.split("\r\n\r\n", 1)[0]
    lines = header_part.split("\r\n")[1:]
    parsed = {}
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip().lower()] = value.strip()
    return parsed


async def _check_async(target, ports):
    probe_results = await async_http_probes(target, ports, path="/", timeout=2.5)
    findings = []
    for item in probe_results:
        if item.get("error"):
            continue
        raw = item.get("raw", "")
        headers = _parse_headers(raw)
        missing = sorted(header for header in SECURITY_HEADERS if header not in headers)
        notes = []

        if "server" in headers and any(ch.isdigit() for ch in headers["server"]):
            notes.append("Server header discloses version info")

        if item.get("port") in TLS_PORTS and "strict-transport-security" not in headers:
            notes.append("HSTS missing on TLS endpoint")

        if missing or notes:
            sev = "Medium"
            if len(missing) >= 3 or "HSTS missing on TLS endpoint" in notes:
                sev = "High"
            findings.append(
                {
                    "port": item.get("port"),
                    "severity": sev,
                    "details": (
                        f"Missing security headers: {', '.join(missing)}"
                        if missing else "Security header weakness detected."
                    ),
                    "notes": notes,
                }
            )
    return findings


def run(target, open_ports, services):
    web_ports = [port for port in open_ports if port in HTTP_PORTS]
    if not web_ports:
        return {"severity": "Safe", "details": "No web ports found for security header checks."}

    try:
        findings = asyncio.run(_check_async(target, web_ports))
    except RuntimeError:
        # Fallback if event loop is already running.
        loop = asyncio.new_event_loop()
        try:
            findings = loop.run_until_complete(_check_async(target, web_ports))
        finally:
            loop.close()

    if not findings:
        return {"severity": "Safe", "details": "No missing HTTP security headers detected."}
    worst = "High" if any(item.get("severity") == "High" for item in findings) else "Medium"
    return {"severity": worst, "findings": findings}
