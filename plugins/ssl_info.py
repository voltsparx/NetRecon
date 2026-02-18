import datetime
import socket
import ssl


TLS_PORTS = {443, 444, 465, 993, 995, 8443}


def _get_cert(target, port, timeout=3.0):
    context = ssl.create_default_context()
    with socket.create_connection((target, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=target) as tls:
            cert = tls.getpeercert()
            cipher = tls.cipher()
            return cert, cipher, tls.version()


def run(target, open_ports, services):
    findings = []
    for port in open_ports:
        if port not in TLS_PORTS:
            continue
        try:
            cert, cipher, tls_version = _get_cert(target, port)
            not_after = cert.get("notAfter")
            days_left = None
            if not_after:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
            details = {
                "port": port,
                "issuer": cert.get("issuer", []),
                "subject": cert.get("subject", []),
                "expires": not_after,
                "days_left": days_left,
                "cipher": cipher[0] if cipher else None,
                "tls_version": tls_version,
            }
            severity = "Low"
            if days_left is not None and days_left < 0:
                severity = "Critical"
                details["note"] = "Certificate appears expired."
            elif days_left is not None and days_left < 15:
                severity = "High"
            elif days_left is not None and days_left < 45:
                severity = "Medium"

            if tls_version in {"TLSv1", "TLSv1.1"}:
                severity = "High"
                details["note"] = "Legacy TLS protocol negotiated."
            if details["cipher"] and any(weak in details["cipher"].upper() for weak in ("RC4", "3DES", "DES")):
                severity = "High"
                details["note"] = "Weak cipher suite negotiated."

            findings.append({"severity": severity, "details": details})
        except Exception as exc:
            findings.append(
                {
                    "severity": "Low",
                    "details": {"port": port, "error": str(exc)},
                }
            )

    if not findings:
        return {"severity": "Safe", "details": "No TLS services found for certificate inspection."}
    if any(item["severity"] == "Critical" for item in findings):
        worst = "Critical"
    elif any(item["severity"] == "High" for item in findings):
        worst = "High"
    else:
        worst = "Medium"
    return {"severity": worst, "findings": findings}
