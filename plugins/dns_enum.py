import ipaddress
import socket


def _classify_ip(ip_text):
    try:
        ip = ipaddress.ip_address(ip_text)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "private/reserved"
        return "public"
    except ValueError:
        return "unknown"


def run(target, open_ports, services):
    findings = []
    try:
        ipaddress.ip_address(target)
        hostname = socket.getfqdn(target)
        findings.append({"details": f"FQDN: {hostname}", "severity": "Low"})
        try:
            rev = socket.gethostbyaddr(target)[0]
            findings.append({"details": f"Reverse DNS: {rev}", "severity": "Low"})
        except Exception:
            pass
    except ValueError:
        try:
            host, aliases, ips = socket.gethostbyname_ex(target)
            findings.append({"details": f"Resolved host: {host}", "severity": "Low"})
            if aliases:
                findings.append({"details": f"Aliases: {', '.join(aliases[:5])}", "severity": "Low"})
            if ips:
                types = [f"{ip} ({_classify_ip(ip)})" for ip in ips[:8]]
                findings.append({"details": f"IPs: {', '.join(types)}", "severity": "Low"})
                for ip in ips[:3]:
                    try:
                        ptr = socket.gethostbyaddr(ip)[0]
                        findings.append({"details": f"PTR {ip}: {ptr}", "severity": "Low"})
                    except Exception:
                        pass
        except Exception as exc:
            return {"severity": "Low", "details": f"DNS lookup failed: {exc}"}

    if not findings:
        return {"severity": "Safe", "details": "No DNS metadata found."}
    return {"severity": "Low", "findings": findings}
