CVE_DB = {
    "OpenSSH 7.2": [
        {
            "cve": "CVE-2016-0777",
            "severity": "High",
            "summary": "Roaming feature could leak private keys from client memory.",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2016-0777",
        }
    ],
    "Apache 2.4.49": [
        {
            "cve": "CVE-2021-41773",
            "severity": "Critical",
            "summary": "Path traversal and possible remote code execution in specific configs.",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        }
    ],
    "nginx 1.3.9-1.4.0": [
        {
            "cve": "CVE-2013-2028",
            "severity": "High",
            "summary": "Buffer overflow in chunked transfer encoding parser.",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2013-2028",
        }
    ],
    "Redis unauthenticated": [
        {
            "cve": "CVE-2022-0543",
            "severity": "Critical",
            "summary": "Lua sandbox escape in Debian/Ubuntu Redis packaging.",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
        }
    ],
}


def _match_keys(service_name, banner):
    candidates = []
    service = (service_name or "").lower()
    text = (banner or "").lower()

    if "openssh" in text:
        candidates.append("OpenSSH 7.2")
    if "apache/2.4.49" in text:
        candidates.append("Apache 2.4.49")
    if "nginx/1.3.9" in text or "nginx/1.4.0" in text:
        candidates.append("nginx 1.3.9-1.4.0")
    if "redis" in service or "redis" in text:
        candidates.append("Redis unauthenticated")

    return candidates


def lookup_cves(service_name, banner=""):
    findings = []
    for key in _match_keys(service_name, banner):
        findings.extend(CVE_DB.get(key, []))
    return findings


def correlate_open_ports(open_ports):
    correlated = []
    for item in open_ports:
        service = item.get("service", {})
        service_name = service.get("name") or item.get("service_name") or "unknown"
        banner = item.get("banner", "")
        for cve in lookup_cves(service_name, banner=banner):
            correlated.append(
                {
                    "target": item.get("target"),
                    "port": item.get("port"),
                    "service": service_name,
                    "cve": cve["cve"],
                    "severity": cve["severity"],
                    "summary": cve["summary"],
                    "reference": cve["reference"],
                }
            )
    return correlated
