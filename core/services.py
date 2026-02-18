SERVICE_FINGERPRINTS = {
    21: {"name": "FTP", "description": "File transfer service", "risk": "Medium"},
    22: {"name": "SSH", "description": "Secure shell access", "risk": "Low"},
    23: {"name": "Telnet", "description": "Remote shell (plaintext)", "risk": "High"},
    25: {"name": "SMTP", "description": "Mail transfer service", "risk": "Low"},
    53: {"name": "DNS", "description": "Domain name service", "risk": "Low"},
    80: {"name": "HTTP", "description": "Web service", "risk": "Low"},
    110: {"name": "POP3", "description": "Mail retrieval", "risk": "Medium"},
    111: {"name": "RPCBind", "description": "RPC mapper", "risk": "Medium"},
    139: {"name": "NetBIOS", "description": "Legacy SMB service", "risk": "Medium"},
    143: {"name": "IMAP", "description": "Mail access protocol", "risk": "Low"},
    389: {"name": "LDAP", "description": "Directory service", "risk": "Medium"},
    443: {"name": "HTTPS", "description": "Secure web service", "risk": "Low"},
    445: {"name": "SMB", "description": "Windows file sharing", "risk": "High"},
    3306: {"name": "MySQL", "description": "Database service", "risk": "High"},
    3389: {"name": "RDP", "description": "Remote desktop", "risk": "High"},
    5432: {"name": "PostgreSQL", "description": "Database service", "risk": "Medium"},
    5900: {"name": "VNC", "description": "Remote desktop service", "risk": "High"},
    6379: {"name": "Redis", "description": "In-memory data store", "risk": "High"},
    8080: {"name": "HTTP-Alt", "description": "Alternate web service", "risk": "Low"},
    8443: {"name": "HTTPS-Alt", "description": "Alternate secure web service", "risk": "Low"},
    9200: {"name": "Elasticsearch", "description": "Search/API service", "risk": "High"},
}


def _from_banner(banner):
    data = (banner or "").lower()
    if not data:
        return None
    if "openssh" in data:
        return {"name": "SSH", "description": "OpenSSH service", "risk": "Low", "confidence": "high"}
    if "nginx" in data:
        return {"name": "HTTP", "description": "Nginx web server", "risk": "Low", "confidence": "high"}
    if "apache" in data:
        return {"name": "HTTP", "description": "Apache web server", "risk": "Low", "confidence": "high"}
    if "microsoft-iis" in data:
        return {"name": "HTTP", "description": "Microsoft IIS web server", "risk": "Low", "confidence": "high"}
    if "redis" in data:
        return {"name": "Redis", "description": "Redis service", "risk": "High", "confidence": "medium"}
    if "mysql" in data:
        return {"name": "MySQL", "description": "MySQL service", "risk": "High", "confidence": "medium"}
    return None


def get_service_info(port, banner=None):
    by_banner = _from_banner(banner)
    if by_banner:
        return by_banner

    if port in SERVICE_FINGERPRINTS:
        item = dict(SERVICE_FINGERPRINTS[port])
        item.setdefault("confidence", "medium")
        return item

    return {
        "name": "unknown",
        "description": "Unknown service",
        "risk": "Low",
        "confidence": "low",
    }


def identify_service(port, banner=None):
    item = get_service_info(port, banner=banner)
    return f"{item['name']} ({item['description']})"


def service_name_only(service_label):
    if not service_label:
        return "unknown"
    return service_label.split("(", 1)[0].strip()
