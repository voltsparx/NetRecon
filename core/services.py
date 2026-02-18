SERVICE_FINGERPRINTS = {
    21: ("FTP", "File Transfer"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Remote Access"),
    25: ("SMTP", "Mail Transfer"),
    53: ("DNS", "Domain Service"),
    80: ("HTTP", "Web Server"),
    110: ("POP3", "Mail Retrieval"),
    119: ("NNTP", "Usenet Service"),
    123: ("NTP", "Time Sync"),
    137: ("NetBIOS", "Windows Network"),
    139: ("SMB", "File Sharing"),
    143: ("IMAP", "Mail Access"),
    161: ("SNMP", "Network Mgmt"),
    389: ("LDAP", "Directory Service"),
    443: ("HTTPS", "Secure Web"),
    445: ("SMB", "Windows Sharing"),
    3306: ("MySQL", "Database"),
    3389: ("RDP", "Remote Desktop"),
    5432: ("PostgreSQL", "Database"),
    6379: ("Redis", "In-Memory DB"),
    8080: ("HTTP-Alt", "Web Proxy"),
    8443: ("HTTPS-Alt", "Secure Web"),
    9200: ("Elasticsearch", "Search Engine"),
    27017: ("MongoDB", "NoSQL DB"),
}

def identify_service(port, banner=None):
    if port in SERVICE_FINGERPRINTS:
        name, desc = SERVICE_FINGERPRINTS[port]
        return f"{name} ({desc})"

    if banner:
        banner = banner.lower()
        if "nginx" in banner:
            return "Nginx (Web Server)"
        if "apache" in banner:
            return "Apache (Web Server)"
        if "microsoft-iis" in banner:
            return "IIS (Web Server)"
        if "ssh" in banner:
            return "SSH Service"

    return "unknown"
