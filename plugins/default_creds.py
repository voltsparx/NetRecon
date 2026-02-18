DEFAULT_CREDS = {
    "FTP": "anonymous / anonymous",
    "MySQL": "root / root",
    "PostgreSQL": "postgres / postgres",
    "Redis": "no auth configured",
    "RDP": "local admin with weak password policy risk",
    "Telnet": "admin / admin",
}

PORT_FALLBACKS = {
    21: "FTP",
    23: "Telnet",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    3389: "RDP",
}


def run(target, open_ports, services):
    warnings = []
    for port in open_ports:
        name = str(services.get(port, "unknown")).strip()
        base = name.split("(", 1)[0].strip()
        if base.lower() == "unknown" and port in PORT_FALLBACKS:
            base = PORT_FALLBACKS[port]
        if base in DEFAULT_CREDS:
            severity = "High"
            if base in {"Telnet", "Redis"}:
                severity = "Critical"
            warnings.append(
                {
                    "port": port,
                    "service": base,
                    "details": f"Common default credential risk: {DEFAULT_CREDS[base]}",
                    "severity": severity,
                }
            )

    if not warnings:
        return {"severity": "Safe", "details": "No default credential hints detected."}
    worst = "Critical" if any(item["severity"] == "Critical" for item in warnings) else "High"
    return {
        "severity": worst,
        "details": "Change vendor default passwords and enforce strong authentication.",
        "findings": warnings,
    }
