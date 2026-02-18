import platform
import re
import subprocess


def _extract_ttl(output):
    match = re.search(r"ttl[=\s:]+(\d+)", output, re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def detect_os(target):
    ping_flag = "-n" if platform.system().lower().startswith("win") else "-c"
    try:
        proc = subprocess.run(
            ["ping", ping_flag, "1", target],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        output = f"{proc.stdout}\n{proc.stderr}"
        ttl = _extract_ttl(output)
        if ttl is None:
            return "Unknown"
        if ttl <= 64:
            return "Linux/Unix"
        if ttl <= 128:
            return "Windows"
        return f"Unknown TTL={ttl}"
    except Exception:
        return "Unknown"


def infer_os_from_open_ports(open_ports):
    ports = {item.get("port") for item in open_ports if isinstance(item, dict)}
    if {135, 139, 445, 3389}.intersection(ports):
        return "Windows (heuristic)"
    if {22, 111, 2049}.intersection(ports):
        return "Linux/Unix (heuristic)"
    return None
