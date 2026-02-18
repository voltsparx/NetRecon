import re
import socket


def _ssh_banner(target, port=22, timeout=2.0):
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(256).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _is_legacy_openssh(banner):
    m = re.search(r"openssh[_-](\d+)\.(\d+)", banner.lower())
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2))
    return major < 7 or (major == 7 and minor < 6)


def run(target, open_ports, services):
    if 22 not in open_ports:
        return {"severity": "Safe", "details": "SSH not detected on port 22."}

    banner = _ssh_banner(target, 22)
    if not banner:
        return {"severity": "Low", "details": "Unable to retrieve SSH banner."}

    lowered = banner.lower()
    if "ssh-1." in lowered:
        return {"severity": "Critical", "details": f"Legacy SSH protocol 1 detected: {banner}"}

    if _is_legacy_openssh(banner):
        return {
            "severity": "High",
            "details": f"Weak/legacy SSH version hint from banner: {banner}",
        }

    if "dropbear_201" in lowered:
        return {
            "severity": "Medium",
            "details": f"Older Dropbear build disclosed in banner: {banner}",
        }

    return {"severity": "Low", "details": f"SSH banner: {banner}"}
