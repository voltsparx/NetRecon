from .config import DEFAULT_PORTS, TOP_COMMON_PORTS

PROFILE_CHOICES = ("quick", "stealth", "aggressive", "web", "vuln")

_QUICK_PORTS = ",".join(str(port) for port in TOP_COMMON_PORTS[:30])
_WEB_PORTS = "80,81,443,444,591,8000,8008,8080,8081,8088,8443,8888"

PROFILES = {
    "quick": {
        "name": "quick",
        "description": "Fast top-ports scan for rapid visibility.",
        "ports": _QUICK_PORTS,
        "stealth": False,
        "syn": False,
        "services": True,
        "plugins": False,
        "cve_lookup": False,
        "threads": 120,
        "timeout": 1.0,
        "retries": 1,
        "rate_limit": 0.0,
        "randomize": False,
        "host_discovery": True,
    },
    "stealth": {
        "name": "stealth",
        "description": "Lower-noise scan with randomized order and pacing.",
        "ports": DEFAULT_PORTS,
        "stealth": True,
        "syn": True,
        "services": False,
        "plugins": False,
        "cve_lookup": False,
        "threads": 80,
        "timeout": 1.4,
        "retries": 1,
        "rate_limit": 0.03,
        "randomize": True,
        "host_discovery": True,
    },
    "aggressive": {
        "name": "aggressive",
        "description": "Deep recon with service checks and plugin modules.",
        "ports": DEFAULT_PORTS,
        "stealth": False,
        "syn": False,
        "services": True,
        "plugins": True,
        "cve_lookup": True,
        "threads": 220,
        "timeout": 1.0,
        "retries": 2,
        "rate_limit": 0.0,
        "randomize": True,
        "host_discovery": True,
    },
    "web": {
        "name": "web",
        "description": "HTTP/TLS focused scan with security header checks.",
        "ports": _WEB_PORTS,
        "stealth": False,
        "syn": False,
        "services": True,
        "plugins": True,
        "cve_lookup": True,
        "threads": 160,
        "timeout": 1.5,
        "retries": 1,
        "rate_limit": 0.01,
        "randomize": True,
        "host_discovery": True,
    },
    "vuln": {
        "name": "vuln",
        "description": "Service and vulnerability-oriented assessment profile.",
        "ports": DEFAULT_PORTS,
        "stealth": False,
        "syn": False,
        "services": True,
        "plugins": True,
        "cve_lookup": True,
        "threads": 180,
        "timeout": 1.3,
        "retries": 2,
        "rate_limit": 0.005,
        "randomize": True,
        "host_discovery": True,
    },
}


def resolve_profile(profile_name):
    key = (profile_name or "quick").strip().lower()
    if key not in PROFILES:
        supported = ", ".join(PROFILE_CHOICES)
        raise ValueError(f"Unsupported profile '{profile_name}'. Supported: {supported}")
    return dict(PROFILES[key])
