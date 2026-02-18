import ipaddress
import random
import socket
import time
from datetime import datetime, timezone


def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def clamp(value, lower, upper):
    return max(lower, min(upper, value))


def parse_ports(port_expr):
    if not port_expr:
        raise ValueError("Ports cannot be empty")

    ports = set()
    for raw_part in str(port_expr).split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)

    parsed = sorted(ports)
    if not parsed:
        raise ValueError("No valid ports found in input")
    return parsed


def expand_targets(target):
    target = (target or "").strip()
    if not target:
        return []

    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass

    if "," in target:
        return [item.strip() for item in target.split(",") if item.strip()]

    return [target]


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def safe_reverse_dns(target):
    try:
        return socket.gethostbyaddr(target)[0]
    except Exception:
        return None


def randomized(items, enabled=True):
    data = list(items)
    if enabled:
        random.shuffle(data)
    return data


def sleep_jitter(min_delay, max_delay):
    if max_delay <= 0:
        return
    time.sleep(random.uniform(max(0.0, min_delay), max_delay))


def severity_rank(level):
    order = {
        "safe": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return order.get(str(level).lower(), 0)


def max_severity(levels):
    if not levels:
        return "Safe"
    normalized = [str(level).title() for level in levels]
    return max(normalized, key=severity_rank)
