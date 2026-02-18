import random
import time

from .config import DEFAULT_RATE_LIMIT

try:
    from scapy.all import IP, TCP, conf, sr1  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def can_syn_scan():
    return SCAPY_AVAILABLE


def syn_scan_port(target, port, timeout=1.0):
    if not SCAPY_AVAILABLE:
        return False, "scapy_not_available"

    try:
        conf.verb = 0
        packet = IP(dst=target) / TCP(dport=int(port), flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response and response.haslayer(TCP):
            flags = int(response[TCP].flags)
            # SYN+ACK means likely open.
            if flags & 0x12 == 0x12:
                return True, None
        return False, None
    except PermissionError:
        return False, "raw_socket_permission_denied"
    except Exception as exc:
        return False, str(exc)


def syn_scan_host(target, ports, timeout=1.0, rate_limit=DEFAULT_RATE_LIMIT, randomize=True):
    open_ports = []
    errors = []
    scan_ports = list(ports)
    if randomize:
        random.shuffle(scan_ports)

    for port in scan_ports:
        is_open, error = syn_scan_port(target, port, timeout=timeout)
        if is_open:
            open_ports.append(port)
        if error:
            errors.append(f"port {port}: {error}")
        if rate_limit > 0:
            time.sleep(rate_limit)

    return sorted(open_ports), errors
