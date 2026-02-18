import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .banners import grab_banner
from .config import (
    MAX_THREADS,
    MIN_THREADS,
    RETRIES,
    SCAN_JITTER_RANGE,
    STEALTH_DELAY_RANGE,
    TIMEOUT,
)
from .os_detect import detect_os, infer_os_from_open_ports
from .services import get_service_info
from .syn_scan import can_syn_scan, syn_scan_host
from .utils import clamp, randomized, sleep_jitter, utc_now_iso


class NetScanner:
    def __init__(
        self,
        stealth=False,
        syn=False,
        detect_services=True,
        threads=None,
        timeout=None,
        retries=None,
        rate_limit=0.0,
        randomize_ports=False,
    ):
        self.stealth = bool(stealth)
        self.syn = bool(syn)
        self.detect_services = bool(detect_services)
        self.threads = clamp(int(threads or MAX_THREADS), MIN_THREADS, MAX_THREADS)
        self.timeout = float(timeout if timeout is not None else TIMEOUT)
        self.retries = max(0, int(retries if retries is not None else RETRIES))
        self.rate_limit = max(0.0, float(rate_limit))
        self.randomize_ports = bool(randomize_ports)

    def scan_host(self, target, ports):
        started = time.time()
        errors = []
        open_ports = []
        scan_ports = randomized(ports, enabled=self.randomize_ports)

        if self.syn:
            if can_syn_scan():
                syn_open, syn_errors = syn_scan_host(
                    target,
                    scan_ports,
                    timeout=self.timeout,
                    rate_limit=self.rate_limit,
                    randomize=self.randomize_ports,
                )
                for port in syn_open:
                    banner = ""
                    if self.detect_services:
                        banner = grab_banner(target, port, timeout=self.timeout)
                    service = get_service_info(port, banner=banner)
                    open_ports.append(
                        {
                            "target": target,
                            "port": port,
                            "state": "open",
                            "service": service,
                            "banner": banner,
                        }
                    )
                errors.extend(syn_errors)
            else:
                errors.append("SYN mode requested but scapy is unavailable. Falling back to TCP connect scan.")
                open_ports.extend(self._scan_connect(target, scan_ports, errors))
        else:
            open_ports.extend(self._scan_connect(target, scan_ports, errors))

        open_ports.sort(key=lambda item: item["port"])
        os_guess = detect_os(target)
        if os_guess == "Unknown":
            os_hint = infer_os_from_open_ports(open_ports)
            if os_hint:
                os_guess = os_hint

        return {
            "target": target,
            "timestamp": utc_now_iso(),
            "scanned_ports": len(scan_ports),
            "open_ports": open_ports,
            "os": os_guess,
            "duration_s": round(time.time() - started, 3),
            "errors": errors,
        }

    def _scan_connect(self, target, ports, errors):
        discovered = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port_connect, target, port): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    item, error = future.result()
                    if item:
                        discovered.append(item)
                    if error:
                        errors.append(f"port {port}: {error}")
                except Exception as exc:
                    errors.append(f"port {port}: {exc}")
        return discovered

    def _scan_port_connect(self, target, port):
        for attempt in range(self.retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        banner = ""
                        if self.detect_services:
                            banner = grab_banner(target, port, timeout=self.timeout)
                        service = get_service_info(port, banner=banner)
                        if self.stealth:
                            sleep_jitter(*STEALTH_DELAY_RANGE)
                        elif self.rate_limit > 0:
                            time.sleep(self.rate_limit)
                        else:
                            sleep_jitter(*SCAN_JITTER_RANGE)
                        return (
                            {
                                "target": target,
                                "port": port,
                                "state": "open",
                                "service": service,
                                "banner": banner,
                            },
                            None,
                        )
            except PermissionError:
                return None, "permission denied"
            except socket.gaierror:
                return None, "invalid target or DNS resolution failure"
            except Exception:
                if attempt >= self.retries:
                    return None, "timeout or connection error"

            time.sleep(min(0.4, 0.08 * (attempt + 1) + random.uniform(0.0, 0.03)))

        return None, None
