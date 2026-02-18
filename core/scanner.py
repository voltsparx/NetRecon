import socket
import time
from concurrent.futures import ThreadPoolExecutor
from .config import MAX_THREADS, STEALTH_DELAY, TIMEOUT
from .services import identify_service
from .banners import grab_banner
from .osdetect import detect_os

class NetScanner:
    def __init__(self, stealth=False, detect_services=False):
        self.stealth = stealth
        self.detect_services = detect_services

    def scan_host(self, target, ports):
        results = {
            "target": target,
            "open_ports": [],
            "os": detect_os(target),
        }

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(self._scan_port, target, p) for p in ports]
            for future in futures:
                result = future.result()
                if result:
                    results["open_ports"].append(result)

        return results

    def _scan_port(self, target, port):
        try:
            with socket.socket() as s:
                s.settimeout(TIMEOUT)
                if s.connect_ex((target, port)) == 0:
                    banner = grab_banner(target, port) if self.detect_services else None
                    service = identify_service(port, banner)
                    time.sleep(STEALTH_DELAY if self.stealth else 0)
                    return (port, service)
        except:
            return None
