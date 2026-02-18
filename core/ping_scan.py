import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import DISCOVERY_TIMEOUT, HOST_DISCOVERY_THREADS


def is_host_alive(target, timeout=DISCOVERY_TIMEOUT):
    ping_flag = "-n" if platform.system().lower().startswith("win") else "-c"
    timeout_flag = "-w" if platform.system().lower().startswith("win") else "-W"
    timeout_value = str(max(1, int(timeout)))

    try:
        proc = subprocess.run(
            ["ping", ping_flag, "1", timeout_flag, timeout_value, target],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
        output = f"{proc.stdout}\n{proc.stderr}".lower()
        ok = proc.returncode == 0 or "ttl=" in output or "time=" in output
        return ok, None
    except FileNotFoundError:
        return True, "ping command unavailable"
    except Exception as exc:
        return False, str(exc)


def discover_live_hosts(targets, threads=HOST_DISCOVERY_THREADS):
    if not targets:
        return [], {}

    live_hosts = []
    errors = {}

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = {executor.submit(is_host_alive, host): host for host in targets}
        for future in as_completed(futures):
            host = futures[future]
            try:
                alive, err = future.result()
                if alive:
                    live_hosts.append(host)
                if err:
                    errors[host] = err
            except Exception as exc:
                errors[host] = str(exc)

    return sorted(live_hosts), errors
