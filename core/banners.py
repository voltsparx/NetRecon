import asyncio
import random
import socket

from .about import format_about
from .color import Color
from .config import HTTP_USER_AGENTS
from .metadata import TOOL_NAME, TOOL_VERSION
from .utils import utc_now_iso


def show_banner():
    print(f"{format_about(show_banner=True)}")


def show_cli_scan_header(target_expr, port_expr, profile_name):
    print(f"{Color.title(f'{TOOL_NAME} {TOOL_VERSION}')} {Color.dim('starting')}")
    print(f"{Color.accent(f'Target : {target_expr}')}")
    print(f"{Color.accent(f'Ports  : {port_expr}')}")
    print(f"{Color.accent(f'Profile: {profile_name}')}")
    print(f"{Color.dim(f'Run time: {utc_now_iso()}')}")


def show_scan_start(target, profile):
    print(f"{Color.dim(f'[{utc_now_iso()}] scan start target={target} profile={profile}')}")


def show_scan_complete(target, duration_s):
    print(f"{Color.success(f'[{utc_now_iso()}] scan complete target={target} duration={duration_s:.2f}s')}")


def _ua():
    return random.choice(HTTP_USER_AGENTS)


def grab_banner(target, port, timeout=1.0):
    payload = (
        f"HEAD / HTTP/1.1\r\nHost: {target}\r\n"
        f"User-Agent: {_ua()}\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in {80, 81, 8000, 8008, 8080, 8081, 8088}:
                sock.sendall(payload)
            data = sock.recv(512)
            return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


async def _http_probe_single(target, port, path="/", use_tls=False, timeout=2.0):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, ssl=use_tls), timeout=timeout
        )
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {target}\r\n"
            f"User-Agent: {_ua()}\r\nConnection: close\r\n\r\n"
        ).encode()
        writer.write(req)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        text = raw.decode("utf-8", errors="ignore")
        first_line = text.splitlines()[0] if text else ""
        return {"port": port, "status_line": first_line, "raw": text}
    except Exception as exc:
        return {"port": port, "error": str(exc)}


async def async_http_probes(target, ports, path="/", timeout=2.0):
    tasks = []
    for port in ports:
        use_tls = port in {443, 444, 8443}
        tasks.append(_http_probe_single(target, port, path=path, use_tls=use_tls, timeout=timeout))
    if not tasks:
        return []
    return await asyncio.gather(*tasks)
