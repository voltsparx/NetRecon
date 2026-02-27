import random
import socket
import time
import errno

from .config import (
    MAX_THREADS,
    MIN_THREADS,
    RETRIES,
    SCAN_JITTER_RANGE,
    STEALTH_DELAY_RANGE,
    TIMEOUT,
    TOP_COMMON_PORTS,
)
from .engine.timing_engine import AdaptiveTimeoutModel, resolve_timing_template
from .engine.threading_engine import ThreadingEngine
from .os_detect import detect_os, infer_os_from_open_ports
from .services import get_service_info
from .service_probe import probe_service_signature
from .syn_scan import can_syn_scan, syn_scan_host
from .utils import clamp, randomized, resolve_target, sleep_jitter, utc_now_iso

_ERR_CLOSED = {errno.ECONNREFUSED, 10061}
_ERR_TIMEOUT = {errno.ETIMEDOUT, 10060}
_ERR_UNREACHABLE = {errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051}


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
        timing_template=3,
        service_intensity=5,
        min_rtt_timeout=0.12,
        max_rtt_timeout=6.0,
        strict_syn=False,
        host_timeout=0.0,
    ):
        template = resolve_timing_template(timing_template)
        base_threads = clamp(int(threads or MAX_THREADS), MIN_THREADS, MAX_THREADS)
        tuned_threads = int(round(base_threads * template["threads_multiplier"]))
        tuned_timeout = float(timeout if timeout is not None else TIMEOUT) * template["timeout_multiplier"]
        tuned_retries = max(0, int(retries if retries is not None else RETRIES))
        tuned_retries = min(tuned_retries, int(template["max_retries"]))

        self.stealth = bool(stealth)
        self.syn = bool(syn)
        self.detect_services = bool(detect_services)
        self.threads = clamp(tuned_threads, MIN_THREADS, MAX_THREADS)
        self.timeout = max(0.05, tuned_timeout)
        self.retries = tuned_retries
        self.rate_limit = max(float(rate_limit), float(template["rate_limit_floor"]))
        self.randomize_ports = bool(randomize_ports)
        self.strict_syn = bool(strict_syn)
        self.timing_template = int(timing_template if timing_template is not None else 3)
        self.timing_template_name = template["name"]
        self.service_intensity = max(0, min(9, int(service_intensity or 0)))
        self.min_rtt_timeout = max(0.05, float(min_rtt_timeout))
        self.max_rtt_timeout = max(self.min_rtt_timeout, float(max_rtt_timeout))
        self.host_timeout = max(0.0, float(host_timeout or 0.0))
        self.timing_model = AdaptiveTimeoutModel(
            initial_timeout_s=self.timeout,
            min_timeout_s=self.min_rtt_timeout,
            max_timeout_s=self.max_rtt_timeout,
            scan_delay_s=self.rate_limit,
        )

    def scan_host(self, target, ports):
        started = time.time()
        errors = []
        open_ports = []
        port_stats = {
            "open": 0,
            "closed": 0,
            "filtered": 0,
            "errors": 0,
            "timeouts": 0,
            "skipped": 0,
        }
        deadline = (started + self.host_timeout) if self.host_timeout > 0 else None
        scan_ports = randomized(ports, enabled=self.randomize_ports)
        if not self.randomize_ports:
            scan_ports = self._prioritize_ports(scan_ports)
        connect_target = resolve_target(target)
        host_timing = AdaptiveTimeoutModel(
            initial_timeout_s=self.timing_model.current_timeout(),
            min_timeout_s=self.min_rtt_timeout,
            max_timeout_s=self.max_rtt_timeout,
            scan_delay_s=self.rate_limit,
        )

        if self.syn:
            if can_syn_scan():
                syn_open, syn_errors = syn_scan_host(
                    connect_target,
                    scan_ports,
                    timeout=self.timeout,
                    rate_limit=self.rate_limit,
                    randomize=self.randomize_ports,
                )
                for port in syn_open:
                    service, banner, probe_trace, svc_error = self._detect_service(
                        target,
                        connect_target,
                        port,
                        host_timing,
                        deadline=deadline,
                    )
                    open_ports.append(
                        {
                            "target": target,
                            "port": port,
                            "state": "open",
                            "reason": "syn-ack",
                            "service": service,
                            "banner": banner,
                            "probe_trace": probe_trace,
                        }
                    )
                    if svc_error:
                        errors.append(f"port {port}: service probe: {svc_error}")
                    port_stats["open"] += 1
                errors.extend(syn_errors)
            else:
                message = "SYN mode requested but scapy/raw sockets are unavailable."
                if self.strict_syn:
                    errors.append(f"{message} Root scan cannot continue without privileged SYN capability.")
                else:
                    errors.append(f"{message} Falling back to TCP connect scan.")
                    open_ports.extend(
                        self._scan_connect(
                            target,
                            connect_target,
                            scan_ports,
                            errors,
                            port_stats,
                            host_timing,
                            deadline,
                        )
                    )
        else:
            open_ports.extend(
                self._scan_connect(
                    target,
                    connect_target,
                    scan_ports,
                    errors,
                    port_stats,
                    host_timing,
                    deadline,
                )
            )

        open_ports.sort(key=lambda item: item["port"])
        os_guess = infer_os_from_open_ports(open_ports) or detect_os(target)

        return {
            "target": target,
            "timestamp": utc_now_iso(),
            "scanned_ports": len(scan_ports),
            "open_ports": open_ports,
            "os": os_guess,
            "duration_s": round(time.time() - started, 3),
            "errors": errors,
            "port_stats": port_stats,
            "timing": host_timing.snapshot(),
            "timing_template": {
                "level": self.timing_template,
                "name": self.timing_template_name,
            },
            "service_intensity": self.service_intensity,
        }

    def _prioritize_ports(self, ports):
        ordered = list(dict.fromkeys(int(port) for port in ports))
        hot = []
        seen = set()
        for port in TOP_COMMON_PORTS:
            if port in ordered and port not in seen:
                hot.append(port)
                seen.add(port)
        rest = [port for port in ordered if port not in seen]
        return hot + rest

    def _scan_connect(
        self,
        display_target,
        connect_target,
        ports,
        errors,
        port_stats,
        timing_model,
        deadline=None,
    ):
        discovered = []
        host_timeout_triggered = False

        def _worker(port):
            return self._scan_port_connect(
                display_target,
                connect_target,
                port,
                timing_model,
                deadline,
            )

        batch_size = max(self.threads, self.threads * 2)
        indexed_ports = list(ports)
        with ThreadingEngine(max_workers=self.threads, thread_name_prefix="port-scan") as engine:
            for start in range(0, len(indexed_ports), batch_size):
                if deadline is not None and time.time() >= deadline:
                    remaining = len(indexed_ports) - start
                    if remaining > 0:
                        port_stats["skipped"] += remaining
                    errors.append(
                        f"host timeout reached after {self.host_timeout:.2f}s; "
                        f"skipped {max(remaining, 0)} port(s)"
                    )
                    break

                batch = indexed_ports[start:start + batch_size]
                for port, payload, exc in engine.map_unordered(batch, _worker):
                    if exc is not None:
                        errors.append(f"port {port}: {exc}")
                        port_stats["errors"] += 1
                        continue

                    item = payload.get("item")
                    error = payload.get("error")
                    state = payload.get("state", "errors")
                    if state == "open":
                        port_stats["open"] += 1
                    elif state == "closed":
                        port_stats["closed"] += 1
                    elif state == "filtered":
                        port_stats["filtered"] += 1
                    elif state == "skipped":
                        port_stats["skipped"] += 1
                        if str(error or "").lower().startswith("host timeout reached"):
                            host_timeout_triggered = True
                            continue
                    else:
                        port_stats["errors"] += 1

                    if payload.get("timeout"):
                        port_stats["timeouts"] += 1

                    if item:
                        discovered.append(item)
                    if error:
                        errors.append(f"port {port}: {error}")
        if host_timeout_triggered:
            message = f"host timeout reached after {self.host_timeout:.2f}s"
            if not any(str(item).startswith("host timeout reached after") for item in errors):
                errors.append(message)
        return discovered

    def _detect_service(self, display_target, connect_target, port, timing_model, deadline=None):
        if deadline is not None and time.time() >= deadline:
            return get_service_info(port, banner=""), "", [], "host timeout reached before service probe"

        if not self.detect_services:
            return get_service_info(port, banner=""), "", [], None

        timeout = timing_model.current_timeout()
        probe_result = probe_service_signature(
            target=connect_target,
            port=port,
            timeout=timeout,
            intensity=self.service_intensity,
            request_host=display_target,
        )
        service = probe_result.get("service") or get_service_info(port, banner="")
        banner = probe_result.get("banner", "")
        probe_trace = probe_result.get("probe_trace", [])
        error = probe_result.get("error")
        return service, banner, probe_trace, error

    def _apply_probe_pacing(self):
        if self.stealth:
            sleep_jitter(*STEALTH_DELAY_RANGE)
            return
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)
            return
        sleep_jitter(*SCAN_JITTER_RANGE)

    def _scan_port_connect(self, display_target, connect_target, port, timing_model, deadline=None):
        for attempt in range(self.retries + 1):
            if deadline is not None and time.time() >= deadline:
                return {
                    "item": None,
                    "state": "skipped",
                    "reason": "host-timeout",
                    "timeout": False,
                    "error": "host timeout reached",
                }
            timed_out = False
            try:
                start = time.perf_counter()
                timeout = timing_model.current_timeout()
                with socket.create_connection((connect_target, port), timeout=timeout):
                    elapsed = max(0.0005, time.perf_counter() - start)
                timing_model.record_rtt(elapsed)
                self.timing_model.record_rtt(elapsed)
                service, banner, probe_trace, svc_error = self._detect_service(
                    display_target,
                    connect_target,
                    port,
                    timing_model,
                    deadline=deadline,
                )
                self._apply_probe_pacing()
                item = {
                    "target": display_target,
                    "port": port,
                    "state": "open",
                    "reason": "connect-success",
                    "service": service,
                    "banner": banner,
                    "probe_trace": probe_trace,
                }
                return {
                    "item": item,
                    "state": "open",
                    "reason": "connect-success",
                    "timeout": False,
                    "error": svc_error,
                }
            except PermissionError:
                return {
                    "item": None,
                    "state": "errors",
                    "reason": "permission-denied",
                    "timeout": False,
                    "error": "permission denied",
                }
            except ConnectionRefusedError:
                timing_model.record_rtt(0.001)
                self.timing_model.record_rtt(0.001)
                return {
                    "item": None,
                    "state": "closed",
                    "reason": "connection-refused",
                    "timeout": False,
                    "error": None,
                }
            except socket.gaierror:
                return {
                    "item": None,
                    "state": "errors",
                    "reason": "dns-resolution-failure",
                    "timeout": False,
                    "error": "invalid target or DNS resolution failure",
                }
            except socket.timeout:
                timing_model.record_timeout()
                self.timing_model.record_timeout()
                timed_out = True
                if attempt >= self.retries:
                    return {
                        "item": None,
                        "state": "filtered",
                        "reason": "socket-timeout",
                        "timeout": True,
                        "error": "timeout waiting for response",
                    }
            except OSError as exc:
                err = exc.errno if exc.errno is not None else getattr(exc, "winerror", None)
                err = int(err) if err is not None else None
                if err in _ERR_CLOSED:
                    timing_model.record_rtt(0.001)
                    self.timing_model.record_rtt(0.001)
                    return {
                        "item": None,
                        "state": "closed",
                        "reason": "connection-refused",
                        "timeout": False,
                        "error": None,
                    }
                if err in _ERR_UNREACHABLE:
                    timing_model.record_timeout()
                    self.timing_model.record_timeout()
                    return {
                        "item": None,
                        "state": "filtered",
                        "reason": f"unreachable-{err}",
                        "timeout": True,
                        "error": None,
                    }
                if err in _ERR_TIMEOUT:
                    timing_model.record_timeout()
                    self.timing_model.record_timeout()
                    timed_out = True
                    if attempt >= self.retries:
                        return {
                            "item": None,
                            "state": "filtered",
                            "reason": f"timeout-{err}",
                            "timeout": True,
                            "error": "timeout waiting for response",
                        }
                else:
                    if attempt >= self.retries:
                        return {
                            "item": None,
                            "state": "errors",
                            "reason": "connection-oserror",
                            "timeout": timed_out,
                            "error": f"socket error: {exc}",
                        }
            except Exception as exc:
                if "timed out" in str(exc).lower():
                    timing_model.record_timeout()
                    self.timing_model.record_timeout()
                    timed_out = True
                if attempt >= self.retries:
                    return {
                        "item": None,
                        "state": "errors",
                        "reason": "connection-error",
                        "timeout": timed_out,
                        "error": f"timeout or connection error: {exc}",
                    }

            time.sleep(min(0.4, 0.08 * (attempt + 1) + random.uniform(0.0, 0.03)))

        return {
            "item": None,
            "state": "filtered",
            "reason": "no-response",
            "timeout": True,
            "error": None,
        }
