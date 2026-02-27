import threading
import time

from ..color import Color
from ..utils import utc_now_iso

_RISK_GUIDANCE = {
    "safe": "No immediate exposure was detected. Keep patching and monitor changes.",
    "low": "Low-risk signals detected. Validate service hardening and access controls.",
    "medium": "Medium risk found. Prioritize internet-facing services and credential hygiene.",
    "high": "High risk found. Patch and restrict access quickly, then re-scan to verify.",
    "critical": "Critical risk found. Treat as urgent incident response and remediate first.",
}


class ScanReporter:
    def __init__(
        self,
        target_expr,
        ports_expr,
        profile_name,
        total_hosts,
        host_workers,
        port_workers,
        host_group_size,
        timing_template_level,
        timing_template_name,
        plugin_workers,
        async_limit,
        service_intensity,
        stats_every=0.0,
        enabled=True,
    ):
        self.target_expr = target_expr
        self.ports_expr = ports_expr
        self.profile_name = profile_name
        self.total_hosts = max(0, int(total_hosts or 0))
        self.host_workers = max(1, int(host_workers or 1))
        self.port_workers = max(1, int(port_workers or 1))
        self.host_group_size = max(1, int(host_group_size or 1))
        self.timing_template_level = int(timing_template_level if timing_template_level is not None else 3)
        self.timing_template_name = str(timing_template_name or "normal")
        self.plugin_workers = max(1, int(plugin_workers or 1))
        self.async_limit = max(1, int(async_limit or 1))
        self.service_intensity = max(0, int(service_intensity or 0))
        self.stats_every = max(0.0, float(stats_every or 0.0))
        self.enabled = bool(enabled)

        self._lock = threading.Lock()
        self._started_at = time.time()
        self._completed = 0
        self._open_ports = 0
        self._hosts_with_errors = 0
        self._stop_event = threading.Event()
        self._ticker = None

    def _write(self, text):
        if not self.enabled:
            return
        with self._lock:
            print(text)

    def announce_plan(self):
        self._write(f"{Color.title('Execution Engine')}")
        self._write(f"{Color.accent('Mode      : Hybrid (threading + parallel + async)')}")
        self._write(f"{Color.accent(f'Targets   : {self.target_expr} ({self.total_hosts} resolved hosts)')}")
        self._write(f"{Color.accent(f'Ports     : {self.ports_expr}')}")
        self._write(f"{Color.accent(f'Profile   : {self.profile_name}')}")
        self._write(
            Color.accent(
                f"Timing    : T{self.timing_template_level} ({self.timing_template_name})"
            )
        )
        self._write(Color.accent(f"Intensity : Service probe level {self.service_intensity}/9"))
        self._write(
            Color.accent(
                "Workers   : "
                f"hosts={self.host_workers}, ports={self.port_workers}, "
                f"plugins={self.plugin_workers}, async={self.async_limit}"
            )
        )
        self._write(Color.accent(f"Host Group: {self.host_group_size} targets per execution batch"))
        self._write(Color.dim(f"Started   : {utc_now_iso()}"))
        self._write(
            Color.dim(
                "Tip       : High/Critical results should be validated and remediated first."
            )
        )
        self._start_ticker()

    def _start_ticker(self):
        if not self.enabled or self.stats_every <= 0 or self._ticker is not None:
            return
        self._stop_event.clear()
        self._ticker = threading.Thread(target=self._stats_loop, name="netrecon-stats", daemon=True)
        self._ticker.start()

    def _stop_ticker(self):
        ticker = self._ticker
        if ticker is None:
            return
        self._stop_event.set()
        ticker.join(timeout=0.25)
        self._ticker = None

    def _stats_loop(self):
        while not self._stop_event.wait(self.stats_every):
            with self._lock:
                completed = self._completed
                total = self.total_hosts
                open_ports = self._open_ports
            elapsed = max(0.001, time.time() - self._started_at)
            remaining = max(0, total - completed)
            rate = completed / elapsed
            eta = (remaining / rate) if rate > 0 else None
            eta_label = f"{eta:.1f}s" if eta is not None else "n/a"
            self._write(
                Color.dim(
                    f"[{utc_now_iso()}] progress hosts={completed}/{total} "
                    f"open_ports={open_ports} elapsed={elapsed:.1f}s eta={eta_label}"
                )
            )

    def host_queued(self, target):
        self._write(Color.dim(f"[{utc_now_iso()}] queued target={target}"))

    def hosts_queued(self, count):
        self._write(Color.dim(f"[{utc_now_iso()}] queued {count} targets for concurrent scanning"))

    def host_group_started(self, group_index, total_groups, group_size):
        self._write(
            Color.dim(
                f"[{utc_now_iso()}] host-group {group_index}/{total_groups} started ({group_size} targets)"
            )
        )

    def host_completed(self, host_report):
        open_ports = host_report.get("open_ports", [])
        port_stats = host_report.get("port_stats") or {}
        risk = str(host_report.get("risk_level", "Safe"))
        errors = host_report.get("errors", [])
        duration = float(host_report.get("duration_s", 0.0))

        with self._lock:
            self._completed += 1
            self._open_ports += len(open_ports)
            if errors:
                self._hosts_with_errors += 1

            done = self._completed
            total = self.total_hosts
            target = host_report.get("target")
            line = (
                f"[{utc_now_iso()}] {done}/{total} completed "
                f"target={target} open={len(open_ports)} "
                f"closed={port_stats.get('closed', 0)} filtered={port_stats.get('filtered', 0)} "
                f"skipped={port_stats.get('skipped', 0)} "
                f"risk={risk} duration={duration:.2f}s"
            )
            print(Color.success(line))
            if errors:
                print(Color.warning(f"  warnings: {len(errors)} issue(s) recorded"))

    def finalize(self, summary):
        self._stop_ticker()
        if not self.enabled:
            return

        worst = str(summary.get("worst_risk", "Safe"))
        guidance = _RISK_GUIDANCE.get(worst.lower(), _RISK_GUIDANCE["low"])
        elapsed = max(0.0, time.time() - self._started_at)

        self._write("")
        generated_at = summary.get("generated_at", utc_now_iso())
        hosts_scanned = summary.get("hosts_scanned", 0)
        open_ports = summary.get("open_ports", self._open_ports)
        closed_ports = summary.get("closed_ports", 0)
        filtered_ports = summary.get("filtered_ports", 0)
        timeouts = summary.get("timeouts", 0)
        skipped_ports = summary.get("skipped_ports", 0)

        self._write(Color.title("Execution Summary"))
        self._write(Color.accent(f"Generated : {generated_at}"))
        self._write(Color.accent(f"Hosts     : {hosts_scanned}"))
        self._write(Color.accent(f"Open Ports: {open_ports}"))
        self._write(Color.accent(f"Closed    : {closed_ports}"))
        self._write(Color.accent(f"Filtered  : {filtered_ports}"))
        self._write(Color.accent(f"Skipped   : {skipped_ports}"))
        self._write(Color.accent(f"Timeouts  : {timeouts}"))
        self._write(Color.accent(f"Worst Risk: {worst}"))
        self._write(Color.accent(f"Run Time  : {elapsed:.2f}s"))
        self._write(Color.dim(f"Host Errors: {self._hosts_with_errors}"))
        self._write(Color.dim(f"Beginner note: {guidance}"))
