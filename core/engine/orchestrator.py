import asyncio

from .async_engine import AsyncEngine
from .parallel_engine import ParallelEngine
from ..cve_lookup import correlate_open_ports
from ..plugin_loader import run_plugins
from ..reporting import build_host_report


class ScanOrchestrator:
    def __init__(
        self,
        scanner,
        profile_name,
        scan_ports,
        plugins_enabled=False,
        cve_lookup_enabled=False,
        host_workers=8,
        host_group_size=32,
        plugin_workers=6,
        async_limit=16,
        host_discovery_errors=None,
        reporter=None,
        on_host_report=None,
    ):
        self.scanner = scanner
        self.profile_name = profile_name
        self.scan_ports = list(scan_ports)
        self.plugins_enabled = bool(plugins_enabled)
        self.cve_lookup_enabled = bool(cve_lookup_enabled)
        self.host_workers = max(1, int(host_workers or 1))
        self.host_group_size = max(1, int(host_group_size or 1))
        self.plugin_workers = max(1, int(plugin_workers or 1))
        self.async_limit = max(1, int(async_limit or 1))
        self.host_discovery_errors = dict(host_discovery_errors or {})
        self.reporter = reporter
        self.on_host_report = on_host_report
        self.completed_reports = []

    async def _plugins_task(self, target, open_ports, services):
        return await asyncio.to_thread(
            run_plugins,
            target,
            open_ports,
            services,
            self.plugin_workers,
            self.async_limit,
        )

    async def _cve_task(self, open_ports):
        return await asyncio.to_thread(correlate_open_ports, open_ports)

    def _run_enrichment(self, target, raw_result):
        plugin_findings = {}
        cve_findings = []

        open_items = list(raw_result.get("open_ports", []))
        open_ports = [item.get("port") for item in open_items if item.get("port") is not None]
        services = {}
        for item in open_items:
            port = item.get("port")
            if port is None:
                continue
            service = item.get("service") or {}
            services[port] = service.get("name", "unknown")

        labels = []
        coroutines = []
        if self.plugins_enabled:
            labels.append("plugins")
            coroutines.append(self._plugins_task(target, open_ports, services))
        if self.cve_lookup_enabled:
            labels.append("cve_lookup")
            coroutines.append(self._cve_task(open_items))

        if not coroutines:
            return plugin_findings, cve_findings

        results = AsyncEngine(concurrency=2).run_coroutines(coroutines)
        for label, item in zip(labels, results):
            if isinstance(item, Exception):
                raw_result.setdefault("errors", []).append(f"{label}: {item}")
                continue
            if label == "plugins":
                plugin_findings = item or {}
            elif label == "cve_lookup":
                cve_findings = item or []

        return plugin_findings, cve_findings

    def _build_error_report(self, target, message):
        return build_host_report(
            raw_result={
                "target": target,
                "open_ports": [],
                "scanned_ports": len(self.scan_ports),
                "os": "Unknown",
                "errors": [str(message)],
                "duration_s": 0.0,
            },
            plugin_findings={},
            cve_findings=[],
            profile_name=self.profile_name,
        )

    def _scan_single_target(self, target):
        raw_result = self.scanner.scan_host(target, self.scan_ports)
        discovery_error = self.host_discovery_errors.get(target)
        if discovery_error:
            raw_result.setdefault("errors", []).append(f"discovery: {discovery_error}")

        plugin_findings, cve_findings = self._run_enrichment(target, raw_result)
        return build_host_report(
            raw_result=raw_result,
            plugin_findings=plugin_findings,
            cve_findings=cve_findings,
            profile_name=self.profile_name,
        )

    def scan_targets(self, targets):
        queue = list(targets)
        if not queue:
            self.completed_reports = []
            return []

        if self.reporter:
            if len(queue) <= 25:
                for target in queue:
                    self.reporter.host_queued(target)
            else:
                self.reporter.hosts_queued(len(queue))

        host_reports = []
        total_groups = (len(queue) + self.host_group_size - 1) // self.host_group_size

        for index in range(total_groups):
            start = index * self.host_group_size
            group = queue[start:start + self.host_group_size]
            workers = min(self.host_workers, max(1, len(group)))
            if self.reporter:
                self.reporter.host_group_started(index + 1, total_groups, len(group))

            engine = ParallelEngine(
                max_workers=workers,
                backend="thread",
                thread_name_prefix="host-scan",
            )

            for target, result, error in engine.map_unordered(group, self._scan_single_target):
                report = result if error is None else self._build_error_report(target, error)
                host_reports.append(report)
                self.completed_reports = list(host_reports)

                if self.on_host_report:
                    self.on_host_report(report)
                if self.reporter:
                    self.reporter.host_completed(report)

        return host_reports
