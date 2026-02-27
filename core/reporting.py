import html

from .color import Color
from .config import HIGH_RISK_PORTS
from .utils import max_severity, severity_rank, utc_now_iso

_BEGINNER_NOTES = {
    "safe": "No urgent finding. Keep monitoring and patch on schedule.",
    "low": "Low-risk exposure. Review configuration hygiene and least privilege.",
    "medium": "Medium-risk findings. Prioritize externally exposed services first.",
    "high": "High-risk findings. Restrict access and patch as soon as possible.",
    "critical": "Critical findings. Treat as urgent and remediate immediately.",
}


def _normalize_severity(value):
    text = str(value or "Low").strip().title()
    if text not in {"Safe", "Low", "Medium", "High", "Critical"}:
        return "Low"
    return text


def _collect_plugin_issues(plugin_findings):
    issues = []
    if not plugin_findings:
        return issues

    for plugin_name, data in plugin_findings.items():
        if isinstance(data, dict):
            severity = _normalize_severity(data.get("severity", "Low"))
            details = data.get("details")
            if details:
                issues.append(
                    {
                        "source": plugin_name,
                        "severity": severity,
                        "details": details,
                    }
                )
            findings = data.get("findings")
            if isinstance(findings, list):
                for item in findings:
                    if isinstance(item, dict):
                        details = item.get("details") or item.get("issue") or str(item)
                        notes = item.get("notes")
                        if notes:
                            if isinstance(notes, list):
                                note_text = "; ".join(str(n) for n in notes)
                            else:
                                note_text = str(notes)
                            details = f"{details} ({note_text})"
                        issues.append(
                            {
                                "source": plugin_name,
                                "severity": _normalize_severity(item.get("severity", severity)),
                                "details": details,
                            }
                        )
                    else:
                        issues.append(
                            {"source": plugin_name, "severity": severity, "details": str(item)}
                        )
        elif isinstance(data, list):
            for item in data:
                issues.append({"source": plugin_name, "severity": "Low", "details": str(item)})
        else:
            issues.append({"source": plugin_name, "severity": "Low", "details": str(data)})
    return issues


def classify_risk(open_ports, cves, plugin_issues):
    levels = []
    if any(item.get("port") in HIGH_RISK_PORTS for item in open_ports):
        levels.append("Medium")

    for item in open_ports:
        service_risk = item.get("service", {}).get("risk", "Low")
        levels.append(_normalize_severity(service_risk))

    for finding in cves:
        levels.append(_normalize_severity(finding.get("severity", "Medium")))

    for issue in plugin_issues:
        levels.append(_normalize_severity(issue.get("severity", "Low")))

    return max_severity(levels)


def build_host_report(raw_result, plugin_findings=None, cve_findings=None, profile_name=None):
    plugin_issues = _collect_plugin_issues(plugin_findings or {})
    cves = cve_findings or []
    risk = classify_risk(raw_result.get("open_ports", []), cves, plugin_issues)
    return {
        "target": raw_result.get("target"),
        "timestamp": raw_result.get("timestamp") or utc_now_iso(),
        "profile": profile_name,
        "os": raw_result.get("os", "Unknown"),
        "duration_s": raw_result.get("duration_s", 0.0),
        "scanned_ports": raw_result.get("scanned_ports", 0),
        "open_ports": raw_result.get("open_ports", []),
        "port_stats": raw_result.get("port_stats", {}),
        "timing": raw_result.get("timing", {}),
        "timing_template": raw_result.get("timing_template", {}),
        "service_intensity": raw_result.get("service_intensity"),
        "errors": raw_result.get("errors", []),
        "plugin_findings": plugin_findings or {},
        "plugin_issues": plugin_issues,
        "cve_findings": cves,
        "risk_level": risk,
    }


def build_scan_summary(host_reports):
    levels = [item.get("risk_level", "Safe") for item in host_reports]
    worst = max(levels, key=severity_rank) if levels else "Safe"
    total_open_ports = sum(len(item.get("open_ports", [])) for item in host_reports)
    total_closed_ports = sum((item.get("port_stats") or {}).get("closed", 0) for item in host_reports)
    total_filtered_ports = sum((item.get("port_stats") or {}).get("filtered", 0) for item in host_reports)
    total_skipped_ports = sum((item.get("port_stats") or {}).get("skipped", 0) for item in host_reports)
    total_timeouts = sum((item.get("port_stats") or {}).get("timeouts", 0) for item in host_reports)
    return {
        "generated_at": utc_now_iso(),
        "hosts_scanned": len(host_reports),
        "open_ports": total_open_ports,
        "closed_ports": total_closed_ports,
        "filtered_ports": total_filtered_ports,
        "skipped_ports": total_skipped_ports,
        "timeouts": total_timeouts,
        "worst_risk": worst,
    }


def _risk_note(level):
    return _BEGINNER_NOTES.get(str(level).lower(), _BEGINNER_NOTES["low"])


def render_cli_summary(scan_bundle, color=False):
    def paint(text, palette):
        if not color:
            return text
        return Color.wrap(text, palette)

    summary = scan_bundle.get("summary", {})
    hosts = scan_bundle.get("hosts", [])
    worst = str(summary.get("worst_risk", "Safe"))
    sorted_hosts = sorted(hosts, key=lambda item: severity_rank(item.get("risk_level", "Safe")), reverse=True)

    lines = []
    lines.append(paint("NetRecon executive summary", f"{Color.BOLD}{Color.BRIGHT_BLUE}"))
    lines.append(paint(f"Generated: {summary.get('generated_at', utc_now_iso())}", Color.DIM))
    lines.append(paint(f"Hosts scanned: {summary.get('hosts_scanned', 0)}", Color.CYAN))
    lines.append(paint(f"Open ports: {summary.get('open_ports', 0)}", Color.CYAN))
    lines.append(paint(f"Closed ports: {summary.get('closed_ports', 0)}", Color.CYAN))
    lines.append(paint(f"Filtered ports: {summary.get('filtered_ports', 0)}", Color.CYAN))
    lines.append(paint(f"Skipped ports: {summary.get('skipped_ports', 0)}", Color.CYAN))
    lines.append(paint(f"Timeouts: {summary.get('timeouts', 0)}", Color.CYAN))
    lines.append(paint(f"Worst risk: {worst}", Color.severity(worst)))
    lines.append(paint(f"Beginner note: {_risk_note(worst)}", Color.DIM))

    if sorted_hosts:
        lines.append(paint("Priority hosts:", Color.BOLD))
        for host in sorted_hosts[:3]:
            target = host.get("target")
            risk = host.get("risk_level", "Safe")
            open_count = len(host.get("open_ports", []))
            lines.append(
                paint(
                    f"- {target} risk={risk} open_ports={open_count}",
                    Color.severity(risk),
                )
            )
    return "\n".join(lines)


def render_cli_report(host_report, color=False):
    def paint(text, palette):
        if not color:
            return text
        return Color.wrap(text, palette)

    lines = []
    lines.append("")
    lines.append(
        paint(
            f"NetRecon scan report for {host_report['target']}",
            f"{Color.BOLD}{Color.BRIGHT_BLUE}",
        )
    )
    lines.append(paint(f"Host time: {host_report['timestamp']}", Color.DIM))
    lines.append(paint(f"Profile: {host_report.get('profile')}", Color.CYAN))
    lines.append(paint(f"OS guess: {host_report['os']}", Color.CYAN))
    lines.append(paint(f"Scanned ports: {host_report['scanned_ports']}", Color.CYAN))
    lines.append(paint(f"Duration: {host_report.get('duration_s', 0.0)}s", Color.CYAN))
    port_stats = host_report.get("port_stats") or {}
    if port_stats:
        lines.append(
            paint(
                "Port states: "
                f"open={port_stats.get('open', 0)} closed={port_stats.get('closed', 0)} "
                f"filtered={port_stats.get('filtered', 0)} skipped={port_stats.get('skipped', 0)} "
                f"timeouts={port_stats.get('timeouts', 0)}",
                Color.CYAN,
            )
        )

    timing_template = host_report.get("timing_template") or {}
    if timing_template:
        level = timing_template.get("level", 3)
        name = timing_template.get("name", "normal")
        lines.append(paint(f"Timing template: T{level} ({name})", Color.CYAN))
    if host_report.get("service_intensity") is not None:
        lines.append(paint(f"Service intensity: {host_report.get('service_intensity')}/9", Color.CYAN))

    timing = host_report.get("timing") or {}
    timeout_s = timing.get("timeout_s")
    if timeout_s is not None:
        lines.append(paint(f"Adaptive timeout: {timeout_s}s", Color.CYAN))

    risk = str(host_report["risk_level"])
    lines.append(paint(f"Risk level: {risk}", Color.severity(risk)))
    lines.append(paint(f"Guidance: {_risk_note(risk)}", Color.DIM))
    lines.append(paint("PORT      STATE   SERVICE        RISK      DESCRIPTION", Color.BOLD))
    lines.append(paint("--------  ------  -------------  --------  -----------------------------", Color.DIM))

    if not host_report["open_ports"]:
        lines.append(paint("none      closed  n/a            Safe      No open ports detected", Color.DIM))
    else:
        for item in host_report["open_ports"]:
            service = item.get("service", {})
            port = f"{item['port']}/tcp"
            state = item.get("state", "open")
            service_name = service.get("name", "unknown")
            service_risk = str(service.get("risk", "Low"))
            desc = service.get("description", "")
            lines.append(
                paint(
                    f"{port:<8}  {state:<6}  {service_name:<13}  {service_risk:<8}  {desc}",
                    Color.severity(service_risk),
                )
            )
    if host_report["cve_findings"]:
        lines.append(paint("CVE findings:", Color.BOLD))
        for cve in host_report["cve_findings"]:
            lines.append(
                paint(
                    f"- {cve['cve']} ({cve['severity']}): {cve['summary']}",
                    Color.severity(cve["severity"]),
                )
            )
    if host_report["plugin_issues"]:
        lines.append(paint("Plugin findings:", Color.BOLD))
        for issue in host_report["plugin_issues"]:
            lines.append(
                paint(
                    f"- {issue['source']} [{issue['severity']}]: {issue['details']}",
                    Color.severity(issue["severity"]),
                )
            )
    if host_report["errors"]:
        lines.append(paint("Errors:", Color.BOLD))
        for err in host_report["errors"]:
            lines.append(paint(f"- {err}", Color.BRIGHT_RED))
    return "\n".join(lines)


def render_html_report(scan_bundle):
    summary = scan_bundle.get("summary", {})
    hosts = scan_bundle.get("hosts", [])
    rows = []
    for host in hosts:
        ports = ", ".join(str(item["port"]) for item in host.get("open_ports", [])) or "none"
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(host.get('target')))}</td>"
            f"<td>{html.escape(str(host.get('os')))}</td>"
            f"<td>{html.escape(str(host.get('risk_level')))}</td>"
            f"<td>{html.escape(ports)}</td>"
            f"<td>{html.escape(str(host.get('duration_s')))}s</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NetRecon Report</title>
  <style>
    body {{ font-family: "Segoe UI", Tahoma, sans-serif; margin: 24px; background: #f6f8fb; color: #1a2233; }}
    h1 {{ margin-bottom: 8px; }}
    .meta {{ margin-bottom: 20px; color: #3f4f66; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #d6deea; padding: 10px; text-align: left; font-size: 14px; }}
    th {{ background: #eaf0fb; }}
  </style>
</head>
<body>
  <h1>NetRecon Scan Report</h1>
  <div class="meta">
    Generated: {html.escape(str(summary.get("generated_at", "")))}<br />
    Hosts scanned: {html.escape(str(summary.get("hosts_scanned", 0)))}<br />
    Closed ports: {html.escape(str(summary.get("closed_ports", 0)))}<br />
    Filtered ports: {html.escape(str(summary.get("filtered_ports", 0)))}<br />
    Skipped ports: {html.escape(str(summary.get("skipped_ports", 0)))}<br />
    Timeouts: {html.escape(str(summary.get("timeouts", 0)))}<br />
    Worst risk: {html.escape(str(summary.get("worst_risk", "Safe")))}
  </div>
  <table>
    <thead>
      <tr>
        <th>Target</th>
        <th>OS Guess</th>
        <th>Risk</th>
        <th>Open Ports</th>
        <th>Duration</th>
      </tr>
    </thead>
    <tbody>
      {"".join(rows)}
    </tbody>
  </table>
</body>
</html>
"""
