import html

from .color import Color
from .config import HIGH_RISK_PORTS
from .utils import max_severity, severity_rank, utc_now_iso


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
    return {
        "generated_at": utc_now_iso(),
        "hosts_scanned": len(host_reports),
        "open_ports": total_open_ports,
        "worst_risk": worst,
    }


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

    risk = str(host_report["risk_level"])
    lines.append(paint(f"Risk level: {risk}", Color.severity(risk)))
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
