#!/usr/bin/env python3

import argparse
import os
import random
import re
import sys
from datetime import datetime

from core.about import print_about
from core.banners import show_banner, show_cli_scan_header
from core.color import Color
from core.engine.orchestrator import ScanOrchestrator
from core.engine.reporter import ScanReporter
from core.engine.timing_engine import resolve_timing_template
from core.help_menu import print_help_menu, print_launch_modes
from core.metadata import TOOL_NAME, TOOL_VERSION
from core.output import display, save_cli_report, save_html_report, save_json_report
from core.ping_scan import discover_live_hosts
from core.privilege import can_sudo_relaunch, is_privileged, privilege_name, relaunch_with_sudo
from core.profiles import PROFILE_CHOICES, resolve_profile
from core.reporting import build_scan_summary
from core.scanner import NetScanner
from core.utils import expand_targets, parse_ports, randomized


def _safe_input(prompt_text):
    try:
        return input(f"{prompt_text}")
    except EOFError:
        raise KeyboardInterrupt


def _prompt_yes_no(prompt_text):
    while True:
        value = _safe_input(f"{Color.accent(prompt_text)}").strip().lower()
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print(f"{Color.warning('Please enter y or n.')}")


def _clear_screen():
    cmd = "cls" if os.name == "nt" else "clear"
    rc = os.system(cmd)
    if rc != 0:
        # Fallback for terminals where shell clear command is unavailable.
        print("\033[2J\033[H", end="")


def _dedupe_preserve(items):
    ordered = []
    seen = set()
    for item in items:
        key = str(item).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(str(item).strip())
    return ordered


def _load_target_lines(path):
    if not path:
        return []
    loaded = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            loaded.append(line)
    return loaded


def _collect_excluded_targets(exclude_expr=None, exclude_file=None):
    values = []
    if exclude_expr:
        values.append(exclude_expr)
    for line in _load_target_lines(exclude_file):
        values.append(line)

    expanded = []
    for item in values:
        expanded.extend(expand_targets(item))
    return _dedupe_preserve(expanded)


def _build_output_filenames(save_prefix):
    if not save_prefix:
        return {}

    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(save_prefix).strip()).strip("._-")
    if not cleaned:
        return {}

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return {
        "cli": f"{cleaned}_cli_{stamp}.txt",
        "json": f"{cleaned}_json_{stamp}.json",
        "html": f"{cleaned}_html_{stamp}.html",
    }


def _ensure_root_privileges(root_scan=False, auto_elevate=False):
    if not root_scan:
        return
    if is_privileged():
        return

    required = privilege_name()
    if auto_elevate:
        if can_sudo_relaunch():
            relaunched, result = relaunch_with_sudo()
            if relaunched:
                raise SystemExit(result)
            raise PermissionError(f"Root scan requested, but elevation failed: {result}")
        if os.name == "nt":
            raise PermissionError(
                "Root scan requested. Please run this terminal as Administrator."
            )

    if can_sudo_relaunch():
        raise PermissionError(
            f"Root scan requested. Please run with elevated privileges ({required}) "
            f"or use --sudo for auto elevation."
        )
    raise PermissionError(
        f"Root scan requested. Please start this shell as {required} and run again."
    )


def _merge_profile_with_overrides(profile, args):
    return {
        "ports": args.ports or profile["ports"],
        "stealth": profile["stealth"] or args.stealth,
        "syn": profile["syn"] or args.syn,
        "services": profile["services"] or args.services,
        "plugins": profile["plugins"] or args.plugins,
        "cve_lookup": profile["cve_lookup"],
        "threads": args.threads if args.threads is not None else profile["threads"],
        "timing_template": (
            args.timing_template
            if args.timing_template is not None
            else profile["timing_template"]
        ),
        "service_intensity": (
            args.service_intensity
            if args.service_intensity is not None
            else profile["service_intensity"]
        ),
        "host_timeout": (
            args.host_timeout
            if args.host_timeout is not None
            else profile.get("host_timeout", 0.0)
        ),
        "stats_every": (
            args.stats_every
            if args.stats_every is not None
            else profile.get("stats_every", 0.0)
        ),
        "timeout": args.timeout if args.timeout is not None else profile["timeout"],
        "min_rtt_timeout": (
            args.min_rtt_timeout
            if args.min_rtt_timeout is not None
            else profile["min_rtt_timeout"]
        ),
        "max_rtt_timeout": (
            args.max_rtt_timeout
            if args.max_rtt_timeout is not None
            else profile["max_rtt_timeout"]
        ),
        "retries": args.retries if args.retries is not None else profile["retries"],
        "rate_limit": args.rate_limit if args.rate_limit is not None else profile["rate_limit"],
        "host_workers": (
            args.host_workers if args.host_workers is not None else profile["host_workers"]
        ),
        "host_group_size": (
            args.host_group_size if args.host_group_size is not None else profile["host_group_size"]
        ),
        "plugin_workers": (
            args.plugin_workers if args.plugin_workers is not None else profile["plugin_workers"]
        ),
        "async_limit": (
            args.async_limit if args.async_limit is not None else profile["async_limit"]
        ),
        "randomize": profile["randomize"],
        "host_discovery": profile["host_discovery"] and not args.no_discovery,
        "root_scan": profile.get("root_scan", False) or args.root_scan,
        "auto_elevate": profile.get("auto_elevate", False) or args.sudo,
        "exclude_targets": args.exclude,
        "exclude_file": args.exclude_file,
        "exclude_ports": args.exclude_ports,
        "save_prefix": args.save_prefix,
    }


def run_scan(
    target,
    profile_name,
    merged,
    export_json=False,
    export_html=False,
    compact_header=False,
):
    _ensure_root_privileges(
        root_scan=merged.get("root_scan", False),
        auto_elevate=merged.get("auto_elevate", False),
    )

    requested_targets = _dedupe_preserve(expand_targets(target))
    if not requested_targets:
        raise ValueError("No valid targets were provided.")

    excluded_targets = _collect_excluded_targets(
        exclude_expr=merged.get("exclude_targets"),
        exclude_file=merged.get("exclude_file"),
    )
    if excluded_targets:
        excluded_keys = {item.lower() for item in excluded_targets}
        requested_targets = [host for host in requested_targets if host.lower() not in excluded_keys]
        if not requested_targets:
            raise ValueError("All targets were excluded. Nothing left to scan.")

    scan_ports = parse_ports(merged["ports"])
    exclude_ports_expr = merged.get("exclude_ports")
    if exclude_ports_expr:
        excluded_ports = set(parse_ports(exclude_ports_expr))
        scan_ports = [port for port in scan_ports if port not in excluded_ports]
        if not scan_ports:
            raise ValueError("All requested ports were excluded. Nothing left to scan.")

    if compact_header:
        port_label = ",".join(str(port) for port in scan_ports)
        show_cli_scan_header(target_expr=target, port_expr=port_label, profile_name=profile_name)

    scan_targets = randomized(requested_targets, enabled=merged["randomize"])
    host_discovery_errors = {}

    if merged["host_discovery"]:
        live_hosts, host_discovery_errors = discover_live_hosts(scan_targets)
        if live_hosts:
            scan_targets = randomized(live_hosts, enabled=merged["randomize"])
        else:
            # Keep original targets when discovery fails to avoid false negatives.
            pass

    min_rtt_timeout = float(merged["min_rtt_timeout"])
    max_rtt_timeout = float(merged["max_rtt_timeout"])
    if min_rtt_timeout > max_rtt_timeout:
        min_rtt_timeout, max_rtt_timeout = max_rtt_timeout, min_rtt_timeout

    scanner = NetScanner(
        stealth=merged["stealth"],
        syn=merged["syn"] or merged.get("root_scan", False),
        detect_services=merged["services"],
        threads=merged["threads"],
        timeout=merged["timeout"],
        retries=merged["retries"],
        rate_limit=merged["rate_limit"],
        randomize_ports=merged["randomize"],
        timing_template=merged["timing_template"],
        service_intensity=merged["service_intensity"],
        host_timeout=merged.get("host_timeout", 0.0),
        min_rtt_timeout=min_rtt_timeout,
        max_rtt_timeout=max_rtt_timeout,
        strict_syn=merged.get("root_scan", False),
    )

    timing_template = resolve_timing_template(merged.get("timing_template", 3))
    host_workers = int(merged.get("host_workers", max(1, int(merged["threads"]) // 8)))
    host_workers = max(1, int(round(host_workers * timing_template["host_workers_multiplier"])))
    host_group_size = max(1, int(merged.get("host_group_size", 32)))
    plugin_workers = int(merged.get("plugin_workers", 6))
    async_limit = int(merged.get("async_limit", max(2, plugin_workers)))

    ports_expr = merged["ports"]
    if exclude_ports_expr:
        ports_expr = f"{merged['ports']} (excluding {exclude_ports_expr})"

    reporter = ScanReporter(
        target_expr=target,
        ports_expr=ports_expr,
        profile_name=profile_name,
        total_hosts=len(scan_targets),
        host_workers=host_workers,
        port_workers=scanner.threads,
        host_group_size=host_group_size,
        timing_template_level=merged.get("timing_template", 3),
        timing_template_name=timing_template["name"],
        plugin_workers=plugin_workers,
        async_limit=async_limit,
        service_intensity=merged.get("service_intensity", 5),
        stats_every=merged.get("stats_every", 0.0),
        enabled=True,
    )
    reporter.announce_plan()

    orchestrator = ScanOrchestrator(
        scanner=scanner,
        profile_name=profile_name,
        scan_ports=scan_ports,
        plugins_enabled=merged["plugins"],
        cve_lookup_enabled=merged["cve_lookup"],
        host_workers=host_workers,
        host_group_size=host_group_size,
        plugin_workers=plugin_workers,
        async_limit=async_limit,
        host_discovery_errors=host_discovery_errors,
        reporter=reporter,
        on_host_report=display,
    )

    host_reports = []
    try:
        host_reports = orchestrator.scan_targets(scan_targets)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Preserving partial results.")
        host_reports = list(orchestrator.completed_reports)

    summary = build_scan_summary(host_reports)
    bundle = {"summary": summary, "hosts": host_reports}
    reporter.finalize(summary)

    output_names = _build_output_filenames(merged.get("save_prefix"))
    cli_path = save_cli_report(bundle, filename=output_names.get("cli"))
    print(f"{Color.success(f'[+] CLI report saved: {cli_path}')}")

    if export_json:
        json_path = save_json_report(bundle, filename=output_names.get("json"))
        print(f"{Color.success(f'[+] JSON report saved: {json_path}')}")

    if export_html:
        html_path = save_html_report(bundle, filename=output_names.get("html"))
        print(f"{Color.success(f'[+] HTML report saved: {html_path}')}")

    return bundle


def run_interactive_mode():
    _clear_screen()
    show_banner()
    print(f"{Color.title(f'Welcome to {TOOL_NAME} {TOOL_VERSION}')}")
    target = _safe_input(f"{Color.accent('Enter target (IP, domain, or CIDR): ')}").strip()
    while not target:
        target = _safe_input(f"{Color.warning('Target cannot be empty. Enter target: ')}").strip()

    profile_map = {
        "1": "quick",
        "2": "stealth",
        "3": "aggressive",
        "4": "web",
        "5": "vuln",
        "6": "root",
    }
    print(f"\n{Color.title('Select scan profile:')}")
    print(f"{Color.accent('  1) Quick')}")
    print(f"{Color.accent('  2) Stealth')}")
    print(f"{Color.accent('  3) Aggressive')}")
    print(f"{Color.accent('  4) Web')}")
    print(f"{Color.accent('  5) Vulnerability Scan')}")
    print(f"{Color.accent('  6) Root Privileged Scan')}")
    pick = _safe_input(f"{Color.accent('Choice: ')}").strip()
    while pick not in profile_map:
        pick = _safe_input(f"{Color.warning('Choose 1, 2, 3, 4, 5, or 6: ')}").strip()

    profile_name = profile_map[pick]
    profile = resolve_profile(profile_name)

    plugins_enabled = _prompt_yes_no("Enable plugins? (y/n): ")
    export_json = _prompt_yes_no("Export JSON report? (y/n): ")
    export_html = _prompt_yes_no("Export HTML report? (y/n): ")

    merged = {
        "ports": profile["ports"],
        "stealth": profile["stealth"],
        "syn": profile["syn"],
        "services": profile["services"],
        "plugins": profile["plugins"] or plugins_enabled,
        "cve_lookup": profile["cve_lookup"],
        "threads": profile["threads"],
        "timing_template": profile["timing_template"],
        "service_intensity": profile["service_intensity"],
        "host_timeout": profile.get("host_timeout", 0.0),
        "stats_every": profile.get("stats_every", 0.0),
        "timeout": profile["timeout"],
        "min_rtt_timeout": profile["min_rtt_timeout"],
        "max_rtt_timeout": profile["max_rtt_timeout"],
        "retries": profile["retries"],
        "rate_limit": profile["rate_limit"],
        "host_workers": profile["host_workers"],
        "host_group_size": profile["host_group_size"],
        "plugin_workers": profile["plugin_workers"],
        "async_limit": profile["async_limit"],
        "randomize": profile["randomize"],
        "host_discovery": profile["host_discovery"],
        "root_scan": profile.get("root_scan", False),
        "auto_elevate": profile.get("auto_elevate", False),
        "exclude_targets": None,
        "exclude_file": None,
        "exclude_ports": None,
        "save_prefix": None,
    }
    run_scan(
        target=target,
        profile_name=profile_name,
        merged=merged,
        export_json=export_json,
        export_html=export_html,
        compact_header=False,
    )


def run_argparse_mode():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} {TOOL_VERSION} - Modular Recon Framework",
        add_help=False,
    )
    parser.add_argument("target", nargs="?", help="Target IP, hostname, CIDR, or comma-separated hosts")
    parser.add_argument("-p", "--profile", default="quick", choices=PROFILE_CHOICES, help="Scan profile")
    parser.add_argument("-T", "--timing-template", type=int, choices=range(0, 6), help="Timing template (0-5)")
    parser.add_argument("-o", "--ports", help="Override profile ports (e.g., 22,80,443 or 1-1024)")
    parser.add_argument("-t", "--threads", type=int, help="Thread count (recommended 100-300)")
    parser.add_argument("-w", "--host-workers", type=int, help="Concurrent host workers")
    parser.add_argument("-g", "--host-group-size", type=int, help="Hosts per parallel execution group")
    parser.add_argument("-k", "--plugin-workers", type=int, help="Plugin worker threads per host")
    parser.add_argument("-a", "--async-limit", type=int, help="Async concurrency limit for enrichment")
    parser.add_argument(
        "-i",
        "--service-intensity",
        type=int,
        choices=range(0, 10),
        help="Service probe intensity (0-9)",
    )
    parser.add_argument("-z", "--host-timeout", type=float, help="Give up on a host after N seconds")
    parser.add_argument("-A", "--stats-every", type=float, help="Print periodic progress every N seconds")
    parser.add_argument("-O", "--timeout", type=float, help="Socket timeout in seconds")
    parser.add_argument("-m", "--min-rtt-timeout", type=float, help="Minimum adaptive RTT timeout in seconds")
    parser.add_argument("-M", "--max-rtt-timeout", type=float, help="Maximum adaptive RTT timeout in seconds")
    parser.add_argument("-r", "--retries", type=int, help="Retries per port")
    parser.add_argument("-R", "--rate-limit", type=float, help="Delay between probes in seconds")
    parser.add_argument("-q", "--exclude-ports", help="Exclude ports from scan set (e.g., 22,3389)")
    parser.add_argument("-E", "--exclude", help="Exclude targets/networks from scanning")
    parser.add_argument("-e", "--exclude-file", help="Exclude targets/networks listed in a file")
    parser.add_argument("-P", "--plugins", action="store_true", help="Enable plugin modules")
    parser.add_argument("-j", "--json", action="store_true", help="Export JSON report")
    parser.add_argument("-H", "--html", action="store_true", help="Export HTML report")
    parser.add_argument("-f", "--save-prefix", help="Custom prefix for saved report filenames")
    parser.add_argument("-n", "--no-discovery", action="store_true", help="Skip ping-based host discovery")
    parser.add_argument("-y", "--syn", action="store_true", help="Force SYN scan mode (requires scapy + privileges)")
    parser.add_argument("-x", "--root-scan", action="store_true", help="Enable privileged root/admin scan mode")
    parser.add_argument("-u", "--sudo", action="store_true", help="Auto relaunch with sudo when root scan is requested")
    parser.add_argument("-s", "--stealth", action="store_true", help="Apply stealth timing strategy")
    parser.add_argument("-sV", "-V", "--services", action="store_true", help="Enable service fingerprinting")
    parser.add_argument("-b", "--about", action="store_true", help="Show tool details")
    parser.add_argument("-L", "--launch-modes", action="store_true", help="Show launch mode guide")
    parser.add_argument("-l", "--list-profiles", action="store_true", help="List available profiles")
    parser.add_argument("-h", "--help", action="store_true", help="Show help menu")
    args = parser.parse_args()

    if args.help:
        print_help_menu()
        return

    if args.about:
        print_about(show_banner=True)
        return

    if args.list_profiles:
        print(f"{Color.title('Available Profiles')}")
        for name in PROFILE_CHOICES:
            profile = resolve_profile(name)
            desc = profile["description"]
            print(f"{Color.accent(f'- {name}: {desc}')}")
        if not args.target:
            return

    if args.launch_modes:
        print_launch_modes()
        return

    if not args.target:
        parser.error("target is required for scanning. Use --help for usage.")

    profile = resolve_profile(args.profile)
    merged = _merge_profile_with_overrides(profile, args)
    run_scan(
        target=args.target,
        profile_name=args.profile,
        merged=merged,
        export_json=args.json,
        export_html=args.html,
        compact_header=True,
    )


def main():
    random.seed()
    try:
        if len(sys.argv) == 1:
            run_interactive_mode()
        else:
            run_argparse_mode()
    except KeyboardInterrupt:
        print(f"\n{Color.warning('[!] User interrupted execution.')}")
    except Exception as exc:
        print(f"{Color.error(f'[!] Fatal error: {exc}')}")


if __name__ == "__main__":
    main()
