#!/usr/bin/env python3

import argparse
import os
import random
import sys

from core.about import print_about
from core.banners import show_banner, show_cli_scan_header, show_scan_complete, show_scan_start
from core.color import Color
from core.cve_lookup import correlate_open_ports
from core.help_menu import print_help_menu, print_launch_modes
from core.metadata import TOOL_NAME, TOOL_VERSION
from core.output import display, save_cli_report, save_html_report, save_json_report
from core.ping_scan import discover_live_hosts
from core.plugin_loader import run_plugins
from core.profiles import PROFILE_CHOICES, resolve_profile
from core.reporting import build_host_report, build_scan_summary
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


def _merge_profile_with_overrides(profile, args):
    return {
        "ports": args.ports or profile["ports"],
        "stealth": profile["stealth"] or args.stealth,
        "syn": profile["syn"] or args.syn,
        "services": profile["services"] or args.services,
        "plugins": profile["plugins"] or args.plugins,
        "cve_lookup": profile["cve_lookup"],
        "threads": args.threads if args.threads is not None else profile["threads"],
        "timeout": args.timeout if args.timeout is not None else profile["timeout"],
        "retries": args.retries if args.retries is not None else profile["retries"],
        "rate_limit": args.rate_limit if args.rate_limit is not None else profile["rate_limit"],
        "randomize": profile["randomize"],
        "host_discovery": profile["host_discovery"] and not args.no_discovery,
    }


def run_scan(target, profile_name, merged, export_json=False, export_html=False, compact_header=False):
    scan_ports = parse_ports(merged["ports"])
    requested_targets = expand_targets(target)
    if not requested_targets:
        raise ValueError("No valid targets were provided.")

    if compact_header:
        show_cli_scan_header(target_expr=target, port_expr=merged["ports"], profile_name=profile_name)

    scan_targets = randomized(requested_targets, enabled=merged["randomize"])
    host_discovery_errors = {}

    if merged["host_discovery"]:
        live_hosts, host_discovery_errors = discover_live_hosts(scan_targets)
        if live_hosts:
            scan_targets = randomized(live_hosts, enabled=merged["randomize"])
        else:
            # Keep original targets when discovery fails to avoid false negatives.
            pass

    scanner = NetScanner(
        stealth=merged["stealth"],
        syn=merged["syn"],
        detect_services=merged["services"],
        threads=merged["threads"],
        timeout=merged["timeout"],
        retries=merged["retries"],
        rate_limit=merged["rate_limit"],
        randomize_ports=merged["randomize"],
    )

    host_reports = []
    for current_target in scan_targets:
        show_scan_start(current_target, profile_name)
        try:
            raw_result = scanner.scan_host(current_target, scan_ports)
            if current_target in host_discovery_errors:
                raw_result["errors"].append(f"discovery: {host_discovery_errors[current_target]}")

            plugin_findings = {}
            if merged["plugins"]:
                open_ports = [item["port"] for item in raw_result.get("open_ports", [])]
                services = {
                    item["port"]: item.get("service", {}).get("name", "unknown")
                    for item in raw_result.get("open_ports", [])
                }
                plugin_findings = run_plugins(current_target, open_ports, services)

            cve_findings = []
            if merged["cve_lookup"]:
                cve_findings = correlate_open_ports(raw_result.get("open_ports", []))

            host_report = build_host_report(
                raw_result=raw_result,
                plugin_findings=plugin_findings,
                cve_findings=cve_findings,
                profile_name=profile_name,
            )
            host_reports.append(host_report)
            display(host_report)
            show_scan_complete(current_target, raw_result.get("duration_s", 0.0))
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user. Preserving partial results.")
            break
        except Exception as exc:
            partial = build_host_report(
                raw_result={
                    "target": current_target,
                    "open_ports": [],
                    "scanned_ports": len(scan_ports),
                    "os": "Unknown",
                    "errors": [str(exc)],
                    "duration_s": 0.0,
                },
                plugin_findings={},
                cve_findings=[],
                profile_name=profile_name,
            )
            host_reports.append(partial)
            display(partial)

    summary = build_scan_summary(host_reports)
    bundle = {"summary": summary, "hosts": host_reports}

    cli_path = save_cli_report(bundle)
    print(f"{Color.success(f'[+] CLI report saved: {cli_path}')}")

    if export_json:
        json_path = save_json_report(bundle)
        print(f"{Color.success(f'[+] JSON report saved: {json_path}')}")

    if export_html:
        html_path = save_html_report(bundle)
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
    }
    print(f"\n{Color.title('Select scan profile:')}")
    print(f"{Color.accent('  1) Quick')}")
    print(f"{Color.accent('  2) Stealth')}")
    print(f"{Color.accent('  3) Aggressive')}")
    print(f"{Color.accent('  4) Web')}")
    print(f"{Color.accent('  5) Vulnerability Scan')}")
    pick = _safe_input(f"{Color.accent('Choice: ')}").strip()
    while pick not in profile_map:
        pick = _safe_input(f"{Color.warning('Choose 1, 2, 3, 4, or 5: ')}").strip()

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
        "timeout": profile["timeout"],
        "retries": profile["retries"],
        "rate_limit": profile["rate_limit"],
        "randomize": profile["randomize"],
        "host_discovery": profile["host_discovery"],
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
    parser.add_argument("--ports", help="Override profile ports (e.g., 22,80,443 or 1-1024)")
    parser.add_argument("--threads", type=int, help="Thread count (recommended 100-300)")
    parser.add_argument("--timeout", type=float, help="Socket timeout in seconds")
    parser.add_argument("--retries", type=int, help="Retries per port")
    parser.add_argument("--rate-limit", type=float, help="Delay between probes in seconds")
    parser.add_argument("--plugins", action="store_true", help="Enable plugin modules")
    parser.add_argument("--json", action="store_true", help="Export JSON report")
    parser.add_argument("--html", action="store_true", help="Export HTML report")
    parser.add_argument("--no-discovery", action="store_true", help="Skip ping-based host discovery")
    parser.add_argument("--syn", action="store_true", help="Force SYN scan mode (requires scapy + privileges)")
    parser.add_argument("-s", "--stealth", action="store_true", help="Apply stealth timing strategy")
    parser.add_argument("-sV", "--services", action="store_true", help="Enable service fingerprinting")
    parser.add_argument("--about", action="store_true", help="Show tool details")
    parser.add_argument("--launch-modes", action="store_true", help="Show launch mode guide")
    parser.add_argument("--list-profiles", action="store_true", help="List available profiles")
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
