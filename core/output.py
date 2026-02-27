import json
import os
from datetime import datetime

from .config import OUTPUT_DIR_CLI, OUTPUT_DIR_HTML, OUTPUT_DIR_JSON
from .reporting import render_cli_report, render_cli_summary, render_html_report


def _timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _display_path(path):
    return str(path).replace("\\", "/")


def ensure_output_dirs():
    os.makedirs(OUTPUT_DIR_CLI, exist_ok=True)
    os.makedirs(OUTPUT_DIR_HTML, exist_ok=True)
    os.makedirs(OUTPUT_DIR_JSON, exist_ok=True)


def display(host_report):
    text = render_cli_report(host_report, color=True)
    print(f"{text}")


def save_cli_report(scan_bundle, filename=None):
    ensure_output_dirs()
    name = filename or f"netrecon_{_timestamp()}.txt"
    path = os.path.join(OUTPUT_DIR_CLI, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_cli_summary(scan_bundle, color=False))
        handle.write("\n\n")
        for host in scan_bundle.get("hosts", []):
            handle.write(render_cli_report(host, color=False))
            handle.write("\n\n")
    return _display_path(path)


def save_json_report(scan_bundle, filename=None):
    ensure_output_dirs()
    name = filename or f"netrecon_{_timestamp()}.json"
    path = os.path.join(OUTPUT_DIR_JSON, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(scan_bundle, handle, indent=2)
    return _display_path(path)


def save_html_report(scan_bundle, filename=None):
    ensure_output_dirs()
    name = filename or f"netrecon_{_timestamp()}.html"
    path = os.path.join(OUTPUT_DIR_HTML, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html_report(scan_bundle))
    return _display_path(path)
