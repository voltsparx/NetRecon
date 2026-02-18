from .color import Color
from .metadata import TOOL_NAME, TOOL_VERSION


def _headline(text):
    return f"{Color.title(text)}"


LAUNCH_MODES_HELP = f"""\
{TOOL_NAME} launch modes
========================

1) Interactive Prompt Mode (beginner friendly)
   Trigger:
     python netrecon.py
   Behavior:
     - Guided prompt flow
     - Full banner + version/author/contact

2) Argparse Fast Mode (automation friendly)
   Trigger:
     python netrecon.py <target> -p <profile> [options]
   Behavior:
     - Compact nmap-style scan header
     - Flag-driven execution for scripts
"""


CLI_HELP_TEXT = f"""\
{TOOL_NAME} {TOOL_VERSION} - Help
==========================

Usage:
  python netrecon.py <target> [options]
  python netrecon.py                     # interactive mode

Targets:
  IP, hostname, CIDR, or comma-separated hosts

Profiles:
  quick | stealth | aggressive | web | vuln

Main options:
  -p, --profile <name>    Select scan profile
      --ports <expr>      Port expression (e.g. 22,80,443 or 1-1024)
      --threads <int>     Thread count
      --timeout <sec>     Socket timeout
      --retries <int>     Retry count
      --rate-limit <sec>  Delay between probes

Feature options:
      --plugins           Enable plugins
      --json              Save JSON report
      --html              Save HTML report
      --no-discovery      Skip ping host discovery
      --syn               Force SYN scan mode (scapy + privilege required)
  -s, --stealth           Apply stealth timing strategy
  -sV, --services         Enable service fingerprinting

Meta options:
      --about             Show tool information
      --list-profiles     List profile descriptions
      --launch-modes      Show launch mode guide
  -h, --help              Show this help menu

Examples:
  python netrecon.py 192.168.1.10 -p quick
  python netrecon.py 10.0.0.0/24 -p aggressive --plugins --json --html
  python netrecon.py example.com -p web --plugins --html
"""


def print_launch_modes():
    print(f"{_headline('Launch Modes')}")
    print(f"{LAUNCH_MODES_HELP}")


def print_help_menu():
    print(f"{_headline('Help Menu')}")
    print(f"{CLI_HELP_TEXT}")
