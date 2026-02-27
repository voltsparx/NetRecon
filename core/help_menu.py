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
  quick | stealth | aggressive | web | vuln | root

Main options:
  -p, --profile <name>    Select scan profile
  -T, --timing-template   Timing template (0=paranoid .. 5=insane)
  -o, --ports <expr>      Port expression (e.g. 22,80,443 or 1-1024)
  -t, --threads <int>     Thread count
  -w, --host-workers <n>  Concurrent host workers
  -g, --host-group-size <n> Hosts per parallel execution group
  -k, --plugin-workers <n> Plugin worker threads per host
  -a, --async-limit <n>   Async enrichment concurrency cap
  -i, --service-intensity <n> Service probe intensity (0-9)
  -z, --host-timeout <sec> Give up on a host after N seconds
  -A, --stats-every <sec> Print periodic progress every N seconds
  -O, --timeout <sec>     Socket timeout
  -m, --min-rtt-timeout <sec> Minimum adaptive RTT timeout
  -M, --max-rtt-timeout <sec> Maximum adaptive RTT timeout
  -r, --retries <int>     Retry count
  -R, --rate-limit <sec>  Delay between probes
  -q, --exclude-ports <expr> Exclude ports from scan set
  -E, --exclude <targets> Exclude targets/networks from scan
  -e, --exclude-file <path> Exclude targets/networks listed in file

Feature options:
  -P, --plugins           Enable plugins
  -j, --json              Save JSON report
  -H, --html              Save HTML report
  -f, --save-prefix <name> Custom prefix for saved reports
  -n, --no-discovery      Skip ping host discovery
  -y, --syn               Force SYN scan mode (scapy + privilege required)
  -x, --root-scan         Require root/admin and run privileged scan path
  -u, --sudo              Attempt sudo auto-elevation for root scan
  -s, --stealth           Apply stealth timing strategy
  -sV, -V, --services     Enable service fingerprinting

Meta options:
  -b, --about             Show tool information
  -l, --list-profiles     List profile descriptions
  -L, --launch-modes      Show launch mode guide
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
