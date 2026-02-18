#!/usr/bin/env python3

import argparse
from core.utils import parse_ports, expand_targets
from core.scanner import NetScanner
from core.output import display
from core.config import DEFAULT_PORTS

def main():
    parser = argparse.ArgumentParser(description="NetRecon v3.2 - Modular Network Scanner")
    parser.add_argument("target", help="Target IP or CIDR")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS)
    parser.add_argument("-s", "--stealth", action="store_true")
    parser.add_argument("-sV", "--services", action="store_true")
    args = parser.parse_args()

    targets = expand_targets(args.target)
    ports = parse_ports(args.ports)

    scanner = NetScanner(stealth=args.stealth, detect_services=args.services)

    for target in targets:
        results = scanner.scan_host(target, ports)
        display(results)

if __name__ == "__main__":
    main()
