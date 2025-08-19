#!/usr/bin/env python3

# NetRecon v2.7 - Advanced Network Scanner
# Copyright (c) 2023 CyberSecurity Analyst
# Licensed under MIT (https://github.com/voltsparx/NetRecon/LICENSE.txt)

"""
NetRecon v2.7 - Advanced Network Scanner
Stealth Scans | Service Fingerprinting | Rich Output | Async Techniques
"""

import socket
import subprocess
import ipaddress
import struct
import random
import select
import argparse
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time
import asyncio
from typing import List, Tuple, Dict, Optional

# Enhanced Module Imports
try:
    from scapy.all import IP, TCP, sr1, RandShort, conf
    SCAPY_ENABLED = True
    conf.verb = 0
except ImportError:
    SCAPY_ENABLED = False

try:
    import nmap
    NMAP_ENABLED = True
except ImportError:
    NMAP_ENABLED = False

try:
    from rich.console import Console
    from rich.table import Table
    RICH_ENABLED = True
except ImportError:
    RICH_ENABLED = False

try:
    import aiohttp
    AIOHTTP_ENABLED = True
except ImportError:
    AIOHTTP_ENABLED = False

# Configuration
DEFAULT_PORTS = "1-1024"
MAX_THREADS = 150
STEALTH_DELAY = 0.2
TIMEOUT = 2.0

class NetRecon:
    def __init__(self):
        self.console = Console() if RICH_ENABLED else None
        self.verbose = False
        self.stealth = False
        self.services = False
        self.scan_stats = {'hosts': 0, 'ports': 0, 'open': 0}

    def _show_banner(self):
        """Display the tool banner with metadata and warning"""
        banner = r"""
 |====================================================|
 |     _   _      _   ____                            |
 |    | \ | | ___| |_|  _ \ ___  ___ ___  _ __        |
 |    |  \| |/ _ \ __| |_) / _ \/ __/ _ \| '_ \       |
 |    | |\  |  __/ |_|  _ <  __/ (_| (_) | | | |      |
 |    |_| \_|\___|\__|_| \_\___|\___\___/|_| |_|      |
 |                                               v2.7 |
 |====================================================|
   """
        
        metadata = {
            "version": "2.7",
            "author": "voltsparx",
            "contact": "voltsparx@gmail.com",
            "repo": "https://github.com/voltsparx/NetRecon",
            "warning": "WARNING: This tool is for authorized security testing and research only!"
        }

        if RICH_ENABLED:
            self.console.print(f"[bold green]{banner}[/]")
            self.console.print(f"[bold cyan]NetRecon {metadata['version']}[/]", justify="center")
            self.console.print("\n[bold]Project Details:[/]")
            self.console.print(f"• Author: [yellow]{metadata['author']}[/]")
            self.console.print(f"• Contact: [yellow]{metadata['contact']}[/]")
            self.console.print(f"• Repository: [blue underline]{metadata['repo']}[/]")
            self.console.print(f"\n[bold red]{metadata['warning']}[/]\n")
        else:
            print(banner)
            print(f"NetRecon {metadata['version']}\n")
            print("Project Details:")
            print(f"• Author: {metadata['author']}")
            print(f"• Contact: {metadata['contact']}")
            print(f"• Repository: {metadata['repo']}")
            print(f"\n{metadata['warning']}\n")

    def scan(self, target: str, ports: List[int]) -> Dict:
        """Execute complete scan workflow"""
        results = {
            'target': target,
            'tcp': [],
            'udp': [],
            'os': self._detect_os(target),
            'hostname': self._resolve_host(target)
        }

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(self._check_port, target, port, 'tcp'): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                port, status, service = future.result()
                if status == 'open':
                    results['tcp'].append((port, service))
                    self._update_stats(port, service)

        return results

    def _check_port(self, target: str, port: int, proto: str) -> Tuple[int, str, str]:
        """Multi-method port checking"""
        if proto == 'tcp':
            status = self._syn_scan(target, port) if (self.stealth and SCAPY_ENABLED) else self._connect_scan(target, port)
        else:
            status = self._udp_probe(target, port)

        service = self._identify_service(target, port, proto) if (status == 'open' and self.services) else "unknown"
        time.sleep(STEALTH_DELAY if self.stealth else 0)
        return (port, status, service)

    def _syn_scan(self, target: str, port: int) -> str:
        """Scapy SYN scan"""
        try:
            pkt = IP(dst=target)/TCP(sport=RandShort(), dport=port, flags="S")
            resp = sr1(pkt, timeout=TIMEOUT, verbose=False)
            if resp and resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    self._send_rst(target, port, resp.getlayer(TCP).sport)
                    return 'open'
                elif resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return 'closed'
            return 'filtered'
        except:
            return 'error'

    def _connect_scan(self, target: str, port: int) -> str:
        """Traditional connect scan"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                return 'open' if s.connect_ex((target, port)) == 0 else 'closed'
        except:
            return 'error'

    def _identify_service(self, target: str, port: int, proto: str) -> str:
        """Layered service detection"""
        if NMAP_ENABLED:
            try:
                nm = nmap.PortScanner()
                nm.scan(target, arguments=f"-sV -p {port} --version-intensity 1")
                service = nm[target][proto][port]['name']
                product = nm[target][proto][port].get('product', '')
                version = nm[target][proto][port].get('version', '')
                if product or version:
                    return f"{service} {product} {version}".strip()
                return service
            except:
                pass

        if proto == 'tcp' and port in [80, 443, 8080] and AIOHTTP_ENABLED:
            banner = asyncio.run(self._get_http_banner(target, port))
            if banner: return banner

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((target, port))
                s.send(b"GET / HTTP/1.0\r\n\r\n")
                return s.recv(1024).decode('utf-8', 'ignore').split('\n')[0][:50]
        except:
            return "unknown"

    async def _get_http_banner(self, target: str, port: int) -> str:
        """Async HTTP banner grab"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=1)) as resp:
                    server = resp.headers.get('Server', '')
                    return f"HTTP ({server})" if server else "HTTP"
        except:
            return ""

    def display(self, results: Dict):
        """Rich or basic output"""
        if RICH_ENABLED:
            self._rich_output(results)
        else:
            self._basic_output(results)

    def _rich_output(self, results: Dict):
        """Rich formatted display"""
        table = Table(title=f"Scan Results for [bold]{results['target']}[/]")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="magenta")
        for port, service in results['tcp']:
            table.add_row(str(port), service)
        self.console.print(table)
        self.console.print(f"\nOS: [bold]{results['os']}[/] | Hostname: [bold]{results['hostname']}[/]")

    def _basic_output(self, results: Dict):
        """Fallback text output"""
        print(f"\nScan Results for {results['target']}")
        print("PORT\tSERVICE")
        for port, service in results['tcp']:
            print(f"{port}\t{service}")
        print(f"\nOS: {results['os']} | Hostname: {results['hostname']}")

    def _detect_os(self, target: str) -> str:
        """OS detection via TTL"""
        try:
            ping = subprocess.Popen(["ping", "-c", "1", target], stdout=subprocess.PIPE)
            output = ping.communicate()[0].decode()
            ttl = [line for line in output.split('\n') if 'ttl=' in line.lower()]
            if ttl:
                ttl_value = int(ttl[0].split('ttl=')[1].split(' ')[0])
                if ttl_value <= 64:
                    return "Linux/Unix"
                elif ttl_value <= 128:
                    return "Windows"
                return f"Unknown (TTL: {ttl_value})"
        except:
            pass
        return "Unknown"

    def _resolve_host(self, target: str) -> Optional[str]:
        """Reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(target)[0]
        except:
            return None

    def _update_stats(self, port: int, service: str):
        """Update scan statistics"""
        self.scan_stats['ports'] += 1
        self.scan_stats['open'] += 1

    def _send_rst(self, target: str, port: int, sport: int):
        """Send RST packet to close connection"""
        if SCAPY_ENABLED:
            try:
                from scapy.all import send  # Import send function locally
                send(IP(dst=target)/TCP(sport=sport, dport=port, flags="R"), verbose=False)
            except:
                pass

def parse_ports(port_str: str) -> List[int]:
    """Parse port ranges like 1-1000,80,443"""
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="NetRecon v2.7 - Advanced Network Scanner")
    parser.add_argument("target", help="Target IP or CIDR range")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Ports to scan")
    parser.add_argument("-s", "--stealth", action="store_true", help="Use stealth scanning")
    parser.add_argument("-sV", "--services", action="store_true", help="Enable service detection")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    scanner = NetRecon()
    scanner.verbose = args.verbose
    scanner.stealth = args.stealth
    scanner.services = args.services
    scanner._show_banner()  # Display banner on startup

    try:
        ports = parse_ports(args.ports)
        start_time = datetime.now()
        results = scanner.scan(args.target, ports)
        scanner.display(results)
        
        if scanner.verbose:
            duration = datetime.now() - start_time
            print(f"\nScan completed in {duration.total_seconds():.2f} seconds")
    except KeyboardInterrupt:
        print("\nScan aborted by user")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()