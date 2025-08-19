
=======================================
NetRecon v2.7 - Advanced Network Scanner
=======================================

Author: voltsparx
Contact: voltsparx@gmail.com
Repository: https://github.com/voltsparx/NetRecon
License: MIT

[![Python 3.6+](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://python.org)  
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  

> ⚠️ **Warning**: Only use on authorized systems. Unauthorized scanning is illegal.

== BANNER ==
 |====================================================|
 |     _   _      _   ____                            |
 |    | \ | | ___| |_|  _ \ ___  ___ ___  _ __        |
 |    |  \| |/ _ \ __| |_) / _ \/ __/ _ \| '_ \       |
 |    | |\  |  __/ |_|  _ <  __/ (_| (_) | | | |      |
 |    |_| \_|\___|\__|_| \_\___|\___\___/|_| |_|      |
 |                                               v2.7 |
 |====================================================|
    
    Version: 2.7
    Author: voltsparx
    Contact: voltsparx@gmail.com
    Repository: https://github.com/voltsparx/NetRecon
    Warning: WARNING: This tool is for authorized security testing and research only!

=== DESCRIPTION ===
NetRecon is a professional-grade network scanning tool for cybersecurity professionals. 
It combines multiple scanning techniques with service fingerprinting and OS detection 
for comprehensive network reconnaissance.

=== FEATURES ===
• Multi-mode scanning (SYN, TCP Connect, UDP)
• Advanced service detection (Nmap integration)
• OS fingerprinting via TTL analysis
• Async HTTP banner grabbing
• Rich console output (with fallback to basic)
• CIDR notation support for network scanning
• Threaded implementation for performance

=== REQUIREMENTS ===
Core Requirements:
• Python 3.6+
• Root/admin privileges for stealth scanning

Optional Dependencies (for enhanced features):
• scapy (for SYN scans)
• python-nmap (for service detection)
• rich (for colored output)
• aiohttp (for async HTTP checks)

Install all dependencies with:
pip install scapy python-nmap rich aiohttp
            |OR|
pip install -r requirements.txt

=== USAGE ===
Basic syntax:
python netrecon.py <target> [options]

Options:
  -p PORTS     Ports to scan (default: 1-1024)
  -s           Enable stealth scanning (SYN)
  -sV          Enable service detection
  -v           Verbose output

Examples:
1. Basic TCP scan:
   python netrecon.py 192.168.1.1

2. Stealth scan with service detection:
   sudo python netrecon.py 10.0.0.1 -s -sV

3. Full port scan on network range:
   sudo python netrecon.py 192.168.1.0/24 -p 1-65535

=== OUTPUT FORMAT ===
The tool provides:
• Open ports with service identification
• OS detection results
• Hostname resolution
• Scan duration statistics

With rich installed, output is formatted in colored tables.
Without rich, basic text output is provided.

=== WORKFLOW ===
1. Host discovery (ICMP ping)
2. Port scanning (selected method)
3. Service detection (if enabled)
4. OS fingerprinting
5. Results presentation

=== ETHICAL WARNING ===
WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.

• You must have explicit permission to scan any network
• Unauthorized scanning is illegal in many jurisdictions
• The author assumes no liability for misuse of this tool
• Use only on networks you own or have permission to test

By using this software, you agree to:
1. Use it only for lawful purposes
2. Obtain proper authorization before scanning
3. Not use it to harm or compromise systems
4. Accept all responsibility for your actions

=== DISCLAIMER & ETHICAL WARNING ===
This tool is provided "AS IS" without warranty of any kind. 
The author shall not be held responsible for any damages 
resulting from the use of this software. Use at your own risk.
By using this software, you agree to only conduct authorized security testing.

=== VERSION HISTORY ===
v2.7 (Current):
- Added full Scapy/Nmap/Rich integration
- Improved async HTTP checks
- Enhanced output formatting
- Added ethical warnings

v1.0:
- Initial public release