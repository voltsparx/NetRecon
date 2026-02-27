# NetRecon v4.9

NetRecon is a modular reconnaissance framework for authorized security testing.  
It supports guided interactive usage for learners and fast flag-based execution for automation.

## Legal Disclaimer

Use this tool only on systems you own or have explicit written permission to assess.  
Unauthorized scanning may violate law and policy. You are responsible for compliant use.

## Ethical Warning

- NetRecon is for defensive security testing and learning in authorized environments only.
- Do not scan public or private infrastructure without explicit approval.
- Do not use findings for exploitation, disruption, or unauthorized access.
- Always operate within legal scope, written rules of engagement, and local law.

## Highlights

- Interactive mode with guided prompts and metadata banner
- Argparse mode with compact nmap-style scan output
- Single host, CIDR, and multi-target scanning
- Hybrid engine stack (threading + parallel + async) for faster multi-host execution
- Nmap-inspired timing templates (`-T0` to `-T5`) with adaptive RTT timeout tuning
- Host grouping scheduler for large target sets
- Target/port exclusion controls (`--exclude`, `--exclude-file`, `--exclude-ports`)
- Optional host timeout guardrails (`--host-timeout`) for slow or unstable targets
- Periodic progress ticker (`--stats-every`) for long scans
- Service probe engine with intensity levels and probe fallback logic
- Threaded TCP scanning with retry, timeout, and jitter controls
- Optional SYN scan mode (Scapy + elevated privileges)
- Service fingerprinting and OS inference
- Plugin-based intelligence and misconfiguration checks
- CVE hint correlation
- Report export: CLI, JSON, HTML

## Installation

Requirements:

- Python 3.8+
- `scapy` (for SYN scanning features)

Install:

```bash
pip install -r requirements.txt
```

## Launch Modes

### Interactive Prompt Mode

```bash
python netrecon.py
```

Behavior:

- Clears terminal first (Windows + Unix)
- Shows full banner, version, author, and contact
- Prompts for profile, plugin usage, and report export

### Argparse Fast Mode

```bash
python netrecon.py <target> [options]
```

Behavior:

- Does not clear terminal
- Shows compact scan header and professional tabular output
- Ideal for scripts and repeatable workflows

## Core Commands

```bash
python netrecon.py --help
python netrecon.py --about
python netrecon.py --launch-modes
python netrecon.py --list-profiles
```

## Scan Examples

Quick:

```bash
python netrecon.py 192.168.1.10 -p quick
```

Aggressive with plugins + JSON/HTML:

```bash
python netrecon.py 10.0.0.0/24 -p aggressive --plugins --json --html
```

Web-focused:

```bash
python netrecon.py example.com -p web --plugins --html
```

Stealth/SYN:

```bash
python netrecon.py 192.168.1.10 -p stealth --syn -s
```

Privileged root scan (will request sudo password on Unix with `--sudo`):

```bash
python netrecon.py 10.0.0.0/24 -p root --sudo --json --html
```

## Usage Cheat Sheet

Basic host scan:

```bash
python netrecon.py 192.168.1.10 -p quick
```

CIDR range scan:

```bash
python netrecon.py 192.168.1.0/24 -p aggressive --plugins
```

Custom ports:

```bash
python netrecon.py example.com --ports 22,80,443,8443 --plugins
```

Full export set:

```bash
python netrecon.py 10.10.10.0/24 -p vuln --plugins --json --html
```

Scoped/excluded scan:

```bash
python netrecon.py 10.0.0.0/24 -p aggressive --exclude 10.0.0.1,10.0.0.2 --exclude-ports 23,445
```

Named output set:

```bash
python netrecon.py 192.168.1.10 -p quick --json --html --save-prefix office_audit
```

## CLI Options

- `target`: IP, hostname, CIDR, or comma-separated hosts
- `-p, --profile`: `quick | stealth | aggressive | web | vuln | root`
- `-o, --ports`: port expression (`22,80,443` or `1-1024`)
- `-t, --threads`: scanner thread count
- `-w, --host-workers`: concurrent host workers
- `-g, --host-group-size`: hosts per parallel execution group
- `-k, --plugin-workers`: plugin worker threads per host
- `-a, --async-limit`: async enrichment concurrency limit
- `-T, --timing-template`: timing template (`0-5`)
- `-i, --service-intensity`: service probe intensity (`0-9`)
- `-z, --host-timeout`: give up on a host after N seconds
- `-A, --stats-every`: print periodic progress every N seconds
- `-O, --timeout`: socket timeout in seconds
- `-m, --min-rtt-timeout`: minimum adaptive RTT timeout
- `-M, --max-rtt-timeout`: maximum adaptive RTT timeout
- `-r, --retries`: retries per probe
- `-R, --rate-limit`: delay between probes
- `-q, --exclude-ports`: exclude ports from the selected port set
- `-E, --exclude`: exclude targets/networks
- `-e, --exclude-file`: exclude targets/networks listed in file
- `-P, --plugins`: enable plugins
- `-j, --json`: save JSON report
- `-H, --html`: save HTML report
- `-f, --save-prefix`: custom prefix for saved report files
- `-n, --no-discovery`: skip ping discovery
- `-y, --syn`: force SYN mode
- `-x, --root-scan`: enforce privileged root/admin scan mode
- `-u, --sudo`: auto relaunch with sudo for root scan
- `-s, --stealth`: enable stealth timing strategy
- `-sV, -V, --services`: enable service fingerprinting
- `-b, --about`: show banner + metadata
- `-L, --launch-modes`: show mode guide
- `-l, --list-profiles`: list profiles
- `-h, --help`: show help

## Profiles

| Profile | Purpose |
|---|---|
| `quick` | Fast top-ports visibility |
| `stealth` | Lower-noise randomized scan |
| `aggressive` | Deep recon with plugins and CVE hints |
| `web` | HTTP/TLS-focused analysis |
| `vuln` | Vulnerability-oriented recon profile |
| `root` | Privileged raw scan requiring root/admin |

`root` profile notes:
- On Linux/macOS, use `--sudo` to trigger a sudo password prompt and relaunch.
- On Windows, run the terminal as Administrator.

## Plugin Set (v4.9)

- `banner_grabber`: captures banners + TLS metadata + outdated version hints
- `default_creds`: default credential risk mapping with port fallbacks
- `dir_listing`: directory listing detection across HTTP/HTTPS
- `dns_enum`: forward/reverse DNS enrichment with IP classification
- `open_proxy`: multi-method proxy exposure checks
- `ssl_info`: certificate expiry, TLS version, weak cipher warnings
- `vuln_headers`: missing security headers, HSTS checks, disclosure hints
- `weak_ssh`: legacy SSH protocol/version checks
- `whois_lookup`: WHOIS key field extraction and enrichment

## Plugin Usage and Examples

Plugins are executed together when `--plugins` is enabled.  
To focus on a specific plugin signal, scan relevant ports/services.

### `banner_grabber`

Purpose:

- Capture banners and TLS metadata for service fingerprint clues.

Example:

```bash
python netrecon.py target.local --ports 21,22,80,443,8443 --plugins
```

### `default_creds`

Purpose:

- Flag services commonly exposed with default credentials.

Example:

```bash
python netrecon.py 192.168.1.50 --ports 21,23,3306,5432,6379 --plugins
```

### `dir_listing`

Purpose:

- Detect directory listing exposure on HTTP/HTTPS roots.

Example:

```bash
python netrecon.py web.internal --ports 80,443,8080,8443 --plugins
```

### `dns_enum`

Purpose:

- Resolve host/IP metadata, aliases, PTR, and IP classification.

Example:

```bash
python netrecon.py example.com -p quick --plugins
```

### `open_proxy`

Purpose:

- Check whether proxy-like ports accept unsafe relay behavior.

Example:

```bash
python netrecon.py proxy.host --ports 3128,8080,8081,8888 --plugins
```

### `ssl_info`

Purpose:

- Inspect TLS cert expiry, protocol version, and weak ciphers.

Example:

```bash
python netrecon.py secure.host --ports 443,465,993,995,8443 --plugins
```

### `vuln_headers`

Purpose:

- Check security headers and web disclosure issues.

Example:

```bash
python netrecon.py app.host --ports 80,443,8080,8443 --plugins
```

### `weak_ssh`

Purpose:

- Detect weak/legacy SSH protocol or server version hints.

Example:

```bash
python netrecon.py 10.0.0.10 --ports 22 --plugins
```

### `whois_lookup`

Purpose:

- Enrich targets with registrar/expiry/ownership clues where available.

Example:

```bash
python netrecon.py example.org -p quick --plugins
```

## Output

Reports are saved in:

- `output/cli/`
- `output/json/`
- `output/html/`

Each report includes target metadata, open ports/services, risk classification, plugin findings, CVE hints, and timing.
Use `--save-prefix <name>` to generate deterministic, labeled report filenames.

## Architecture

1. Parse mode/input and apply exclusion filters
2. Expand/dedupe targets
3. Optional host discovery
4. Orchestrate host execution with host-group scheduling and hybrid engines
5. Scan ports (connect/SYN) with adaptive timing template controls and optional host timeout cutoff
6. Service/OS inference with probe intensity and fallback logic
7. Run plugins and CVE correlation in parallel
8. Classify risk + render reports
9. Persist outputs

## Release Validation (v4.9)

Smoke checks run during this release:

```bash
python -B -c "import netrecon; print('import_ok')"
python -B netrecon.py --help
python -B netrecon.py --about
python -B netrecon.py --list-profiles
python -B netrecon.py 127.0.0.1 -p quick -o 80,443 -q 443 -n -A 0.5 -z 2
python -B netrecon.py 127.0.0.1 -p quick --ports 80,443,445 --plugins --json --html
```

## Security

See `SECURITY.md` for responsible disclosure and support policy.

## Conduct

See `CODE_OF_CONDUCT.md`.

## License

MIT. See `LICENSE`.
