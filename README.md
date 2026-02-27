# NetRecon v4.9

**NetRecon** is a modular reconnaissance framework for authorized security testing, combining guided learning workflows with high-speed automated scanning.

It supports interactive usage for learners and fast flag-based execution for automation and repeatable security assessments.

**Author**: voltsparx<br>
**Contact**: voltsparx@gmail.com

---

## ⚖️ Legal Disclaimer

Use this tool only on systems you own or have explicit written permission to assess.  
Unauthorized scanning may violate law and policy. You are responsible for compliant use.

---

## 🛡️ Ethical Use Warning

- NetRecon is for defensive security testing and learning in authorized environments only.
- Do not scan public or private infrastructure without explicit approval.
- Do not use findings for exploitation, disruption, or unauthorized access.
- Always operate within legal scope, written rules of engagement, and local law.

---

## ✨ Highlights

- Interactive mode with guided prompts and metadata banner  
- Argparse mode with compact, industry-familiar scan output  
- Single host, CIDR, and multi-target scanning  
- Hybrid engine stack (threading + parallel + async) for faster execution  
- Timing templates (`-T0` to `-T5`) with adaptive RTT timeout tuning  
- Host grouping scheduler for large target sets  
- Target/port exclusion controls  
- Optional host timeout guardrails for unstable targets  
- Periodic progress ticker for long scans  
- Service probe engine with intensity levels and fallback logic  
- TCP connect scanning with retry, timeout, and jitter controls  
- Optional SYN scan mode (Scapy + elevated privileges)  
- Service fingerprinting and OS inference  
- Plugin-based intelligence and misconfiguration checks  
- CVE hint correlation  
- Report export: CLI, JSON, HTML  

---

## 🧭 Who Is NetRecon For?

- 🎓 Security students learning reconnaissance workflows  
- 🛡️ Blue teams performing internal audits  
- 🧪 Researchers building scanning pipelines  
- 🧑‍🏫 Educators running lab environments  

---

## 📦 Installation

### Requirements

- Python 3.8+
- `scapy` (required for SYN scanning)

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Launch Modes

### Interactive Prompt Mode

```bash
python netrecon.py
```

**Behavior**

- Clears terminal (Windows + Unix)
- Displays banner, version, author, and contact
- Prompts for profile, plugins, and report export

---

### Argparse Fast Mode

```bash
python netrecon.py <target> [options]
```

**Behavior**

- Does not clear terminal
- Displays compact scan header and tabular output
- Ideal for scripts and automation

---

## 🧪 Core Commands

```bash
python netrecon.py --help
python netrecon.py --about
python netrecon.py --launch-modes
python netrecon.py --list-profiles
```

---

## 🔍 Scan Examples

### Quick scan

```bash
python netrecon.py 192.168.1.10 -p quick
```

### Aggressive scan with plugins and reports

```bash
python netrecon.py 10.0.0.0/24 -p aggressive --plugins --json --html
```

### Web-focused analysis

```bash
python netrecon.py example.com -p web --plugins --html
```

### Stealth / SYN scan

```bash
python netrecon.py 192.168.1.10 -p stealth --syn -s
```

### Privileged root scan

```bash
python netrecon.py 10.0.0.0/24 -p root --sudo --json --html
```

---

## ⚡ Usage Cheat Sheet

### Basic host scan

```bash
python netrecon.py 192.168.1.10 -p quick
```

### CIDR range scan

```bash
python netrecon.py 192.168.1.0/24 -p aggressive --plugins
```

### Custom ports

```bash
python netrecon.py example.com --ports 22,80,443,8443 --plugins
```

### Full export set

```bash
python netrecon.py 10.10.10.0/24 -p vuln --plugins --json --html
```

### Scoped/excluded scan

```bash
python netrecon.py 10.0.0.0/24 -p aggressive --exclude 10.0.0.1,10.0.0.2 --exclude-ports 23,445
```

### Named output

```bash
python netrecon.py 192.168.1.10 -p quick --json --html --save-prefix office_audit
```

---

## 🧰 CLI Options

| Option | Description |
|--------|-------------|
| `target` | IP, hostname, CIDR, or comma-separated hosts |
| `-p, --profile` | quick · stealth · aggressive · web · vuln · root |
| `-o, --ports` | Port expression (`22,80,443` or `1-1024`) |
| `-t, --threads` | Scanner thread count |
| `-w, --host-workers` | Concurrent host workers |
| `-g, --host-group-size` | Hosts per execution group |
| `-k, --plugin-workers` | Plugin worker threads per host |
| `-a, --async-limit` | Async enrichment concurrency |
| `-T, --timing-template` | Timing template (`0–5`) |
| `-i, --service-intensity` | Probe intensity (`0–9`) |
| `-z, --host-timeout` | Host timeout (seconds) |
| `-A, --stats-every` | Progress interval |
| `-O, --timeout` | Socket timeout |
| `-m, --min-rtt-timeout` | Minimum RTT timeout |
| `-M, --max-rtt-timeout` | Maximum RTT timeout |
| `-r, --retries` | Retries per probe |
| `-R, --rate-limit` | Delay between probes |
| `-q, --exclude-ports` | Exclude ports |
| `-E, --exclude` | Exclude targets |
| `-e, --exclude-file` | Exclude targets from file |
| `-P, --plugins` | Enable plugins |
| `-j, --json` | Save JSON report |
| `-H, --html` | Save HTML report |
| `-f, --save-prefix` | Custom report prefix |
| `-n, --no-discovery` | Skip ping discovery |
| `-y, --syn` | Force SYN mode |
| `-x, --root-scan` | Require privileged scan |
| `-u, --sudo` | Relaunch with sudo |
| `-s, --stealth` | Enable stealth timing |
| `-V, --services` | Service fingerprinting |
| `-b, --about` | Show banner |
| `-L, --launch-modes` | Mode guide |
| `-l, --list-profiles` | List profiles |
| `-h, --help` | Show help |

---

## 🧪 Profiles

| Profile | Purpose |
|--------|---------|
| `quick` | Fast top-ports visibility |
| `stealth` | Lower-noise randomized scan |
| `aggressive` | Deep recon with plugins and CVE hints |
| `web` | HTTP/TLS-focused analysis |
| `vuln` | Vulnerability-oriented recon |
| `root` | Privileged raw scan requiring admin |

**Root Profile Notes**

- Linux/macOS: use `--sudo`
- Windows: run terminal as Administrator

---

## 🔌 Plugin Set (v4.9)

- `banner_grabber` — banners, TLS metadata, outdated version hints  
- `default_creds` — default credential exposure risks  
- `dir_listing` — directory listing detection  
- `dns_enum` — DNS enrichment & classification  
- `open_proxy` — proxy exposure checks  
- `ssl_info` — certificate expiry & cipher warnings  
- `vuln_headers` — missing security headers  
- `weak_ssh` — legacy SSH detection  
- `whois_lookup` — registrar & ownership enrichment  

---

## 📂 Output

Reports are saved in:

- `output/cli/`
- `output/json/`
- `output/html/`

Each report includes:

- target metadata  
- open ports/services  
- risk classification  
- plugin findings  
- CVE hints  
- timing metrics  

Use `--save-prefix <name>` for deterministic filenames.

---

## 🏗️ Architecture Overview

```
Targets → Scheduler → Scan Engine → Fingerprinting → Plugins → Risk Engine → Reports
```

---

## ✅ Release Validation (v4.9)

```bash
python -B -c "import netrecon; print('import_ok')"
python -B netrecon.py --help
python -B netrecon.py --about
python -B netrecon.py --list-profiles
python -B netrecon.py 127.0.0.1 -p quick -o 80,443 -q 443 -n -A 0.5 -z 2
python -B netrecon.py 127.0.0.1 -p quick --ports 80,443,445 --plugins --json --html
```

---

## 🔒 Security

See `SECURITY.md` for responsible disclosure policy.

---

## 🤝 Code of Conduct

See `CODE_OF_CONDUCT.md`.

---

## 📜 License

MIT License. See `LICENSE`.
