# SecAudit Toolkit

A modular, extensible security assessment toolkit for web applications and network infrastructure, written in Python.

> **Legal Notice:** This tool is for authorized security testing only. Only use it against systems you own or have explicit written permission to test. Unauthorized access is illegal under the CFAA, Computer Misuse Act, and similar laws worldwide.

---

## Features

| Module | Description |
|---|---|
| `port_scanner` | Concurrent TCP port scanner with service detection and banner grabbing |
| `header_checker` | HTTP security headers analyzer (HSTS, CSP, X-Frame-Options, etc.) |
| `ssl_checker` | SSL/TLS configuration audit (certificate validity, weak ciphers, deprecated protocols) |
| `tech_fingerprint` | Technology stack identification and sensitive path probing |
| `vuln_scanner` | Active vulnerability tests: XSS, SQLi, Open Redirect, SSTI, CORS |

All findings are rated by severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

Reports are generated as **HTML** (dark theme, styled) or **JSON** for integration with other tools.

---

## Installation

```bash
git clone https://github.com/Valeriop03/SecAudit.git
cd secaudit
pip install -e ".[dev]"
```

Or install dependencies directly:

```bash
pip install -r requirements.txt
pip install -e .
```

**Requirements:** Python 3.10+

---

## Usage

### Full scan

```bash
secaudit scan https://example.com
```

### Select specific modules

```bash
secaudit scan https://example.com --modules headers,ssl,vulns
```

### Port scan with custom ports

```bash
secaudit scan 192.168.1.100 --modules ports --ports 22,80,443,3306,5432,8080
```

### Verbose output + HTML report

```bash
secaudit scan https://example.com --verbose --output report.html
```

### JSON output for pipeline integration

```bash
secaudit scan https://example.com --json-output results.json
```

### List available modules

```bash
secaudit list-modules
```

---

## CLI Reference

```
Usage: secaudit scan [OPTIONS] TARGET_URL

Options:
  -m, --modules TEXT        Comma-separated modules (default: all)
  -o, --output TEXT         HTML report output path
  -j, --json-output TEXT    JSON report output path
  -t, --timeout INTEGER     Request timeout in seconds (default: 10)
  -v, --verbose             Show detailed findings
  -p, --ports TEXT          Custom port list for port scanner
  --workers INTEGER         Port scan thread count (default: 100)
  --version                 Show version and exit
  --help                    Show this message and exit
```

---

## Architecture

```
secaudit-toolkit/
├── secaudit/
│   ├── cli.py               # Click-based CLI entry point
│   ├── core/
│   │   ├── target.py        # URL parsing and target representation
│   │   └── base_module.py   # Abstract base class, Finding, ModuleResult
│   ├── modules/
│   │   ├── port_scanner.py  # Concurrent TCP scanner
│   │   ├── header_checker.py
│   │   ├── ssl_checker.py
│   │   ├── tech_fingerprint.py
│   │   └── vuln_scanner.py
│   ├── report/
│   │   └── generator.py     # HTML + JSON report generation
│   └── utils/
│       └── console.py       # Rich-based terminal output
└── tests/
    ├── test_target.py
    ├── test_header_checker.py
    ├── test_port_scanner.py
    └── test_report_generator.py
```

### Adding a custom module

1. Create a class that inherits from `BaseModule`
2. Set `name` and `description` class attributes
3. Implement the `run(target: Target) -> ModuleResult` method
4. Register it in `cli.py`

```python
from secaudit.core.base_module import BaseModule, Finding, ModuleResult, Severity
from secaudit.core.target import Target

class MyCustomModule(BaseModule):
    name = "my_module"
    description = "Does something useful"

    def run(self, target: Target) -> ModuleResult:
        result = self._result(target)
        # ... your logic here ...
        result.add_finding(Finding(
            title="Something found",
            severity=Severity.HIGH,
            description="Detailed description",
            recommendation="How to fix it",
        ))
        return result
```

---

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=secaudit --cov-report=html
```

---

## Example Output

```
  ____            _                  _ _ _
 / ___|  ___  ___/ \  _   _  __| (_) |_
 \___ \ / _ \/ __/ _ \| | | |/ _` | | __|
  ___) |  __/ (_/ ___ \ |_| | (_| | | |_
 |____/ \___|\___\/ \_/\__,_|\__,_|_|\__|

  Web & Network Security Assessment Toolkit

[*] Target: https://example.com:443  (IP: 93.184.216.34)
[*] Modules: port_scanner, header_checker, ssl_checker
[*] Running port_scanner...

────────────────────────────────────────────────────────────
  PORT SCANNER
────────────────────────────────────────────────────────────
  [+] INFO   Open ports detected (2 found)
  [!] HIGH   Risky service exposed: FTP (port 21)

────────────────────────────────────────────────────────────
  HEADER CHECKER
────────────────────────────────────────────────────────────
  [!] HIGH   Missing security header: Strict-Transport-Security
  [~] MEDIUM Missing security header: Content-Security-Policy

┌─────────────────────────────────────────┐
│              Scan Summary               │
├──────────┬────────────────────────────── │
│ CRITICAL │ 0                             │
│ HIGH     │ 3                             │
│ MEDIUM   │ 2                             │
│ LOW      │ 1                             │
│ INFO     │ 2                             │
└──────────┴──────────────────────────────┘
```

---

## Technologies Used

- **Python 3.10+** — type hints, dataclasses, `ssl` stdlib
- **Requests** — HTTP client
- **Rich** — terminal UI (progress bars, tables, colored output)
- **Click** — CLI framework
- **Concurrent.futures** — parallel port scanning
- **Pytest + responses** — unit testing with HTTP mocking

---

## Roadmap

- [ ] Subdomain enumeration module
- [ ] Directory/file brute-forcer
- [ ] CVE lookup via NVD API
- [ ] Nuclei template integration
- [ ] Async scanning with `asyncio` / `aiohttp`
- [ ] Docker container for isolated scanning

---

## License

MIT License — see [LICENSE](LICENSE) for details.
