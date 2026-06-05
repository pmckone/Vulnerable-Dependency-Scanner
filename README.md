# Vulnerable Dependency Scanner

Scans project dependencies for known CVEs using the [OSV.dev](https://osv.dev) database. Automatically fails CI/CD builds on HIGH or CRITICAL severity findings to prevent vulnerable packages from reaching production.

---

## Features

- Multi-ecosystem support — Python (`requirements.txt`), Node.js (`package.json`), Ruby (`Gemfile.lock`)
- Real CVE data — queries the open OSV.dev vulnerability database, no API key required
- Transitive dependency resolution — scans the full dependency tree, not just direct dependencies
- Concurrent scanning — scans multiple packages in parallel using a thread pool
- Build gate — exits with code `1` on HIGH/CRITICAL findings, failing CI pipelines
- Structured output — JSON report saved after every scan
- GitHub Actions workflow — five jobs covering Python, Node, Ruby, clean app, and full transitive tree
- Modular codebase — split into focused modules for easy extension

---

## Project Structure

```
Vulnerable-Dependency-Scanner/
├── scanner.py                      # CLI entry point
├── requirements.txt                # scanner dependencies (python-dotenv)
├── .env.example                    # template for local environment variables
├── .gitignore
├── README.md
├── Scanner/
│   ├── __init__.py
│   ├── config.py                   # environment variables and constants
│   ├── parsers.py                  # manifest file parsers per ecosystem
│   ├── transitive.py               # full dependency tree resolution
│   ├── osv.py                      # OSV.dev API calls and severity extraction
│   ├── scan.py                     # concurrent scanning logic
│   └── report.py                   # console output, JSON report, build gate
├── sample-projects/
│   ├── python-app/
│   │   └── requirements.txt        # intentionally vulnerable Python deps
│   ├── node-app/
│   │   └── package.json            # intentionally vulnerable Node deps
│   ├── ruby-app/
│   │   └── Gemfile.lock            # intentionally vulnerable Ruby deps
│   └── clean-app/
│       └── requirements.txt        # minimal deps for build pass verification
└── .github/
    └── workflows/
        └── security-scan.yml       # GitHub Actions CI workflow
```

---

## Quick Start

Make sure you have Python 3.8 or higher installed, then run:

```bash
# install scanner dependencies
pip install -r requirements.txt

# scan a project (direct dependencies only)
python scanner.py sample-projects/python-app --verbose

# scan the full dependency tree including transitive dependencies
python scanner.py sample-projects/python-app --transitive --verbose

# scan any directory
python scanner.py ./my-app

# save the report to a specific file
python scanner.py ./my-app --output results.json

# report only, never fail the build
python scanner.py ./my-app --no-fail
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Scan passed — no HIGH/CRITICAL findings |
| `1`  | Scan failed — one or more blocking vulnerabilities found |

---

## Direct vs Transitive Dependencies

Your `requirements.txt` lists the packages you explicitly chose to install. Those are direct dependencies. But each of those packages has its own dependencies, and those have dependencies too. None of those appear in your manifest file but they all get installed silently. Those are transitive dependencies.

Example:

```
requests==2.18.0          <- you listed this (direct)
  └── urllib3             <- requests needs this (transitive)
  └── certifi             <- requests needs this (transitive)
       └── cryptography   <- buried two levels deep (transitive)
```

If `urllib3` has a critical CVE, a scan of direct dependencies only would miss it entirely because it never appears in `requirements.txt`. The `--transitive` flag resolves the full tree and scans every package in it.

This is exactly how Log4Shell worked in 2021. Most affected teams had never heard of Log4j — it was pulled in silently by something else they were using.

```
# without --transitive
Scanned: 19 dependencies

# with --transitive
Scanned: 60+ dependencies
```

---

## How It Works

1. The scanner detects a supported manifest file in the target directory
2. It parses every dependency name and version from that file
3. If `--transitive` is passed, it resolves the full dependency tree using pip or npm
4. All packages are submitted to a thread pool and scanned concurrently against OSV.dev
5. The scanner extracts the severity and CVE IDs from each response
6. A full report is printed to the console and saved as JSON
7. If any finding is HIGH or CRITICAL, the process exits with code 1, failing the build

### Severity levels

| Severity | Build gate | What it means |
|----------|------------|---------------|
| CRITICAL | Fail       | Trivial to exploit or catastrophic impact |
| HIGH     | Fail       | Significant risk, exploitable under common conditions |
| MEDIUM   | Pass       | Exploitable but requires specific conditions |
| LOW      | Pass       | Minimal risk or very difficult to exploit |

---

## Module Breakdown

| File | Responsibility |
|------|---------------|
| `scanner.py` | CLI argument parsing and scan orchestration |
| `Scanner/config.py` | Reads environment variables, defines constants |
| `Scanner/parsers.py` | Parses requirements.txt, package.json, Gemfile.lock |
| `Scanner/transitive.py` | Resolves full dependency tree via pip and npm |
| `Scanner/osv.py` | Sends queries to OSV.dev, extracts severity |
| `Scanner/scan.py` | Runs concurrent scans using ThreadPoolExecutor |
| `Scanner/report.py` | Prints console report, writes JSON, runs build gate |

---

## Configuration

The scanner reads configuration from environment variables. For local development, create a `.env` file by copying `.env.example`:

```bash
cp .env.example .env
```

Available variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PUBLICAPI` | `https://api.osv.dev/v1/query` | OSV API endpoint |
| `MAX_WORKERS` | `10` | Number of parallel scan threads |

In GitHub Actions, set these as repository secrets or variables and reference them in the workflow:

```yaml
env:
  PUBLICAPI: ${{ secrets.PUBLICAPI }}
```

The `.env` file is gitignored and should never be committed.

---

## GitHub Actions

The workflow runs five jobs automatically on every push to `main` or `develop`, on all pull requests, and daily at 06:00 UTC to catch newly disclosed CVEs.

| Job | What it scans | Expected result |
|-----|--------------|-----------------|
| `python-scan` | `sample-projects/python-app` | Fail — many known CVEs |
| `node-scan` | `sample-projects/node-app` | Fail — many known CVEs |
| `ruby-scan` | `sample-projects/ruby-app` | Fail — known vulnerable gems |
| `clean-scan` | `sample-projects/clean-app` | Pass — minimal safe packages |
| `transitive-scan` | Python and Node full tree | Shows transitive findings |

Each job uploads its JSON report as a downloadable artifact retained for 90 days. If a scan fails on a pull request, it posts a comment to the PR listing every blocking vulnerability.

To trigger a scan manually without pushing code:

1. Go to your repo on GitHub
2. Click the Actions tab
3. Click Supply Chain Security Scan on the left
4. Click Run workflow

---

## Sample Results

Running the scanner against the included sample projects produces real findings from OSV.dev. From a recent scan of `sample-projects/python-app`:

```
Scanned:     19 dependencies
Findings:    172 total vulnerabilities

CRITICAL     10
HIGH         44
LOW          8
UNKNOWN      67

BUILD FAILED - 54 HIGH/CRITICAL vulnerability(ies) found.
```

Notable findings include prototype pollution in lodash, remote code execution in handlebars, sandbox escape in vm2, authentication bypass in paramiko, and SQL injection in Django.

The packages are intentionally outdated. Do not use these versions in a real project.

---

## Adding More Ecosystems

To add support for a new package manager, add a parser function to `Scanner/parsers.py` and register it in `detect_and_parse()`.

Example — adding Go module support:

```python
def parse_go_sum(filepath):
    deps = []
    with open(filepath) as f:
        for line in f:
            match = re.match(r"^([^\s]+)\s+v([\d\.]+)", line)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(2),
                    "ecosystem": "Go",
                    "raw": line.strip(),
                    "transitive": False
                })
    return deps
```

Then add it to the checks list in `detect_and_parse()`:

```python
(project_path / "go.sum", parse_go_sum, "go.sum", "go"),
```

OSV supports these ecosystems: `PyPI`, `npm`, `RubyGems`, `Go`, `Maven`, `NuGet`, `crates.io`, `Hex`, `Packagist`

---

## JSON Report Format

```json
{
  "scan_time": "2026-06-05T15:33:22",
  "deps_scanned": 19,
  "transitive_mode": false,
  "total_findings": 172,
  "direct_findings": 172,
  "transitive_findings": 0,
  "workers_used": 10,
  "summary": {
    "CRITICAL": 10,
    "HIGH": 44,
    "MEDIUM": 0,
    "LOW": 8,
    "UNKNOWN": 67
  },
  "findings": [
    {
      "package": "PyYAML",
      "version": "5.1",
      "ecosystem": "PyPI",
      "transitive": false,
      "vuln_id": "GHSA-6757-jp84-gxfx",
      "cve_ids": ["CVE-2020-14343"],
      "summary": "Improper Input Validation in PyYAML",
      "severity": "CRITICAL",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"],
      "fail_build": true
    }
  ]
}
```

---

## Data Source

All vulnerability data comes from [OSV.dev](https://osv.dev), an open vulnerability database aggregating from:

- GitHub Advisory Database (GHSA)
- National Vulnerability Database (NVD)
- PyPA Advisory Database
- RustSec Advisory Database
- Go Vulnerability Database

No account or API key is required.

---

## Supply Chain Attack Context

Supply chain attacks target the dependencies your code relies on rather than your code directly. Because most projects pull in dozens or hundreds of packages, a single compromised or vulnerable dependency can affect the entire application.

Notable real-world examples:

- **event-stream (2018)** — a malicious maintainer injected code into a popular npm package to steal Bitcoin wallets
- **SolarWinds (2020)** — attackers backdoored the build pipeline of a widely used IT monitoring tool, affecting 18,000 organisations
- **Log4Shell (2021)** — a critical remote code execution vulnerability in the Log4j logging library used by millions of Java applications, mostly pulled in as a transitive dependency
- **xz-utils (2024)** — a multi-year social engineering effort inserted a backdoor into a core Linux compression utility

This scanner addresses the known vulnerability vector. For a more complete supply chain security posture, also consider:

- Pinning all dependencies to exact versions and committing lockfiles
- Generating a Software Bill of Materials (SBOM) on each release
- Using Sigstore for signed releases and provenance verification
- Mirroring dependencies through a private registry
