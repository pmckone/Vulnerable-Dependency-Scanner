# Vulnerable Dependency Scanner

Scans project dependencies for known CVEs using the [OSV.dev](https://osv.dev) database. Automatically fails CI/CD builds on HIGH or CRITICAL severity findings to prevent vulnerable packages from reaching production.

---

## Features

- Multi-ecosystem support — Python (`requirements.txt`), Node.js (`package.json`)
- Real CVE data — queries the open OSV.dev vulnerability database, no API key required
- Build gate — exits with code `1` on HIGH/CRITICAL findings, failing CI pipelines
- Structured output — JSON report saved after every scan
- GitHub Actions workflow — runs on every push and pull request, with PR comments on failure
- Zero dependencies — scanner uses Python stdlib only

---

## Project Structure

```
Vulnerable-Dependency-Scanner/
├── Scanner/
│   └── scanner.py                  # Main scanner
├── sample-projects/
│   ├── python-app/
│   │   └── requirements.txt        # Intentionally vulnerable Python deps for testing
│   └── node-app/
│       └── package.json            # Intentionally vulnerable Node deps for testing
├── .github/
│   └── workflows/
│       └── security-scan.yml       # GitHub Actions CI workflow
└── README.md
```

---

## Quick Start

Python 3.8 or higher installed

```bash
# scan the python sample project
python Scanner/scanner.py sample-projects/python-app --verbose

# scan the node sample project
python Scanner/scanner.py sample-projects/node-app --verbose

# scan any directory
python Scanner/scanner.py ./my-app

# save the report to a specific file
python Scanner/scanner.py ./my-app --output results.json

# report only, never fail the build
python Scanner/scanner.py ./my-app --no-fail
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Scan passed — no HIGH/CRITICAL findings |
| `1`  | Scan failed — one or more blocking vulnerabilities found |

---

## How It Works

1. The scanner looks for a supported manifest file in the target directory
2. It parses every dependency name and version from that file
3. For each dependency it sends a request to the OSV.dev API
4. OSV returns any known vulnerabilities for that package and version
5. The scanner extracts the severity and CVE IDs from the response
6. At the end it prints a full report and saves it as JSON
7. If any finding is HIGH or CRITICAL, the process exits with code 1, failing the build

### Severity levels

| Severity | Build gate | What it means |
|----------|------------|---------------|
| CRITICAL | Fail       | Trivial to exploit or catastrophic impact |
| HIGH     | Fail       | Significant risk, exploitable under common conditions |
| MEDIUM   | Pass       | Exploitable but requires specific conditions |
| LOW      | Pass       | Minimal risk or very difficult to exploit |

---

## GitHub Actions Integration

The workflow runs automatically on every push to `main` or `develop`, on all pull requests, and on a daily schedule to catch newly disclosed CVEs.

It runs two separate jobs — one for the Python sample project and one for the Node.js sample project. Each job uploads its JSON report as a downloadable artifact. If a scan fails on a pull request, it posts a comment to the PR listing every blocking vulnerability.

To trigger a scan manually without pushing code:

1. Go to your repo on GitHub
2. Click the Actions tab
3. Click Supply Chain Security Scan on the left
4. Click Run workflow

### Viewing results

After a workflow run completes, click into the run from the Actions tab and expand the "Run security scan" step to see the full terminal output. The JSON report is available at the bottom of the run summary page under Artifacts.

---

## Sample Project Results

Running the scanner against the included sample projects will produce real findings from OSV.dev. The packages were chosen because they have known CVEs and demonstrate what the scanner catches in practice.

The Node.js sample (`sample-projects/node-app`) includes packages like `lodash@4.17.4`, `axios@0.18.0`, and `handlebars@4.0.11` which collectively produce dozens of findings including prototype pollution, remote code execution, and SSRF vulnerabilities.

The Python sample (`sample-projects/python-app`) includes packages like `PyYAML==5.1`, `jinja2==2.10`, and `paramiko==2.4.1` which include critical vulnerabilities for arbitrary code execution and authentication bypass.

These are intentionally outdated. Do not use these versions in a real project.

---

## Configuration

The API endpoint is read from an environment variable so it can be overridden without touching the code:

```bash
# use the default OSV.dev public API (no configuration needed)
python Scanner/scanner.py .

# override the endpoint, for example to point at an internal mirror
OSV_API_URL=https://your-internal-mirror.com/v1/query python Scanner/scanner.py .
```

In GitHub Actions you can set this as a repository secret or variable and reference it in the workflow:

```yaml
env:
  OSV_API_URL: ${{ secrets.OSV_API_URL }}
```

---

## JSON Report Format

The scanner saves a structured JSON report after every run. The default filename is `scan-results.json`.

```json
{
  "scan_time": "2026-05-29T22:57:29",
  "deps_scanned": 10,
  "total_findings": 58,
  "summary": {
    "CRITICAL": 6,
    "HIGH": 27,
    "MEDIUM": 0,
    "LOW": 4
  },
  "findings": [
    {
      "package": "lodash",
      "version": "4.17.4",
      "ecosystem": "npm",
      "vuln_id": "GHSA-jf85-cpcp-92p4",
      "cve_ids": ["CVE-2019-10744"],
      "summary": "Prototype Pollution in lodash",
      "severity": "CRITICAL",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"],
      "fail_build": true
    }
  ]
}
```

## Data Source

All vulnerability data comes from [OSV.dev](https://osv.dev), an open vulnerability database that aggregates from:

- GitHub Advisory Database (GHSA)
- National Vulnerability Database (NVD)
- PyPA Advisory Database
- RustSec Advisory Database
- Go Vulnerability Database
- And many more

No account or API key is required. The API is free and has generous rate limits suitable for CI use.

---

## Supply Chain Attack Context

Supply chain attacks target the dependencies your code relies on rather than your code directly. Because most projects pull in dozens or hundreds of packages, a single compromised or vulnerable dependency can affect the entire application.

Notable real-world examples:

- **event-stream (2018)** — a malicious maintainer injected code into a popular npm package to steal Bitcoin wallets
- **SolarWinds (2020)** — attackers backdoored the build pipeline of a widely used IT monitoring tool, affecting 18,000 organisations
- **Log4Shell (2021)** — a critical remote code execution vulnerability in the Log4j logging library used by millions of Java applications
- **xz-utils (2024)** — a multi-year social engineering effort inserted a backdoor into a core Linux compression utility

This scanner addresses the known vulnerability vector — packages with publicly disclosed CVEs. For a more complete supply chain security posture, also consider:

- Pinning all dependencies to exact versions and committing lockfiles
- Generating a Software Bill of Materials (SBOM) on each release
- Using Sigstore or similar tools for signed releases and provenance verification
- Mirroring dependencies through a private registry to prevent dependency confusion attacks

---

## License

MIT
