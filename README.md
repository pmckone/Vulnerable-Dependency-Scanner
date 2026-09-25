# Vulnerable Dependency Scanner

Scans project dependencies for known CVEs using the [OSV.dev](https://osv.dev) database, and fails CI/CD builds on HIGH or CRITICAL findings.

Optionally sends results to **Splunk** for dashboards/alerting, and enriches findings with **CrowdStrike Falcon Spotlight** to see which vulnerable dependencies are also live on managed hosts.

---

## Features

- Multi-ecosystem: Python (`requirements.txt`), Node.js (`package.json`), Ruby (`Gemfile.lock`)
- Real CVE data from OSV.dev, no API key needed
- Optional transitive dependency scanning (the full tree, not just what you listed)
- Concurrent scanning, JSON report output
- Build gate: exits `1` on HIGH/CRITICAL findings
- Optional Splunk + CrowdStrike integrations
- GitHub Actions workflow included

---

## Quick Start

```
pip install -r requirements.txt

python scanner.py sample-projects/python-app --verbose        # direct deps only
python scanner.py sample-projects/python-app --transitive     # full dependency tree
python scanner.py ./my-app --output results.json              # custom output path
python scanner.py ./my-app --no-fail                          # report only, don't fail build
```

Exit code `0` = no HIGH/CRITICAL findings. Exit code `1` = build should fail.

---

## Why Transitive Matters

Your `requirements.txt` lists what you chose to install. Each of those packages pulls in its own dependencies, invisibly. A scan of direct dependencies alone can miss a critical CVE two or three layers deep — which is exactly how Log4Shell caught people off guard in 2021. `--transitive` resolves the full tree so nothing hides.

---

## Project Structure

```
scanner.py                    # scan + build gate
publish.py                    # optional: send results to Splunk / CrowdStrike
Scanner/
├── parsers.py                # reads manifest files per ecosystem
├── transitive.py             # resolves full dependency tree
├── osv.py                    # queries OSV.dev
├── scan.py                   # runs scans concurrently
├── report.py                 # console + JSON output, build gate
└── integrations/
    ├── splunk.py              # ships events to Splunk HEC
    └── crowdstrike.py         # Falcon Spotlight enrichment
tests/                        # unit tests (fake Splunk + Falcon, no live creds needed)
lab/docker-compose.splunk.yml # throwaway local Splunk for testing
sample-projects/              # intentionally vulnerable test apps
.github/workflows/            # CI pipeline
```

---

## Configuration

Copy `.env.example` to `.env` and fill in what you need:

| Variable | Required for | Notes |
| --- | --- | --- |
| `PUBLICAPI` | scanner | defaults to `https://api.osv.dev/v1/query` |
| `MAX_WORKERS` | scanner | defaults to `10` |
| `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN` | Splunk | see below |
| `SPLUNK_INDEX`, `SPLUNK_CA_BUNDLE`, `SPLUNK_VERIFY_TLS` | Splunk | optional |
| `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET` | CrowdStrike | needs the Vulnerabilities/Spotlight read scope |
| `FALCON_BASE_URL` | CrowdStrike | only if not on the default US-1 cloud |

`.env` is gitignored — never commit real credentials. In CI, use repository secrets instead.

---

## Splunk & CrowdStrike Integrations

`scanner.py` writes a JSON report. `publish.py` reads it and optionally ships it to Splunk and/or enriches it with CrowdStrike data. This is a separate step on purpose — an integration outage can never affect whether a build passes.

```
pip install -r requirements-integrations.txt   # only needed for --crowdstrike

python scanner.py ./my-app --no-fail
python publish.py scan-results.json --splunk --crowdstrike
```

### Splunk

Fastest way to try it locally:

```
# in .env: SPLUNK_PASSWORD, SPLUNK_HEC_TOKEN, SPLUNK_HEC_URL=https://localhost:8088, SPLUNK_VERIFY_TLS=false
docker compose --env-file .env -f lab/docker-compose.splunk.yml up -d
```

Wait a few minutes for it to report healthy, then run `publish.py --splunk` and search `index=main sourcetype="vuln_scanner:*"` at http://localhost:8000.

Against a real Splunk instance: create a HEC token (Settings → Data inputs → HTTP Event Collector), set `SPLUNK_HEC_URL`/`SPLUNK_HEC_TOKEN`, and use `SPLUNK_CA_BUNDLE` to trust a self-signed cert instead of disabling TLS checks.

Each scan sends one summary event and one event per finding, tagged `vuln_scanner:summary` / `vuln_scanner:finding`.

### CrowdStrike

Needs a Falcon tenant with Spotlight and hosts reporting in, plus an API client with the **Vulnerabilities: Read** scope. Set `FALCON_CLIENT_ID`/`FALCON_CLIENT_SECRET`, then run `publish.py --crowdstrike`.

Findings gain a `falcon_affected_hosts` field — how many managed hosts have that CVE open. Expect a lot of zeros: Spotlight tracks OS/installed software, so it matches best with things like Log4j or OpenSSL, less often with a bare Python or npm library.

Only host **counts** are kept — never hostnames or sensor IDs — so it's safe to appear in public CI logs.

### In GitHub Actions

Add the `publish-findings` job (see `workflow/publish-findings.yml`) to `security-scan.yml`, then add these as repo secrets:
- Splunk: `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`
- CrowdStrike: `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`

The job only runs an integration if its secrets are set, and skips on pull requests. Note: GitHub-hosted runners can't reach a Splunk instance on a private network — use a self-hosted runner or a tunnel for that case.

---

## Testing

```
python -m unittest discover -s tests -t .
```

Splunk tests run against a local fake HEC server; CrowdStrike tests run against a fake Falcon client. No live credentials needed to test the code — but that also means these tests don't prove your actual Splunk/Falcon setup works. Verify that with the steps above.

---

## GitHub Actions

Runs on push to `main`/`develop`, on PRs, and daily at 06:00 UTC.

| Job | Scans | Expected result |
| --- | --- | --- |
| `python-scan` | `sample-projects/python-app` | Fail (known CVEs) |
| `node-scan` | `sample-projects/node-app` | Fail (known CVEs) |
| `ruby-scan` | `sample-projects/ruby-app` | Fail (known CVEs) |
| `clean-scan` | `sample-projects/clean-app` | Pass |
| `transitive-scan` | Python + Node full tree | Shows transitive findings |
| `publish-findings` | all reports above | Sends to Splunk/CrowdStrike if configured |

Each job uploads its JSON report as an artifact; failed scans on a PR get a comment with the findings.

---
