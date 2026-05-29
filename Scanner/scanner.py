import json
import sys
import os
import argparse
import urllib.request
import urllib.error
import re
from pathlib import Path
from datetime import datetime


#PUBLIC API KEY
OSV_API_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev/v1/query")

SEVERITY_SCORES = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

FAIL_ON_SEVERITY = ["CRITICAL", "HIGH"] 

def parse_requirements_txt(filepath):
    deps = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]+)\s*([\d\.]+)", line)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(3),
                    "ecosystem": "PyPI",
                    "raw": line
                })
            else:
                name = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if name:
                    deps.append({
                        "name": name.group(1),
                        "version": None,
                        "ecosystem": "PyPI",
                        "raw": line
                    })
    return deps


def parse_package_json(filepath):
    deps = []
    with open(filepath) as f:
        data = json.load(f)

    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for name, version_str in all_deps.items():
        clean_version = re.sub(r"^[\^~>=<*]+", "", version_str).strip()
        deps.append({
            "name": name,
            "version": clean_version if clean_version else None,
            "ecosystem": "npm",
            "raw": f"{name}@{version_str}"
        })
    return deps


def parse_gemfile_lock(filepath):
    deps = []
    in_gems = False
    with open(filepath) as f:
        for line in f:
            line = line.rstrip()
            if line == "GEM":
                in_gems = True
                continue
            if in_gems and line == "":
                in_gems = False
                continue
            if in_gems:
                match = re.match(r"^\s{4}([A-Za-z0-9_\-\.]+)\s+\(([\d\.]+)\)", line)
                if match:
                    deps.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "ecosystem": "RubyGems",
                        "raw": line.strip()
                    })
    return deps

def detect_and_parse(project_path):
    project_path = Path(project_path)
    found = []

    checks = [
        (project_path / "requirements.txt", parse_requirements_txt, "requirements.txt"),
        (project_path / "package.json", parse_package_json, "package.json"),
        (project_path / "Gemfile.lock", parse_gemfile_lock, "Gemfile.lock"),
    ]

    for path, parser, label in checks:
        if path.exists():
            print(f"  found {label}")
            deps = parser(path)
            print(f"  {len(deps)} dependencies parsed")
            found.extend(deps)

    return found

def query_osv(package_name, version, ecosystem):
    """Query OSV.dev for known vulnerabilities."""
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    if version:
        payload["version"] = version

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_API_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("vulns", [])
    except urllib.error.URLError as e:
        print(f"  warning: could not reach OSV for {package_name} ({e})")
        return []
    except Exception as e:
        print(f"  warning: unexpected error querying {package_name} ({e})")
        return []


def extract_severity(vuln):
    severity = "UNKNOWN"
    score = None

    for sev in vuln.get("severity", []):
        sev_type = sev.get("type", "")
        sev_score = sev.get("score", "")
        if sev_type in ("CVSS_V3", "CVSS_V2"):
            score = sev_score

    for affected in vuln.get("affected", []):
        db_spec = affected.get("database_specific", {})
        if "severity" in db_spec:
            severity = db_spec["severity"].upper()
            break

    db_spec = vuln.get("database_specific", {})
    if "severity" in db_spec:
        severity = db_spec["severity"].upper()

    return severity, score

def scan_dependencies(deps, verbose=False):
    """Query OSV for each dependency and collect findings."""
    findings = []
    total = len(deps)

    for i, dep in enumerate(deps, 1):
        name = dep["name"]
        version = dep.get("version")
        ecosystem = dep.get("ecosystem", "PyPI")

        if verbose:
            print(f"  [{i}/{total}] checking {name}@{version or 'unknown'} ({ecosystem})")

        vulns = query_osv(name, version, ecosystem)

        for vuln in vulns:
            severity, cvss = extract_severity(vuln)
            aliases = vuln.get("aliases", [])
            cve_ids = [a for a in aliases if a.startswith("CVE-")]

            findings.append({
                "package": name,
                "version": version or "unspecified",
                "ecosystem": ecosystem,
                "vuln_id": vuln.get("id", "UNKNOWN"),
                "cve_ids": cve_ids,
                "summary": vuln.get("summary", "No summary available"),
                "severity": severity,
                "cvss": cvss,
                "published": vuln.get("published", ""),
                "modified": vuln.get("modified", ""),
                "references": [r.get("url") for r in vuln.get("references", [])[:3]],
                "fail_build": severity in FAIL_ON_SEVERITY,
            })

    return findings

def severity_label(severity):
    labels = {
        "CRITICAL": "[CRITICAL]",
        "HIGH":     "[HIGH]    ",
        "MEDIUM":   "[MEDIUM]  ",
        "LOW":      "[LOW]     ",
        "UNKNOWN":  "[UNKNOWN] ",
    }
    return labels.get(severity, "[UNKNOWN] ")


def print_report(findings, deps_count):
    print()
    print("=" * 60)
    print("  SUPPLY CHAIN SECURITY SCAN REPORT")
    print("=" * 60)
    print(f"  Scanned:  {deps_count} dependencies")
    print(f"  Findings: {len(findings)} vulnerabilities")
    print(f"  Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if not findings:
        print()
        print("  No known vulnerabilities found.")
        print()
        return

    by_severity = {}
    for f in findings:
        s = f["severity"]
        by_severity.setdefault(s, []).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        group = by_severity.get(sev, [])
        if not group:
            continue
        print()
        print(f"  {sev} ({len(group)})")
        print("  " + "-" * 55)
        for f in group:
            cves = ", ".join(f["cve_ids"]) if f["cve_ids"] else f["vuln_id"]
            print(f"  {f['package']}@{f['version']}")
            print(f"    id:      {cves}")
            print(f"    summary: {f['summary'][:80]}")
            if f["references"]:
                print(f"    ref:     {f['references'][0]}")
            print()

    counts = {s: len(v) for s, v in by_severity.items()}
    print("  SUMMARY")
    print("  " + "-" * 55)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        c = counts.get(sev, 0)
        if c:
            print(f"  {sev:<10}  {c}")

def save_json_report(findings, deps_count, output_path):
    """Save structured JSON report."""
    report = {
        "scan_time": datetime.now().isoformat(),
        "deps_scanned": deps_count,
        "total_findings": len(findings),
        "findings": findings,
        "summary": {
            s: len([f for f in findings if f["severity"] == s])
            for s in SEVERITY_SCORES
        }
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  report saved to {output_path}")
    return report

def evaluate_build_gate(findings):
    """Return exit code: 0 = pass, 1 = fail."""
    blocking = [f for f in findings if f["fail_build"]]
    if blocking:
        print()
        print(f"  BUILD FAILED - {len(blocking)} HIGH/CRITICAL vulnerability(ies) found.")
        print("  Fix or suppress these before merging:")
        print()
        for f in blocking:
            cves = ", ".join(f["cve_ids"]) if f["cve_ids"] else f["vuln_id"]
            print(f"    {f['package']}@{f['version']}  {cves}  [{f['severity']}]")
        print()
        return 1
    else:
        print()
        print("  BUILD PASSED - no blocking vulnerabilities found.")
        print()
        return 0

def main():
    parser = argparse.ArgumentParser(
        description="Supply Chain Security Scanner - scans dependencies for CVEs"
    )
    parser.add_argument(
        "project_path",
        nargs="?",
        default=".",
        help="Path to the project directory (default: current directory)"
    )
    parser.add_argument(
        "--output", "-o",
        default="scan-results.json",
        help="Output file for JSON report (default: scan-results.json)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show per-package scan progress"
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Never fail the build (report only)"
    )
    args = parser.parse_args()

    print()
    print("Supply Chain Security Scanner")
    print("-" * 40)
    print(f"  project: {os.path.abspath(args.project_path)}")
    print()
    print("Detecting dependencies...")

    deps = detect_and_parse(args.project_path)

    if not deps:
        print("  No supported manifest files found.")
        print("  Supported formats: requirements.txt, package.json, Gemfile.lock")
        sys.exit(0)

    print()
    print(f"Scanning {len(deps)} dependencies against OSV.dev...")
    findings = scan_dependencies(deps, verbose=args.verbose)

    print_report(findings, len(deps))
    save_json_report(findings, len(deps), args.output)

    if args.no_fail:
        sys.exit(0)

    exit_code = evaluate_build_gate(findings)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()