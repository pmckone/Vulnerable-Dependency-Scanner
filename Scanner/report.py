import json
from datetime import datetime

from Scanner.config import MAX_WORKERS, SEVERITY_SCORES


def print_report(findings, deps_count, transitive_mode=False):
    direct_count = sum(1 for f in findings if not f.get("transitive"))
    transitive_count = sum(1 for f in findings if f.get("transitive"))

    print()
    print("=" * 60)
    print("  SUPPLY CHAIN SECURITY SCAN REPORT")
    print("=" * 60)
    print(f"  Scanned:     {deps_count} dependencies")
    if transitive_mode:
        print(f"  Mode:        full transitive tree")
    print(f"  Findings:    {len(findings)} total vulnerabilities")
    if transitive_mode:
        print(f"               {direct_count} in direct deps")
        print(f"               {transitive_count} in transitive deps")
    print(f"  Time:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
            tag = " [transitive]" if f.get("transitive") else " [direct]"
            print(f"  {f['package']}@{f['version']}{tag}")
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


def save_json_report(findings, deps_count, output_path, transitive_mode=False):
    report = {
        "scan_time": datetime.now().isoformat(),
        "deps_scanned": deps_count,
        "transitive_mode": transitive_mode,
        "total_findings": len(findings),
        "direct_findings": sum(1 for f in findings if not f.get("transitive")),
        "transitive_findings": sum(1 for f in findings if f.get("transitive")),
        "workers_used": MAX_WORKERS,
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
    blocking = [f for f in findings if f["fail_build"]]
    if blocking:
        print()
        print(f"  BUILD FAILED - {len(blocking)} HIGH/CRITICAL vulnerability(ies) found.")
        print("  Fix or suppress these before merging:")
        print()
        for f in blocking:
            cves = ", ".join(f["cve_ids"]) if f["cve_ids"] else f["vuln_id"]
            tag = " [transitive]" if f.get("transitive") else ""
            print(f"    {f['package']}@{f['version']}  {cves}  [{f['severity']}]{tag}")
        print()
        return 1
    else:
        print()
        print("  BUILD PASSED - no blocking vulnerabilities found.")
        print()
        return 0