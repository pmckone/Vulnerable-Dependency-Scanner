#!/usr/bin/env python3
""""
    python publish.py scan-results.json --splunk
    python publish.py scan-results.json --crowdstrike --splunk
    python publish.py reports/ --splunk --crowdstrike   
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  
    pass

from Scanner.integrations import crowdstrike, splunk, warn


def find_reports(paths):
    found = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            candidates = sorted(path.rglob("*.json"))
        elif path.is_file():
            candidates = [path]
        else:
            warn("{} not found, skipping".format(raw))
            continue
        for candidate in candidates:
            try:
                report = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(report, dict) and isinstance(report.get("findings"), list):
                found.append((candidate, report))
    return found


def scan_name_for(path):
    parent = path.parent.name
    return parent if parent not in ("", ".") else path.stem


def print_exposures(findings, limit=10):
    exposed = [f for f in findings if f.get("falcon_affected_hosts")]
    exposed.sort(key=lambda f: f["falcon_affected_hosts"], reverse=True)
    if not exposed:
        return
    print("  Findings that are also live on managed hosts:")
    for f in exposed[:limit]:
        plus = "+" if f.get("falcon_hosts_truncated") else ""
        print("    {:<8} {}=={}  {}  ({}{} hosts)".format(
            f.get("severity", "?"), f.get("package"), f.get("version"),
            f.get("vuln_id"), f["falcon_affected_hosts"], plus))


def main():
    parser = argparse.ArgumentParser(description="Publish scan reports to Splunk / CrowdStrike")
    parser.add_argument("reports", nargs="+", help="report JSON files, or directories containing them")
    parser.add_argument("--splunk", action="store_true", help="send events to Splunk HEC")
    parser.add_argument("--crowdstrike", action="store_true",
                        help="enrich findings with Falcon Spotlight host exposure")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 if an integration fails (default: warn and exit 0)")
    args = parser.parse_args()

    if not (args.splunk or args.crowdstrike):
        parser.error("choose at least one of --splunk / --crowdstrike")

    reports = find_reports(args.reports)
    if not reports:
        print("No scan reports found.")
        return 0

    failures = 0
    for path, report in reports:
        name = scan_name_for(path)
        findings = report["findings"]
        print("{}: {} findings".format(name, len(findings)))

        # Enrich first so the Splunk events carry the falcon_* fields.
        if args.crowdstrike:
            try:
                stats = crowdstrike.enrich_findings(findings)
                print("  crowdstrike: checked {cves_checked} CVEs, {cves_with_exposure} exposed "
                      "on managed hosts ({lookup_errors} errors, {cves_skipped_by_cap} over cap)".format(**stats))
                print_exposures(findings)
            except crowdstrike.CrowdStrikeError as error:
                failures += 1
                warn("crowdstrike enrichment skipped for {}: {}".format(name, error))

        if args.splunk:
            try:
                count = splunk.send(splunk.build_events(name, report))
                print("  splunk: sent {} events".format(count))
            except splunk.SplunkError as error:
                failures += 1
                warn("splunk delivery failed for {}: {}".format(name, error))

    return 1 if (failures and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())