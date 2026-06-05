#!/usr/bin/env python3
import sys
import os
import argparse
from datetime import datetime

from Scanner.config import MAX_WORKERS
from Scanner.parsers import detect_and_parse
from Scanner.scan import scan_dependencies
from Scanner.report import print_report, save_json_report, evaluate_build_gate


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
    parser.add_argument(
        "--transitive",
        action="store_true",
        help="Resolve and scan the full dependency tree including transitive dependencies"
    )
    args = parser.parse_args()

    print()
    print("Supply Chain Security Scanner")
    print("-" * 40)
    print(f"  project: {os.path.abspath(args.project_path)}")
    if args.transitive:
        print("  mode:    full transitive tree")
    else:
        print("  mode:    direct dependencies only (use --transitive for full tree)")
    print()
    print("Detecting dependencies...")

    deps = detect_and_parse(args.project_path, transitive=args.transitive)

    if not deps:
        print("  No supported manifest files found.")
        print("  Supported formats: requirements.txt, package.json, Gemfile.lock")
        sys.exit(0)

    print()
    print(f"Scanning {len(deps)} dependencies against OSV.dev...")
    print(f"  workers: {min(MAX_WORKERS, len(deps))}  (set MAX_WORKERS to adjust)")
    scan_start = datetime.now()
    findings = scan_dependencies(deps, verbose=args.verbose)
    elapsed = (datetime.now() - scan_start).total_seconds()
    print(f"  scan completed in {elapsed:.1f}s")

    print_report(findings, len(deps), transitive_mode=args.transitive)
    save_json_report(findings, len(deps), args.output, transitive_mode=args.transitive)

    if args.no_fail:
        sys.exit(0)

    exit_code = evaluate_build_gate(findings)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()