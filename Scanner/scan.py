import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from Scanner.config import MAX_WORKERS, FAIL_ON_SEVERITY
from Scanner.osv import query_osv, extract_severity


def scan_single(dep, verbose=False, counter=None, total=None, lock=None):
    name = dep["name"]
    version = dep.get("version")
    ecosystem = dep.get("ecosystem", "PyPI")
    is_transitive = dep.get("transitive", False)
    findings = []

    vulns = query_osv(name, version, ecosystem)

    for vuln in vulns:
        severity, cvss = extract_severity(vuln)
        aliases = vuln.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]

        findings.append({
            "package": name,
            "version": version or "unspecified",
            "ecosystem": ecosystem,
            "transitive": is_transitive,
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

    if verbose and lock and counter is not None:
        with lock:
            counter[0] += 1
            label = "transitive" if is_transitive else "direct"
            print(f"  [{counter[0]}/{total}] checked {name}@{version or 'unknown'} ({ecosystem}, {label}) - {len(vulns)} finding(s)")

    return findings


def scan_dependencies(deps, verbose=False):
    all_findings = []
    total = len(deps)
    counter = [0]
    lock = threading.Lock()

    if verbose:
        print(f"  running {min(MAX_WORKERS, total)} workers in parallel")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(scan_single, dep, verbose, counter, total, lock): dep
            for dep in deps
        }

        for future in as_completed(futures):
            dep = futures[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
            except Exception as e:
                print(f"  warning: scan failed for {dep['name']} ({e})")

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    all_findings.sort(key=lambda f: (
        severity_order.index(f["severity"]) if f["severity"] in severity_order else 99,
        f.get("transitive", False)
    ))

    return all_findings