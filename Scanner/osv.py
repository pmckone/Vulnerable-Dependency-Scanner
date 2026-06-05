import json
import urllib.request
import urllib.error

from Scanner.config import OSV_API_URL


def query_osv(package_name, version, ecosystem):
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