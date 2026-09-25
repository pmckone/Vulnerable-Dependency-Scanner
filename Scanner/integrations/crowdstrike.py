"""Ship scan results to Splunk via the HTTP Event Collector (HEC).

Uses only the standard library, so the base scanner install stays dependency-light.

Environment variables:
    SPLUNK_HEC_URL      required  e.g. https://splunk.lab:8088 (path is added if missing)
    SPLUNK_HEC_TOKEN    required  HEC token
    SPLUNK_INDEX        optional  target index (token default is used if unset)
    SPLUNK_VERIFY_TLS   optional  "false" disables certificate checks (default: true)
    SPLUNK_CA_BUNDLE    optional  path to a CA/self-signed cert to trust (preferred
                                  over disabling verification)
    SPLUNK_BATCH_SIZE   optional  events per HTTP request (default: 100)
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.request

from Scanner.integrations import ci_context

SOURCE = "vulnerable-dependency-scanner"
SOURCETYPE_FINDING = "vuln_scanner:finding"
SOURCETYPE_SUMMARY = "vuln_scanner:summary"

DEFAULT_BATCH_SIZE = 100
TIMEOUT_SECONDS = 15
MAX_ATTEMPTS = 3
RETRY_DELAY = 2  # seconds; multiplied by the attempt number


class SplunkError(Exception):
    pass


class SplunkConfigError(SplunkError):
    pass


def _env_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


def _endpoint(url):
    url = url.rstrip("/")
    if "/services/collector" in url:
        return url
    return url + "/services/collector/event"


def _ssl_context(endpoint):
    if not endpoint.lower().startswith("https"):
        return None
    context = ssl.create_default_context(cafile=os.environ.get("SPLUNK_CA_BUNDLE") or None)
    if not _env_bool("SPLUNK_VERIFY_TLS", True):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _wrap(event, sourcetype, timestamp):
    payload = {
        "time": round(timestamp, 3),
        "source": SOURCE,
        "sourcetype": sourcetype,
        "event": event,
    }
    index = os.environ.get("SPLUNK_INDEX")
    if index:
        payload["index"] = index
    return payload


def build_events(scan_name, report):
    findings = report.get("findings", [])
    now = time.time()
    blocking = sum(1 for f in findings if f.get("fail_build"))

    base = {"scan_name": scan_name, "scan_time": report.get("scan_time")}
    base.update(ci_context())

    summary = dict(base)
    summary.update({
        "event_type": "scan_summary",
        "deps_scanned": report.get("deps_scanned"),
        "transitive_mode": report.get("transitive_mode"),
        "total_findings": report.get("total_findings", len(findings)),
        "direct_findings": report.get("direct_findings"),
        "transitive_findings": report.get("transitive_findings"),
        "severity_counts": report.get("summary", {}),
        "blocking_findings": blocking,
        "build_passed": blocking == 0,
    })
    events = [_wrap(summary, SOURCETYPE_SUMMARY, now)]

    for finding in findings:
        event = dict(base)
        event["event_type"] = "finding"
        event.update(finding)
        events.append(_wrap(event, SOURCETYPE_FINDING, now))
    return events


def _post(endpoint, token, body, context):
    headers = {
        "Authorization": "Splunk {}".format(token),
        "Content-Type": "application/json",
    }
    last_error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS, context=context) as response:
                raw = response.read().decode("utf-8", errors="replace")
            try:
                result = json.loads(raw) if raw else {}
            except ValueError:
                raise SplunkError("HEC returned a non-JSON response: {}".format(raw[:200])) from None
            if result.get("code", 0) != 0:
                raise SplunkError("HEC rejected the batch: {}".format(result))
            return
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:200]
            # 4xx (other than 429) means bad token/index/payload; retrying will not help.
            if error.code < 500 and error.code != 429:
                raise SplunkError("HEC returned HTTP {}: {}".format(error.code, detail)) from None
            last_error = "HTTP {}: {}".format(error.code, detail)
        except OSError as error:  # URLError, timeouts, connection resets, TLS failures
            last_error = str(error)
        if attempt < MAX_ATTEMPTS:
            time.sleep(RETRY_DELAY * attempt)
    raise SplunkError("HEC unreachable after {} attempts: {}".format(MAX_ATTEMPTS, last_error))


def send(events, url=None, token=None, batch_size=None):
    """POST events to HEC in batches. Returns the number of events delivered."""
    url = url or os.environ.get("SPLUNK_HEC_URL")
    token = token or os.environ.get("SPLUNK_HEC_TOKEN")
    if not url or not token:
        raise SplunkConfigError("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN must be set")

    batch_size = batch_size or int(os.environ.get("SPLUNK_BATCH_SIZE", DEFAULT_BATCH_SIZE))
    endpoint = _endpoint(url)
    context = _ssl_context(endpoint)

    sent = 0
    for start in range(0, len(events), batch_size):
        batch = events[start:start + batch_size]
        body = "\n".join(json.dumps(event) for event in batch).encode("utf-8")
        _post(endpoint, token, body, context)
        sent += len(batch)
    return sent