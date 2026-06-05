import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

OSV_API_URL = os.getenv("PUBLICAPI", "https://api.osv.dev/v1/query")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))

SEVERITY_SCORES = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

FAIL_ON_SEVERITY = ["CRITICAL", "HIGH"]