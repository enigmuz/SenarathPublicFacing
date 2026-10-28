"""
Senarath Bank - General Website  |  SIMULATION / SECURITY TRAINING LAB
Shared helpers: database connection + structured (SIEM-ready) logging.

*** DELIBERATELY VULNERABLE TRAINING APP - DO NOT EXPOSE ALONGSIDE REAL DATA ***

Logging design
--------------
Two JSON-lines log files are written to /app/logs (bind-mounted to the host
so the on-prem NG SIEM Log Collector can tail them):

    access.log   one line per HTTP request
    audit.log    one line per security-relevant event (auth, admin, upload,
                 suspected injection, access-control events, ...)

Every line is a single flat JSON object -> trivial to parse in CrowdStrike
NG SIEM / LogScale, Splunk, Elastic, etc.
"""
import os
import json
import time
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

import pymysql

APP_NAME = "senarath-web"
LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
os.makedirs(LOG_DIR, exist_ok=True)

DB_CONFIG = dict(
    host=os.environ.get("DB_HOST", "db"),
    port=int(os.environ.get("DB_PORT", "3306")),
    user=os.environ.get("DB_USER", "senarath_app"),
    password=os.environ.get("DB_PASSWORD", "App@12345"),
    database=os.environ.get("DB_NAME", "senarath_web"),
    charset="utf8mb4",
    autocommit=True,
    cursorclass=pymysql.cursors.DictCursor,
)


# ---------------------------------------------------------------------------
#  Database
# ---------------------------------------------------------------------------
def get_db():
    """Open a new connection. (No pooling - fine for a lab.)"""
    return pymysql.connect(**DB_CONFIG)


def wait_for_db(retries=60, delay=2):
    """Block until MariaDB is reachable (container start-up race)."""
    last = None
    for _ in range(retries):
        try:
            conn = get_db()
            conn.close()
            print(f"[{APP_NAME}] database is up", flush=True)
            return True
        except Exception as e:          # noqa
            last = e
            print(f"[{APP_NAME}] waiting for database... ({e})", flush=True)
            time.sleep(delay)
    raise RuntimeError(f"database never came up: {last}")


# ---------------------------------------------------------------------------
#  Structured logging
# ---------------------------------------------------------------------------
def _json_handler(filename):
    h = RotatingFileHandler(os.path.join(LOG_DIR, filename),
                            maxBytes=10 * 1024 * 1024, backupCount=10)
    h.setFormatter(logging.Formatter("%(message)s"))
    return h


access_logger = logging.getLogger("senarath.web.access")
access_logger.setLevel(logging.INFO)
access_logger.addHandler(_json_handler("access.log"))
access_logger.propagate = False

audit_logger = logging.getLogger("senarath.web.audit")
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(_json_handler("audit.log"))
# also echo audit to stdout -> visible in `docker logs` and Falcon sensor
_stdout = logging.StreamHandler()
_stdout.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_stdout)
audit_logger.propagate = False


def _now():
    return datetime.now(timezone.utc).isoformat()


def log_access(record: dict):
    record = {"@timestamp": _now(), "app": APP_NAME, "log_type": "access", **record}
    access_logger.info(json.dumps(record, ensure_ascii=False))


def log_event(event_type, action, outcome="success", severity="info",
              username=None, src_ip=None, http_method=None, path=None,
              detail=None, **extra):
    """Write one security event to audit.log (JSON) and to the DB audit_log."""
    record = {
        "@timestamp": _now(),
        "app": APP_NAME,
        "log_type": "audit",
        "event_type": event_type,
        "severity": severity,
        "action": action,
        "outcome": outcome,
        "username": username,
        "src_ip": src_ip,
        "http_method": http_method,
        "path": path,
        "detail": detail,
    }
    record.update(extra)
    audit_logger.info(json.dumps(record, ensure_ascii=False))
    # best-effort DB mirror
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (event_type, severity, username, src_ip, "
                "http_method, path, action, outcome, detail) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (event_type, severity, username, src_ip, http_method, path,
                 action, outcome, (detail or "")[:4000]),
            )
        conn.close()
    except Exception as e:              # noqa
        audit_logger.info(json.dumps({"@timestamp": _now(), "app": APP_NAME,
                                      "log_type": "audit",
                                      "event_type": "audit_db_error",
                                      "severity": "warn", "detail": str(e)}))


# Simple signatures so the app can *flag* likely attacks in the audit log.
# (The app is still vulnerable - this only enriches telemetry for the SIEM.)
SQLI_SIGNS = ["'", "\"", " or ", " union ", "--", "/*", " sleep(", "information_schema",
              " xp_", "' or '1'='1", "0x", " drop ", " insert ", " update ", " delete "]
XSS_SIGNS = ["<script", "onerror=", "onload=", "javascript:", "<img", "<svg", "<iframe", "alert("]
TRAVERSAL_SIGNS = ["../", "..\\", "%2e%2e", "/etc/passwd", "boot.ini", "c:\\windows"]


def classify_payload(value: str):
    """Return a list of attack tags found in a string (best-effort)."""
    if not value:
        return []
    low = value.lower()
    tags = []
    if any(s in low for s in SQLI_SIGNS):
        tags.append("sqli")
    if any(s in low for s in XSS_SIGNS):
        tags.append("xss")
    if any(s in low for s in TRAVERSAL_SIGNS):
        tags.append("path_traversal")
    return tags
