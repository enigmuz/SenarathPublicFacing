"""
Senarath Bank - SenNet Online Banking  |  SIMULATION / SECURITY TRAINING LAB
Shared helpers: database connection + structured (SIEM-ready) logging.

*** DELIBERATELY VULNERABLE TRAINING APP - DO NOT EXPOSE ALONGSIDE REAL DATA ***

JSON-lines logs written to /app/logs (bind-mounted for the NG SIEM collector):
    access.log   one line per HTTP request
    audit.log    one line per security-relevant event
    auth.log     one line per authentication attempt (brute-force telemetry)
"""
import os
import json
import time
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

import pymysql

APP_NAME = "senarath-bank"
LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
os.makedirs(LOG_DIR, exist_ok=True)

DB_CONFIG = dict(
    host=os.environ.get("DB_HOST", "db"),
    port=int(os.environ.get("DB_PORT", "3306")),
    user=os.environ.get("DB_USER", "senarath_app"),
    password=os.environ.get("DB_PASSWORD", "App@12345"),
    database=os.environ.get("DB_NAME", "senarath_bank"),
    charset="utf8mb4",
    autocommit=True,
    cursorclass=pymysql.cursors.DictCursor,
)


def get_db():
    return pymysql.connect(**DB_CONFIG)


def wait_for_db(retries=60, delay=2):
    last = None
    for _ in range(retries):
        try:
            get_db().close()
            print(f"[{APP_NAME}] database is up", flush=True)
            return True
        except Exception as e:                   # noqa
            last = e
            print(f"[{APP_NAME}] waiting for database... ({e})", flush=True)
            time.sleep(delay)
    raise RuntimeError(f"database never came up: {last}")


def _json_handler(filename):
    h = RotatingFileHandler(os.path.join(LOG_DIR, filename),
                            maxBytes=10 * 1024 * 1024, backupCount=10)
    h.setFormatter(logging.Formatter("%(message)s"))
    return h


access_logger = logging.getLogger("senarath.bank.access")
access_logger.setLevel(logging.INFO)
access_logger.addHandler(_json_handler("access.log"))
access_logger.propagate = False

audit_logger = logging.getLogger("senarath.bank.audit")
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(_json_handler("audit.log"))
_stdout = logging.StreamHandler()
_stdout.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_stdout)
audit_logger.propagate = False

auth_logger = logging.getLogger("senarath.bank.auth")
auth_logger.setLevel(logging.INFO)
auth_logger.addHandler(_json_handler("auth.log"))
auth_logger.addHandler(_stdout)
auth_logger.propagate = False


def _now():
    return datetime.now(timezone.utc).isoformat()


def log_access(record: dict):
    access_logger.info(json.dumps(
        {"@timestamp": _now(), "app": APP_NAME, "log_type": "access", **record},
        ensure_ascii=False))


def log_event(event_type, action, outcome="success", severity="info",
              username=None, src_ip=None, http_method=None, path=None,
              detail=None, **extra):
    record = {"@timestamp": _now(), "app": APP_NAME, "log_type": "audit",
              "event_type": event_type, "severity": severity, "action": action,
              "outcome": outcome, "username": username, "src_ip": src_ip,
              "http_method": http_method, "path": path, "detail": detail}
    record.update(extra)
    audit_logger.info(json.dumps(record, ensure_ascii=False))
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (event_type,severity,username,src_ip,"
                "http_method,path,action,outcome,detail) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (event_type, severity, username, src_ip, http_method, path,
                 action, outcome, (detail or "")[:4000]))
        conn.close()
    except Exception as e:                       # noqa
        audit_logger.info(json.dumps({"@timestamp": _now(), "app": APP_NAME,
                          "log_type": "audit", "event_type": "audit_db_error",
                          "severity": "warn", "detail": str(e)}))


def log_auth(username, outcome, src_ip, user_agent=None, detail=None):
    """Authentication-specific log (ideal brute-force / password-spray source)."""
    rec = {"@timestamp": _now(), "app": APP_NAME, "log_type": "auth",
           "event_type": "authentication", "username": username,
           "outcome": outcome, "src_ip": src_ip, "user_agent": user_agent,
           "detail": detail,
           "severity": "medium" if outcome == "failure" else "info"}
    auth_logger.info(json.dumps(rec, ensure_ascii=False))
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO login_log (username,src_ip,user_agent,"
                        "outcome,detail) VALUES (%s,%s,%s,%s,%s)",
                        (username, src_ip, (user_agent or "")[:400], outcome,
                         detail))
        conn.close()
    except Exception:                            # noqa
        pass


SQLI_SIGNS = ["'", "\"", " or ", " union ", "--", "/*", " sleep(",
              "information_schema", " xp_", "0x", " drop ", " insert ",
              " update ", " delete ", "' or '1'='1"]
XSS_SIGNS = ["<script", "onerror=", "onload=", "javascript:", "<img", "<svg",
             "<iframe", "alert("]
TRAVERSAL_SIGNS = ["../", "..\\", "%2e%2e", "/etc/passwd", "boot.ini"]


def classify_payload(value: str):
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
