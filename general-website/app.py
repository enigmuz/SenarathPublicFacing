"""
Senarath Bank - General / Public Website  (DMZ1 Web Server 1)
SIMULATION / SECURITY TRAINING LAB  -  intentionally vulnerable.

This file concentrates the deliberate weaknesses so they are easy to find,
teach, and detect. Each one is tagged  # [VULN: ...]  in the code and listed
in the README. Everything meaningful is logged for SIEM analysis.
"""
import os
import hashlib
import datetime
from flask import (Flask, request, render_template, redirect, url_for,
                   session, make_response, send_from_directory, Response, g)

import common
from common import get_db, log_access, log_event, classify_payload

app = Flask(__name__)

# [VULN: hard-coded, guessable secret key -> forgeable session cookies]
app.secret_key = "senarath-bank-secret-2024"

# [VULN: insecure cookie flags - no HttpOnly, no Secure, no SameSite]
app.config.update(
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE=None,
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
)

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/app/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def client_ip():
    # honour XFF so attacks through a proxy still show a source (and so the
    # header is trusted blindly -> spoofable, which is itself realistic)
    return (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()


# ---------------------------------------------------------------------------
#  Request logging + (missing) security headers
# ---------------------------------------------------------------------------
@app.before_request
def _before():
    g.start = datetime.datetime.utcnow()
    # flag suspicious input across all params for the SIEM
    tags = set()
    for v in list(request.args.values()) + list(request.form.values()):
        tags.update(classify_payload(v))
    if tags:
        log_event("attack_suspected", "suspicious_input_detected",
                  outcome="flagged", severity="high",
                  username=session.get("cms_user"), src_ip=client_ip(),
                  http_method=request.method, path=request.full_path,
                  detail=f"tags={sorted(tags)}", attack_tags=sorted(tags),
                  user_agent=request.headers.get("User-Agent"))


@app.after_request
def _after(resp):
    try:
        dur = (datetime.datetime.utcnow() - g.start).total_seconds() * 1000
    except Exception:
        dur = None
    log_access({
        "src_ip": client_ip(),
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode("utf-8", "ignore"),
        "status": resp.status_code,
        "bytes": resp.calculate_content_length(),
        "referer": request.headers.get("Referer"),
        "user_agent": request.headers.get("User-Agent"),
        "username": session.get("cms_user"),
        "duration_ms": round(dur, 1) if dur is not None else None,
    })
    # [VULN: deliberately NOT setting CSP / HSTS / X-Frame-Options / nosniff]
    resp.headers["Server"] = "SenarathWeb/1.0 (Werkzeug)"
    return resp


@app.context_processor
def _inject():
    return dict(year=datetime.date.today().year,
                cms_user=session.get("cms_user"),
                cms_role=session.get("cms_role"),
                web_url=os.environ.get("WEB_URL", "http://localhost:8090"),
                bank_url=os.environ.get("BANK_URL", "http://localhost:8091"))


# ---------------------------------------------------------------------------
#  Public site
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM news_articles WHERE published=1 "
                    "ORDER BY published_at DESC LIMIT 3")
        news = cur.fetchall()
    conn.close()
    return render_template("index.html", news=news)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/personal")
def personal():
    return render_template("personal.html")


@app.route("/business")
def business():
    return render_template("business.html")


@app.route("/loans")
def loans():
    return render_template("loans.html")


@app.route("/cards")
def cards():
    return render_template("cards.html")


@app.route("/branches")
def branches():
    # [VULN: SQL injection - city filter concatenated straight into the query]
    city = request.args.get("city", "")
    conn = get_db()
    rows = []
    err = None
    try:
        with conn.cursor() as cur:
            if city:
                q = ("SELECT * FROM branches WHERE city LIKE '%" + city + "%' "
                     "OR name LIKE '%" + city + "%'")
                cur.execute(q)
            else:
                cur.execute("SELECT * FROM branches ORDER BY id")
            rows = cur.fetchall()
    except Exception as e:                       # [VULN: verbose SQL error to user]
        err = str(e)
        log_event("sql_error", "branch_search_failed", outcome="error",
                  severity="high", src_ip=client_ip(), path=request.full_path,
                  detail=err)
    conn.close()
    return render_template("branches.html", branches=rows, city=city, err=err)


@app.route("/news")
def news_list():
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM news_articles WHERE published=1 "
                    "ORDER BY published_at DESC")
        news = cur.fetchall()
    conn.close()
    return render_template("news.html", news=news)


@app.route("/news/<slug>")
def news_detail(slug):
    conn = get_db()
    with conn.cursor() as cur:
        # [VULN: SQL injection via slug]
        cur.execute("SELECT * FROM news_articles WHERE slug = '" + slug + "'")
        article = cur.fetchone()
    conn.close()
    if not article:
        return render_template("404.html"), 404
    # [VULN: body rendered unescaped in template with |safe -> stored XSS]
    return render_template("news_detail.html", a=article)


@app.route("/careers")
def careers():
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM careers ORDER BY posted_at DESC")
        jobs = cur.fetchall()
    conn.close()
    return render_template("careers.html", jobs=jobs)


@app.route("/careers/apply", methods=["POST"])
def careers_apply():
    name = request.form.get("applicant", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    note = request.form.get("cover_note", "")
    career_id = request.form.get("career_id") or None
    fname = None
    f = request.files.get("cv")
    if f and f.filename:
        # [VULN: unrestricted file upload - original filename, no type/size check]
        fname = f.filename
        f.save(os.path.join(UPLOAD_DIR, fname))
        log_event("file_upload", "cv_uploaded", outcome="success",
                  severity="medium", src_ip=client_ip(), path=request.path,
                  detail=f"filename={fname}", filename=fname)
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO job_applications (career_id, applicant, email, "
                    "phone, cover_note, cv_filename, src_ip) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (career_id, name, email, phone, note, fname, client_ip()))
    conn.close()
    log_event("form_submit", "job_application", src_ip=client_ip(),
              path=request.path, detail=f"applicant={name}")
    return render_template("thanks.html", what="application")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        subject = request.form.get("subject", "")
        message = request.form.get("message", "")
        conn = get_db()
        with conn.cursor() as cur:
            # parameterised insert, but content is rendered unescaped later
            # [VULN: stored XSS - message shown raw in the admin inbox]
            cur.execute("INSERT INTO contact_messages (name,email,phone,subject,"
                        "message,src_ip,user_agent) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (name, email, phone, subject, message, client_ip(),
                         request.headers.get("User-Agent")))
        conn.close()
        log_event("form_submit", "contact_message", src_ip=client_ip(),
                  path=request.path, detail=f"from={name} <{email}>")
        return render_template("thanks.html", what="message")
    return render_template("contact.html")


@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form.get("email", "")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO newsletter_subscribers (email) VALUES (%s)", (email,))
    conn.close()
    log_event("form_submit", "newsletter_subscribe", src_ip=client_ip(),
              path=request.path, detail=f"email={email}")
    return redirect(request.referrer or url_for("index"))


@app.route("/search")
def search():
    # [VULN: reflected XSS - q echoed unescaped in the template]
    q = request.args.get("q", "")
    conn = get_db()
    results = []
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM news_articles WHERE published=1 AND "
                    "(title LIKE %s OR body LIKE %s)", (f"%{q}%", f"%{q}%"))
        results = cur.fetchall()
    conn.close()
    return render_template("search.html", q=q, results=results)


# ---------------------------------------------------------------------------
#  CMS / back office
# ---------------------------------------------------------------------------
@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        conn = get_db()
        row = None
        err = None
        try:
            with conn.cursor() as cur:
                # [VULN: SQL injection in auth + unsalted MD5 + no lockout]
                sql = ("SELECT * FROM cms_users WHERE username = '" + u +
                       "' AND password_md5 = '" + md5(p) + "'")
                cur.execute(sql)
                row = cur.fetchone()
        except Exception as e:
            err = str(e)                         # [VULN: verbose error]
        conn.close()
        if row:
            session["cms_user"] = row["username"]
            session["cms_role"] = row["role"]
            log_event("authentication", "cms_login", outcome="success",
                      severity="info", username=u, src_ip=client_ip(),
                      path=request.path)
            return redirect(url_for("admin_dashboard"))
        log_event("authentication", "cms_login", outcome="failure",
                  severity="medium", username=u, src_ip=client_ip(),
                  path=request.path, detail="invalid credentials")
        return render_template("admin_login.html",
                               error=err or "Invalid username or password")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    log_event("authentication", "cms_logout", username=session.get("cms_user"),
              src_ip=client_ip(), path=request.path)
    session.clear()
    return redirect(url_for("admin_login"))


def require_cms():
    if not session.get("cms_user"):
        return False
    return True


@app.route("/admin/dashboard")
def admin_dashboard():
    if not require_cms():
        return redirect(url_for("admin_login"))
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) c FROM contact_messages"); msgs = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM newsletter_subscribers"); subs = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM news_articles"); arts = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM job_applications"); apps_ = cur.fetchone()["c"]
        cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 15"); audit = cur.fetchall()
    conn.close()
    log_event("admin_access", "view_dashboard", username=session.get("cms_user"),
              src_ip=client_ip(), path=request.path)
    return render_template("admin_dashboard.html", msgs=msgs, subs=subs,
                           arts=arts, apps=apps_, audit=audit)


@app.route("/admin/messages")
def admin_messages():
    if not require_cms():
        return redirect(url_for("admin_login"))
    # [VULN: SQL injection in the search box (string concatenation)]
    q = request.args.get("q", "")
    conn = get_db()
    err = None
    rows = []
    try:
        with conn.cursor() as cur:
            if q:
                cur.execute("SELECT * FROM contact_messages WHERE name LIKE '%" + q +
                            "%' OR subject LIKE '%" + q + "%' ORDER BY id DESC")
            else:
                cur.execute("SELECT * FROM contact_messages ORDER BY id DESC")
            rows = cur.fetchall()
    except Exception as e:
        err = str(e)
        log_event("sql_error", "message_search_failed", outcome="error",
                  severity="high", username=session.get("cms_user"),
                  src_ip=client_ip(), path=request.full_path, detail=err)
    conn.close()
    log_event("admin_access", "view_messages", username=session.get("cms_user"),
              src_ip=client_ip(), path=request.full_path, detail=f"q={q}")
    # [VULN: messages rendered unescaped -> stored XSS fires here]
    return render_template("admin_messages.html", rows=rows, q=q, err=err)


@app.route("/admin/messages.json")
def admin_messages_json():
    # [VULN: broken access control - no auth check on this data export endpoint]
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM contact_messages ORDER BY id DESC")
        rows = cur.fetchall()
    conn.close()
    log_event("access_control", "messages_export", outcome="success",
              severity="high", username=session.get("cms_user"),
              src_ip=client_ip(), path=request.path,
              detail="unauthenticated export endpoint accessed")
    import json as _j
    return Response(_j.dumps(rows, default=str), mimetype="application/json")


@app.route("/admin/news/new", methods=["GET", "POST"])
@app.route("/admin/news/edit/<int:aid>", methods=["GET", "POST"])
def admin_news_edit(aid=None):
    if not require_cms():
        return redirect(url_for("admin_login"))
    conn = get_db()
    article = None
    if aid:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM news_articles WHERE id=%s", (aid,))
            article = cur.fetchone()
    if request.method == "POST":
        title = request.form.get("title", "")
        slug = request.form.get("slug", "")
        summary = request.form.get("summary", "")
        body = request.form.get("body", "")          # stored raw -> stored XSS
        category = request.form.get("category", "News")
        with conn.cursor() as cur:
            if aid:
                cur.execute("UPDATE news_articles SET title=%s,slug=%s,summary=%s,"
                            "body=%s,category=%s WHERE id=%s",
                            (title, slug, summary, body, category, aid))
            else:
                cur.execute("INSERT INTO news_articles (title,slug,summary,body,"
                            "author,category) VALUES (%s,%s,%s,%s,%s,%s)",
                            (title, slug, summary, body,
                             session.get("cms_user"), category))
        conn.close()
        log_event("content_change", "news_saved", username=session.get("cms_user"),
                  src_ip=client_ip(), path=request.path, detail=f"title={title}")
        return redirect(url_for("admin_dashboard"))
    conn.close()
    return render_template("admin_news_edit.html", a=article)


@app.route("/admin/users")
def admin_users():
    if not require_cms():
        return redirect(url_for("admin_login"))
    conn = get_db()
    with conn.cursor() as cur:
        # [VULN: password hashes exposed to any logged-in operator]
        cur.execute("SELECT * FROM cms_users ORDER BY id")
        rows = cur.fetchall()
    conn.close()
    log_event("admin_access", "view_users", username=session.get("cms_user"),
              src_ip=client_ip(), path=request.path)
    return render_template("admin_users.html", rows=rows)


# ---------------------------------------------------------------------------
#  Information-disclosure / misconfiguration endpoints (intentional)
# ---------------------------------------------------------------------------
@app.route("/robots.txt")
def robots():
    # [VULN: robots.txt advertises sensitive paths]
    body = ("User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /admin/login\n"
            "Disallow: /backup.sql\n"
            "Disallow: /debug\n"
            "Disallow: /uploads/\n")
    return Response(body, mimetype="text/plain")


@app.route("/backup.sql")
def backup():
    # [VULN: database backup left in web root]
    log_event("info_disclosure", "backup_sql_accessed", outcome="success",
              severity="critical", src_ip=client_ip(), path=request.path,
              detail="exposed DB backup downloaded")
    sample = ("-- Senarath Bank DB backup (SIMULATION)\n"
              "-- cms_users (username, md5)\n"
              "-- admin:0e7517141fb53f21ee439b355b5a1d0a\n"
              "-- editor1:5f4dcc3b5aa765d61d8327deb882cf99\n")
    return Response(sample, mimetype="text/plain")


@app.route("/debug")
def debug():
    # [VULN: debug/config disclosure]
    log_event("info_disclosure", "debug_endpoint_accessed", outcome="success",
              severity="high", src_ip=client_ip(), path=request.path)
    info = {
        "app": "senarath-web",
        "env": {k: v for k, v in os.environ.items()
                if k.startswith(("DB_", "LOG_", "FLASK_"))},
        "secret_key": app.secret_key,
        "version": "1.0.0",
    }
    import json as _j
    return Response(_j.dumps(info, indent=2), mimetype="application/json")


@app.route("/uploads/")
@app.route("/uploads/<path:fname>")
def uploads(fname=None):
    if fname is None:
        # [VULN: directory listing of uploads]
        files = os.listdir(UPLOAD_DIR)
        links = "".join(f'<li><a href="/uploads/{f}">{f}</a></li>' for f in files)
        return f"<h3>Index of /uploads</h3><ul>{links}</ul>"
    # [VULN: files served back with no auth -> uploaded scripts retrievable]
    return send_from_directory(UPLOAD_DIR, fname)


@app.errorhandler(404)
def nf(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    common.wait_for_db()
    log_event("system", "app_start", severity="info",
              detail="senarath-web started")
    # [VULN: debug=True in a public app -> Werkzeug console + stack traces]
    app.run(host="0.0.0.0", port=8080, debug=True)
