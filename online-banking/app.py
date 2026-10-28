"""
Senarath Bank - SenNet Online Banking  (DMZ1 Web Server 2)
SIMULATION / SECURITY TRAINING LAB  -  intentionally vulnerable.

Deliberate weaknesses are tagged  # [VULN: ...]  and listed in the README.
Authentication, transfers, account access and admin actions are all logged
for SIEM analysis (access.log / audit.log / auth.log, plus DB tables).
"""
import os
import hashlib
import random
import string
import datetime
from flask import (Flask, request, render_template, redirect, url_for,
                   session, Response, g)

import common
from common import get_db, log_access, log_event, log_auth, classify_payload

app = Flask(__name__)

# [VULN: hard-coded, guessable secret key -> forgeable session cookies]
app.secret_key = "sennet-online-banking-key-2024"

# [VULN: insecure cookie flags]
app.config.update(
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE=None,
)


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def client_ip():
    return (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()


def ref():
    return "TRF" + "".join(random.choices(string.digits, k=9))


def current_user():
    if not session.get("uid"):
        return None
    return {"uid": session.get("uid"), "username": session.get("username"),
            "role": session.get("role"), "customer_id": session.get("customer_id"),
            "full_name": session.get("full_name")}


# ---------------------------------------------------------------------------
#  Request logging + suspicious-input flagging
# ---------------------------------------------------------------------------
@app.before_request
def _before():
    g.start = datetime.datetime.utcnow()
    tags = set()
    for v in list(request.args.values()) + list(request.form.values()):
        tags.update(classify_payload(v))
    if tags:
        log_event("attack_suspected", "suspicious_input_detected",
                  outcome="flagged", severity="high",
                  username=session.get("username"), src_ip=client_ip(),
                  http_method=request.method, path=request.full_path,
                  detail=f"tags={sorted(tags)}", attack_tags=sorted(tags),
                  user_agent=request.headers.get("User-Agent"))


@app.after_request
def _after(resp):
    try:
        dur = (datetime.datetime.utcnow() - g.start).total_seconds() * 1000
    except Exception:
        dur = None
    log_access({"src_ip": client_ip(), "method": request.method,
                "path": request.path,
                "query": request.query_string.decode("utf-8", "ignore"),
                "status": resp.status_code,
                "user_agent": request.headers.get("User-Agent"),
                "username": session.get("username"),
                "duration_ms": round(dur, 1) if dur is not None else None})
    # [VULN: no CSP / HSTS / X-Frame-Options / nosniff]
    resp.headers["Server"] = "SenNet/1.0 (Werkzeug)"
    return resp


@app.context_processor
def _inject():
    return dict(year=datetime.date.today().year, user=current_user(),
                web_url=os.environ.get("WEB_URL", "http://localhost:8090"),
                bank_url=os.environ.get("BANK_URL", "http://localhost:8091"))


# ---------------------------------------------------------------------------
#  Auth
# ---------------------------------------------------------------------------
@app.route("/")
def root():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        conn = get_db()
        row, err = None, None
        try:
            with conn.cursor() as cur:
                # [VULN: SQL injection + unsalted MD5 + no account lockout]
                sql = ("SELECT u.*, c.full_name, c.cust_no FROM users u "
                       "LEFT JOIN customers c ON c.id=u.customer_id "
                       "WHERE u.username = '" + u + "' "
                       "AND u.password_md5 = '" + md5(p) + "'")
                cur.execute(sql)
                row = cur.fetchone()
                # [VULN: user enumeration - distinguish unknown user vs bad pw]
                if not row:
                    cur.execute("SELECT id FROM users WHERE username = '" + u + "'")
                    exists = cur.fetchone()
        except Exception as e:
            err = str(e)                          # [VULN: verbose SQL error]
            exists = None
        conn.close()

        if row:
            session.update(uid=row["id"], username=row["username"],
                           role=row["role"], customer_id=row["customer_id"],
                           full_name=row.get("full_name") or row["username"])
            log_auth(u, "success", client_ip(), request.headers.get("User-Agent"))
            # update last_login / reset counter (not enforced anyway)
            try:
                c = get_db()
                with c.cursor() as cur:
                    cur.execute("UPDATE users SET last_login=NOW(), "
                                "failed_attempts=0 WHERE id=%s", (row["id"],))
                c.close()
            except Exception:
                pass
            return redirect(url_for("dashboard"))

        log_auth(u, "failure", client_ip(), request.headers.get("User-Agent"),
                 detail="invalid credentials")
        try:
            c = get_db()
            with c.cursor() as cur:
                cur.execute("UPDATE users SET failed_attempts=failed_attempts+1 "
                            "WHERE username=%s", (u,))
            c.close()
        except Exception:
            pass
        msg = err or ("User not found" if not locals().get("exists")
                      else "Incorrect password")   # enumeration message
        return render_template("login.html", error=msg)
    return render_template("login.html")


@app.route("/logout")
def logout():
    log_event("authentication", "logout", username=session.get("username"),
              src_ip=client_ip(), path=request.path)
    session.clear()
    return redirect(url_for("login"))


def login_required():
    return current_user() is not None


# ---------------------------------------------------------------------------
#  Banking
# ---------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM accounts WHERE customer_id=%s", (u["customer_id"],))
        accounts = cur.fetchall()
        acct_ids = [a["id"] for a in accounts] or [0]
        fmt = ",".join(["%s"] * len(acct_ids))
        cur.execute(f"SELECT * FROM transactions WHERE account_id IN ({fmt}) "
                    "ORDER BY ts DESC LIMIT 6", acct_ids)
        recent = cur.fetchall()
        cur.execute("SELECT * FROM cards WHERE customer_id=%s", (u["customer_id"],))
        cards = cur.fetchall()
    conn.close()
    total = sum(float(a["balance"]) for a in accounts)
    return render_template("dashboard.html", accounts=accounts, recent=recent,
                           cards=cards, total=total)


@app.route("/accounts")
def accounts():
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM accounts WHERE customer_id=%s", (u["customer_id"],))
        rows = cur.fetchall()
    conn.close()
    return render_template("accounts.html", accounts=rows)


@app.route("/account/<account_no>")
def account_detail(account_no):
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    conn = get_db()
    with conn.cursor() as cur:
        # [VULN: IDOR - account fetched by number with NO ownership check]
        cur.execute("SELECT * FROM accounts WHERE account_no=%s", (account_no,))
        acct = cur.fetchone()
        txns = []
        if acct:
            cur.execute("SELECT * FROM transactions WHERE account_id=%s "
                        "ORDER BY ts DESC LIMIT 100", (acct["id"],))
            txns = cur.fetchall()
    conn.close()
    if not acct:
        return render_template("404.html"), 404
    # flag horizontal access for the SIEM (still allowed - just logged)
    if acct["customer_id"] != u["customer_id"]:
        log_event("access_control", "idor_account_view", outcome="success",
                  severity="high", username=u["username"], src_ip=client_ip(),
                  path=request.path,
                  detail=f"viewed account {account_no} owned by customer "
                         f"{acct['customer_id']} (attacker customer "
                         f"{u['customer_id']})")
    return render_template("account_detail.html", acct=acct, txns=txns)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM accounts WHERE customer_id=%s", (u["customer_id"],))
        my_accounts = cur.fetchall()
        cur.execute("SELECT * FROM beneficiaries WHERE customer_id=%s", (u["customer_id"],))
        benes = cur.fetchall()
    result = None
    if request.method == "POST":
        from_no = request.form.get("from_account", "")
        to_no = request.form.get("to_account", "")
        try:
            amount = float(request.form.get("amount", "0") or 0)
        except ValueError:
            amount = 0
        memo = request.form.get("memo", "")      # [VULN: stored XSS via memo]
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM accounts WHERE account_no=%s", (from_no,))
            src = cur.fetchone()
            cur.execute("SELECT * FROM accounts WHERE account_no=%s", (to_no,))
            dst = cur.fetchone()

            # [VULN: no ownership check on the source account -> transfer from
            #        anyone's account if you know the number]
            if src and src["customer_id"] != u["customer_id"]:
                log_event("access_control", "idor_transfer_source",
                          outcome="success", severity="critical",
                          username=u["username"], src_ip=client_ip(),
                          path=request.path,
                          detail=f"transfer initiated from non-owned account {from_no}")

            if not src:
                result = ("error", "Source account not found.")
            # [VULN: no balance check -> overdraft / negative balance allowed]
            # [VULN: no positive-amount check -> negative amounts allowed]
            else:
                new_src = float(src["balance"]) - amount
                r = ref()
                cur.execute("UPDATE accounts SET balance=%s WHERE id=%s",
                            (new_src, src["id"]))
                cur.execute("INSERT INTO transactions (account_id,txn_type,amount,"
                            "balance_after,counterparty_acct,counterparty_name,"
                            "memo,channel,status,reference) VALUES "
                            "(%s,'transfer',%s,%s,%s,%s,%s,'online','completed',%s)",
                            (src["id"], amount, new_src, to_no,
                             dst["account_no"] if dst else to_no, memo, r))
                if dst:
                    new_dst = float(dst["balance"]) + amount
                    cur.execute("UPDATE accounts SET balance=%s WHERE id=%s",
                                (new_dst, dst["id"]))
                    cur.execute("INSERT INTO transactions (account_id,txn_type,"
                                "amount,balance_after,counterparty_acct,"
                                "counterparty_name,memo,channel,status,reference) "
                                "VALUES (%s,'credit',%s,%s,%s,%s,%s,'online',"
                                "'completed',%s)",
                                (dst["id"], amount, new_dst, from_no,
                                 src["full_name"] if src.get("full_name") else from_no,
                                 memo, r))
                log_event("transaction", "funds_transfer", outcome="success",
                          severity="medium", username=u["username"],
                          src_ip=client_ip(), path=request.path,
                          detail=f"from={from_no} to={to_no} amount={amount} "
                                 f"ref={r}", amount=amount, from_account=from_no,
                          to_account=to_no, reference=r)
                result = ("ok", f"Transferred LKR {amount:,.2f} to {to_no}. "
                                f"Reference {r}.")
    conn.close()
    return render_template("transfer.html", my_accounts=my_accounts,
                           benes=benes, result=result)


@app.route("/beneficiaries", methods=["GET", "POST"])
def beneficiaries():
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    conn = get_db()
    if request.method == "POST":
        with conn.cursor() as cur:
            # [VULN: stored XSS via nickname/payee_name]
            cur.execute("INSERT INTO beneficiaries (customer_id,nickname,"
                        "account_no,bank,payee_name) VALUES (%s,%s,%s,%s,%s)",
                        (u["customer_id"], request.form.get("nickname", ""),
                         request.form.get("account_no", ""),
                         request.form.get("bank", ""),
                         request.form.get("payee_name", "")))
        log_event("account_change", "beneficiary_added", username=u["username"],
                  src_ip=client_ip(), path=request.path,
                  detail=request.form.get("account_no", ""))
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM beneficiaries WHERE customer_id=%s", (u["customer_id"],))
        rows = cur.fetchall()
    conn.close()
    return render_template("beneficiaries.html", benes=rows)


@app.route("/payments", methods=["GET", "POST"])
def payments():
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM accounts WHERE customer_id=%s", (u["customer_id"],))
        my_accounts = cur.fetchall()
    result = None
    if request.method == "POST":
        biller = request.form.get("biller", "")
        from_no = request.form.get("from_account", "")
        try:
            amount = float(request.form.get("amount", "0") or 0)
        except ValueError:
            amount = 0
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM accounts WHERE account_no=%s", (from_no,))
            src = cur.fetchone()
            if src:
                new_bal = float(src["balance"]) - amount
                r = "BILL" + "".join(random.choices(string.digits, k=8))
                cur.execute("UPDATE accounts SET balance=%s WHERE id=%s", (new_bal, src["id"]))
                cur.execute("INSERT INTO transactions (account_id,txn_type,amount,"
                            "balance_after,counterparty_name,memo,channel,status,"
                            "reference) VALUES (%s,'debit',%s,%s,%s,%s,'online',"
                            "'completed',%s)",
                            (src["id"], amount, new_bal, biller,
                             f"Bill payment - {biller}", r))
                log_event("transaction", "bill_payment", username=u["username"],
                          src_ip=client_ip(), path=request.path,
                          detail=f"biller={biller} amount={amount} ref={r}")
                result = ("ok", f"Paid LKR {amount:,.2f} to {biller}. Ref {r}.")
            else:
                result = ("error", "Source account not found.")
    conn.close()
    billers = ["CEB - Electricity", "Water Board", "SLT - Telephone",
               "Dialog", "Mobitel", "Netflix LK", "Insurance Premium"]
    return render_template("payments.html", my_accounts=my_accounts,
                           billers=billers, result=result)


@app.route("/statements")
def statements():
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    acct_no = request.args.get("account", "")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM accounts WHERE customer_id=%s", (u["customer_id"],))
        my_accounts = cur.fetchall()
        txns = []
        if acct_no:
            # [VULN: IDOR - statement for any account number]
            cur.execute("SELECT a.*, c.full_name FROM accounts a "
                        "LEFT JOIN customers c ON c.id=a.customer_id "
                        "WHERE a.account_no=%s", (acct_no,))
            acct = cur.fetchone()
            if acct:
                cur.execute("SELECT * FROM transactions WHERE account_id=%s "
                            "ORDER BY ts DESC", (acct["id"],))
                txns = cur.fetchall()
                if acct["customer_id"] != u["customer_id"]:
                    log_event("access_control", "idor_statement", outcome="success",
                              severity="high", username=u["username"],
                              src_ip=client_ip(), path=request.full_path,
                              detail=f"statement for non-owned account {acct_no}")
            else:
                acct = None
        else:
            acct = None
    conn.close()
    return render_template("statements.html", my_accounts=my_accounts,
                           acct=acct, txns=txns, selected=acct_no)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    conn = get_db()
    msg = None
    if request.method == "POST":
        with conn.cursor() as cur:
            # [VULN: stored XSS via address; no re-auth for profile change]
            cur.execute("UPDATE customers SET email=%s, phone=%s, address=%s "
                        "WHERE id=%s",
                        (request.form.get("email", ""),
                         request.form.get("phone", ""),
                         request.form.get("address", ""), u["customer_id"]))
        log_event("account_change", "profile_update", username=u["username"],
                  src_ip=client_ip(), path=request.path)
        msg = "Profile updated."
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM customers WHERE id=%s", (u["customer_id"],))
        cust = cur.fetchone()
        cur.execute("SELECT * FROM cards WHERE customer_id=%s", (u["customer_id"],))
        cards = cur.fetchall()
    conn.close()
    return render_template("profile.html", cust=cust, cards=cards, msg=msg)


@app.route("/support", methods=["GET", "POST"])
def support():
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    conn = get_db()
    if request.method == "POST":
        with conn.cursor() as cur:
            # [VULN: stored XSS via subject/body]
            cur.execute("INSERT INTO support_tickets (customer_id,subject,body) "
                        "VALUES (%s,%s,%s)",
                        (u["customer_id"], request.form.get("subject", ""),
                         request.form.get("body", "")))
        log_event("support", "ticket_created", username=u["username"],
                  src_ip=client_ip(), path=request.path)
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM support_tickets WHERE customer_id=%s "
                    "ORDER BY id DESC", (u["customer_id"],))
        tickets = cur.fetchall()
    conn.close()
    return render_template("support.html", tickets=tickets)


# ---------------------------------------------------------------------------
#  "Admin" / staff area  (broken access control)
# ---------------------------------------------------------------------------
@app.route("/admin")
def admin():
    # [VULN: broken access control - ANY logged-in user reaches the admin panel;
    #        there is no role check for 'admin'/'teller']
    if not login_required():
        return redirect(url_for("login"))
    u = current_user()
    if u["role"] not in ("admin", "teller"):
        log_event("access_control", "admin_privilege_escalation",
                  outcome="success", severity="critical",
                  username=u["username"], src_ip=client_ip(), path=request.path,
                  detail=f"non-admin role '{u['role']}' accessed /admin")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT u.*, c.full_name, c.nic, c.email FROM users u "
                    "LEFT JOIN customers c ON c.id=u.customer_id ORDER BY u.id")
        users = cur.fetchall()
        cur.execute("SELECT a.*, c.full_name FROM accounts a "
                    "LEFT JOIN customers c ON c.id=a.customer_id ORDER BY a.id")
        accts = cur.fetchall()
        cur.execute("SELECT * FROM login_log ORDER BY id DESC LIMIT 20")
        logins = cur.fetchall()
    conn.close()
    log_event("admin_access", "view_admin_panel", username=u["username"],
              src_ip=client_ip(), path=request.path)
    return render_template("admin.html", users=users, accts=accts, logins=logins)


# ---------------------------------------------------------------------------
#  Unauthenticated JSON APIs (sensitive data exposure / IDOR)
# ---------------------------------------------------------------------------
@app.route("/api/customer/<int:cid>")
def api_customer(cid):
    # [VULN: no auth, IDOR - full PII for any customer id]
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM customers WHERE id=%s", (cid,))
        cust = cur.fetchone()
        cur.execute("SELECT account_no,account_type,balance,currency FROM accounts "
                    "WHERE customer_id=%s", (cid,))
        accts = cur.fetchall()
    conn.close()
    log_event("info_disclosure", "api_customer", outcome="success",
              severity="high", src_ip=client_ip(), path=request.path,
              detail=f"customer {cid} PII requested (unauthenticated)")
    import json as _j
    return Response(_j.dumps({"customer": cust, "accounts": accts}, default=str),
                    mimetype="application/json")


@app.route("/api/accounts")
def api_accounts():
    # [VULN: no auth - dumps every account + balance]
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT account_no,account_type,balance,currency,customer_id "
                    "FROM accounts")
        rows = cur.fetchall()
    conn.close()
    log_event("info_disclosure", "api_accounts_dump", outcome="success",
              severity="critical", src_ip=client_ip(), path=request.path,
              detail="all accounts enumerated (unauthenticated)")
    import json as _j
    return Response(_j.dumps(rows, default=str), mimetype="application/json")


@app.route("/debug")
def debug():
    # [VULN: config / environment disclosure]
    log_event("info_disclosure", "debug_endpoint", outcome="success",
              severity="high", src_ip=client_ip(), path=request.path)
    info = {"app": "senarath-bank",
            "env": {k: v for k, v in os.environ.items()
                    if k.startswith(("DB_", "LOG_", "FLASK_"))},
            "secret_key": app.secret_key, "version": "1.0.0"}
    import json as _j
    return Response(_j.dumps(info, indent=2), mimetype="application/json")


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /api/\n"
                    "Disallow: /debug\n", mimetype="text/plain")


@app.errorhandler(404)
def nf(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    common.wait_for_db()
    log_event("system", "app_start", detail="senarath-bank (SenNet) started")
    # [VULN: debug=True]
    app.run(host="0.0.0.0", port=8080, debug=True)
