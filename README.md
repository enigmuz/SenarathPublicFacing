# Senarath Bank — Security Simulation Lab

**A deliberately vulnerable fictional banking environment for SOC / SIEM detection training.**

> ⚠️ **THIS IS A TRAINING LAB. NOT A REAL BANK.**
> *Senarath Bank* is fictional. All customers, accounts, balances and transactions are
> seeded fake data. The applications are **intentionally insecure** so that attacks against
> them generate realistic telemetry for your CrowdStrike NG SIEM pipeline.
> **Never** put real people, real credentials, real money, or production data in here, and
> only run it on an **isolated** network (see *Safe operation*).

This repo contains the two DMZ-1 web applications from your reference architecture:

| # | Project | Role in architecture | Port | Stack |
|---|---------|----------------------|------|-------|
| 1 | `general-website/` | DMZ 1 — Web Server 1 (General public website) | `8090` | Flask + MariaDB |
| 2 | `online-banking/`  | DMZ 1 — Web Server 2 (SenNet online banking app) | `8091` | Flask + MariaDB |

Both log everything (access + security audit + auth) as **JSON lines** to `./siem-logs/`,
ready for your on-prem NG SIEM Log Collector to tail and forward to CrowdStrike NG SIEM.

---

## 1. Contents

```
senarath/
├── docker-compose.yml          # brings up db + both web apps
├── .env.example                # set WEB_URL / BANK_URL for your domain
├── Logo/logo.png               # Senarath Bank logo (used across both apps)
├── db/
│   └── init/                   # auto-run by MariaDB on first boot
│       ├── 00_user.sql         # app DB user + grants
│       ├── 01_schema.sql       # two databases: senarath_web, senarath_bank
│       └── 02_seed.sql         # fictional Sri Lankan customers/accounts/txns
├── general-website/            # PROJECT 1 — public site + CMS
│   ├── app.py  common.py  Dockerfile  requirements.txt
│   ├── templates/   static/(css,img)
│   └── logs/                   # (per-app) also mounted to ../siem-logs
├── online-banking/             # PROJECT 2 — SenNet online banking
│   ├── app.py  common.py  Dockerfile  requirements.txt
│   ├── templates/   static/(css,img)
│   └── logs/
└── siem-logs/                  # <-- POINT YOUR NG SIEM COLLECTOR HERE
    ├── general-website/        # access.log, audit.log  (JSON lines)
    ├── online-banking/         # access.log, audit.log, auth.log
    └── db/                     # MariaDB general query log
```

---

## 2. Quick start (Windows + Docker Desktop)

1. **Install Docker Desktop for Windows** (WSL 2 backend) → https://www.docker.com/products/docker-desktop/
   Start it and wait for the whale icon to say *Engine running*.
2. Open **PowerShell** in this folder:
   ```powershell
   cd "C:\Users\Laptop Outlet\Documents\Crypto_Projects\Crowdstike Event\Public_facing_Webapp and website"
   docker compose up -d --build
   ```
   First run pulls MariaDB + Python images and seeds the database (~2–3 min).
3. Open in your browser:
   * General website → **http://localhost:8090**
   * SenNet online banking → **http://localhost:8091**
4. Watch logs being produced:
   ```powershell
   docker compose logs -f online-banking
   dir .\siem-logs\online-banking
   ```
5. Stop / reset:
   ```powershell
   docker compose down            # stop (keeps the database volume)
   docker compose down -v         # stop AND wipe the DB (re-seeds on next up)
   ```

> If port 8090/8091/3307 is busy, edit the `ports:` lines in `docker-compose.yml`.

---

## 3. Lab credentials

All passwords are intentionally weak and stored as **unsalted MD5** (so cracking is part of the exercise).

### SenNet online banking — `http://localhost:8091`
| Username | Password | Role | Notes |
|----------|----------|------|-------|
| `kperera` | `password123` | customer | Kamal Perera — 2 accounts |
| `nsilva` | `123456` | customer | Nimal Silva |
| `sfernando` | `qwerty123` | customer | Saman Fernando — incl. a Rs. 2.5M FD |
| `ajayawardena` | `senarath` | customer | Anoma Jayawardena |
| `dbandara` | `dinesh123` | customer | Dinesh Bandara |
| `msenanayake` | `abc12345` | customer | Malini Senanayake — high balance |
| `sweerasinghe` | `password` | customer | Sunil Weerasinghe |
| `teller1` | `teller123` | **teller** | staff |
| `admin` | `admin123` | **admin** | full admin panel |

(Other customers: `cwickrama/nimal2023`, `irajapaksa/iloveyou`, `tgunawardena/sunil@123`, `rdissanayake/letmein`, `nherath/welcome1`.)

### General website CMS — `http://localhost:8090/admin`
| Username | Password | Role |
|----------|----------|------|
| `admin` | `Admin@123` | superadmin |
| `nsenanayake` | `senarath2024` | admin |
| `editor1` | `password` | editor |

### Database — `localhost:3307`
`senarath_app` / `App@12345` (app user), root `root` / `Root@12345`.

---

## 4. Built-in weaknesses (attack surface → SIEM signal)

Every item below is deliberate and tagged `# [VULN: ...]` in the source. The right-hand column is
what your SIEM should be able to *see* when it's exercised — that's the detection-engineering value.

### SenNet online banking
| Weakness | Where | OWASP | Telemetry it produces |
|----------|-------|-------|-----------------------|
| SQL injection in login | `/login` | A03 | `auth.log` failures; `audit.log` `attack_suspected` with `sqli` tag; SQL errors |
| Unsalted MD5 passwords, no lockout | login / DB | A07 | repeated `authentication/failure` from one IP (brute force / spray) |
| Username enumeration | `/login` error text | A07 | distinguishable failure messages |
| **IDOR** — view any account | `/account/<account_no>` | A01 | `audit.log` `access_control / idor_account_view` (severity high) |
| **IDOR** — statement for any account | `/statements?account=` | A01 | `access_control / idor_statement` |
| **Transfer from an account you don't own** | `/transfer` | A01 | `access_control / idor_transfer_source` (critical) + `transaction/funds_transfer` |
| No balance / no positive-amount check | `/transfer` | A04 | overdrafts & negative amounts in `transactions`, large/odd `funds_transfer` events |
| Broken access control to admin panel | `/admin` | A01 | `access_control / admin_privilege_escalation` (critical) |
| Unauthenticated PII API | `/api/customer/<id>` | A01/A02 | `info_disclosure / api_customer` (high) |
| Unauthenticated account dump | `/api/accounts` | A01 | `info_disclosure / api_accounts_dump` (critical) |
| Stored XSS | transfer memo, beneficiary, support ticket | A03 | `attack_suspected` with `xss` tag on submit |
| No CSRF protection | transfers, profile | A01 | state-changing requests with foreign `Referer` |
| Config/secret disclosure | `/debug` | A05 | `info_disclosure / debug_endpoint` |
| Weak session key, insecure cookies | app config | A05/A07 | forged-cookie sessions (no HttpOnly/Secure) |
| Verbose errors / Flask debug console | everywhere | A05 | stack traces, `/console` reachable |

### General website / CMS
| Weakness | Where | OWASP | Telemetry |
|----------|-------|-------|-----------|
| SQL injection | `/branches?city=`, `/news/<slug>`, CMS login, `/admin/messages?q=` | A03 | `sqli` tags, `sql_error` events, verbose errors |
| Stored XSS | contact message (admin inbox), news body | A03 | `xss` tag on submit; fires in `/admin/messages` |
| Reflected XSS | `/search?q=` | A03 | `xss` tag in query string |
| Broken access control | `/admin/messages.json` (no auth) | A01 | `access_control / messages_export` |
| Sensitive data exposure | `/admin/users` shows hashes; `/backup.sql` | A02 | `info_disclosure / backup_sql_accessed` (critical) |
| Unrestricted file upload | `/careers` CV upload → served from `/uploads/` | A05/A08 | `file_upload` (medium), uploads dir listing |
| Info disclosure | `/robots.txt`, `/debug` | A05 | `info_disclosure` events |
| Missing security headers | all responses | A05 | no CSP/HSTS/X-Frame-Options/nosniff |

> These are the same classes you'd find in DVWA / OWASP Juice Shop — just wrapped in a realistic
> bank so your analysts practise on something that *feels* like a real target.

---

## 5. Logging & SIEM integration

### Where logs go
Each app writes JSON-lines files into a host folder (bind-mounted):

| File | What |
|------|------|
| `siem-logs/online-banking/access.log` | every HTTP request |
| `siem-logs/online-banking/audit.log`  | security events (auth, IDOR, admin, transfers, disclosure…) |
| `siem-logs/online-banking/auth.log`   | every login attempt (brute-force/spray source) |
| `siem-logs/general-website/access.log` / `audit.log` | same for the public site |
| `siem-logs/db/general.log` | MariaDB query log (see the actual SQL that reached the DB) |

Audit events are **also** mirrored into the `audit_log` / `login_log` DB tables, and echoed to
`docker logs` (so the Falcon sensor on the host picks them up too).

### Event schema (every audit line is one flat JSON object)
```json
{
  "@timestamp": "2026-10-28T16:40:12.123456+00:00",
  "app": "senarath-bank",
  "log_type": "audit",
  "event_type": "access_control",
  "severity": "critical",
  "action": "idor_transfer_source",
  "outcome": "success",
  "username": "kperera",
  "src_ip": "203.0.113.45",
  "http_method": "POST",
  "path": "/transfer",
  "detail": "transfer initiated from non-owned account 1001000011",
  "amount": 500000.0,
  "from_account": "1001000011",
  "to_account": "1001000099"
}
```
Stable field names (`event_type`, `severity`, `action`, `outcome`, `src_ip`, `username`, `path`,
`attack_tags`) make parsing in CrowdStrike NG SIEM / LogScale trivial.

### Point the collector at it
Configure your **NG SIEM Log Collector (on-prem)** to tail `./siem-logs/**/*.log` and parse as JSON.
For the CrowdStrike **LogScale/NG SIEM** path, a Falcon Log Collector (`fdr`/`logscale-collector`)
file source like:
```yaml
sources:
  senarath-weblogs:
    type: file
    include: ["/data/senarath/siem-logs/**/*.log"]
    parser: json
```
Because `src_ip` honours `X-Forwarded-For`, keep that header accurate at your proxy/tunnel (see §7)
so the SIEM sees the real attacker IP.

### Detections worth building first
* Brute force / password spray → `event_type=authentication outcome=failure` grouped by `src_ip`.
* IDOR / priv-esc → `event_type=access_control severity in (high,critical)`.
* Injection attempts → `event_type=attack_suspected` / `attack_tags` contains `sqli`/`xss`.
* Sensitive exposure → `event_type=info_disclosure`.
* Anomalous transfer → `action=funds_transfer` with large/negative `amount`.

---

## 6. Deploying on your Windows host

1. **One machine runs everything** (Docker Desktop). Keep `docker compose up -d` running.
2. Set your public URLs so the inter-app links resolve on the internet. Copy `.env.example` → `.env`:
   ```
   WEB_URL=http://bank.<yourlabdomain>
   BANK_URL=http://banking.<yourlabdomain>
   ```
   then `docker compose up -d` again.
3. **Windows Firewall**: allow inbound on the ports you expose (8090/8091), or better, front them
   with the tunnel/proxy in §7 so you don't open the host directly.
4. Make it start on boot: Docker Desktop → *Settings → General → Start Docker Desktop when you log in*,
   and the compose services already use `restart: unless-stopped`.

---

## 7. Putting it on a public domain **without Cloudflare**

You're right that **Cloudflare Tunnel is a poor fit for this**: it terminates TLS at Cloudflare,
rides an outbound-only encrypted tunnel, and its WAF/bot-mitigation filters exactly the malicious
traffic you *want* to reach the box. For an attack-telemetry lab you want the raw requests to land on
your app so your sensors and SIEM see them. Here are three alternatives, best first.

### Option A (recommended) — Cheap VPS + reverse tunnel (`frp`), your own domain
Gives you a **stable public IP + real domain**, keeps your Windows host off the open internet, and
passes raw HTTP straight through so attacks hit the app.

1. Rent a small VPS with a public IP (DigitalOcean / Vultr / Linode / Hetzner, ~US$5/mo).
2. Point your domain's **A records** at the VPS IP:
   `bank.<domain> → VPS`, `banking.<domain> → VPS`.
3. On the **VPS** run `frps` (frp server); on the **Windows host** run `frpc` (frp client) pointing at
   your two containers (`localhost:8090`, `localhost:8091`). frp forwards public :80 → your boxes.
4. Put **nginx** on the VPS in front of frp so you can host both apps on one IP and inject the real
   client IP:
   ```nginx
   server {
     listen 80;
     server_name bank.<domain>;
     location / {
       proxy_pass http://127.0.0.1:18080;              # frp -> general-website
       proxy_set_header X-Forwarded-For $remote_addr;   # real attacker IP -> SIEM
       proxy_set_header Host $host;
     }
   }
   server {
     listen 80;
     server_name banking.<domain>;
     location / {
       proxy_pass http://127.0.0.1:18081;              # frp -> online-banking
       proxy_set_header X-Forwarded-For $remote_addr;
       proxy_set_header Host $host;
     }
   }
   ```
   (The apps already read `X-Forwarded-For`, so the SIEM logs the true source.)
   > Keep it **HTTP** (no TLS) if you want the attack traffic fully in the clear for the exercise, or
   > add a plain Let's Encrypt cert on nginx — either way nginx, not Cloudflare, is the edge, so
   > nothing is filtered.

   *Alternatives to frp with the same shape:* a **WireGuard** tunnel from the host to the VPS, then
   nginx `proxy_pass` over the tunnel; or an **SSH reverse tunnel**
   (`ssh -R 18080:localhost:8090 user@vps`). Same result — you own the edge.

### Option B (simplest, quick demos) — `ngrok`
```powershell
winget install ngrok
ngrok config add-authtoken <token>
ngrok http 8091          # public URL -> SenNet (run a second agent for 8090, or use a config file)
```
Gives an instant public HTTPS URL; traffic reaches your app (ngrok does **not** filter attacks like
Cloudflare's WAF). Trade-offs: random subdomain on the free tier (custom domains are paid), a
click-through interstitial on free HTTP, and the client IP arrives via `X-Forwarded-For`. Fine for a
short exercise; less ideal for a persistent, domain-branded lab. (Similar tools: `localtunnel`, `bore`.)

### Option C (most "raw", cheapest) — Router port-forward + Dynamic DNS
If your ISP gives you a **public (non-CGNAT) IP**:
1. Free dynamic DNS: **DuckDNS**, **No-IP**, or **afraid.org** → get `yourlab.duckdns.org` and run
   its updater on the host.
2. On your router, **port-forward** external 80→host:8090 and e.g. 8091→host:8091.
This is the most direct exposure — real source IPs, no middle-box, closest to a real DMZ edge and to a
honeypot. **But** it exposes your own network, so the isolation in §8 is non-negotiable. (Check for
CGNAT first: if your WAN IP ≠ the IP on https://ifconfig.me, you're behind CGNAT and Option A is the way.)

| | A: VPS + frp | B: ngrok | C: Port-forward + DDNS |
|---|---|---|---|
| Stable custom domain | ✅ | ⚠️ paid | ✅ (DDNS hostname) |
| Raw attacks reach app | ✅ | ✅ | ✅ |
| Real client IP to SIEM | ✅ (XFF via nginx) | ⚠️ (XFF) | ✅ (direct) |
| Hides your home network | ✅ | ✅ | ❌ |
| Cost | ~$5/mo | free/paid | free |
| Best for | persistent lab | quick demo | most realistic edge |

---

## 8. Safe operation (please read)

This box is **built to be broken into**. Treat it as hostile from day one:

* **Isolate it.** Run it on its own VLAN / dedicated machine with **no route to any real asset** (home
  PCs, work network, NAS). An exposed vulnerable host *will* be compromised and can be used to pivot or
  as a botnet node — that's expected; containment is your job.
* **No real data, ever.** Fake customers, fake money, lab-only passwords. Don't reuse any password here
  that you use anywhere else.
* **Watch egress.** Your CrowdStrike Falcon sensor on the host + the SIEM should alert on outbound
  connections from these containers — that's a great detection to build and your early warning that
  the box has been taken over.
* **Rebuild often.** `docker compose down -v && docker compose up -d --build` gives a clean, re-seeded
  environment in minutes. Do it between exercises.
* **Keep the simulation banner.** Every page shows a "SIMULATION — NOT A REAL BANK" ribbon so no human
  who stumbles onto it mistakes it for a real bank or enters real details. Leave it on.
* **Take it down when you're done.** Don't leave a vulnerable public banking-looking site up longer
  than the exercise needs.

---

## 9. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Apps show "waiting for database" | MariaDB still seeding on first boot — give it 1–2 min; `docker compose logs db`. |
| `Access denied for user 'senarath_app'` | DB volume predates a change — `docker compose down -v` then `up` to re-seed. |
| Inter-app links point at `localhost` on your domain | set `WEB_URL`/`BANK_URL` in `.env`, then `docker compose up -d`. |
| No logs in `siem-logs/` | confirm the bind mounts in `docker-compose.yml` and that the apps are running. |
| Port already in use | change the `ports:` mapping in `docker-compose.yml`. |

---

*Senarath Bank is a fictional institution created solely for cybersecurity simulation and SIEM
detection training. Any resemblance to a real bank is coincidental.*
