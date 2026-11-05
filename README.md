# RASED — راصد

Offline, Arabic-first (RTL) network discovery, asset inventory and security-exposure monitoring
for networks your organisation owns and administers.

**Release 0.15.0.** See [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)
for exactly what is implemented and verified, and what is not yet built.

Beyond discovery and inventory, RASED now includes: logical + **physical (SNMP/LLDP) network maps**,
**Fusion** analytics, comprehensive **Arabic reports** (PDF/Excel/JSON + SHA-256), an offline
**CVE engine with EPSS + CISA KEV prioritisation**, **Active Directory** directory intelligence,
**approved-service baseline** and rogue detection, **maintenance windows + e-mail alerts**, an
**endpoint agent**, active **UDP** probing, anonymous **SMB** share browsing, **discovery
diagnostics**, import adapters (**Nmap / DHCP / CSV / Greenbone / Nessus / Wazuh / osquery**),
and **compliance mapping** (NCA ECC / ISO 27001 / PCI-DSS). All fully offline.

| | |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0, Alembic, PostgreSQL 17 (SQLite only for tests) |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 4, TanStack Query/Table, Apache ECharts, Cytoscape.js, Cairo font (bundled) |
| Scanning | Native engine: two-stage sweep, Windows IP Helper ICMP + ARP, TCP connect, reverse DNS, NetBIOS, SSDP/UPnP, banners, TLS metadata, traceroute |
| Intelligence | IEEE OUI vendors, evidence-based classification, network map (Cytoscape), Fusion Tables (ECharts) |
| Control | Credential vault (Fernet), WinRM (pypsrp) and SSH (paramiko, host-key pinning) command execution, audited |
| Security | Argon2id, server-side sessions, CSRF tokens, RBAC (admin / operator / auditor), audit log, rate limiting, scope approval |

## Repository layout

```
backend/
  rased/                 application package
    api/                 FastAPI routers (auth+users, scopes+scans, inventory+dashboard+audit)
    discovery/           tcp_probe, icmp, arp, dns, services (identification), fingerprint, oui, engine
    security/            passwords (Argon2id), rbac, ratelimit
    migrations/          Alembic environment + versions
    inventory.py         persistence + identity correlation + change detection
    jobs.py              background scan runner (cancellation, crash recovery)
    scope.py             scan-scope validation (the safety boundary)
    backup_crypto.py     AES-256-GCM backup encryption
    app.py / cli.py      app factory / `python -m rased …`
  tests/                 pytest suite (unit, integration, API, migrations, real loopback scans)
  requirements.lock      exact runtime versions
frontend/                React SPA (built to frontend/dist and served by the backend)
scripts/                 PowerShell: setup, start, install-service, backup, restore, upgrade, rollback, healthcheck
docs/                    architecture & threat model, Arabic admin guide, acceptance checklist
Dockerfile, docker-compose.yml   optional Linux deployment
```

## Quick start (development, Windows)

```powershell
# PostgreSQL: any reachable instance, e.g. a local container
docker run -d --name rased-db -e POSTGRES_USER=rased -e POSTGRES_PASSWORD=<pw> -e POSTGRES_DB=rased -p 127.0.0.1:5432:5432 postgres:17-alpine

cd backend
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
copy .env.example .env      # then edit RASED_DATABASE_URL; set RASED_COOKIE_SECURE=false for plain-HTTP dev
.venv\Scripts\python -m rased init-db
.venv\Scripts\python -m rased create-admin --username admin

cd ..\frontend
npm ci
npm run build               # or `npm run dev` (proxies /api to 127.0.0.1:8765)

cd ..\backend
.venv\Scripts\python -m rased serve --port 8765          # dev, HTTP
```

Production installation: `scripts\setup.ps1` (see the Arabic guide in `docs/ar/`).

## Tests

```powershell
cd backend
.venv\Scripts\python -m pytest                                   # SQLite, ~1.5 min
$env:RASED_TEST_DATABASE_URL = 'postgresql+psycopg://user:pw@127.0.0.1:5432/rased_test'   # DB is wiped!
.venv\Scripts\python -m pytest                                   # same suite on PostgreSQL

cd ..\frontend
npm test                    # vitest
npm run build; npm run check-offline   # fails if the bundle loads any external URL
```

Scanner tests run **real** TCP/TLS/ping probes against servers they start on `127.0.0.1`;
only ICMP/ARP/DNS are replaced by deterministic doubles in the API-level tests.

## CLI

```
python -m rased init-db                         apply migrations + seed roles/profiles
python -m rased create-admin --username U       create an administrator (prompts for password)
python -m rased import-oui oui.csv              import IEEE MA-L vendor registry (offline file)
python -m rased gen-cert --hostname rased.corp  self-signed TLS certificate
python -m rased encrypt-file / decrypt-file     backup encryption (used by scripts/backup.ps1)
python -m rased serve --cert C --key K          HTTPS server (single worker)
```

## Operating constraints

* Run a **single server process**: scan jobs and rate limiters live in-process.
* Scans only run against scopes an administrator approved; any change to a scope's range,
  exclusions or sensitivity revokes the approval.
* No exploitation, brute force, credential guessing, stealth or DoS techniques exist in the code.

## Quick start (any machine)

**Windows (one command)** — creates the venv, installs backend deps, builds the frontend,
writes `backend/.env`, applies migrations, creates the admin, and generates a TLS cert:

```powershell
cd scripts
.\setup.ps1 -DatabaseUrl 'postgresql+psycopg://rased:CHANGE_ME@127.0.0.1:5432/rased' -AdminUser admin -Hostname rased.local
.\start.ps1          # serves on https://127.0.0.1:8765
```

Install as a Windows service (auto-start): `.\install-service.ps1`.

**Docker (any OS)** — PostgreSQL + the app, built fully offline inside the image:

```bash
docker compose up -d --build
# first run: create an admin
docker compose exec app python -m rased create-admin --username admin
```

**Manual (any OS)**:

```bash
# backend
cd backend && python -m venv .venv
.venv/bin/pip install -r requirements.lock          # Windows: .venv\Scripts\pip
cp .env.example .env                                 # then edit: DB URL + a generated secret key
python -m rased gen-secret-key                        # put the output in RASED_SECRET_KEY
python -m rased init-db && python -m rased create-admin --username admin
# frontend
cd ../frontend && npm ci && npm run build
# run (serves the built frontend from backend)
cd ../backend && python -m rased serve --host 0.0.0.0 --port 8765
```

## Production mode

* Set a strong **`RASED_SECRET_KEY`** (`python -m rased gen-secret-key`) and a real PostgreSQL URL in `backend/.env` — never commit this file.
* Serve over **HTTPS**: `python -m rased serve --cert cert.pem --key key.pem` (or put RASED behind a TLS reverse proxy) and set `RASED_COOKIE_SECURE=true`.
* Run a **single process** (state is in-process); use `scripts/install-service.ps1` for auto-start, `scripts/backup.ps1` for encrypted backups, and `scripts/upgrade.ps1` / `rollback.ps1` for updates.
* Bind to `127.0.0.1` unless it is intentionally exposed; all access is RBAC-gated and audited.

## Publishing to GitHub

The repository is clean to publish: `.gitignore` excludes `backend/.env`, `.venv`,
`node_modules`, `dist`, certs, backups, logs and databases — **no secrets or build artifacts are tracked**.

```bash
git init && git add -A && git commit -m "RASED 0.11.0"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

Before pushing, confirm `git status` shows no `.env`, `*.sqlite`, `certs/` or `.venv/`.
See [LICENSE](LICENSE) for usage terms.
