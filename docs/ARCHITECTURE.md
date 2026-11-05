# Architecture, threat model and compatibility assessment

## 1. Architecture

```
 Browser (RTL Arabic SPA, same origin, no CDN)
        │ HTTPS, session cookie (HttpOnly, Secure, SameSite=Strict) + X-CSRF-Token
        ▼
 FastAPI app (single process)
   ├─ hardening middleware: CSP, frame/sniff/referrer headers, per-IP rate limit,
   │  Origin / Sec-Fetch-Site check, JSON-only bodies
   ├─ auth & RBAC dependencies  ──►  audit_logs
   ├─ routers: auth/users · scopes/profiles/scans · assets/services/alerts/events/dashboard/audit
   └─ JobRunner (ThreadPoolExecutor, max_concurrent_jobs)
          └─ ScanEngine (asyncio, per job)
               liveness: ICMP (OS ping) + TCP connect to discovery ports  ─┐
               neighbour table (Get-NetNeighbor / ip neigh)                 │ chunks of 256 hosts
               reverse DNS, TCP service probes, passive banners, TLS meta  ─┘
                  │ observations per chunk
                  ▼
          InventoryRecorder (one DB transaction per chunk)
               identity correlation → assets / identifiers / ip_observations
               services / service_observations / device_fingerprints / scan_results
               change detection → events + de-duplicated alerts
        ▼
 PostgreSQL (Alembic-managed schema)
```

### Key design decisions

| Decision | Reason |
|---|---|
| Native Python engine instead of mandatory Nmap | Works on a clean Windows host with no extra binaries or Npcap; full TCP connect only (no raw packets). An Nmap XML import adapter is planned as an optional integration. |
| Chunked scanning with per-chunk transactions | Bounded memory for /16 scopes; an interrupted scan keeps everything already observed; a failing chunk rolls back atomically. |
| Global token bucket + global semaphore + per-host semaphore | Protects production availability: configurable packet rate, concurrency and per-target load. |
| Neighbour entries only prove liveness when *reachable* | Stale ARP cache entries can outlive a device by hours. |
| Probe result `None` when cancelled | "Not probed" is never confused with "filtered", so cancelling cannot mark services closed. |
| Scope snapshot stored on each job, re-validated at execution | History is reproducible and the safety boundary is enforced twice. |
| Partial unique index: one active job per scope | Concurrent requests cannot start duplicate scans even under races. |
| Classification via noisy-OR of weighted evidence, threshold 0.5 | Confidence grows with independent evidence but never reaches 100 %; weak evidence yields "unknown — requires review". |
| Timezone-aware UTC everywhere (`UTCDateTime`) | Naive datetimes are rejected at bind time. |

### Identity correlation (DHCP-safe)

1. MAC seen for exactly one IP in the job → identity. Unknown MAC reuses the asset holding the
   IP only if that asset has no MAC and no conflicting hostname.
2. MAC seen on several IPs in one job (proxy ARP, spoofing) → ignored for identity, alert raised.
3. Unknown *randomised* MAC → may match an asset with the same hostname whose MAC is also randomised.
4. No usable MAC → hostname, then current IP unless the hostname conflicts.

## 2. Threat model (STRIDE summary)

Assets protected: inventory data (network map is sensitive reconnaissance data), credentials,
audit trail, availability of the production network.

| Threat | Mitigation in this release |
|---|---|
| **S**poofed user / session theft | Argon2id hashes; 256-bit random session tokens stored as SHA-256; HttpOnly+Secure+SameSite=Strict cookies; idle (60 min) and absolute (8 h) expiry; sessions revoked on password change/role change/deactivation; generic login errors; constant-time dummy hash for unknown users. |
| Password guessing against the UI | Per-account lockout (5 failures / 15 min), per-IP login rate limit, audit of every failure. |
| **T**ampering via CSRF | Per-session CSRF token required on all state-changing requests; Origin and Sec-Fetch-Site checks; JSON-only request bodies (blocks form posts). |
| Malicious device banners / hostnames (stored XSS, terminal injection, bidi spoofing) | Control/format characters (incl. bidi overrides) stripped, length capped; React output encoding; strict CSP (`script-src 'self'`). |
| SQL injection / arbitrary queries | ORM only; sort fields whitelisted; LIKE wildcards escaped; no raw SQL endpoint. |
| **R**epudiation | `audit_logs` for login/logout, denied authorisation, users, scopes, approvals, scans, cancels, emergency stop, asset edits, alert transitions. |
| **I**nformation disclosure | Role-based read permissions; no CDN/telemetry; Swagger UI disabled; `.env`/key files ACL-restricted by setup; backups AES-256-GCM encrypted, plaintext dump deleted. |
| **D**enial of service to production network | Explicit scope approval; private ranges only by default; host-count cap; IPv6 enumeration limited to /120; sensitive scopes restricted to the safe profile; rate/concurrency/per-host limits; cancellation and emergency stop; no intrusive profiles. |
| DoS against RASED | API rate limit; paginated queries with max page size; bounded chunk memory. |
| **E**levation of privilege | Permission checked per endpoint; last active admin cannot be removed; operators cannot approve scopes; auditors are read-only. |
| Scanner abused to attack third parties | Public ranges rejected unless explicitly enabled; scope re-validated at execution; full audit trail. |

Residual risks / out of scope for 0.1.0: no MFA; in-memory rate limiter resets on restart;
the server must run under a least-privilege account (documented, not enforced);
TLS certificate is self-signed unless replaced with an internal-CA certificate.

## 3. Technology compatibility assessment (verified on this build machine)

| Component | Version used | Status |
|---|---|---|
| Python | 3.12.x (3.14 also present; 3.12 chosen for broad wheel availability) | ✅ test-suite passes |
| PostgreSQL | 17 (container `postgres:17-alpine`) | ✅ full suite + migration diff + backup/restore |
| FastAPI / Starlette | 0.162.0 / 1.10.0 (lifespan API, no deprecated startup hooks) | ✅ |
| SQLAlchemy / Alembic | 2.0.57 / 1.20.1 | ✅ migration == models (autogenerate diff empty) |
| psycopg | 3.3.7 (binary wheels) | ✅ |
| React / Router / TanStack Table | 19.3 / 8.5 / 9.3 (v9 `useTable` API) | ✅ typecheck + build |
| TypeScript / Vite / Tailwind | 7.0 / 8.3 / 4.3 | ✅ |
| Windows neighbour table | `Get-NetNeighbor` (≈4–5 s per call, once per 256-host chunk) | ✅ executed on Windows 10 |
| Windows ping | `%SystemRoot%\System32\PING.EXE`, TTL-based reply detection | ✅ executed |

Not used in this release (planned integrations): Nmap, Npcap, Scapy, SNMPv3, WMI/WinRM, SSH,
SMB enumeration, mDNS/SSDP/LLDP, osquery, Wazuh, Greenbone, Redis, APScheduler, Cytoscape.js.
