# Acceptance checklist — release 0.1.0

Legend: ✅ implemented and verified by an executed test or run · 🟡 partially implemented ·
❌ not implemented in this release. "Evidence" names the test or manual run that verified it.

## Specification §24 acceptance criteria

| # | Criterion | Status | Evidence / notes |
|---|---|---|---|
| 1 | Administrator can log in securely | ✅ | `test_login_session_csrf_logout`, `test_session_cookie_flags`, `test_account_lockout_and_admin_unlock`; HTTP smoke run |
| 2 | Configure an approved CIDR scope | ✅ | automatic discovery of attached/routed networks (`test_network_discovery.py`) + one-click add/approve/scan; `test_scope.py`, `test_boundary_change_revokes_approval`, `test_scope_validation_messages_are_arabic` |
| 3 | Discovers reachable authorised devices | ✅ | `test_engine_end_to_end_on_loopback`; smoke run on 127.0.0.1 (found 135, 445, 27017). Not yet run on a real LAN subnet (canary phase 2). |
| 4 | Discovery observations persisted | ✅ | `test_new_asset_is_persisted_with_provenance` (SQLite + PostgreSQL) |
| 5 | Asset details display correctly | 🟡 | API verified (`test_full_scan_flow_on_loopback`); UI typechecked and built, **not yet manually reviewed in a browser** |
| 6 | Authorised TCP service scans work | ✅ | real loopback probes: open/closed/banner/HTTP HEAD/TLS tests |
| 7 | Supported UDP discovery profiles work | 🟡 | UDP NetBIOS node-status (137) and SSDP/UPnP (1900) discovery run in every ARP-enabled profile and were verified on the live LAN (`test_netbios_request_and_response`, `test_ssdp_and_upnp_description_parsing`); generic UDP port scanning (SNMP, DNS, …) is not implemented |
| 8 | Classifications include confidence and evidence | ✅ | `test_identification.py`, evidence stored per fingerprint |
| 9 | Shared-folder metadata displayed | ❌ | SMB share enumeration not implemented (SMB *exposure* is reported) |
| 10 | Vulnerability findings linked to evidence | ❌ | vulnerability engine / CVE feeds not implemented |
| 11 | Endpoint health visible where agents installed | ❌ | agents not implemented |
| 12 | New assets generate alerts | ✅ | `test_new_asset_is_persisted_with_provenance` |
| 13 | New observed services generate change alerts | ✅ | `test_new_port_alert_and_service_closure`, API full flow |
| 14 | Fusion Tables query real records | ✅ | structured filters → parameterised SQL, grouping + charts, saved/shared views, CSV export with formula-injection defence (`test_fusion_query_spec_example_and_grouping`, `test_fusion_export_and_saved_views`); live: Windows + 445 open = 19 devices |
| 15 | Topology differentiates verified/inferred links | ✅ | Cytoscape map; edges carry `verified`; silent traceroute hops and multi-homed devices are `inferred` (`test_topology_graph`); native traceroute matches Windows `tracert` hop-for-hop |
| 16 | Reports export in Arabic | ❌ | reporting engine not implemented |
| 17 | Interface fully RTL | 🟡 | `dir="rtl"` shell, logical CSS properties, LTR isolation of identifiers (tested); browser review pending |
| 18 | Functions without Internet | ✅ | `npm run check-offline`; no CDN, fonts bundled, Swagger UI disabled; all runtime dependencies local |
| 19 | Access controls prevent unauthorised operations | ✅ | `test_rbac_matrix`, CSRF tests, `test_last_admin_cannot_be_removed` |
| 20 | Backups can be restored | ✅ | `test_backup_crypto.py`; manual run of `backup.ps1` → tamper rejected → `restore.ps1` restored exact row counts on PostgreSQL 17 |
| 21 | Scan jobs can be cancelled | ✅ | `test_concurrent_scan_on_same_scope_rejected_and_cancel`, `test_emergency_stop`, engine cancellation tests |
| 22 | Failures handled without corrupting inventory | ✅ | `test_failed_chunk_rolls_back_atomically`, `test_worker_failure_is_recorded_not_hidden`, `test_interrupted_jobs_recovered_on_startup`, `test_unprobed_port_is_not_closed` |
| 23 | Tests run with documented commands | ✅ | README "Tests" |
| 24 | Findings preserve timestamps and provenance | ✅ | job id + UTC timestamps on every observation; naive datetimes rejected |
| 25 | Reproducible deployment on a clean machine | 🟡 | `setup.ps1` written and syntax-checked; CLI steps it calls were executed; the script itself has **not** been run end-to-end on a clean machine |

## Adversarial / failure scenarios (§22)

| Scenario | Status | Evidence |
|---|---|---|
| Duplicate MAC addresses | ✅ | `test_duplicate_mac_in_one_scan_is_not_used_for_identity` |
| Randomised MAC addresses | ✅ | `test_rotating_randomized_mac_matched_by_hostname`, `test_randomized_mac_detection` |
| DHCP IP reassignment | ✅ | `test_dhcp_reassignment_does_not_merge_devices`, `test_same_mac_new_ip_is_same_asset` |
| Offline devices | ✅ | `test_offline_marking_and_recovery`, `test_offline_marking_respects_scope` |
| Firewalled devices / stale ARP | ✅ | `test_stale_neighbor_entry_does_not_prove_liveness` |
| False-positive service identification | ✅ | port-only identity marked low confidence; banner identity never downgraded |
| Interrupted scans | ✅ | cancellation + startup recovery tests |
| Database disconnection / worker crash | ✅ | `test_worker_failure_is_recorded_not_hidden` (simulated OperationalError) |
| Unexpected Unicode hostnames, malicious banners | ✅ | `test_hostname_sanitisation`, `test_banner_sanitisation`, `test_malicious_banner_is_neutralised` |
| Concurrent scan requests | ✅ | API 409 + DB partial unique index test |
| Invalid backup files | ✅ | `test_invalid_backup_files_rejected`, tamper test |
| Unauthorised network ranges | ✅ | public/multicast/reserved/oversized/IPv6 scope tests |
| Malformed scan output | ✅ | ping / ARP / ip-neigh / Get-NetNeighbor parser tests |
| Large scan result files, credential expiration, incorrect CVE correlation, partial imports, load tests | ❌ | depend on modules not yet built (imports, credentialed scans, CVE engine) |

## Executed test results (this build)

* Backend: **161 tests passed** on SQLite and on PostgreSQL 17 (including real SSH against an OpenSSH server and real loopback TCP/TLS/ICMP).
* Frontend: TypeScript strict typecheck clean, production build succeeds, `check-offline` OK, 27 vitest tests passed.
* Docker: image builds (frontend build + offline check inside the build); application imports in the
  Linux image. The test-suite has **not** been executed inside the Linux image yet.

## Added in release 0.2.0 (all verified by tests and on the live network)

* Discovery 22× faster (two-stage sweep, native Windows ICMP + ARP via IP Helper, local-segment timing): /20 in ~85–104 s.
* Device intelligence: IEEE OUI (40 439 vendors), NetBIOS name/workgroup/domain-controller, UPnP make/model/type, default-gateway role, smart-TV type.
* Scan control: automatic resume after interruption (exact offset), rerun/resume buttons, single-device rescan, schedules, custom profiles (port ranges).
* Fusion Tables, interactive network map with traceroute-based inter-network paths, networks-on-path suggestions.
* Credential vault (Fernet) + execution of guidance commands over WinRM / SSH (host-key pinning), admin command console, full audit of every command and its output.
* Router / network-device control over SSH: per-platform command sets (RouterOS / Cisco IOS / Linux-OpenWrt) — connected clients, routing/ARP/firewall, block a client by MAC, interface up/down, reboot — with strict parameter validation and full audit (`test_netadmin.py`, verified against a real OpenSSH device).
* Assets page: table / cards / points views; the points view plots every device as a colour-coded dot grouped by subnet (Fusion colour system).
* Data maintenance: delete a scan, wipe inventory (configuration and audit log kept).
* UI: Cairo font, redesigned layout, lazy-loaded pages (main bundle 1.5 MB → 294 kB).

**Not verified against a real Windows WinRM endpoint** (only a protocol double in tests): enable WinRM on one test host and run «اختبار الاتصال بالحساب» from the vault before relying on it.

## Added in release 0.3.0 (verified by tests and on the live network)

* **Reporting engine** (`rased/reports.py`, `api/reports.py`): a comprehensive Arabic assessment report — executive summary, per-device/per-network risk scoring, device-type/OS/exposure distributions, the exposed-ports catalogue with the administrator verify/close commands embedded per port, top exposed devices, high/critical alerts, scan history, remote-management activity and prioritised recommendations. Served as structured JSON with a **SHA-256 integrity digest**, as a downloadable JSON, and as a native **.xlsx workbook** (RTL, 7 sheets, via openpyxl). Frontend «التقارير» tab renders it with ECharts and a print-to-PDF stylesheet. Tests: `test_reports.py` (report sections, scoring, valid xlsx, integrity, permission gate).
* **Directory (Active Directory / LDAP) intelligence** (`rased/domain.py`, `api/domain.py`): authenticated, read-only enumeration with a vaulted domain account (NTLM for `DOMAIN\\user`, else simple/UPN bind; LDAP or LDAPS) — all users with per-account effective privileges derived from well-known privileged groups, UAC flags (disabled / password-never-expires / not-required / delegation / adminCount), all groups with membership, and domain computers. Never writes, never extracts password material, never attacks credentials. Frontend «مستخدمو الدومين» tab. Tests: `test_domain.py` (UAC decode, privilege derivation, parsing, summary).
* **Network map — Fusion radial-dots mode** (default): scanner at centre, networks as sized dots, devices cascading outward; added to `topologyModel.ts` + `Topology.tsx` (`test topology.test.ts` fusion case).
* New permissions `report:read` (admin/operator/auditor) and `directory:read` (admin/operator). New runtime deps: `ldap3`, `openpyxl` (both pure-Python, offline after install; pinned in `requirements.lock`).

## Added in release 0.4.0 (verified by tests; live SNMP/AD paths need a real device to confirm)

* **Physical topology over SNMP** (`rased/snmp.py`, `rased/physical.py`, `api/snmp.py`): authenticated read-only collection from a switch/router via a vaulted SNMP v2c account — walks **LLDP-MIB**, **CISCO-CDP-MIB** and the **BRIDGE-MIB forwarding table**, reconstructs port-to-port links, and resolves each neighbour to a known asset by MAC or system name. No SNMP SET is ever issued. New `physical_links` table; migration `0003`. Frontend «التوبولوجي الفيزيائي» tab (Cytoscape map + per-switch collection panel). Tests: `test_snmp.py` (LLDP/CDP/FDB parsing, MAC formatting, dedupe, resolution + graph).
* **Vulnerability (CVE) engine** (`rased/cve.py`, `api/cve.py`): import an **offline** JSON feed (RASED compact format, tolerant of a simplified NVD shape), correlate each open service's product+version against the feed's affected-version ranges (numeric-aware comparison, inclusive-start/exclusive-end), and record `asset_vulnerabilities`. Closed services auto-resolve. New `cve_entries` + `asset_vulnerabilities` tables. Frontend «الثغرات الأمنية» tab (import file/paste, severity summary, findings table). The main report and its Excel now carry a vulnerabilities section. Tests: `test_cve.py` (severity, version ranges, NVD normalisation, import+correlate, permission gate).
* Credential vault extended with an **SNMP** kind (v2c community); migration `0003` widens the `kind` CHECK constraint. New dep `puresnmp` (pure-Python, offline). Version 0.4.0.

## Added in release 0.5.0

* **Nmap XML import** (`rased/nmap_import.py`, `api/imports.py`): import an existing `nmap -oX` result file (no scanning performed). Parsed safely with defusedxml (XXE/entity-expansion rejected), then upserted into assets/services — tagged `nmap_import` / identification `import`, and it never overwrites a banner-confirmed service identity. Exposed at `POST /api/imports/nmap` (raw XML body; `scan:run`); the security middleware now allows a non-JSON body only on `/api/imports/*`. Frontend: an upload card on «سجل الفحوصات». Tests: `test_nmap_import.py` (parse, XXE safety, upsert that preserves banner identity, permission gate).

## Added in release 0.6.0 (verified by tests; live SMTP send needs the operator's mail server)

* **Approved-service baseline + unauthorised/rogue detection** (`rased/baseline.py`, `api/operations.py`, spec §6): an admin allow-list (`service_policy_rules`; port/device-type wildcards). Any open service matching no rule raises an `unauthorized_service` alert; more than one default gateway on a /24 raises a `rogue_gateway` alert — both auto-resolve when fixed. «اعتمد الوضع الحالي كخط أساس» bootstraps rules from current services.
* **Maintenance windows** (`maintenance_windows`): time (and optional subnet) ranges during which alert notifications are suppressed.
* **Alert e-mail notifications + escalation** (`rased/notify.py`): configurable internal SMTP (`notification_config`, password vaulted). The scheduler sends a digest of fresh alerts at/above a severity threshold, re-sends (escalates) criticals left open past a threshold, and skips assets under an active maintenance window. SMTP send is injectable (unit-tested); a «رسالة اختبار» endpoint verifies the live server. Frontend «السياسات والإشعارات» tab. Tests: `test_operations.py` (baseline/rogue, seed, digest, suppression, notify+escalate, API+permissions).
* Migration `0004` (three tables); scheduler gained a notification tick. Version 0.6.0.

## Added in release 0.7.0 (verified by tests; live agent/SNMPv3 paths need a real host/switch)

* **Import adapters** (`rased/importers.py`, `api/imports.py`): **DHCP leases** (ISC dhcpd + dnsmasq), **generic device CSV** (wireless-controller / MDM / spreadsheet exports, flexible column names) and **Greenbone/OpenVAS XML** reports (linked to known assets, creating CVE entries + findings). Parsed with defusedxml/csv and upserted offline. Frontend: a four-adapter upload card on «سجل الفحوصات». Tests: `test_importers.py`.
* **SNMPv3** collection: the vault SNMP credential also stores a v3 identity (user + auth/priv keys & algorithms, as an encrypted JSON blob); the collector builds a v3 session. Frontend vault gained a v2c/v3 switch. Tests extend `test_snmp.py`.
* **Endpoint agent** (`rased/agent_ingest.py`, `api/agents.py`, `agent/rased_agent.py`): enrollment tokens (SHA-256, shown once) managed under «السياسات والإشعارات»; a token-authenticated `POST /api/agents/report` ingests a host's self-report (hostname/OS/IP/MAC/listening ports). The reference agent is dependency-light (stdlib + optional psutil). New `agent_tokens` table (migration 0005). Tests: `test_agents.py`.
* Version 0.7.0.

## Added in releases 0.7.1–0.7.2

* **Directory auto-discovery** (0.7.1): the «مستخدمو الدومين» page detects the AD domain, base DN and domain controllers from the server's own domain membership, DNS and inventory, and binds **as the current Windows user over Kerberos (no password)** when the RASED host is domain-joined (`winkerberos`); otherwise a domain account can be added inline. `GET /api/directory/discover`; `credential_id` is now optional (null → integrated bind).
* **More import adapters** (0.7.2): **Nessus** (`.nessus` XML) and **Wazuh** (JSON) vulnerability reports, and **osquery** (JSON) device inventory — joining Nmap/DHCP/CSV/Greenbone. Frontend upload card now offers all seven. Tests extend `test_importers.py` / `test_domain.py`.

## Added in release 0.8.0 (probe builders + loopback behaviour unit-tested)

* **Active UDP service probing** (`rased/discovery/udp.py`, `api/udpscan.py`): protocol-specific probes for DNS, NTP, SNMP, NetBIOS, SSDP, mDNS, TFTP and ISAKMP. A port is marked **open only on a real reply**; an ICMP port-unreachable marks it closed; silence is `filtered` and never reported open (no false positives). No raw sockets/privileges. `POST /api/assets/{id}/udp-scan` requires the target to be in an **approved scope**; open ports are stored as `udp` services. Frontend: a «فحص منافذ UDP» panel on the asset page. Tests: `test_udp.py` (builders, live-loopback open/closed, silent-port-not-open, scope enforcement). Verified against a loopback responder.

## Added in release 0.8.1

* **Discovery diagnostics** (`rased/diagnostics.py`, `api/diagnostics.py`): `POST /api/diagnostics/reachability` runs ICMP, TCP connects, UDP probes and a short traceroute (all concurrent) against an IP and returns an Arabic verdict — in an approved scope or not; reachable, silent, or **blocked behind the gateway** (segment isolation). Frontend «لماذا لا يظهر جهاز؟» panel on the discovery page. This turns "a device isn't showing up" into an actionable explanation. Tests: `test_diagnostics.py`. (Diagnosed a real case live: a phone at 10.235.0.223 was unreachable — the gateway does not route the scanner's network to that segment.)

## Added in release 0.8.2

* **Manual device registration** (`POST /api/assets`, `asset:write`): register a known device by IP (name/MAC/type/notes) — for devices on segments the scanner cannot reach (e.g. an isolated-VLAN phone). Tagged `discovery_method = manual`; duplicate IP → 409, bad IP/type → 422. Frontend: an «إضافة جهاز يدوياً» form on the assets page. Tests: `test_manual_asset.py`.

## Added in release 0.8.3

* **Assets page UX**: the table now loads everything in one request (no pagination; `page_size` cap raised to **1000**), and **column headers are click-to-sort** (toggle asc/desc) across all columns, client-side. A note shows the count and warns if the 1000 cap is hit.
* **Screen preview for displays** (`ScreenPreview` on the asset page, for `tv`/`iot` devices): embeds the device's own served web page (what a public, network-owned signage display renders) in a sandboxed iframe, with per-service buttons and an open-in-tab link. Viewing what the display already serves on the network — no protection is bypassed. CSP gained `frame-src 'self' http: https:` (framing only; scripts/connections stay `'self'`).

## Added in release 0.9.0

* **Anonymous SMB share browsing** (`rased/smbshares.py`, `api/smbshares.py`, spec §7): read-only, guest/anonymous only — lists accessible public shares (probing common names) and browses folders/files (names/sizes, never contents); protected shares are reported and skipped (no credentials ever sent); admin shares (IPC$/C$/ADMIN$) and path traversal are blocked. Frontend «الملفات المشتركة للعامة» panel. Tests: `test_smbshares.py`. *(Verified live: all 30 SMB devices on the test network reject anonymous access — correctly reported as protected, none browsed.)*
* **Much stronger device identification**: `fingerprint.py` gained many signatures — smart-TV/streaming ports (Chromecast/DIAL 8008/9, Roku 8060, AirPlay, ADB 5555→Android, Samsung), MikroTik Winbox 8291→router, WSD 5357→Windows, NFS/AFP/Plex→NAS, SNMP+network-vendor→network device, a TV-brand vendor list, and far more model/hostname markers. Tests extend `test_identification.py` (20 pass).
* **One-click re-scan of all approved scopes** (`POST /api/scans/rescan-all`) with a reusable button on the Assets and Network-map pages.
* **CVE feed export** (`GET /api/cve/export`): download the current CVE database as editable JSON (or a template) for IT to edit/add and re-import. (Updates stay offline — no automatic internet fetch.)
* **Audible alert for new serious vulnerabilities**: a header bell that beeps (Web Audio, offline) when open critical/high findings increase, with a persisted mute/unmute toggle.
* **Manual device registration** and **active UDP probing** and **screen preview for displays** (0.8.x) remain.

## Added in release 0.10.0 — world-class roadmap item #1

* **Compliance mapping** (`rased/compliance.py`, `api/compliance.py`): evaluates RASED's own inventory against **NCA ECC (Saudi)**, **ISO/IEC 27001:2022** and **PCI-DSS 4.0** controls — automated checks for cleartext protocols, exposed RDP/SMB, unresolved critical/high vulnerabilities, unauthorised services + rogue gateways, asset/scan coverage, audit logging and encrypted remote admin; non-automatable controls are marked `manual`. Produces a per-framework score + control table, downloadable as JSON (per framework or all). Frontend «الامتثال للمعايير» tab. Tests: `test_compliance.py`. *(Live: NCA ECC/ISO/PCI ≈ 71% on the test network.)*

## Added in release 0.11.0 — world-class roadmap item #2

* **EPSS + CISA KEV risk prioritisation** (`rased/cve.py`, `api/cve.py`, migration 0006): import a FIRST **EPSS** CSV (`POST /api/cve/epss`) and the **CISA KEV** catalog (`POST /api/cve/kev`), enriching CVE entries with exploit-prediction scores and a known-exploited flag. A single **priority score (0–100)** combines CVSS + EPSS + KEV (KEV floors at 90 = critical priority), and the vulnerabilities list is sorted by it with EPSS%/KEV columns and a KEV badge; the summary shows open KEV findings. Tests extend `test_cve.py` (priority formula, EPSS/KEV import, prioritisation).

## Added in release 0.12.0 — world-class roadmap item #3 (partial) + production/GitHub readiness

* **Deeper fingerprinting via SNMP** (`rased/snmp.py`): reads **sysObjectID** and maps the enterprise number (1.3.6.1.4.1.**N**) to a vendor + device-type, refined by **sysDescr** keywords (RouterOS/switch/printer/Windows/Linux). The physical-collect endpoint now applies this identity to the asset (filling weak/unknown vendor, device type, OS). Tests in `test_snmp.py`. *(Other deep-fingerprint signals — DHCP option-55, JA3/JA4, favicon hash — remain for a later pass as they need new scan-engine inputs.)*
* **Production & GitHub readiness**: refreshed `README.md` (quick-start for Windows one-command / Docker / manual, a Production-mode section, and a Publishing-to-GitHub section); added `LICENSE` (proprietary, editable); hardened `.gitignore` (no `.env`, `.venv`, `node_modules`, `dist`, certs, DBs, logs tracked); initialised a git repository with a clean initial commit (195 files, no secrets). `scripts/` already provides `setup.ps1`, `start.ps1`, `install-service.ps1`, `backup.ps1`, `upgrade.ps1`, `rollback.ps1`; `Dockerfile` + `docker-compose.yml` build and run fully offline.

## Added in release 0.13.0 — world-class roadmap items #4 and #3 (completed)

* **Active Directory attack-path analysis** (`rased/attackpaths.py`, `api/directory/attack-paths`, plan item #4): over the enumerated users/groups it computes which accounts reach a privileged group (Domain Admins / Enterprise Admins / Administrators…) **directly or through nested group membership**, with the shortest path, plus risky-account flags (disabled-but-privileged, password-never-expires, delegation, nested escalation). Frontend «مسارات الهجوم» panel on the directory page. Tests: `test_attackpaths.py`.
* **Fingerprint hash primitives** (`rased/discovery/fphash.py`, plan item #3 completion): dependency-free **MurmurHash3** (verified against reference vectors), Shodan-style **favicon hash**, **JA3** TLS fingerprint, **DHCP option-55** fingerprint, and **SSH host-key SHA256** — ready to feed from captured scan inputs. Tests: `test_fphash.py`.

## Not yet built (next phases — "world-class" plan)

0. (done 0.10.0) Compliance mapping NCA ECC / ISO 27001 / PCI-DSS.
0. (done 0.11.0) EPSS + CISA KEV risk prioritisation.
0. (done 0.12.0) SNMP sysObjectID fingerprinting + production/GitHub packaging.
0. (done 0.13.0) AD attack-path analysis (#4) + fingerprint hash primitives (#3).
1. **Passive discovery + distributed collectors** (plan item #5) — needs a live capture source (SPAN/TAP/NetFlow) and multi-host deployment; cannot be built/verified offline on a single host. The import adapters + endpoint agent are the offline-buildable parts already shipped.
2. Wiring the remaining fphash primitives (DHCP option-55, TLS JA3) into the engine — these need passive capture / crafted TLS probes (part of item #5). The **favicon hash is now wired** (0.14.0).

## Added in release 0.15.0

* **Distributed collectors** (`rased/collectors.py`, `api/collectors.py`, CLI `rased forward`): a RASED instance on another segment forwards its inventory to a central RASED over token-authenticated HTTPS (`POST /api/collectors/report`), so devices the central server cannot reach directly (isolated VLANs, remote sites) still appear centrally — the offline-buildable half of the "distributed collectors" roadmap item. Tests: `test_collectors.py`.
* **Security & clean-code hardening pass**: `pip-audit` reports **0 dependency CVEs**; `bandit` reports **0 findings** (the one real item — JA3's MD5 — fixed with `usedforsecurity=False`; SSH exec and the outbound forward URL annotated `# nosec` with rationale; documented false-positive categories configured in `[tool.bandit]`); `ruff` is **all-pass** (`[tool.ruff]` config). Production Docker image now excludes tests, dev requirements and docs.

## Added in release 0.14.0

* **Web fingerprinting** (`rased/webfp.py`, `POST /api/assets/{id}/web-fingerprint`): for each open web port, fetches the landing page + `/favicon.ico` from the device's own address and captures the **Server header, page title, and Shodan-style favicon hash** (via the `fphash` primitive). Read-only, bounded, tolerates self-signed certs, no proxy. Frontend «بصمة الويب» panel on the asset page. Tests: `test_webfp.py` (against a local HTTP server). This wires plan item #3's favicon primitive into a real feature.
2. Deeper fingerprinting: DHCP option-55, JA3/JA4, favicon hash, SSH-key hash, SNMP sysObjectID — plan item #3.
3. AD attack-path analysis over the directory data — plan item #5.
4. Passive discovery + distributed collectors (needs live network) — plan item #4.
5. mDNS/SSDP sweep, rogue DHCP/DNS probing, authenticated SMB auditing, live MDM/Wi-Fi APIs.
2. *Authenticated* SMB share auditing (vaulted creds); live MDM/Wi-Fi-controller APIs.
3. Ethernet cable-length readout — only available from managed switches that expose cable-diagnostic (TDR) MIBs over SNMP; not generally possible. The nearest RASED signal is traceroute hop distance (already shown in topology/diagnostics).
