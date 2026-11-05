# MASTER ENGINEERING PROMPT
## Build an Enterprise-Grade, Fully Offline, Arabic-First Network Discovery, Security Assessment, Asset Intelligence, and Monitoring Platform

You are acting as a principal cybersecurity architect, senior network engineer, enterprise software architect, Python engineer, security researcher, database architect, DevSecOps engineer, and senior Arabic UX/UI designer.

Your mission is to DESIGN, IMPLEMENT, TEST, DOCUMENT, and PACKAGE a production-oriented, fully local network security management platform for an organization that owns and administers its internal computer networks.

**Product working name:** RASED — راصد

**Primary interface language:** Arabic (Egyptian-friendly terminology, professional Modern Standard Arabic for technical labels).

**Interface direction:** RTL, with correct LTR handling for IP addresses, MAC addresses, commands, protocols, file paths, and technical identifiers.

**Primary deployment:** Windows 10/11 and Windows Server, with optional Linux-based scanning workers.

**Primary operating principle:** 100% local operation, with no mandatory cloud dependency, external telemetry, SaaS account, external API, or Internet access.

The platform must operate on explicitly authorized network ranges and managed assets only.

Do not produce a mockup, a superficial dashboard, a demonstration-only application, or disconnected code snippets.

Deliver a functional, modular, maintainable software system with real discovery engines, persistent data, working APIs, background jobs, security controls, tests, and deployment instructions.

---

# 1. CORE PRODUCT VISION

Create a centralized network security command center that provides comprehensive visibility into:

- Every discoverable IP address.
- Every discoverable device.
- Online and offline devices.
- Windows computers.
- Linux computers.
- macOS computers.
- Android and iOS phones.
- Tablets.
- Printers.
- Network-attached storage.
- Routers and gateways.
- Managed switches.
- Wireless access points.
- IP cameras.
- IoT equipment.
- Virtual machines.
- Hypervisors.
- Containers.
- Servers.
- Unauthorized services.
- Open ports.
- Network protocols.
- Shared folders.
- Exposed services.
- Software vulnerabilities.
- Operating-system weaknesses.
- Missing security updates.
- Endpoint health issues.
- Network configuration weaknesses.
- Unexpected changes.
- Unknown and newly connected devices.
- Rogue DHCP services.
- Unexpected DNS services.
- Potentially unauthorized servers.
- Shadow IT.
- Configuration drift.
- Network topology and asset relationships.

The system must clearly distinguish verified findings, inferred observations, and unknown information.

Never claim perfect discovery or zero false positives.

---

# 2. REQUIRED TECHNOLOGY STACK

Use the following preferred architecture unless a better technically justified alternative exists.

Backend:
- Python 3.13 or a verified compatible supported version.
- FastAPI.
- SQLAlchemy 2.x.
- Pydantic.
- PostgreSQL.
- Alembic database migrations.
- Redis or a local persistent task queue where justified.
- APScheduler or an equivalent reliable scheduler.
- Structured JSON logging.

Frontend:
- React.
- TypeScript.
- Vite.
- Tailwind CSS.
- Professional component library with accessible RTL support.
- TanStack Table.
- TanStack Query.
- ECharts or Apache ECharts.
- Cytoscape.js for network topology.
- Arabic-compatible typography.

Scanning and inventory integrations:
- Nmap.
- Npcap on Windows where required.
- Scapy where supported.
- psutil.
- SNMPv3.
- WMI/CIM.
- WinRM over HTTPS.
- SSH.
- SMB discovery.
- mDNS.
- SSDP.
- LLDP where observable.
- DHCP lease imports.
- ARP and IPv6 neighbor discovery.
- DNS and reverse DNS.
- Optional osquery agents.
- Optional Wazuh integration.
- Optional Greenbone/OpenVAS integration.

Use only legitimate, maintained, appropriately licensed dependencies.

Do not fabricate library APIs, scanner capabilities, or compatibility.

All dependencies must be pinned and auditable.

---

# 3. NETWORK DISCOVERY ENGINE

Implement multiple discovery strategies.

## 3.1 IPv4 discovery

Support:

- ICMP echo discovery.
- ARP discovery within the appropriate local broadcast domain.
- TCP-based host discovery.
- DNS resolution.
- Reverse DNS.
- DHCP lease correlation.
- Passive observations from authorized network sensors.
- SNMP-based discovery of managed network equipment.

Support CIDR ranges such as:

192.168.1.0/24
10.0.0.0/24
172.16.0.0/16

The administrator must explicitly configure and approve scanning scope.

## 3.2 IPv6 discovery

Support:

- IPv6 neighbor discovery.
- ICMPv6.
- IPv6 DNS records.
- Observed IPv6 addresses.
- Explicitly scoped IPv6 host discovery.

Never attempt exhaustive brute-force enumeration of large IPv6 address spaces.

## 3.3 Discovery accuracy

For each asset record:

- IP address.
- IPv6 addresses.
- MAC address, if observable.
- Manufacturer, if identifiable.
- Hostname.
- DNS name.
- Operating system.
- OS version, if verified.
- Device type.
- Device category.
- Network interface.
- VLAN, if available.
- Subnet.
- Gateway.
- Discovery method.
- First seen.
- Last seen.
- Last successful scan.
- Current status.
- Confidence score.
- Evidence source.

Avoid incorrectly merging devices when DHCP changes IP assignments.

Use multiple identifiers and historical correlation.

---

# 4. ADVANCED DEVICE FINGERPRINTING

Create a device identification engine capable of distinguishing:

- Desktop computers.
- Laptops.
- Smartphones.
- Tablets.
- Printers.
- NAS devices.
- Network switches.
- Routers.
- Wireless access points.
- Cameras.
- Virtual machines.
- Hypervisors.
- Servers.
- IoT devices.

Use multiple signals:

- MAC OUI.
- DHCP fingerprints.
- DNS names.
- mDNS records.
- SSDP announcements.
- SNMP system descriptions.
- Service banners.
- HTTP response metadata.
- TLS certificate metadata.
- OS fingerprints.
- Authorized endpoint agents.
- Switch and wireless-controller inventory.

Implement evidence-based classification.

Display:

"نوع الجهاز: هاتف محمول — الثقة 82%"

or:

"نوع الجهاز: غير مؤكد — يتطلب مراجعة"

Do not infer a specific smartphone model unless reliable evidence exists.

---

# 5. PORT AND SERVICE INTELLIGENCE

Build an authorized port and service assessment engine.

Support:

- TCP port discovery.
- Selected UDP service discovery.
- Configurable port profiles.
- Common service identification.
- Service version detection where reliable.
- TLS configuration inspection.
- HTTP/HTTPS service identification.
- SMB.
- RDP.
- SSH.
- FTP.
- DNS.
- DHCP.
- SNMP.
- SMTP.
- LDAP.
- Kerberos.
- Database services.
- Remote management services.
- Printer services.
- Web administration interfaces.

For each observed service record:

- Asset ID.
- IP address.
- Port.
- Protocol.
- State.
- Service name.
- Version.
- Discovery timestamp.
- Exposure category.
- Business justification.
- Security assessment.
- Evidence.
- Recommended remediation.

Do not assume that a high number of open ports automatically means a device is vulnerable.

Classify risk according to service configuration, exposure, asset criticality, and verified weaknesses.

Provide comparisons between consecutive scans.

---

# 6. UNAUTHORIZED SERVER DETECTION

Detect devices potentially hosting services that were not approved.

Examples:

- Unexpected web servers.
- Unauthorized database services.
- Unexpected FTP servers.
- Unapproved remote administration.
- Rogue DHCP servers.
- Unapproved DNS resolvers.
- Unknown file servers.
- Unexpected proxy services.
- Unauthorized container-exposed services.

Implement a configurable approved-service baseline.

Compare observed services with the approved baseline.

Generate alerts such as:

"تم اكتشاف خدمة ويب غير معتمدة على الجهاز PC-014"

Include:

- Device.
- IP.
- Service.
- Port.
- First detected.
- Confidence.
- Supporting evidence.
- Recommended investigation.
- Approval status.

Do not automatically label a service malicious merely because it is unexpected.

---

# 7. FILE SHARING AND SMB AUDITING

Create a safe file-sharing visibility module.

Detect:

- SMB availability.
- Authorized share enumeration.
- Share names.
- Administrative shares where authorized.
- Guest-access configuration.
- Anonymous access exposure.
- SMB signing configuration.
- SMB protocol versions.
- Potentially unsafe legacy SMB configurations.
- Excessively permissive share permissions.
- Excessively permissive NTFS permissions, where credentialed access allows verification.
- Unexpected shared folders.

For Windows endpoints, use read-only authenticated administrative queries.

For every finding, explain whether the evidence comes from:

- Network observation.
- Authenticated SMB query.
- Endpoint agent.
- Imported configuration.

Never retrieve file contents as part of routine share discovery.

Do not enumerate sensitive file contents or user documents.

Provide an Arabic report showing:

"المجلدات المشتركة"
"مستوى الصلاحيات"
"المستخدمون والمجموعات المصرح لهم"
"مخاطر المشاركة"
"الإجراء المقترح"

---

# 8. VULNERABILITY ASSESSMENT ENGINE

Implement a defensive vulnerability management subsystem.

Use:

- Local CVE intelligence database.
- Offline vulnerability feed imports.
- Vendor advisories imported by administrators.
- Software inventory.
- Operating-system inventory.
- Authenticated patch inventory.
- Nmap service metadata.
- Optional Greenbone integration.
- Optional Wazuh findings.
- Optional osquery results.

The application must work without Internet access after installation and offline feed provisioning.

For every finding, record:

- CVE ID, when applicable.
- CVSS score and version.
- Severity.
- Affected product.
- Affected version.
- Installed version.
- Fixed version, when known.
- Asset criticality.
- Evidence.
- Detection method.
- Confidence.
- Remediation.
- Detection date.
- Last verified date.
- False-positive status.
- Remediation status.

Do not classify version-only matches as confirmed exploitation or confirmed vulnerability without sufficient evidence.

Provide:

- Critical vulnerabilities.
- High vulnerabilities.
- Medium vulnerabilities.
- Low vulnerabilities.
- Informational findings.

Implement configurable risk prioritization based on:

- Severity.
- Exposure.
- Asset importance.
- Exploitability intelligence when available.
- Detection confidence.
- Compensating controls.

No exploit execution, brute-force attacks, credential attacks, or destructive validation.

Any intrusive security testing must be excluded from automatic scanning and require a separately approved process.

---

# 9. ENDPOINT HEALTH MONITORING

Provide optional lightweight endpoint agents for managed devices.

Collect only administrator-approved operational metrics:

- CPU usage.
- RAM usage.
- Disk utilization.
- Disk health where supported.
- Network adapter status.
- OS uptime.
- Reboot pending.
- Security update status.
- Windows Defender status.
- Firewall status.
- Service health.
- Critical system event summaries.
- Hardware inventory.
- Software inventory.
- Local listening services.
- Local network connections metadata.
- Endpoint configuration compliance.

Support Windows initially.

Design Linux support as an extension.

Use authenticated, encrypted communications.

Implement signed agent packages and secure enrollment.

Do not collect passwords, private user documents, browsing history, message contents, or keystrokes.

---

# 10. SMARTPHONE AND WIRELESS VISIBILITY

Create a module for discovering mobile devices visible through authorized infrastructure.

Integrate where supported with:

- DHCP leases.
- Wireless controller inventory.
- Access point client lists.
- Managed switch information.
- DNS.
- mDNS.
- MDM exports.
- Network access control systems.

Show:

- IP address.
- MAC address where observable.
- Randomized MAC indicator when inferable.
- Device type.
- Manufacturer when reliable.
- Hostname.
- Wireless SSID if available.
- Access point if available.
- VLAN.
- First seen.
- Last seen.
- Connection status.
- Confidence.

Clearly explain that encrypted traffic, randomized MAC addresses, client isolation, VLAN boundaries, and unavailable controller access can limit identification.

Do not promise to identify every phone model or user.

---

# 11. NETWORK TOPOLOGY VISUALIZATION

Create a professional interactive topology engine.

Display:

- Subnets.
- Routers.
- Switches.
- Access points.
- Computers.
- Servers.
- Printers.
- Mobile devices.
- Network relationships.

Use Cytoscape.js.

Features:

- Zoom.
- Pan.
- Search.
- Filter.
- Group by VLAN.
- Group by subnet.
- Group by device type.
- Group by risk.
- Group by online/offline status.
- Device details on selection.
- Export to PNG, SVG, and PDF.
- Historical topology comparisons.

Represent inferred relationships differently from verified relationships.

Do not invent physical connections without LLDP, switch MAC tables, controller information, or other supporting evidence.

---

# 12. FUSION TABLES AND CORRELATION ENGINE

Build a powerful multi-source correlation workspace.

Call this module:

"جداول الدمج والتحليل"

It must support interactive fusion of:

- Assets.
- IP addresses.
- MAC addresses.
- Hostnames.
- Ports.
- Services.
- Vulnerabilities.
- Shared folders.
- Users and groups where authorized.
- Subnets.
- VLANs.
- Events.
- Security alerts.
- Endpoint health metrics.
- Historical observations.

Features:

- Advanced filtering.
- Multiple-column sorting.
- Column customization.
- Grouping.
- Pivot-style aggregation.
- Saved views.
- Conditional formatting.
- Bulk selection.
- Export CSV/XLSX/PDF.
- Historical comparisons.
- Cross-source evidence correlation.
- Search across all indexed inventory fields.
- Asset relationship visualization.
- Risk-based prioritization.

Example:

Show all Windows devices that have SMB enabled, an unapproved share, missing security updates, and a high-risk finding.

Implement this as a real database-backed query, not static sample data.

Use server-side pagination, query optimization, and indexed filtering.

Prevent unsafe arbitrary SQL execution.

---

# 13. FULL ARABIC DASHBOARD

Create a premium enterprise dashboard.

Main sections:

1. لوحة التحكم الرئيسية
2. اكتشاف الشبكة
3. الأجهزة المتصلة
4. الهواتف والأجهزة المحمولة
5. الخوادم والخدمات
6. المنافذ والبروتوكولات
7. المجلدات المشتركة
8. الثغرات الأمنية
9. الحالة الصحية للأجهزة
10. خريطة الشبكة
11. جداول الدمج والتحليل
12. التنبيهات والأحداث
13. سجل التغييرات
14. التقارير
15. مهام الفحص المجدولة
16. إدارة المستخدمين والصلاحيات
17. الإعدادات والسياسات
18. سجل التدقيق

Dashboard metrics:

- Total discovered assets.
- Online devices.
- Offline devices.
- Newly discovered devices.
- Unknown devices.
- Smartphones.
- Servers.
- Critical vulnerabilities.
- High-risk assets.
- Open services.
- Unauthorized services.
- Unexpected file shares.
- Unhealthy endpoints.
- Active alerts.
- Last scan time.

Include charts for:

- Asset categories.
- Risk distribution.
- Vulnerability trends.
- Network growth.
- Service exposure.
- Endpoint health.
- Historical discovery.
- Remediation progress.

Every displayed statistic must be derived from real database queries.

---

# 14. AUTOMATED MONITORING AND ALERTING

Build a reliable scheduler.

Support:

- Manual discovery.
- Scheduled discovery.
- Incremental scanning.
- Configurable full scans.
- Agent-based monitoring.
- Baseline comparisons.
- Change detection.
- Alert deduplication.
- Alert acknowledgment.
- Alert escalation.
- Maintenance windows.

Example alerts:

"جهاز جديد متصل بالشبكة"

"تم اكتشاف منفذ جديد"

"تم تفعيل مشاركة ملفات غير معتمدة"

"تم اكتشاف خدمة غير مصرح بها"

"الجهاز لا يستجيب"

"ارتفاع استهلاك المعالج"

"وجود تحديثات أمنية مفقودة"

"تم اكتشاف ثغرة حرجة"

"تغير عنوان IP الخاص بالجهاز"

Provide local desktop notifications and in-app notifications.

Email alerts must be optional and work with a configured internal mail server.

No external notification dependency is required.

---

# 15. SECURITY ARCHITECTURE

Apply enterprise security engineering.

Mandatory controls:

- Local authentication.
- Argon2id password hashing.
- Role-based access control.
- Administrator and auditor roles.
- Least-privilege scanner accounts.
- Secure credential vault.
- Encryption at rest for stored secrets.
- TLS for internal application and agent connections.
- CSRF protection where applicable.
- Input validation.
- Output encoding.
- Rate limiting.
- Audit logs.
- Signed offline update packages.
- Dependency integrity checks.
- Database backup encryption.
- Secure session management.
- Network scope authorization.
- Scan rate limits.
- Per-target concurrency limits.
- Safe cancellation.
- Sensitive device exclusion lists.
- Read-only default assessment mode.

Do not hardcode secrets.

Do not disable Windows security controls.

Do not require Domain Administrator privileges for ordinary scanning.

Provide documented least-privilege alternatives.

---

# 16. SCANNING SAFETY

The application will run on a production company network.

Protect availability and business continuity.

Implement:

- Explicit scan scope approval.
- Scan profiles.
- Safe discovery profile.
- Standard inventory profile.
- Credentialed assessment profile.
- Controlled vulnerability assessment profile.
- Configurable packet rate.
- Configurable concurrency.
- Timeouts.
- Retry limits.
- Excluded hosts.
- Excluded ports.
- Sensitive network segments.
- Maintenance windows.
- Emergency stop.
- Scan audit logs.
- Resource usage limits.

Never silently run intrusive scans.

Do not perform exploitation, denial-of-service testing, credential guessing, authentication bypass, or stealth/evasion techniques.

---

# 17. DATABASE DESIGN

Design a normalized PostgreSQL schema.

Include at minimum:

- users
- roles
- permissions
- networks
- subnets
- scan_scopes
- scan_profiles
- scan_jobs
- scan_results
- assets
- asset_identifiers
- network_interfaces
- ip_observations
- device_fingerprints
- services
- service_observations
- shares
- share_permissions
- software_inventory
- patch_inventory
- vulnerabilities
- vulnerability_evidence
- health_metrics
- topology_nodes
- topology_edges
- alerts
- events
- asset_baselines
- policies
- audit_logs
- agent_enrollments
- feed_imports

Use proper foreign keys, indexes, constraints, migrations, and retention policies.

Support historical records without unnecessary duplication.

Implement auditability and data provenance.

---

# 18. APPLICATION PERFORMANCE

Target a baseline environment of:

- Windows desktop or Windows Server.
- 8 GB RAM minimum for small deployments.
- Intel Core i5-class processor.
- PostgreSQL running locally or on an internal server.
- Up to 250 managed assets for the initial validated deployment.

Design for future scalability to thousands of assets using distributed scanning workers.

Performance requirements:

- Responsive dashboard.
- Background scanning.
- No UI freezing.
- Bounded memory usage.
- Incremental database updates.
- Database connection pooling.
- Paginated queries.
- Scan progress tracking.
- Scan cancellation.
- Backpressure.
- Worker health monitoring.

Do not claim performance targets have been met without benchmark evidence.

---

# 19. OFFLINE-FIRST REQUIREMENTS

The platform must remain operational when disconnected from the Internet.

Implement:

- Local frontend assets.
- Local database.
- Local authentication.
- Local scan engines.
- Local documentation.
- Local logs.
- Local reports.
- Offline CVE feed imports.
- Offline OUI database imports.
- Offline software updates.
- Local backup and restore.
- No runtime CDN requests.
- No external fonts.
- No cloud telemetry.
- No forced license validation.

Provide an offline dependency installation strategy.

Provide checks that detect unexpected outbound connections.

---

# 20. REPORTING ENGINE

Generate professional Arabic reports.

Formats:

- PDF.
- Excel.
- CSV.
- HTML.

Reports:

- Complete network inventory.
- Newly discovered assets.
- Offline devices.
- Open ports.
- Unexpected services.
- Shared folders.
- Vulnerability assessment.
- Endpoint health.
- Risk trends.
- Asset changes.
- Network topology.
- Compliance baseline.
- Executive summary.

Reports must include:

- Organization name.
- Reporting period.
- Scan scope.
- Methodology.
- Evidence limitations.
- Findings.
- Severity.
- Recommended actions.
- Responsible team.
- Remediation status.
- Timestamp.
- Report identifier.

Generate SHA-256 hashes for exported reports and provide verification instructions.

---

# 21. SOFTWARE ENGINEERING QUALITY

Use a clean modular architecture.

Separate:

- API layer.
- Authentication.
- Database models.
- Discovery engines.
- Service detection.
- Vulnerability correlation.
- Endpoint health.
- Asset intelligence.
- Network topology.
- Alerts.
- Scheduling.
- Reporting.
- Frontend.

Use typed interfaces and reusable components.

Include:

- Unit tests.
- Integration tests.
- API tests.
- Database migration tests.
- Frontend tests.
- Security tests.
- Failure recovery tests.
- Scanner parser tests.
- Offline operation tests.
- Load tests.
- Dependency checks.

Create realistic synthetic test fixtures.

Never represent simulated test results as actual execution.

---

# 22. ADVERSARIAL AND FAILURE TESTING

Test the application against:

- Malformed scan output.
- Duplicate MAC addresses.
- Randomized MAC addresses.
- DHCP IP reassignment.
- Devices with multiple interfaces.
- Offline devices.
- Firewalled devices.
- False-positive service identification.
- Interrupted scans.
- Database disconnection.
- Worker crashes.
- Credential expiration.
- Large scan result files.
- Unexpected Unicode hostnames.
- Maliciously crafted device banners.
- Incorrect CVE correlations.
- Concurrent scan requests.
- Partial data imports.
- Invalid backup files.
- Unauthorized network ranges.

Implement safe recovery behavior.

---

# 23. DEPLOYMENT AND ROLLBACK

Deliver:

- Windows installation instructions.
- PowerShell setup script.
- PostgreSQL configuration.
- Database initialization.
- Backend startup.
- Frontend build.
- Local service installation.
- Optional Docker Compose deployment.
- Firewall configuration guidance.
- Local HTTPS configuration.
- Backup script.
- Restore script.
- Upgrade script.
- Rollback script.
- Health-check script.

Use canary deployment:

Phase 1: localhost and synthetic test environment.

Phase 2: one authorized test subnet with a small approved device set.

Phase 3: selected production VLANs.

Phase 4: full approved network scope.

Require acceptance checks before each expansion.

---

# 24. REQUIRED ACCEPTANCE CRITERIA

The product is not complete until:

1. An administrator can log in securely.
2. An administrator can configure an approved CIDR scope.
3. The system discovers reachable authorized devices.
4. Discovery observations are persisted.
5. Asset details display correctly.
6. Authorized TCP service scans work.
7. Supported UDP discovery profiles work.
8. Device classifications include confidence and evidence.
9. Shared-folder metadata is displayed where access permits.
10. Vulnerability findings are linked to defensible evidence.
11. Endpoint health is visible where agents are installed.
12. New assets generate alerts.
13. New observed services generate change alerts.
14. Fusion Tables query real persisted records.
15. Topology differentiates verified and inferred links.
16. Reports export successfully in Arabic.
17. The interface is fully RTL.
18. The application functions without Internet access.
19. Access controls prevent unauthorized operations.
20. Backups can be restored successfully.
21. Scan jobs can be canceled.
22. Failure scenarios are handled without corrupting inventory.
23. Tests run with documented commands.
24. All findings preserve timestamps and provenance.
25. The deployment is reproducible on a clean machine.

---

# 25. DELIVERY INSTRUCTIONS

Do not merely explain how to build this platform.

Actually generate the project.

Begin by producing:

A. Architecture and threat model.

B. Technology compatibility assessment.

C. Complete repository directory structure.

D. Database schema and migrations.

E. Backend implementation.

F. Scanning engine implementation.

G. Frontend implementation.

H. Fusion Tables implementation.

I. Monitoring and alerting.

J. Reporting system.

K. Security hardening.

L. Automated tests.

M. Deployment scripts.

N. Backup and rollback procedures.

O. Arabic administrator documentation.

P. Acceptance test checklist.

For each implementation phase:

1. Explain the scope briefly.
2. Create actual source files.
3. Include all necessary imports.
4. Provide dependency definitions.
5. Provide executable commands.
6. Run available tests.
7. Identify failures honestly.
8. Fix discovered defects.
9. Explain remaining limitations.
10. Continue to the next phase.

If execution tools are unavailable, explicitly identify untested code and provide commands for local verification.

Do not use placeholder functions, fake integrations, or invented scan results in production code.

Do not silently omit major requirements.

If an advanced feature requires an external local service, explain that dependency and provide an integration adapter.

If a feature is technically impossible without privileged access, endpoint agents, network sensors, or infrastructure integration, explain the limitation and implement the best legitimate alternative.

If the complete system cannot fit into one response, build it incrementally, prioritizing a working vertical slice over incomplete scaffolding.

**Start implementation now. First deliver a working local version containing authentication, PostgreSQL persistence, approved subnet discovery, asset inventory, TCP service discovery, Arabic dashboard, scan history, and automated tests. Then extend it module by module until the full specification is implemented.**

All user-facing text must be in Arabic.

All code identifiers and developer documentation may use English.

The final product must be an actual usable offline network security management application, not a concept presentation.