export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Role {
  id: number;
  name: "admin" | "operator" | "auditor";
  name_ar: string;
  description_ar: string;
}

export interface User {
  id: number;
  username: string;
  display_name: string;
  is_active: boolean;
  role: Role;
  last_login_at: string | null;
  locked_until: string | null;
  created_at: string;
}

export interface Me {
  user: User;
  permissions: string[];
  csrf_token: string;
}

export interface Scope {
  id: number;
  name: string;
  cidr: string;
  description: string;
  excluded_hosts: string[];
  excluded_ports: number[];
  is_sensitive: boolean;
  is_approved: boolean;
  approved_at: string | null;
  approved_by_id: number | null;
  is_active: boolean;
  created_at: string;
  target_count: number;
  has_active_job: boolean;
  schedule_profile_id: number | null;
  schedule_interval_minutes: number | null;
  schedule_next_run_at: string | null;
  schedule_last_run_at: string | null;
  schedule_last_error: string | null;
}

export interface CandidateNetwork {
  cidr: string;
  sources: ("interface" | "route" | "trace")[];
  interfaces: string[];
  local_ips: string[];
  gateways: string[];
  is_virtual: boolean;
  host_count: number;
  allowed: boolean;
  reason_ar: string | null;
  suggested_cidr: string | null;
  existing_scope_id: number | null;
  existing_scope_name: string | null;
  existing_scope_approved: boolean;
  overlaps_scope_names: string[];
}

export interface BulkScopeResult {
  cidr: string;
  scope_id: number | null;
  created: boolean;
  approved: boolean;
  job_id: number | null;
  error_ar: string | null;
}

export interface Profile {
  id: number;
  code: string;
  name_ar: string;
  description_ar: string;
  discovery_ports: number[];
  tcp_ports: number[];
  use_icmp: boolean;
  use_arp: boolean;
  resolve_dns: boolean;
  grab_banners: boolean;
  max_concurrency: number;
  per_host_concurrency: number;
  rate_per_second: number;
  connect_timeout_ms: number;
  retries: number;
  is_intrusive: boolean;
}

export type JobStatus = "queued" | "running" | "completed" | "cancelled" | "failed" | "interrupted";

export interface Job {
  id: number;
  scope_id: number;
  profile_id: number;
  requested_by_id: number | null;
  trigger: string;
  status: JobStatus;
  cancel_requested: boolean;
  total_hosts: number;
  processed_hosts: number;
  alive_hosts: number;
  open_services: number;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  scope_name: string;
  scope_cidr: string;
  profile_name_ar: string;
  resumed_from_id: number | null;
  resume_offset: number;
  target_ip: string | null;
}

export interface ScanResult {
  id: number;
  ip: string;
  asset_id: number | null;
  mac: string | null;
  hostname: string | null;
  ttl: number | null;
  liveness_methods: string[];
  open_ports: number[];
  observed_at: string;
}

export interface ScanDiff {
  job_id: number;
  previous_job_id: number | null;
  new_hosts: string[];
  missing_hosts: string[];
  new_services: string[];
  closed_services: string[];
}

export interface Asset {
  id: number;
  display_name: string | null;
  current_ip: string | null;
  hostname: string | null;
  mac: string | null;
  mac_randomized: boolean;
  vendor: string | null;
  device_type: string;
  device_type_confidence: number;
  os_family: string;
  os_confidence: number;
  status: "online" | "offline" | "unknown";
  criticality: "low" | "normal" | "high" | "critical";
  discovery_methods: string[];
  netbios_name: string | null;
  workgroup: string | null;
  model: string | null;
  is_gateway: boolean;
  upnp: Record<string, string | null> | null;
  first_seen: string;
  last_seen: string;
  open_service_count: number;
}

export interface Service {
  id: number;
  asset_id: number;
  port: number;
  protocol: string;
  state: "open" | "closed";
  service_name: string;
  product: string | null;
  version: string | null;
  banner: string | null;
  tls: Record<string, unknown> | null;
  identification_confidence: number;
  identification_method: string;
  exposure_category: string;
  exposure_note_ar: string | null;
  first_seen: string;
  last_seen: string;
  asset_ip: string | null;
  asset_label: string | null;
  guidance?: ServiceGuidance | null;
}

export interface GuidanceCommand {
  label_ar: string;
  command: string;
  shell: "powershell" | "bash";
  run_on: "device" | "admin_pc";
}

export interface PlatformGuide {
  platform: "windows" | "linux" | "appliance";
  platform_ar: string;
  verify: GuidanceCommand[];
  disable: GuidanceCommand[];
  harden: GuidanceCommand[];
  warnings_ar: string[];
  notes_ar: string[];
}

export interface ServiceGuidance {
  network_checks: GuidanceCommand[];
  access: GuidanceCommand[];
  access_note_ar: string;
  platforms: PlatformGuide[];
  recheck_ar: string;
}

export interface EvidenceItem {
  signal: string;
  value: string;
  target: string;
  weight: number;
  detail_ar: string;
}

export interface Fingerprint {
  device_type: string;
  device_type_confidence: number;
  os_family: string;
  os_confidence: number;
  evidence: EvidenceItem[];
  created_at: string;
  last_confirmed_at: string;
}

export interface ChangeEvent {
  id: number;
  kind: string;
  message_ar: string;
  asset_id: number | null;
  job_id: number | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface Alert {
  id: number;
  kind: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title_ar: string;
  message_ar: string;
  status: "open" | "acknowledged" | "resolved";
  occurrences: number;
  asset_id: number | null;
  job_id: number | null;
  details: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
}

export interface AssetDetail extends Asset {
  notes: string;
  identifiers: { kind: string; value: string; source: string; first_seen: string; last_seen: string }[];
  ip_history: { ip: string; mac: string | null; first_seen: string; last_seen: string; sightings: number }[];
  services: Service[];
  fingerprint: Fingerprint | null;
  events: ChangeEvent[];
  alerts: Alert[];
}

export interface AuditEntry {
  id: number;
  actor_username: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  success: boolean;
  client_ip: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface DashboardSummary {
  generated_at: string;
  total_assets: number;
  online: number;
  offline: number;
  new_24h: number;
  unknown_type: number;
  mobile: number;
  servers: number;
  open_services: number;
  active_alerts: number;
  running_jobs: number;
  last_scan: { id: number; status: JobStatus; finished_at: string } | null;
  device_types: Record<string, number>;
  exposure: Record<string, number>;
  top_ports: { port: number; service: string; count: number }[];
  alerts_by_severity: Record<string, number>;
  discovery_history: { date: string; new_assets: number }[];
}

export interface Credential {
  id: number;
  name: string;
  kind: "winrm" | "ssh" | "snmp";
  username: string;
  use_https: boolean;
  port: number;
  verify_tls: boolean;
  created_at: string;
  last_used_at: string | null;
}

export interface Execution {
  id: number;
  asset_id: number | null;
  target: string;
  service_port: number | null;
  section: string;
  label_ar: string;
  command: string;
  status: "ok" | "error";
  had_errors: boolean;
  output: string;
  started_at: string;
  finished_at: string | null;
}

export interface SshHostKey {
  id: number;
  ip: string;
  port: number;
  key_type: string;
  fingerprint: string;
  first_seen: string;
}

export interface FusionFilters {
  text?: string;
  ip_cidr?: string;
  statuses?: string[];
  device_types?: string[];
  os_families?: string[];
  criticality?: string[];
  vendor_contains?: string;
  open_ports_all?: number[];
  open_ports_any?: number[];
  open_ports_none?: number[];
  exposures_any?: string[];
  service_contains?: string;
  has_open_alerts?: boolean | null;
  min_alert_severity?: string | null;
  mac_randomized?: boolean | null;
  min_open_services?: number | null;
  first_seen_within_days?: number | null;
  not_seen_for_days?: number | null;
}

export interface FusionQuery {
  filters: FusionFilters;
  columns: string[];
  sort: string;
  order: "asc" | "desc";
  group_by: string | null;
  page: number;
  page_size: number;
}

export interface FusionResult {
  total: number;
  page: number;
  page_size: number;
  columns: string[];
  rows: Record<string, unknown>[];
  group_by?: string;
  groups?: { key: string; count: number }[];
}

export interface FusionView {
  id: number;
  name: string;
  definition: FusionQuery;
  is_shared: boolean;
  owner_id: number;
  is_mine: boolean;
}

export interface TopoNode {
  id: string;
  type: "scanner" | "network" | "device" | "hop";
  label: string;
  kind?: string;
  cidr?: string;
  ip?: string;
  asset_id?: number;
  device_type?: string;
  os_family?: string;
  status?: string;
  vendor?: string | null;
  model?: string | null;
  is_gateway?: boolean;
  open_alerts?: number;
  open_services?: number;
  hostname?: string | null;
  mac?: string | null;
  devices?: number;
  online?: number;
  ips?: string[];
  scope_name?: string;
}

export interface TopoEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  verified: boolean;
  label_ar: string;
}

export interface Topology {
  nodes: TopoNode[];
  edges: TopoEdge[];
  stats: { networks: number; devices: number; routers: number; paths: number; truncated: boolean };
}

export interface NetActionParam { name: string; label_ar: string; kind: "ip" | "mac" | "interface"; placeholder: string; }
export interface NetAction { id: string; label_ar: string; category: "info" | "change"; description_ar: string; warning_ar: string | null; params: NetActionParam[]; }
export interface NetAdmin { platform: string; platform_ar: string; note_ar: string; actions: NetAction[]; is_network_device: boolean; has_ssh: boolean; }

// --- Reports ---------------------------------------------------------------------------
export interface ReportMeta {
  title: string; tool: string; version: string; generated_at: string;
  scope_count: number; scopes: { name: string; cidr: string; sensitive: boolean }[];
  integrity_sha256?: string;
}
export interface ReportSummary {
  total_assets: number; online: number; offline: number; networks: number; routers: number;
  gateways: number; open_services: number; exposed_devices: number; high_risk_ports: number;
  open_alerts: number; critical_alerts: number; high_alerts: number; last_scan_at: string | null;
  overall_risk_band: string; open_vulnerabilities: number; physical_links: number;
}
export interface Dist { key: string; label_ar: string; count: number }
export interface ReportNetwork {
  cidr: string; name: string | null; in_scope: boolean; devices: number; online: number;
  routers: number; gateways: number; open_service_count: number;
  top_ports: { port: number; count: number }[]; risk_score: number; risk_band: string;
}
export interface ExposedPort {
  port: number; service_name: string; protocol: string; exposure_category: string; count: number;
  assets: { id: number; ip: string | null; name: string | null }[];
  high_risk: boolean; risk_note_ar: string | null; guidance: ServiceGuidance | null;
}
export interface ExposedDevice {
  id: number; ip: string | null; name: string | null; device_type: string; device_type_ar: string;
  os_family: string; status: string; is_gateway: boolean; open_services: number; open_alerts: number;
  risk_score: number; risk_band: string; ports: number[];
}
export interface ReportAlert {
  id: number; severity: string; severity_ar: string; title_ar: string; message_ar: string;
  asset_id: number | null; occurrences: number; last_seen: string | null;
}
export interface ReportScan {
  id: number; scope: string | null; status: string; alive_hosts: number; open_services: number;
  total_hosts: number; started_at: string | null; finished_at: string | null;
}
export interface Recommendation { priority: string; title_ar: string; detail_ar: string }
export interface ReportVulnerabilities {
  cve_entries: number; open_findings: number; affected_assets: number;
  by_severity: Dist[];
  top: { cve_id: string; severity: string; severity_ar: string; cvss_score: number; asset_id: number; product: string; version: string | null; matched_on: string }[];
}
export interface NetworkReport {
  meta: ReportMeta; summary: ReportSummary;
  distributions: { device_types: Dist[]; os_families: Dist[]; statuses: Dist[]; severities: Dist[]; exposures: Dist[] };
  networks: ReportNetwork[]; exposed_ports: ExposedPort[]; top_exposed_devices: ExposedDevice[];
  alerts: ReportAlert[]; vulnerabilities: ReportVulnerabilities; scan_history: ReportScan[];
  remote_activity: { total: number; recent: { target: string; label_ar: string; section: string; status: string; had_errors: boolean; started_at: string | null }[] };
  recommendations: Recommendation[];
}

// --- Directory (Active Directory / LDAP) -----------------------------------------------
export interface DirectoryCredential { id: number; name: string; username: string; kind: string }
export interface DirUserFlags {
  enabled: boolean; locked_out: boolean; password_not_required: boolean; password_never_expires: boolean;
  smartcard_required: boolean; trusted_for_delegation: boolean; password_expired: boolean;
}
export interface DirPrivilege { group: string; label_ar: string }
export interface DirUser {
  sam: string; display_name: string; upn: string; mail: string; description: string; dn: string;
  enabled: boolean; flags: DirUserFlags; admin_count: number; groups: string[]; group_count: number;
  privileges: DirPrivilege[]; is_privileged: boolean; when_created: string; last_logon: string;
}
export interface DirGroup {
  name: string; sam: string; description: string; dn: string; member_count: number; members: string[];
  admin_count: number; privileged: boolean; label_ar: string | null;
}
export interface DirComputer { name: string; dns: string; os: string; os_version: string; dn: string; enabled: boolean }
export interface DirectoryResult {
  domain: { base_dn: string; host: string; naming_contexts: string[]; dns_domain: string };
  counts: {
    users: number; groups: number; computers: number; enabled_users: number; disabled_users: number;
    privileged_users: number; privileged_groups: number; password_never_expires: number;
  };
  users: DirUser[]; groups: DirGroup[]; computers: DirComputer[];
}

// --- Vulnerabilities (CVE) -------------------------------------------------------------
export interface VulnSummary {
  cve_entries: number; open_findings: number; affected_assets: number;
  kev_entries?: number; kev_open_findings?: number;
  by_severity: { severity: string; count: number }[];
}
export interface Vulnerability {
  id: number; asset_id: number; asset_ip: string | null; asset_name: string | null;
  cve_id: string; product: string; version: string | null; matched_on: string;
  cvss_score: number; severity: string; status: string; description: string; references: string[];
  epss: number; kev: boolean; kev_date: string | null; priority: number; priority_band: string;
}
export interface CveImportResult {
  import: { added: number; updated: number; skipped: number; total: number };
  correlation: { matched: number; resolved: number; cve_count: number; services: number };
}

// --- Physical topology (SNMP/LLDP) -----------------------------------------------------
export interface PhysicalNode {
  id: string; kind: "asset" | "external"; asset_id?: number; label: string;
  device_type?: string; ip?: string | null; mac?: string | null;
}
export interface PhysicalEdge {
  id: string; source: string; target: string; source_kind: string;
  local_port: string; remote_port: string; label: string;
}
export interface PhysicalGraph {
  nodes: PhysicalNode[]; edges: PhysicalEdge[];
  stats: { links: number; nodes: number; resolved: number };
}
export interface SnmpCredential { id: number; name: string; port: number }
export interface SnmpCollectResult {
  sys_name: string; sys_descr: string;
  counts: { lldp: number; cdp: number; fdb: number; total: number };
  stored: { added: number; updated: number; resolved: number; total: number };
}

// --- Operations: policy, maintenance windows, notifications ----------------------------
export interface PolicyRule { id: number; port: number | null; protocol: string; device_type: string | null; note_ar: string }
export interface PolicyFinding {
  id: number; kind: string; severity: string; title_ar: string; message_ar: string;
  asset_id: number | null; details: Record<string, unknown>;
}
export interface PolicyStats { unauthorized: number; rogue_gateways: number; resolved: number; rules: number; services: number }
export interface MaintenanceWindow {
  id: number; name: string; starts_at: string; ends_at: string; cidr: string | null; note_ar: string; active: boolean;
}
export interface NotificationConfig {
  enabled: boolean; smtp_host: string; smtp_port: number; use_tls: boolean; from_addr: string;
  to_addrs: string[]; username: string; has_password: boolean; min_severity: string; escalation_minutes: number;
}
export interface AgentTokenRow { id: number; label: string; is_active: boolean; created_at: string; last_seen_at: string | null; last_host: string | null }
export interface AgentTokenCreated { id: number; label: string; token: string }
export interface DirectoryDiscovery {
  domain: string | null; base_dn: string | null;
  controllers: { host: string; source: string }[];
  integrated_available: boolean;
  env: { USERDNSDOMAIN: string | null; USERDOMAIN: string | null; LOGONSERVER: string | null; USERNAME: string | null };
}
export interface SmbEntry { name: string; is_dir: boolean; size: number; mtime: number | null }
export interface SmbShare { share: string; entries: SmbEntry[]; truncated: boolean }
export interface SmbShares { ip: string; shares: SmbShare[]; count: number; note_ar: string }
export interface SmbBrowse { ip: string; share: string; path: string; entries: SmbEntry[]; count: number }
export interface ComplianceFramework { key: string; name_ar: string }
export interface ComplianceControl { control_id: string; title_ar: string; family_ar: string; status: string; detail_ar: string }
export interface ComplianceReport {
  framework: string; framework_ar: string; generated_at: string; score: number | null;
  summary: { total: number; pass: number; fail: number; partial: number; manual: number; not_applicable: number };
  controls: ComplianceControl[];
}
export interface AttackPath { user: string; display_name: string; enabled: boolean; target: string; label_ar: string; path: string[]; hops: number; direct: boolean }
export interface AttackPathSummary {
  privileged_users: number; nested_escalations: number;
  targets: { group: string; label_ar: string; reachable_users: number }[];
  risky: { user: string; target: string; hops: number; reasons_ar: string[] }[];
  paths: AttackPath[];
  domain: { dns_domain: string; base_dn: string }; counts: { users: number; groups: number };
}
