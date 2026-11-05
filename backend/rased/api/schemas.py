"""Pydantic request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


# --- auth / users -------------------------------------------------------------------------


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class RoleOut(ORM):
    id: int
    name: str
    name_ar: str
    description_ar: str


class UserOut(ORM):
    id: int
    username: str
    display_name: str
    is_active: bool
    role: RoleOut
    last_login_at: datetime | None
    locked_until: datetime | None
    created_at: datetime


class MeOut(BaseModel):
    user: UserOut
    permissions: list[str]
    csrf_token: str


USERNAME_PATTERN = r"^[A-Za-z0-9_.\-]{3,64}$"


class UserCreateIn(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    display_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    role: Literal["admin", "operator", "auditor"]


class UserUpdateIn(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    role: Literal["admin", "operator", "auditor"] | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=1, max_length=256)
    unlock: bool | None = None


# --- scopes / profiles / jobs -------------------------------------------------------------


class ScopeIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    cidr: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=2000)
    excluded_hosts: list[str] = Field(default_factory=list, max_length=1024)
    excluded_ports: list[int] = Field(default_factory=list, max_length=1024)
    is_sensitive: bool = False

    @field_validator("name", "cidr")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class ScopeUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    cidr: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=2000)
    excluded_hosts: list[str] | None = Field(default=None, max_length=1024)
    excluded_ports: list[int] | None = Field(default=None, max_length=1024)
    is_sensitive: bool | None = None


class ScopeApproveIn(BaseModel):
    confirm: bool = Field(description="Must be true: the approver confirms the organisation owns this range")


class ScopeOut(ORM):
    id: int
    name: str
    cidr: str
    description: str
    excluded_hosts: list[str]
    excluded_ports: list[int]
    is_sensitive: bool
    is_approved: bool
    approved_at: datetime | None
    approved_by_id: int | None
    is_active: bool
    created_at: datetime
    target_count: int = 0
    has_active_job: bool = False
    schedule_profile_id: int | None = None
    schedule_interval_minutes: int | None = None
    schedule_next_run_at: datetime | None = None
    schedule_last_run_at: datetime | None = None
    schedule_last_error: str | None = None


class CandidateOut(BaseModel):
    cidr: str
    sources: list[str]
    interfaces: list[str]
    local_ips: list[str]
    gateways: list[str]
    is_virtual: bool
    host_count: int
    allowed: bool
    reason_ar: str | None = None
    suggested_cidr: str | None = None
    existing_scope_id: int | None = None
    existing_scope_name: str | None = None
    existing_scope_approved: bool = False
    overlaps_scope_names: list[str] = Field(default_factory=list)


class BulkScopeItem(BaseModel):
    cidr: str = Field(min_length=1, max_length=64)
    name: str | None = Field(default=None, max_length=128)


class BulkScopeIn(BaseModel):
    items: list[BulkScopeItem] = Field(min_length=1, max_length=64)
    approve: bool = False
    confirm: bool = False
    start_scan_profile_id: int | None = None


class BulkScopeResult(BaseModel):
    cidr: str
    scope_id: int | None = None
    created: bool = False
    approved: bool = False
    job_id: int | None = None
    error_ar: str | None = None


class ProfileOut(ORM):
    id: int
    code: str
    name_ar: str
    description_ar: str
    discovery_ports: list[int]
    tcp_ports: list[int]
    use_icmp: bool
    use_arp: bool
    resolve_dns: bool
    grab_banners: bool
    max_concurrency: int
    per_host_concurrency: int
    rate_per_second: int
    connect_timeout_ms: int
    retries: int
    is_intrusive: bool


class ScanCreateIn(BaseModel):
    scope_id: int
    profile_id: int


class JobOut(ORM):
    id: int
    scope_id: int
    profile_id: int
    requested_by_id: int | None
    trigger: str
    status: str
    cancel_requested: bool
    total_hosts: int
    processed_hosts: int
    alive_hosts: int
    open_services: int
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    scope_name: str = ""
    scope_cidr: str = ""
    profile_name_ar: str = ""
    resumed_from_id: int | None = None
    resume_offset: int = 0
    target_ip: str | None = None


class RerunIn(BaseModel):
    mode: Literal["restart", "resume"] = "restart"


class ScheduleIn(BaseModel):
    profile_id: int | None = None
    interval_minutes: int | None = Field(default=None, ge=15, le=30 * 24 * 60)
    first_run_after_minutes: int = Field(default=0, ge=0, le=30 * 24 * 60)


class RescanIn(BaseModel):
    profile_id: int


PORT_LIST_MAX = 2048


class ProfileIn(BaseModel):
    name_ar: str = Field(min_length=1, max_length=128)
    description_ar: str = Field(default="", max_length=2000)
    discovery_ports: list[int] = Field(min_length=1, max_length=32)
    tcp_ports: list[int] = Field(default_factory=list, max_length=PORT_LIST_MAX)
    use_icmp: bool = True
    use_arp: bool = True
    resolve_dns: bool = True
    grab_banners: bool = False
    max_concurrency: int = Field(default=256, ge=1, le=1024)
    per_host_concurrency: int = Field(default=8, ge=1, le=64)
    rate_per_second: int = Field(default=150, ge=1, le=2000)
    connect_timeout_ms: int = Field(default=2000, ge=200, le=30000)
    retries: int = Field(default=0, ge=0, le=3)

    @field_validator("discovery_ports", "tcp_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in v):
            raise ValueError("port out of range")
        return sorted(set(v))


class ScanResultOut(ORM):
    id: int
    ip: str
    asset_id: int | None
    mac: str | None
    hostname: str | None
    ttl: int | None
    liveness_methods: list[str]
    open_ports: list[int]
    observed_at: datetime


class ScanDiffOut(BaseModel):
    job_id: int
    previous_job_id: int | None
    new_hosts: list[str]
    missing_hosts: list[str]
    new_services: list[str]
    closed_services: list[str]


# --- assets / services --------------------------------------------------------------------


class AssetOut(ORM):
    id: int
    display_name: str | None
    current_ip: str | None
    hostname: str | None
    mac: str | None
    mac_randomized: bool
    vendor: str | None
    device_type: str
    device_type_confidence: float
    os_family: str
    os_confidence: float
    status: str
    criticality: str
    discovery_methods: list[str]
    netbios_name: str | None = None
    workgroup: str | None = None
    model: str | None = None
    is_gateway: bool = False
    upnp: dict[str, Any] | None = None
    first_seen: datetime
    last_seen: datetime
    open_service_count: int = 0


class AssetUpdateIn(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    criticality: Literal["low", "normal", "high", "critical"] | None = None
    notes: str | None = Field(default=None, max_length=5000)


class IdentifierOut(ORM):
    kind: str
    value: str
    source: str
    first_seen: datetime
    last_seen: datetime


class IpObservationOut(ORM):
    ip: str
    mac: str | None
    first_seen: datetime
    last_seen: datetime
    sightings: int


class ServiceOut(ORM):
    id: int
    asset_id: int
    port: int
    protocol: str
    state: str
    service_name: str
    product: str | None
    version: str | None
    banner: str | None
    tls: dict[str, Any] | None
    identification_confidence: float
    identification_method: str
    exposure_category: str
    exposure_note_ar: str | None = None
    first_seen: datetime
    last_seen: datetime
    asset_ip: str | None = None
    asset_label: str | None = None
    guidance: dict[str, Any] | None = None


class FingerprintOut(ORM):
    device_type: str
    device_type_confidence: float
    os_family: str
    os_confidence: float
    evidence: list[dict[str, Any]]
    created_at: datetime
    last_confirmed_at: datetime


class EventOut(ORM):
    id: int
    kind: str
    message_ar: str
    asset_id: int | None
    job_id: int | None
    details: dict[str, Any]
    created_at: datetime


class AlertOut(ORM):
    id: int
    kind: str
    severity: str
    title_ar: str
    message_ar: str
    status: str
    occurrences: int
    asset_id: int | None
    job_id: int | None
    details: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None


class AssetDetailOut(AssetOut):
    notes: str
    identifiers: list[IdentifierOut]
    ip_history: list[IpObservationOut]
    services: list[ServiceOut]
    fingerprint: FingerprintOut | None
    events: list[EventOut]
    alerts: list[AlertOut]


class AuditOut(ORM):
    id: int
    actor_username: str | None
    action: str
    target_type: str | None
    target_id: str | None
    success: bool
    client_ip: str | None
    details: dict[str, Any]
    created_at: datetime
