"""SQLAlchemy ORM models (PostgreSQL primary target, SQLite for tests).

Provenance rules applied across the schema:
* every observation carries the scan job that produced it and a UTC timestamp;
* classification results store the evidence list they were derived from;
* "current state" tables (assets, services) are separated from history tables
  (ip_observations, service_observations, device_fingerprints, scan_results, events).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

JSONType = JSON().with_variant(JSONB(), "postgresql")


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on every backend (SQLite drops tzinfo otherwise)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime values are not accepted; use UTC-aware datetimes")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# ---------------------------------------------------------------------------------------
# Identity & access
# ---------------------------------------------------------------------------------------


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[int] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    name_ar: Mapped[str] = mapped_column(String(128))
    description_ar: Mapped[str] = mapped_column(Text, default="")

    permissions: Mapped[list[Permission]] = relationship(
        secondary="role_permissions", lazy="selectin", order_by="Permission.code"
    )


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    description_ar: Mapped[str] = mapped_column(Text, default="")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(128))
    password_hash: Mapped[str] = mapped_column(String(255))
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    password_changed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    role: Mapped[Role] = relationship(lazy="joined")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)

    user: Mapped[User] = relationship(lazy="joined")


# ---------------------------------------------------------------------------------------
# Scan configuration
# ---------------------------------------------------------------------------------------


class ScanScope(Base):
    """An administrator-approved network range. Scanning outside approved scopes is impossible."""

    __tablename__ = "scan_scopes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    cidr: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text, default="")
    excluded_hosts: Mapped[list[str]] = mapped_column(JSONType, default=list)
    excluded_ports: Mapped[list[int]] = mapped_column(JSONType, default=list)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    is_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    # Optional recurring scan (one schedule per scope).
    schedule_profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_profiles.id", ondelete="SET NULL"), nullable=True
    )
    schedule_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    schedule_next_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, index=True)
    schedule_last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    schedule_last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    __table_args__ = (
        CheckConstraint("max_concurrency BETWEEN 1 AND 1024", name="max_concurrency_range"),
        CheckConstraint("per_host_concurrency BETWEEN 1 AND 64", name="per_host_concurrency_range"),
        CheckConstraint("rate_per_second BETWEEN 1 AND 5000", name="rate_range"),
        CheckConstraint("connect_timeout_ms BETWEEN 100 AND 30000", name="timeout_range"),
        CheckConstraint("retries BETWEEN 0 AND 5", name="retries_range"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    name_ar: Mapped[str] = mapped_column(String(128))
    description_ar: Mapped[str] = mapped_column(Text, default="")
    discovery_ports: Mapped[list[int]] = mapped_column(JSONType, default=list)
    tcp_ports: Mapped[list[int]] = mapped_column(JSONType, default=list)
    use_icmp: Mapped[bool] = mapped_column(Boolean, default=True)
    use_arp: Mapped[bool] = mapped_column(Boolean, default=True)
    resolve_dns: Mapped[bool] = mapped_column(Boolean, default=True)
    grab_banners: Mapped[bool] = mapped_column(Boolean, default=False)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=32)
    per_host_concurrency: Mapped[int] = mapped_column(Integer, default=4)
    rate_per_second: Mapped[int] = mapped_column(Integer, default=50)
    connect_timeout_ms: Mapped[int] = mapped_column(Integer, default=2000)
    retries: Mapped[int] = mapped_column(Integer, default=0)
    is_intrusive: Mapped[bool] = mapped_column(Boolean, default=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)


JOB_ACTIVE_STATUSES = ("queued", "running")
JOB_STATUSES = ("queued", "running", "completed", "cancelled", "failed", "interrupted")


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','completed','cancelled','failed','interrupted')",
            name="status_valid",
        ),
        # At most one active job per scope (also enforced in the API with a row lock).
        Index(
            "uq_scan_jobs_active_scope",
            "scope_id",
            unique=True,
            postgresql_where=text("status IN ('queued','running')"),
            sqlite_where=text("status IN ('queued','running')"),
        ),
        Index("ix_scan_jobs_scope_created", "scope_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scope_id: Mapped[int] = mapped_column(ForeignKey("scan_scopes.id", ondelete="RESTRICT"))
    profile_id: Mapped[int] = mapped_column(ForeignKey("scan_profiles.id", ondelete="RESTRICT"))
    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    trigger: Mapped[str] = mapped_column(String(16), default="manual")
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    # Snapshot of the effective configuration so history stays reproducible after edits.
    scope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    profile_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    total_hosts: Mapped[int] = mapped_column(Integer, default=0)
    processed_hosts: Mapped[int] = mapped_column(Integer, default=0)
    alive_hosts: Mapped[int] = mapped_column(Integer, default=0)
    open_services: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Resume support: continue an interrupted job after its last persisted chunk.
    resumed_from_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    resume_offset: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    # Start of the observation window this job's results belong to (earlier for resumed jobs);
    # assets not seen since this instant are the ones marked offline at the end.
    coverage_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    scope: Mapped[ScanScope] = relationship(lazy="joined")
    profile: Mapped[ScanProfile] = relationship(lazy="joined")


class ScanResult(Base):
    """One responsive host observed by one scan job (unresponsive addresses are not stored)."""

    __tablename__ = "scan_results"
    __table_args__ = (UniqueConstraint("job_id", "ip", name="uq_scan_results_job_ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ip: Mapped[str] = mapped_column(String(45))
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    liveness_methods: Mapped[list[str]] = mapped_column(JSONType, default=list)
    open_ports: Mapped[list[int]] = mapped_column(JSONType, default=list)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


# ---------------------------------------------------------------------------------------
# Asset intelligence
# ---------------------------------------------------------------------------------------


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("status IN ('online','offline','unknown')", name="status_valid"),
        CheckConstraint(
            "criticality IN ('low','normal','high','critical')", name="criticality_valid"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    current_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    mac_randomized: Mapped[bool] = mapped_column(Boolean, default=False)
    vendor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    device_type: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    device_type_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    os_family: Mapped[str] = mapped_column(String(32), default="unknown")
    os_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    criticality: Mapped[str] = mapped_column(String(16), default="normal")
    notes: Mapped[str] = mapped_column(Text, default="")
    discovery_methods: Mapped[list[str]] = mapped_column(JSONType, default=list)
    netbios_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    workgroup: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    upnp: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    is_gateway: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_scan_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )

    identifiers: Mapped[list[AssetIdentifier]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )
    services: Mapped[list[Service]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )


class AssetIdentifier(Base):
    __tablename__ = "asset_identifiers"
    __table_args__ = (
        UniqueConstraint("asset_id", "kind", "value", name="uq_asset_identifiers_asset_kind_value"),
        Index("ix_asset_identifiers_kind_value", "kind", "value"),
        CheckConstraint("kind IN ('mac','hostname','ipv4','ipv6')", name="kind_valid"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(253))
    source: Mapped[str] = mapped_column(String(32))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="identifiers")


class IpObservation(Base):
    """Interval record: asset X held IP Y between first_seen and last_seen (one row per pair)."""

    __tablename__ = "ip_observations"
    __table_args__ = (UniqueConstraint("asset_id", "ip", name="uq_ip_observations_asset_ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    ip: Mapped[str] = mapped_column(String(45), index=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    sightings: Mapped[int] = mapped_column(Integer, default=1)
    first_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    last_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )


class DeviceFingerprint(Base):
    """Classification history: a row is added only when the classification changes."""

    __tablename__ = "device_fingerprints"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    device_type: Mapped[str] = mapped_column(String(32))
    device_type_confidence: Mapped[float] = mapped_column(Float)
    os_family: Mapped[str] = mapped_column(String(32))
    os_confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_confirmed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_services_asset_port_protocol"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="port_range"),
        CheckConstraint("protocol IN ('tcp','udp')", name="protocol_valid"),
        CheckConstraint("state IN ('open','closed')", name="state_valid"),
        Index("ix_services_port_state", "port", "state"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(3), default="tcp")
    state: Mapped[str] = mapped_column(String(8), default="open")
    service_name: Mapped[str] = mapped_column(String(64), default="unknown")
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(512), nullable=True)
    tls: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    identification_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    identification_method: Mapped[str] = mapped_column(String(32), default="port")
    exposure_category: Mapped[str] = mapped_column(String(32), default="other")
    business_justification: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )

    asset: Mapped[Asset] = relationship(back_populates="services")


class ServiceObservation(Base):
    __tablename__ = "service_observations"
    __table_args__ = (
        UniqueConstraint("service_id", "job_id", name="uq_service_observations_service_job"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"))
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(8))
    banner: Mapped[str | None] = mapped_column(String(512), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class OuiVendor(Base):
    """IEEE MA-L registry entries imported offline (``rased import-oui oui.csv``)."""

    __tablename__ = "oui_vendors"

    prefix: Mapped[str] = mapped_column(String(6), primary_key=True)  # 6 upper-case hex digits
    vendor: Mapped[str] = mapped_column(String(256))


# ---------------------------------------------------------------------------------------
# Alerts, change log, audit
# ---------------------------------------------------------------------------------------


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("status IN ('open','acknowledged','resolved')", name="status_valid"),
        CheckConstraint(
            "severity IN ('info','low','medium','high','critical')", name="severity_valid"
        ),
        Index("ix_alerts_dedup_status", "dedup_key", "status"),
        Index("ix_alerts_status_last_seen", "status", "last_seen"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    title_ar: Mapped[str] = mapped_column(String(256))
    message_ar: Mapped[str] = mapped_column(Text)
    dedup_key: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(16), default="open")
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    acknowledged_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Event(Base):
    """Change log (سجل التغييرات): every inventory change with its provenance."""

    __tablename__ = "events"
    __table_args__ = (Index("ix_events_created", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    message_ar: Mapped[str] = mapped_column(Text)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    job_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class FusionView(Base):
    """A saved Fusion Tables query (filters, columns, grouping) — never raw SQL."""

    __tablename__ = "fusion_views"
    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_fusion_views_owner_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Credential(Base):
    """Vaulted remote-management credential. The secret is encrypted at rest (Fernet)."""

    __tablename__ = "credentials"
    __table_args__ = (CheckConstraint("kind IN ('winrm','ssh','snmp')", name="kind_valid"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(16), default="winrm")
    username: Mapped[str] = mapped_column(String(256))
    secret_encrypted: Mapped[str] = mapped_column(Text)
    use_https: Mapped[bool] = mapped_column(Boolean, default=True)
    port: Mapped[int] = mapped_column(Integer, default=5986)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class SshHostKey(Base):
    """Pinned SSH host key per device (trust on first use; a change blocks the connection)."""

    __tablename__ = "ssh_host_keys"
    __table_args__ = (UniqueConstraint("ip", "port", name="uq_ssh_host_keys_ip_port"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45))
    port: Mapped[int] = mapped_column(Integer)
    key_type: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(128))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class RemoteExecution(Base):
    """Every command RASED ran on a managed device or on the scanner host, with its output."""

    __tablename__ = "remote_executions"
    __table_args__ = (
        CheckConstraint("status IN ('ok','error')", name="status_valid"),
        Index("ix_remote_executions_started", "started_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    target: Mapped[str] = mapped_column(String(64))  # device IP, or "scanner" for local network checks
    service_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    section: Mapped[str] = mapped_column(String(16))
    label_ar: Mapped[str] = mapped_column(Text)
    command: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(8))
    had_errors: Mapped[bool] = mapped_column(Boolean, default=False)
    output: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class RouteTrace(Base):
    """A traceroute observation: how the scanner reached ``target`` (hop list, in order)."""

    __tablename__ = "route_traces"
    __table_args__ = (Index("ix_route_traces_target_created", "target", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(45))
    hops: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    reached: Mapped[bool] = mapped_column(Boolean, default=False)
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_created", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


# ---------------------------------------------------------------------------------------
# Physical topology (SNMP / LLDP / CDP / bridge forwarding tables)
# ---------------------------------------------------------------------------------------


class PhysicalLink(Base):
    """A discovered layer-2 adjacency: a local switch/device port and what is attached to it.

    ``source`` is how it was learned: ``lldp`` / ``cdp`` (neighbour advertises itself) or
    ``fdb`` (the switch's forwarding table maps a MAC to a port). ``remote_asset_id`` is filled
    when the neighbour resolves to a known inventory asset (by MAC or system name).
    """

    __tablename__ = "physical_links"
    __table_args__ = (
        UniqueConstraint("local_asset_id", "local_port", "remote_chassis_id", "remote_port", "source",
                         name="uq_physical_links_edge"),
        CheckConstraint("source IN ('lldp','cdp','fdb')", name="source_valid"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    local_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    local_port: Mapped[str] = mapped_column(String(128), default="")
    remote_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    remote_chassis_id: Mapped[str] = mapped_column(String(128), default="")
    remote_sysname: Mapped[str] = mapped_column(String(253), default="")
    remote_port: Mapped[str] = mapped_column(String(128), default="")
    remote_descr: Mapped[str] = mapped_column(String(256), default="")
    source: Mapped[str] = mapped_column(String(8), default="lldp")
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


# ---------------------------------------------------------------------------------------
# Vulnerability intelligence (offline CVE feed + correlation)
# ---------------------------------------------------------------------------------------


class CveEntry(Base):
    """One CVE from an imported offline feed, with its product-match rules in ``affected``."""

    __tablename__ = "cve_entries"
    __table_args__ = (Index("ix_cve_entries_severity", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    description_ar: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    published: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # [{vendor, product, version_start, version_end, version_exact}] — matched in Python.
    affected: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    references: Mapped[list[str]] = mapped_column(JSONType, default=list)
    imported_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # Exploit-prediction (FIRST EPSS) and known-exploited (CISA KEV) enrichment.
    epss: Mapped[float] = mapped_column(Float, default=0.0, server_default=text("0"))
    kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    kev_date: Mapped[str | None] = mapped_column(String(32), nullable=True)


class AssetVulnerability(Base):
    """A correlation between a discovered service and a known CVE."""

    __tablename__ = "asset_vulnerabilities"
    __table_args__ = (
        UniqueConstraint("asset_id", "service_id", "cve_id", name="uq_asset_vuln"),
        CheckConstraint("status IN ('open','resolved','false_positive')", name="status_valid"),
        Index("ix_asset_vuln_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    product: Mapped[str] = mapped_column(String(128), default="")
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    matched_on: Mapped[str] = mapped_column(String(128), default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    status: Mapped[str] = mapped_column(String(16), default="open")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


# ---------------------------------------------------------------------------------------
# Service policy (approved-service baseline) and operations (maintenance / notifications)
# ---------------------------------------------------------------------------------------


class ServicePolicyRule(Base):
    """An allow rule for the approved-service baseline. An open service that matches no rule
    is reported as unauthorised. ``port``/``device_type`` = NULL means 'any'."""

    __tablename__ = "service_policy_rules"
    __table_args__ = (
        CheckConstraint("protocol IN ('tcp','udp')", name="protocol_valid"),
        UniqueConstraint("port", "protocol", "device_type", name="uq_service_policy_rule"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(3), default="tcp")
    device_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note_ar: Mapped[str] = mapped_column(Text, default="")
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class MaintenanceWindow(Base):
    """A time window during which alert notifications are suppressed (optionally per subnet)."""

    __tablename__ = "maintenance_windows"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    starts_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ends_at: Mapped[datetime] = mapped_column(UTCDateTime)
    cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    note_ar: Mapped[str] = mapped_column(Text, default="")
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class NotificationConfig(Base):
    """Single-row (id=1) e-mail notification configuration for alerts."""

    __tablename__ = "notification_config"

    id: Mapped[int] = mapped_column(primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    smtp_host: Mapped[str] = mapped_column(String(253), default="")
    smtp_port: Mapped[int] = mapped_column(Integer, default=587)
    use_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    from_addr: Mapped[str] = mapped_column(String(253), default="")
    to_addrs: Mapped[list[str]] = mapped_column(JSONType, default=list)
    username: Mapped[str] = mapped_column(String(253), default="")
    secret_encrypted: Mapped[str] = mapped_column(Text, default="")
    min_severity: Mapped[str] = mapped_column(String(16), default="high")
    escalation_minutes: Mapped[int] = mapped_column(Integer, default=60)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AgentToken(Base):
    """An enrollment token for an endpoint agent. Only the SHA-256 hash is stored."""

    __tablename__ = "agent_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_host: Mapped[str | None] = mapped_column(String(253), nullable=True)
