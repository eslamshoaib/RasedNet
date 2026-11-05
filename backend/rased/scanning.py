"""Single entry point for creating scan jobs (API, single-device rescan, resume, scheduler).

Every path goes through ``create_scan_job`` so the safety checks are identical everywhere:
approved scope, non-intrusive profile, sensitive-scope rule, one active job per scope,
and re-validation of the scope against current settings.
"""

from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from rased.config import Settings
from rased.models import JOB_ACTIVE_STATUSES, ScanJob, ScanProfile, ScanScope, utcnow
from rased.scope import ScopeError, validate_scope
from rased.seed import profile_snapshot

# Sensitive scopes accept only gentle profiles (no banner reads, bounded packet rate).
SENSITIVE_MAX_RATE = 150

REQUIRED_PROFILE_KEYS = frozenset({
    "discovery_ports", "tcp_ports", "use_icmp", "use_arp", "resolve_dns", "grab_banners", "max_concurrency",
    "per_host_concurrency", "rate_per_second", "connect_timeout_ms", "retries",
})


class ScanStartError(Exception):
    def __init__(self, status_code: int, message_ar: str) -> None:
        super().__init__(message_ar)
        self.status_code = status_code
        self.message_ar = message_ar


def _validated(settings: Settings, cidr: str, hosts: list[str], ports: list[int]):  # type: ignore[no-untyped-def]
    try:
        return validate_scope(cidr, hosts, ports, allow_public=settings.allow_public_scopes, max_hosts=settings.max_scope_hosts)
    except ScopeError as exc:
        raise ScanStartError(422, str(exc)) from exc


def find_scope_for_ip(db: Session, settings: Settings, ip: str) -> ScanScope | None:
    """The most specific active, approved scope that covers ``ip`` (exclusions respected)."""
    best: tuple[int, ScanScope] | None = None
    for scope in db.scalars(select(ScanScope).where(ScanScope.is_active.is_(True), ScanScope.is_approved.is_(True))):
        try:
            validated = validate_scope(scope.cidr, scope.excluded_hosts, scope.excluded_ports,
                                       allow_public=settings.allow_public_scopes, max_hosts=settings.max_scope_hosts)
        except ScopeError:
            continue
        if validated.contains(ip) and (best is None or validated.network.prefixlen > best[0]):
            best = (validated.network.prefixlen, scope)
    return best[1] if best else None


def create_scan_job(
    db: Session,
    settings: Settings,
    *,
    scope_id: int,
    profile_id: int,
    requested_by_id: int | None,
    trigger: str,
    target_ip: str | None = None,
    resume_of: ScanJob | None = None,
) -> ScanJob:
    """Create (flush, not commit) a queued job after all safety checks. Raises ScanStartError."""
    scope = db.scalar(select(ScanScope).where(ScanScope.id == scope_id).with_for_update())
    if scope is None or not scope.is_active:
        raise ScanStartError(404, "النطاق غير موجود")
    if not scope.is_approved:
        raise ScanStartError(409, "لا يمكن الفحص: النطاق غير معتمد من المسؤول")
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise ScanStartError(404, "ملف الفحص غير موجود")
    if profile.is_intrusive:
        raise ScanStartError(409, "ملفات الفحص التدخلية غير مسموحة في الفحص الآلي وتتطلب إجراء اعتماد منفصلاً")
    if scope.is_sensitive and (profile.grab_banners or profile.rate_per_second > SENSITIVE_MAX_RATE):
        raise ScanStartError(409, "هذا النطاق مصنف حساساً ولا يُسمح عليه إلا بملف «اكتشاف آمن»")
    validated = _validated(settings, scope.cidr, scope.excluded_hosts, scope.excluded_ports)
    if db.scalar(select(ScanJob.id).where(ScanJob.scope_id == scope.id, ScanJob.status.in_(JOB_ACTIVE_STATUSES))):
        raise ScanStartError(409, "يوجد فحص قيد التنفيذ أو في الانتظار على هذا النطاق")

    snapshot = {
        "cidr": validated.cidr,
        "excluded_hosts": [str(n) for n in validated.exclusions],
        "excluded_ports": sorted(validated.excluded_ports),
        "name": scope.name,
        "approved_at": scope.approved_at.isoformat() if scope.approved_at else None,
        "approved_by_id": scope.approved_by_id,
    }
    total = validated.target_count()
    offset = 0
    coverage = None
    prof_snapshot = profile_snapshot(profile)

    if target_ip is not None:
        ip = str(ipaddress.ip_address(target_ip))
        if not validated.contains(ip):
            raise ScanStartError(409, "الجهاز خارج النطاق المعتمد أو ضمن العناوين المستثناة")
        snapshot.update(cidr=f"{ip}/{32 if ':' not in ip else 128}", excluded_hosts=[], target_ip=ip)
        total = 1
    elif resume_of is not None:
        # Continue exactly where the interrupted job stopped, with its original configuration.
        snapshot = dict(resume_of.scope_snapshot or {})
        prof_snapshot = dict(resume_of.profile_snapshot or {})
        if "cidr" not in snapshot or not REQUIRED_PROFILE_KEYS <= prof_snapshot.keys():
            raise ScanStartError(409, "لا يمكن استكمال هذا الفحص لأن بيانات إعداده غير مكتملة؛ شغّل فحصاً جديداً")
        _validated(settings, snapshot["cidr"], snapshot.get("excluded_hosts", []), snapshot.get("excluded_ports", []))
        # processed_hosts already includes the job's own starting offset and only grows after a
        # chunk has been committed, so it is exactly the number of targets fully recorded.
        offset = resume_of.processed_hosts
        total = resume_of.total_hosts
        coverage = resume_of.coverage_started_at or resume_of.started_at
        if offset >= total:
            raise ScanStartError(409, "الفحص السابق كان قد عالج كل العناوين؛ لا شيء لاستكماله")

    job = ScanJob(
        scope_id=scope.id, profile_id=profile.id, requested_by_id=requested_by_id, trigger=trigger,
        status="queued", cancel_requested=False, scope_snapshot=snapshot, profile_snapshot=prof_snapshot,
        total_hosts=total, processed_hosts=offset, alive_hosts=0, open_services=0, created_at=utcnow(),
        resumed_from_id=resume_of.id if resume_of is not None else None, resume_offset=offset,
        coverage_started_at=coverage,
    )
    db.add(job)
    try:
        db.flush()
    except IntegrityError as exc:  # partial unique index: a concurrent request won the race
        db.rollback()
        raise ScanStartError(409, "يوجد فحص قيد التنفيذ أو في الانتظار على هذا النطاق") from exc
    return job
