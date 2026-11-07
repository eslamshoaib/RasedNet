"""Scan scopes (with explicit approval), scan profiles and scan jobs."""

from __future__ import annotations

import ipaddress
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, not_found, require
from rasednet.i18n import get_lang, tr
from rasednet.api.schemas import (
    BulkScopeIn,
    BulkScopeResult,
    CandidateOut,
    JobOut,
    Page,
    ProfileOut,
    RerunIn,
    ScanCreateIn,
    ScanDiffOut,
    ScanResultOut,
    ScheduleIn,
    ScopeApproveIn,
    ScopeIn,
    ScopeOut,
    ScopeUpdateIn,
)
from rasednet.config import Settings
from rasednet.discovery.networks import CandidateNetwork, discover_candidate_networks
from rasednet.models import (
    JOB_ACTIVE_STATUSES,
    JOB_STATUSES,
    RouteTrace,
    ScanJob,
    ScanProfile,
    ScanResult,
    ScanScope,
    utcnow,
)
from rasednet.scanning import ScanStartError, create_scan_job
from rasednet.scope import ScopeError, ValidatedScope, validate_scope

router = APIRouter(prefix="/api", tags=["scans"])



def _validate(settings: Settings, cidr: str, excluded_hosts: list[str], excluded_ports: list[int]) -> ValidatedScope:
    try:
        return validate_scope(
            cidr, excluded_hosts, excluded_ports,
            allow_public=settings.allow_public_scopes, max_hosts=settings.max_scope_hosts,
        )
    except ScopeError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def _active_job_scope_ids(db: Session) -> set[int]:
    return set(db.scalars(select(ScanJob.scope_id).where(ScanJob.status.in_(JOB_ACTIVE_STATUSES))))


def _scope_out(scope: ScanScope, settings: Settings, active: set[int]) -> ScopeOut:
    out = ScopeOut.model_validate(scope)
    try:
        out.target_count = _validate(settings, scope.cidr, scope.excluded_hosts, scope.excluded_ports).target_count()
    except HTTPException:
        out.target_count = 0  # no longer valid under current settings; cannot be scanned
    out.has_active_job = scope.id in active
    return out


# --- scopes -------------------------------------------------------------------------------


@router.get("/scopes", response_model=list[ScopeOut])
def list_scopes(
    request: Request, include_inactive: bool = False,
    _: AuthContext = Depends(require("scope:read")), db: Session = Depends(get_db),
) -> list[ScopeOut]:
    q = select(ScanScope).order_by(ScanScope.id)
    if not include_inactive:
        q = q.where(ScanScope.is_active.is_(True))
    active = _active_job_scope_ids(db)
    return [_scope_out(s, request.app.state.settings, active) for s in db.scalars(q)]


@router.post("/scopes", response_model=ScopeOut, status_code=201)
def create_scope(
    body: ScopeIn, request: Request, auth: AuthContext = Depends(require("scope:manage")), db: Session = Depends(get_db)
) -> ScopeOut:
    settings: Settings = request.app.state.settings
    validated = _validate(settings, body.cidr, body.excluded_hosts, body.excluded_ports)
    if db.scalar(select(ScanScope.id).where(ScanScope.name == body.name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("يوجد نطاق آخر بنفس الاسم", "Another scope with this name exists"))
    now = utcnow()
    scope = ScanScope(
        name=body.name,
        cidr=validated.cidr,
        description=body.description,
        excluded_hosts=[str(n) for n in validated.exclusions],
        excluded_ports=sorted(validated.excluded_ports),
        is_sensitive=body.is_sensitive,
        is_approved=False,
        is_active=True,
        created_by_id=auth.user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(scope)
    db.flush()
    audit(db, request, "scope.create", auth=auth, target_type="scope", target_id=scope.id,
          details={"cidr": scope.cidr, "excluded_hosts": scope.excluded_hosts, "sensitive": scope.is_sensitive})
    db.commit()
    return _scope_out(scope, settings, set())


def _get_scope(db: Session, scope_id: int, *, lock: bool = False) -> ScanScope:
    q = select(ScanScope).where(ScanScope.id == scope_id)
    if lock:
        q = q.with_for_update()
    scope = db.scalar(q)
    if scope is None or not scope.is_active:
        raise not_found("النطاق")
    return scope


@router.patch("/scopes/{scope_id}", response_model=ScopeOut)
def update_scope(
    scope_id: int, body: ScopeUpdateIn, request: Request,
    auth: AuthContext = Depends(require("scope:manage")), db: Session = Depends(get_db),
) -> ScopeOut:
    settings: Settings = request.app.state.settings
    scope = _get_scope(db, scope_id, lock=True)
    if scope.id in _active_job_scope_ids(db):
        raise HTTPException(status.HTTP_409_CONFLICT, tr("لا يمكن تعديل النطاق أثناء تنفيذ فحص عليه", "The scope cannot be edited while a scan on it is running"))
    changes: dict[str, object] = {}
    if body.name is not None and body.name.strip() != scope.name:
        name = body.name.strip()
        if db.scalar(select(ScanScope.id).where(ScanScope.name == name, ScanScope.id != scope.id)) is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, tr("يوجد نطاق آخر بنفس الاسم", "Another scope with this name exists"))
        scope.name = name
        changes["name"] = name
    if body.description is not None:
        scope.description = body.description
        changes["description"] = True
    boundary_changed = any(v is not None for v in (body.cidr, body.excluded_hosts, body.excluded_ports, body.is_sensitive))
    if boundary_changed:
        validated = _validate(
            settings,
            body.cidr if body.cidr is not None else scope.cidr,
            body.excluded_hosts if body.excluded_hosts is not None else scope.excluded_hosts,
            body.excluded_ports if body.excluded_ports is not None else scope.excluded_ports,
        )
        scope.cidr = validated.cidr
        scope.excluded_hosts = [str(n) for n in validated.exclusions]
        scope.excluded_ports = sorted(validated.excluded_ports)
        if body.is_sensitive is not None:
            scope.is_sensitive = body.is_sensitive
        # Any change to the scanning boundary requires a fresh approval.
        if scope.is_approved:
            scope.is_approved = False
            scope.approved_at = None
            scope.approved_by_id = None
            changes["approval_revoked"] = True
        changes.update(cidr=scope.cidr, excluded_hosts=scope.excluded_hosts, excluded_ports=scope.excluded_ports,
                       sensitive=scope.is_sensitive)
    scope.updated_at = utcnow()
    audit(db, request, "scope.update", auth=auth, target_type="scope", target_id=scope.id, details=changes)
    db.commit()
    return _scope_out(scope, settings, set())


@router.post("/scopes/{scope_id}/approve", response_model=ScopeOut)
def approve_scope(
    scope_id: int, body: ScopeApproveIn, request: Request,
    auth: AuthContext = Depends(require("scope:approve")), db: Session = Depends(get_db),
) -> ScopeOut:
    settings: Settings = request.app.state.settings
    if not body.confirm:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("يجب تأكيد أن المؤسسة تملك هذا النطاق ومصرح لها بفحصه", "You must confirm the organisation owns this scope and is authorized to scan it"))
    scope = _get_scope(db, scope_id, lock=True)
    _validate(settings, scope.cidr, scope.excluded_hosts, scope.excluded_ports)
    scope.is_approved = True
    scope.approved_at = utcnow()
    scope.approved_by_id = auth.user.id
    audit(db, request, "scope.approve", auth=auth, target_type="scope", target_id=scope.id, details={"cidr": scope.cidr})
    db.commit()
    return _scope_out(scope, settings, _active_job_scope_ids(db))


@router.post("/scopes/{scope_id}/revoke", response_model=ScopeOut)
def revoke_scope(
    scope_id: int, request: Request, auth: AuthContext = Depends(require("scope:approve")), db: Session = Depends(get_db)
) -> ScopeOut:
    scope = _get_scope(db, scope_id, lock=True)
    scope.is_approved = False
    scope.approved_at = None
    scope.approved_by_id = None
    audit(db, request, "scope.revoke", auth=auth, target_type="scope", target_id=scope.id)
    db.commit()
    return _scope_out(scope, request.app.state.settings, _active_job_scope_ids(db))


@router.put("/scopes/{scope_id}/schedule", response_model=ScopeOut)
def set_schedule(
    scope_id: int, body: ScheduleIn, request: Request,
    auth: AuthContext = Depends(require("scan:run")), db: Session = Depends(get_db),
) -> ScopeOut:
    """Enable (interval + profile) or disable (interval null) the recurring scan of a scope."""
    scope = _get_scope(db, scope_id, lock=True)
    if body.interval_minutes is None:
        scope.schedule_interval_minutes = None
        scope.schedule_next_run_at = None
        scope.schedule_last_error = None
        details: dict[str, object] = {"enabled": False}
    else:
        if body.profile_id is None or db.get(ScanProfile, body.profile_id) is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("اختر ملف فحص صالحاً للجدولة", "Choose a valid scan profile for the schedule"))
        if not scope.is_approved:
            raise HTTPException(status.HTTP_409_CONFLICT, tr("لا يمكن جدولة فحص نطاق غير معتمد", "Cannot schedule a scan for an unapproved scope"))
        scope.schedule_profile_id = body.profile_id
        scope.schedule_interval_minutes = body.interval_minutes
        scope.schedule_next_run_at = utcnow() + timedelta(minutes=body.first_run_after_minutes)
        scope.schedule_last_error = None
        details = {"enabled": True, "interval_minutes": body.interval_minutes, "profile_id": body.profile_id}
    audit(db, request, "scope.schedule", auth=auth, target_type="scope", target_id=scope.id, details=details)
    db.commit()
    return _scope_out(scope, request.app.state.settings, _active_job_scope_ids(db))


@router.delete("/scopes/{scope_id}", status_code=204)
def delete_scope(
    scope_id: int, request: Request, auth: AuthContext = Depends(require("scope:manage")), db: Session = Depends(get_db)
) -> Response:
    scope = _get_scope(db, scope_id, lock=True)
    if scope.id in _active_job_scope_ids(db):
        raise HTTPException(status.HTTP_409_CONFLICT, tr("لا يمكن حذف النطاق أثناء تنفيذ فحص عليه", "The scope cannot be deleted while a scan on it is running"))
    # Soft delete: scan history keeps referring to the scope.
    scope.is_active = False
    scope.is_approved = False
    scope.name = (f"{scope.name} (deleted #{scope.id})" if get_lang()=="en" else f"{scope.name} (محذوف #{scope.id})")[:128]
    audit(db, request, "scope.delete", auth=auth, target_type="scope", target_id=scope.id)
    db.commit()
    return Response(status_code=204)


# --- automatic network discovery ----------------------------------------------------------


def _host_count(network: ipaddress.IPv4Network) -> int:
    return network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2


def _suggest_narrower(settings: Settings, local_ips: list[str], network: ipaddress.IPv4Network) -> str | None:
    """Largest sub-network around the host's own address that fits the scope-size limit."""
    anchor = local_ips[0] if local_ips else str(network.network_address)
    for prefix in range(network.prefixlen + 1, 31):
        candidate = ipaddress.IPv4Network(f"{anchor}/{prefix}", strict=False)
        if _host_count(candidate) <= settings.max_scope_hosts:
            return str(candidate)
    return None


@router.get("/scopes/candidates", response_model=list[CandidateOut])
def scope_candidates(
    request: Request, _: AuthContext = Depends(require("scope:manage")), db: Session = Depends(get_db)
) -> list[CandidateOut]:
    """Networks this server is attached to or has routes for (read from the OS, nothing sent)."""
    settings: Settings = request.app.state.settings
    discover = getattr(request.app.state, "network_discovery", None) or discover_candidate_networks
    scopes = list(db.scalars(select(ScanScope).where(ScanScope.is_active.is_(True))))
    parsed: list[tuple[ScanScope, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for s in scopes:
        try:
            parsed.append((s, ipaddress.ip_network(s.cidr, strict=False)))
        except ValueError:
            continue
    result: list[CandidateOut] = []
    found = list(discover())
    # Networks revealed by traced routing paths (each responding router sits inside one).
    known = {c.cidr for c in found}
    for trace in db.scalars(select(RouteTrace).order_by(RouteTrace.created_at.desc()).limit(200)):
        previous = None
        for hop in trace.hops:
            ip = hop.get("ip")
            try:
                addr = ipaddress.ip_address(ip) if ip else None
            except ValueError:
                addr = None
            if addr is None or addr.version != 4 or not addr.is_private:
                continue
            net = ipaddress.ip_network(f"{addr}/24", strict=False)
            if str(net) not in known and not any(net.overlaps(ipaddress.ip_network(c)) for c in known):
                known.add(str(net))
                found.append(CandidateNetwork(cidr=str(net), sources=["trace"], interfaces=[],
                                              gateways=[previous] if previous else []))
            previous = str(addr)
    for cand in found:
        network = cand.network
        out = CandidateOut(
            cidr=cand.cidr, sources=cand.sources, interfaces=cand.interfaces, local_ips=cand.local_ips,
            gateways=cand.gateways, is_virtual=cand.is_virtual, host_count=_host_count(network), allowed=True,
        )
        try:
            validate_scope(cand.cidr, [], [], allow_public=settings.allow_public_scopes, max_hosts=settings.max_scope_hosts)
        except ScopeError as exc:
            out.allowed = False
            out.reason_ar = str(exc)
            if out.host_count > settings.max_scope_hosts:
                out.suggested_cidr = _suggest_narrower(settings, cand.local_ips, network)
        for scope, scope_net in parsed:
            if scope_net.version != 4:
                continue
            if scope_net == network:
                out.existing_scope_id = scope.id
                out.existing_scope_name = scope.name
                out.existing_scope_approved = scope.is_approved
            elif scope_net.overlaps(network):
                out.overlaps_scope_names.append(scope.name)
        result.append(out)
    return result


@router.post("/scopes/bulk", response_model=list[BulkScopeResult])
def bulk_scopes(
    body: BulkScopeIn, request: Request, auth: AuthContext = Depends(require("scope:manage")), db: Session = Depends(get_db)
) -> list[BulkScopeResult]:
    """Add several networks at once; optionally approve them and start a scan on each."""
    settings: Settings = request.app.state.settings
    if body.approve:
        if not auth.can("scope:approve"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, tr("ليست لديك صلاحية اعتماد النطاقات", "You do not have permission to approve scopes"))
        if not body.confirm:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("يجب تأكيد أن المؤسسة تملك هذه النطاقات ومصرح لها بفحصها", "You must confirm the organisation owns these scopes and is authorized to scan them"))
    if body.start_scan_profile_id is not None:
        if not body.approve:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("لا يمكن بدء الفحص دون اعتماد النطاقات", "Cannot start the scan without approving the scopes"))
        if not auth.can("scan:run"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, tr("ليست لديك صلاحية تشغيل الفحص", "You do not have permission to run scans"))

    results: list[BulkScopeResult] = []
    for item in body.items:
        res = BulkScopeResult(cidr=item.cidr)
        results.append(res)
        try:
            validated = validate_scope(item.cidr, [], [], allow_public=settings.allow_public_scopes, max_hosts=settings.max_scope_hosts)
        except ScopeError as exc:
            res.error_ar = str(exc)
            continue
        res.cidr = validated.cidr
        scope = db.scalar(select(ScanScope).where(ScanScope.cidr == validated.cidr, ScanScope.is_active.is_(True)).limit(1))
        now = utcnow()
        if scope is None:
            base = (item.name or (f"Network {validated.cidr}" if get_lang()=="en" else f"شبكة {validated.cidr}")).strip()[:120]
            name, n = base, 2
            while db.scalar(select(ScanScope.id).where(ScanScope.name == name)) is not None:
                name, n = f"{base} ({n})", n + 1
            scope = ScanScope(
                name=name, cidr=validated.cidr, description=("Added from automatic network discovery" if get_lang()=="en" else "أضيف من الاكتشاف التلقائي للشبكات"),
                excluded_hosts=[], excluded_ports=[], is_sensitive=False, is_approved=False, is_active=True,
                created_by_id=auth.user.id, created_at=now, updated_at=now,
            )
            db.add(scope)
            db.flush()
            res.created = True
            audit(db, request, "scope.create", auth=auth, target_type="scope", target_id=scope.id,
                  details={"cidr": scope.cidr, "source": "auto_discovery"})
        res.scope_id = scope.id
        if body.approve and not scope.is_approved:
            scope.is_approved = True
            scope.approved_at = now
            scope.approved_by_id = auth.user.id
            audit(db, request, "scope.approve", auth=auth, target_type="scope", target_id=scope.id,
                  details={"cidr": scope.cidr, "source": "auto_discovery"})
        res.approved = scope.is_approved
        db.commit()

    if body.start_scan_profile_id is not None:
        for res in results:
            if res.scope_id is None or res.error_ar:
                continue
            try:
                res.job_id = _launch_scan(db, request, auth, res.scope_id, body.start_scan_profile_id).id
            except HTTPException as exc:
                db.rollback()
                res.error_ar = str(exc.detail)
    return results


# --- profiles -----------------------------------------------------------------------------


@router.get("/profiles", response_model=list[ProfileOut])
def list_profiles(_: AuthContext = Depends(require("scan:read")), db: Session = Depends(get_db)) -> list[ScanProfile]:
    return list(db.scalars(select(ScanProfile).order_by(ScanProfile.id)))


# --- jobs ---------------------------------------------------------------------------------


def _job_out(job: ScanJob) -> JobOut:
    out = JobOut.model_validate(job)
    out.scope_name = job.scope.name
    out.scope_cidr = str(job.scope_snapshot.get("cidr", job.scope.cidr))
    out.profile_name_ar = job.profile.name_ar
    out.target_ip = job.scope_snapshot.get("target_ip")
    return out


@router.post("/scans", response_model=JobOut, status_code=201)
def start_scan(
    body: ScanCreateIn, request: Request, auth: AuthContext = Depends(require("scan:run")), db: Session = Depends(get_db)
) -> JobOut:
    return _job_out(_launch_scan(db, request, auth, body.scope_id, body.profile_id))


def _launch_scan(
    db: Session, request: Request, auth: AuthContext, scope_id: int, profile_id: int, *,
    trigger: str = "manual", target_ip: str | None = None, resume_of: ScanJob | None = None,
) -> ScanJob:
    """Create a job through the shared safety checks, audit it, commit and submit it."""
    settings: Settings = request.app.state.settings
    try:
        job = create_scan_job(db, settings, scope_id=scope_id, profile_id=profile_id, requested_by_id=auth.user.id,
                              trigger=trigger, target_ip=target_ip, resume_of=resume_of)
    except ScanStartError as exc:
        db.rollback()
        audit(db, request, "scan.start", auth=auth, success=False, target_type="scope", target_id=scope_id,
              details={"reason": exc.message_ar, "trigger": trigger})
        db.commit()
        raise HTTPException(exc.status_code, exc.message_ar) from exc
    audit(db, request, "scan.start", auth=auth, target_type="scan_job", target_id=job.id,
          details={"scope_id": scope_id, "cidr": job.scope_snapshot.get("cidr"), "profile": job.profile_snapshot.get("code"),
                   "targets": job.total_hosts, "trigger": trigger, "resume_offset": job.resume_offset})
    db.commit()
    request.app.state.runner.submit(job.id)
    return job


@router.post("/scans/{job_id}/rerun", response_model=JobOut, status_code=201)
def rerun_scan(
    job_id: int, body: RerunIn, request: Request,
    auth: AuthContext = Depends(require("scan:run")), db: Session = Depends(get_db),
) -> JobOut:
    """Run a finished job again: from the start, or continue where an unfinished one stopped."""
    old = db.get(ScanJob, job_id)
    if old is None:
        raise not_found("الفحص")
    if old.status in JOB_ACTIVE_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("الفحص ما زال قيد التنفيذ", "The scan is still running"))
    if body.mode == "resume":
        if old.status not in ("interrupted", "cancelled", "failed") or old.processed_hosts >= old.total_hosts:
            raise HTTPException(status.HTTP_409_CONFLICT, tr("لا يوجد جزء متبقٍ من هذا الفحص لاستكماله", "There is no remaining part of this scan to resume"))
        job = _launch_scan(db, request, auth, old.scope_id, old.profile_id, trigger="resume", resume_of=old)
    else:
        target = old.scope_snapshot.get("target_ip")
        job = _launch_scan(db, request, auth, old.scope_id, old.profile_id, trigger="rerun", target_ip=target)
    return _job_out(job)


class RescanAllIn(BaseModel):
    profile_id: int | None = None


@router.post("/scans/rescan-all")
def rescan_all(body: RescanAllIn, request: Request,
               auth: AuthContext = Depends(require("scan:run")), db: Session = Depends(get_db)) -> dict[str, object]:
    """Queue a scan for every approved scope that has no active job — one click for all networks."""
    profile_id = body.profile_id
    if profile_id is None:
        prof = db.scalar(select(ScanProfile).where(ScanProfile.code == "standard_inventory")) \
            or db.scalar(select(ScanProfile).where(ScanProfile.is_intrusive.is_(False)).order_by(ScanProfile.id))
        if prof is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, tr("لا يوجد ملف فحص متاح", "No scan profile is available"))
        profile_id = prof.id
    active = _active_job_scope_ids(db)
    scopes = db.scalars(select(ScanScope).where(ScanScope.is_active.is_(True), ScanScope.is_approved.is_(True))).all()
    started: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    for scope in scopes:
        if scope.id in active:
            skipped.append({"scope_id": scope.id, "name": scope.name, "reason": tr("قيد التنفيذ بالفعل", "already running")})
            continue
        try:
            job = _launch_scan(db, request, auth, scope.id, profile_id, trigger="manual")
            started.append({"scope_id": scope.id, "name": scope.name, "job_id": job.id})
        except HTTPException as exc:
            skipped.append({"scope_id": scope.id, "name": scope.name, "reason": str(exc.detail)})
    audit(db, request, "scan.rescan_all", auth=auth, details={"started": len(started), "skipped": len(skipped)})
    db.commit()
    return {"started": started, "skipped": skipped}


@router.get("/scans", response_model=Page[JobOut])
def list_scans(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
    scope_id: int | None = None, status_filter: str | None = Query(None, alias="status"),
    _: AuthContext = Depends(require("scan:read")), db: Session = Depends(get_db),
) -> Page[JobOut]:
    q = select(ScanJob)
    if scope_id is not None:
        q = q.where(ScanJob.scope_id == scope_id)
    if status_filter:
        if status_filter not in JOB_STATUSES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("حالة الفحص غير معروفة", "Unknown scan mode"))
        q = q.where(ScanJob.status == status_filter)
    total = int(db.scalar(select(func.count()).select_from(q.subquery())) or 0)
    jobs = db.scalars(q.order_by(ScanJob.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[_job_out(j) for j in jobs], total=total, page=page, page_size=page_size)


@router.get("/scans/{job_id}", response_model=JobOut)
def get_scan(job_id: int, _: AuthContext = Depends(require("scan:read")), db: Session = Depends(get_db)) -> JobOut:
    job = db.get(ScanJob, job_id)
    if job is None:
        raise not_found("الفحص")
    return _job_out(job)


@router.post("/scans/emergency-stop", response_model=list[int])
def emergency_stop(request: Request, auth: AuthContext = Depends(require("scan:run")), db: Session = Depends(get_db)) -> list[int]:
    jobs = db.scalars(select(ScanJob).where(ScanJob.status.in_(JOB_ACTIVE_STATUSES))).all()
    runner = request.app.state.runner
    ids = []
    for job in jobs:
        job.cancel_requested = True
        if job.status == "queued" and not runner.is_tracked(job.id):
            job.status = "cancelled"
            job.finished_at = utcnow()
        ids.append(job.id)
    audit(db, request, "scan.emergency_stop", auth=auth, details={"jobs": ids})
    db.commit()
    runner.cancel_all()
    return ids


@router.post("/scans/{job_id}/cancel", response_model=JobOut)
def cancel_scan(job_id: int, request: Request, auth: AuthContext = Depends(require("scan:run")), db: Session = Depends(get_db)) -> JobOut:
    job = db.get(ScanJob, job_id)
    if job is None:
        raise not_found("الفحص")
    if job.status not in JOB_ACTIVE_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("الفحص منتهٍ بالفعل", "The scan has already finished"))
    runner = request.app.state.runner
    job.cancel_requested = True
    if job.status == "queued" and not runner.is_tracked(job.id):
        job.status = "cancelled"
        job.finished_at = utcnow()
    audit(db, request, "scan.cancel", auth=auth, target_type="scan_job", target_id=job.id)
    db.commit()
    runner.cancel(job.id)
    return _job_out(job)


@router.get("/scans/{job_id}/results", response_model=Page[ScanResultOut])
def scan_results(
    job_id: int, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
    _: AuthContext = Depends(require("scan:read")), db: Session = Depends(get_db),
) -> Page[ScanResultOut]:
    if db.get(ScanJob, job_id) is None:
        raise not_found("الفحص")
    q = select(ScanResult).where(ScanResult.job_id == job_id)
    total = int(db.scalar(select(func.count()).select_from(q.subquery())) or 0)
    rows = db.scalars(q.order_by(ScanResult.id).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[ScanResultOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)


@router.get("/scans/{job_id}/diff", response_model=ScanDiffOut)
def scan_diff(job_id: int, _: AuthContext = Depends(require("scan:read")), db: Session = Depends(get_db)) -> ScanDiffOut:
    """Compare a job with the previous *completed* job on the same scope."""
    job = db.get(ScanJob, job_id)
    if job is None:
        raise not_found("الفحص")
    previous = db.scalar(
        select(ScanJob)
        .where(ScanJob.scope_id == job.scope_id, ScanJob.id < job.id, ScanJob.status == "completed")
        .order_by(ScanJob.id.desc())
        .limit(1)
    )

    def snapshot(jid: int) -> tuple[set[str], set[str]]:
        hosts: set[str] = set()
        services: set[str] = set()
        for ip, ports in db.execute(select(ScanResult.ip, ScanResult.open_ports).where(ScanResult.job_id == jid)):
            hosts.add(ip)
            services.update(f"{ip}:{p}/tcp" for p in ports or [])
        return hosts, services

    cur_hosts, cur_services = snapshot(job.id)
    prev_hosts, prev_services = snapshot(previous.id) if previous else (set(), set())
    return ScanDiffOut(
        job_id=job.id,
        previous_job_id=previous.id if previous else None,
        new_hosts=sorted(cur_hosts - prev_hosts),
        missing_hosts=sorted(prev_hosts - cur_hosts),
        new_services=sorted(cur_services - prev_services),
        closed_services=sorted(prev_services - cur_services),
    )
