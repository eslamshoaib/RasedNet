"""Assets, services, alerts, change log, dashboard and audit log endpoints."""

from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, like_pattern, not_found, require
from rasednet.api.schemas import (
    AlertOut,
    AssetDetailOut,
    AssetOut,
    AssetUpdateIn,
    AuditOut,
    EventOut,
    FingerprintOut,
    IdentifierOut,
    IpObservationOut,
    JobOut,
    Page,
    RescanIn,
    ServiceOut,
)
from rasednet.discovery.fingerprint import DEVICE_TYPES
from rasednet.discovery.services import exposure_note
from rasednet.i18n import get_lang, tr
from rasednet.inventory import asset_label
from rasednet.models import (
    Alert,
    Asset,
    AuditLog,
    DeviceFingerprint,
    Event,
    IpObservation,
    ScanJob,
    Service,
    utcnow,
)
from rasednet.remediation import build_guidance
from rasednet.scanning import find_scope_for_ip

router = APIRouter(prefix="/api", tags=["inventory"])

ASSET_SORTS = {
    "last_seen": Asset.last_seen,
    "first_seen": Asset.first_seen,
    "current_ip": Asset.current_ip,
    "hostname": Asset.hostname,
    "device_type": Asset.device_type,
    "status": Asset.status,
}


def _service_out(svc: Service, asset: Asset | None = None) -> ServiceOut:
    out = ServiceOut.model_validate(svc)
    out.exposure_note_ar = exposure_note(svc.service_name)
    if asset is not None:
        out.asset_ip = asset.current_ip
        out.asset_label = asset_label(asset)
    return out


def _with_guidance(out: ServiceOut, svc: Service, asset: Asset) -> ServiceOut:
    if svc.state == "open":
        out.guidance = build_guidance(svc.service_name, svc.port, asset.current_ip, asset.os_family, asset.device_type)
    return out


def _open_counts(db: Session, asset_ids: list[int]) -> dict[int, int]:
    if not asset_ids:
        return {}
    rows = db.execute(
        select(Service.asset_id, func.count())
        .where(Service.asset_id.in_(asset_ids), Service.state == "open")
        .group_by(Service.asset_id)
    )
    return {aid: int(n) for aid, n in rows}


# --- assets -------------------------------------------------------------------------------


@router.get("/assets", response_model=Page[AssetOut])
def list_assets(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=1000),
    q: str | None = Query(None, max_length=128),
    status_filter: str | None = Query(None, alias="status", pattern="^(online|offline|unknown)$"),
    device_type: str | None = Query(None, max_length=32),
    sort: str = Query("last_seen"), order: str = Query("desc", pattern="^(asc|desc)$"),
    _: AuthContext = Depends(require("asset:read")), db: Session = Depends(get_db),
) -> Page[AssetOut]:
    if sort not in ASSET_SORTS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("حقل الترتيب غير مدعوم", "Unsupported sort field"))
    if device_type is not None and device_type not in DEVICE_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("نوع الجهاز غير معروف", "Unknown device type"))
    query = select(Asset)
    if q and q.strip():
        pattern = like_pattern(q.strip())
        query = query.where(
            or_(
                Asset.current_ip.ilike(pattern, escape="\\"),
                Asset.hostname.ilike(pattern, escape="\\"),
                Asset.mac.ilike(pattern, escape="\\"),
                Asset.display_name.ilike(pattern, escape="\\"),
                Asset.vendor.ilike(pattern, escape="\\"),
                Asset.netbios_name.ilike(pattern, escape="\\"),
                Asset.model.ilike(pattern, escape="\\"),
            )
        )
    if status_filter:
        query = query.where(Asset.status == status_filter)
    if device_type:
        query = query.where(Asset.device_type == device_type)
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    column = ASSET_SORTS[sort]
    ordering = column.asc() if order == "asc" else column.desc()
    assets = db.scalars(query.order_by(ordering, Asset.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    counts = _open_counts(db, [a.id for a in assets])
    items = []
    for a in assets:
        out = AssetOut.model_validate(a)
        out.open_service_count = counts.get(a.id, 0)
        items.append(out)
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/assets/{asset_id}", response_model=AssetDetailOut)
def get_asset(asset_id: int, _: AuthContext = Depends(require("asset:read")), db: Session = Depends(get_db)) -> AssetDetailOut:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise not_found("الجهاز")
    fingerprint = db.scalar(
        select(DeviceFingerprint).where(DeviceFingerprint.asset_id == asset.id)
        .order_by(DeviceFingerprint.created_at.desc(), DeviceFingerprint.id.desc()).limit(1)
    )
    ip_history = db.scalars(
        select(IpObservation).where(IpObservation.asset_id == asset.id).order_by(IpObservation.last_seen.desc()).limit(100)
    ).all()
    events = db.scalars(select(Event).where(Event.asset_id == asset.id).order_by(Event.id.desc()).limit(50)).all()
    alerts = db.scalars(
        select(Alert).where(Alert.asset_id == asset.id, Alert.status != "resolved").order_by(Alert.id.desc()).limit(50)
    ).all()
    services = sorted(asset.services, key=lambda s: (s.state != "open", s.port))
    base = AssetOut.model_validate(asset).model_dump()
    base["open_service_count"] = sum(1 for s in services if s.state == "open")
    return AssetDetailOut(
        **base,
        notes=asset.notes,
        identifiers=[IdentifierOut.model_validate(i) for i in sorted(asset.identifiers, key=lambda i: (i.kind, i.value))],
        ip_history=[IpObservationOut.model_validate(o) for o in ip_history],
        services=[_with_guidance(_service_out(s), s, asset) for s in services],
        fingerprint=FingerprintOut.model_validate(fingerprint) if fingerprint else None,
        events=[EventOut.model_validate(e) for e in events],
        alerts=[AlertOut.model_validate(a) for a in alerts],
    )


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int, body: AssetUpdateIn, request: Request,
    auth: AuthContext = Depends(require("asset:write")), db: Session = Depends(get_db),
) -> AssetOut:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise not_found("الجهاز")
    changes = body.model_dump(exclude_unset=True)
    if "display_name" in changes:
        asset.display_name = (body.display_name or "").strip() or None
    if body.criticality is not None:
        asset.criticality = body.criticality
    if body.notes is not None:
        asset.notes = body.notes
    audit(db, request, "asset.update", auth=auth, target_type="asset", target_id=asset.id, details=changes)
    db.commit()
    out = AssetOut.model_validate(asset)
    out.open_service_count = _open_counts(db, [asset.id]).get(asset.id, 0)
    return out


class AssetCreateIn(BaseModel):
    current_ip: str = Field(min_length=1, max_length=45)
    display_name: str | None = Field(default=None, max_length=128)
    mac: str | None = Field(default=None, max_length=17)
    hostname: str | None = Field(default=None, max_length=253)
    device_type: str = "unknown"
    criticality: Literal["low", "normal", "high", "critical"] = "normal"
    notes: str = Field(default="", max_length=2000)


@router.post("/assets", response_model=AssetOut, status_code=201)
def create_asset(body: AssetCreateIn, request: Request,
                 auth: AuthContext = Depends(require("asset:write")), db: Session = Depends(get_db)) -> AssetOut:
    """Manually register a known device by IP (e.g. one on a segment the scanner cannot reach)."""
    try:
        ip = str(ipaddress.ip_address(body.current_ip.strip()))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, tr("عنوان IP غير صالح", "Invalid IP address")) from exc
    if body.device_type not in DEVICE_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, tr("نوع جهاز غير معروف", "Unknown device type"))
    if db.scalar(select(Asset).where(Asset.current_ip == ip)):
        raise HTTPException(status.HTTP_409_CONFLICT, tr("يوجد جهاز بهذا العنوان بالفعل", "A device with this address already exists"))
    mac = (body.mac or "").upper().replace("-", ":").strip() or None
    now = utcnow()
    asset = Asset(current_ip=ip, display_name=(body.display_name or "").strip() or None, mac=mac,
                  hostname=(body.hostname or "").strip() or None, device_type=body.device_type,
                  device_type_confidence=1.0 if body.device_type != "unknown" else 0.0,
                  criticality=body.criticality, notes=body.notes, status="unknown",
                  discovery_methods=["manual"], first_seen=now, last_seen=now)
    db.add(asset)
    db.flush()
    db.add(Event(kind="asset_new", asset_id=asset.id, created_at=now,
                 message_ar=(f"Manually added device: {asset.display_name or ip}" if get_lang()=="en" else f"جهاز مُضاف يدوياً: {asset.display_name or ip}"), details={"source": "manual"}))
    audit(db, request, "asset.create", auth=auth, target_type="asset", target_id=asset.id,
          details={"ip": ip, "device_type": body.device_type, "source": "manual"})
    db.commit()
    out = AssetOut.model_validate(asset)
    out.open_service_count = 0
    return out


@router.post("/assets/{asset_id}/rescan", response_model=JobOut, status_code=201)
def rescan_asset(
    asset_id: int, body: RescanIn, request: Request,
    auth: AuthContext = Depends(require("scan:run")), db: Session = Depends(get_db),
) -> JobOut:
    """Scan just this device, inside the approved scope that covers its current address."""
    from rasednet.api.scans import _job_out, _launch_scan

    asset = db.get(Asset, asset_id)
    if asset is None:
        raise not_found("الجهاز")
    if not asset.current_ip:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("لا يوجد عنوان معروف لهذا الجهاز", "This device has no known address"))
    scope = find_scope_for_ip(db, request.app.state.settings, asset.current_ip)
    if scope is None:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("عنوان الجهاز خارج النطاقات المعتمدة؛ أضف نطاقاً يغطيه واعتمده أولاً", "The device address is outside the approved scopes; add and approve a scope that covers it first"))
    return _job_out(_launch_scan(db, request, auth, scope.id, body.profile_id, trigger="asset", target_ip=asset.current_ip))


# --- services -----------------------------------------------------------------------------


@router.get("/services", response_model=Page[ServiceOut])
def list_services(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    port: int | None = Query(None, ge=1, le=65535),
    exposure: str | None = Query(None, max_length=32),
    state: str | None = Query("open", pattern="^(open|closed)$"),
    q: str | None = Query(None, max_length=128),
    _: AuthContext = Depends(require("asset:read")), db: Session = Depends(get_db),
) -> Page[ServiceOut]:
    query = select(Service, Asset).join(Asset, Asset.id == Service.asset_id)
    if port is not None:
        query = query.where(Service.port == port)
    if exposure:
        query = query.where(Service.exposure_category == exposure)
    if state:
        query = query.where(Service.state == state)
    if q and q.strip():
        pattern = like_pattern(q.strip())
        query = query.where(
            or_(
                Service.service_name.ilike(pattern, escape="\\"),
                Service.product.ilike(pattern, escape="\\"),
                Service.banner.ilike(pattern, escape="\\"),
                Asset.current_ip.ilike(pattern, escape="\\"),
                Asset.hostname.ilike(pattern, escape="\\"),
            )
        )
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.execute(query.order_by(Service.port, Service.id).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[_service_out(s, a) for s, a in rows], total=total, page=page, page_size=page_size)


# --- alerts & events ----------------------------------------------------------------------


@router.get("/alerts", response_model=Page[AlertOut])
def list_alerts(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status", pattern="^(open|acknowledged|resolved)$"),
    severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
    asset_id: int | None = None,
    _: AuthContext = Depends(require("alert:read")), db: Session = Depends(get_db),
) -> Page[AlertOut]:
    query = select(Alert)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if severity:
        query = query.where(Alert.severity == severity)
    if asset_id is not None:
        query = query.where(Alert.asset_id == asset_id)
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.scalars(query.order_by(Alert.last_seen.desc(), Alert.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[AlertOut.model_validate(a) for a in rows], total=total, page=page, page_size=page_size)


def _transition_alert(db: Session, request: Request, auth: AuthContext, alert_id: int, target: str) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise not_found("التنبيه")
    if alert.status == "resolved":
        raise HTTPException(status.HTTP_409_CONFLICT, tr("التنبيه مغلق بالفعل", "The alert is already resolved"))
    now = utcnow()
    if target == "acknowledged":
        if alert.status == "acknowledged":
            raise HTTPException(status.HTTP_409_CONFLICT, tr("تم الإقرار بالتنبيه مسبقاً", "The alert has already been acknowledged"))
        alert.status = "acknowledged"
        alert.acknowledged_at = now
        alert.acknowledged_by_id = auth.user.id
    else:
        alert.status = "resolved"
        alert.resolved_at = now
    audit(db, request, f"alert.{target}", auth=auth, target_type="alert", target_id=alert.id)
    db.commit()
    return alert


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(alert_id: int, request: Request, auth: AuthContext = Depends(require("alert:manage")), db: Session = Depends(get_db)) -> Alert:
    return _transition_alert(db, request, auth, alert_id, "acknowledged")


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut)
def resolve_alert(alert_id: int, request: Request, auth: AuthContext = Depends(require("alert:manage")), db: Session = Depends(get_db)) -> Alert:
    return _transition_alert(db, request, auth, alert_id, "resolved")


@router.get("/events", response_model=Page[EventOut])
def list_events(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    asset_id: int | None = None, kind: str | None = Query(None, max_length=32),
    _: AuthContext = Depends(require("alert:read")), db: Session = Depends(get_db),
) -> Page[EventOut]:
    query = select(Event)
    if asset_id is not None:
        query = query.where(Event.asset_id == asset_id)
    if kind:
        query = query.where(Event.kind == kind)
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.scalars(query.order_by(Event.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[EventOut.model_validate(e) for e in rows], total=total, page=page, page_size=page_size)


# --- dashboard ----------------------------------------------------------------------------


@router.get("/dashboard/summary")
def dashboard_summary(
    tz_offset: int = Query(0, ge=-14 * 60, le=14 * 60, description="JavaScript Date.getTimezoneOffset() of the viewer"),
    _: AuthContext = Depends(require("dashboard:read")), db: Session = Depends(get_db),
) -> dict[str, object]:
    """Every figure here is computed from persisted records at request time."""
    now = utcnow()
    to_local = timedelta(minutes=-tz_offset)  # getTimezoneOffset() = UTC - local

    def count(stmt) -> int:  # type: ignore[no-untyped-def]
        return int(db.scalar(stmt) or 0)

    asset_count = select(func.count()).select_from(Asset)
    by_status = dict(db.execute(select(Asset.status, func.count()).group_by(Asset.status)).all())
    by_type = dict(db.execute(select(Asset.device_type, func.count()).group_by(Asset.device_type)).all())
    exposure = dict(
        db.execute(select(Service.exposure_category, func.count()).where(Service.state == "open").group_by(Service.exposure_category)).all()
    )
    top_ports = [
        {"port": port, "service": name, "count": int(n)}
        for port, name, n in db.execute(
            select(Service.port, func.min(Service.service_name), func.count())
            .where(Service.state == "open").group_by(Service.port).order_by(func.count().desc(), Service.port).limit(10)
        )
    ]
    alerts_by_severity = dict(
        db.execute(select(Alert.severity, func.count()).where(Alert.status == "open").group_by(Alert.severity)).all()
    )
    since = now - timedelta(days=31)
    first_seen_days: Counter[str] = Counter(
        (ts + to_local).date().isoformat() for ts in db.scalars(select(Asset.first_seen).where(Asset.first_seen >= since))
    )
    history = []
    for offset in range(29, -1, -1):
        day = (now + to_local - timedelta(days=offset)).date().isoformat()
        history.append({"date": day, "new_assets": first_seen_days.get(day, 0)})
    last_job = db.scalar(select(ScanJob).where(ScanJob.finished_at.is_not(None)).order_by(ScanJob.finished_at.desc()).limit(1))
    return {
        "generated_at": now.isoformat(),
        "total_assets": count(asset_count),
        "online": int(by_status.get("online", 0)),
        "offline": int(by_status.get("offline", 0)),
        "new_24h": count(select(func.count()).select_from(Asset).where(Asset.first_seen >= now - timedelta(hours=24))),
        "unknown_type": int(by_type.get("unknown", 0)),
        "mobile": int(by_type.get("mobile", 0)) + int(by_type.get("tablet", 0)),
        "servers": int(by_type.get("server", 0)),
        "open_services": count(select(func.count()).select_from(Service).where(Service.state == "open")),
        "active_alerts": count(select(func.count()).select_from(Alert).where(Alert.status == "open")),
        "running_jobs": count(select(func.count()).select_from(ScanJob).where(ScanJob.status.in_(("queued", "running")))),
        "last_scan": (
            {"id": last_job.id, "status": last_job.status, "finished_at": last_job.finished_at.isoformat()}
            if last_job and last_job.finished_at else None
        ),
        "device_types": {k: int(v) for k, v in by_type.items()},
        "exposure": {k: int(v) for k, v in exposure.items()},
        "top_ports": top_ports,
        "alerts_by_severity": {k: int(v) for k, v in alerts_by_severity.items()},
        "discovery_history": history,
    }


# --- audit --------------------------------------------------------------------------------


@router.get("/audit", response_model=Page[AuditOut])
def list_audit(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    action: str | None = Query(None, max_length=64), actor: str | None = Query(None, max_length=64),
    success: bool | None = None,
    _: AuthContext = Depends(require("audit:read")), db: Session = Depends(get_db),
) -> Page[AuditOut]:
    query = select(AuditLog)
    if action:
        query = query.where(AuditLog.action == action)
    if actor:
        query = query.where(AuditLog.actor_username == actor.lower())
    if success is not None:
        query = query.where(AuditLog.success.is_(success))
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = db.scalars(query.order_by(AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[AuditOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)
