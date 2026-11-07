"""Operations API: approved-service policy, maintenance windows and alert e-mail notifications."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, require
from rasednet.i18n import get_lang, tr
from rasednet.baseline import evaluate, seed_from_current
from rasednet.models import Alert, MaintenanceWindow, NotificationConfig, ServicePolicyRule, utcnow
from rasednet.notify import get_config, notify_due
from rasednet.remote import encrypt_secret

router = APIRouter(prefix="/api", tags=["operations"])


# --- approved-service policy ------------------------------------------------------------

class PolicyRuleIn(BaseModel):
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    device_type: str | None = Field(default=None, max_length=32)
    note_ar: str = Field(default="", max_length=500)


@router.get("/policy/rules")
def list_rules(_: AuthContext = Depends(require("alert:read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rules = db.scalars(select(ServicePolicyRule).order_by(ServicePolicyRule.port)).all()
    return [{"id": r.id, "port": r.port, "protocol": r.protocol, "device_type": r.device_type, "note_ar": r.note_ar}
            for r in rules]


@router.post("/policy/rules", status_code=201)
def add_rule(body: PolicyRuleIn, request: Request, auth: AuthContext = Depends(require("data:manage")),
             db: Session = Depends(get_db)) -> dict[str, Any]:
    exists = db.scalar(select(ServicePolicyRule).where(
        ServicePolicyRule.port.is_(body.port) if body.port is None else ServicePolicyRule.port == body.port,
        ServicePolicyRule.protocol == body.protocol,
        ServicePolicyRule.device_type.is_(body.device_type) if body.device_type is None else ServicePolicyRule.device_type == body.device_type,
    ))
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("القاعدة موجودة بالفعل", "The rule already exists"))
    rule = ServicePolicyRule(port=body.port, protocol=body.protocol, device_type=body.device_type,
                             note_ar=body.note_ar, created_by_id=auth.user.id, created_at=utcnow())
    db.add(rule)
    db.flush()
    audit(db, request, "policy.rule.add", auth=auth, target_type="policy", target_id=rule.id,
          details={"port": body.port, "protocol": body.protocol, "device_type": body.device_type})
    db.commit()
    return {"id": rule.id}


@router.delete("/policy/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, request: Request, auth: AuthContext = Depends(require("data:manage")),
                db: Session = Depends(get_db)) -> Response:
    rule = db.get(ServicePolicyRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, tr("القاعدة غير موجودة", "The rule was not found"))
    db.delete(rule)
    audit(db, request, "policy.rule.delete", auth=auth, target_type="policy", target_id=rule_id)
    db.commit()
    return Response(status_code=204)


@router.post("/policy/seed")
def seed_policy(request: Request, auth: AuthContext = Depends(require("data:manage")),
                db: Session = Depends(get_db)) -> dict[str, int]:
    stats = seed_from_current(db, auth.user.id)
    audit(db, request, "policy.seed", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/policy/evaluate")
def evaluate_policy(request: Request, auth: AuthContext = Depends(require("data:manage")),
                    db: Session = Depends(get_db)) -> dict[str, int]:
    stats = evaluate(db)
    audit(db, request, "policy.evaluate", auth=auth, details=stats)
    db.commit()
    return stats


@router.get("/policy/findings")
def policy_findings(_: AuthContext = Depends(require("alert:read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(Alert).where(Alert.kind.in_(("unauthorized_service", "rogue_gateway")),
                            Alert.status.in_(("open", "acknowledged"))).order_by(Alert.severity.desc(), Alert.id.desc())
    ).all()
    return [{"id": a.id, "kind": a.kind, "severity": a.severity, "title_ar": a.title_ar,
             "message_ar": a.message_ar, "asset_id": a.asset_id, "details": a.details} for a in rows]


# --- maintenance windows ----------------------------------------------------------------

class WindowIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    starts_at: datetime
    ends_at: datetime
    cidr: str | None = Field(default=None, max_length=64)
    note_ar: str = Field(default="", max_length=500)


@router.get("/maintenance/windows")
def list_windows(_: AuthContext = Depends(require("alert:read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    now = utcnow()
    rows = db.scalars(select(MaintenanceWindow).order_by(MaintenanceWindow.starts_at.desc())).all()
    return [{"id": w.id, "name": w.name, "starts_at": w.starts_at.isoformat(), "ends_at": w.ends_at.isoformat(),
             "cidr": w.cidr, "note_ar": w.note_ar, "active": w.starts_at <= now <= w.ends_at} for w in rows]


@router.post("/maintenance/windows", status_code=201)
def add_window(body: WindowIn, request: Request, auth: AuthContext = Depends(require("data:manage")),
               db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.ends_at <= body.starts_at:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, tr("وقت الانتهاء يجب أن يكون بعد البداية", "The end time must be after the start time"))
    w = MaintenanceWindow(name=body.name, starts_at=body.starts_at, ends_at=body.ends_at, cidr=body.cidr,
                          note_ar=body.note_ar, created_by_id=auth.user.id, created_at=utcnow())
    db.add(w)
    db.flush()
    audit(db, request, "maintenance.window.add", auth=auth, target_type="window", target_id=w.id,
          details={"name": w.name, "cidr": w.cidr})
    db.commit()
    return {"id": w.id}


@router.delete("/maintenance/windows/{window_id}", status_code=204)
def delete_window(window_id: int, request: Request, auth: AuthContext = Depends(require("data:manage")),
                  db: Session = Depends(get_db)) -> Response:
    w = db.get(MaintenanceWindow, window_id)
    if w is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, tr("النافذة غير موجودة", "The window was not found"))
    db.delete(w)
    audit(db, request, "maintenance.window.delete", auth=auth, target_type="window", target_id=window_id)
    db.commit()
    return Response(status_code=204)


# --- notification configuration ---------------------------------------------------------

class NotificationIn(BaseModel):
    enabled: bool = False
    smtp_host: str = Field(default="", max_length=253)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    use_tls: bool = True
    from_addr: str = Field(default="", max_length=253)
    to_addrs: list[str] = Field(default_factory=list, max_length=20)
    username: str = Field(default="", max_length=253)
    password: str | None = Field(default=None, max_length=512)  # None = keep existing
    min_severity: Literal["low", "medium", "high", "critical"] = "high"
    escalation_minutes: int = Field(default=60, ge=5, le=1440)


def _config_out(cfg: NotificationConfig) -> dict[str, Any]:
    return {"enabled": cfg.enabled, "smtp_host": cfg.smtp_host, "smtp_port": cfg.smtp_port, "use_tls": cfg.use_tls,
            "from_addr": cfg.from_addr, "to_addrs": cfg.to_addrs, "username": cfg.username,
            "has_password": bool(cfg.secret_encrypted), "min_severity": cfg.min_severity,
            "escalation_minutes": cfg.escalation_minutes}


@router.get("/notifications/config")
def get_notifications(_: AuthContext = Depends(require("data:manage")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return _config_out(get_config(db))


@router.put("/notifications/config")
def set_notifications(body: NotificationIn, request: Request, auth: AuthContext = Depends(require("data:manage")),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    settings = request.app.state.settings
    cfg = get_config(db)
    cfg.enabled = body.enabled
    cfg.smtp_host = body.smtp_host.strip()
    cfg.smtp_port = body.smtp_port
    cfg.use_tls = body.use_tls
    cfg.from_addr = body.from_addr.strip()
    cfg.to_addrs = [a.strip() for a in body.to_addrs if a.strip()]
    cfg.username = body.username.strip()
    if body.password:
        cfg.secret_encrypted = encrypt_secret(settings, body.password)
    cfg.min_severity = body.min_severity
    cfg.escalation_minutes = body.escalation_minutes
    cfg.updated_at = utcnow()
    audit(db, request, "notifications.config", auth=auth, details={"enabled": cfg.enabled, "host": cfg.smtp_host})
    db.commit()
    return _config_out(cfg)


@router.post("/notifications/test")
def test_notification(request: Request, auth: AuthContext = Depends(require("data:manage")),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    from rasednet.notify import _password, _smtp_send

    settings = request.app.state.settings
    cfg = get_config(db)
    if not cfg.smtp_host or not cfg.to_addrs:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, tr("اضبط خادم SMTP وعنوان مستلم أولاً", "Configure the SMTP server and a recipient first"))
    subject, body = (("[RasedNet] Test message", "This is a test message from RasedNet. Email configuration works.") if get_lang()=="en" else ("[راصد] رسالة اختبار", "هذه رسالة اختبار من منصة راصد. إعداد البريد يعمل بنجاح."))
    try:
        _smtp_send(cfg, _password(db, settings, cfg), subject, body)
    except Exception as exc:  # noqa: BLE001 - surface the SMTP error to the operator
        audit(db, request, "notifications.test", auth=auth, success=False, details={"error": str(exc)[:200]})
        db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, (f"Could not send: {exc}" if get_lang()=="en" else f"تعذر الإرسال: {exc}")) from exc
    audit(db, request, "notifications.test", auth=auth, details={"to": cfg.to_addrs})
    db.commit()
    return {"sent": True}


@router.post("/notifications/run")
def run_notifications(request: Request, auth: AuthContext = Depends(require("data:manage")),
                      db: Session = Depends(get_db)) -> dict[str, int]:
    return notify_due(db, request.app.state.settings)
