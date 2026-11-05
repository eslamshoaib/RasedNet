"""Alert e-mail notifications, maintenance-window suppression and escalation.

Notifications go out through the organisation's own SMTP server (configured in the DB). During
an active maintenance window, alerts for the covered subnet are not notified. Critical alerts
left open past the escalation threshold are re-sent once. The SMTP send is injectable so the
logic is unit-tested without a live server; ``build_digest`` is pure.
"""

from __future__ import annotations

import ipaddress
import smtplib
from collections.abc import Callable
from datetime import datetime, timedelta
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.config import Settings
from rased.models import Alert, Asset, MaintenanceWindow, NotificationConfig, utcnow
from rased.remote import decrypt_secret

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_AR = {"critical": "حرِج", "high": "مرتفع", "medium": "متوسط", "low": "منخفض", "info": "معلومة"}

Sender = Callable[[NotificationConfig, str, str, str], None]


def get_config(db: Session) -> NotificationConfig:
    cfg = db.get(NotificationConfig, 1)
    if cfg is None:
        cfg = NotificationConfig(id=1, updated_at=utcnow())
        db.add(cfg)
        db.flush()
    return cfg


def active_windows(db: Session, now: datetime) -> list[MaintenanceWindow]:
    return list(db.scalars(
        select(MaintenanceWindow).where(MaintenanceWindow.starts_at <= now, MaintenanceWindow.ends_at >= now)
    ))


def is_suppressed(windows: list[MaintenanceWindow], ip: str | None) -> bool:
    """True if any active window covers this asset (a window with no CIDR covers everything)."""
    for w in windows:
        if not w.cidr:
            return True
        if ip:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(w.cidr, strict=False):
                    return True
            except ValueError:
                continue
    return False


def build_digest(alerts: list[tuple[Alert, str | None]], *, escalation: bool = False) -> tuple[str, str]:
    """Build (subject, body) for a batch of (alert, asset_ip). Pure."""
    n = len(alerts)
    prefix = "تصعيد: " if escalation else ""
    worst = max((SEVERITY_RANK.get(a.severity, 0) for a, _ in alerts), default=0)
    worst_ar = next((SEVERITY_AR[s] for s, r in SEVERITY_RANK.items() if r == worst), "")
    subject = f"[راصد] {prefix}{n} تنبيه ({worst_ar})"
    lines = [f"رصد راصد {n} تنبيهاً يحتاج انتباهك:", ""]
    for a, ip in alerts:
        where = f" — {ip}" if ip else ""
        lines.append(f"• [{SEVERITY_AR.get(a.severity, a.severity)}] {a.title_ar}{where}")
        lines.append(f"    {a.message_ar}")
    lines += ["", "هذه رسالة آلية من منصة راصد لمراقبة الشبكة."]
    return subject, "\n".join(lines)


def _smtp_send(cfg: NotificationConfig, password: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = cfg.from_addr
    msg["To"] = ", ".join(cfg.to_addrs)
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as server:
        if cfg.use_tls:
            server.starttls()
        if cfg.username:
            server.login(cfg.username, password)
        server.send_message(msg)


def _password(db: Session, settings: Settings, cfg: NotificationConfig) -> str:
    if not cfg.secret_encrypted:
        return ""
    try:
        return decrypt_secret(settings, cfg.secret_encrypted)
    except Exception:  # pragma: no cover - vault misconfig; send may still work without auth
        return ""


def notify_due(db: Session, settings: Settings, *, sender: Sender | None = None,
               now: datetime | None = None) -> dict[str, int]:
    """Send pending notifications and escalations. Returns counts. Commits its own marks."""
    now = now or utcnow()
    cfg = get_config(db)
    stats = {"notified": 0, "escalated": 0, "suppressed": 0, "sent_emails": 0}
    if not cfg.enabled or not cfg.smtp_host or not cfg.to_addrs:
        return stats

    send = sender or _smtp_send
    password = _password(db, settings, cfg)
    threshold = SEVERITY_RANK.get(cfg.min_severity, 3)
    windows = active_windows(db, now)
    ip_of = {a.id: a.current_ip for a in db.scalars(select(Asset))}

    open_alerts = db.scalars(
        select(Alert).where(Alert.status.in_(("open", "acknowledged"))).order_by(Alert.id)
    ).all()

    fresh: list[tuple[Alert, str | None]] = []
    escalate: list[tuple[Alert, str | None]] = []
    for al in open_alerts:
        if SEVERITY_RANK.get(al.severity, 0) < threshold:
            continue
        ip = ip_of.get(al.asset_id) if al.asset_id else None
        if is_suppressed(windows, ip):
            stats["suppressed"] += 1
            continue
        notified_at = (al.details or {}).get("notified_at")
        if not notified_at:
            fresh.append((al, ip))
        elif al.severity == "critical" and not (al.details or {}).get("escalated_at"):
            try:
                when = datetime.fromisoformat(notified_at)
            except ValueError:
                continue
            if now - when >= timedelta(minutes=cfg.escalation_minutes):
                escalate.append((al, ip))

    if fresh:
        subject, body = build_digest(fresh)
        send(cfg, password, subject, body)
        stats["sent_emails"] += 1
        for al, _ in fresh:
            al.details = {**(al.details or {}), "notified_at": now.isoformat()}
            stats["notified"] += 1
    if escalate:
        subject, body = build_digest(escalate, escalation=True)
        send(cfg, password, subject, body)
        stats["sent_emails"] += 1
        for al, _ in escalate:
            al.details = {**(al.details or {}), "escalated_at": now.isoformat()}
            stats["escalated"] += 1

    db.commit()
    return stats
