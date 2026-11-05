"""Alert de-duplication and change-log helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.models import Alert, Event

OPEN_STATUSES = ("open", "acknowledged")


def raise_alert(
    session: Session,
    *,
    kind: str,
    severity: str,
    title_ar: str,
    message_ar: str,
    dedup_key: str,
    now: datetime,
    asset_id: int | None = None,
    job_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> Alert:
    """Create an alert, or bump the occurrence counter of the matching unresolved alert."""
    existing = session.scalar(
        select(Alert)
        .where(Alert.dedup_key == dedup_key, Alert.status.in_(OPEN_STATUSES))
        .order_by(Alert.id.desc())
        .limit(1)
    )
    if existing is not None:
        existing.occurrences += 1
        existing.last_seen = now
        existing.message_ar = message_ar
        if job_id is not None:
            existing.job_id = job_id
        return existing
    alert = Alert(
        kind=kind,
        severity=severity,
        title_ar=title_ar,
        message_ar=message_ar,
        dedup_key=dedup_key,
        status="open",
        occurrences=1,
        asset_id=asset_id,
        job_id=job_id,
        details=details or {},
        first_seen=now,
        last_seen=now,
    )
    session.add(alert)
    return alert


def resolve_alerts(session: Session, dedup_key: str, now: datetime) -> int:
    alerts = session.scalars(
        select(Alert).where(Alert.dedup_key == dedup_key, Alert.status.in_(OPEN_STATUSES))
    ).all()
    for alert in alerts:
        alert.status = "resolved"
        alert.resolved_at = now
    return len(alerts)


def add_event(
    session: Session,
    *,
    kind: str,
    message_ar: str,
    now: datetime,
    asset_id: int | None = None,
    job_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> Event:
    event = Event(
        kind=kind,
        message_ar=message_ar,
        asset_id=asset_id,
        job_id=job_id,
        details=details or {},
        created_at=now,
    )
    session.add(event)
    return event
