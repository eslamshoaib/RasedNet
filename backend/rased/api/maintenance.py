"""Data maintenance: delete scan history or wipe the whole inventory and start over.

Configuration (users, scopes, profiles, vault, saved views) and the audit log are never deleted.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, not_found, require
from rased.models import (
    JOB_ACTIVE_STATUSES,
    Alert,
    Asset,
    AssetIdentifier,
    DeviceFingerprint,
    Event,
    IpObservation,
    RemoteExecution,
    ScanJob,
    ScanResult,
    Service,
    ServiceObservation,
)

router = APIRouter(prefix="/api", tags=["maintenance"])

RESET_PHRASE = "حذف كل البيانات"


class ResetIn(BaseModel):
    confirm_text: str


def _no_active_jobs(db: Session) -> None:
    if db.scalar(select(ScanJob.id).where(ScanJob.status.in_(JOB_ACTIVE_STATUSES)).limit(1)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "يوجد فحص قيد التنفيذ؛ أوقفه أولاً")


@router.delete("/scans/{job_id}", status_code=204)
def delete_scan(job_id: int, request: Request, auth: AuthContext = Depends(require("data:manage")),
                db: Session = Depends(get_db)) -> Response:
    """Remove one scan job and its per-scan records. Devices and their current state are kept."""
    job = db.get(ScanJob, job_id)
    if job is None:
        raise not_found("الفحص")
    if job.status in JOB_ACTIVE_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, "لا يمكن حذف فحص قيد التنفيذ")
    # Explicit deletes/updates (do not rely on database-level cascades being enabled).
    db.execute(delete(ScanResult).where(ScanResult.job_id == job_id))
    db.execute(delete(ServiceObservation).where(ServiceObservation.job_id == job_id))
    for model, column in ((Alert, Alert.job_id), (Event, Event.job_id), (Asset, Asset.last_scan_job_id),
                          (ScanJob, ScanJob.resumed_from_id), (Service, Service.last_job_id),
                          (IpObservation, IpObservation.first_job_id), (IpObservation, IpObservation.last_job_id),
                          (DeviceFingerprint, DeviceFingerprint.job_id)):
        db.execute(update(model).where(column == job_id).values({column.key: None}))
    db.delete(job)
    audit(db, request, "scan.delete", auth=auth, target_type="scan_job", target_id=job_id,
          details={"cidr": job.scope_snapshot.get("cidr"), "status": job.status})
    db.commit()
    return Response(status_code=204)


@router.post("/maintenance/reset-inventory")
def reset_inventory(body: ResetIn, request: Request, auth: AuthContext = Depends(require("data:manage")),
                    db: Session = Depends(get_db)) -> dict[str, int]:
    if body.confirm_text.strip() != RESET_PHRASE:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"للتأكيد اكتب العبارة: {RESET_PHRASE}")
    _no_active_jobs(db)
    counts = {
        "assets": int(db.scalar(select(func.count()).select_from(Asset)) or 0),
        "scans": int(db.scalar(select(func.count()).select_from(ScanJob)) or 0),
        "alerts": int(db.scalar(select(func.count()).select_from(Alert)) or 0),
    }
    # Children first, so the order is valid with or without ON DELETE CASCADE.
    for model in (RemoteExecution, ServiceObservation, ScanResult, Service, DeviceFingerprint, IpObservation,
                  AssetIdentifier, Alert, Event):
        db.execute(delete(model))
    db.execute(update(ScanJob).values(resumed_from_id=None))
    db.execute(delete(Asset))
    db.execute(delete(ScanJob))
    audit(db, request, "maintenance.reset_inventory", auth=auth, details=counts)
    db.commit()
    return counts
