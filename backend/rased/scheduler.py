"""Recurring scans and automatic resumption of interrupted scans.

The scheduler is a single daemon thread in the (single) server process. Every tick it starts
the scans whose ``schedule_next_run_at`` is due, through the same safety checks as manual
scans. A scope that is busy, no longer approved or otherwise invalid records the reason in
``schedule_last_error`` instead of failing silently.
"""

from __future__ import annotations

import logging
import threading
from datetime import timedelta

from sqlalchemy import select

from rased.config import Settings
from rased.db import Database
from rased.jobs import JobRunner
from rased.models import AuditLog, ScanJob, ScanScope, utcnow
from rased.scanning import ScanStartError, create_scan_job

log = logging.getLogger(__name__)

MIN_INTERVAL_MINUTES = 15
MAX_INTERVAL_MINUTES = 30 * 24 * 60


def _system_audit(session, action: str, *, target_id: object, success: bool, details: dict) -> None:  # type: ignore[no-untyped-def]
    session.add(AuditLog(actor_id=None, actor_username="system", action=action, target_type="scan_job" if success else "scope",
                         target_id=str(target_id), success=success, client_ip=None, details=details, created_at=utcnow()))


def resume_jobs(db: Database, settings: Settings, runner: JobRunner, job_ids: list[int]) -> list[int]:
    """Create continuation jobs for interrupted ones; returns the new job ids."""
    started: list[int] = []
    for job_id in job_ids:
        try:
            new_id = _resume_one(db, settings, job_id)
        except Exception:  # noqa: BLE001 - one bad job must never prevent the server from starting
            log.exception("could not resume interrupted scan", extra={"job_id": job_id})
            continue
        if new_id is not None:
            runner.submit(new_id)
            started.append(new_id)
    if started:
        log.info("resumed interrupted scans", extra={"jobs": started})
    return started


def _resume_one(db: Database, settings: Settings, job_id: int) -> int | None:
    """Create the continuation job (committed) or record why it cannot be resumed."""
    with db.session() as session:
        old = session.get(ScanJob, job_id)
        if old is None:
            return None
        scope_id = old.scope_id
        try:
            job = create_scan_job(session, settings, scope_id=old.scope_id, profile_id=old.profile_id,
                                  requested_by_id=old.requested_by_id, trigger="resume", resume_of=old)
        except ScanStartError as exc:
            session.rollback()
            _system_audit(session, "scan.resume", target_id=scope_id, success=False,
                          details={"interrupted_job": job_id, "reason": exc.message_ar})
            return None
        _system_audit(session, "scan.resume", target_id=job.id, success=True,
                      details={"interrupted_job": job_id, "resume_offset": job.resume_offset, "total": job.total_hosts})
        return job.id


class Scheduler:
    def __init__(self, db: Database, settings: Settings, runner: JobRunner, tick_seconds: float = 30.0) -> None:
        self.db = db
        self.settings = settings
        self.runner = runner
        self.tick_seconds = tick_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="rased-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.run_due()
            except Exception:  # noqa: BLE001 - the scheduler must survive a transient DB error
                log.exception("scheduler tick failed")
            try:
                self.notify_due()
            except Exception:  # noqa: BLE001 - notifications must never crash the scheduler
                log.exception("notification tick failed")

    def notify_due(self) -> dict[str, int]:
        """Send pending alert e-mails / escalations (no-op unless notifications are configured)."""
        from rased.notify import notify_due as _notify_due

        with self.db.session() as session:
            return _notify_due(session, self.settings)

    def run_due(self) -> list[int]:
        now = utcnow()
        with self.db.session() as session:
            due = list(session.scalars(
                select(ScanScope.id).where(
                    ScanScope.is_active.is_(True),
                    ScanScope.schedule_interval_minutes.is_not(None),
                    ScanScope.schedule_profile_id.is_not(None),
                    ScanScope.schedule_next_run_at <= now,
                ).order_by(ScanScope.schedule_next_run_at)
            ))
        started: list[int] = []
        for scope_id in due:
            job_id = None
            with self.db.session() as session:
                scope = session.get(ScanScope, scope_id)
                if scope is None or scope.schedule_interval_minutes is None or scope.schedule_profile_id is None:
                    continue
                scope.schedule_last_run_at = now
                scope.schedule_next_run_at = now + timedelta(minutes=scope.schedule_interval_minutes)
                try:
                    job = create_scan_job(session, self.settings, scope_id=scope.id, profile_id=scope.schedule_profile_id,
                                          requested_by_id=None, trigger="schedule")
                    scope.schedule_last_error = None
                    _system_audit(session, "scan.start", target_id=job.id, success=True,
                                  details={"scope_id": scope.id, "trigger": "schedule"})
                    job_id = job.id
                except ScanStartError as exc:
                    # create_scan_job may have rolled back; re-load and record why it did not run.
                    session.rollback()
                    scope = session.get(ScanScope, scope_id)
                    if scope is not None:
                        scope.schedule_last_run_at = now
                        scope.schedule_next_run_at = now + timedelta(minutes=scope.schedule_interval_minutes or MIN_INTERVAL_MINUTES)
                        scope.schedule_last_error = exc.message_ar
                    _system_audit(session, "scan.start", target_id=scope_id, success=False,
                                  details={"trigger": "schedule", "reason": exc.message_ar})
            if job_id is not None:
                self.runner.submit(job_id)
                started.append(job_id)
        return started
