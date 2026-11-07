"""Background execution of scan jobs with safe cancellation and crash recovery."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from itertools import islice

from sqlalchemy import select, update

from rasednet.config import Settings
from rasednet.db import Database
from rasednet.discovery.engine import EngineConfig, ScanEngine
from rasednet.inventory import InventoryRecorder
from rasednet.models import JOB_ACTIVE_STATUSES, ScanJob, utcnow
from rasednet.scope import ScopeError, validate_scope

log = logging.getLogger(__name__)

EngineFactory = Callable[[EngineConfig, threading.Event], ScanEngine]

INTERRUPTED_AR = "توقف الخادم أثناء تنفيذ الفحص؛ البيانات المسجلة قبل التوقف محفوظة ويمكن استكمال الفحص من حيث توقف"


class JobRunner:
    def __init__(self, db: Database, settings: Settings, engine_factory: EngineFactory | None = None) -> None:
        self.db = db
        self.settings = settings
        self._engine_factory: EngineFactory = engine_factory or (lambda cfg, ev: ScanEngine(cfg, ev))
        self._executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_jobs, thread_name_prefix="rasednet-scan")
        self._events: dict[int, threading.Event] = {}
        self._futures: dict[int, Future[None]] = {}
        self._lock = threading.Lock()
        self._closed = False

    # -- lifecycle -------------------------------------------------------------------
    def recover_interrupted(self) -> list[int]:
        """Jobs left queued/running by a previous process can never finish: mark them.

        Returns their ids (oldest first) so the caller can resume them.
        """
        with self.db.session() as session:
            ids = list(session.scalars(
                select(ScanJob.id).where(ScanJob.status.in_(JOB_ACTIVE_STATUSES)).order_by(ScanJob.id)
            ))
            if ids:
                session.execute(
                    update(ScanJob)
                    .where(ScanJob.id.in_(ids))
                    .values(status="interrupted", finished_at=utcnow(), error_message=INTERRUPTED_AR)
                )
        if ids:
            log.warning("marked interrupted scan jobs", extra={"jobs": ids})
        return ids

    def shutdown(self, wait: bool = True) -> None:
        with self._lock:
            self._closed = True
            for event in self._events.values():
                event.set()
        self._executor.shutdown(wait=wait, cancel_futures=True)

    # -- control ---------------------------------------------------------------------
    def submit(self, job_id: int) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("job runner is shut down")
            event = threading.Event()
            self._events[job_id] = event
            self._futures[job_id] = self._executor.submit(self._run, job_id, event)

    def cancel(self, job_id: int) -> None:
        with self._lock:
            event = self._events.get(job_id)
        if event is not None:
            event.set()

    def cancel_all(self) -> None:
        with self._lock:
            for event in self._events.values():
                event.set()

    def wait(self, job_id: int, timeout: float | None = None) -> None:
        with self._lock:
            future = self._futures.get(job_id)
        if future is not None:
            future.result(timeout=timeout)

    def is_tracked(self, job_id: int) -> bool:
        with self._lock:
            return job_id in self._events

    # -- execution -------------------------------------------------------------------
    def _run(self, job_id: int, cancel: threading.Event) -> None:
        status = "failed"
        error: str | None = None
        owns_job = False
        try:
            with self.db.session() as session:
                job = session.get(ScanJob, job_id)
                if job is None:
                    return
                if job.status != "queued":
                    return
                if job.cancel_requested or cancel.is_set():
                    job.status = "cancelled"
                    job.finished_at = utcnow()
                    return
                started_at = utcnow()
                job.status = "running"
                job.started_at = started_at
                if job.coverage_started_at is None:
                    job.coverage_started_at = started_at
                coverage_started_at = job.coverage_started_at
                resume_offset = job.resume_offset or 0
                owns_job = True
                scope_snapshot = dict(job.scope_snapshot)
                profile_snapshot = dict(job.profile_snapshot)

            # Re-validate the snapshot: the safety boundary is checked at execution time too.
            scope = validate_scope(
                scope_snapshot["cidr"],
                scope_snapshot.get("excluded_hosts", []),
                scope_snapshot.get("excluded_ports", []),
                allow_public=self.settings.allow_public_scopes,
                max_hosts=self.settings.max_scope_hosts,
            )
            config = EngineConfig.from_profile(profile_snapshot, scope.excluded_ports)
            recorder = InventoryRecorder(self.db, job_id, scope, coverage_started_at)

            def on_chunk(observations, processed):  # type: ignore[no-untyped-def]
                recorder.record_chunk(observations, processed)
                with self.db.session() as s:
                    requested = s.scalar(select(ScanJob.cancel_requested).where(ScanJob.id == job_id))
                if requested:
                    cancel.set()

            engine = self._engine_factory(config, cancel)
            completed = engine.run(islice(scope.targets(), resume_offset, None), on_chunk)
            recorder.finalize(completed)
            if completed:
                status = "completed"
            elif self._closed:
                # Stopped by a server shutdown, not by a user: resumable on next start.
                status, error = "interrupted", INTERRUPTED_AR
            else:
                status = "cancelled"
        except ScopeError as exc:
            error = f"النطاق لم يعد مسموحاً بفحصه: {exc}"
            log.warning("scan scope rejected at execution", extra={"job_id": job_id})
        except Exception as exc:  # noqa: BLE001 - recorded on the job, never swallowed silently
            error = f"فشل الفحص بسبب خطأ داخلي: {type(exc).__name__}: {str(exc)[:400]}"
            log.exception("scan job failed", extra={"job_id": job_id})
        finally:
            try:
                if owns_job:
                    with self.db.session() as session:
                        job = session.get(ScanJob, job_id)
                        if job is not None and job.status in JOB_ACTIVE_STATUSES:
                            job.status = status
                            job.error_message = error
                            job.finished_at = utcnow()
            except Exception:  # noqa: BLE001 - DB unavailable; recover_interrupted() fixes it on restart
                log.exception("could not record final job status", extra={"job_id": job_id})
            with self._lock:
                self._events.pop(job_id, None)
                self._futures.pop(job_id, None)
