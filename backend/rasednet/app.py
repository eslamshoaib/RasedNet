"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from rasednet import __version__
from rasednet.i18n import set_lang, tr
from rasednet.api import agents as agents_api
from rasednet.api import auth as auth_api
from rasednet.api import collectors as collectors_api
from rasednet.api import compliance as compliance_api
from rasednet.api import cve as cve_api
from rasednet.api import diagnostics as diagnostics_api
from rasednet.api import domain as domain_api
from rasednet.api import fusion as fusion_api
from rasednet.api import imports as imports_api
from rasednet.api import inventory as inventory_api
from rasednet.api import maintenance as maintenance_api
from rasednet.api import netadmin as netadmin_api
from rasednet.api import operations as operations_api
from rasednet.api import profiles as profiles_api
from rasednet.api import remote as remote_api
from rasednet.api import reports as reports_api
from rasednet.api import scans as scans_api
from rasednet.api import smbshares as smbshares_api
from rasednet.api import snmp as snmp_api
from rasednet.api import topology as topology_api
from rasednet.api import udpscan as udpscan_api
from rasednet.api import webfp as webfp_api
from rasednet.config import Settings, get_settings
from rasednet.db import Database
from rasednet.jobs import EngineFactory, JobRunner
from rasednet.logging_setup import configure_logging
from rasednet.migrations_util import schema_status
from rasednet.scheduler import Scheduler, resume_jobs
from rasednet.security.ratelimit import SlidingWindowLimiter
from rasednet.seed import seed_reference_data

log = logging.getLogger(__name__)

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
    "font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; "
    # frame-src allows embedding a network display's own web page (the «screen preview» for TVs/
    # signage). Framing only — scripts/connections stay locked to 'self'.
    "frame-src 'self' http: https:; "
    "base-uri 'self'; form-action 'self'"
)


class SchemaNotReadyError(RuntimeError):
    pass


class SPAStaticFiles(StaticFiles):
    """Serve the built frontend; unknown non-API paths fall back to index.html (client routing)."""

    async def get_response(self, path: str, scope: Scope):  # type: ignore[override]
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404 and not path.startswith("api"):
                return await super().get_response("index.html", scope)
            raise


def _validation_errors_ar(exc: RequestValidationError) -> list[dict[str, object]]:
    errors = []
    for err in exc.errors():
        loc = [str(p) for p in err.get("loc", ()) if p not in ("body", "query", "path")]
        errors.append({"field": ".".join(loc) or None, "type": err.get("type")})
    return errors


def create_app(
    settings: Settings | None = None,
    *,
    engine_factory: EngineFactory | None = None,
    check_schema: bool = True,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_dir)
    db = Database(settings.database_url, settings.db_pool_size, settings.db_max_overflow)
    runner = JobRunner(db, settings, engine_factory)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if check_schema:
            current, head = schema_status(db.engine, settings.database_url)
            if current != head:
                raise SchemaNotReadyError(
                    f"database schema is at {current!r}, expected {head!r}; run: python -m rasednet init-db"
                )
        with db.session() as session:
            seed_reference_data(session)
        interrupted = runner.recover_interrupted()
        if interrupted and settings.resume_interrupted:
            resume_jobs(db, settings, runner, interrupted)
        scheduler = Scheduler(db, settings, runner, settings.scheduler_tick_seconds)
        app.state.scheduler = scheduler
        if settings.scheduler_enabled:
            scheduler.start()
        log.info("rasednet started", extra={"version": __version__})
        try:
            yield
        finally:
            scheduler.stop()
            runner.shutdown(wait=True)
            db.dispose()

    app = FastAPI(
        title="RasedNet",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,  # Swagger UI loads assets from a CDN; disabled for offline operation.
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.db = db
    app.state.runner = runner
    app.state.login_limiter = SlidingWindowLimiter(settings.login_rate_per_minute, 60)
    app.state.api_limiter = SlidingWindowLimiter(settings.api_rate_per_minute, 60)

    @app.middleware("http")
    async def hardening(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Select the UI language for this request (default Arabic) before anything else,
        # so all user-facing text — including the rejections below — is localized.
        set_lang(request.headers.get("x-lang") or request.headers.get("accept-language"))
        path = request.url.path
        is_api = path.startswith("/api/")
        if is_api:
            ip = request.client.host if request.client else "unknown"
            if not app.state.api_limiter.allow(ip):
                return JSONResponse({"detail": tr("عدد كبير من الطلبات، يرجى الإبطاء", "Too many requests, please slow down")}, status_code=429)
            if request.method in UNSAFE_METHODS:
                origin = request.headers.get("origin")
                if origin and urlsplit(origin).netloc != request.headers.get("host", ""):
                    return JSONResponse({"detail": tr("تم رفض طلب من مصدر خارجي", "Request from an external origin was rejected")}, status_code=403)
                if request.headers.get("sec-fetch-site") == "cross-site":
                    return JSONResponse({"detail": tr("تم رفض طلب من مصدر خارجي", "Request from an external origin was rejected")}, status_code=403)
                has_body = request.headers.get("content-length", "0") not in ("", "0") or "transfer-encoding" in request.headers
                ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
                # File-upload endpoints (e.g. Nmap XML import) accept a raw non-JSON body.
                allowed = {"application/json"}
                if path.startswith("/api/imports/") or path == "/api/cve/epss":
                    allowed |= {"application/xml", "text/xml", "application/octet-stream", "text/plain", "text/csv"}
                if has_body and ctype not in allowed:
                    return JSONResponse({"detail": tr("نوع المحتوى غير مدعوم لهذا الطلب", "Unsupported content type for this request")}, status_code=415)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if is_api:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            {"detail": "بيانات الطلب غير صالحة، يرجى مراجعة الحقول المدخلة", "errors": _validation_errors_ar(exc)},
            status_code=422,
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"path": request.url.path})
        return JSONResponse({"detail": "حدث خطأ داخلي في الخادم. تم تسجيل الخطأ للمراجعة"}, status_code=500)

    @app.get("/api/health", include_in_schema=False)
    def health() -> JSONResponse:
        try:
            with db.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            db_state = "ok"
        except Exception:  # noqa: BLE001
            db_state = "unavailable"
        code = 200 if db_state == "ok" else 503
        return JSONResponse({"status": "ok" if code == 200 else "degraded", "database": db_state, "version": __version__}, status_code=code)

    app.include_router(auth_api.router)
    app.include_router(scans_api.router)
    app.include_router(inventory_api.router)
    app.include_router(profiles_api.router)
    app.include_router(fusion_api.router)
    app.include_router(remote_api.router)
    app.include_router(maintenance_api.router)
    app.include_router(topology_api.router)
    app.include_router(netadmin_api.router)
    app.include_router(reports_api.router)
    app.include_router(domain_api.router)
    app.include_router(snmp_api.router)
    app.include_router(cve_api.router)
    app.include_router(imports_api.router)
    app.include_router(operations_api.router)
    app.include_router(agents_api.router)
    app.include_router(udpscan_api.router)
    app.include_router(diagnostics_api.router)
    app.include_router(smbshares_api.router)
    app.include_router(compliance_api.router)
    app.include_router(webfp_api.router)
    app.include_router(collectors_api.router)

    dist = settings.frontend_dist or (Path(__file__).resolve().parents[2] / "frontend" / "dist")
    if (dist / "index.html").is_file():
        app.mount("/", SPAStaticFiles(directory=dist, html=True), name="frontend")
    else:
        log.warning("frontend build not found; API only", extra={"path": str(dist)})
    return app
