"""API, security-control and job-lifecycle tests (FastAPI TestClient against a real database)."""

from __future__ import annotations

import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from rased.app import SchemaNotReadyError, create_app
from rased.config import Settings
from rased.db import Database
from rased.discovery.arp import Neighbor
from rased.inventory import InventoryRecorder
from rased.models import Alert, Asset, AuditLog, ScanJob, ScanProfile, Service, utcnow
from tests.conftest import STRONG_PASSWORD, fake_ping_dead, login, make_engine_factory, make_user


@pytest.fixture
def admin(db: Database) -> int:
    return make_user(db, "admin", "admin")


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def wait_job(client: TestClient, job_id: int, timeout: float = 60) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/scans/{job_id}").json()
        if job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.1)
    raise AssertionError(f"job {job_id} did not finish: {job}")


def profile_id(db: Database, code: str) -> int:
    with db.session() as s:
        return s.scalar(select(ScanProfile.id).where(ScanProfile.code == code))


def approved_scope(client: TestClient, csrf: str, cidr: str = "127.0.0.1/32", name: str = "loopback", **extra) -> int:
    r = client.post("/api/scopes", json={"name": name, "cidr": cidr, **extra}, headers=h(csrf))
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    r = client.post(f"/api/scopes/{sid}/approve", json={"confirm": True}, headers=h(csrf))
    assert r.status_code == 200 and r.json()["is_approved"]
    return sid


class Listener:
    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self._stop = False
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
                conn.close()
            except OSError:
                continue

    def close(self) -> None:
        self._stop = True
        self.t.join(2)
        self.sock.close()


# --- authentication -------------------------------------------------------------------------


def test_health_and_unauthenticated_access(make_client):
    client = make_client()
    assert client.get("/api/health").json()["database"] == "ok"
    r = client.get("/api/assets")
    assert r.status_code == 401 and r.json()["detail"] == "يجب تسجيل الدخول للمتابعة"


def test_login_session_csrf_logout(make_client, admin):
    client = make_client()
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"}).status_code == 401
    csrf = login(client, "ADMIN")  # usernames are case-insensitive
    me = client.get("/api/auth/me").json()
    assert me["user"]["username"] == "admin" and "scope:approve" in me["permissions"]
    # Unsafe request without the CSRF header is refused even with a valid session cookie.
    r = client.post("/api/scopes", json={"name": "x", "cidr": "10.0.0.0/24"})
    assert r.status_code == 403
    assert client.post("/api/scopes", json={"name": "x", "cidr": "10.0.0.0/24"}, headers=h("forged")).status_code == 403
    assert client.post("/api/scopes", json={"name": "x", "cidr": "10.0.0.0/24"}, headers=h(csrf)).status_code == 201
    assert client.post("/api/auth/logout", headers=h(csrf)).status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_session_cookie_flags(make_client, settings, admin):
    secure = settings.model_copy(update={"cookie_secure": True})
    client = make_client(settings_override=secure)
    r = client.post("/api/auth/login", json={"username": "admin", "password": STRONG_PASSWORD})
    cookies = r.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith("rased_session="))
    assert "HttpOnly" in session_cookie and "Secure" in session_cookie and "SameSite=strict" in session_cookie
    csrf_cookie = next(c for c in cookies if c.startswith("rased_csrf="))
    assert "HttpOnly" not in csrf_cookie
    assert r.headers["strict-transport-security"].startswith("max-age=")


def test_account_lockout_and_admin_unlock(make_client, db, admin):
    make_user(db, "operator1", "operator")
    client = make_client()
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "operator1", "password": "bad"}).status_code == 401
    # Locked: even the right password is refused for now.
    assert client.post("/api/auth/login", json={"username": "operator1", "password": STRONG_PASSWORD}).status_code == 401
    admin_client = make_client()
    csrf = login(admin_client, "admin")
    users = admin_client.get("/api/users").json()
    op = next(u for u in users if u["username"] == "operator1")
    assert op["locked_until"] is not None
    assert admin_client.patch(f"/api/users/{op['id']}", json={"unlock": True}, headers=h(csrf)).status_code == 200
    login(client, "operator1")
    with db.session() as s:
        reasons = [a.details.get("reason") for a in s.scalars(select(AuditLog).where(AuditLog.action == "auth.login", AuditLog.success.is_(False)))]
    assert reasons.count("bad_password") == 5 and "locked" in reasons


def test_login_rate_limit(make_client, settings, admin):
    client = make_client(settings_override=settings.model_copy(update={"login_rate_per_minute": 3}))
    codes = [client.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code for _ in range(4)]
    assert codes == [401, 401, 401, 429]


def test_unknown_user_and_inactive_user_rejected_identically(make_client, db, admin):
    uid = make_user(db, "gone", "operator")
    with db.session() as s:
        from rased.models import User

        s.get(User, uid).is_active = False
    client = make_client()
    a = client.post("/api/auth/login", json={"username": "gone", "password": STRONG_PASSWORD})
    b = client.post("/api/auth/login", json={"username": "nobody", "password": STRONG_PASSWORD})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_password_change_revokes_other_sessions(make_client, admin):
    c1, c2 = make_client(), make_client()
    csrf1 = login(c1, "admin")
    login(c2, "admin")
    r = c1.post("/api/auth/change-password", json={"current_password": STRONG_PASSWORD, "new_password": "short"}, headers=h(csrf1))
    assert r.status_code == 422 and "حرفاً" in r.json()["detail"]
    r = c1.post("/api/auth/change-password", json={"current_password": STRONG_PASSWORD, "new_password": "N3w!Password-2026"}, headers=h(csrf1))
    assert r.status_code == 204
    assert c1.get("/api/auth/me").status_code == 200
    assert c2.get("/api/auth/me").status_code == 401


# --- authorisation --------------------------------------------------------------------------


def test_rbac_matrix(make_client, db, admin):
    make_user(db, "auditor1", "auditor")
    make_user(db, "operator1", "operator")
    admin_c = make_client()
    a_csrf = login(admin_c, "admin")
    sid = admin_c.post("/api/scopes", json={"name": "lan", "cidr": "192.168.50.0/24"}, headers=h(a_csrf)).json()["id"]

    auditor = make_client()
    au_csrf = login(auditor, "auditor1")
    assert auditor.get("/api/scopes").status_code == 200
    assert auditor.get("/api/audit").status_code == 200
    r = auditor.post("/api/scopes", json={"name": "y", "cidr": "10.1.0.0/24"}, headers=h(au_csrf))
    assert r.status_code == 403 and r.json()["detail"] == "ليست لديك صلاحية لتنفيذ هذا الإجراء"
    assert auditor.post("/api/scans", json={"scope_id": sid, "profile_id": 1}, headers=h(au_csrf)).status_code == 403

    operator = make_client()
    op_csrf = login(operator, "operator1")
    assert operator.post(f"/api/scopes/{sid}/approve", json={"confirm": True}, headers=h(op_csrf)).status_code == 403
    assert operator.get("/api/audit").status_code == 403
    assert operator.get("/api/users").status_code == 403
    with db.session() as s:
        denied = s.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "authorization.denied"))
    assert denied == 5


def test_last_admin_cannot_be_removed(make_client, db, admin):
    client = make_client()
    csrf = login(client, "admin")
    r = client.patch(f"/api/users/{admin}", json={"is_active": False}, headers=h(csrf))
    assert r.status_code == 409
    r = client.post("/api/users", json={"username": "weak", "display_name": "W", "password": "password", "role": "operator"}, headers=h(csrf))
    assert r.status_code == 422
    r = client.post("/api/users", json={"username": "ops.user", "display_name": "مشغل", "password": STRONG_PASSWORD, "role": "operator"}, headers=h(csrf))
    assert r.status_code == 201 and r.json()["role"]["name"] == "operator"
    assert client.post("/api/users", json={"username": "ops.user", "display_name": "x", "password": STRONG_PASSWORD, "role": "operator"}, headers=h(csrf)).status_code == 409


# --- scopes ---------------------------------------------------------------------------------


def test_scope_validation_messages_are_arabic(make_client, admin):
    client = make_client()
    csrf = login(client, "admin")
    r = client.post("/api/scopes", json={"name": "pub", "cidr": "8.8.8.0/24"}, headers=h(csrf))
    assert r.status_code == 422 and "العناوين العامة" in r.json()["detail"]
    r = client.post("/api/scopes", json={"name": "bits", "cidr": "192.168.1.7/24"}, headers=h(csrf))
    assert r.status_code == 422 and "192.168.1.0/24" in r.json()["detail"]
    r = client.post("/api/scopes", json={"name": 5}, headers=h(csrf))
    assert r.status_code == 422 and r.json()["detail"].startswith("بيانات الطلب غير صالحة")


def test_boundary_change_revokes_approval(make_client, admin):
    client = make_client()
    csrf = login(client, "admin")
    sid = approved_scope(client, csrf, "192.168.60.0/24", "office")
    r = client.patch(f"/api/scopes/{sid}", json={"description": "مكتب"}, headers=h(csrf))
    assert r.json()["is_approved"] is True
    r = client.patch(f"/api/scopes/{sid}", json={"excluded_hosts": ["192.168.60.1"]}, headers=h(csrf))
    assert r.json()["is_approved"] is False and r.json()["target_count"] == 253
    assert client.post(f"/api/scopes/{sid}/approve", json={"confirm": False}, headers=h(csrf)).status_code == 422


# --- scans ----------------------------------------------------------------------------------


def test_scan_requires_approved_scope(make_client, db, admin):
    client = make_client()
    csrf = login(client, "admin")
    sid = client.post("/api/scopes", json={"name": "lab", "cidr": "127.0.0.1/32"}, headers=h(csrf)).json()["id"]
    r = client.post("/api/scans", json={"scope_id": sid, "profile_id": profile_id(db, "safe_discovery")}, headers=h(csrf))
    assert r.status_code == 409 and "غير معتمد" in r.json()["detail"]


def test_full_scan_flow_on_loopback(make_client, db, admin):
    listener = Listener()
    try:
        # Start the app first: start-up re-seeds built-in profiles to their canonical definitions.
        client = make_client(make_engine_factory(neighbors={"127.0.0.1": Neighbor("00:1A:2B:3C:4D:5E", True)}))
        with db.session() as s:
            p = s.scalar(select(ScanProfile).where(ScanProfile.code == "standard_inventory"))
            p.tcp_ports = [listener.port, 1]
            p.discovery_ports = [listener.port]
            p.grab_banners = False
        csrf = login(client, "admin")
        sid = approved_scope(client, csrf)
        r = client.post("/api/scans", json={"scope_id": sid, "profile_id": profile_id(db, "standard_inventory")}, headers=h(csrf))
        assert r.status_code == 201, r.text
        job = wait_job(client, r.json()["id"])
        assert job["status"] == "completed", job
        assert (job["total_hosts"], job["processed_hosts"], job["alive_hosts"], job["open_services"]) == (1, 1, 1, 1)

        assets = client.get("/api/assets").json()
        assert assets["total"] == 1
        asset = assets["items"][0]
        assert asset["current_ip"] == "127.0.0.1" and asset["mac"] == "00:1A:2B:3C:4D:5E" and asset["open_service_count"] == 1
        detail = client.get(f"/api/assets/{asset['id']}").json()
        assert [s["port"] for s in detail["services"]] == [listener.port]
        assert detail["fingerprint"] is not None and detail["events"][0]["kind"] == "asset_new"

        assert client.get("/api/assets", params={"q": "127.0"}).json()["total"] == 1
        assert client.get("/api/assets", params={"q": "%"}).json()["total"] == 0  # LIKE wildcards escaped
        assert client.get("/api/assets", params={"sort": "password_hash"}).status_code == 422
        assert client.get("/api/services", params={"port": listener.port}).json()["total"] == 1

        summary = client.get("/api/dashboard/summary", params={"tz_offset": -120}).json()
        with db.session() as s:
            assert summary["total_assets"] == s.scalar(select(func.count()).select_from(Asset)) == 1
            assert summary["open_services"] == s.scalar(select(func.count()).select_from(Service).where(Service.state == "open"))
            assert summary["active_alerts"] == s.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open"))
        assert summary["online"] == 1 and summary["new_24h"] == 1 and summary["last_scan"]["status"] == "completed"
        assert sum(d["new_assets"] for d in summary["discovery_history"]) == 1

        results = client.get(f"/api/scans/{job['id']}/results").json()
        assert results["items"][0]["open_ports"] == [listener.port]

        # Second scan: a new service starts listening → change alert, and the diff shows it.
        listener2 = Listener()
        with db.session() as s:
            s.scalar(select(ScanProfile).where(ScanProfile.code == "standard_inventory")).tcp_ports = [listener.port, listener2.port, 1]
        alerts = client.get("/api/alerts", params={"status": "open"}).json()
        new_asset_alert = next(a for a in alerts["items"] if a["kind"] == "new_asset")
        assert client.post(f"/api/alerts/{new_asset_alert['id']}/acknowledge", headers=h(csrf)).json()["status"] == "acknowledged"
        assert client.post(f"/api/alerts/{new_asset_alert['id']}/acknowledge", headers=h(csrf)).status_code == 409

        r2 = client.post("/api/scans", json={"scope_id": sid, "profile_id": profile_id(db, "standard_inventory")}, headers=h(csrf))
        job2 = wait_job(client, r2.json()["id"])
        listener2.close()
        assert job2["status"] == "completed"
        diff = client.get(f"/api/scans/{job2['id']}/diff").json()
        assert diff["previous_job_id"] == job["id"] and diff["new_hosts"] == [] and diff["missing_hosts"] == []
        assert diff["new_services"] == [f"127.0.0.1:{listener2.port}/tcp"] and diff["closed_services"] == []
        port_alerts = client.get("/api/alerts", params={"status": "open"}).json()["items"]
        (port_alert,) = [a for a in port_alerts if a["kind"] == "new_port"]
        assert port_alert["title_ar"] == "تم اكتشاف منفذ جديد" and port_alert["details"]["port"] == listener2.port
        history = client.get("/api/scans").json()
        assert history["total"] == 2 and history["items"][0]["id"] == job2["id"]
        with db.session() as s:
            actions = [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]
        assert actions.count("scan.start") == 2 and "scope.approve" in actions and "alert.acknowledged" in actions
    finally:
        listener.close()


def test_concurrent_scan_on_same_scope_rejected_and_cancel(make_client, db, admin):
    gate = threading.Event()
    client = make_client(make_engine_factory(pinger=fake_ping_dead, gate=gate))
    csrf = login(client, "admin")
    sid = approved_scope(client, csrf)
    pid = profile_id(db, "safe_discovery")
    first = client.post("/api/scans", json={"scope_id": sid, "profile_id": pid}, headers=h(csrf))
    assert first.status_code == 201
    second = client.post("/api/scans", json={"scope_id": sid, "profile_id": pid}, headers=h(csrf))
    assert second.status_code == 409
    assert client.get("/api/scopes").json()[0]["has_active_job"] is True
    assert client.patch(f"/api/scopes/{sid}", json={"cidr": "127.0.0.2/32"}, headers=h(csrf)).status_code == 409
    r = client.post(f"/api/scans/{first.json()['id']}/cancel", headers=h(csrf))
    assert r.status_code == 200 and r.json()["cancel_requested"]
    gate.set()
    job = wait_job(client, first.json()["id"])
    assert job["status"] == "cancelled"
    assert client.post(f"/api/scans/{job['id']}/cancel", headers=h(csrf)).status_code == 409


def test_emergency_stop(make_client, db, admin):
    gate = threading.Event()
    client = make_client(make_engine_factory(pinger=fake_ping_dead, gate=gate))
    csrf = login(client, "admin")
    ids = []
    for i in range(2):
        sid = approved_scope(client, csrf, f"127.0.0.{i + 1}/32", f"s{i}")
        ids.append(client.post("/api/scans", json={"scope_id": sid, "profile_id": profile_id(db, "safe_discovery")}, headers=h(csrf)).json()["id"])
    stopped = client.post("/api/scans/emergency-stop", headers=h(csrf)).json()
    assert sorted(stopped) == sorted(ids)
    gate.set()
    assert {wait_job(client, j)["status"] for j in ids} == {"cancelled"}


def test_sensitive_scope_allows_only_safe_profile(make_client, db, admin):
    client = make_client(make_engine_factory(pinger=fake_ping_dead))
    csrf = login(client, "admin")
    sid = approved_scope(client, csrf, is_sensitive=True)
    r = client.post("/api/scans", json={"scope_id": sid, "profile_id": profile_id(db, "standard_inventory")}, headers=h(csrf))
    assert r.status_code == 409 and "حساس" in r.json()["detail"]
    r = client.post("/api/scans", json={"scope_id": sid, "profile_id": profile_id(db, "safe_discovery")}, headers=h(csrf))
    assert r.status_code == 201
    assert wait_job(client, r.json()["id"])["status"] == "completed"


def test_worker_failure_is_recorded_not_hidden(make_client, db, admin, monkeypatch):
    from sqlalchemy.exc import OperationalError

    def broken(self, observations, processed):  # type: ignore[no-untyped-def]
        raise OperationalError("INSERT", {}, Exception("connection to server lost"))

    monkeypatch.setattr(InventoryRecorder, "record_chunk", broken)
    client = make_client()
    csrf = login(client, "admin")
    sid = approved_scope(client, csrf)
    r = client.post("/api/scans", json={"scope_id": sid, "profile_id": profile_id(db, "safe_discovery")}, headers=h(csrf))
    job = wait_job(client, r.json()["id"])
    assert job["status"] == "failed" and "OperationalError" in job["error_message"]
    # The scope is usable again afterwards.
    monkeypatch.undo()
    r = client.post("/api/scans", json={"scope_id": sid, "profile_id": profile_id(db, "safe_discovery")}, headers=h(csrf))
    assert r.status_code == 201


def test_interrupted_jobs_recovered_on_startup(settings, db, admin):
    with db.session() as s:
        from rased.models import ScanScope

        scope = ScanScope(name="x", cidr="127.0.0.1/32", is_approved=True, excluded_hosts=[], excluded_ports=[], description="", is_sensitive=False, is_active=True)
        s.add(scope)
        s.flush()
        s.add(ScanJob(scope_id=scope.id, profile_id=1, status="running", scope_snapshot={}, profile_snapshot={}, created_at=utcnow(), started_at=utcnow()))
    with TestClient(create_app(settings)):
        pass
    with db.session() as s:
        job = s.scalar(select(ScanJob))
        assert job.status == "interrupted" and job.error_message


def test_startup_refuses_unmigrated_database(tmp_path):
    settings = Settings(_env_file=None, database_url=f"sqlite:///{(tmp_path / 'empty.db').as_posix()}", cookie_secure=False)  # type: ignore[call-arg]
    with pytest.raises(SchemaNotReadyError):
        with TestClient(create_app(settings)):
            pass


# --- request hardening ----------------------------------------------------------------------


def test_request_hardening(make_client, admin):
    client = make_client()
    r = client.post("/api/auth/login", content=b"username=admin&password=x", headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415
    r = client.post("/api/auth/login", json={"username": "admin", "password": STRONG_PASSWORD}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    r = client.get("/api/health")
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert client.get("/api/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 404  # CDN-dependent Swagger UI disabled


def test_spa_fallback_and_api_404(settings, db, tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><html dir='rtl'></html>", encoding="utf-8")
    with TestClient(create_app(settings.model_copy(update={"frontend_dist": dist}))) as client:
        assert "dir='rtl'" in client.get("/assets/42").text
        r = client.get("/api/does-not-exist")
        assert r.status_code == 404 and "rtl" not in r.text
