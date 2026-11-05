"""Scan control (resume / rerun / single-device rescan / schedules / custom profiles),
Fusion Tables, credential vault and command execution."""

from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select

from rased import remote
from rased.app import create_app
from rased.config import Settings
from rased.db import Database
from rased.discovery import engine as engine_mod
from rased.models import Alert, Asset, AuditLog, Credential, ScanJob, ScanProfile, ScanScope, Service, utcnow
from rased.scheduler import Scheduler
from tests.conftest import fake_ping_alive, fake_ping_dead, login, make_engine_factory, make_user


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def wait_job(client: TestClient, job_id: int, timeout: float = 60) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/scans/{job_id}").json()
        if job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.05)
    raise AssertionError(job)


def pid(db: Database, code: str) -> int:
    with db.session() as s:
        return s.scalar(select(ScanProfile.id).where(ScanProfile.code == code))


def approved(client: TestClient, csrf: str, cidr: str, name: str) -> int:
    sid = client.post("/api/scopes", json={"name": name, "cidr": cidr}, headers=h(csrf)).json()["id"]
    assert client.post(f"/api/scopes/{sid}/approve", json={"confirm": True}, headers=h(csrf)).status_code == 200
    return sid


@pytest.fixture
def admin(db: Database) -> int:
    return make_user(db, "admin", "admin")


# --- resume after an interruption ----------------------------------------------------------------


def test_interrupted_scan_resumes_exactly_where_it_stopped(settings, db, admin, monkeypatch):
    monkeypatch.setattr(engine_mod, "CHUNK_SIZE", 4)
    seen: list[str] = []

    async def recording_ping(ip: str, t: int):  # type: ignore[no-untyped-def]
        seen.append(ip)
        return await fake_ping_alive(ip, t)

    # Simulate a crash: 8 of 14 addresses of 127.0.0.0/28 were committed, then the process died.
    with db.session() as s:
        scope = ScanScope(name="lab", cidr="127.0.0.0/28", is_approved=True, excluded_hosts=[], excluded_ports=[],
                          description="", is_sensitive=False, is_active=True)
        s.add(scope)
        s.flush()
        started = utcnow() - timedelta(minutes=5)
        s.add(ScanJob(scope_id=scope.id, profile_id=pid(db, "safe_discovery"), status="running", trigger="manual",
                      scope_snapshot={"cidr": "127.0.0.0/28", "excluded_hosts": [], "excluded_ports": []},
                      profile_snapshot={**{k: v for k, v in s.get(ScanProfile, pid(db, "safe_discovery")).__dict__.items()
                                           if not k.startswith("_")}, "discovery_ports": [], "tcp_ports": []},
                      total_hosts=14, processed_hosts=8, alive_hosts=8, open_services=0, created_at=started,
                      started_at=started, coverage_started_at=started))
    factory = make_engine_factory(pinger=recording_ping)
    with TestClient(create_app(settings, engine_factory=factory)) as client:
        login(client, "admin")
        jobs = client.get("/api/scans").json()["items"]
        resumed = next(j for j in jobs if j["trigger"] == "resume")
        assert resumed["resumed_from_id"] == jobs[-1]["id"] and resumed["resume_offset"] == 8
        done = wait_job(client, resumed["id"])
    assert done["status"] == "completed" and done["processed_hosts"] == 14
    assert sorted(seen, key=lambda ip: int(ip.split(".")[-1])) == [f"127.0.0.{i}" for i in range(9, 15)]
    with db.session() as s:
        assert s.scalar(select(ScanJob.status).where(ScanJob.trigger == "manual")) == "interrupted"
        assert s.scalar(select(AuditLog.id).where(AuditLog.action == "scan.resume", AuditLog.success.is_(True)))


def test_rerun_and_resume_endpoints(make_client, db, admin):
    gate = threading.Event()
    client = make_client(make_engine_factory(pinger=fake_ping_dead, gate=gate))
    csrf = login(client, "admin")
    sid = approved(client, csrf, "127.0.0.1/32", "lo")
    first = client.post("/api/scans", json={"scope_id": sid, "profile_id": pid(db, "safe_discovery")}, headers=h(csrf)).json()
    assert client.post(f"/api/scans/{first['id']}/rerun", json={}, headers=h(csrf)).status_code == 409  # still running
    gate.set()
    wait_job(client, first["id"])
    r = client.post(f"/api/scans/{first['id']}/rerun", json={"mode": "resume"}, headers=h(csrf))
    assert r.status_code == 409  # completed: nothing left to resume
    again = client.post(f"/api/scans/{first['id']}/rerun", json={"mode": "restart"}, headers=h(csrf))
    assert again.status_code == 201 and again.json()["trigger"] == "rerun"
    assert wait_job(client, again.json()["id"])["status"] == "completed"


def test_graceful_shutdown_marks_running_scan_resumable(settings, db, admin):
    gate = threading.Event()
    app = create_app(settings, engine_factory=make_engine_factory(pinger=fake_ping_dead, gate=gate))
    with TestClient(app) as client:
        csrf = login(client, "admin")
        sid = approved(client, csrf, "127.0.0.1/32", "lo")
        job = client.post("/api/scans", json={"scope_id": sid, "profile_id": pid(db, "safe_discovery")}, headers=h(csrf)).json()
        time.sleep(0.3)
        gate.set()  # server stops while the job is in flight
    with db.session() as s:
        status = s.scalar(select(ScanJob.status).where(ScanJob.id == job["id"]))
    assert status in ("interrupted", "completed")  # never mislabelled as user-cancelled


# --- single device, schedules, profiles -------------------------------------------------------------


def test_single_device_rescan(make_client, db, admin):
    client = make_client(make_engine_factory(pinger=fake_ping_alive))
    csrf = login(client, "admin")
    approved(client, csrf, "127.0.0.0/29", "lab")
    with db.session() as s:
        now = utcnow()
        a = Asset(current_ip="127.0.0.3", status="online", first_seen=now, last_seen=now)
        outside = Asset(current_ip="10.99.0.1", status="online", first_seen=now, last_seen=now)
        s.add_all([a, outside])
        s.flush()
        aid, oid = a.id, outside.id
    r = client.post(f"/api/assets/{aid}/rescan", json={"profile_id": pid(db, "safe_discovery")}, headers=h(csrf))
    assert r.status_code == 201, r.text
    job = wait_job(client, r.json()["id"])
    assert (job["total_hosts"], job["target_ip"], job["scope_cidr"]) == (1, "127.0.0.3", "127.0.0.3/32")
    r = client.post(f"/api/assets/{oid}/rescan", json={"profile_id": pid(db, "safe_discovery")}, headers=h(csrf))
    assert r.status_code == 409 and "خارج النطاقات" in r.json()["detail"]


def test_scheduler_starts_due_scans_and_records_failures(settings, db, admin):
    client_app = create_app(settings.model_copy(update={"scheduler_enabled": False}), engine_factory=make_engine_factory(pinger=fake_ping_dead))
    with TestClient(client_app) as client:
        csrf = login(client, "admin")
        sid = approved(client, csrf, "127.0.0.1/32", "lo")
        r = client.put(f"/api/scopes/{sid}/schedule", json={"profile_id": pid(db, "safe_discovery"), "interval_minutes": 60}, headers=h(csrf))
        assert r.status_code == 200 and r.json()["schedule_interval_minutes"] == 60
        assert client.put(f"/api/scopes/{sid}/schedule", json={"profile_id": 1, "interval_minutes": 5}, headers=h(csrf)).status_code == 422
        scheduler: Scheduler = client_app.state.scheduler
        (job_id,) = scheduler.run_due()  # first run is due immediately after enabling
        assert wait_job(client, job_id)["trigger"] == "schedule"
        assert scheduler.run_due() == []  # next run is an hour away
        with db.session() as s:
            assert s.get(ScanScope, sid).schedule_next_run_at > utcnow() + timedelta(minutes=59)
        # Revoked approval: the schedule records why it did not run instead of failing silently.
        client.post(f"/api/scopes/{sid}/revoke", headers=h(csrf))
        with db.session() as s:
            s.get(ScanScope, sid).schedule_next_run_at = utcnow() - timedelta(seconds=1)
        assert scheduler.run_due() == []
        with db.session() as s:
            scope = s.get(ScanScope, sid)
            assert "غير معتمد" in scope.schedule_last_error and scope.schedule_next_run_at > utcnow()
        r = client.put(f"/api/scopes/{sid}/schedule", json={"interval_minutes": None}, headers=h(csrf))
        assert r.json()["schedule_interval_minutes"] is None


def test_custom_profiles(make_client, db, admin):
    make_user(db, "op", "operator")
    client = make_client()
    csrf = login(client, "admin")
    body = {"name_ar": "منافذ الويب", "discovery_ports": [80, 443], "tcp_ports": list(range(8000, 8011)) + [80, 80],
            "grab_banners": True, "rate_per_second": 100, "connect_timeout_ms": 1500}
    r = client.post("/api/profiles", json=body, headers=h(csrf))
    assert r.status_code == 201, r.text
    prof = r.json()
    assert prof["code"].startswith("custom_") and prof["tcp_ports"][0] == 80 and len(prof["tcp_ports"]) == 12
    assert client.post("/api/profiles", json=body, headers=h(csrf)).status_code == 409  # duplicate name
    assert client.post("/api/profiles", json={**body, "name_ar": "x", "tcp_ports": [70000]}, headers=h(csrf)).status_code == 422
    assert client.put(f"/api/profiles/{pid(db, 'safe_discovery')}", json=body, headers=h(csrf)).status_code == 409  # built-in
    r = client.put(f"/api/profiles/{prof['id']}", json={**body, "rate_per_second": 50}, headers=h(csrf))
    assert r.json()["rate_per_second"] == 50 and r.json()["is_intrusive"] is False
    op = make_client()
    op_csrf = login(op, "op")
    assert op.post("/api/profiles", json={**body, "name_ar": "y"}, headers=h(op_csrf)).status_code == 403
    assert client.delete(f"/api/profiles/{prof['id']}", headers=h(csrf)).status_code == 204


# --- Fusion Tables --------------------------------------------------------------------------------


def _fusion_data(db: Database) -> dict[str, int]:
    now = utcnow()
    ids = {}
    with db.session() as s:
        def asset(ip, os_family, device, ports, alert=None):  # type: ignore[no-untyped-def]
            a = Asset(current_ip=ip, hostname=f"h-{ip.split('.')[-1]}", status="online", os_family=os_family,
                      device_type=device, first_seen=now, last_seen=now)
            s.add(a)
            s.flush()
            for p, name, exp in ports:
                s.add(Service(asset_id=a.id, port=p, protocol="tcp", state="open", service_name=name,
                              exposure_category=exp, first_seen=now, last_seen=now))
            if alert:
                s.add(Alert(kind="x", severity=alert, title_ar="t", message_ar="m", dedup_key=f"k{ip}", status="open",
                            asset_id=a.id, first_seen=now, last_seen=now))
            ids[ip] = a.id

        asset("10.0.0.10", "windows", "computer", [(445, "smb", "file_sharing"), (3389, "rdp", "remote_admin")], "high")
        asset("10.0.0.2", "windows", "computer", [(445, "smb", "file_sharing")], "low")
        asset("10.0.1.5", "linux", "server", [(22, "ssh", "remote_admin"), (80, "http", "web")])
        asset("192.168.5.9", "unknown", "printer", [(9100, "jetdirect", "printing")])
    return ids


def test_fusion_query_spec_example_and_grouping(make_client, db, admin):
    ids = _fusion_data(db)
    client = make_client()
    csrf = login(client, "admin")
    assert client.post("/api/fusion/query", json={}).status_code == 403  # POST requires the CSRF token
    q = lambda body: client.post("/api/fusion/query", json=body, headers=h(csrf)).json()  # noqa: E731
    # Spec example (with the data RASED has): Windows + SMB open + an open high-or-worse alert.
    r = q({"filters": {"os_families": ["windows"], "open_ports_all": [445], "min_alert_severity": "high"}})
    assert [row["ip"] for row in r["rows"]] == ["10.0.0.10"]
    # Numeric IP ordering (10.0.0.2 before 10.0.0.10), CIDR filter, column selection.
    r = q({"filters": {"ip_cidr": "10.0.0.0/16"}, "columns": ["ip", "open_ports", "max_alert_severity"]})
    assert [row["ip"] for row in r["rows"]] == ["10.0.0.2", "10.0.0.10", "10.0.1.5"]
    assert set(r["rows"][0]) == {"id", "ip", "open_ports", "max_alert_severity"} and r["rows"][1]["open_ports"] == [445, 3389]
    assert q({"filters": {"open_ports_none": [445], "exposures_any": ["remote_admin"]}})["total"] == 1
    assert q({"filters": {"has_open_alerts": False}})["total"] == 2
    assert q({"filters": {"min_open_services": 2}})["total"] == 2
    assert q({"filters": {"service_contains": "jetdirect"}})["rows"][0]["ip"] == "192.168.5.9"
    groups = {g["key"]: g["count"] for g in q({"group_by": "port"})["groups"]}
    assert groups == {"445": 2, "3389": 1, "22": 1, "80": 1, "9100": 1}
    subnets = {g["key"]: g["count"] for g in q({"group_by": "subnet24"})["groups"]}
    assert subnets == {"10.0.0.0/24": 2, "10.0.1.0/24": 1, "192.168.5.0/24": 1}
    # Validation: no arbitrary values, no SQL.
    assert client.post("/api/fusion/query", json={"filters": {"device_types": ["x; DROP TABLE assets"]}}, headers=h(csrf)).status_code == 422
    assert client.post("/api/fusion/query", json={"sort": "password_hash"}, headers=h(csrf)).status_code == 422
    assert ids


def test_fusion_export_and_saved_views(make_client, db, admin):
    _fusion_data(db)
    with db.session() as s:
        s.scalar(select(Asset).where(Asset.current_ip == "10.0.0.2")).hostname = "=HYPERLINK(\"http://evil\")"
    make_user(db, "aud", "auditor")
    client = make_client()
    csrf = login(client, "admin")
    r = client.post("/api/fusion/export", json={"columns": ["ip", "hostname", "open_ports"]}, headers=h(csrf))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    text = r.content.decode("utf-8")
    assert text.startswith("\ufeffعنوان IP,اسم الجهاز,المنافذ المفتوحة")
    assert "'=HYPERLINK" in text  # formula injection neutralised
    view = {"name": "ويندوز مع SMB", "definition": {"filters": {"os_families": ["windows"], "open_ports_all": [445]}}, "is_shared": True}
    saved = client.post("/api/fusion/views", json=view, headers=h(csrf)).json()
    other = make_client()
    other_csrf = login(other, "aud")
    shared = other.get("/api/fusion/views").json()
    assert shared[0]["name"] == "ويندوز مع SMB" and shared[0]["is_mine"] is False
    assert other.delete(f"/api/fusion/views/{saved['id']}", headers=h(other_csrf)).status_code == 403
    assert client.delete(f"/api/fusion/views/{saved['id']}", headers=h(csrf)).status_code == 204


# --- vault + command execution -----------------------------------------------------------------------


class FakeStreams:
    def __init__(self, errors):  # type: ignore[no-untyped-def]
        self.error = errors


class FakeClient:
    calls: list[tuple[str, str]] = []

    def __init__(self, ip, username, password, **kw):  # type: ignore[no-untyped-def]
        if password != "S3cret!Pass":
            raise RuntimeError("401 Unauthorized: the specified credentials were rejected")
        self.ip = ip

    def execute_ps(self, script):  # type: ignore[no-untyped-def]
        FakeClient.calls.append((self.ip, script))
        return "Name : RpcSs\nStatus : Running", FakeStreams([]), False


@pytest.fixture
def vault_client(make_client, settings, db, admin, monkeypatch):  # type: ignore[no-untyped-def]
    FakeClient.calls = []
    monkeypatch.setattr(remote, "client_factory", FakeClient)
    key = Fernet.generate_key().decode()
    client = make_client(settings_override=settings.model_copy(update={"secret_key": key}))
    csrf = login(client, "admin")
    approved(client, csrf, "10.0.0.0/24", "lan")
    with db.session() as s:
        now = utcnow()
        a = Asset(current_ip="10.0.0.7", status="online", os_family="windows", device_type="computer", first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        svc = Service(asset_id=a.id, port=135, protocol="tcp", state="open", service_name="msrpc", first_seen=now, last_seen=now)
        s.add(svc)
        s.flush()
        ids = (a.id, svc.id)
    return client, csrf, ids


def test_vault_encrypts_and_never_returns_secrets(vault_client, db):
    client, csrf, _ = vault_client
    r = client.post("/api/credentials", json={"name": "مسؤول المجال", "username": "CORP\\rased-svc", "password": "S3cret!Pass"}, headers=h(csrf))
    assert r.status_code == 201 and "password" not in r.json() and r.json()["port"] == 5985
    with db.session() as s:
        stored = s.scalar(select(Credential.secret_encrypted))
    assert "S3cret" not in stored and stored.startswith("gAAAA")  # Fernet token
    assert "S3cret" not in client.get("/api/credentials").text


def test_vault_requires_key(make_client, db, admin):
    client = make_client()
    csrf = login(client, "admin")
    r = client.post("/api/credentials", json={"name": "x", "username": "u", "password": "p"}, headers=h(csrf))
    assert r.status_code == 409 and "RASED_SECRET_KEY" in r.json()["detail"]


def test_remote_verify_and_change_flow(vault_client, db):
    client, csrf, (asset_id, svc_id) = vault_client
    cred = client.post("/api/credentials", json={"name": "c", "username": "admin", "password": "S3cret!Pass"}, headers=h(csrf)).json()
    url = f"/api/assets/{asset_id}/services/{svc_id}/execute"
    r = client.post(url, json={"section": "verify", "index": 0, "credential_id": cred["id"]}, headers=h(csrf))
    assert r.status_code == 200, r.text
    ex = r.json()
    assert ex["status"] == "ok" and ex["target"] == "10.0.0.7" and "RpcSs" in ex["output"]
    assert FakeClient.calls[0][1].startswith("$c = Get-NetTCPConnection -State Listen -LocalPort 135")
    # Changing the device needs explicit confirmation and validated placeholder values.
    r = client.post(url, json={"section": "disable", "index": 0, "credential_id": cred["id"]}, headers=h(csrf))
    assert r.status_code == 422
    r = client.post(url, json={"section": "disable", "index": 0, "credential_id": cred["id"], "confirm": True,
                               "params": {"subnet": "10.9.9.0/24; Remove-Item C:\\"}}, headers=h(csrf))
    assert r.status_code == 422
    r = client.post(url, json={"section": "disable", "index": 0, "credential_id": cred["id"], "confirm": True,
                               "params": {"subnet": "10.9.9.0/24"}}, headers=h(csrf))
    assert r.status_code == 200 and "-RemoteAddress '10.9.9.0/24'" in FakeClient.calls[-1][1]
    history = client.get(f"/api/assets/{asset_id}/executions").json()
    assert len(history) == 2
    with db.session() as s:
        actions = [a.details.get("section") for a in s.scalars(select(AuditLog).where(AuditLog.action == "remote.execute"))]
    assert actions == ["verify", "disable"]


def test_remote_errors_are_explained_and_operators_cannot_change(vault_client, db):
    client, csrf, (asset_id, svc_id) = vault_client
    bad = client.post("/api/credentials", json={"name": "bad", "username": "u", "password": "wrong"}, headers=h(csrf)).json()
    r = client.post(f"/api/assets/{asset_id}/services/{svc_id}/execute",
                    json={"section": "verify", "index": 0, "credential_id": bad["id"]}, headers=h(csrf)).json()
    assert r["status"] == "error" and "فشل تسجيل الدخول" in r["output"]
    make_user(db, "op", "operator")
    from tests.conftest import make_user as _  # noqa: F401
    op = TestClient(client.app)
    op_csrf = login(op, "op")
    r = op.post(f"/api/assets/{asset_id}/services/{svc_id}/execute",
                json={"section": "disable", "index": 0, "credential_id": bad["id"], "confirm": True, "params": {"subnet": "10.0.0.0/8"}},
                headers=h(op_csrf))
    assert r.status_code == 403
    assert op.post("/api/credentials", json={"name": "x", "username": "u", "password": "p"}, headers=h(op_csrf)).status_code == 403


def test_interactive_commands_are_never_executed(vault_client, db):
    client, csrf, (asset_id, _) = vault_client
    with db.session() as s:
        now = utcnow()
        svc = Service(asset_id=asset_id, port=3389, protocol="tcp", state="open", service_name="rdp", first_seen=now, last_seen=now)
        s.add(svc)
        s.flush()
        sid = svc.id
    guidance = client.get(f"/api/assets/{asset_id}").json()["services"]
    rdp = next(s for s in guidance if s["port"] == 3389)["guidance"]
    idx = next(i for i, c in enumerate(rdp["network_checks"]) if c["command"].startswith("mstsc"))
    r = client.post(f"/api/assets/{asset_id}/services/{sid}/execute", json={"section": "network_checks", "index": idx}, headers=h(csrf))
    assert r.status_code == 409
    assert rdp["access"][0]["command"] == "mstsc /v:10.0.0.7"


def test_assets_outside_approved_scopes_are_refused(vault_client, db):
    client, csrf, _ = vault_client
    with db.session() as s:
        now = utcnow()
        a = Asset(current_ip="172.30.0.5", status="online", os_family="windows", first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        svc = Service(asset_id=a.id, port=445, protocol="tcp", state="open", service_name="smb", first_seen=now, last_seen=now)
        s.add(svc)
        s.flush()
        ids = (a.id, svc.id)
    r = client.post(f"/api/assets/{ids[0]}/services/{ids[1]}/execute", json={"section": "verify", "index": 0, "credential_id": 1}, headers=h(csrf))
    assert r.status_code == 409 and "خارج النطاقات" in r.json()["detail"]


@pytest.mark.skipif(not __import__("sys").platform == "win32", reason="local PowerShell")
def test_network_check_runs_locally_on_scanner(vault_client):
    client, csrf, (asset_id, svc_id) = vault_client
    r = client.post(f"/api/assets/{asset_id}/services/{svc_id}/execute", json={"section": "network_checks", "index": 0}, headers=h(csrf))
    assert r.status_code == 200 and r.json()["target"] == "scanner"
    assert "TcpTestSucceeded" in r.json()["output"] or r.json()["status"] == "error"


def test_settings_type(settings: Settings):
    assert settings.resume_interrupted is True
