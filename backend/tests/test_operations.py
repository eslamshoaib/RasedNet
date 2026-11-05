"""Approved-service baseline, rogue detection, maintenance windows and alert notifications."""

from __future__ import annotations

from datetime import timedelta

import sqlalchemy as sa
from cryptography.fernet import Fernet

from rased.baseline import evaluate, is_authorized, seed_from_current
from rased.models import (
    Alert, Asset, MaintenanceWindow, NotificationConfig, ServicePolicyRule, Service, utcnow,
)
from rased.notify import build_digest, is_suppressed, notify_due
from tests.conftest import login, make_user


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def _seed(db) -> tuple[int, int]:  # type: ignore[no-untyped-def]
    now = utcnow()
    with db.session() as s:
        gw1 = Asset(current_ip="10.0.0.1", status="online", device_type="router", is_gateway=True, first_seen=now, last_seen=now)
        gw2 = Asset(current_ip="10.0.0.2", status="online", device_type="router", is_gateway=True, first_seen=now, last_seen=now)
        pc = Asset(current_ip="10.0.0.10", status="online", device_type="computer", first_seen=now, last_seen=now)
        s.add_all([gw1, gw2, pc])
        s.flush()
        s.add_all([
            Service(asset_id=pc.id, port=80, protocol="tcp", state="open", service_name="http",
                    exposure_category="web", first_seen=now, last_seen=now),
            Service(asset_id=pc.id, port=3389, protocol="tcp", state="open", service_name="rdp",
                    exposure_category="remote_admin", first_seen=now, last_seen=now),
        ])
        s.flush()
        return pc.id, gw1.id


def test_is_authorized_matching():
    rules = [
        ServicePolicyRule(port=80, protocol="tcp", device_type=None),
        ServicePolicyRule(port=None, protocol="tcp", device_type="router"),  # routers may expose anything
    ]
    assert is_authorized(80, "tcp", "computer", rules)
    assert not is_authorized(3389, "tcp", "computer", rules)
    assert is_authorized(22, "tcp", "router", rules)       # wildcard-port rule for routers
    assert not is_authorized(80, "udp", "computer", rules)  # protocol must match


def test_evaluate_flags_unauthorized_and_rogue_then_resolves(db):
    _seed(db)
    with db.session() as s:
        # Allow http everywhere, so only RDP is unauthorised.
        s.add(ServicePolicyRule(port=80, protocol="tcp", device_type=None))
        s.commit()
        stats = evaluate(s)
        s.commit()
    assert stats["unauthorized"] == 1      # RDP only
    assert stats["rogue_gateways"] == 1    # two gateways on 10.0.0.0/24

    with db.session() as s:
        kinds = {a.kind for a in s.scalars(sa.select(Alert).where(Alert.status == "open"))}
        assert {"unauthorized_service", "rogue_gateway"} <= kinds

    # Approve RDP and remove the second gateway → both alerts resolve.
    with db.session() as s:
        s.add(ServicePolicyRule(port=3389, protocol="tcp", device_type=None))
        gw2 = s.scalar(sa.select(Asset).where(Asset.current_ip == "10.0.0.2"))
        gw2.is_gateway = False
        s.commit()
        stats = evaluate(s)
        s.commit()
    assert stats["unauthorized"] == 0 and stats["rogue_gateways"] == 0
    with db.session() as s:
        open_baseline = s.scalars(sa.select(Alert).where(
            Alert.kind.in_(("unauthorized_service", "rogue_gateway")), Alert.status == "open")).all()
        assert open_baseline == []


def test_seed_from_current(db):
    _seed(db)
    with db.session() as s:
        stats = seed_from_current(s)
        s.commit()
    assert stats["added"] == 2  # ports 80 and 3389
    with db.session() as s:
        # After seeding, nothing is unauthorised.
        assert evaluate(s)["unauthorized"] == 0


def test_build_digest_is_arabic_and_counts():
    alerts = [
        (Alert(kind="x", severity="critical", title_ar="خدمة خطيرة", message_ar="تفاصيل", dedup_key="a"), "10.0.0.5"),
        (Alert(kind="y", severity="high", title_ar="تنبيه آخر", message_ar="تفاصيل٢", dedup_key="b"), None),
    ]
    subject, body = build_digest(alerts)
    assert "2 تنبيه" in subject and "حرِج" in subject
    assert "10.0.0.5" in body and "خدمة خطيرة" in body


def test_is_suppressed_by_window():
    now = utcnow()
    glob = MaintenanceWindow(name="g", starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1), cidr=None)
    sub = MaintenanceWindow(name="s", starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1), cidr="10.0.0.0/24")
    assert is_suppressed([glob], "1.2.3.4")              # no-CIDR window covers everything
    assert is_suppressed([sub], "10.0.0.9")              # inside the subnet
    assert not is_suppressed([sub], "192.168.1.1")       # outside the subnet


def test_notify_due_sends_escalates_and_suppresses(db, settings):
    now = utcnow()
    sent: list[tuple[str, str]] = []
    fake = lambda cfg, pwd, subject, body: sent.append((subject, body))  # noqa: E731

    with db.session() as s:
        a = Asset(current_ip="10.0.0.10", status="online", device_type="computer", first_seen=now, last_seen=now)
        supp = Asset(current_ip="10.9.9.9", status="online", device_type="computer", first_seen=now, last_seen=now)
        s.add_all([a, supp])
        s.flush()
        s.add(NotificationConfig(id=1, enabled=True, smtp_host="smtp.local", smtp_port=25, use_tls=False,
                                 from_addr="rased@local", to_addrs=["soc@local"], min_severity="high",
                                 escalation_minutes=60, updated_at=now))
        # A fresh high alert → should notify.
        s.add(Alert(kind="k", severity="high", title_ar="تنبيه مرتفع", message_ar="x", dedup_key="d1",
                    status="open", asset_id=a.id, details={}, first_seen=now, last_seen=now))
        # A low alert → below threshold, ignored.
        s.add(Alert(kind="k", severity="low", title_ar="منخفض", message_ar="x", dedup_key="d2",
                    status="open", asset_id=a.id, details={}, first_seen=now, last_seen=now))
        # A suppressed alert for an asset under a global maintenance window.
        s.add(Alert(kind="k", severity="critical", title_ar="مكتوم", message_ar="x", dedup_key="d3",
                    status="open", asset_id=supp.id, details={}, first_seen=now, last_seen=now))
        s.add(MaintenanceWindow(name="w", starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1),
                                cidr="10.9.9.0/24"))
        # A critical alert notified 2h ago and still open → should escalate.
        s.add(Alert(kind="k", severity="critical", title_ar="قديم حرج", message_ar="x", dedup_key="d4",
                    status="open", asset_id=a.id, details={"notified_at": (now - timedelta(hours=2)).isoformat()},
                    first_seen=now, last_seen=now))
        s.commit()

    with db.session() as s:
        stats = notify_due(s, settings, sender=fake, now=now)
    assert stats["notified"] == 1      # the fresh high alert
    assert stats["escalated"] == 1     # the stale critical alert
    assert stats["suppressed"] == 1    # the maintenance-covered critical alert
    assert len(sent) == 2              # one digest + one escalation e-mail
    assert any("تصعيد" in subj for subj, _ in sent)

    with db.session() as s:
        d1 = s.scalar(sa.select(Alert).where(Alert.dedup_key == "d1"))
        assert d1.details.get("notified_at")  # marked, so a second run won't re-send
        stats2 = notify_due(s, settings, sender=fake, now=now)
    assert stats2["notified"] == 0


def test_operations_api_permissions_and_flow(make_client, db, settings):
    make_user(db, "admin", "admin")
    make_user(db, "auditor", "auditor")
    pc_id, _ = _seed(db)
    client = make_client(settings_override=settings.model_copy(update={"secret_key": Fernet.generate_key().decode()}))
    csrf = login(client, "admin")

    # Seed the baseline from current services, then evaluate → no unauthorised services.
    assert client.post("/api/policy/seed", headers=h(csrf)).json()["added"] == 2
    ev = client.post("/api/policy/evaluate", headers=h(csrf)).json()
    assert ev["unauthorized"] == 0
    assert client.get("/api/policy/rules").json()  # listable

    # Add a maintenance window.
    now = utcnow()
    w = client.post("/api/maintenance/windows", headers=h(csrf), json={
        "name": "ليلة الصيانة", "starts_at": now.isoformat(), "ends_at": (now + timedelta(hours=2)).isoformat(),
        "cidr": "10.0.0.0/24"})
    assert w.status_code == 201
    assert any(x["active"] for x in client.get("/api/maintenance/windows").json())

    # Notification config round-trips without leaking the password.
    client.put("/api/notifications/config", headers=h(csrf), json={
        "enabled": True, "smtp_host": "smtp.local", "to_addrs": ["soc@local"], "password": "secret123",
        "min_severity": "high"})
    cfg = client.get("/api/notifications/config").json()
    assert cfg["enabled"] and cfg["has_password"] is True
    assert "password" not in cfg and "secret_encrypted" not in cfg

    # Auditor may read findings but not manage policy.
    aud = make_client()
    ac = login(aud, "auditor")
    assert aud.get("/api/policy/findings").status_code == 200
    assert aud.post("/api/policy/evaluate", headers=h(ac)).status_code == 403
    assert aud.get("/api/notifications/config").status_code == 403  # config needs data:manage
