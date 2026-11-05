"""Compliance framework evaluation over inventory data."""

from __future__ import annotations

from rased.compliance import FRAMEWORKS, collect_metrics, evaluate_framework
from rased.models import Asset, Service, utcnow
from tests.conftest import login, make_user


def _seed(db) -> None:  # type: ignore[no-untyped-def]
    now = utcnow()
    with db.session() as s:
        a = Asset(current_ip="10.0.0.10", status="online", device_type="server", first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        s.add_all([
            Service(asset_id=a.id, port=23, protocol="tcp", state="open", service_name="telnet",
                    exposure_category="remote_admin", first_seen=now, last_seen=now),
            Service(asset_id=a.id, port=3389, protocol="tcp", state="open", service_name="ms-wbt-server",
                    exposure_category="remote_admin", first_seen=now, last_seen=now),
        ])
        s.flush()


def test_metrics_detect_cleartext_and_rdp(db):
    _seed(db)
    with db.session() as s:
        m = collect_metrics(s)
    assert m.telnet_exposed == 1 and m.rdp_exposed == 1 and m.total_assets == 1


def test_evaluate_frameworks_score_and_fail_cleartext(db):
    _seed(db)
    for fw in FRAMEWORKS:
        with db.session() as s:
            r = evaluate_framework(s, fw)
        assert r["framework"] == fw and isinstance(r["score"], int)
        assert r["summary"]["total"] == len(r["controls"])
        # The cleartext (Telnet) control must FAIL given an exposed telnet service.
        cleartext = [c for c in r["controls"] if "صريح" in c["detail_ar"] or "مشفّرة" in c["detail_ar"] or "SSH/SFTP" in c["detail_ar"]]
        assert any(c["status"] == "fail" for c in cleartext)


def test_compliance_api(make_client, db):
    _seed(db)
    make_user(db, "admin", "admin")
    client = make_client()
    login(client, "admin")
    fws = client.get("/api/compliance/frameworks").json()
    assert {f["key"] for f in fws} == set(FRAMEWORKS)
    r = client.get("/api/compliance/nca_ecc")
    assert r.status_code == 200 and r.json()["score"] is not None
    assert client.get("/api/compliance/bogus").status_code == 404
    exp = client.get("/api/compliance/nca_ecc/export")
    assert exp.status_code == 200 and "attachment" in exp.headers["content-disposition"]
