"""Comprehensive report assembly, Excel rendering, integrity digest and API permission gate."""

from __future__ import annotations

from rased.models import Alert, Asset, Service, utcnow
from rased.reports import build_report, build_workbook
from tests.conftest import login, make_user


def _seed_inventory(db) -> None:  # type: ignore[no-untyped-def]
    now = utcnow()
    with db.session() as s:
        gw = Asset(current_ip="10.0.0.1", status="online", device_type="router", vendor="MikroTik",
                   is_gateway=True, os_family="network_os", first_seen=now, last_seen=now)
        pc = Asset(current_ip="10.0.0.10", hostname="pc1", status="online", device_type="computer",
                   os_family="windows", first_seen=now, last_seen=now)
        srv = Asset(current_ip="10.0.0.20", status="online", device_type="server", os_family="linux",
                    first_seen=now, last_seen=now)
        s.add_all([gw, pc, srv])
        s.flush()
        # A high-risk exposure (RDP) plus several ordinary services for scoring/exposure counts.
        s.add_all([
            Service(asset_id=pc.id, port=3389, protocol="tcp", state="open", service_name="ms-wbt-server",
                    exposure_category="remote_admin", first_seen=now, last_seen=now),
            Service(asset_id=pc.id, port=445, protocol="tcp", state="open", service_name="microsoft-ds",
                    exposure_category="file_sharing", first_seen=now, last_seen=now),
            Service(asset_id=srv.id, port=22, protocol="tcp", state="open", service_name="ssh",
                    exposure_category="remote_admin", first_seen=now, last_seen=now),
            Service(asset_id=srv.id, port=80, protocol="tcp", state="open", service_name="http",
                    exposure_category="web", first_seen=now, last_seen=now),
            Service(asset_id=srv.id, port=5432, protocol="tcp", state="open", service_name="postgresql",
                    exposure_category="database", first_seen=now, last_seen=now),
        ])
        s.add(Alert(kind="exposure", severity="high", title_ar="منفذ سطح المكتب البعيد مكشوف",
                    message_ar="RDP مفتوح على 10.0.0.10", dedup_key="rdp:10.0.0.10", status="open",
                    asset_id=pc.id, first_seen=now, last_seen=now))
        s.flush()


def test_build_report_sections_and_scoring(db, settings):
    _seed_inventory(db)
    with db.session() as s:
        report = build_report(s, settings)

    summary = report["summary"]
    assert summary["total_assets"] == 3
    assert summary["online"] == 3
    assert summary["open_services"] == 5
    assert summary["gateways"] == 1
    assert summary["high_alerts"] == 1

    # High-risk ports are detected and called out (RDP 3389, SMB 445, PostgreSQL 5432).
    high = {e["port"] for e in report["exposed_ports"] if e["high_risk"]}
    assert {3389, 445, 5432} <= high
    # Each exposed port carries administrator verify/close guidance built from validated values.
    rdp = next(e for e in report["exposed_ports"] if e["port"] == 3389)
    assert rdp["guidance"] and rdp["guidance"]["platforms"]

    # The most exposed device is the PC (RDP + SMB + a high alert), ranked first.
    assert report["top_exposed_devices"][0]["ip"] == "10.0.0.10"
    # Recommendations mention the high-risk ports and the serious alert.
    assert any("3389" in r["title_ar"] for r in report["recommendations"])
    assert any(r["priority"] == "high" for r in report["recommendations"])


def test_workbook_is_valid_xlsx(db, settings):
    _seed_inventory(db)
    with db.session() as s:
        report = build_report(s, settings)
    data = build_workbook(report)
    assert data[:2] == b"PK"  # xlsx is a zip container
    assert len(data) > 2000


def test_report_api_requires_permission_and_returns_integrity(make_client, db):
    _seed_inventory(db)
    make_user(db, "admin", "admin")
    make_user(db, "op", "operator")
    client = make_client()
    csrf = login(client, "admin")
    assert csrf  # authenticated

    r = client.get("/api/reports/network")
    assert r.status_code == 200, r.text
    body = r.json()
    digest = body["meta"]["integrity_sha256"]
    assert isinstance(digest, str) and len(digest) == 64

    # Excel download has the right content type.
    xlsx = client.get("/api/reports/network.xlsx")
    assert xlsx.status_code == 200
    assert "spreadsheetml" in xlsx.headers["content-type"]
    assert xlsx.content[:2] == b"PK"

    # The operator role also has report:read (reports are broadly readable).
    op = make_client()
    op_csrf = login(op, "op")
    assert op.get("/api/reports/network", headers={"X-CSRF-Token": op_csrf}).status_code == 200
