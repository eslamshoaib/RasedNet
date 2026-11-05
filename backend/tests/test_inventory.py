"""Inventory correlation and change detection using synthetic observations (no network I/O)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from rased.alerts import raise_alert
from rased.db import Database
from rased.discovery.engine import HostObservation
from rased.discovery.tcp_probe import TcpProbeResult
from rased.inventory import InventoryRecorder
from rased.models import (
    Alert,
    Asset,
    DeviceFingerprint,
    Event,
    IpObservation,
    ScanJob,
    ScanProfile,
    ScanResult,
    ScanScope,
    Service,
    ServiceObservation,
    utcnow,
)
from rased.scope import validate_scope

SCOPE = validate_scope("192.168.1.0/24", [], [], allow_public=False, max_hosts=65536)


def new_job(db: Database) -> tuple[int, object]:
    with db.session() as s:
        scope = s.scalar(select(ScanScope).where(ScanScope.name == "lan"))
        if scope is None:
            scope = ScanScope(name="lan", cidr="192.168.1.0/24", is_approved=True, excluded_hosts=[], excluded_ports=[],
                              description="", is_sensitive=False, is_active=True)
            s.add(scope)
            s.flush()
        profile = s.scalar(select(ScanProfile).where(ScanProfile.code == "standard_inventory"))
        started = utcnow()
        job = ScanJob(scope_id=scope.id, profile_id=profile.id, status="completed", scope_snapshot={}, profile_snapshot={},
                      started_at=started, created_at=started)
        s.add(job)
        s.flush()
        return job.id, started


def obs(ip, mac=None, hostname=None, open_ports=(), closed_ports=(), banners=None, ttl=None):  # type: ignore[no-untyped-def]
    o = HostObservation(ip=ip, methods=["tcp"], mac=mac, hostname=hostname, ttl=ttl)
    for p in open_ports:
        o.ports[p] = TcpProbeResult(p, "open", banner=(banners or {}).get(p))
    for p in closed_ports:
        o.ports[p] = TcpProbeResult(p, "closed")
    return o


def record(db: Database, *observations: HostObservation, completed: bool = True) -> InventoryRecorder:
    job_id, started = new_job(db)
    rec = InventoryRecorder(db, job_id, SCOPE, started, gateways=set())
    rec.record_chunk(list(observations), len(observations))
    rec.finalize(completed)
    return rec


def assets(db: Database) -> list[Asset]:
    with db.session() as s:
        return list(s.scalars(select(Asset).order_by(Asset.id)))


def alerts(db: Database, kind: str) -> list[Alert]:
    with db.session() as s:
        return list(s.scalars(select(Alert).where(Alert.kind == kind).order_by(Alert.id)))


def test_new_asset_is_persisted_with_provenance(db):
    record(db, obs("192.168.1.10", mac="00:1A:2B:3C:4D:5E", hostname="pc-014", open_ports=[135, 445, 3389], ttl=128))
    (asset,) = assets(db)
    assert (asset.current_ip, asset.mac, asset.hostname, asset.status) == ("192.168.1.10", "00:1A:2B:3C:4D:5E", "pc-014", "online")
    assert asset.os_family == "windows" and asset.device_type == "computer"
    with db.session() as s:
        kinds = {(i.kind, i.value) for i in s.get(Asset, asset.id).identifiers}
        assert kinds == {("ipv4", "192.168.1.10"), ("mac", "00:1A:2B:3C:4D:5E"), ("hostname", "pc-014")}
        assert s.scalar(select(func.count()).select_from(Service).where(Service.asset_id == asset.id)) == 3
        assert s.scalar(select(func.count()).select_from(ServiceObservation)) == 3
        result = s.scalar(select(ScanResult))
        assert result.asset_id == asset.id and result.open_ports == [135, 445, 3389]
        fp = s.scalar(select(DeviceFingerprint))
        assert fp.evidence and all("detail_ar" in e for e in fp.evidence)
        assert s.scalar(select(ScanJob.alive_hosts)) == 1
    (alert,) = alerts(db, "new_asset")
    assert alert.title_ar == "جهاز جديد متصل بالشبكة"
    assert alerts(db, "new_port") == []  # ports of a brand-new device are part of its "new asset" alert


def test_same_mac_new_ip_is_same_asset(db):
    record(db, obs("192.168.1.10", mac="00:1A:2B:3C:4D:5E"))
    record(db, obs("192.168.1.77", mac="00:1A:2B:3C:4D:5E"))
    (asset,) = assets(db)
    assert asset.current_ip == "192.168.1.77"
    (alert,) = alerts(db, "ip_changed")
    assert alert.title_ar == "تغير عنوان IP الخاص بالجهاز"
    with db.session() as s:
        assert {o.ip for o in s.scalars(select(IpObservation))} == {"192.168.1.10", "192.168.1.77"}


def test_dhcp_reassignment_does_not_merge_devices(db):
    record(db, obs("192.168.1.10", mac="00:1A:2B:00:00:01", hostname="pc-a"))
    record(db, obs("192.168.1.10", mac="00:1A:2B:00:00:02", hostname="pc-b"))
    a, b = assets(db)
    assert a.mac == "00:1A:2B:00:00:01" and b.mac == "00:1A:2B:00:00:02"
    assert a.hostname == "pc-a" and b.hostname == "pc-b"
    assert a.status == "offline"  # pc-a did not answer the second complete scan


def test_duplicate_mac_in_one_scan_is_not_used_for_identity(db):
    record(db, obs("192.168.1.20", mac="00:1A:2B:99:99:99"), obs("192.168.1.21", mac="00:1A:2B:99:99:99"))
    found = assets(db)
    assert len(found) == 2 and all(a.mac is None for a in found)
    (alert,) = alerts(db, "duplicate_mac")
    assert alert.details["ips"] == ["192.168.1.20", "192.168.1.21"]


def test_routed_host_matched_by_hostname_across_ip_change(db):
    record(db, obs("192.168.1.30", hostname="srv-files"))
    record(db, obs("192.168.1.31", hostname="srv-files"))
    (asset,) = assets(db)
    assert asset.current_ip == "192.168.1.31"


def test_ip_reused_by_differently_named_host_creates_new_asset(db):
    record(db, obs("192.168.1.40", hostname="laptop-1"))
    record(db, obs("192.168.1.40", hostname="laptop-2"))
    assert [a.hostname for a in assets(db)] == ["laptop-1", "laptop-2"]


def test_rotating_randomized_mac_matched_by_hostname(db):
    record(db, obs("192.168.1.50", mac="DA:A1:19:00:00:01", hostname="iphone-ahmed"))
    record(db, obs("192.168.1.51", mac="DE:AD:19:00:00:02", hostname="iphone-ahmed"))
    (asset,) = assets(db)
    assert asset.mac == "DE:AD:19:00:00:02" and asset.mac_randomized


def test_new_port_alert_and_service_closure(db):
    record(db, obs("192.168.1.60", mac="00:1A:2B:00:00:60", open_ports=[22]))
    record(db, obs("192.168.1.60", mac="00:1A:2B:00:00:60", open_ports=[22, 80]))
    (alert,) = alerts(db, "new_port")
    assert alert.title_ar == "تم اكتشاف منفذ جديد" and alert.details["port"] == 80
    # Port 80 seen again: no duplicate alert.
    record(db, obs("192.168.1.60", mac="00:1A:2B:00:00:60", open_ports=[22, 80]))
    assert len(alerts(db, "new_port")) == 1 and alerts(db, "new_port")[0].occurrences == 1
    # Port 80 explicitly probed and refused: service closed, alert resolved, event logged.
    record(db, obs("192.168.1.60", mac="00:1A:2B:00:00:60", open_ports=[22], closed_ports=[80]))
    with db.session() as s:
        svc = s.scalar(select(Service).where(Service.port == 80))
        assert svc.state == "closed"
        assert s.scalar(select(func.count()).select_from(Event).where(Event.kind == "service_closed")) == 1
    assert alerts(db, "new_port")[0].status == "resolved"


def test_unprobed_port_is_not_closed(db):
    record(db, obs("192.168.1.61", mac="00:1A:2B:00:00:61", open_ports=[22, 443]))
    record(db, obs("192.168.1.61", mac="00:1A:2B:00:00:61", open_ports=[22]))  # 443 not in this observation at all
    with db.session() as s:
        assert s.scalar(select(Service.state).where(Service.port == 443)) == "open"


def test_banner_identity_not_downgraded_by_port_only_scan(db):
    record(db, obs("192.168.1.62", mac="00:1A:2B:00:00:62", open_ports=[22], banners={22: b"SSH-2.0-OpenSSH_9.6\r\n"}))
    record(db, obs("192.168.1.62", mac="00:1A:2B:00:00:62", open_ports=[22]))
    with db.session() as s:
        svc = s.scalar(select(Service))
        assert (svc.product, svc.version, svc.identification_method) == ("OpenSSH", "9.6", "banner")


def test_offline_marking_and_recovery(db):
    record(db, obs("192.168.1.70", mac="00:1A:2B:00:00:70"), obs("192.168.1.71", mac="00:1A:2B:00:00:71"))
    record(db, obs("192.168.1.70", mac="00:1A:2B:00:00:70"))
    a70, a71 = assets(db)
    assert a70.status == "online" and a71.status == "offline"
    (alert,) = alerts(db, "asset_offline")
    assert alert.title_ar == "الجهاز لا يستجيب" and alert.asset_id == a71.id
    record(db, obs("192.168.1.71", mac="00:1A:2B:00:00:71"), obs("192.168.1.70", mac="00:1A:2B:00:00:70"))
    assert {a.status for a in assets(db)} == {"online"}
    assert alerts(db, "asset_offline")[0].status == "resolved"


def test_cancelled_scan_never_marks_assets_offline(db):
    record(db, obs("192.168.1.80", mac="00:1A:2B:00:00:80"))
    record(db, completed=False)
    assert assets(db)[0].status == "online"


def test_offline_marking_respects_scope(db):
    record(db, obs("192.168.1.90", mac="00:1A:2B:00:00:90"))
    job_id, started = new_job(db)
    other_scope = validate_scope("10.0.0.0/24", [], [], allow_public=False, max_hosts=65536)
    rec = InventoryRecorder(db, job_id, other_scope, started + timedelta(seconds=1), gateways=set())
    rec.record_chunk([], 254)
    rec.finalize(True)
    assert assets(db)[0].status == "online"


def test_alert_deduplication(db):
    with db.session() as s:
        for _ in range(3):
            raise_alert(s, kind="x", severity="low", title_ar="t", message_ar="m", dedup_key="k", now=utcnow())
    (alert,) = alerts(db, "x")
    assert alert.occurrences == 3


def test_failed_chunk_rolls_back_atomically(db, monkeypatch):
    job_id, started = new_job(db)
    rec = InventoryRecorder(db, job_id, SCOPE, started, gateways=set())
    rec.record_chunk([obs("192.168.1.100", mac="00:1A:2B:00:01:00")], 1)

    def boom(*a, **k):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulated database failure mid-chunk")

    monkeypatch.setattr(InventoryRecorder, "_record_fingerprint", boom)
    with pytest.raises(RuntimeError):
        rec.record_chunk([obs("192.168.1.101", mac="00:1A:2B:00:01:01")], 1)
    # The first chunk survives intact; nothing from the failed chunk is half-written.
    assert [a.current_ip for a in assets(db)] == ["192.168.1.100"]
    with db.session() as s:
        assert s.scalar(select(ScanJob.processed_hosts).where(ScanJob.id == job_id)) == 1


def test_only_one_active_job_per_scope_enforced_by_database(db):
    job_id, _ = new_job(db)
    with db.session() as s:
        job = s.get(ScanJob, job_id)
        s.add(ScanJob(scope_id=job.scope_id, profile_id=job.profile_id, status="running", scope_snapshot={}, profile_snapshot={}, created_at=utcnow()))
    with pytest.raises(IntegrityError):
        with db.session() as s:
            s.add(ScanJob(scope_id=job.scope_id, profile_id=job.profile_id, status="queued", scope_snapshot={}, profile_snapshot={}, created_at=utcnow()))


def test_naive_datetimes_rejected(db):
    from datetime import datetime

    with pytest.raises(Exception):
        with db.session() as s:
            s.add(Event(kind="x", message_ar="m", details={}, created_at=datetime.now()))
