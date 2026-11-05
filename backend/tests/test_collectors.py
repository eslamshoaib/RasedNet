"""Distributed-collector forward payload + central batch ingest + token-authed API."""

from __future__ import annotations

import sqlalchemy as sa

from rased.collectors import build_forward_payload, ingest_batch
from rased.models import Asset, Service, utcnow
from tests.conftest import login, make_user


def test_build_forward_payload_shape(db):
    now = utcnow()
    with db.session() as s:
        a = Asset(current_ip="10.1.0.5", hostname="node5", os_family="linux", status="online",
                  device_type="server", first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        s.add(Service(asset_id=a.id, port=22, protocol="tcp", state="open", service_name="ssh",
                      first_seen=now, last_seen=now))
        s.flush()
        payload = build_forward_payload(s)
    assert payload["count"] == 1
    h = payload["hosts"][0]
    assert h["ip"] == "10.1.0.5" and h["hostname"] == "node5" and h["os"] == "linux"
    assert h["ports"] == [{"port": 22, "protocol": "tcp"}]


def test_ingest_batch_upserts_with_collector_tag(db):
    payload = {"hosts": [
        {"ip": "10.235.0.223", "hostname": "isolated-phone", "os": "Android", "ports": [{"port": 8008}]},
        {"ip": "10.235.0.50", "mac": "AA:BB:CC:00:00:50", "ports": []},
        {"bogus": True},  # skipped
    ]}
    with db.session() as s:
        stats = ingest_batch(s, payload, source="collector")
        s.commit()
    assert stats["hosts"] == 3 and stats["assets_new"] == 2 and stats["skipped"] == 1
    with db.session() as s:
        a = s.scalar(sa.select(Asset).where(Asset.current_ip == "10.235.0.223"))
        assert a.hostname == "isolated-phone" and "collector" in a.discovery_methods
        assert {x.port for x in a.services} == {8008}


def test_collector_api_requires_token(make_client, db):
    make_user(db, "admin", "admin")
    client = make_client()
    csrf = login(client, "admin")
    # Create a collector token via the agent-token endpoint (same mechanism).
    token = client.post("/api/agents/tokens", json={"label": "فرع-معزول"}, headers={"X-CSRF-Token": csrf}).json()["token"]

    batch = {"hosts": [{"ip": "10.235.0.223", "hostname": "phone"}]}
    assert client.post("/api/collectors/report", json=batch).status_code == 401
    assert client.post("/api/collectors/report", json=batch, headers={"X-Agent-Token": "rsd_bad"}).status_code == 401
    ok = client.post("/api/collectors/report", json=batch, headers={"X-Agent-Token": token})
    assert ok.status_code == 200 and ok.json()["assets_new"] == 1
    with db.session() as s:
        assert s.scalar(sa.select(Asset).where(Asset.current_ip == "10.235.0.223")) is not None
