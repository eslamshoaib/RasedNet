"""Endpoint-agent token management and token-authenticated report ingest."""

from __future__ import annotations

import sqlalchemy as sa

from rased.agent_ingest import hash_token, ingest_report, new_token, normalize_report
from rased.models import AgentToken, Asset, Service, utcnow
from tests.conftest import login, make_user


def test_new_token_is_hashed():
    plain, digest = new_token()
    assert plain.startswith("rsd_") and digest == hash_token(plain) and len(digest) == 64
    assert plain != digest


def test_normalize_report_validates():
    r = normalize_report({"hostname": "pc1", "os": "Windows 11", "ip": "10.0.0.5",
                          "mac": "aa-bb-cc-dd-ee-ff", "ports": [{"port": 445}, 3389, {"port": 99999}]})
    assert r["hostname"] == "pc1" and r["os_family"] == "windows" and r["ip"] == "10.0.0.5"
    assert r["mac"] == "AA:BB:CC:DD:EE:FF"
    assert {p["port"] for p in r["ports"]} == {445, 3389}  # out-of-range port dropped
    try:
        normalize_report({"ports": []})
        assert False
    except ValueError:
        pass


def test_ingest_report_upserts_asset_and_services(db):
    with db.session() as s:
        r = normalize_report({"hostname": "web01", "os": "Linux", "ip": "10.0.0.5", "ports": [{"port": 22}, {"port": 443}]})
        res = ingest_report(s, r)
        s.commit()
    assert res["created"] and res["new_services"] == 2
    with db.session() as s:
        a = s.scalar(sa.select(Asset).where(Asset.current_ip == "10.0.0.5"))
        assert a.os_family == "linux" and "agent" in a.discovery_methods
        assert {x.port for x in a.services} == {22, 443}
        # A second report with one more port updates, not duplicates.
        res2 = ingest_report(s, normalize_report({"hostname": "web01", "ip": "10.0.0.5", "ports": [{"port": 22}, {"port": 8080}]}))
        s.commit()
    assert res2["created"] is False and res2["new_services"] == 1


def test_agent_api_token_flow_and_ingest(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "op", "operator")
    client = make_client()
    csrf = login(client, "admin")

    created = client.post("/api/agents/tokens", json={"label": "لابتوبات"}, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 201
    token = created.json()["token"]
    assert token.startswith("rsd_")
    # Listing never returns the secret.
    row = client.get("/api/agents/tokens").json()[0]
    assert "token" not in row and row["label"] == "لابتوبات"

    # Report without a token is rejected; with the token it ingests.
    assert client.post("/api/agents/report", json={"hostname": "h"}).status_code == 401
    assert client.post("/api/agents/report", json={"hostname": "h"}, headers={"X-Agent-Token": "rsd_wrong"}).status_code == 401
    ok = client.post("/api/agents/report", json={"hostname": "agent-pc", "os": "Windows", "ip": "10.0.0.77",
                                                 "ports": [{"port": 3389}]}, headers={"X-Agent-Token": token})
    assert ok.status_code == 200 and ok.json()["created"] is True

    with db.session() as s:
        assert s.scalar(sa.select(Asset).where(Asset.current_ip == "10.0.0.77")) is not None
        tok = s.scalar(sa.select(AgentToken))
        assert tok.last_seen_at is not None and tok.last_host == "agent-pc"

    # Operators cannot manage tokens (needs user:manage).
    op = make_client()
    oc = login(op, "op")
    assert op.post("/api/agents/tokens", json={"label": "x"}, headers={"X-CSRF-Token": oc}).status_code == 403
