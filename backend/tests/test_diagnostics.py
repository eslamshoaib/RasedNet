"""Discovery reachability diagnostics (uses loopback so it is fast and deterministic)."""

from __future__ import annotations


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def test_reachability_loopback_in_and_out_of_scope(make_client, db):
    from tests.conftest import login, make_user
    make_user(db, "admin", "admin")
    client = make_client()
    csrf = login(client, "admin")

    # Loopback is reachable but not in any approved scope yet → "reachable_out_of_scope".
    r = client.post("/api/diagnostics/reachability", json={"ip": "127.0.0.1"}, headers=h(csrf))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reachable"] is True
    assert body["in_scope"] is False
    assert body["verdict"] == "reachable_out_of_scope"

    # Approve a scope covering loopback → verdict becomes "reachable".
    sid = client.post("/api/scopes", json={"name": "lo", "cidr": "127.0.0.1/32"}, headers=h(csrf)).json()["id"]
    client.post(f"/api/scopes/{sid}/approve", json={"confirm": True}, headers=h(csrf))
    body2 = client.post("/api/diagnostics/reachability", json={"ip": "127.0.0.1"}, headers=h(csrf)).json()
    assert body2["in_scope"] is True and body2["verdict"] == "reachable"


def test_reachability_rejects_bad_ip(make_client, db):
    from tests.conftest import login, make_user
    make_user(db, "admin", "admin")
    client = make_client()
    csrf = login(client, "admin")
    assert client.post("/api/diagnostics/reachability", json={"ip": "not-an-ip"}, headers=h(csrf)).status_code == 422
