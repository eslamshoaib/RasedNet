"""Manual device registration (POST /api/assets)."""

from __future__ import annotations

import sqlalchemy as sa

from rased.models import Asset
from tests.conftest import login, make_user


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def test_create_asset_manually(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "auditor", "auditor")
    client = make_client()
    csrf = login(client, "admin")

    r = client.post("/api/assets", json={"current_ip": "10.235.0.223", "display_name": "هاتف المكتب",
                                          "device_type": "mobile", "mac": "aa-bb-cc-dd-ee-ff"}, headers=h(csrf))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["current_ip"] == "10.235.0.223" and body["device_type"] == "mobile"

    with db.session() as s:
        a = s.scalar(sa.select(Asset).where(Asset.current_ip == "10.235.0.223"))
        assert a.display_name == "هاتف المكتب" and a.mac == "AA:BB:CC:DD:EE:FF"
        assert a.discovery_methods == ["manual"] and a.status == "unknown"

    # Duplicate IP → 409; bad IP → 422; bad type → 422.
    assert client.post("/api/assets", json={"current_ip": "10.235.0.223"}, headers=h(csrf)).status_code == 409
    assert client.post("/api/assets", json={"current_ip": "nope"}, headers=h(csrf)).status_code == 422
    assert client.post("/api/assets", json={"current_ip": "10.0.0.9", "device_type": "spaceship"}, headers=h(csrf)).status_code == 422

    # Auditors cannot create (no asset:write).
    aud = make_client()
    ac = login(aud, "auditor")
    assert aud.post("/api/assets", json={"current_ip": "10.0.0.8"}, headers=h(ac)).status_code == 403
