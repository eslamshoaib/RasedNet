"""Anonymous SMB share browsing — safety guards and API gating (no live SMB needed)."""

from __future__ import annotations

import pytest

from rased.models import Asset, Service, utcnow
from rased.smbshares import ADMIN_SHARES, COMMON_SHARES, SmbError, browse
from tests.conftest import login, make_user


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def test_common_shares_exclude_admin_shares():
    assert not ({s.lower() for s in COMMON_SHARES} & ADMIN_SHARES)


def test_browse_rejects_admin_shares_and_traversal():
    # These raise before any network connection is attempted.
    with pytest.raises(SmbError):
        browse("10.0.0.5", "C$")
    with pytest.raises(SmbError):
        browse("10.0.0.5", "ADMIN$")
    with pytest.raises(SmbError):
        browse("10.0.0.5", "Public", "a/../../secret")


def _smb_asset(db, ip="10.0.0.5", with_smb=True):  # type: ignore[no-untyped-def]
    now = utcnow()
    with db.session() as s:
        a = Asset(current_ip=ip, status="online", device_type="nas", first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        if with_smb:
            s.add(Service(asset_id=a.id, port=445, protocol="tcp", state="open", service_name="smb",
                          first_seen=now, last_seen=now))
        s.flush()
        return a.id


def test_api_gating(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "auditor", "auditor")
    no_smb = _smb_asset(db, ip="10.0.0.6", with_smb=False)
    client = make_client()
    csrf = login(client, "admin")

    # Missing asset → 404; asset without SMB → 409.
    assert client.get("/api/assets/999999/smb/shares").status_code == 404
    assert client.get(f"/api/assets/{no_smb}/smb/shares").status_code == 409

    # Auditor lacks remote:verify.
    aud = make_client()
    ac = login(aud, "auditor")
    assert aud.get(f"/api/assets/{no_smb}/smb/shares", headers=h(ac)).status_code == 403
