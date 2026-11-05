"""Router / network-device administration: platform detection, command safety, API, real SSH."""

from __future__ import annotations

import socket

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from rased.models import Asset, AuditLog, Service, utcnow
from rased.netadmin import NetAdminError, build_command, detect_platform, get_action, platform_for, platform_payload
from tests.conftest import login, make_user


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def test_platform_detection():
    assert detect_platform("MikroTik", "RB750", None) == "routeros"
    assert detect_platform(None, None, "SSH-2.0-ROSSSH") == "routeros"
    assert detect_platform("Cisco Systems", "Catalyst 2960", None) == "cisco_ios"
    assert detect_platform("TP-Link", "TL-WR840N", "SSH-2.0-dropbear_2019.78") == "linux"
    assert detect_platform(None, None, None) == "linux"


def test_every_action_template_is_valid_and_declares_its_params():
    for key in ("routeros", "cisco_ios", "linux"):
        for action in platform_for(key).actions:
            names = {p.name for p in action.params}
            # Build with placeholder-safe values to prove the template only needs declared params.
            values = {p.name: ("10.0.0.5" if p.kind == "ip" else "AA:BB:CC:DD:EE:FF" if p.kind == "mac" else "eth0") for p in action.params}
            built = build_command(action, values)
            for name in names:  # every declared parameter token is substituted
                assert "{" + name + "}" not in built
            assert values.keys() == names  # command needs exactly its declared params
    # Cisco is read-only in this release.
    assert all(a.category == "info" for a in platform_for("cisco_ios").actions)


def test_parameter_validation_blocks_injection():
    block = get_action("linux", "block_mac")
    assert build_command(block, {"mac": "aa-bb-cc-dd-ee-ff"}).endswith("--mac-source AA:BB:CC:DD:EE:FF -j DROP && echo 'تم الحظر'")
    for bad in ("AA:BB:CC:DD:EE:FF; rm -rf /", "$(reboot)", "", "not-a-mac"):
        with pytest.raises(NetAdminError):
            build_command(block, {"mac": bad})
    iface = get_action("routeros", "disable_iface")
    with pytest.raises(NetAdminError):
        build_command(iface, {"iface": "ether1; /system reboot"})
    assert build_command(iface, {"iface": "ether1"}) == "/interface disable ether1"


def test_public_payload_hides_raw_command():
    payload = platform_payload("routeros")
    assert payload["platform"] == "routeros" and payload["actions"]
    action = next(a for a in payload["actions"] if a["id"] == "block_mac")
    assert "command" not in action and action["category"] == "change" and action["warning_ar"]
    assert action["params"][0]["kind"] == "mac"


def _router_asset(db, vendor="TP-Link", ssh=True):  # type: ignore[no-untyped-def]
    now = utcnow()
    with db.session() as s:
        a = Asset(current_ip="127.0.0.1", status="online", device_type="router", vendor=vendor, is_gateway=True,
                  first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        if ssh:
            s.add(Service(asset_id=a.id, port=2222, protocol="tcp", state="open", service_name="ssh",
                          product="dropbear", first_seen=now, last_seen=now))
        s.flush()
        return a.id


def test_netadmin_listing_and_authorisation(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "op", "operator")
    aid = _router_asset(db, vendor="MikroTik")
    client = make_client()
    csrf = login(client, "admin")
    actions = client.get(f"/api/assets/{aid}/netadmin").json()
    assert actions["platform"] == "routeros" and actions["is_network_device"] and actions["has_ssh"]
    assert any(a["id"] == "block_mac" for a in actions["actions"])
    # A non-network device is refused.
    now = utcnow()
    with db.session() as s:
        pc = Asset(current_ip="127.0.0.1", status="online", device_type="computer", first_seen=now, last_seen=now)
        s.add(pc)
        s.flush()
        pc_id = pc.id
    sid = client.post("/api/scopes", json={"name": "lo", "cidr": "127.0.0.1/32"}, headers=h(csrf)).json()["id"]
    client.post(f"/api/scopes/{sid}/approve", json={"confirm": True}, headers=h(csrf))
    r = client.post(f"/api/assets/{pc_id}/netadmin/routes", json={"credential_id": 1, "params": {}}, headers=h(csrf))
    assert r.status_code == 409
    # Operators cannot run change actions.
    op = make_client()
    op_csrf = login(op, "op")
    r = op.post(f"/api/assets/{aid}/netadmin/reboot", json={"credential_id": 1, "confirm": True}, headers=h(op_csrf))
    assert r.status_code == 403


def _ssh_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 2222), timeout=1):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _ssh_up(), reason="throwaway OpenSSH container on 127.0.0.1:2222 not running")
def test_real_router_admin_over_ssh(make_client, settings, db):
    make_user(db, "admin", "admin")
    aid = _router_asset(db, vendor="TP-Link")
    client = make_client(settings_override=settings.model_copy(update={"secret_key": Fernet.generate_key().decode()}))
    csrf = login(client, "admin")
    sid = client.post("/api/scopes", json={"name": "lo", "cidr": "127.0.0.1/32"}, headers=h(csrf)).json()["id"]
    client.post(f"/api/scopes/{sid}/approve", json={"confirm": True}, headers=h(csrf))
    cred = client.post("/api/credentials", json={"name": "router", "kind": "ssh", "username": "rasedtest",
                                                 "password": "SshTest#2026", "port": 2222}, headers=h(csrf)).json()
    assert client.get(f"/api/assets/{aid}/netadmin").json()["platform"] == "linux"
    # Read-only action really runs on the device.
    r = client.post(f"/api/assets/{aid}/netadmin/neighbors", json={"credential_id": cred["id"]}, headers=h(csrf))
    assert r.status_code == 200 and r.json()["status"] == "ok", r.text
    r = client.post(f"/api/assets/{aid}/netadmin/system", json={"credential_id": cred["id"]}, headers=h(csrf)).json()
    assert "Linux" in r["output"]
    # Change action needs confirmation and a valid MAC; the command is audited.
    assert client.post(f"/api/assets/{aid}/netadmin/block_mac", json={"credential_id": cred["id"], "params": {"mac": "AA:BB:CC:DD:EE:FF"}}, headers=h(csrf)).status_code == 422
    assert client.post(f"/api/assets/{aid}/netadmin/block_mac", json={"credential_id": cred["id"], "confirm": True, "params": {"mac": "bad"}}, headers=h(csrf)).status_code == 422
    with db.session() as s:
        actions = [a.action for a in s.scalars(select(AuditLog).where(AuditLog.action == "remote.execute"))]
    assert actions.count("remote.execute") >= 2
