"""Administrator verify/close guidance per service."""

from __future__ import annotations

import pytest

from rased.remediation import FW_FILE_PRINTER_SHARING, FW_REMOTE_DESKTOP, build_guidance


def cmds(guide: dict, section: str) -> list[str]:
    return [c["command"] for p in guide["platforms"] for c in p[section]]


def test_windows_smb_guidance():
    g = build_guidance("smb", 445, "10.150.12.85", "windows", "computer")
    assert [p["platform"] for p in g["platforms"]] == ["windows"]
    assert g["network_checks"][0]["command"] == "Test-NetConnection 10.150.12.85 -Port 445"
    assert any(c["command"] == "net view \\\\10.150.12.85 /all" for c in g["network_checks"])
    verify = cmds(g, "verify")
    assert any("-LocalPort 445" in c for c in verify) and any("Get-SmbShare" in c for c in verify)
    disable = cmds(g, "disable")
    assert f"Disable-NetFirewallRule -Group '{FW_FILE_PRINTER_SHARING}'" in disable
    assert any("Set-Service LanmanServer -StartupType Disabled" in c for c in disable)
    assert any("EnableSMB1Protocol $false" in c for c in cmds(g, "harden"))
    assert g["platforms"][0]["warnings_ar"]


def test_rdp_has_disable_and_undo():
    g = build_guidance("rdp", 3389, "10.0.0.5", "windows", "computer")
    disable = cmds(g, "disable")
    assert any("fDenyTSConnections -Value 1" in c for c in disable)
    assert any("fDenyTSConnections -Value 0" in c for c in disable)  # undo
    assert f"Disable-NetFirewallRule -Group '{FW_REMOTE_DESKTOP}'" in disable
    assert any(c["command"] == "mstsc /v:10.0.0.5" for c in g["network_checks"])


def test_core_rpc_is_never_stopped():
    g = build_guidance("msrpc", 135, "10.0.0.5", "windows", "computer")
    disable = cmds(g, "disable")
    assert not any("Stop-Service" in c for c in disable)
    assert any("UNTRUSTED_SUBNET" in c for c in disable)
    assert any("أساسية" in w for w in g["platforms"][0]["warnings_ar"])


def test_linux_and_unknown_os():
    linux = build_guidance("http", 8080, "10.0.0.9", "linux", "server")
    assert [p["platform"] for p in linux["platforms"]] == ["linux"]
    assert cmds(linux, "verify")[0].startswith("sudo ss -ltnp 'sport = :8080' 2>/dev/null || sudo netstat")
    assert "sudo ufw deny 8080/tcp" in cmds(linux, "disable")
    assert any(c["command"] == "curl.exe -skI http://10.0.0.9:8080/" for c in linux["network_checks"])
    unknown = build_guidance("http", 80, "10.0.0.9", "unknown", "unknown")
    assert [p["platform"] for p in unknown["platforms"]] == ["windows", "linux"]


def test_appliances_get_admin_panel_guidance():
    g = build_guidance("jetdirect", 9100, "10.0.0.50", "unknown", "printer")
    (platform,) = g["platforms"]
    assert platform["platform"] == "appliance" and platform["verify"] == [] and "http://10.0.0.50" in platform["notes_ar"][0]


def test_database_hardening_note():
    g = build_guidance("mongodb", 27017, "127.0.0.1", "windows", "server")
    assert any("bindIp" in n for n in g["platforms"][0]["notes_ar"])


@pytest.mark.parametrize("ip,port", [(None, 80), ("10.0.0.1; Remove-Item C:\\ -Recurse", 80), ("10.0.0.1", 0), ("10.0.0.1", 70000)])
def test_only_validated_values_reach_commands(ip, port):
    assert build_guidance("http", port, ip, "windows", "computer") is None


def test_no_network_text_in_commands():
    """Service names come from our own table; ensure an odd name cannot alter a command."""
    g = build_guidance("evil'; rm -rf /", 4444, "10.0.0.1", "windows", "computer")
    for c in cmds(g, "verify") + cmds(g, "disable"):
        assert "rm -rf" not in c


def test_asset_detail_includes_guidance_for_open_services(make_client, db):
    from sqlalchemy import select

    from rased.models import Asset, Service, utcnow
    from tests.conftest import login, make_user

    make_user(db, "admin", "admin")
    with db.session() as s:
        now = utcnow()
        a = Asset(current_ip="10.0.0.7", status="online", os_family="windows", device_type="computer", first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        s.add_all([
            Service(asset_id=a.id, port=3389, protocol="tcp", state="open", service_name="rdp", first_seen=now, last_seen=now),
            Service(asset_id=a.id, port=21, protocol="tcp", state="closed", service_name="ftp", first_seen=now, last_seen=now),
        ])
        asset_id = a.id
    client = make_client()
    login(client, "admin")
    services = {s["port"]: s for s in client.get(f"/api/assets/{asset_id}").json()["services"]}
    assert services[3389]["guidance"]["platforms"][0]["platform"] == "windows"
    assert services[21]["guidance"] is None  # closed services need no action
    with db.session() as s:
        assert s.scalar(select(Service.id).where(Service.port == 3389)) is not None
