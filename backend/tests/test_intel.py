"""Device intelligence (NetBIOS, UPnP, gateways), network map, traceroute, SSH, data reset."""

from __future__ import annotations

import socket
import struct

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import func, select

from rased.discovery.fingerprint import FingerprintInput, classify
from rased.discovery.netbios import build_request, parse_response
from rased.discovery.ssdp import parse_description, parse_ssdp_response
from rased.discovery.traceroute import parse_unix_traceroute
from rased.models import Alert, Asset, AuditLog, IpObservation, RouteTrace, ScanJob, ScanScope, Service, User, utcnow
from rased.remote import ssh_command
from tests.conftest import login, make_user


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


# --- NetBIOS -------------------------------------------------------------------------------------


def _nbstat_reply(tid: int, names: list[tuple[str, int, bool]], mac: bytes) -> bytes:
    header = struct.pack(">HHHHHH", tid, 0x8400, 0, 1, 0, 0)
    name = build_request(tid)[12:12 + 34]
    body = bytes([len(names)])
    for n, suffix, group in names:
        body += n.ljust(15).encode("latin-1") + bytes([suffix]) + struct.pack(">H", 0x8000 if group else 0x0400)
    body += mac + b"\x00" * 40
    return header + name + struct.pack(">HHIH", 0x0021, 0x0001, 0, len(body)) + body


def test_netbios_request_and_response():
    req = build_request(0x1234)
    assert req[:2] == b"\x12\x34" and req[12] == 32 and req[13:15] == b"CK" and req[-4:] == b"\x00\x21\x00\x01"
    info = parse_response(_nbstat_reply(0x1234, [("CRIMEDATA", 0x00, False), ("WORKGROUP", 0x00, True), ("CRIMEDATA", 0x20, False),
                                                  ("CORP", 0x1C, True)], bytes.fromhex("B47AF1346768")), 0x1234)
    assert (info.computer_name, info.workgroup, info.file_server, info.domain_controller, info.mac) == (
        "crimedata", "workgroup", True, True, "B4:7A:F1:34:67:68")
    samba = parse_response(_nbstat_reply(7, [("NAS01", 0, False)], b"\x00" * 6), 7)
    assert samba.mac is None  # Samba: all-zero MAC
    assert parse_response(_nbstat_reply(7, [("X", 0, False)], b"\x00" * 6), 8) is None  # wrong transaction
    for junk in (b"", b"\x00" * 11, b"\xff" * 64, _nbstat_reply(1, [("A", 0, False)], b"")[:-50]):
        parse_response(junk)  # never raises


# --- UPnP ------------------------------------------------------------------------------------


def test_ssdp_and_upnp_description_parsing():
    headers = parse_ssdp_response(b"HTTP/1.1 200 OK\r\nSERVER: Linux/2.6.36, UPnP/1.0\r\nLOCATION: http://10.0.0.1:1900/igd.xml\r\n\r\n")
    assert headers["location"] == "http://10.0.0.1:1900/igd.xml"
    assert parse_ssdp_response(b"garbage") is None
    xml = b"""<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
      <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
      <friendlyName>Wireless N Router</friendlyName><manufacturer>TP-Link</manufacturer>
      <modelName>TL-WR840N</modelName><modelNumber>6.0</modelNumber></device></root>"""
    d = parse_description(xml)
    assert d["manufacturer"] == "TP-Link" and d["model_name"] == "TL-WR840N" and d["device_type"].endswith("InternetGatewayDevice:1")
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><root><device><friendlyName>&b;</friendlyName></device></root>'
    with pytest.raises(Exception):  # defusedxml refuses entity expansion attacks
        parse_description(bomb)


def test_new_classification_signals():
    router = classify(FingerprintInput(open_ports=frozenset({80}), upnp_type="urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                                       upnp_manufacturer="TP-Link", upnp_model="TL-WR840N"))
    assert router.device_type == "router" and router.device_confidence > 0.9
    ap = classify(FingerprintInput(open_ports=frozenset({80}), upnp_type="urn:schemas-wifialliance-org:device:WFADevice:1",
                                   upnp_manufacturer="TP-LINK", upnp_model="TL-WA801ND"))
    assert ap.device_type == "access_point"
    tv = classify(FingerprintInput(open_ports=frozenset(), upnp_type="urn:dial-multiscreen-org:device:dial:1",
                                   upnp_manufacturer="Hisense", upnp_model="HiSmart 2K ATV4"))
    assert tv.device_type == "tv"
    gw = classify(FingerprintInput(open_ports=frozenset({53, 80}), is_gateway=True))
    assert gw.device_type == "router"
    win = classify(FingerprintInput(open_ports=frozenset({445}), netbios=True, netbios_file_server=True))
    assert win.os_family == "windows"
    samba = classify(FingerprintInput(open_ports=frozenset({445, 22}), netbios=True, netbios_null_mac=True))
    assert samba.os_family == "linux"
    dc = classify(FingerprintInput(open_ports=frozenset({445}), netbios=True, netbios_domain_controller=True))
    assert dc.device_type == "server"


# --- traceroute -------------------------------------------------------------------------------


def test_unix_traceroute_parsing():
    out = "traceroute to 10.20.0.1 (10.20.0.1), 15 hops max\n 1  10.150.0.1  0.412 ms\n 2  *\n 3  192.168.2.1  1.2 ms\n"
    hops = parse_unix_traceroute(out)
    assert [(h.ttl, h.ip) for h in hops] == [(1, "10.150.0.1"), (2, None), (3, "192.168.2.1")]


@pytest.mark.skipif(not __import__("sys").platform == "win32", reason="native Windows ICMP")
def test_native_traceroute_reaches_loopback():
    from rased.discovery.traceroute import trace

    hops = trace("127.0.0.1", max_hops=3)
    assert hops and hops[-1].ip == "127.0.0.1"


# --- network map --------------------------------------------------------------------------------


def test_topology_graph(make_client, db, monkeypatch):
    import rased.topology as topo

    monkeypatch.setattr(topo, "_local_networks", lambda: [(__import__("ipaddress").ip_network("10.150.0.0/20"), "Ethernet", "10.150.12.85")])
    make_user(db, "admin", "admin")
    now = utcnow()
    with db.session() as s:
        s.add(ScanScope(name="remote", cidr="10.20.0.0/24", is_approved=True, excluded_hosts=[], excluded_ports=[],
                        description="", is_sensitive=False, is_active=True))
        gw = Asset(current_ip="10.150.0.1", status="online", is_gateway=True, device_type="router", first_seen=now, last_seen=now)
        pc = Asset(current_ip="10.150.3.7", status="online", device_type="computer", first_seen=now, last_seen=now)
        bridge = Asset(current_ip="10.150.4.4", status="online", device_type="server", first_seen=now, last_seen=now)
        s.add_all([gw, pc, bridge])
        s.flush()
        s.add_all([IpObservation(asset_id=bridge.id, ip="10.150.4.4", first_seen=now, last_seen=now, sightings=1),
                   IpObservation(asset_id=bridge.id, ip="10.20.0.9", first_seen=now, last_seen=now, sightings=1)])
        s.add(RouteTrace(target="10.20.0.1", hops=[{"ttl": 1, "ip": "10.150.0.1"}, {"ttl": 2, "ip": None}, {"ttl": 3, "ip": "10.10.10.29"},
                                                    {"ttl": 4, "ip": "10.20.0.1"}], reached=True, created_at=now))
        ids = (gw.id, pc.id, bridge.id)
    client = make_client()
    login(client, "admin")
    g = client.get("/api/topology").json()
    nodes = {n["id"]: n for n in g["nodes"]}
    edges = {(e["source"], e["target"], e["kind"]): e for e in g["edges"]}
    assert {"scanner", "net:10.150.0.0/20", "net:10.20.0.0/24", f"a:{ids[0]}", "hop:10.10.10.29"} <= set(nodes)
    assert edges[("scanner", "net:10.150.0.0/20", "attached")]["verified"] is True
    assert edges[("scanner", f"a:{ids[0]}", "path")]["verified"] is True
    assert edges[(f"a:{ids[0]}", "hop:10.10.10.29", "path")]["verified"] is False  # silent hop in between: inferred
    multi = [e for e in g["edges"] if e["kind"] == "multihomed"]
    assert {e["target"] for e in multi} == {"net:10.150.0.0/20", "net:10.20.0.0/24"}
    assert nodes[f"a:{ids[0]}"]["device_type"] == "router" and g["stats"]["paths"] == 1
    assert len([n for n in client.get("/api/topology", params={"include_devices": False}).json()["nodes"] if n["type"] == "device"]) == 1


def test_trace_refuses_unapproved_targets(make_client, db):
    make_user(db, "admin", "admin")
    client = make_client()
    csrf = login(client, "admin")
    r = client.post("/api/topology/trace", json={"targets": ["8.8.8.8"]}, headers=h(csrf))
    assert r.status_code == 409


# --- data maintenance -------------------------------------------------------------------------------


def test_delete_scan_and_reset_inventory(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "op", "operator")
    now = utcnow()
    with db.session() as s:
        scope = ScanScope(name="x", cidr="10.0.0.0/24", is_approved=True, excluded_hosts=[], excluded_ports=[],
                          description="", is_sensitive=False, is_active=True)
        s.add(scope)
        s.flush()
        job = ScanJob(scope_id=scope.id, profile_id=1, status="completed", scope_snapshot={}, profile_snapshot={}, created_at=now)
        s.add(job)
        s.flush()
        a = Asset(current_ip="10.0.0.5", status="online", first_seen=now, last_seen=now, last_scan_job_id=job.id)
        s.add(a)
        s.flush()
        s.add(Service(asset_id=a.id, port=22, protocol="tcp", state="open", service_name="ssh", first_seen=now, last_seen=now, last_job_id=job.id))
        s.add(Alert(kind="new_asset", severity="medium", title_ar="t", message_ar="m", dedup_key="k", status="open", asset_id=a.id,
                    job_id=job.id, first_seen=now, last_seen=now))
        job_id = job.id
    op = make_client()
    op_csrf = login(op, "op")
    assert op.delete(f"/api/scans/{job_id}", headers=h(op_csrf)).status_code == 403
    client = make_client()
    csrf = login(client, "admin")
    assert client.delete(f"/api/scans/{job_id}", headers=h(csrf)).status_code == 204
    with db.session() as s:
        assert s.scalar(select(func.count()).select_from(ScanJob)) == 0
        assert s.scalar(select(Asset.last_scan_job_id)) is None and s.scalar(select(func.count()).select_from(Asset)) == 1
    r = client.post("/api/maintenance/reset-inventory", json={"confirm_text": "نعم"}, headers=h(csrf))
    assert r.status_code == 422
    r = client.post("/api/maintenance/reset-inventory", json={"confirm_text": "حذف كل البيانات"}, headers=h(csrf))
    assert r.status_code == 200 and r.json()["assets"] == 1
    with db.session() as s:
        for model in (Asset, Service, Alert, ScanJob):
            assert s.scalar(select(func.count()).select_from(model)) == 0
        assert s.scalar(select(func.count()).select_from(ScanScope)) == 1  # configuration kept
        assert s.scalar(select(func.count()).select_from(User)) == 2
        assert s.scalar(select(AuditLog.id).where(AuditLog.action == "maintenance.reset_inventory")) is not None


# --- SSH --------------------------------------------------------------------------------------------


def test_ssh_command_elevation():
    assert ssh_command("uname -a", "admin") == ("uname -a", False)
    cmd, needs = ssh_command("sudo systemctl status $(sudo ss -ltnpH 'sport = :22' | head -n1)", "admin")
    assert needs and cmd.startswith("sudo -S -p '' sh -c ") and cmd.count("sudo") == 1
    root, needs_root = ssh_command("sudo ufw deny 22/tcp", "root")
    assert root == "sh -c 'ufw deny 22/tcp'" and needs_root is False


def _ssh_server_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 2222), timeout=1):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _ssh_server_up(), reason="throwaway OpenSSH container on 127.0.0.1:2222 not running")
def test_real_ssh_execution_through_api(make_client, settings, db):
    make_user(db, "admin", "admin")
    client = make_client(settings_override=settings.model_copy(update={"secret_key": Fernet.generate_key().decode()}))
    csrf = login(client, "admin")
    sid = client.post("/api/scopes", json={"name": "lo", "cidr": "127.0.0.1/32"}, headers=h(csrf)).json()["id"]
    client.post(f"/api/scopes/{sid}/approve", json={"confirm": True}, headers=h(csrf))
    now = utcnow()
    with db.session() as s:
        a = Asset(current_ip="127.0.0.1", status="online", os_family="linux", device_type="server", first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        svc = Service(asset_id=a.id, port=2222, protocol="tcp", state="open", service_name="ssh", first_seen=now, last_seen=now)
        s.add(svc)
        s.flush()
        aid, svc_id = a.id, svc.id
    cred = client.post("/api/credentials", json={"name": "lab-ssh", "kind": "ssh", "username": "rasedtest",
                                                 "password": "SshTest#2026", "port": 2222}, headers=h(csrf)).json()
    assert cred["kind"] == "ssh" and cred["port"] == 2222
    t = client.post(f"/api/credentials/{cred['id']}/test", json={"asset_id": aid}, headers=h(csrf)).json()
    assert t["status"] == "ok" and "Linux" in t["output"], t
    keys = client.get("/api/ssh-host-keys").json()
    assert keys[0]["fingerprint"].startswith("SHA256:")
    r = client.post(f"/api/assets/{aid}/services/{svc_id}/execute", json={"section": "verify", "index": 0, "credential_id": cred["id"]},
                    headers=h(csrf)).json()
    assert r["status"] == "ok" and "2222" in r["output"], r
    c = client.post(f"/api/assets/{aid}/console", json={"credential_id": cred["id"], "command": "sudo id -u", "confirm": True},
                    headers=h(csrf)).json()
    assert c["status"] == "ok" and c["output"].splitlines()[0].strip() == "0"


def test_trace_internal_target_and_candidates_from_paths(make_client, db, monkeypatch):
    """Tracing toward an internal address needs no scope; networks on the path become suggestions."""
    import rased.api.topology as topo_api
    from rased.discovery.traceroute import Hop

    async def fake_trace_many(ips, max_hops=15, timeout_ms=800):  # type: ignore[no-untyped-def]
        return {ip: [Hop(1, "10.150.0.1", 1), Hop(2, None, None), Hop(3, "192.168.2.1", 1), Hop(4, ip, 1)] for ip in ips}

    monkeypatch.setattr(topo_api, "trace_many", fake_trace_many)
    make_user(db, "admin", "admin")
    client = make_client()
    client.app.state.network_discovery = lambda: []
    csrf = login(client, "admin")
    r = client.post("/api/topology/trace", json={"targets": ["10.20.0.1"]}, headers=h(csrf))
    assert r.status_code == 200 and r.json()["paths"][0]["reached"] is True
    assert client.post("/api/topology/trace", json={"targets": ["8.8.8.8"]}, headers=h(csrf)).status_code == 409
    cands = {c["cidr"]: c for c in client.get("/api/scopes/candidates").json()}
    assert {"10.150.0.0/24", "192.168.2.0/24", "10.20.0.0/24"} <= set(cands)
    assert cands["192.168.2.0/24"]["sources"] == ["trace"] and cands["192.168.2.0/24"]["gateways"] == ["10.150.0.1"]


def test_pc_vendor_with_windows_ttl_is_a_windows_computer():
    c = classify(FingerprintInput(open_ports=frozenset(), vendor="Dell Inc.", ttl=128))
    assert c.device_type == "computer" and c.os_family == "windows" and c.os_confidence < 0.6
    assert classify(FingerprintInput(open_ports=frozenset(), vendor="Hewlett Packard", ttl=128)).device_type == "unknown"
