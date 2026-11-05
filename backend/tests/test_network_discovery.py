"""Automatic discovery of candidate networks (interfaces + routing table)."""

from __future__ import annotations

from rased.discovery.networks import (
    CandidateNetwork,
    InterfaceAddress,
    Route,
    build_candidates,
    discover_candidate_networks,
    parse_linux_routes,
    parse_windows_routes,
)
from tests.conftest import STRONG_PASSWORD, login, make_user

# Shape of a real Windows 10 host with Hyper-V / WSL switches (captured from Get-NetRoute).
WIN_ROUTES = '''"DestinationPrefix","NextHop","InterfaceAlias"
"172.22.175.255/32","0.0.0.0","vEthernet (Default Switch)"
"172.22.160.0/20","0.0.0.0","vEthernet (Default Switch)"
"127.0.0.0/8","0.0.0.0","Loopback Pseudo-Interface 1"
"10.150.12.85/32","0.0.0.0","Ethernet"
"10.150.0.0/20","0.0.0.0","Ethernet"
"10.20.0.0/16","10.150.0.1","Ethernet"
"224.0.0.0/4","0.0.0.0","Ethernet"
"0.0.0.0/0","10.150.0.1","Ethernet"
'''

INTERFACES = [
    InterfaceAddress("vEthernet (Default Switch)", "172.22.160.1", "255.255.240.0"),
    InterfaceAddress("Ethernet", "10.150.12.85", "255.255.240.0"),
    InterfaceAddress("Loopback Pseudo-Interface 1", "127.0.0.1", "255.0.0.0"),
    InterfaceAddress("Wi-Fi", "169.254.10.20", "255.255.0.0"),
    InterfaceAddress("Ethernet 2", "192.168.50.7", "255.255.255.0", is_up=False),
]


def test_parse_windows_routes():
    routes = parse_windows_routes(WIN_ROUTES)
    assert Route("10.20.0.0/16", "10.150.0.1", "Ethernet") in routes and len(routes) == 8


def test_parse_linux_routes():
    out = (
        "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
        "10.10.0.0/16 via 192.168.1.254 dev eth0\n"
        "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.20\n"
        "broadcast 192.168.1.255 dev eth0 table local proto kernel scope link src 192.168.1.20\n"
    )
    routes = parse_linux_routes(out)
    assert [r.prefix for r in routes] == ["10.10.0.0/16", "192.168.1.0/24"]
    assert routes[0].next_hop == "192.168.1.254" and routes[1].next_hop == "0.0.0.0"


def test_build_candidates_from_real_host_shape():
    cands = build_candidates(INTERFACES, parse_windows_routes(WIN_ROUTES))
    by_cidr = {c.cidr: c for c in cands}
    # Loopback, link-local (APIPA), multicast, default and host routes are never suggested; down interfaces ignored.
    assert set(by_cidr) == {"10.150.0.0/20", "10.20.0.0/16", "172.22.160.0/20"}
    eth = by_cidr["10.150.0.0/20"]
    assert eth.sources == ["interface", "route"] and eth.local_ips == ["10.150.12.85"] and not eth.is_virtual
    routed = by_cidr["10.20.0.0/16"]
    assert routed.sources == ["route"] and routed.gateways == ["10.150.0.1"]
    assert by_cidr["172.22.160.0/20"].is_virtual
    assert cands[-1].cidr == "172.22.160.0/20"  # virtual networks listed last


def test_discovery_on_this_host_returns_valid_networks():
    """Executes the real OS readers (psutil + route table)."""
    for cand in discover_candidate_networks():
        assert cand.network.prefixlen <= 30 and not cand.network.is_loopback


def _fake(app_client, candidates):  # type: ignore[no-untyped-def]
    app_client.app.state.network_discovery = lambda: candidates


def test_candidates_endpoint_and_one_click_scan(make_client, db):
    make_user(db, "admin", "admin")
    client = make_client()
    _fake(client, [
        CandidateNetwork("127.0.0.0/30", ["interface"], ["Ethernet"], ["127.0.0.1"]),
        CandidateNetwork("10.0.0.0/8", ["route"], ["Ethernet"], [], ["10.150.0.1"]),
        CandidateNetwork("8.8.8.0/24", ["route"], ["Ethernet"]),
    ])
    csrf = login(client, "admin")
    cands = {c["cidr"]: c for c in client.get("/api/scopes/candidates").json()}
    assert cands["127.0.0.0/30"]["allowed"] and cands["127.0.0.0/30"]["host_count"] == 2
    big = cands["10.0.0.0/8"]
    assert not big["allowed"] and big["suggested_cidr"] == "10.0.0.0/16"
    assert not cands["8.8.8.0/24"]["allowed"] and "العامة" in cands["8.8.8.0/24"]["reason_ar"]

    pid = next(p["id"] for p in client.get("/api/profiles").json() if p["code"] == "safe_discovery")
    h = {"X-CSRF-Token": csrf}
    # Approval needs explicit confirmation.
    r = client.post("/api/scopes/bulk", json={"items": [{"cidr": "127.0.0.0/30"}], "approve": True}, headers=h)
    assert r.status_code == 422
    r = client.post("/api/scopes/bulk", headers=h, json={
        "items": [{"cidr": "127.0.0.0/30", "name": "Ethernet — 127.0.0.0/30"}, {"cidr": "8.8.8.0/24"}],
        "approve": True, "confirm": True, "start_scan_profile_id": pid,
    })
    assert r.status_code == 200, r.text
    ok, bad = r.json()
    assert ok["created"] and ok["approved"] and ok["job_id"] is not None and ok["error_ar"] is None
    assert bad["scope_id"] is None and "العامة" in bad["error_ar"]
    # Listed as already added afterwards; repeating the request reuses the scope.
    assert {c["cidr"]: c for c in client.get("/api/scopes/candidates").json()}["127.0.0.0/30"]["existing_scope_approved"]
    again = client.post("/api/scopes/bulk", json={"items": [{"cidr": "127.0.0.0/30"}]}, headers=h).json()[0]
    assert again["created"] is False and again["scope_id"] == ok["scope_id"]


def test_bulk_permissions(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "op", "operator")
    client = make_client()
    _fake(client, [])
    csrf = login(client, "op", STRONG_PASSWORD)
    assert client.get("/api/scopes/candidates").status_code == 403  # operators cannot define scopes
    assert client.post("/api/scopes/bulk", json={"items": [{"cidr": "127.0.0.1/32"}]}, headers={"X-CSRF-Token": csrf}).status_code == 403
