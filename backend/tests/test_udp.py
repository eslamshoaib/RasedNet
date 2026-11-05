"""Active UDP probing: probe builders, live loopback open/closed, and the scope-enforced API."""

from __future__ import annotations

import asyncio

from rased.discovery.udp import (
    UDP_PROBES,
    dns_query,
    mdns_query,
    ntp_client_request,
    probe_port,
    scan_host,
    snmp_get_sysdescr,
    tftp_rrq,
)
from rased.models import Asset, utcnow
from tests.conftest import login, make_user


def h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def test_probe_builders_are_well_formed():
    s = snmp_get_sysdescr()
    assert s[0] == 0x30 and b"public" in s           # SNMP SEQUENCE + community
    assert ntp_client_request()[0] == 0x1B and len(ntp_client_request()) == 48
    assert mdns_query()[-4:] == b"\x00\x0c\x00\x01"   # PTR / IN
    assert tftp_rrq()[:2] == b"\x00\x01"              # RRQ opcode
    assert dns_query()[:2] == b"\x1a\x2b"             # fixed query id
    assert set(UDP_PROBES) >= {53, 123, 137, 161, 1900, 5353}


def test_probe_open_against_loopback_responder():
    async def run() -> str:
        loop = asyncio.get_running_loop()

        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):  # type: ignore[no-untyped-def]
                self.t = transport

            def datagram_received(self, data, addr):  # type: ignore[no-untyped-def]
                self.t.sendto(data, addr)

        transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        port = transport.get_extra_info("socket").getsockname()[1]
        try:
            return await probe_port("127.0.0.1", port, b"hello", timeout=2.0)
        finally:
            transport.close()

    assert asyncio.run(run()) == "open"  # a responder → open


def test_probe_silent_port_is_not_reported_open():
    # Nothing listening on a high loopback port: closed (ICMP) or filtered — never 'open'.
    state = asyncio.run(probe_port("127.0.0.1", 59321, b"x", timeout=1.0))
    assert state in ("closed", "filtered")


def test_scan_host_only_probes_known_ports():
    results = asyncio.run(scan_host("127.0.0.1", [161, 12345], timeout=0.5))  # 12345 has no probe → skipped
    assert {r.port for r in results} == {161}
    assert all(r.state in ("open", "closed", "filtered") for r in results)


def test_udp_scan_api_requires_approved_scope(make_client, db):
    make_user(db, "admin", "admin")
    now = utcnow()
    with db.session() as s:
        in_scope = Asset(current_ip="127.0.0.1", status="online", device_type="server", first_seen=now, last_seen=now)
        out_scope = Asset(current_ip="8.8.8.8", status="online", device_type="server", first_seen=now, last_seen=now)
        s.add_all([in_scope, out_scope])
        s.flush()
        in_id, out_id = in_scope.id, out_scope.id
    client = make_client()
    csrf = login(client, "admin")
    sid = client.post("/api/scopes", json={"name": "lo", "cidr": "127.0.0.1/32"}, headers=h(csrf)).json()["id"]
    client.post(f"/api/scopes/{sid}/approve", json={"confirm": True}, headers=h(csrf))

    # Out-of-scope target is refused.
    assert client.post(f"/api/assets/{out_id}/udp-scan", json={}, headers=h(csrf)).status_code == 403
    # In-scope target runs (nothing is listening, so 0 open — and never a false positive).
    r = client.post(f"/api/assets/{in_id}/udp-scan", json={"ports": [161], "timeout": 0.5}, headers=h(csrf))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["open"] == 0 and body["results"][0]["port"] == 161
