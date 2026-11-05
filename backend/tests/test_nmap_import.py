"""Nmap XML parsing (safe), and importing hosts/services into the inventory."""

from __future__ import annotations

import sqlalchemy as sa
import pytest

from rased.models import Asset, Service, utcnow
from rased.nmap_import import NmapImportError, import_hosts, parse_nmap_xml
from tests.conftest import login, make_user

SAMPLE = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.50" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="Dell Inc."/>
    <hostnames><hostname name="web01.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.51" addrtype="ipv4"/>
  </host>
</nmaprun>"""


def test_parse_nmap_xml_extracts_open_ports_only():
    hosts = parse_nmap_xml(SAMPLE)
    # Both hosts parse (the 'down' host is only skipped at import time, not parse time).
    assert len(hosts) == 2
    h = next(x for x in hosts if x.ip == "10.0.0.50")
    assert h.up is True
    assert not next(x for x in hosts if x.ip == "10.0.0.51").up
    assert h.mac == "AA:BB:CC:DD:EE:01"
    assert h.vendor == "Dell Inc."
    assert h.hostname == "web01.local"
    ports = {p.port: p for p in h.ports}
    assert set(ports) == {22, 443}  # the closed port 23 is excluded
    assert ports[22].product == "OpenSSH" and ports[22].version == "8.9"


def test_parse_rejects_non_nmap_and_malformed():
    with pytest.raises(NmapImportError):
        parse_nmap_xml("<html><body>nope</body></html>")
    with pytest.raises(NmapImportError):
        parse_nmap_xml("not xml at all <<<")


def test_parse_is_safe_against_xxe():
    # An external-entity payload must not be expanded (defusedxml raises).
    xxe = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           '<nmaprun><host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/>'
           '<ports><port protocol="tcp" portid="80"><state state="open"/>'
           '<service name="&x;"/></port></ports></host></nmaprun>')
    with pytest.raises(NmapImportError):
        parse_nmap_xml(xxe)


def test_import_hosts_creates_and_updates(db):
    now = utcnow()
    with db.session() as s:
        # Pre-existing asset with a banner-identified service that must NOT be clobbered.
        a = Asset(current_ip="10.0.0.50", status="unknown", device_type="computer", first_seen=now, last_seen=now)
        s.add(a)
        s.flush()
        s.add(Service(asset_id=a.id, port=443, protocol="tcp", state="open", service_name="https",
                      product="nginx", identification_method="banner", first_seen=now, last_seen=now))
        s.flush()

    hosts = parse_nmap_xml(SAMPLE)
    with db.session() as s:
        stats = import_hosts(s, hosts)
        s.commit()
    assert stats["hosts"] == 2  # parsed; the down host is skipped during import
    assert stats["assets_new"] == 0 and stats["assets_updated"] == 1
    assert stats["services_new"] == 1  # ssh added; https already existed

    with db.session() as s:
        a = s.scalar(sa.select(Asset).where(Asset.current_ip == "10.0.0.50"))
        assert a.status == "online"
        assert a.hostname == "web01.local"
        assert "nmap_import" in a.discovery_methods
        svcs = {x.port: x for x in a.services}
        assert svcs[22].service_name == "ssh" and svcs[22].identification_method == "import"
        # The banner-confirmed https identity is preserved (not overwritten by the import).
        assert svcs[443].product == "nginx" and svcs[443].identification_method == "banner"


def test_import_api_requires_scan_run(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "auditor", "auditor")
    client = make_client()
    csrf = login(client, "admin")
    r = client.post("/api/imports/nmap", content=SAMPLE,
                    headers={"X-CSRF-Token": csrf, "Content-Type": "application/xml"})
    assert r.status_code == 200, r.text
    assert r.json()["assets_new"] >= 1

    aud = make_client()
    aud_csrf = login(aud, "auditor")
    assert aud.post("/api/imports/nmap", content=SAMPLE,
                    headers={"X-CSRF-Token": aud_csrf, "Content-Type": "application/xml"}).status_code == 403
