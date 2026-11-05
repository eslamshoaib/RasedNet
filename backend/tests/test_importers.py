"""Offline import adapters: DHCP leases, device CSV, Greenbone/OpenVAS report."""

from __future__ import annotations

import sqlalchemy as sa

from rased.importers import (
    ImportError_,
    csv_import,
    dhcp_import,
    greenbone_import,
    parse_device_csv,
    parse_dhcp_leases,
    parse_greenbone_xml,
    parse_nessus_xml,
    nessus_import,
    wazuh_import,
    osquery_import,
    upsert_records,
    HostRecord,
)
from rased.models import Asset, AssetVulnerability, CveEntry, Service, utcnow
from tests.conftest import login, make_user

DNSMASQ = """1699999999 aa:bb:cc:dd:ee:01 10.0.0.21 laptop-1 01:aa:bb:cc:dd:ee:01
1699999999 aa:bb:cc:dd:ee:02 10.0.0.22 * 01:aa:bb:cc:dd:ee:02
"""

ISC = """
lease 10.0.0.31 {
  starts 4 2026/01/01 00:00:00;
  hardware ethernet aa:bb:cc:dd:ee:31;
  client-hostname "printer-a";
}
lease 10.0.0.32 {
  hardware ethernet aa:bb:cc:dd:ee:32;
}
"""


def test_parse_dnsmasq_and_isc():
    dm = parse_dhcp_leases(DNSMASQ)
    assert {r.ip for r in dm} == {"10.0.0.21", "10.0.0.22"}
    assert dm[0].hostname == "laptop-1" and dm[1].hostname is None  # '*' → no hostname
    isc = parse_dhcp_leases(ISC)
    assert {r.ip for r in isc} == {"10.0.0.31", "10.0.0.32"}
    assert next(r for r in isc if r.ip == "10.0.0.31").hostname == "printer-a"


def test_parse_device_csv_flexible_headers():
    text = "IP Address,MAC,Device Name,Type,OS\n10.0.0.41,AA-BB-CC-DD-EE-41,ap-lobby,access_point,network_os\n,,norow,,\n"
    recs = parse_device_csv(text)
    assert len(recs) == 1
    assert recs[0].ip == "10.0.0.41" and recs[0].device_type == "access_point"


def test_csv_requires_ip_or_mac_column():
    try:
        parse_device_csv("name,os\nfoo,linux\n")
        assert False, "expected ImportError_"
    except ImportError_:
        pass


def test_upsert_records_creates_and_sets_type(db):
    with db.session() as s:
        stats = upsert_records(s, [
            HostRecord(ip="10.0.0.41", mac="AA:BB:CC:DD:EE:41", hostname="ap-lobby", device_type="access_point"),
        ], source="csv_import")
        s.commit()
    assert stats["assets_new"] == 1
    with db.session() as s:
        a = s.scalar(sa.select(Asset).where(Asset.current_ip == "10.0.0.41"))
        assert a.device_type == "access_point" and a.hostname == "ap-lobby"
        assert "csv_import" in a.discovery_methods


GREENBONE = """<?xml version="1.0"?>
<report>
  <results>
    <result>
      <host>10.0.0.50</host>
      <port>22/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.1">
        <name>OpenSSH &lt; 8.0 vulnerability</name>
        <cvss_base>9.8</cvss_base>
        <refs><ref type="cve" id="CVE-2023-9999"/></refs>
      </nvt>
    </result>
    <result>
      <host>10.0.0.99</host>
      <nvt oid="x"><name>Unmatched host finding</name><cvss_base>5.0</cvss_base></nvt>
    </result>
  </results>
</report>"""


def test_parse_greenbone():
    res = parse_greenbone_xml(GREENBONE)
    assert len(res) == 2
    r = next(x for x in res if x.ip == "10.0.0.50")
    assert r.cve_ids == ["CVE-2023-9999"] and r.cvss == 9.8


def test_greenbone_import_links_to_known_assets(db):
    now = utcnow()
    with db.session() as s:
        s.add(Asset(current_ip="10.0.0.50", status="online", device_type="server", first_seen=now, last_seen=now))
        s.commit()
    with db.session() as s:
        stats = greenbone_import(s, GREENBONE)
        s.commit()
    assert stats["matched_assets"] == 1 and stats["unmatched"] == 1
    assert stats["findings"] == 1 and stats["cve_added"] == 1
    with db.session() as s:
        v = s.scalar(sa.select(AssetVulnerability))
        assert v.cve_id == "CVE-2023-9999" and v.severity == "critical"
        assert s.scalar(sa.select(CveEntry).where(CveEntry.cve_id == "CVE-2023-9999")) is not None


def test_import_api_endpoints(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "auditor", "auditor")
    now = utcnow()
    with db.session() as s:
        s.add(Asset(current_ip="10.0.0.50", status="online", device_type="server", first_seen=now, last_seen=now))
        s.commit()
    client = make_client()
    csrf = login(client, "admin")
    hdr = {"X-CSRF-Token": csrf, "Content-Type": "text/plain"}
    assert client.post("/api/imports/dhcp", content=DNSMASQ, headers=hdr).json()["assets_new"] == 2
    assert client.post("/api/imports/csv", content="ip,mac\n10.0.0.60,AA:BB:CC:DD:EE:60\n", headers=hdr).json()["assets_new"] == 1
    gb = client.post("/api/imports/greenbone", content=GREENBONE, headers={"X-CSRF-Token": csrf, "Content-Type": "application/xml"})
    assert gb.status_code == 200 and gb.json()["findings"] == 1

    # Auditor lacks scan:run.
    aud = make_client()
    ac = login(aud, "auditor")
    assert aud.post("/api/imports/dhcp", content=DNSMASQ, headers={"X-CSRF-Token": ac, "Content-Type": "text/plain"}).status_code == 403


NESSUS = """<?xml version="1.0"?>
<NessusClientData_v2><Report name="r">
  <ReportHost name="10.0.0.50">
    <HostProperties><tag name="host-ip">10.0.0.50</tag></HostProperties>
    <ReportItem port="443" protocol="tcp" severity="4" pluginName="TLS vuln">
      <cve>CVE-2024-1234</cve><cvss_base_score>7.5</cvss_base_score>
    </ReportItem>
    <ReportItem port="0" protocol="tcp" severity="0" pluginName="info only"></ReportItem>
  </ReportHost>
</Report></NessusClientData_v2>"""

WAZUH = {"data": {"affected_items": [
    {"agent": {"ip": "10.0.0.50"}, "cve": "CVE-2024-5678", "cvss3_score": 9.1, "title": "kernel flaw", "package": "linux"},
    {"agent": {"ip": "10.9.9.9"}, "cve": "CVE-2024-0000", "cvss3_score": 5.0, "title": "unmatched"},
]}}

OSQUERY = [
    {"hostname": "oq-host", "address": "10.0.0.61", "mac": "AA:BB:CC:DD:EE:61", "platform": "linux"},
    {"address": "not-an-ip"},
]


def test_parse_nessus_skips_info_and_reads_cve():
    res = parse_nessus_xml(NESSUS)
    assert len(res) == 1  # the severity-0 item is dropped
    assert res[0].ip == "10.0.0.50" and res[0].cve_ids == ["CVE-2024-1234"] and res[0].cvss == 7.5


def test_nessus_and_wazuh_import_link_to_assets(db):
    now = utcnow()
    with db.session() as s:
        s.add(Asset(current_ip="10.0.0.50", status="online", device_type="server", first_seen=now, last_seen=now))
        s.commit()
    with db.session() as s:
        n = nessus_import(s, NESSUS)
        w = wazuh_import(s, WAZUH)
        s.commit()
    assert n["findings"] == 1 and n["unmatched"] == 0
    assert w["findings"] == 1 and w["unmatched"] == 1  # 10.9.9.9 not in inventory
    with db.session() as s:
        cves = {v.cve_id for v in s.scalars(sa.select(AssetVulnerability))}
        assert {"CVE-2024-1234", "CVE-2024-5678"} <= cves


def test_osquery_import_creates_assets(db):
    with db.session() as s:
        stats = osquery_import(s, OSQUERY)
        s.commit()
    assert stats["assets_new"] == 1  # the invalid row is skipped
    with db.session() as s:
        a = s.scalar(sa.select(Asset).where(Asset.current_ip == "10.0.0.61"))
        assert a.hostname == "oq-host" and "osquery_import" in a.discovery_methods
