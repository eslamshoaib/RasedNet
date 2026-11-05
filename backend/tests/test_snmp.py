"""SNMP physical-topology parsing (LLDP / CDP / FDB) and link resolution/storage."""

from __future__ import annotations

from rased.models import Asset, PhysicalLink, utcnow
from rased.physical import physical_graph, resolve_and_store
from rased.snmp import (
    CDP_DEVICEID,
    CDP_DEVICEPORT,
    DOT1D_BASEPORT_IFINDEX,
    DOT1D_FDB_PORT,
    IF_NAME,
    LLDP_LOC_PORTID,
    LLDP_REM_CHASSIS,
    LLDP_REM_PORTID,
    LLDP_REM_SYSNAME,
    as_mac,
    dedupe,
    parse_baseport_ifindex,
    parse_cdp,
    parse_fdb,
    parse_ifnames,
    parse_lldp,
)


def test_target_from_secret_v2c_and_v3():
    from rased.api.snmp import _target_from_secret
    import json as _json
    v2 = _target_from_secret("10.0.0.1", 161, "public")
    assert v2.version == "v2c" and v2.community == "public"
    blob = _json.dumps({"version": "v3", "user": "u", "auth_key": "ak", "auth_proto": "sha",
                        "priv_key": "pk", "priv_proto": "aes"})
    v3 = _target_from_secret("10.0.0.1", 161, blob)
    assert v3.version == "v3" and v3.v3_user == "u" and v3.v3_priv_proto == "aes"


def test_as_mac_formats_six_octets():
    assert as_mac(b"\xaa\xbb\xcc\xdd\xee\xff") == "AA:BB:CC:DD:EE:FF"
    assert as_mac("0.1.2.3.4.5") == "00:01:02:03:04:05"
    assert as_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"
    assert as_mac(b"hello-world") != ""  # non-MAC falls back to text, not crash


def test_parse_lldp_maps_local_port_and_neighbour():
    walk = {
        f"{LLDP_LOC_PORTID}.5": b"Gi0/5",
        f"{LLDP_REM_CHASSIS}.0.5.1": b"\x00\x11\x22\x33\x44\x55",
        f"{LLDP_REM_PORTID}.0.5.1": b"Gi0/1",
        f"{LLDP_REM_SYSNAME}.0.5.1": b"core-switch",
    }
    [n] = parse_lldp(walk)
    assert n["source"] == "lldp"
    assert n["local_port"] == "Gi0/5"
    assert n["remote_chassis_id"] == "00:11:22:33:44:55"
    assert n["remote_port"] == "Gi0/1"
    assert n["remote_sysname"] == "core-switch"


def test_parse_cdp_uses_ifname():
    ifnames = parse_ifnames({f"{IF_NAME}.10": b"GigabitEthernet0/10"}, {})
    walk = {f"{CDP_DEVICEID}.10.1": b"AP-1.local", f"{CDP_DEVICEPORT}.10.1": b"Gig0"}
    [n] = parse_cdp(walk, ifnames)
    assert n["source"] == "cdp"
    assert n["local_port"] == "GigabitEthernet0/10"
    assert n["remote_sysname"] == "AP-1.local"


def test_parse_fdb_resolves_bridge_port_to_ifname():
    ifnames = {"3": "Gi0/3"}
    baseport = parse_baseport_ifindex({f"{DOT1D_BASEPORT_IFINDEX}.7": 3})
    assert baseport == {"7": "3"}
    walk = {f"{DOT1D_FDB_PORT}.0.17.34.51.68.85": 7}  # MAC 00:11:22:33:44:55 on bridge port 7
    [n] = parse_fdb(walk, baseport, ifnames)
    assert n["source"] == "fdb"
    assert n["local_port"] == "Gi0/3"
    assert n["remote_chassis_id"] == "00:11:22:33:44:55"


def test_dedupe_drops_empty_and_duplicates():
    rows = [
        {"local_port": "1", "remote_chassis_id": "AA", "remote_port": "x", "source": "lldp", "remote_sysname": ""},
        {"local_port": "1", "remote_chassis_id": "AA", "remote_port": "x", "source": "lldp", "remote_sysname": ""},
        {"local_port": "2", "remote_chassis_id": "", "remote_port": "", "source": "fdb", "remote_sysname": ""},
    ]
    out = dedupe(rows)
    assert len(out) == 1  # one duplicate removed, one empty neighbour dropped


def test_resolve_and_store_links_to_known_asset_by_mac(db):
    now = utcnow()
    with db.session() as s:
        sw = Asset(current_ip="10.0.0.1", status="online", device_type="switch", first_seen=now, last_seen=now)
        host = Asset(current_ip="10.0.0.9", mac="00:11:22:33:44:55", status="online", device_type="computer",
                     first_seen=now, last_seen=now)
        s.add_all([sw, host])
        s.flush()
        sw_id, host_id = sw.id, host.id

    neighbours = [
        {"source": "lldp", "local_port": "Gi0/5", "remote_chassis_id": "00:11:22:33:44:55",
         "remote_port": "eth0", "remote_sysname": "pc1", "remote_descr": ""},
        {"source": "lldp", "local_port": "Gi0/6", "remote_chassis_id": "AA:BB:CC:00:00:01",
         "remote_port": "", "remote_sysname": "unknown-ap", "remote_descr": "AP"},
    ]
    with db.session() as s:
        stats = resolve_and_store(s, sw_id, neighbours)
        s.commit()
    assert stats == {"added": 2, "updated": 0, "resolved": 1, "total": 2}

    with db.session() as s:
        links = list(s.scalars(__import__("sqlalchemy").select(PhysicalLink)))
        resolved = {link.local_port: link.remote_asset_id for link in links}
        assert resolved["Gi0/5"] == host_id   # resolved to the known PC by MAC
        assert resolved["Gi0/6"] is None       # unknown neighbour stays unresolved
        graph = physical_graph(s)
    assert graph["stats"]["links"] == 2
    assert graph["stats"]["resolved"] == 1
    assert any(n["kind"] == "external" for n in graph["nodes"])  # the unknown AP is an external node


def test_snmp_enterprise_and_classify():
    from rased.snmp import snmp_enterprise, classify_snmp
    assert snmp_enterprise("1.3.6.1.4.1.14988.1.2") == 14988
    assert snmp_enterprise("1.3.6.1.2.1.1") is None
    mt = classify_snmp("RouterOS CCR", "1.3.6.1.4.1.14988.1")
    assert mt["vendor"] == "MikroTik" and mt["device_type"] == "router" and mt["os_family"] == "network_os"
    pr = classify_snmp("HP JETDIRECT", "1.3.6.1.4.1.11.2")
    assert pr["device_type"] == "printer"
    lx = classify_snmp("Linux srv 6.1", "1.3.6.1.4.1.8072.3")
    assert lx["os_family"] == "linux"
    assert classify_snmp("", "") == {}
