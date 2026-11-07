"""Physical (layer-2) topology discovery over SNMP — authenticated, read-only.

With a vaulted SNMP account (v2c community, or v3 user) RasedNet *reads* standard MIBs from a
switch/router and reconstructs how things are physically wired:

* **LLDP-MIB** (``lldpRemTable``) — the neighbour each local port sees (vendor-neutral).
* **CISCO-CDP-MIB** (``cdpCacheTable``) — the Cisco equivalent.
* **BRIDGE-MIB** forwarding table (``dot1dTpFdbTable``) — which MAC is learned on which port.

Everything here is a read (SNMP GET/WALK). RasedNet never issues an SNMP SET, never changes the
device, and uses only the account the operator stored in the vault.

The parsing is pure (walked OID→value maps → structured neighbours), so it is unit-tested
without a live device; the thin ``collect`` layer performs the actual walks.
"""

from __future__ import annotations
from rasednet.i18n import get_lang, tr

import binascii
from dataclasses import dataclass
from typing import Any

# --- OIDs --------------------------------------------------------------------------------

OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"

# SNMP enterprise number (the N in 1.3.6.1.4.1.N.*) → (vendor, device-type hint).
ENTERPRISE_VENDORS: dict[int, tuple[str, str]] = {
    9: ("Cisco", "network_device"), 2636: ("Juniper", "network_device"), 14988: ("MikroTik", "router"),
    11: ("HP/HPE", "network_device"), 2011: ("Huawei", "network_device"), 25506: ("H3C", "network_device"),
    1916: ("Extreme Networks", "switch"), 1991: ("Brocade/Foundry", "switch"), 6027: ("Dell/Force10", "switch"),
    674: ("Dell", "server"), 171: ("D-Link", "network_device"), 890: ("Zyxel", "network_device"),
    11863: ("TP-Link", "router"), 4526: ("Netgear", "network_device"), 41112: ("Ubiquiti", "access_point"),
    3375: ("F5 Networks", "network_device"), 12356: ("Fortinet", "network_device"), 25461: ("Palo Alto", "network_device"),
    8072: ("net-snmp (Linux/Unix)", "server"), 311: ("Microsoft", "server"), 2: ("IBM", "server"),
    2435: ("Brother", "printer"), 1602: ("Canon", "printer"), 1248: ("Epson", "printer"), 641: ("Lexmark", "printer"),
    367: ("Ricoh", "printer"), 236: ("Samsung", "printer"), 18334: ("Konica Minolta", "printer"),
    4874: ("Synology", "nas"), 24681: ("QNAP", "nas"), 23695: ("Dahua", "camera"), 39165: ("Hikvision", "camera"),
}


def snmp_enterprise(sys_object_id: str) -> int | None:
    """Extract the enterprise number N from a sysObjectID like 1.3.6.1.4.1.N.x.y."""
    parts = (sys_object_id or "").strip().lstrip(".").split(".")
    if len(parts) >= 7 and parts[:6] == ["1", "3", "6", "1", "4", "1"]:
        try:
            return int(parts[6])
        except ValueError:
            return None
    return None


def classify_snmp(sys_descr: str, sys_object_id: str) -> dict[str, Any]:
    """Identify vendor / device type / OS from SNMP system info. Empty dict if inconclusive."""
    text = (sys_descr or "").lower()
    out: dict[str, Any] = {}
    ent = snmp_enterprise(sys_object_id)
    if ent in ENTERPRISE_VENDORS:
        vendor, dtype = ENTERPRISE_VENDORS[ent]
        out["vendor"] = vendor
        out["device_type"] = dtype
        out["confidence"] = 0.85
    # sysDescr keywords refine/override the device type and OS.
    if any(k in text for k in ("router", "routeros", "ios", "junos", "switch", "ethernet switch")):
        out.setdefault("device_type", "network_device")
        if "switch" in text:
            out["device_type"] = "switch"
        elif "router" in text or "routeros" in text:
            out["device_type"] = "router"
        out["os_family"] = "network_os"
    if "printer" in text or "jetdirect" in text or "laserjet" in text:
        out["device_type"] = "printer"
    if "windows" in text:
        out["os_family"] = "windows"
    elif "linux" in text:
        out["os_family"] = "linux"
    if out:
        out.setdefault("confidence", 0.6)
    return out

# LLDP-MIB
LLDP_LOC_PORTID = "1.0.8802.1.1.2.1.3.7.1.3"       # index: localPortNum
LLDP_REM_CHASSIS = "1.0.8802.1.1.2.1.4.1.1.5"      # index: timeMark.localPortNum.remIndex
LLDP_REM_PORTID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORTDESC = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYSDESC = "1.0.8802.1.1.2.1.4.1.1.10"

# CISCO-CDP-MIB cdpCacheTable (index: ifIndex.deviceIndex)
CDP_DEVICEID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_DEVICEPORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

# IF-MIB
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"                 # index: ifIndex
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"                   # index: ifIndex

# BRIDGE-MIB forwarding database
DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"          # index: 6 MAC octets → bridge port
DOT1D_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # index: bridge port → ifIndex


class SnmpError(Exception):
    """Arabic, user-facing SNMP failure message."""


@dataclass(frozen=True)
class SnmpTarget:
    host: str
    port: int = 161
    version: str = "v2c"            # v2c | v3
    community: str = "public"
    # v3 (optional)
    v3_user: str = ""
    v3_auth_key: str = ""
    v3_auth_proto: str = "sha"      # md5 | sha
    v3_priv_key: str = ""
    v3_priv_proto: str = "aes"      # des | aes


# --- helpers -----------------------------------------------------------------------------


def _suffix(oid: str, base: str) -> str | None:
    """Index portion of ``oid`` under ``base`` (``base.1.2`` under ``base`` → ``1.2``)."""
    if oid == base:
        return ""
    if oid.startswith(base + "."):
        return oid[len(base) + 1:]
    return None


def rows(walk: dict[str, Any], base: str) -> dict[str, Any]:
    """Collapse a flat ``{oid: value}`` walk into ``{index_suffix: value}`` for one table column."""
    out: dict[str, Any] = {}
    for oid, value in walk.items():
        idx = _suffix(str(oid), base)
        if idx is not None:
            out[idx] = value
    return out


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "replace").strip("\x00").strip()
        except Exception:  # pragma: no cover - defensive
            return value.hex()
    return str(value).strip()


def as_mac(value: Any) -> str:
    """Format a chassis-id / FDB key as a colon MAC when it is six octets, else hex/text."""
    raw: bytes | None = None
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        parts = value.split(".")
        if parts and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts) and len(parts) == 6:
            raw = bytes(int(p) for p in parts)
        else:
            try:
                raw = binascii.unhexlify(value.replace(":", "").replace("-", ""))
            except (binascii.Error, ValueError):
                raw = None
    if raw and len(raw) == 6:
        return ":".join(f"{b:02X}" for b in raw)
    return as_text(value)


# --- pure parsers ------------------------------------------------------------------------


def parse_lldp(walk: dict[str, Any]) -> list[dict[str, Any]]:
    """LLDP neighbours: one entry per (local port, remote device)."""
    loc = {idx: as_text(v) for idx, v in rows(walk, LLDP_LOC_PORTID).items()}
    chassis = rows(walk, LLDP_REM_CHASSIS)
    portid = rows(walk, LLDP_REM_PORTID)
    portdesc = rows(walk, LLDP_REM_PORTDESC)
    sysname = rows(walk, LLDP_REM_SYSNAME)
    sysdesc = rows(walk, LLDP_REM_SYSDESC)
    out: list[dict[str, Any]] = []
    for index, chassis_val in chassis.items():
        parts = index.split(".")
        local_port_num = parts[1] if len(parts) >= 2 else (parts[0] if parts else "")
        out.append({
            "source": "lldp",
            "local_port": loc.get(local_port_num, local_port_num),
            "remote_chassis_id": as_mac(chassis_val),
            "remote_port": as_text(portid.get(index)) or as_text(portdesc.get(index)),
            "remote_sysname": as_text(sysname.get(index)),
            "remote_descr": as_text(sysdesc.get(index)),
        })
    return out


def parse_cdp(walk: dict[str, Any], ifnames: dict[str, str]) -> list[dict[str, Any]]:
    device = rows(walk, CDP_DEVICEID)
    port = rows(walk, CDP_DEVICEPORT)
    platform = rows(walk, CDP_PLATFORM)
    out: list[dict[str, Any]] = []
    for index, dev in device.items():
        if_index = index.split(".")[0] if index else ""
        out.append({
            "source": "cdp",
            "local_port": ifnames.get(if_index, if_index),
            "remote_chassis_id": "",
            "remote_sysname": as_text(dev),
            "remote_port": as_text(port.get(index)),
            "remote_descr": as_text(platform.get(index)),
        })
    return out


def parse_fdb(walk: dict[str, Any], baseport_ifindex: dict[str, str], ifnames: dict[str, str]) -> list[dict[str, Any]]:
    """Forwarding-database: which MAC is learned on which physical port."""
    fdb = rows(walk, DOT1D_FDB_PORT)
    out: list[dict[str, Any]] = []
    for mac_index, bridge_port in fdb.items():
        bp = as_text(bridge_port)
        if_index = baseport_ifindex.get(bp, bp)
        out.append({
            "source": "fdb",
            "local_port": ifnames.get(if_index, bp),
            "remote_chassis_id": as_mac(mac_index),
            "remote_sysname": "",
            "remote_port": "",
            "remote_descr": "",
        })
    return out


def parse_ifnames(name_walk: dict[str, Any], descr_walk: dict[str, Any]) -> dict[str, str]:
    names = {idx: as_text(v) for idx, v in rows(name_walk, IF_NAME).items()}
    for idx, v in rows(descr_walk, IF_DESCR).items():
        names.setdefault(idx, as_text(v))
    return names


def parse_baseport_ifindex(walk: dict[str, Any]) -> dict[str, str]:
    return {idx: as_text(v) for idx, v in rows(walk, DOT1D_BASEPORT_IFINDEX).items()}


def dedupe(neighbours: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop empty-neighbour rows and collapse duplicates by (local_port, chassis, remote_port, source)."""
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for n in neighbours:
        if not (n.get("remote_chassis_id") or n.get("remote_sysname")):
            continue
        key = (n["local_port"], n.get("remote_chassis_id", ""), n.get("remote_port", ""), n["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# --- live collection (puresnmp) ----------------------------------------------------------


async def _walk_all(client: Any, oid: str, limit: int = 20000) -> dict[str, Any]:
    out: dict[str, Any] = {}
    async for vb in client.walk(oid):
        out[str(vb.oid)] = vb.value
        if len(out) >= limit:
            break
    return out


def _client(target: SnmpTarget) -> Any:
    from puresnmp import V2C, V3, Auth, Client, Priv, PyWrapper

    if target.version == "v3":
        if not target.v3_user:
            raise SnmpError(tr("حساب SNMPv3 يتطلب اسم مستخدم.", "An SNMPv3 account requires a username."))
        auth = Auth(target.v3_auth_key.encode(), target.v3_auth_proto) if target.v3_auth_key else None
        priv = Priv(target.v3_priv_key.encode(), target.v3_priv_proto) if target.v3_priv_key else None
        creds: Any = V3(target.v3_user, auth=auth, priv=priv)
    else:
        creds = V2C(target.community)
    return PyWrapper(Client(target.host, creds, port=target.port))


async def collect(target: SnmpTarget, *, include_fdb: bool = True) -> dict[str, Any]:
    """Walk the relevant MIBs and return system info + de-duplicated physical neighbours."""
    try:
        client = _client(target)
        sys_name = as_text(await client.get(OID_SYSNAME))
        sys_descr = as_text(await client.get(OID_SYSDESCR))
        try:
            sys_object_id = as_text(await client.get(OID_SYSOBJECTID))
        except Exception:  # noqa: BLE001 - optional OID
            sys_object_id = ""
        ifnames = parse_ifnames(await _walk_all(client, IF_NAME), await _walk_all(client, IF_DESCR))
        lldp = parse_lldp(await _walk_all(client, "1.0.8802.1.1.2.1"))
        cdp = parse_cdp(await _walk_all(client, "1.3.6.1.4.1.9.9.23.1.2.1.1"), ifnames)
        fdb: list[dict[str, Any]] = []
        if include_fdb:
            baseport = parse_baseport_ifindex(await _walk_all(client, DOT1D_BASEPORT_IFINDEX))
            fdb = parse_fdb(await _walk_all(client, DOT1D_FDB_PORT), baseport, ifnames)
    except SnmpError:
        raise
    except Exception as exc:  # puresnmp raises various transport/timeout errors
        raise SnmpError((f"Could not connect to the device over SNMP or read its data: {exc}" if get_lang()=="en" else f"تعذر الاتصال بالجهاز عبر SNMP أو قراءة بياناته: {exc}")) from exc

    neighbours = dedupe(lldp + cdp + fdb)
    return {
        "sys_name": sys_name,
        "sys_descr": sys_descr,
        "sys_object_id": sys_object_id,
        "identity": classify_snmp(sys_descr, sys_object_id),
        "neighbours": neighbours,
        "counts": {"lldp": len(lldp), "cdp": len(cdp), "fdb": len(fdb), "total": len(neighbours)},
    }
