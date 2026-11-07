"""Offline import adapters: DHCP leases, generic device CSV, and Greenbone/OpenVAS reports.

All adapters parse a file the operator already has and upsert the result into the inventory —
no scanning or network activity. Parsing is pure (functions over text/bytes) so it is unit-
tested without any external system; the ``*_import`` helpers do the database upsert.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from defusedxml import ElementTree as DET
from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.cve import severity_from_cvss
from rasednet.models import Asset, AssetVulnerability, CveEntry, Event, utcnow
from rasednet.text import sanitize_banner
from rasednet.i18n import get_lang, tr

DEVICE_TYPES = {
    "router", "access_point", "switch", "network_device", "server", "computer", "mobile", "tablet",
    "printer", "camera", "tv", "nas", "iot", "virtual_machine", "hypervisor", "unknown",
}


class ImportError_(Exception):
    """Arabic, user-facing import error."""


@dataclass
class HostRecord:
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    os_family: str | None = None
    note: str | None = None


def _clean(value: str | None, limit: int = 128) -> str | None:
    if not value:
        return None
    out = sanitize_banner(value)[:limit].strip()
    return out or None


def _norm_mac(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip().upper().replace("-", ":")
    return v if re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", v) else None


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


# --- generic upsert ---------------------------------------------------------------------


def upsert_records(db: Session, records: list[HostRecord], source: str) -> dict[str, int]:
    """Upsert host records into assets. Matches by IP, else by MAC. Does not commit."""
    now = utcnow()
    by_ip = {a.current_ip: a for a in db.scalars(select(Asset)) if a.current_ip}
    by_mac = {a.mac.upper(): a for a in db.scalars(select(Asset)) if a.mac}
    stats = {"records": len(records), "assets_new": 0, "assets_updated": 0}
    for rec in records:
        ip = _valid_ip(rec.ip)
        mac = _norm_mac(rec.mac)
        if not ip and not mac:
            continue
        asset = (by_ip.get(ip) if ip else None) or (by_mac.get(mac) if mac else None)
        if asset is None:
            asset = Asset(current_ip=ip, status="unknown", first_seen=now, last_seen=now)
            db.add(asset)
            db.flush()
            if ip:
                by_ip[ip] = asset
            if mac:
                by_mac[mac] = asset
            stats["assets_new"] += 1
            db.add(Event(kind="asset_new", asset_id=asset.id, created_at=now,
                         message_ar=(f"New device from import ({source}): {ip or mac}" if get_lang()=="en" else f"جهاز جديد من استيراد ({source}): {ip or mac}"), details={"source": source}))
        else:
            stats["assets_updated"] += 1
        asset.last_seen = now
        if ip and not asset.current_ip:
            asset.current_ip = ip
        if mac and not asset.mac:
            asset.mac = mac
        if rec.hostname and not asset.hostname:
            asset.hostname = _clean(rec.hostname, 253)
        if rec.vendor and not asset.vendor:
            asset.vendor = _clean(rec.vendor, 256)
        if rec.device_type in DEVICE_TYPES and rec.device_type != "unknown" and asset.device_type == "unknown":
            asset.device_type = rec.device_type
        if rec.os_family and asset.os_family == "unknown":
            asset.os_family = _clean(rec.os_family, 32) or "unknown"
        asset.discovery_methods = sorted(set(asset.discovery_methods or []) | {source})
    db.flush()
    return stats


# --- DHCP leases ------------------------------------------------------------------------

_DNSMASQ_RE = re.compile(r"^\d+\s+([0-9a-fA-F:]{17})\s+(\S+)\s+(\S+)")


def parse_dhcp_leases(text: str) -> list[HostRecord]:
    """Parse ISC ``dhcpd.leases`` or dnsmasq ``dnsmasq.leases`` content."""
    records: list[HostRecord] = []
    # dnsmasq: "<expiry> <mac> <ip> <hostname> <clientid>" per line.
    dnsmasq_hits = 0
    for line in text.splitlines():
        m = _DNSMASQ_RE.match(line.strip())
        # dnsmasq fields: <expiry> <mac(1)> <ip(2)> <hostname(3)> <clientid>
        if m and _valid_ip(m.group(2)):
            dnsmasq_hits += 1
            host = m.group(3)
            records.append(HostRecord(ip=m.group(2), mac=m.group(1),
                                      hostname=None if host == "*" else host))
    if dnsmasq_hits:
        return records

    # ISC dhcpd: "lease <ip> { ... hardware ethernet <mac>; client-hostname \"x\"; }"
    current_ip: str | None = None
    rec: HostRecord | None = None
    for raw in text.splitlines():
        line = raw.strip()
        lm = re.match(r"^lease\s+(\S+)\s*\{", line)
        if lm:
            current_ip = _valid_ip(lm.group(1))
            rec = HostRecord(ip=current_ip) if current_ip else None
            continue
        if rec is None:
            continue
        hw = re.match(r"^hardware\s+ethernet\s+([0-9a-fA-F:]{17})", line)
        if hw:
            rec.mac = hw.group(1)
        ch = re.match(r'^client-hostname\s+"([^"]*)"', line)
        if ch:
            rec.hostname = ch.group(1)
        if line.startswith("}"):
            if rec and rec.ip:
                records.append(rec)
            rec = None
    return records


def dhcp_import(db: Session, text: str) -> dict[str, int]:
    records = parse_dhcp_leases(text)
    if not records:
        raise ImportError_(tr("لم يُعثر على حجوزات DHCP صالحة في الملف (صيغة ISC dhcpd أو dnsmasq).", "No valid DHCP leases found in the file (ISC dhcpd or dnsmasq format)."))
    return upsert_records(db, records, "dhcp_import")


# --- generic device CSV -----------------------------------------------------------------

_CSV_ALIASES = {
    "ip": "ip", "ip_address": "ip", "address": "ip", "عنوان": "ip",
    "mac": "mac", "mac_address": "mac", "hardware": "mac",
    "hostname": "hostname", "name": "hostname", "device": "hostname", "host": "hostname",
    "device_name": "hostname", "host_name": "hostname",
    "vendor": "vendor", "manufacturer": "vendor",
    "type": "device_type", "device_type": "device_type", "category": "device_type",
    "os": "os_family", "os_family": "os_family", "platform": "os_family", "operating_system": "os_family",
    "note": "note", "notes": "note",
}


def parse_device_csv(text: str) -> list[HostRecord]:
    """Parse a CSV export (wireless controller / MDM / spreadsheet). Flexible column names."""
    try:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ImportError_(tr("ملف CSV فارغ أو بلا ترويسة أعمدة.", "The CSV file is empty or has no column header."))
        colmap = {name: _CSV_ALIASES[name.strip().lower().replace(" ", "_")] for name in reader.fieldnames
                  if name and name.strip().lower().replace(" ", "_") in _CSV_ALIASES}
        if "ip" not in colmap.values() and "mac" not in colmap.values():
            raise ImportError_(tr("يجب أن يحتوي CSV على عمود عنوان IP أو MAC على الأقل.", "The CSV must contain at least an IP or MAC column."))
        records: list[HostRecord] = []
        for row in reader:
            rec = HostRecord()
            for src, dest in colmap.items():
                setattr(rec, dest, (row.get(src) or "").strip() or None)
            if rec.ip or rec.mac:
                records.append(rec)
        return records
    except ImportError_:
        raise
    except Exception as exc:  # malformed CSV
        raise ImportError_((f"Could not read the CSV file: {exc}" if get_lang()=="en" else f"تعذر قراءة ملف CSV: {exc}")) from exc


def csv_import(db: Session, text: str) -> dict[str, int]:
    records = parse_device_csv(text)
    if not records:
        raise ImportError_(tr("لا توجد صفوف صالحة (كل صف يحتاج IP أو MAC).", "No valid rows (each row needs an IP or MAC)."))
    return upsert_records(db, records, "csv_import")


# --- Greenbone / OpenVAS vulnerability report -------------------------------------------


@dataclass
class VulnResult:
    ip: str
    name: str
    cve_ids: list[str] = field(default_factory=list)
    cvss: float = 0.0
    port: str = ""
    summary: str = ""


def parse_greenbone_xml(data: bytes | str) -> list[VulnResult]:
    """Parse a Greenbone/OpenVAS XML report (``<report><results><result>…``). Safe (defusedxml)."""
    try:
        root = DET.fromstring(data.encode("utf-8") if isinstance(data, str) else data)
    except Exception as exc:
        raise ImportError_(tr("ملف Greenbone/OpenVAS XML غير صالح أو تالف.", "The Greenbone/OpenVAS XML file is invalid or corrupt.")) from exc
    results = root.iter("result")
    out: list[VulnResult] = []
    for r in results:
        host_el = r.find("host")
        ip = _valid_ip(host_el.text if host_el is not None else None)
        if not ip:
            continue
        nvt = r.find("nvt")
        name = ""
        cves: list[str] = []
        cvss = 0.0
        if nvt is not None:
            nm = nvt.find("name")
            name = _clean(nm.text if nm is not None else "", 256) or ""
            cvss_el = nvt.find("cvss_base")
            try:
                cvss = float(cvss_el.text) if cvss_el is not None and cvss_el.text else 0.0
            except (TypeError, ValueError):
                cvss = 0.0
            refs = nvt.find("refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    if (ref.get("type") or "").lower() == "cve":
                        cve = ref.get("id")
                        if cve:
                            cves.append(cve.strip())
        # Fallback: a <cve> element or threat-based score.
        if not cves:
            cve_el = r.find("cve")
            if cve_el is not None and cve_el.text and cve_el.text.upper().startswith("CVE"):
                cves = [cve_el.text.strip()]
        if cvss == 0.0:
            sev_el = r.find("severity")
            try:
                cvss = float(sev_el.text) if sev_el is not None and sev_el.text else 0.0
            except (TypeError, ValueError):
                cvss = 0.0
        port_el = r.find("port")
        out.append(VulnResult(ip=ip, name=name, cve_ids=cves, cvss=max(cvss, 0.0),
                              port=_clean(port_el.text if port_el is not None else "", 32) or "",
                              summary=name))
    return out


def store_vuln_results(db: Session, results: list[VulnResult], source: str, pseudo_prefix: str) -> dict[str, int]:
    """Shared: ensure CVE entries exist and link each result to a known asset (matched by IP)."""
    now = utcnow()
    by_ip = {a.current_ip: a for a in db.scalars(select(Asset)) if a.current_ip}
    cves = {c.cve_id: c for c in db.scalars(select(CveEntry))}
    existing = {(v.asset_id, v.cve_id): v for v in db.scalars(select(AssetVulnerability))}
    stats = {"results": len(results), "matched_assets": 0, "findings": 0, "unmatched": 0, "cve_added": 0}
    seen_assets: set[int] = set()
    for res in results:
        asset = by_ip.get(res.ip)
        if asset is None:
            stats["unmatched"] += 1
            continue
        if asset.id not in seen_assets:
            seen_assets.add(asset.id)
            stats["matched_assets"] += 1
        ids = res.cve_ids or [f"{pseudo_prefix}:{res.name[:40]}"]  # finding without a CVE → stable pseudo-id
        severity = severity_from_cvss(res.cvss)
        for cid in ids:
            entry = cves.get(cid)
            if entry is None:
                entry = CveEntry(cve_id=cid, description=res.summary, cvss_score=res.cvss, severity=severity,
                                 affected=[], references=[], imported_at=now)
                db.add(entry)
                cves[cid] = entry
                stats["cve_added"] += 1
            key = (asset.id, cid)
            row = existing.get(key)
            if row is None:
                row = AssetVulnerability(asset_id=asset.id, cve_id=cid, first_seen=now)
                db.add(row)
                existing[key] = row
            row.product = (res.port or source)[:128]
            row.matched_on = f"{source}: {res.name}"[:128]
            row.cvss_score = res.cvss
            row.severity = severity
            row.status = "open"
            row.last_seen = now
            stats["findings"] += 1
    db.flush()
    return stats


def greenbone_import(db: Session, data: bytes | str) -> dict[str, int]:
    """Import a Greenbone report: ensure CVE entries exist and link findings to known assets."""
    results = parse_greenbone_xml(data)
    if not results:
        raise ImportError_(tr("لا توجد نتائج في التقرير.", "No results in the report."))
    return store_vuln_results(db, results, "Greenbone", "GB")


# --- Nessus (.nessus) report ------------------------------------------------------------


def parse_nessus_xml(data: bytes | str) -> list[VulnResult]:
    """Parse a Nessus ``.nessus`` v2 report (``<Report><ReportHost><ReportItem>…``). Safe."""
    try:
        root = DET.fromstring(data.encode("utf-8") if isinstance(data, str) else data)
    except Exception as exc:
        raise ImportError_(tr("ملف Nessus غير صالح أو تالف.", "The Nessus file is invalid or corrupt.")) from exc
    out: list[VulnResult] = []
    for host in root.iter("ReportHost"):
        # Host IP is the name attr, or a <tag name="host-ip"> property.
        ip = _valid_ip(host.get("name"))
        if ip is None:
            for tag in host.iter("tag"):
                if tag.get("name") == "host-ip":
                    ip = _valid_ip(tag.text)
                    break
        if ip is None:
            continue
        for item in host.iter("ReportItem"):
            if (item.get("severity") or "0") == "0":  # severity 0 = informational
                continue
            name = _clean(item.get("pluginName"), 256) or ""
            cvss = 0.0
            score_el = item.find("cvss3_base_score") if item.find("cvss3_base_score") is not None else item.find("cvss_base_score")
            try:
                cvss = float(score_el.text) if score_el is not None and score_el.text else 0.0
            except (TypeError, ValueError):
                cvss = 0.0
            cves = [c.text.strip() for c in item.findall("cve") if c.text and c.text.upper().startswith("CVE")]
            port = item.get("port") or ""
            out.append(VulnResult(ip=ip, name=name, cve_ids=cves, cvss=cvss,
                                  port=f"{port}/{item.get('protocol', 'tcp')}" if port and port != "0" else "", summary=name))
    return out


def nessus_import(db: Session, data: bytes | str) -> dict[str, int]:
    results = parse_nessus_xml(data)
    if not results:
        raise ImportError_(tr("لا توجد نتائج في تقرير Nessus.", "No results in the Nessus report."))
    return store_vuln_results(db, results, "Nessus", "NESSUS")


# --- Wazuh vulnerability export (JSON) --------------------------------------------------


def parse_wazuh_json(data: Any) -> list[VulnResult]:
    """Parse a Wazuh vulnerability export. Tolerant of several shapes (API or exported rows)."""
    import json as _json
    if isinstance(data, (bytes, str)):
        try:
            data = _json.loads(data)
        except ValueError as exc:
            raise ImportError_(tr("ملف Wazuh JSON غير صالح.", "The Wazuh JSON file is invalid.")) from exc
    # Normalise to a flat list of finding dicts.
    rows: list[dict[str, Any]] = []
    if isinstance(data, dict):
        d = data.get("data", data)
        rows = d.get("affected_items") or d.get("vulnerabilities") or d.get("items") or []
        host_hint = data.get("agent") or data.get("host") or {}
    elif isinstance(data, list):
        rows, host_hint = data, {}
    else:
        raise ImportError_(tr("صيغة Wazuh غير متوقعة.", "Unexpected Wazuh format."))
    out: list[VulnResult] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        agent = r.get("agent") or r.get("host") or host_hint or {}
        ip = _valid_ip(r.get("ip") or (agent.get("ip") if isinstance(agent, dict) else None))
        if ip is None:
            continue
        cve = r.get("cve") or r.get("cveid") or r.get("id")
        cves = [cve.strip()] if isinstance(cve, str) and cve.upper().startswith("CVE") else []
        try:
            cvss = float(r.get("cvss3_score") or r.get("cvss") or r.get("score") or 0.0)
        except (TypeError, ValueError):
            cvss = 0.0
        name = _clean(str(r.get("title") or r.get("name") or cve or "finding"), 256) or ""
        out.append(VulnResult(ip=ip, name=name, cve_ids=cves, cvss=cvss,
                              port=str(r.get("package") or r.get("product") or "")[:40], summary=name))
    return out


def wazuh_import(db: Session, data: Any) -> dict[str, int]:
    results = parse_wazuh_json(data)
    if not results:
        raise ImportError_(tr("لا توجد نتائج بعناوين IP معروفة في ملف Wazuh.", "No results with known IP addresses in the Wazuh file."))
    return store_vuln_results(db, results, "Wazuh", "WAZUH")


# --- osquery results (JSON) → device/service inventory ----------------------------------


def parse_osquery_json(data: Any) -> list[HostRecord]:
    """Parse osquery results (system_info / interface_addresses / listening_ports style rows)."""
    import json as _json
    if isinstance(data, (bytes, str)):
        try:
            data = _json.loads(data)
        except ValueError as exc:
            raise ImportError_(tr("ملف osquery JSON غير صالح.", "The osquery JSON file is invalid.")) from exc
    rows = data.get("data") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ImportError_(tr("صيغة osquery غير متوقعة (المتوقع قائمة صفوف).", "Unexpected osquery format (a list of rows is expected)."))
    by_key: dict[str, HostRecord] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        ip = _valid_ip(r.get("address") or r.get("ip") or r.get("ipv4"))
        mac = _norm_mac(r.get("mac") or r.get("interface_mac"))
        host = r.get("hostname") or r.get("host") or r.get("computer_name")
        key = ip or mac or (host or "")
        if not key:
            continue
        rec = by_key.setdefault(key, HostRecord(ip=ip, mac=mac, hostname=host))
        if ip and not rec.ip:
            rec.ip = ip
        if mac and not rec.mac:
            rec.mac = mac
        if host and not rec.hostname:
            rec.hostname = host
        if r.get("os") or r.get("platform"):
            rec.os_family = str(r.get("os") or r.get("platform"))
    return [r for r in by_key.values() if r.ip or r.mac]


def osquery_import(db: Session, data: Any) -> dict[str, int]:
    records = parse_osquery_json(data)
    if not records:
        raise ImportError_(tr("لا توجد صفوف صالحة (كل صف يحتاج IP أو MAC).", "No valid rows (each row needs an IP or MAC)."))
    return upsert_records(db, records, "osquery_import")
