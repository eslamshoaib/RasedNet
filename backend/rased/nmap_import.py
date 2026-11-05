"""Import an existing Nmap scan (XML) into the inventory — offline, no scanning performed.

This lets an operator bring results they already collected with Nmap into RASED. It parses the
XML safely (defusedxml, so no entity-expansion or external-entity attacks), then upserts assets
and their open services directly — tagging them with the ``nmap_import`` discovery method and a
``import`` identification method so their provenance is clear. Nothing here contacts the network.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from defusedxml import ElementTree as DET
from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.discovery.services import EXPOSURE_BY_SERVICE, WELL_KNOWN_TCP
from rased.inventory import asset_label
from rased.models import Asset, Event, Service, utcnow
from rased.text import sanitize_banner


class NmapImportError(Exception):
    """Arabic, user-facing parse/import error."""


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    service_name: str
    product: str | None = None
    version: str | None = None


@dataclass
class NmapHost:
    ip: str | None = None
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    up: bool = True
    ports: list[NmapPort] = field(default_factory=list)


def _clean(value: str | None, limit: int = 128) -> str | None:
    if not value:
        return None
    out = sanitize_banner(value)[:limit].strip()
    return out or None


def parse_nmap_xml(data: bytes | str) -> list[NmapHost]:
    """Parse Nmap XML into structured hosts. Safe against malicious XML (defusedxml)."""
    try:
        root = DET.fromstring(data.encode("utf-8") if isinstance(data, str) else data)
    except Exception as exc:  # defusedxml raises on malformed or dangerous XML
        raise NmapImportError("ملف Nmap XML غير صالح أو تالف.") from exc
    if root.tag != "nmaprun":
        raise NmapImportError("هذا ليس ملف نتائج Nmap (العنصر الجذر ليس nmaprun).")

    hosts: list[NmapHost] = []
    for host_el in root.findall("host"):
        host = NmapHost()
        status = host_el.find("status")
        host.up = status is None or status.get("state") != "down"
        for addr in host_el.findall("address"):
            kind = addr.get("addrtype")
            value = addr.get("addr")
            if kind == "ipv4" or kind == "ipv6":
                try:
                    host.ip = str(ipaddress.ip_address(value)) if value else host.ip
                except ValueError:
                    continue
            elif kind == "mac":
                host.mac = (value or "").upper().replace("-", ":") or None
                host.vendor = _clean(addr.get("vendor"), 256)
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host.hostname = _clean(hn.get("name"), 253)
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue
                try:
                    num = int(p.get("portid", "0"))
                except ValueError:
                    continue
                if not (1 <= num <= 65535):
                    continue
                svc_el = p.find("service")
                name = (svc_el.get("name") if svc_el is not None else None) or WELL_KNOWN_TCP.get(num, "unknown")
                host.ports.append(NmapPort(
                    port=num, protocol=p.get("protocol", "tcp"), state="open",
                    service_name=_clean(name, 64) or "unknown",
                    product=_clean(svc_el.get("product"), 128) if svc_el is not None else None,
                    version=_clean(svc_el.get("version"), 64) if svc_el is not None else None,
                ))
        if host.ip or host.mac:
            hosts.append(host)
    return hosts


def import_hosts(db: Session, hosts: list[NmapHost]) -> dict[str, int]:
    """Upsert parsed hosts into assets/services. Returns counts. Does not commit."""
    now = utcnow()
    by_ip = {a.current_ip: a for a in db.scalars(select(Asset)) if a.current_ip}
    stats = {"hosts": len(hosts), "assets_new": 0, "assets_updated": 0, "services_new": 0, "services_updated": 0}

    for host in hosts:
        if not host.up and not host.ports:
            continue
        asset = by_ip.get(host.ip) if host.ip else None
        if asset is None:
            asset = Asset(current_ip=host.ip, status="online" if host.up else "unknown",
                          first_seen=now, last_seen=now)
            db.add(asset)
            db.flush()
            if host.ip:
                by_ip[host.ip] = asset
            stats["assets_new"] += 1
            db.add(Event(kind="asset_new", asset_id=asset.id, created_at=now,
                         message_ar=f"جهاز جديد من استيراد Nmap: {host.ip or host.mac}",
                         details={"source": "nmap_import"}))
        else:
            stats["assets_updated"] += 1
        asset.last_seen = now
        if host.up:
            asset.status = "online"
        if host.hostname and not asset.hostname:
            asset.hostname = host.hostname
        if host.mac and not asset.mac:
            asset.mac = host.mac
        if host.vendor and not asset.vendor:
            asset.vendor = host.vendor
        asset.discovery_methods = sorted(set(asset.discovery_methods or []) | {"nmap_import"})

        existing = {(s.port, s.protocol): s for s in asset.services}
        for np in host.ports:
            exposure = EXPOSURE_BY_SERVICE.get(np.service_name, "other")
            svc = existing.get((np.port, np.protocol))
            if svc is None:
                svc = Service(asset_id=asset.id, port=np.port, protocol=np.protocol, state="open",
                              service_name=np.service_name, product=np.product, version=np.version,
                              identification_method="import", identification_confidence=0.6,
                              exposure_category=exposure, first_seen=now, last_seen=now)
                db.add(svc)
                stats["services_new"] += 1
                db.add(Event(kind="service_new", asset_id=asset.id, created_at=now,
                             message_ar=f"منفذ {np.port}/{np.protocol} ({np.service_name}) من استيراد Nmap على {asset_label(asset)}",
                             details={"source": "nmap_import", "port": np.port, "service": np.service_name}))
            else:
                svc.state = "open"
                svc.last_seen = now
                # Only overwrite weak (port-only) identifications; never clobber a banner-confirmed one.
                if svc.identification_method != "banner":
                    svc.service_name = np.service_name
                    svc.product = np.product or svc.product
                    svc.version = np.version or svc.version
                    svc.exposure_category = exposure
                    svc.identification_method = "import"
                stats["services_updated"] += 1
    db.flush()
    return stats
