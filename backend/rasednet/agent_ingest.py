"""Endpoint-agent report ingestion.

A lightweight agent running on a host authenticates with an enrollment token and POSTs a small
JSON report (hostname, OS, addresses, listening ports, optional installed software). RasedNet
upserts the matching asset and its services, tagging them with the ``agent`` discovery method.
This is the host telling RasedNet about itself — no scanning involved.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.discovery.services import EXPOSURE_BY_SERVICE, WELL_KNOWN_TCP
from rasednet.models import Asset, Event, Service, utcnow
from rasednet.text import sanitize_banner
from rasednet.i18n import get_lang, tr

OS_FAMILIES = {"windows", "linux", "unix", "macos", "ios", "android", "network_os", "unknown"}


def new_token() -> tuple[str, str]:
    """Return (plaintext_token, sha256_hash). The plaintext is shown once and never stored."""
    token = "rsd_" + secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _os_family(value: str | None) -> str:
    v = (value or "").strip().lower()
    if v in OS_FAMILIES:
        return v
    if "windows" in v:
        return "windows"
    if "darwin" in v or "mac" in v:
        return "macos"
    if "linux" in v:
        return "linux"
    return "unknown"


def normalize_report(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and clean an agent report. Raises ValueError on malformed input."""
    if not isinstance(payload, dict):
        raise ValueError(tr("تقرير غير صالح", "Invalid report"))
    hostname = (sanitize_banner(str(payload.get("hostname", ""))) or "")[:253].strip() or None
    ip = None
    for candidate in [payload.get("ip"), *(payload.get("ips") or [])]:
        try:
            ip = str(ipaddress.ip_address(str(candidate)))
            break
        except (ValueError, TypeError):
            continue
    mac = str(payload.get("mac", "")).upper().replace("-", ":").strip() or None
    ports: list[dict[str, Any]] = []
    for p in (payload.get("ports") or [])[:500]:
        try:
            num = int(p.get("port") if isinstance(p, dict) else p)
        except (TypeError, ValueError):
            continue
        if 1 <= num <= 65535:
            proto = (p.get("protocol") if isinstance(p, dict) else "tcp") or "tcp"
            ports.append({"port": num, "protocol": "udp" if str(proto).lower() == "udp" else "tcp"})
    if not hostname and not ip and not mac:
        raise ValueError(tr("يجب أن يحتوي التقرير على اسم مضيف أو عنوان IP أو MAC", "The report must contain a hostname, IP or MAC"))
    return {"hostname": hostname, "ip": ip, "mac": mac, "os_family": _os_family(str(payload.get("os", ""))),
            "ports": ports}


def ingest_report(db: Session, report: dict[str, Any], *, source: str = "agent") -> dict[str, Any]:
    """Upsert the asset and services described by a normalised report. ``source`` tags provenance
    (``agent`` for an endpoint agent, ``collector`` for a remote RasedNet collector). Does not commit."""
    now = utcnow()
    source_label = (tr("جامع موزّع", "distributed collector") if source == "collector" else tr("وكيل النهاية", "endpoint agent"))
    asset = None
    if report["ip"]:
        asset = db.scalar(select(Asset).where(Asset.current_ip == report["ip"]))
    if asset is None and report["mac"]:
        asset = db.scalar(select(Asset).where(Asset.mac == report["mac"]))
    if asset is None and report["hostname"]:
        asset = db.scalar(select(Asset).where(Asset.hostname == report["hostname"]))

    created = False
    if asset is None:
        asset = Asset(current_ip=report["ip"], hostname=report["hostname"], status="online",
                      first_seen=now, last_seen=now)
        db.add(asset)
        db.flush()
        created = True
        db.add(Event(kind="asset_new", asset_id=asset.id, created_at=now,
                     message_ar=(f"New device from {source_label}: {report['hostname'] or report['ip']}" if get_lang()=="en" else f"جهاز جديد من {source_label}: {report['hostname'] or report['ip']}"),
                     details={"source": source}))
    asset.last_seen = now
    asset.status = "online"
    if report["hostname"] and not asset.hostname:
        asset.hostname = report["hostname"]
    if report["mac"] and not asset.mac:
        asset.mac = report["mac"]
    if report["os_family"] != "unknown":
        asset.os_family = report["os_family"]
        asset.os_confidence = max(asset.os_confidence, 0.9)  # the host reported it itself
    asset.discovery_methods = sorted(set(asset.discovery_methods or []) | {source})

    existing = {(s.port, s.protocol): s for s in asset.services}
    new_services = 0
    for p in report["ports"]:
        key = (p["port"], p["protocol"])
        name = WELL_KNOWN_TCP.get(p["port"], "unknown")
        if key in existing:
            svc = existing[key]
            svc.state = "open"
            svc.last_seen = now
        else:
            db.add(Service(asset_id=asset.id, port=p["port"], protocol=p["protocol"], state="open",
                           service_name=name, identification_method=source, identification_confidence=0.9,
                           exposure_category=EXPOSURE_BY_SERVICE.get(name, "other"), first_seen=now, last_seen=now))
            new_services += 1
    db.flush()
    return {"asset_id": asset.id, "created": created, "new_services": new_services, "ports": len(report["ports"])}
