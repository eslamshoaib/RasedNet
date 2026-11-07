"""Distributed collectors: let a RasedNet instance on another network segment forward its inventory
to a central RasedNet, so devices the central server cannot reach directly (isolated VLANs, remote
sites) still appear centrally.

``build_forward_payload`` turns a local inventory into a batch report; ``ingest_batch`` upserts
such a batch centrally (reusing the per-host agent ingest, tagged ``collector``). Transport is
ordinary token-authenticated HTTPS — no passive capture or special hardware required.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.agent_ingest import ingest_report, normalize_report
from rasednet.models import Asset, Service
from rasednet.i18n import get_lang, tr


def build_forward_payload(db: Session) -> dict[str, Any]:
    """Serialise the local inventory (online assets + open services) into a collector report."""
    assets = list(db.scalars(select(Asset)))
    svc_by_asset: dict[int, list[Service]] = {}
    for s in db.scalars(select(Service).where(Service.state == "open")):
        svc_by_asset.setdefault(s.asset_id, []).append(s)
    hosts: list[dict[str, Any]] = []
    for a in assets:
        if not (a.current_ip or a.mac):
            continue
        hosts.append({
            "ip": a.current_ip,
            "mac": a.mac,
            "hostname": a.hostname or a.display_name,
            "os": a.os_family if a.os_family != "unknown" else "",
            "ports": [{"port": s.port, "protocol": s.protocol} for s in svc_by_asset.get(a.id, [])],
        })
    return {"hosts": hosts, "count": len(hosts)}


def ingest_batch(db: Session, payload: Any, *, source: str = "collector") -> dict[str, int]:
    """Upsert a collector's batch of host reports. Does not commit."""
    hosts = payload.get("hosts") if isinstance(payload, dict) else payload
    if not isinstance(hosts, list):
        raise ValueError(tr("صيغة تقرير الجامع غير صالحة: المتوقع قائمة أجهزة.", "Invalid collector report format: a list of hosts is expected."))
    created = updated = services = skipped = 0
    for raw in hosts:
        if not isinstance(raw, dict):
            skipped += 1
            continue
        try:
            norm = normalize_report(raw)
        except ValueError:
            skipped += 1
            continue
        res = ingest_report(db, norm, source=source)
        created += 1 if res["created"] else 0
        updated += 0 if res["created"] else 1
        services += res["new_services"]
    db.flush()
    return {"hosts": len(hosts), "assets_new": created, "assets_updated": updated,
            "services_new": services, "skipped": skipped}
