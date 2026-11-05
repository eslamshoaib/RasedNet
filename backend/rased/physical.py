"""Persist SNMP-discovered physical links and expose them as a map graph.

``resolve_and_store`` turns the neighbour list from :mod:`rased.snmp` into ``PhysicalLink`` rows,
resolving each neighbour to a known inventory asset by MAC or system name when possible.
``physical_graph`` renders all stored links as nodes/edges for the physical-topology view.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.models import Asset, AssetIdentifier, PhysicalLink, utcnow


def _norm_mac(value: str) -> str:
    return value.replace("-", ":").upper().strip()


def _asset_lookup(db: Session) -> tuple[dict[str, int], dict[str, int]]:
    """Return (mac → asset_id, sysname/hostname → asset_id) maps for neighbour resolution."""
    by_mac: dict[str, int] = {}
    by_name: dict[str, int] = {}
    for a in db.scalars(select(Asset)):
        if a.mac:
            by_mac[_norm_mac(a.mac)] = a.id
        for name in (a.hostname, a.netbios_name, a.display_name):
            if name:
                by_name.setdefault(name.strip().lower(), a.id)
    for ident in db.scalars(select(AssetIdentifier).where(AssetIdentifier.kind == "mac")):
        by_mac.setdefault(_norm_mac(ident.value), ident.asset_id)
    return by_mac, by_name


def resolve_and_store(db: Session, local_asset_id: int, neighbours: list[dict[str, Any]],
                      credential_id: int | None = None) -> dict[str, int]:
    """Upsert the neighbours as physical links of ``local_asset_id``; resolve remote assets."""
    by_mac, by_name = _asset_lookup(db)
    existing = {
        (link.local_port, link.remote_chassis_id, link.remote_port, link.source): link
        for link in db.scalars(select(PhysicalLink).where(PhysicalLink.local_asset_id == local_asset_id))
    }
    now = utcnow()
    added = updated = resolved = 0
    for n in neighbours:
        key = (n.get("local_port", ""), n.get("remote_chassis_id", ""), n.get("remote_port", ""), n["source"])
        remote_id = None
        mac = n.get("remote_chassis_id", "")
        if mac:
            remote_id = by_mac.get(_norm_mac(mac))
        if remote_id is None and n.get("remote_sysname"):
            remote_id = by_name.get(n["remote_sysname"].strip().lower())
        if remote_id == local_asset_id:
            remote_id = None  # never link a device to itself
        if remote_id is not None:
            resolved += 1
        link = existing.get(key)
        if link is None:
            link = PhysicalLink(local_asset_id=local_asset_id, local_port=key[0], remote_chassis_id=key[1],
                                remote_port=key[2], source=key[3], first_seen=now)
            db.add(link)
            existing[key] = link
            added += 1
        else:
            updated += 1
        link.remote_asset_id = remote_id
        link.remote_sysname = (n.get("remote_sysname") or "")[:253]
        link.remote_descr = (n.get("remote_descr") or "")[:256]
        link.vlan = n.get("vlan")
        link.credential_id = credential_id
        link.last_seen = now
    db.flush()
    return {"added": added, "updated": updated, "resolved": resolved, "total": len(neighbours)}


def physical_graph(db: Session) -> dict[str, Any]:
    """Nodes/edges of every stored physical link, for the physical-topology map."""
    links = list(db.scalars(select(PhysicalLink)))
    assets = {a.id: a for a in db.scalars(select(Asset))}
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def asset_node(aid: int) -> str:
        a = assets.get(aid)
        nid = f"a:{aid}"
        if nid not in nodes:
            nodes[nid] = {
                "id": nid, "kind": "asset", "asset_id": aid,
                "label": (a.display_name or a.hostname or a.current_ip or f"#{aid}") if a else f"#{aid}",
                "device_type": a.device_type if a else "unknown",
                "ip": a.current_ip if a else None,
            }
        return nid

    for link in links:
        src = asset_node(link.local_asset_id)
        if link.remote_asset_id:
            dst = asset_node(link.remote_asset_id)
        else:
            # Unresolved neighbour: a leaf node labelled by its name or MAC.
            label = link.remote_sysname or link.remote_chassis_id or "جهاز غير معروف"
            dst = f"ext:{label}"
            nodes.setdefault(dst, {"id": dst, "kind": "external", "label": label,
                                   "mac": link.remote_chassis_id or None, "device_type": "unknown"})
        edges.append({
            "id": f"pl:{link.id}", "source": src, "target": dst, "source_kind": link.source,
            "local_port": link.local_port, "remote_port": link.remote_port,
            "label": f"{link.local_port} ↔ {link.remote_port}".strip(" ↔"),
        })
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {"links": len(links), "nodes": len(nodes),
                  "resolved": sum(1 for link in links if link.remote_asset_id)},
    }
