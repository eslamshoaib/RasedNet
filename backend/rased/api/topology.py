"""Network map API."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, require
from rased.discovery.traceroute import trace_many
from rased.models import RouteTrace, utcnow
from rased.scanning import find_scope_for_ip
from rased.topology import build_topology, default_trace_targets

router = APIRouter(prefix="/api/topology", tags=["topology"])


@router.get("")
def topology(request: Request, include_devices: bool = True, _: AuthContext = Depends(require("asset:read")),
             db: Session = Depends(get_db)) -> dict[str, Any]:
    return build_topology(db, request.app.state.settings, include_devices=include_devices)


class TraceIn(BaseModel):
    targets: list[str] = Field(default_factory=list, max_length=64)
    max_hops: int = Field(default=15, ge=1, le=30)


@router.post("/trace")
def trace(body: TraceIn, request: Request, auth: AuthContext = Depends(require("scan:run")),
          db: Session = Depends(get_db)) -> dict[str, Any]:
    """Discover the router chain toward approved networks (or the given addresses inside them)."""
    settings = request.app.state.settings
    targets: list[str] = []
    for raw in body.targets or default_trace_targets(db, settings):
        try:
            ip = str(ipaddress.ip_address(raw.strip()))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"عنوان غير صالح: {raw}") from exc
        # Path discovery is a single TTL-limited ICMP echo per hop (diagnostics, not scanning):
        # allowed toward any internal address, or toward public ones only if explicitly enabled.
        addr = ipaddress.ip_address(ip)
        internal = addr.is_private and not addr.is_loopback and not addr.is_link_local and not addr.is_multicast
        if not internal and find_scope_for_ip(db, settings, ip) is None and not settings.allow_public_scopes:
            raise HTTPException(status.HTTP_409_CONFLICT, f"العنوان {ip} ليس عنواناً داخلياً ولا يقع ضمن نطاق معتمد")
        targets.append(ip)
    if not targets:
        return {"traced": 0, "paths": []}
    results = asyncio.run(trace_many(targets, body.max_hops))
    paths = []
    for ip, hops in results.items():
        reached = bool(hops) and hops[-1].ip == ip
        db.add(RouteTrace(target=ip, hops=[{"ttl": h.ttl, "ip": h.ip, "rtt_ms": h.rtt_ms} for h in hops], reached=reached,
                          requested_by_id=auth.user.id, created_at=utcnow()))
        paths.append({"target": ip, "reached": reached, "hops": [h.ip for h in hops]})
    audit(db, request, "topology.trace", auth=auth, details={"targets": targets})
    db.commit()
    return {"traced": len(paths), "paths": paths}
