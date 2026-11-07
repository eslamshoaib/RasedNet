"""Active UDP service probing of a single asset (authorised: target must be in an approved scope)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, require
from rasednet.discovery.udp import DEFAULT_UDP_PORTS, UDP_PROBES, scan_host
from rasednet.models import Asset, Event, Service, utcnow
from rasednet.scanning import find_scope_for_ip
from rasednet.i18n import get_lang, tr

router = APIRouter(prefix="/api/assets", tags=["udp"])

# UDP service → exposure category (service names come from rasednet.discovery.udp).
_UDP_EXPOSURE = {
    "dns": "infrastructure", "ntp": "infrastructure", "snmp": "infrastructure", "isakmp": "infrastructure",
    "netbios-ns": "file_sharing", "tftp": "file_sharing", "ssdp": "other", "mdns": "other",
}


class UdpScanIn(BaseModel):
    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_UDP_PORTS), max_length=64)
    timeout: float = Field(default=2.0, ge=0.3, le=5.0)


@router.post("/{asset_id}/udp-scan")
def udp_scan(asset_id: int, body: UdpScanIn, request: Request,
             auth: AuthContext = Depends(require("scan:run")),
             db: Session = Depends(get_db)) -> dict[str, Any]:
    settings = request.app.state.settings
    asset = db.get(Asset, asset_id)
    if asset is None or not asset.current_ip:
        raise HTTPException(status.HTTP_404_NOT_FOUND, tr("الجهاز غير موجود أو بلا عنوان IP", "Device not found or has no IP address"))
    # Active scanning is only allowed inside an approved scope.
    if find_scope_for_ip(db, settings, asset.current_ip) is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            tr("عنوان الجهاز خارج النطاقات المعتمدة؛ لا يمكن إجراء فحص نشط عليه.", "The device address is outside the approved scopes; an active scan cannot be run on it."))

    ports = [p for p in body.ports if p in UDP_PROBES] or list(DEFAULT_UDP_PORTS)
    results = asyncio.run(scan_host(asset.current_ip, ports, timeout=body.timeout))

    now = utcnow()
    existing = {(s.port, s.protocol): s for s in asset.services}
    opened = 0
    out: list[dict[str, Any]] = []
    for r in results:
        out.append({"port": r.port, "service": r.service, "state": r.state})
        if r.state != "open":
            continue
        opened += 1
        svc = existing.get((r.port, "udp"))
        if svc is None:
            svc = Service(asset_id=asset.id, port=r.port, protocol="udp", state="open",
                          service_name=r.service, identification_method="udp-probe", identification_confidence=0.85,
                          exposure_category=_UDP_EXPOSURE.get(r.service, "other"), first_seen=now, last_seen=now)
            db.add(svc)
            db.add(Event(kind="service_new", asset_id=asset.id, created_at=now,
                         message_ar=(f"Open UDP port {r.port} ({r.service}) on {asset.current_ip}" if get_lang()=="en" else f"منفذ UDP مفتوح {r.port} ({r.service}) على {asset.current_ip}"),
                         details={"source": "udp-probe", "port": r.port, "protocol": "udp"}))
        else:
            svc.state = "open"
            svc.last_seen = now
    asset.last_seen = now
    audit(db, request, "udp.scan", auth=auth, target_type="asset", target_id=asset_id,
          details={"ip": asset.current_ip, "ports": ports, "open": opened})
    db.commit()
    return {"ip": asset.current_ip, "open": opened, "results": out}
