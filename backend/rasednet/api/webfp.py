"""Web-fingerprint API: capture HTTP identity (server/title/favicon hash) of an asset's web services."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, require
from rasednet.i18n import get_lang, tr
from rasednet.models import Asset
from rasednet.webfp import WEB_PORTS, fingerprint_asset

router = APIRouter(prefix="/api/assets", tags=["webfp"])


@router.post("/{asset_id}/web-fingerprint")
def web_fingerprint(asset_id: int, request: Request, auth: AuthContext = Depends(require("remote:verify")),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None or not asset.current_ip:
        raise HTTPException(status.HTTP_404_NOT_FOUND, tr("الجهاز غير موجود أو بلا عنوان IP", "Device not found or has no IP address"))
    web_ports = [s.port for s in asset.services if s.state == "open" and s.port in WEB_PORTS]
    if not web_ports:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("لا توجد خدمة ويب مفتوحة على هذا الجهاز", "No open web service on this device"))
    # Sync endpoint → FastAPI runs it in a worker thread, so the blocking fetch is safe here.
    results = fingerprint_asset(asset.current_ip, web_ports)
    audit(db, request, "web.fingerprint", auth=auth, target_type="asset", target_id=asset_id,
          details={"ip": asset.current_ip, "ports": web_ports})
    db.commit()
    return {"ip": asset.current_ip, "services": results}
