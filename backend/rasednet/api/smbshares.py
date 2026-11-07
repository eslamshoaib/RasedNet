"""Anonymous SMB share browsing API (read-only, no credentials)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, require
from rasednet.i18n import get_lang, tr
from rasednet.models import Asset
from rasednet.smbshares import SmbError, browse, list_accessible_shares

router = APIRouter(prefix="/api/assets", tags=["smb"])


def _smb_asset(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None or not asset.current_ip:
        raise HTTPException(status.HTTP_404_NOT_FOUND, tr("الجهاز غير موجود أو بلا عنوان IP", "Device not found or has no IP address"))
    has_smb = any(s.state == "open" and s.port in (445, 139) for s in asset.services)
    if not has_smb:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("لا يوجد منفذ مشاركة ملفات مفتوح (445/139) على هذا الجهاز", "No open file-sharing port (445/139) on this device"))
    return asset


@router.get("/{asset_id}/smb/shares")
def smb_shares(asset_id: int, request: Request, auth: AuthContext = Depends(require("remote:verify")),
               db: Session = Depends(get_db)) -> dict[str, Any]:
    asset = _smb_asset(db, asset_id)
    try:
        result = list_accessible_shares(asset.current_ip)
    except SmbError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    audit(db, request, "smb.shares", auth=auth, target_type="asset", target_id=asset_id,
          details={"ip": asset.current_ip, "shares": [s["share"] for s in result["shares"]]})
    db.commit()
    return result


@router.get("/{asset_id}/smb/browse")
def smb_browse(asset_id: int, request: Request, share: str = Query(..., min_length=1, max_length=128),
               path: str = Query("", max_length=1024), auth: AuthContext = Depends(require("remote:verify")),
               db: Session = Depends(get_db)) -> dict[str, Any]:
    asset = _smb_asset(db, asset_id)
    try:
        result = browse(asset.current_ip, share, path)
    except SmbError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    audit(db, request, "smb.browse", auth=auth, target_type="asset", target_id=asset_id,
          details={"ip": asset.current_ip, "share": share, "path": path, "entries": result["count"]})
    db.commit()
    return result
