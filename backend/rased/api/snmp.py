"""Physical topology (SNMP/LLDP/CDP/FDB) API — authenticated, read-only collection."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, require
from rased.models import Asset, Credential, utcnow
from rased.physical import physical_graph, resolve_and_store
from rased.remote import VaultError, decrypt_secret
from rased.snmp import SnmpError, SnmpTarget, collect

router = APIRouter(prefix="/api/physical", tags=["physical"])


class CollectIn(BaseModel):
    credential_id: int
    include_fdb: bool = True


def _target_from_secret(host: str, port: int, secret: str) -> SnmpTarget:
    """A vaulted SNMP secret is either a v2c community string, or a JSON blob for SNMPv3."""
    secret = secret.strip()
    if secret.startswith("{"):
        try:
            data = json.loads(secret)
            if isinstance(data, dict) and data.get("version") == "v3":
                return SnmpTarget(
                    host=host, port=port, version="v3",
                    v3_user=str(data.get("user", "")), v3_auth_key=str(data.get("auth_key", "")),
                    v3_auth_proto=str(data.get("auth_proto", "sha")), v3_priv_key=str(data.get("priv_key", "")),
                    v3_priv_proto=str(data.get("priv_proto", "aes")),
                )
        except (ValueError, TypeError):
            pass
    return SnmpTarget(host=host, port=port, version="v2c", community=secret)


@router.get("/graph")
def graph(_: AuthContext = Depends(require("asset:read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return physical_graph(db)


@router.get("/credentials")
def snmp_credentials(_: AuthContext = Depends(require("asset:read")),
                     db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    creds = db.scalars(select(Credential).where(Credential.kind == "snmp")).all()
    return [{"id": c.id, "name": c.name, "port": c.port} for c in creds]


@router.post("/assets/{asset_id}/collect")
def collect_asset(asset_id: int, body: CollectIn, request: Request,
                  auth: AuthContext = Depends(require("remote:verify")),
                  db: Session = Depends(get_db)) -> dict[str, Any]:
    settings = request.app.state.settings
    asset = db.get(Asset, asset_id)
    if asset is None or not asset.current_ip:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "الجهاز غير موجود أو بلا عنوان IP")
    cred = db.get(Credential, body.credential_id)
    if cred is None or cred.kind != "snmp":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "اختر حساب SNMP من الخزنة")
    try:
        community = decrypt_secret(settings, cred.secret_encrypted)
    except VaultError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    target = _target_from_secret(asset.current_ip, cred.port or 161, community)
    try:
        result = asyncio.run(collect(target, include_fdb=body.include_fdb))
    except SnmpError as exc:
        audit(db, request, "physical.collect", auth=auth, success=False, target_type="asset",
              target_id=asset_id, details={"ip": asset.current_ip, "error": str(exc)[:200]})
        db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    stats = resolve_and_store(db, asset.id, result["neighbours"], cred.id)
    cred.last_used_at = utcnow()

    # Enrich identity from SNMP sysObjectID/sysDescr (fills weak/unknown fields only).
    ident = result.get("identity") or {}
    applied: dict[str, Any] = {}
    if ident:
        conf = float(ident.get("confidence", 0.6))
        if ident.get("vendor") and not asset.vendor:
            asset.vendor = ident["vendor"][:256]; applied["vendor"] = asset.vendor
        if ident.get("device_type") and (asset.device_type == "unknown" or asset.device_type_confidence < conf):
            asset.device_type = ident["device_type"]; asset.device_type_confidence = conf; applied["device_type"] = asset.device_type
        if ident.get("os_family") and asset.os_family == "unknown":
            asset.os_family = ident["os_family"]; asset.os_confidence = max(asset.os_confidence, conf); applied["os_family"] = asset.os_family
        if result.get("sys_name") and not asset.hostname:
            asset.hostname = result["sys_name"][:253]
    audit(db, request, "physical.collect", auth=auth, target_type="asset", target_id=asset_id,
          details={"ip": asset.current_ip, "sys_name": result["sys_name"], "counts": result["counts"],
                   "stored": stats, "identified": applied})
    db.commit()
    return {"sys_name": result["sys_name"], "sys_descr": result["sys_descr"],
            "sys_object_id": result.get("sys_object_id", ""), "identity": ident, "identified": applied,
            "counts": result["counts"], "stored": stats, "neighbours": result["neighbours"]}
