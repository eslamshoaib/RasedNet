"""Router / network-device administration over SSH (ready command sets per platform)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, get_db, not_found, require
from rased.api.remote import ExecutionOut, _authorised_asset, _credential, _record, _run_on_device
from rased.config import Settings
from rased.models import Asset, RemoteExecution, Service
from rased.netadmin import (
    NETWORK_DEVICE_TYPES,
    NetAdminError,
    build_command,
    detect_platform,
    get_action,
    platform_payload,
)

router = APIRouter(prefix="/api", tags=["netadmin"])


def _ssh_banner(db: Session, asset: Asset) -> str | None:
    svc = db.scalar(
        select(Service).where(Service.asset_id == asset.id, Service.service_name == "ssh", Service.state == "open").limit(1)
    )
    if svc is None:
        return None
    return " ".join(x for x in (svc.product, svc.version, svc.banner) if x) or None


def _is_network_device(asset: Asset) -> bool:
    return asset.device_type in NETWORK_DEVICE_TYPES or asset.is_gateway


def _platform_key(db: Session, asset: Asset) -> str:
    return detect_platform(asset.vendor, asset.model, _ssh_banner(db, asset))


@router.get("/assets/{asset_id}/netadmin")
def netadmin_actions(asset_id: int, request: Request, _: AuthContext = Depends(require("remote:verify")),
                     db: Session = Depends(get_db)) -> dict[str, object]:
    """Available control actions for a router / network device, by its detected platform."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise not_found("الجهاز")
    payload = platform_payload(_platform_key(db, asset))
    has_ssh = db.scalar(
        select(Service.id).where(Service.asset_id == asset.id, Service.service_name == "ssh", Service.state == "open").limit(1)
    ) is not None
    payload["is_network_device"] = _is_network_device(asset)
    payload["has_ssh"] = has_ssh
    if not has_ssh:
        payload["note_ar"] = (str(payload["note_ar"])
                              + " — لم يُرصد منفذ SSH مفتوح على هذا الجهاز؛ فعّل SSH على الموجّه أولاً.")
    return payload


class NetAdminIn(BaseModel):
    credential_id: int
    params: dict[str, str] = Field(default_factory=dict, max_length=8)
    confirm: bool = False


@router.post("/assets/{asset_id}/netadmin/{action_id}", response_model=ExecutionOut)
def run_netadmin(asset_id: int, action_id: str, body: NetAdminIn, request: Request,
                 auth: AuthContext = Depends(require("remote:verify")), db: Session = Depends(get_db)) -> RemoteExecution:
    settings: Settings = request.app.state.settings
    asset = _authorised_asset(db, settings, asset_id)
    if not _is_network_device(asset):
        raise HTTPException(status.HTTP_409_CONFLICT, "هذه الأدوات مخصصة للموجّهات وأجهزة الشبكة")
    platform_key = _platform_key(db, asset)
    action = get_action(platform_key, action_id)
    if action is None:
        raise not_found("الإجراء")
    if action.category == "change":
        if not auth.can("remote:change"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "تنفيذ أوامر التغيير على الأجهزة يتطلب صلاحية مسؤول النظام")
        if not body.confirm:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "يجب تأكيد تنفيذ أمر يغيّر إعدادات الجهاز")

    cred, password = _credential(db, settings, body.credential_id)
    if cred.kind != "ssh":
        raise HTTPException(status.HTTP_409_CONFLICT, "إدارة أجهزة الشبكة تتطلب حساب SSH من الخزنة")
    try:
        command = build_command(action, body.params)
    except NetAdminError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    ip = asset.current_ip or ""
    return _record(
        db, request, auth, asset=asset, cred=cred, target=ip, port=cred.port,
        section=f"netadmin_{action.category}", label=f"[{platform_key}] {action.label_ar}", command=command,
        run=lambda: _run_on_device(db, settings, cred, password, ip, command),
    )
