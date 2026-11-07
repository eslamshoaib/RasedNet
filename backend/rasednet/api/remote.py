"""Credential vault and execution of guidance commands on devices (WinRM) or on the scanner."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.api.deps import AuthContext, audit, get_db, not_found, require
from rasednet.i18n import get_lang, tr
from rasednet.config import Settings
from rasednet.models import Asset, Credential, RemoteExecution, Service, SshHostKey, utcnow
from rasednet.remediation import build_guidance
from rasednet.remote import (
    HostKey,
    RemoteError,
    VaultError,
    decrypt_secret,
    encrypt_secret,
    fill_placeholders,
    is_executable,
    run_local_powershell,
    run_remote_powershell,
    run_ssh,
)
from rasednet.scanning import find_scope_for_ip

router = APIRouter(prefix="/api", tags=["remote"])


# --- schemas -------------------------------------------------------------------------------


class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: Literal["winrm", "ssh", "snmp"] = "winrm"
    username: str = Field(min_length=1, max_length=256, pattern=r"^[^\s'\"`]+$")
    password: str = Field(min_length=1, max_length=512)
    use_https: bool = False
    port: int | None = Field(default=None, ge=1, le=65535)
    verify_tls: bool = True


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    kind: str
    username: str
    use_https: bool
    port: int
    verify_tls: bool
    created_at: datetime
    last_used_at: datetime | None


class ExecuteIn(BaseModel):
    section: Literal["network_checks", "verify", "disable", "harden"]
    index: int = Field(ge=0, le=50)
    credential_id: int | None = None
    params: dict[str, str] = Field(default_factory=dict, max_length=5)
    confirm: bool = False


class ExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int | None
    target: str
    service_port: int | None
    section: str
    label_ar: str
    command: str
    status: str
    had_errors: bool
    output: str
    started_at: datetime
    finished_at: datetime | None


class TestCredentialIn(BaseModel):
    asset_id: int


# --- vault ---------------------------------------------------------------------------------


@router.get("/credentials", response_model=list[CredentialOut])
def list_credentials(_: AuthContext = Depends(require("remote:verify")), db: Session = Depends(get_db)) -> list[Credential]:
    # Usable by operators for read-only checks; secrets are never returned.
    return list(db.scalars(select(Credential).order_by(Credential.name)))


@router.post("/credentials", response_model=CredentialOut, status_code=201)
def create_credential(body: CredentialIn, request: Request, auth: AuthContext = Depends(require("credential:manage")),
                      db: Session = Depends(get_db)) -> Credential:
    settings: Settings = request.app.state.settings
    if db.scalar(select(Credential.id).where(Credential.name == body.name.strip())) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("يوجد حساب آخر بنفس الاسم", "Another account with this name exists"))
    try:
        secret = encrypt_secret(settings, body.password)
    except VaultError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    default_port = (22 if body.kind == "ssh" else 161 if body.kind == "snmp"
                    else (5986 if body.use_https else 5985))
    cred = Credential(name=body.name.strip(), kind=body.kind, username=body.username, secret_encrypted=secret,
                      use_https=body.use_https and body.kind == "winrm", port=body.port or default_port,
                      verify_tls=body.verify_tls, created_by_id=auth.user.id, created_at=utcnow())
    db.add(cred)
    db.flush()
    audit(db, request, "credential.create", auth=auth, target_type="credential", target_id=cred.id,
          details={"name": cred.name, "kind": cred.kind, "username": cred.username, "https": cred.use_https, "port": cred.port})
    db.commit()
    return cred


@router.delete("/credentials/{credential_id}", status_code=204)
def delete_credential(credential_id: int, request: Request, auth: AuthContext = Depends(require("credential:manage")),
                      db: Session = Depends(get_db)) -> Response:
    cred = db.get(Credential, credential_id)
    if cred is None:
        raise not_found("الحساب")
    audit(db, request, "credential.delete", auth=auth, target_type="credential", target_id=cred.id, details={"name": cred.name})
    db.delete(cred)
    db.commit()
    return Response(status_code=204)


# --- execution -----------------------------------------------------------------------------


def _authorised_asset(db: Session, settings: Settings, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise not_found("الجهاز")
    if not asset.current_ip:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("لا يوجد عنوان معروف لهذا الجهاز", "This device has no known address"))
    if find_scope_for_ip(db, settings, asset.current_ip) is None:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("الجهاز خارج النطاقات المعتمدة؛ لا يُسمح بتنفيذ أوامر عليه", "The device is outside the approved scopes; running commands on it is not allowed"))
    return asset


def _credential(db: Session, settings: Settings, credential_id: int | None) -> tuple[Credential, str]:
    if credential_id is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("اختر حساب الدخول للجهاز من الخزنة", "Choose the device credential from the vault"))
    cred = db.get(Credential, credential_id)
    if cred is None:
        raise not_found("الحساب")
    try:
        return cred, decrypt_secret(settings, cred.secret_encrypted)
    except VaultError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


def _record(db: Session, request: Request, auth: AuthContext, *, asset: Asset | None, cred: Credential | None, target: str,
            port: int | None, section: str, label: str, command: str, run) -> RemoteExecution:  # type: ignore[no-untyped-def]
    started = utcnow()
    try:
        result = run()
        status_value, had_errors, output = "ok", result.had_errors, result.output
    except RemoteError as exc:
        status_value, had_errors, output = "error", True, str(exc)
    execution = RemoteExecution(
        asset_id=asset.id if asset else None, credential_id=cred.id if cred else None, user_id=auth.user.id,
        target=target, service_port=port, section=section, label_ar=label, command=command, status=status_value,
        had_errors=had_errors, output=output, started_at=started, finished_at=utcnow(),
    )
    db.add(execution)
    if cred is not None:
        cred.last_used_at = utcnow()
    db.flush()
    audit(db, request, "remote.execute", auth=auth, target_type="asset" if asset else "scanner",
          target_id=asset.id if asset else None, success=status_value == "ok",
          details={"execution_id": execution.id, "section": section, "command": command, "target": target,
                   "credential": cred.name if cred else None, "had_errors": had_errors})
    db.commit()
    return execution


@router.post("/assets/{asset_id}/services/{service_id}/execute", response_model=ExecutionOut)
def execute(asset_id: int, service_id: int, body: ExecuteIn, request: Request,
            auth: AuthContext = Depends(require("remote:verify")), db: Session = Depends(get_db)) -> RemoteExecution:
    settings: Settings = request.app.state.settings
    changes_device = body.section in ("disable", "harden")
    if changes_device:
        if not auth.can("remote:change"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, tr("تنفيذ أوامر الإغلاق والتأمين يتطلب صلاحية مسؤول النظام", "Running disable/harden commands requires administrator permission"))
        if not body.confirm:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("يجب تأكيد تنفيذ أمر يغيّر إعدادات الجهاز", "You must confirm running a command that changes the device settings"))
    asset = _authorised_asset(db, settings, asset_id)
    svc = db.get(Service, service_id)
    if svc is None or svc.asset_id != asset.id:
        raise not_found("الخدمة")
    guidance = build_guidance(svc.service_name, svc.port, asset.current_ip, asset.os_family, asset.device_type)
    if guidance is None:
        raise HTTPException(status.HTTP_409_CONFLICT, tr("لا توجد أوامر لهذه الخدمة", "There are no commands for this service"))

    cred: Credential | None = None
    password = ""
    if body.section == "network_checks":
        commands = guidance["network_checks"]
    else:
        cred, password = _credential(db, settings, body.credential_id)
        platform = "windows" if cred.kind == "winrm" else "linux"
        guide = next((p for p in guidance["platforms"] if p["platform"] == platform), None)  # type: ignore[index]
        if guide is None:
            raise HTTPException(status.HTTP_409_CONFLICT, tr("نوع حساب الدخول لا يناسب نظام هذا الجهاز (WinRM لويندوز، SSH للينكس)", "The credential type does not match this device OS (WinRM for Windows, SSH for Linux)"))
        commands = guide[body.section]
    if body.index >= len(commands):  # type: ignore[arg-type]
        raise not_found("الأمر")
    cmd = commands[body.index]  # type: ignore[index]
    if not is_executable(cmd["command"]):
        raise HTTPException(status.HTTP_409_CONFLICT, tr("هذا الأمر يفتح برنامجاً تفاعلياً؛ انسخه ونفّذه بنفسك", "This command opens an interactive program; copy and run it yourself"))
    try:
        script = fill_placeholders(cmd["command"], body.params)
    except RemoteError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    timeout = settings.remote_exec_timeout_seconds
    if cmd["run_on"] == "admin_pc":
        return _record(db, request, auth, asset=asset, cred=None, target="scanner", port=svc.port, section=body.section,
                       label=cmd["label_ar"], command=script, run=lambda: run_local_powershell(script, timeout))
    assert cred is not None
    return _record(db, request, auth, asset=asset, cred=cred, target=asset.current_ip or "", port=svc.port,
                   section=body.section, label=cmd["label_ar"], command=script,
                   run=lambda: _run_on_device(db, settings, cred, password, asset.current_ip or "", script))


@router.post("/credentials/{credential_id}/test", response_model=ExecutionOut)
def test_credential(credential_id: int, body: TestCredentialIn, request: Request,
                    auth: AuthContext = Depends(require("remote:verify")), db: Session = Depends(get_db)) -> RemoteExecution:
    settings: Settings = request.app.state.settings
    asset = _authorised_asset(db, settings, body.asset_id)
    cred, password = _credential(db, settings, credential_id)
    if cred.kind == "winrm":
        script = "$env:COMPUTERNAME; (Get-CimInstance Win32_OperatingSystem).Caption"
    else:
        script = 'hostname; uname -sr; (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || true'
    return _record(db, request, auth, asset=asset, cred=cred, target=asset.current_ip or "", port=None, section="test",
                   label=tr("اختبار الاتصال بالحساب", "Test account connection"), command=script,
                   run=lambda: _run_on_device(db, settings, cred, password, asset.current_ip or "", script))


class ConsoleIn(BaseModel):
    credential_id: int
    command: str = Field(min_length=1, max_length=4000)
    confirm: bool = False


@router.post("/assets/{asset_id}/console", response_model=ExecutionOut)
def console(asset_id: int, body: ConsoleIn, request: Request, auth: AuthContext = Depends(require("remote:change")),
            db: Session = Depends(get_db)) -> RemoteExecution:
    """Administrator console: run a typed command on a managed device (audited, output kept)."""
    if not body.confirm:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, tr("يجب تأكيد تنفيذ الأمر على الجهاز", "You must confirm running the command on the device"))
    settings: Settings = request.app.state.settings
    asset = _authorised_asset(db, settings, asset_id)
    cred, password = _credential(db, settings, body.credential_id)
    command = body.command.strip()
    return _record(db, request, auth, asset=asset, cred=cred, target=asset.current_ip or "", port=None, section="console",
                   label=tr("أمر مخصص من وحدة التحكم", "Custom command from the console"), command=command,
                   run=lambda: _run_on_device(db, settings, cred, password, asset.current_ip or "", command))


def _host_key_store(db: Session):  # type: ignore[no-untyped-def]
    def lookup(ip: str, port: int) -> HostKey | None:
        row = db.scalar(select(SshHostKey).where(SshHostKey.ip == ip, SshHostKey.port == port))
        return HostKey(row.key_type, row.fingerprint) if row else None

    def store(ip: str, port: int, key: HostKey) -> None:
        db.add(SshHostKey(ip=ip, port=port, key_type=key.key_type, fingerprint=key.fingerprint, first_seen=utcnow()))
        db.flush()

    return lookup, store


def _run_on_device(db: Session, settings: Settings, cred: Credential, password: str, ip: str, script: str):  # type: ignore[no-untyped-def]
    timeout = settings.remote_exec_timeout_seconds
    if cred.kind == "ssh":
        lookup, store = _host_key_store(db)
        return run_ssh(ip, cred.port, cred.username, password, script, timeout, lookup, store)
    return run_remote_powershell(ip, cred.username, password, ssl=cred.use_https, port=cred.port,
                                 verify_tls=cred.verify_tls, script=script, timeout=timeout)


@router.get("/ssh-host-keys")
def list_host_keys(_: AuthContext = Depends(require("remote:verify")), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return [{"id": k.id, "ip": k.ip, "port": k.port, "key_type": k.key_type, "fingerprint": k.fingerprint,
             "first_seen": k.first_seen.isoformat()} for k in db.scalars(select(SshHostKey).order_by(SshHostKey.ip))]


@router.delete("/ssh-host-keys/{key_id}", status_code=204)
def forget_host_key(key_id: int, request: Request, auth: AuthContext = Depends(require("credential:manage")),
                    db: Session = Depends(get_db)) -> Response:
    key = db.get(SshHostKey, key_id)
    if key is None:
        raise not_found("المفتاح")
    audit(db, request, "ssh_host_key.forget", auth=auth, details={"ip": key.ip, "port": key.port, "fingerprint": key.fingerprint})
    db.delete(key)
    db.commit()
    return Response(status_code=204)


@router.get("/assets/{asset_id}/executions", response_model=list[ExecutionOut])
def list_executions(asset_id: int, _: AuthContext = Depends(require("remote:verify")), db: Session = Depends(get_db)) -> list[RemoteExecution]:
    return list(db.scalars(
        select(RemoteExecution).where(RemoteExecution.asset_id == asset_id).order_by(RemoteExecution.id.desc()).limit(50)
    ))
