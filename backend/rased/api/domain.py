"""Directory (Active Directory / LDAP) intelligence API — authenticated, read-only."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, require
from rased.domain import DirectoryError, DirectoryQuery, enumerate_directory
from rased.models import Credential, utcnow
from rased.remote import VaultError, decrypt_secret

router = APIRouter(prefix="/api/directory", tags=["directory"])


class DirectoryQueryIn(BaseModel):
    credential_id: int | None = None  # None → bind as the current Windows user (Kerberos)
    host: str = Field(min_length=1, max_length=253)
    base_dn: str | None = Field(default=None, max_length=512)
    use_ssl: bool = False
    port: int | None = Field(default=None, ge=1, le=65535)
    scope: Literal["users", "groups", "computers", "all"] = "all"
    limit: int = Field(default=2000, ge=1, le=10000)


@router.get("/credentials")
def usable_credentials(_: AuthContext = Depends(require("directory:read")),
                       db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Vault accounts usable for a directory bind (any stored account; a WinRM/domain account is typical)."""
    from sqlalchemy import select
    creds = db.scalars(select(Credential)).all()
    return [{"id": c.id, "name": c.name, "username": c.username, "kind": c.kind} for c in creds]


def _run_directory_query(db: Session, request: Request, auth: AuthContext, body: DirectoryQueryIn,
                         audit_action: str) -> dict[str, Any]:
    """Shared: bind (vaulted account or current-user integrated) and enumerate the directory."""
    settings = request.app.state.settings
    integrated = body.credential_id is None
    cred = None
    username: str | None = None
    password: str | None = None
    verify = True
    if not integrated:
        cred = db.get(Credential, body.credential_id)
        if cred is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "بيانات الدخول غير موجودة")
        try:
            password = decrypt_secret(settings, cred.secret_encrypted)
        except VaultError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        username, verify = cred.username, cred.verify_tls

    port = body.port or (636 if body.use_ssl else 389)
    query = DirectoryQuery(host=body.host.strip(), port=port, use_ssl=body.use_ssl,
                           base_dn=(body.base_dn or None), scope=body.scope, page_limit=body.limit)
    try:
        result = enumerate_directory(query, username, password, integrated=integrated,
                                     verify_tls=verify, timeout=15)
    except DirectoryError as exc:
        audit(db, request, audit_action, auth=auth, success=False,
              details={"host": query.host, "scope": query.scope, "integrated": integrated, "error": str(exc)[:200]})
        db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    if cred is not None:
        cred.last_used_at = utcnow()
    audit(db, request, audit_action, auth=auth, target_type="credential", target_id=cred.id if cred else None,
          details={"host": query.host, "scope": query.scope, "integrated": integrated,
                   "base_dn": result["domain"]["base_dn"], "counts": result["counts"]})
    db.commit()
    return result


@router.post("/query")
def query_directory(body: DirectoryQueryIn, request: Request,
                    auth: AuthContext = Depends(require("directory:read")),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    return _run_directory_query(db, request, auth, body, "directory.query")


@router.post("/attack-paths")
def attack_paths(body: DirectoryQueryIn, request: Request,
                 auth: AuthContext = Depends(require("directory:read")),
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    """Analyse which accounts can reach privileged groups (directly or via nested membership)."""
    from rased.attackpaths import summarize
    result = _run_directory_query(db, request, auth, body, "directory.attack_paths")
    analysis = summarize(result["users"], result["groups"])
    analysis["domain"] = result["domain"]
    analysis["counts"] = {"users": result["counts"]["users"], "groups": result["counts"]["groups"]}
    return analysis


@router.get("/discover")
def discover(_: AuthContext = Depends(require("directory:read")),
             db: Session = Depends(get_db)) -> dict[str, Any]:
    """Auto-detect the domain, base DN and candidate domain controllers (host env + DNS + inventory)."""
    from sqlalchemy import select

    from rased.domain import discover_domain
    from rased.models import Asset, Service

    rows = db.execute(
        select(Asset.current_ip).join(Service, Service.asset_id == Asset.id)
        .where(Service.state == "open", Service.port.in_((389, 636, 88, 3268)), Asset.current_ip.is_not(None))
        .distinct()
    ).all()
    candidates = [r[0] for r in rows if r[0]]
    return discover_domain(candidates)
