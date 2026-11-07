"""Endpoint-agent API: enrollment-token management and the token-authenticated report ingest."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.agent_ingest import hash_token, ingest_report, new_token, normalize_report
from rasednet.i18n import get_lang, tr
from rasednet.api.deps import AuthContext, audit, client_ip, get_db, require
from rasednet.models import AgentToken, utcnow

router = APIRouter(prefix="/api/agents", tags=["agents"])


class TokenIn(BaseModel):
    label: str = Field(min_length=1, max_length=128)


@router.get("/tokens")
def list_tokens(_: AuthContext = Depends(require("user:manage")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.scalars(select(AgentToken).order_by(AgentToken.created_at.desc())).all()
    return [{"id": t.id, "label": t.label, "is_active": t.is_active,
             "created_at": t.created_at.isoformat(),
             "last_seen_at": t.last_seen_at.isoformat() if t.last_seen_at else None,
             "last_host": t.last_host} for t in rows]


@router.post("/tokens", status_code=201)
def create_token(body: TokenIn, request: Request, auth: AuthContext = Depends(require("user:manage")),
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    plaintext, digest = new_token()
    tok = AgentToken(label=body.label.strip(), token_hash=digest, created_by_id=auth.user.id, created_at=utcnow())
    db.add(tok)
    db.flush()
    audit(db, request, "agent.token.create", auth=auth, target_type="agent_token", target_id=tok.id,
          details={"label": tok.label})
    db.commit()
    # The plaintext token is returned exactly once.
    return {"id": tok.id, "label": tok.label, "token": plaintext}


@router.delete("/tokens/{token_id}", status_code=204)
def delete_token(token_id: int, request: Request, auth: AuthContext = Depends(require("user:manage")),
                 db: Session = Depends(get_db)) -> Response:
    tok = db.get(AgentToken, token_id)
    if tok is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, tr("الرمز غير موجود", "The token was not found"))
    db.delete(tok)
    audit(db, request, "agent.token.delete", auth=auth, target_type="agent_token", target_id=token_id)
    db.commit()
    return Response(status_code=204)


@router.post("/report")
def report(payload: dict[str, Any], request: Request, db: Session = Depends(get_db),
           x_agent_token: str | None = Header(default=None)) -> dict[str, Any]:
    """Token-authenticated ingest (no session). The agent sends ``X-Agent-Token``."""
    if not x_agent_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, tr("رمز الوكيل مفقود", "The agent token is missing"))
    tok = db.scalar(select(AgentToken).where(AgentToken.token_hash == hash_token(x_agent_token),
                                             AgentToken.is_active.is_(True)))
    if tok is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, tr("رمز وكيل غير صالح", "Invalid agent token"))
    try:
        normalized = normalize_report(payload)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    result = ingest_report(db, normalized)
    tok.last_seen_at = utcnow()
    tok.last_host = (normalized["hostname"] or normalized["ip"] or "")[:253]
    audit(db, request, "agent.report", actor_username=f"agent:{tok.label}"[:64], success=True,
          target_type="asset", target_id=result["asset_id"],
          details={"token_id": tok.id, "created": result["created"], "ip": client_ip(request)})
    db.commit()
    return result
