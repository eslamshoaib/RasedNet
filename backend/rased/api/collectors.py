"""Distributed-collector ingest API: a remote RASED collector forwards its inventory here.

Authenticated by a collector/agent enrollment token (``X-Agent-Token``) — no user session. The
payload is a batch of host reports; each is upserted centrally and tagged ``collector``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.agent_ingest import hash_token
from rased.api.deps import audit, client_ip, get_db
from rased.collectors import ingest_batch
from rased.models import AgentToken, utcnow

router = APIRouter(prefix="/api/collectors", tags=["collectors"])


@router.post("/report")
def collector_report(payload: dict[str, Any], request: Request, db: Session = Depends(get_db),
                     x_agent_token: str | None = Header(default=None)) -> dict[str, Any]:
    """Ingest a batch inventory report from a remote collector (token-authenticated)."""
    if not x_agent_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "رمز الجامع مفقود")
    tok = db.scalar(select(AgentToken).where(AgentToken.token_hash == hash_token(x_agent_token),
                                             AgentToken.is_active.is_(True)))
    if tok is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "رمز جامع غير صالح")
    try:
        stats = ingest_batch(db, payload, source="collector")
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    tok.last_seen_at = utcnow()
    tok.last_host = f"collector:{tok.label}"[:253]
    audit(db, request, "collector.report", actor_username=f"collector:{tok.label}"[:64], success=True,
          details={"token_id": tok.id, "stats": stats, "ip": client_ip(request)})
    db.commit()
    return stats
