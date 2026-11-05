"""Discovery diagnostics API: explain why a given IP is or isn't discoverable."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, require
from rased.diagnostics import reachability
from rased.scanning import find_scope_for_ip

router = APIRouter(prefix="/api/diagnostics", tags=["diagnostics"])


class ReachabilityIn(BaseModel):
    ip: str = Field(min_length=1, max_length=45)


@router.post("/reachability")
def check_reachability(body: ReachabilityIn, request: Request,
                       auth: AuthContext = Depends(require("scope:read")),
                       db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        ip = str(ipaddress.ip_address(body.ip.strip()))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "عنوان IP غير صالح") from exc
    settings = request.app.state.settings
    in_scope = find_scope_for_ip(db, settings, ip) is not None
    result = asyncio.run(reachability(ip, in_scope=in_scope))
    audit(db, request, "diagnostics.reachability", auth=auth,
          details={"ip": ip, "verdict": result["verdict"], "reachable": result["reachable"]})
    db.commit()
    return result
