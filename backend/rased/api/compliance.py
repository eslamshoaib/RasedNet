"""Compliance framework evaluation API (offline, read-only)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, require
from rased.compliance import FRAMEWORKS, evaluate_all, evaluate_framework

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


@router.get("/frameworks")
def list_frameworks(_: AuthContext = Depends(require("report:read"))) -> list[dict[str, str]]:
    return [{"key": k, "name_ar": v} for k, v in FRAMEWORKS.items()]


@router.get("/{framework}")
def framework_report(framework: str, _: AuthContext = Depends(require("report:read")),
                     db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        return evaluate_framework(db, framework)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "إطار امتثال غير معروف") from exc


@router.get("/{framework}/export")
def framework_export(framework: str, request: Request, auth: AuthContext = Depends(require("report:read")),
                     db: Session = Depends(get_db)) -> Response:
    try:
        report = evaluate_all(db) if framework == "all" else evaluate_framework(db, framework)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "إطار امتثال غير معروف") from exc
    audit(db, request, "compliance.export", auth=auth, details={"framework": framework})
    db.commit()
    body = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    return Response(content=body, media_type="application/json; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="rased-compliance-{framework}.json"'})
