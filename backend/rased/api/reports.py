"""Report generation API: structured JSON, signed JSON download and a native Excel workbook."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, require
from rased.reports import build_report, build_workbook

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _report(request: Request, db: Session) -> dict[str, Any]:
    return build_report(db, request.app.state.settings)


def _integrity(report: dict[str, Any]) -> str:
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@router.get("/network")
def network_report(request: Request, auth: AuthContext = Depends(require("report:read")),
                   db: Session = Depends(get_db)) -> dict[str, Any]:
    """Full structured Arabic assessment report, with a SHA-256 integrity digest."""
    report = _report(request, db)
    report["meta"]["integrity_sha256"] = _integrity(report)
    audit(db, request, "report.generate", auth=auth, details={"format": "json"})
    db.commit()
    return report


@router.get("/network.json")
def network_report_download(request: Request, auth: AuthContext = Depends(require("report:read")),
                            db: Session = Depends(get_db)) -> Response:
    report = _report(request, db)
    report["meta"]["integrity_sha256"] = _integrity(report)
    audit(db, request, "report.generate", auth=auth, details={"format": "json-file"})
    db.commit()
    body = json.dumps(report, ensure_ascii=False, indent=2, default=str).encode("utf-8")
    return Response(content=body, media_type="application/json; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="rased-report.json"'})


@router.get("/network.xlsx")
def network_report_xlsx(request: Request, auth: AuthContext = Depends(require("report:read")),
                        db: Session = Depends(get_db)) -> Response:
    report = _report(request, db)
    report["meta"]["integrity_sha256"] = _integrity(report)
    data = build_workbook(report)
    audit(db, request, "report.generate", auth=auth, details={"format": "xlsx"})
    db.commit()
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="rased-report.xlsx"'},
    )
