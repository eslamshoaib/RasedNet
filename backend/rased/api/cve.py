"""Vulnerability intelligence API: import an offline CVE feed, correlate, and browse findings."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, require
from rased.cve import correlate, import_epss, import_feed, import_kev, priority_band, priority_score
from rased.models import Asset, AssetVulnerability, CveEntry

router = APIRouter(prefix="/api/cve", tags=["vulnerabilities"])

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


@router.get("/summary")
def summary(_: AuthContext = Depends(require("asset:read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    total_cves = db.scalar(select(func.count()).select_from(CveEntry)) or 0
    by_sev: dict[str, int] = {}
    rows = db.execute(
        select(AssetVulnerability.severity, func.count())
        .where(AssetVulnerability.status == "open").group_by(AssetVulnerability.severity)
    ).all()
    for sev, n in rows:
        by_sev[sev] = int(n)
    affected_assets = db.scalar(
        select(func.count(func.distinct(AssetVulnerability.asset_id))).where(AssetVulnerability.status == "open")
    ) or 0
    # Known-exploited (KEV) open findings: CVE flagged kev and an open vulnerability for it.
    kev_cves = {c.cve_id for c in db.scalars(select(CveEntry).where(CveEntry.kev.is_(True)))}
    open_cve_ids = db.scalars(select(AssetVulnerability.cve_id).where(AssetVulnerability.status == "open")).all()
    kev_open = sum(1 for cid in open_cve_ids if cid in kev_cves)
    return {
        "cve_entries": int(total_cves),
        "kev_entries": len(kev_cves),
        "open_findings": sum(by_sev.values()),
        "kev_open_findings": kev_open,
        "by_severity": [{"severity": s, "count": by_sev.get(s, 0)}
                        for s in ("critical", "high", "medium", "low", "unknown") if by_sev.get(s)],
        "affected_assets": int(affected_assets),
    }


@router.get("/vulnerabilities")
def list_vulnerabilities(status_filter: str = "open", severity: str | None = None,
                         asset_id: int | None = None, limit: int = 500,
                         _: AuthContext = Depends(require("asset:read")),
                         db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    q = select(AssetVulnerability)
    if status_filter != "all":
        q = q.where(AssetVulnerability.status == status_filter)
    if severity:
        q = q.where(AssetVulnerability.severity == severity)
    if asset_id is not None:
        q = q.where(AssetVulnerability.asset_id == asset_id)
    rows = list(db.scalars(q.limit(min(limit, 2000))))
    assets = {a.id: a for a in db.scalars(select(Asset).where(Asset.id.in_({r.asset_id for r in rows})))} if rows else {}
    cves = {c.cve_id: c for c in db.scalars(select(CveEntry).where(CveEntry.cve_id.in_({r.cve_id for r in rows})))} if rows else {}
    out = []
    for r in rows:
        a = assets.get(r.asset_id)
        c = cves.get(r.cve_id)
        epss = c.epss if c else 0.0
        kev = bool(c.kev) if c else False
        prio = priority_score(r.cvss_score, epss, kev)
        out.append({
            "id": r.id, "asset_id": r.asset_id,
            "asset_ip": a.current_ip if a else None,
            "asset_name": (a.display_name or a.hostname) if a else None,
            "cve_id": r.cve_id, "product": r.product, "version": r.version, "matched_on": r.matched_on,
            "cvss_score": r.cvss_score, "severity": r.severity, "status": r.status,
            "epss": round(epss, 4), "kev": kev, "kev_date": c.kev_date if c else None,
            "priority": prio, "priority_band": priority_band(prio),
            "description": (c.description_ar or c.description) if c else "",
            "references": c.references if c else [],
        })
    # Sort by the prioritisation score (KEV + EPSS + CVSS), highest first.
    out.sort(key=lambda d: d["priority"], reverse=True)
    return out


@router.get("/export")
def export_feed(request: Request, auth: AuthContext = Depends(require("report:read")),
                db: Session = Depends(get_db)) -> Response:
    """Download the current CVE feed as editable JSON (IT edits/adds entries and re-imports)."""
    entries = db.scalars(select(CveEntry).order_by(CveEntry.cve_id)).all()
    cves = [{
        "cve_id": c.cve_id, "cvss_score": c.cvss_score, "severity": c.severity,
        "description": c.description, "description_ar": c.description_ar, "published": c.published,
        "affected": c.affected or [], "references": c.references or [],
    } for c in entries]
    if not cves:
        # An editable template so IT can start from scratch.
        cves = [{
            "cve_id": "CVE-YYYY-NNNNN", "cvss_score": 9.8, "severity": "critical",
            "description": "وصف الثغرة", "description_ar": "", "published": "2026-01-01",
            "affected": [{"vendor": "", "product": "OpenSSH", "version_start": "0", "version_end": "8.0", "version_exact": ""}],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN"],
        }]
    body = json.dumps({"cves": cves}, ensure_ascii=False, indent=2).encode("utf-8")
    audit(db, request, "cve.export", auth=auth, details={"count": len(entries)})
    db.commit()
    return Response(content=body, media_type="application/json; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="rased-cve-feed.json"'})


@router.post("/import")
def import_cve_feed(request: Request, payload: Any = Body(...),
                    auth: AuthContext = Depends(require("data:manage")),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        stats = import_feed(db, payload)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    result = correlate(db)
    audit(db, request, "cve.import", auth=auth, details={"feed": stats, "correlation": result})
    db.commit()
    return {"import": stats, "correlation": result}


@router.post("/epss")
async def import_epss_feed(request: Request, auth: AuthContext = Depends(require("data:manage")),
                          db: Session = Depends(get_db)) -> dict[str, int]:
    """Import a FIRST EPSS CSV (raw body: cve,epss,percentile). Enriches existing CVE entries."""
    body = (await request.body()).decode("utf-8", "replace")
    if not body.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "لم يُرسل أي ملف.")
    stats = import_epss(db, body)
    audit(db, request, "cve.epss", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/kev")
def import_kev_feed(request: Request, payload: Any = Body(...),
                    auth: AuthContext = Depends(require("data:manage")),
                    db: Session = Depends(get_db)) -> dict[str, int]:
    """Import the CISA KEV catalog (JSON). Flags matching CVE entries as known-exploited."""
    try:
        stats = import_kev(db, payload)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit(db, request, "cve.kev", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/correlate")
def run_correlation(request: Request, auth: AuthContext = Depends(require("data:manage")),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    result = correlate(db)
    audit(db, request, "cve.correlate", auth=auth, details=result)
    db.commit()
    return result
