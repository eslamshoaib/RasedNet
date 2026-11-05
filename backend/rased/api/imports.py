"""Import adapters API: bring external scan data (currently Nmap XML) into the inventory."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from rased.api.deps import AuthContext, audit, get_db, require
from rased.importers import (
    ImportError_,
    csv_import,
    dhcp_import,
    greenbone_import,
    nessus_import,
    osquery_import,
    wazuh_import,
)
from rased.nmap_import import NmapImportError, import_hosts, parse_nmap_xml

router = APIRouter(prefix="/api/imports", tags=["imports"])

MAX_UPLOAD = 25 * 1024 * 1024  # 25 MB


async def _read_body(request: Request) -> bytes:
    body = await request.body()
    if not body:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "لم يُرسل أي ملف.")
    if len(body) > MAX_UPLOAD:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "الملف أكبر من الحد المسموح (25 ميجابايت).")
    return body


@router.post("/nmap")
async def import_nmap(request: Request, auth: AuthContext = Depends(require("scan:run")),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import an Nmap XML result file (raw body). No scanning is performed."""
    body = await _read_body(request)
    try:
        hosts = parse_nmap_xml(body)
    except NmapImportError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    stats = import_hosts(db, hosts)
    audit(db, request, "import.nmap", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/dhcp")
async def import_dhcp(request: Request, auth: AuthContext = Depends(require("scan:run")),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import DHCP leases (ISC dhcpd.leases or dnsmasq.leases)."""
    body = await _read_body(request)
    try:
        stats = dhcp_import(db, body.decode("utf-8", "replace"))
    except ImportError_ as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit(db, request, "import.dhcp", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/csv")
async def import_csv(request: Request, auth: AuthContext = Depends(require("scan:run")),
                     db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import a device inventory CSV (wireless controller / MDM / spreadsheet export)."""
    body = await _read_body(request)
    try:
        stats = csv_import(db, body.decode("utf-8", "replace"))
    except ImportError_ as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit(db, request, "import.csv", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/greenbone")
async def import_greenbone(request: Request, auth: AuthContext = Depends(require("scan:run")),
                           db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import a Greenbone/OpenVAS XML report as vulnerabilities on known assets."""
    body = await _read_body(request)
    try:
        stats = greenbone_import(db, body)
    except ImportError_ as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit(db, request, "import.greenbone", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/nessus")
async def import_nessus(request: Request, auth: AuthContext = Depends(require("scan:run")),
                        db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import a Nessus .nessus XML report as vulnerabilities on known assets."""
    body = await _read_body(request)
    try:
        stats = nessus_import(db, body)
    except ImportError_ as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit(db, request, "import.nessus", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/wazuh")
async def import_wazuh(request: Request, auth: AuthContext = Depends(require("scan:run")),
                       db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import a Wazuh vulnerability export (JSON) as vulnerabilities on known assets."""
    body = await _read_body(request)
    try:
        stats = wazuh_import(db, body)
    except ImportError_ as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit(db, request, "import.wazuh", auth=auth, details=stats)
    db.commit()
    return stats


@router.post("/osquery")
async def import_osquery(request: Request, auth: AuthContext = Depends(require("scan:run")),
                         db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import osquery results (JSON) as device inventory."""
    body = await _read_body(request)
    try:
        stats = osquery_import(db, body)
    except ImportError_ as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit(db, request, "import.osquery", auth=auth, details=stats)
    db.commit()
    return stats
