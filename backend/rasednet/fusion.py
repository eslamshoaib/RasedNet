"""Fusion Tables (جداول الدمج والتحليل): structured, database-backed cross-source queries.

Queries are described by a validated JSON structure (filters / columns / sort / grouping);
arbitrary SQL is never accepted. Every filter becomes a parameterised SQLAlchemy clause.
"""

from __future__ import annotations

import csv
import io
import ipaddress
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session

from rasednet.discovery.fingerprint import DEVICE_TYPES, OS_FAMILIES
from rasednet.models import Alert, Asset, Service, utcnow

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
EXPOSURES = ["remote_admin", "file_sharing", "web", "database", "directory", "mail", "printing",
             "infrastructure", "media", "iot", "mobile", "other"]

Column = Literal[
    "ip", "hostname", "display_name", "mac", "vendor", "model", "workgroup", "is_gateway", "device_type", "os_family", "status", "criticality",
    "open_ports", "open_service_count", "exposures", "services", "open_alerts", "max_alert_severity",
    "first_seen", "last_seen",
]
SortKey = Literal["ip", "hostname", "device_type", "os_family", "status", "first_seen", "last_seen", "open_service_count"]
GroupKey = Literal["device_type", "os_family", "status", "vendor", "model", "workgroup", "criticality", "subnet24", "port", "exposure", "max_alert_severity"]

DEFAULT_COLUMNS: list[Column] = ["ip", "hostname", "device_type", "os_family", "status", "open_ports", "open_alerts", "last_seen"]

COLUMN_LABELS_AR: dict[str, str] = {
    "ip": "عنوان IP", "hostname": "اسم الجهاز", "display_name": "الاسم المعتمد", "mac": "عنوان MAC",
    "vendor": "الشركة المصنعة", "model": "الطراز", "workgroup": "مجموعة العمل / المجال", "is_gateway": "بوابة الشبكة",
    "device_type": "نوع الجهاز", "os_family": "نظام التشغيل", "status": "الحالة",
    "criticality": "الأهمية", "open_ports": "المنافذ المفتوحة", "open_service_count": "عدد الخدمات المفتوحة",
    "exposures": "فئات التعرض", "services": "الخدمات", "open_alerts": "التنبيهات المفتوحة",
    "max_alert_severity": "أعلى خطورة", "first_seen": "أول ظهور", "last_seen": "آخر ظهور",
}
COLUMN_LABELS_EN: dict[str, str] = {
    "ip": "IP address", "hostname": "Hostname", "display_name": "Display name", "mac": "MAC address",
    "vendor": "Vendor", "model": "Model", "workgroup": "Workgroup / domain", "is_gateway": "Gateway",
    "device_type": "Device type", "os_family": "Operating system", "status": "Status",
    "criticality": "Criticality", "open_ports": "Open ports", "open_service_count": "Open service count",
    "exposures": "Exposure categories", "services": "Services", "open_alerts": "Open alerts",
    "max_alert_severity": "Max severity", "first_seen": "First seen", "last_seen": "Last seen",
}


class FusionFilters(BaseModel):
    text: str | None = Field(default=None, max_length=128)
    ip_cidr: str | None = Field(default=None, max_length=64)
    statuses: list[Literal["online", "offline", "unknown"]] = Field(default_factory=list)
    device_types: list[str] = Field(default_factory=list, max_length=len(DEVICE_TYPES))
    os_families: list[str] = Field(default_factory=list, max_length=len(OS_FAMILIES))
    criticality: list[Literal["low", "normal", "high", "critical"]] = Field(default_factory=list)
    vendor_contains: str | None = Field(default=None, max_length=128)
    open_ports_all: list[int] = Field(default_factory=list, max_length=64)
    open_ports_any: list[int] = Field(default_factory=list, max_length=256)
    open_ports_none: list[int] = Field(default_factory=list, max_length=64)
    exposures_any: list[str] = Field(default_factory=list, max_length=len(EXPOSURES))
    service_contains: str | None = Field(default=None, max_length=128)
    has_open_alerts: bool | None = None
    min_alert_severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    mac_randomized: bool | None = None
    min_open_services: int | None = Field(default=None, ge=0, le=65535)
    max_open_services: int | None = Field(default=None, ge=0, le=65535)
    first_seen_within_days: int | None = Field(default=None, ge=0, le=3650)
    not_seen_for_days: int | None = Field(default=None, ge=0, le=3650)

    @field_validator("device_types")
    @classmethod
    def _dt(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if x not in DEVICE_TYPES]
        if bad:
            raise ValueError(f"unknown device type: {bad[0]}")
        return v

    @field_validator("os_families")
    @classmethod
    def _os(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if x not in OS_FAMILIES]
        if bad:
            raise ValueError(f"unknown OS family: {bad[0]}")
        return v

    @field_validator("exposures_any")
    @classmethod
    def _exp(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if x not in EXPOSURES]
        if bad:
            raise ValueError(f"unknown exposure: {bad[0]}")
        return v

    @field_validator("open_ports_all", "open_ports_any", "open_ports_none")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in v):
            raise ValueError("port out of range")
        return sorted(set(v))

    @field_validator("ip_cidr")
    @classmethod
    def _cidr(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        return str(ipaddress.ip_network(v.strip(), strict=False))


class FusionQuery(BaseModel):
    filters: FusionFilters = Field(default_factory=FusionFilters)
    columns: list[Column] = Field(default_factory=lambda: list(DEFAULT_COLUMNS), min_length=1, max_length=20)
    sort: SortKey = "ip"
    order: Literal["asc", "desc"] = "asc"
    group_by: GroupKey | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)


def _open_service_exists(*conditions: Any) -> Any:
    return exists().where(Service.asset_id == Asset.id, Service.state == "open", *conditions)


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _open_count_subquery() -> Any:
    return (
        select(func.count(Service.id))
        .where(Service.asset_id == Asset.id, Service.state == "open")
        .correlate(Asset)
        .scalar_subquery()
    )


def _where(f: FusionFilters) -> list[Any]:
    clauses: list[Any] = []
    now = utcnow()
    if f.text and f.text.strip():
        p = _like(f.text.strip())
        clauses.append(or_(*(col.ilike(p, escape="\\") for col in (
            Asset.current_ip, Asset.hostname, Asset.mac, Asset.vendor, Asset.display_name, Asset.netbios_name, Asset.model))))
    if f.statuses:
        clauses.append(Asset.status.in_(f.statuses))
    if f.device_types:
        clauses.append(Asset.device_type.in_(f.device_types))
    if f.os_families:
        clauses.append(Asset.os_family.in_(f.os_families))
    if f.criticality:
        clauses.append(Asset.criticality.in_(f.criticality))
    if f.vendor_contains and f.vendor_contains.strip():
        clauses.append(Asset.vendor.ilike(_like(f.vendor_contains.strip()), escape="\\"))
    for port in f.open_ports_all:
        clauses.append(_open_service_exists(Service.port == port))
    if f.open_ports_any:
        clauses.append(_open_service_exists(Service.port.in_(f.open_ports_any)))
    for port in f.open_ports_none:
        clauses.append(~_open_service_exists(Service.port == port))
    if f.exposures_any:
        clauses.append(_open_service_exists(Service.exposure_category.in_(f.exposures_any)))
    if f.service_contains and f.service_contains.strip():
        p = _like(f.service_contains.strip())
        clauses.append(_open_service_exists(or_(
            Service.service_name.ilike(p, escape="\\"), Service.product.ilike(p, escape="\\"),
            Service.banner.ilike(p, escape="\\"))))
    open_alert = exists().where(Alert.asset_id == Asset.id, Alert.status == "open")
    if f.has_open_alerts is True:
        clauses.append(open_alert)
    elif f.has_open_alerts is False:
        clauses.append(~open_alert)
    if f.min_alert_severity:
        allowed = SEVERITY_ORDER[SEVERITY_ORDER.index(f.min_alert_severity):]
        clauses.append(exists().where(Alert.asset_id == Asset.id, Alert.status == "open", Alert.severity.in_(allowed)))
    if f.mac_randomized is not None:
        clauses.append(Asset.mac_randomized.is_(f.mac_randomized))
    if f.min_open_services is not None:
        clauses.append(_open_count_subquery() >= f.min_open_services)
    if f.max_open_services is not None:
        clauses.append(_open_count_subquery() <= f.max_open_services)
    if f.first_seen_within_days is not None:
        clauses.append(Asset.first_seen >= now - timedelta(days=f.first_seen_within_days))
    if f.not_seen_for_days is not None:
        clauses.append(Asset.last_seen <= now - timedelta(days=f.not_seen_for_days))
    return clauses


def _ip_key(ip: str | None) -> tuple[int, int]:
    if not ip:
        return (9, 0)
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (9, 0)


def matching_assets(db: Session, q: FusionQuery) -> list[tuple[int, str | None]]:
    """(asset id, ip) of every match, in the requested order."""
    sort_cols = {
        "hostname": Asset.hostname, "device_type": Asset.device_type, "os_family": Asset.os_family,
        "status": Asset.status, "first_seen": Asset.first_seen, "last_seen": Asset.last_seen,
        "open_service_count": _open_count_subquery(), "ip": Asset.id,
    }
    col = sort_cols[q.sort]
    stmt = select(Asset.id, Asset.current_ip).where(and_(*_where(q.filters)))
    stmt = stmt.order_by(col.asc() if q.order == "asc" else col.desc(), Asset.id)
    rows = [(r[0], r[1]) for r in db.execute(stmt)]
    if q.filters.ip_cidr:
        net = ipaddress.ip_network(q.filters.ip_cidr)
        rows = [(i, ip) for i, ip in rows if ip and _in_net(ip, net)]
    if q.sort == "ip":  # numeric, not lexical, IP ordering
        rows.sort(key=lambda r: _ip_key(r[1]), reverse=q.order == "desc")
    return rows


def _in_net(ip: str, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def _details(db: Session, ids: list[int]) -> dict[int, dict[str, Any]]:
    if not ids:
        return {}
    assets = {a.id: a for a in db.scalars(select(Asset).where(Asset.id.in_(ids)))}
    ports: dict[int, list[int]] = defaultdict(list)
    exposures: dict[int, set[str]] = defaultdict(set)
    services: dict[int, list[str]] = defaultdict(list)
    for asset_id, port, name, product, version, exposure in db.execute(
        select(Service.asset_id, Service.port, Service.service_name, Service.product, Service.version, Service.exposure_category)
        .where(Service.asset_id.in_(ids), Service.state == "open").order_by(Service.port)
    ):
        ports[asset_id].append(port)
        exposures[asset_id].add(exposure)
        services[asset_id].append(f"{port}/{name}" + (f" ({product}{' ' + version if version else ''})" if product else ""))
    alerts_count: Counter[int] = Counter()
    max_sev: dict[int, str] = {}
    for asset_id, severity in db.execute(select(Alert.asset_id, Alert.severity).where(Alert.asset_id.in_(ids), Alert.status == "open")):
        alerts_count[asset_id] += 1
        if asset_id not in max_sev or SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(max_sev[asset_id]):
            max_sev[asset_id] = severity
    out: dict[int, dict[str, Any]] = {}
    for aid, a in assets.items():
        out[aid] = {
            "id": aid, "ip": a.current_ip, "hostname": a.hostname, "display_name": a.display_name, "mac": a.mac,
            "vendor": a.vendor, "model": a.model, "workgroup": a.workgroup, "is_gateway": a.is_gateway,
            "device_type": a.device_type, "os_family": a.os_family, "status": a.status,
            "criticality": a.criticality, "open_ports": ports.get(aid, []), "open_service_count": len(ports.get(aid, [])),
            "exposures": sorted(exposures.get(aid, set())), "services": services.get(aid, []),
            "open_alerts": alerts_count.get(aid, 0), "max_alert_severity": max_sev.get(aid),
            "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(),
        }
    return out


def _groups(db: Session, ids: list[int], key: str) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    if key in ("port", "exposure"):
        col = Service.port if key == "port" else Service.exposure_category
        for i in range(0, len(ids), 1000):
            batch = ids[i:i + 1000]
            for value, n in db.execute(
                select(col, func.count(func.distinct(Service.asset_id)))
                .where(Service.asset_id.in_(batch), Service.state == "open").group_by(col)
            ):
                counts[str(value)] += int(n)
    else:
        details = {}
        for i in range(0, len(ids), 1000):
            details.update(_details(db, ids[i:i + 1000]))
        for d in details.values():
            if key == "subnet24":
                ip = d["ip"]
                value = str(ipaddress.ip_network(f"{ip}/24", strict=False)) if ip and ":" not in ip else "—"
            else:
                value = d.get(key) or "—"
            counts[str(value)] += 1
    return [{"key": k, "count": n} for k, n in counts.most_common()]


def run_query(db: Session, q: FusionQuery) -> dict[str, Any]:
    matches = matching_assets(db, q)
    ids = [i for i, _ in matches]
    page_ids = ids[(q.page - 1) * q.page_size: q.page * q.page_size]
    details = _details(db, page_ids)
    rows = [{c: details[i][c] for c in ["id", *q.columns]} for i in page_ids if i in details]
    result: dict[str, Any] = {"total": len(ids), "page": q.page, "page_size": q.page_size, "columns": q.columns, "rows": rows}
    if q.group_by:
        result["group_by"] = q.group_by
        result["groups"] = _groups(db, ids, q.group_by)
    return result


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        from rasednet.i18n import get_lang
        return ("Yes" if value else "No") if get_lang() == "en" else ("نعم" if value else "لا")
    if isinstance(value, list):
        from rasednet.i18n import get_lang
        return (", " if get_lang() == "en" else "، ").join(str(v) for v in value)
    return str(value)


def export_csv(db: Session, q: FusionQuery, limit: int = 50_000) -> tuple[str, int]:
    """UTF-8 CSV with BOM (Excel opens Arabic correctly). Returns (text, row count)."""
    ids = [i for i, _ in matching_assets(db, q)][:limit]
    buffer = io.StringIO()
    buffer.write("﻿")
    writer = csv.writer(buffer)
    from rasednet.i18n import get_lang
    _labels = COLUMN_LABELS_EN if get_lang() == "en" else COLUMN_LABELS_AR
    writer.writerow([_labels.get(c, c) for c in q.columns])
    for i in range(0, len(ids), 1000):
        batch = ids[i:i + 1000]
        details = _details(db, batch)
        for aid in batch:
            if aid in details:
                # Defuse spreadsheet formula injection from device-supplied text.
                writer.writerow([_safe_csv(_cell(details[aid][c])) for c in q.columns])
    return buffer.getvalue(), len(ids)


def _safe_csv(text: str) -> str:
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
