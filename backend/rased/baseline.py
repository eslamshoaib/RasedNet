"""Approved-service baseline and unauthorised / rogue detection (spec §6).

The administrator maintains an allow-list of permitted services (``ServicePolicyRule``). Any
open service that matches no rule is reported as an *unauthorised service* alert; when it is
approved or closed, that alert resolves automatically. The engine also flags *rogue gateways*
(more than one default gateway on the same /24).

Pure, parameterised queries; no network activity.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.alerts import raise_alert
from rased.models import Alert, Asset, Service, ServicePolicyRule, utcnow

HIGH_EXPOSURES = frozenset({"remote_admin", "database", "directory"})


def is_authorized(port: int, protocol: str, device_type: str | None, rules: list[ServicePolicyRule]) -> bool:
    """A service is authorised if any rule matches it. NULL port/device_type in a rule = 'any'."""
    for r in rules:
        if r.protocol != protocol:
            continue
        if r.port is not None and r.port != port:
            continue
        if r.device_type is not None and r.device_type != (device_type or "unknown"):
            continue
        return True
    return False


def _subnet(ip: str | None) -> str | None:
    if not ip or ":" in ip:
        return ip
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


def evaluate(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Re-evaluate the whole inventory against the policy; raise/resolve alerts. Does not commit."""
    now = now or utcnow()
    rules = list(db.scalars(select(ServicePolicyRule)))
    assets = {a.id: a for a in db.scalars(select(Asset))}
    services = list(db.scalars(select(Service).where(Service.state == "open")))

    live_keys: set[str] = set()
    unauthorized = 0
    for svc in services:
        asset = assets.get(svc.asset_id)
        dtype = asset.device_type if asset else "unknown"
        if is_authorized(svc.port, svc.protocol, dtype, rules):
            continue
        unauthorized += 1
        key = f"unauthorized:{svc.asset_id}:{svc.port}/{svc.protocol}"
        live_keys.add(key)
        sev = "high" if svc.exposure_category in HIGH_EXPOSURES else "medium"
        ip = asset.current_ip if asset else "?"
        raise_alert(
            db, kind="unauthorized_service", severity=sev,
            title_ar=f"خدمة غير معتمدة: منفذ {svc.port}/{svc.protocol}",
            message_ar=f"المنفذ {svc.port}/{svc.protocol} ({svc.service_name}) مفتوح على {ip} وليس ضمن الخدمات المعتمدة.",
            dedup_key=key, now=now, asset_id=svc.asset_id,
            details={"port": svc.port, "protocol": svc.protocol, "service": svc.service_name,
                     "exposure": svc.exposure_category},
        )

    # Rogue gateways: more than one default gateway on the same /24.
    gw_by_subnet: dict[str, list[Asset]] = defaultdict(list)
    for a in assets.values():
        if a.is_gateway and a.current_ip:
            sub = _subnet(a.current_ip)
            if sub:
                gw_by_subnet[sub].append(a)
    rogue = 0
    for sub, gws in gw_by_subnet.items():
        key = f"rogue_gateway:{sub}"
        if len(gws) > 1:
            rogue += 1
            live_keys.add(key)
            ips = "، ".join(sorted(g.current_ip for g in gws if g.current_ip))
            raise_alert(
                db, kind="rogue_gateway", severity="high",
                title_ar=f"أكثر من بوابة على الشبكة {sub}",
                message_ar=f"رُصدت {len(gws)} بوابات على {sub}: {ips}. تحقّق من عدم وجود موجّه/راوتر غير مصرّح به.",
                dedup_key=key, now=now, details={"subnet": sub, "gateways": ips},
            )

    # Resolve any previously-open baseline alert that no longer applies.
    resolved = 0
    open_alerts = db.scalars(
        select(Alert).where(Alert.kind.in_(("unauthorized_service", "rogue_gateway")),
                            Alert.status.in_(("open", "acknowledged")))
    ).all()
    for al in open_alerts:
        if al.dedup_key not in live_keys:
            al.status = "resolved"
            al.resolved_at = now
            resolved += 1

    db.flush()
    return {"unauthorized": unauthorized, "rogue_gateways": rogue, "resolved": resolved,
            "rules": len(rules), "services": len(services)}


def seed_from_current(db: Session, created_by_id: int | None = None) -> dict[str, int]:
    """Bootstrap the allow-list from the currently-open services (distinct port/protocol)."""
    now = utcnow()
    existing = {(r.port, r.protocol, r.device_type) for r in db.scalars(select(ServicePolicyRule))}
    pairs = {(s.port, s.protocol) for s in db.scalars(select(Service).where(Service.state == "open"))}
    added = 0
    for port, protocol in sorted(pairs):
        if (port, protocol, None) in existing:
            continue
        db.add(ServicePolicyRule(port=port, protocol=protocol, device_type=None,
                                 note_ar="من خط الأساس الأولي", created_by_id=created_by_id, created_at=now))
        added += 1
    db.flush()
    return {"added": added, "total_pairs": len(pairs)}
