"""Offline CVE intelligence: import a vulnerability feed and correlate it with discovered services.

Fully offline. The operator imports a JSON feed (RasedNet's own compact format, tolerant of a
simplified NVD-style shape). Correlation matches each open service's product + version against
each CVE's affected-product rules, entirely in Python (no external calls, no version guessing
beyond the declared ranges), and records the matches as ``AssetVulnerability`` rows.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.models import AssetVulnerability, CveEntry, Service, utcnow

_VER_RE = re.compile(r"\d+|[A-Za-z]+")


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def version_key(version: str) -> tuple[Any, ...]:
    """A comparable key for a dotted version string (numbers compare as numbers)."""
    parts: list[Any] = []
    for token in _VER_RE.findall(version or ""):
        parts.append((0, int(token)) if token.isdigit() else (1, token.lower()))
    return tuple(parts)


def version_in_range(version: str, *, start: str | None, end: str | None, exact: str | None) -> bool:
    """Is ``version`` matched by a rule? start is inclusive, end is exclusive."""
    if exact:
        return version_key(version) == version_key(exact)
    if not version:
        return False
    v = version_key(version)
    if start and v < version_key(start):
        return False
    if end and v >= version_key(end):
        return False
    return True


def _product_matches(service_product: str, rule_product: str) -> bool:
    sp = (service_product or "").strip().lower()
    rp = (rule_product or "").strip().lower()
    if not sp or not rp:
        return False
    return sp == rp or rp in sp or sp in rp


def match_entry(product: str, version: str, affected: list[dict[str, Any]]) -> str | None:
    """Return a human 'matched_on' string if any affected rule matches, else None."""
    for rule in affected:
        if not _product_matches(product, str(rule.get("product", ""))):
            continue
        start = rule.get("version_start") or None
        end = rule.get("version_end") or None
        exact = rule.get("version_exact") or None
        if not (start or end or exact):
            return f"{rule.get('product')} (كل الإصدارات)"
        if version and version_in_range(version, start=start, end=end, exact=exact):
            label = exact or f"{start or '*'}–{end or '*'}"
            return f"{rule.get('product')} {label}"
        if not version:
            return f"{rule.get('product')} (الإصدار غير معروف)"
    return None


# --- feed import -------------------------------------------------------------------------


def normalize_feed_entry(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Accept RasedNet's compact format and a simplified NVD-ish shape; return a normalized dict."""
    cve_id = raw.get("cve_id") or raw.get("id") or raw.get("cve")
    if isinstance(cve_id, dict):  # NVD: {"cve": {"id": ...}}
        cve_id = cve_id.get("id")
    if not cve_id or not isinstance(cve_id, str):
        return None

    score = raw.get("cvss_score")
    if score is None:
        # tolerate {"cvss": 7.5} or an NVD metrics block
        score = raw.get("cvss")
    try:
        score = float(score) if score is not None else 0.0
    except (TypeError, ValueError):
        score = 0.0

    affected = raw.get("affected") or []
    norm_affected: list[dict[str, Any]] = []
    for a in affected:
        if isinstance(a, str):  # a bare "vendor:product" or "product"
            norm_affected.append({"product": a.split(":")[-1]})
        elif isinstance(a, dict):
            norm_affected.append({
                "vendor": a.get("vendor", ""),
                "product": a.get("product", ""),
                "version_start": a.get("version_start") or a.get("versionStartIncluding"),
                "version_end": a.get("version_end") or a.get("versionEndExcluding"),
                "version_exact": a.get("version_exact") or a.get("version"),
            })
    return {
        "cve_id": cve_id.strip(),
        "description": str(raw.get("description", ""))[:4000],
        "description_ar": str(raw.get("description_ar", ""))[:4000],
        "cvss_score": score,
        "severity": raw.get("severity") or severity_from_cvss(score),
        "published": str(raw.get("published", "")) or None,
        "affected": norm_affected,
        "references": [str(r) for r in (raw.get("references") or [])][:20],
    }


def import_feed(db: Session, feed: Any) -> dict[str, int]:
    """Upsert CVE entries from a parsed feed (a list, or {'cves'|'vulnerabilities': [...]} )."""
    if isinstance(feed, dict):
        items = feed.get("cves") or feed.get("vulnerabilities") or feed.get("items") or []
    else:
        items = feed
    if not isinstance(items, list):
        raise ValueError("صيغة التغذية غير صالحة: المتوقع قائمة من الثغرات.")

    added = updated = skipped = 0
    existing = {c.cve_id: c for c in db.scalars(select(CveEntry))}
    for raw in items:
        if not isinstance(raw, dict):
            skipped += 1
            continue
        norm = normalize_feed_entry(raw)
        if norm is None:
            skipped += 1
            continue
        entry = existing.get(norm["cve_id"])
        if entry is None:
            entry = CveEntry(cve_id=norm["cve_id"], imported_at=utcnow())
            db.add(entry)
            existing[norm["cve_id"]] = entry
            added += 1
        else:
            updated += 1
        entry.description = norm["description"]
        entry.description_ar = norm["description_ar"]
        entry.cvss_score = norm["cvss_score"]
        entry.severity = norm["severity"]
        entry.published = norm["published"]
        entry.affected = norm["affected"]
        entry.references = norm["references"]
        entry.imported_at = utcnow()
    db.flush()
    return {"added": added, "updated": updated, "skipped": skipped, "total": added + updated}


# --- correlation -------------------------------------------------------------------------


def correlate(db: Session, *, only_asset_id: int | None = None) -> dict[str, int]:
    """Match open services against imported CVEs and (re)build AssetVulnerability rows."""
    entries = list(db.scalars(select(CveEntry)))
    # Index affected rules by product keyword for a cheaper scan.
    now = utcnow()
    services_q = select(Service).where(Service.state == "open")
    if only_asset_id is not None:
        services_q = services_q.where(Service.asset_id == only_asset_id)
    services = list(db.scalars(services_q))

    existing = {(v.asset_id, v.service_id, v.cve_id): v
                for v in db.scalars(select(AssetVulnerability))}
    matched = 0
    seen_keys: set[tuple[int, int | None, str]] = set()
    for svc in services:
        product = svc.product or svc.service_name or ""
        version = svc.version or ""
        if not product:
            continue
        for entry in entries:
            matched_on = match_entry(product, version, entry.affected or [])
            if not matched_on:
                continue
            key = (svc.asset_id, svc.id, entry.cve_id)
            seen_keys.add(key)
            row = existing.get(key)
            if row is None:
                row = AssetVulnerability(asset_id=svc.asset_id, service_id=svc.id, cve_id=entry.cve_id,
                                         first_seen=now)
                db.add(row)
                existing[key] = row
            row.product = product[:128]
            row.version = version[:64] or None
            row.matched_on = matched_on[:128]
            row.cvss_score = entry.cvss_score
            row.severity = entry.severity
            row.last_seen = now
            if row.status == "resolved":
                row.status = "open"  # reappeared
            matched += 1

    # Anything previously open but no longer matched (e.g. service closed) → resolved.
    resolved = 0
    for (asset_id, service_id, cve_id), row in existing.items():
        scope_ok = only_asset_id is None or asset_id == only_asset_id
        if scope_ok and row.status == "open" and (asset_id, service_id, cve_id) not in seen_keys:
            row.status = "resolved"
            row.last_seen = now
            resolved += 1
    db.flush()
    return {"matched": matched, "resolved": resolved, "cve_count": len(entries), "services": len(services)}


# --- EPSS (exploit prediction) + CISA KEV (known exploited) enrichment -------------------

def priority_score(cvss: float, epss: float, kev: bool) -> int:
    """A single 0–100 prioritisation score: severity, exploit likelihood (EPSS), and KEV."""
    score = cvss * 10.0 + max(0.0, min(1.0, epss)) * 20.0
    if kev:  # actively exploited in the wild → always top priority
        score = max(score, 90.0)
    return int(round(max(0.0, min(100.0, score))))


def priority_band(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def import_epss(db: Session, csv_text: str) -> dict[str, int]:
    """Import a FIRST EPSS CSV (``cve,epss,percentile``). Updates existing CVE entries only."""
    entries = {c.cve_id: c for c in db.scalars(select(CveEntry))}
    updated = unmatched = 0
    for line in csv_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.lower().startswith("cve,"):  # skip comments + header row only
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        cve = parts[0].strip().upper()
        try:
            epss = float(parts[1])
        except ValueError:
            continue
        entry = entries.get(cve)
        if entry is None:
            unmatched += 1
            continue
        entry.epss = max(0.0, min(1.0, epss))
        updated += 1
    db.flush()
    return {"updated": updated, "unmatched": unmatched}


def import_kev(db: Session, data: Any) -> dict[str, int]:
    """Import the CISA KEV catalog (JSON). Flags matching CVE entries as known-exploited."""
    import json as _json
    if isinstance(data, (bytes, str)):
        try:
            data = _json.loads(data)
        except ValueError as exc:
            raise ValueError("ملف KEV JSON غير صالح.") from exc
    items = data.get("vulnerabilities", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError("صيغة KEV غير متوقعة.")
    entries = {c.cve_id: c for c in db.scalars(select(CveEntry))}
    flagged = unmatched = 0
    for it in items:
        cve = (it.get("cveID") or it.get("cve_id") or it.get("cve")) if isinstance(it, dict) else None
        if not cve:
            continue
        entry = entries.get(str(cve).strip().upper())
        if entry is None:
            unmatched += 1
            continue
        entry.kev = True
        entry.kev_date = str(it.get("dateAdded") or "")[:32] or None
        flagged += 1
    db.flush()
    return {"flagged": flagged, "unmatched": unmatched}
