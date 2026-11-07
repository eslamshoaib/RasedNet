"""Comprehensive Arabic security-assessment report assembly.

Pure, read-only aggregation over the inventory database. ``build_report`` returns a fully
structured Arabic report (executive summary, risk scoring, per-network breakdown, exposed
services with the administrator verify/close commands, alerts, scan history and generated
recommendations). ``build_workbook`` renders the same report as a native .xlsx workbook.

No external I/O, no network, no raw SQL — just parameterised ORM queries — so the report is
fully offline and reproducible.
"""

from __future__ import annotations

import io
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rasednet import __version__
from rasednet.config import Settings
from rasednet.models import (
    Alert,
    Asset,
    AssetVulnerability,
    CveEntry,
    PhysicalLink,
    RemoteExecution,
    ScanJob,
    ScanScope,
    Service,
    utcnow,
)
from rasednet.i18n import get_lang
from rasednet.remediation import build_guidance

# --- Arabic label tables (kept in sync with the frontend) -------------------------------

DEVICE_TYPES_AR: dict[str, str] = {
    "router": "موجّه", "access_point": "نقطة وصول", "switch": "محوّل", "network_device": "جهاز شبكة",
    "server": "خادم", "computer": "حاسوب", "mobile": "هاتف محمول", "tablet": "جهاز لوحي",
    "printer": "طابعة", "camera": "كاميرا", "tv": "تلفاز", "nas": "تخزين شبكي",
    "iot": "إنترنت الأشياء", "virtual_machine": "جهاز افتراضي", "hypervisor": "مُشرف افتراضي",
    "unknown": "غير معروف",
}
OS_FAMILIES_AR: dict[str, str] = {
    "windows": "ويندوز", "linux": "لينكس", "unix": "يونكس", "macos": "ماك", "ios": "iOS",
    "android": "أندرويد", "network_os": "نظام شبكي", "unknown": "غير معروف",
}
STATUS_AR: dict[str, str] = {"online": "متصل", "offline": "غير متصل", "unknown": "غير معروف"}
SEVERITY_AR: dict[str, str] = {"critical": "حرِج", "high": "مرتفع", "medium": "متوسط", "low": "منخفض", "info": "معلومة"}
EXPOSURE_AR: dict[str, str] = {
    "remote_admin": "إدارة عن بعد", "file_sharing": "مشاركة ملفات", "web": "ويب", "database": "قاعدة بيانات",
    "directory": "خدمة دليل", "mail": "بريد", "printing": "طباعة", "infrastructure": "بنية تحتية",
    "media": "وسائط", "iot": "إنترنت الأشياء", "mobile": "جوال", "other": "أخرى",
}

DEVICE_TYPES_EN: dict[str, str] = {
    "router": "Router", "access_point": "Access point", "switch": "Switch", "network_device": "Network device",
    "server": "Server", "computer": "Computer", "mobile": "Mobile phone", "tablet": "Tablet",
    "printer": "Printer", "camera": "Camera", "tv": "TV", "nas": "Network storage",
    "iot": "IoT", "virtual_machine": "Virtual machine", "hypervisor": "Hypervisor", "unknown": "Unknown",
}
OS_FAMILIES_EN: dict[str, str] = {
    "windows": "Windows", "linux": "Linux", "unix": "Unix", "macos": "macOS", "ios": "iOS",
    "android": "Android", "network_os": "Network OS", "unknown": "Unknown",
}
STATUS_EN: dict[str, str] = {"online": "Online", "offline": "Offline", "unknown": "Unknown"}
SEVERITY_EN: dict[str, str] = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
EXPOSURE_EN: dict[str, str] = {
    "remote_admin": "Remote administration", "file_sharing": "File sharing", "web": "Web", "database": "Database",
    "directory": "Directory service", "mail": "Mail", "printing": "Printing", "infrastructure": "Infrastructure",
    "media": "Media", "iot": "IoT", "mobile": "Mobile", "other": "Other",
}


def _en() -> bool:
    return get_lang() == "en"


def dev_label(k: str) -> str:
    return (DEVICE_TYPES_EN if _en() else DEVICE_TYPES_AR).get(k, k)


def os_label(k: str) -> str:
    return (OS_FAMILIES_EN if _en() else OS_FAMILIES_AR).get(k, k)


def status_label(k: str) -> str:
    return (STATUS_EN if _en() else STATUS_AR).get(k, k)


def sev_label(k: str) -> str:
    return (SEVERITY_EN if _en() else SEVERITY_AR).get(k, k)


def exp_label(k: str) -> str:
    return (EXPOSURE_EN if _en() else EXPOSURE_AR).get(k, k)


# Weight of each open service toward a device's exposure score.
EXPOSURE_WEIGHT: dict[str, int] = {
    "remote_admin": 5, "database": 5, "directory": 4, "file_sharing": 3, "mail": 3, "web": 2,
    "infrastructure": 2, "media": 1, "iot": 2, "mobile": 1, "other": 1,
}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Ports that always deserve an explicit call-out in the report, with the reason in Arabic.
HIGH_RISK_PORTS: dict[int, str] = {
    23: "Telnet — إدارة عن بعد بنص صريح غير مشفّر؛ يُنصح باستبداله بـ SSH وإغلاقه.",
    21: "FTP — نقل ملفات بنص صريح غالباً؛ استخدم SFTP/FTPS أو أغلقه.",
    139: "NetBIOS — بروتوكول قديم لمشاركة الملفات؛ عطّله إن لم يكن مطلوباً.",
    445: "SMB — مشاركة ملفات ويندوز؛ يجب حصره في شبكة الإدارة ومنعه عبر الشبكات غير الموثوقة.",
    3389: "RDP — سطح المكتب البعيد؛ لا يجوز تعريضه خارج شبكة الإدارة، فعّل NLA وحدّ من مصادر الاتصال.",
    5900: "VNC — تحكم عن بعد كثيراً ما يكون بلا تشفير قوي؛ احصره أو أغلقه.",
    1433: "قاعدة بيانات SQL Server مكشوفة على الشبكة؛ احصرها في خوادم التطبيقات فقط.",
    3306: "قاعدة بيانات MySQL مكشوفة على الشبكة؛ احصرها في خوادم التطبيقات فقط.",
    5432: "قاعدة بيانات PostgreSQL مكشوفة على الشبكة؛ احصرها في خوادم التطبيقات فقط.",
    6379: "Redis مكشوف — كثيراً ما يكون بلا كلمة مرور؛ احصره على 127.0.0.1 أو شبكة خاصة.",
    27017: "MongoDB مكشوف على الشبكة؛ فعّل المصادقة واحصر الوصول.",
    9200: "Elasticsearch مكشوف — غالباً بلا مصادقة؛ احصر الوصول فوراً.",
    161: "SNMP — قد يكشف معلومات الجهاز؛ استخدم SNMPv3 أو عطّله.",
}

HIGH_RISK_PORTS_EN: dict[int, str] = {
    23: "Telnet — unencrypted cleartext remote administration; replace with SSH and close it.",
    21: "FTP — often cleartext file transfer; use SFTP/FTPS or close it.",
    139: "NetBIOS — legacy file-sharing protocol; disable it if not needed.",
    445: "SMB — Windows file sharing; restrict it to the management network and block it over untrusted networks.",
    3389: "RDP — Remote Desktop; must not be exposed outside the management network, enable NLA and limit sources.",
    5900: "VNC — remote control, often without strong encryption; restrict or close it.",
    1433: "SQL Server database exposed on the network; restrict it to application servers only.",
    3306: "MySQL database exposed on the network; restrict it to application servers only.",
    5432: "PostgreSQL database exposed on the network; restrict it to application servers only.",
    6379: "Redis exposed — often with no password; bind it to 127.0.0.1 or a private network.",
    27017: "MongoDB exposed on the network; enable authentication and restrict access.",
    9200: "Elasticsearch exposed — often without authentication; restrict access immediately.",
    161: "SNMP — may reveal device information; use SNMPv3 or disable it.",
}


def high_risk_note(port: int) -> str | None:
    return (HIGH_RISK_PORTS_EN if get_lang() == "en" else HIGH_RISK_PORTS).get(port)


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _risk_band(score: float) -> str:
    if score >= 12:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _network_of(ip: str | None) -> str | None:
    """A device's /24 (IPv4) grouping key, used when no scan scope contains it."""
    if not ip or ":" in ip:
        return ip
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


def build_report(db: Session, settings: Settings) -> dict[str, Any]:
    """Assemble the full structured report. Read-only."""
    now = utcnow()
    assets = list(db.scalars(select(Asset)))
    services = list(db.scalars(select(Service).where(Service.state == "open")))
    scopes = list(db.scalars(select(ScanScope)))
    svc_by_asset: dict[int, list[Service]] = defaultdict(list)
    for s in services:
        svc_by_asset[s.asset_id].append(s)

    # --- executive summary ---
    online = sum(1 for a in assets if a.status == "online")
    gateways = sum(1 for a in assets if a.is_gateway)
    exposed_assets = [a for a in assets if len(svc_by_asset.get(a.id, [])) >= 5]
    type_counts = Counter(a.device_type for a in assets)
    os_counts = Counter(a.os_family for a in assets)
    status_counts = Counter(a.status for a in assets)

    open_alerts = list(db.scalars(select(Alert).where(Alert.status != "resolved")))
    sev_counts = Counter(al.severity for al in open_alerts)

    scope_cidrs = {sc.cidr for sc in scopes}

    # --- per-device exposure scoring ---
    def device_score(a: Asset) -> float:
        svcs = svc_by_asset.get(a.id, [])
        score = sum(EXPOSURE_WEIGHT.get(s.exposure_category, 1) for s in svcs)
        score += sum(3 for s in svcs if s.port in HIGH_RISK_PORTS)
        if any(al.asset_id == a.id and al.severity in ("high", "critical") for al in open_alerts):
            score += 4
        return float(score)

    alerts_by_asset: dict[int, int] = Counter(al.asset_id for al in open_alerts if al.asset_id)

    # --- per-network breakdown ---
    net_members: dict[str, list[Asset]] = defaultdict(list)
    net_label: dict[str, str] = {}
    for a in assets:
        key = None
        for sc in scopes:
            # cheap containment: scope cidr prefix match on the /24 for display grouping
            if a.current_ip and _ip_in_cidr(a.current_ip, sc.cidr):
                key = sc.cidr
                net_label[key] = sc.name
                break
        if key is None:
            key = _network_of(a.current_ip) or ("Unspecified" if _en() else "غير محدد")
        net_members[key].append(a)

    networks = []
    for cidr, members in sorted(net_members.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        open_ports: Counter[int] = Counter()
        for a in members:
            for s in svc_by_asset.get(a.id, []):
                open_ports[s.port] += 1
        net_score = sum(device_score(a) for a in members)
        networks.append({
            "cidr": cidr,
            "name": net_label.get(cidr),
            "in_scope": cidr in scope_cidrs,
            "devices": len(members),
            "online": sum(1 for a in members if a.status == "online"),
            "routers": sum(1 for a in members if a.device_type in ("router", "network_device", "switch", "access_point")),
            "gateways": sum(1 for a in members if a.is_gateway),
            "open_service_count": sum(len(svc_by_asset.get(a.id, [])) for a in members),
            "top_ports": [{"port": p, "count": c} for p, c in open_ports.most_common(8)],
            "risk_score": round(net_score, 1),
            "risk_band": _risk_band(net_score / max(1, len(members))),
        })

    # --- exposed services aggregated by port (with admin verify/close commands) ---
    port_index: dict[tuple[int, str], dict[str, Any]] = {}
    for s in services:
        key = (s.port, s.service_name)
        entry = port_index.setdefault(key, {
            "port": s.port, "service_name": s.service_name, "protocol": s.protocol,
            "exposure_category": s.exposure_category, "count": 0, "assets": [],
            "high_risk": s.port in HIGH_RISK_PORTS, "risk_note_ar": high_risk_note(s.port),
        })
        entry["count"] += 1
        if len(entry["assets"]) < 50:
            asset = next((a for a in assets if a.id == s.asset_id), None)
            if asset:
                entry["assets"].append({"id": asset.id, "ip": asset.current_ip, "name": asset.display_name or asset.hostname})
    exposed_ports = sorted(port_index.values(), key=lambda e: (not e["high_risk"], -e["count"], e["port"]))
    for entry in exposed_ports:
        # One representative guidance block per port (commands are built from validated values only).
        sample = entry["assets"][0] if entry["assets"] else None
        entry["guidance"] = build_guidance(
            entry["service_name"], entry["port"], sample["ip"] if sample else "127.0.0.1",
            os_family="unknown", device_type="unknown",
        )

    # --- top exposed devices ---
    scored = sorted(assets, key=device_score, reverse=True)
    top_exposed = [{
        "id": a.id, "ip": a.current_ip, "name": a.display_name or a.hostname or a.current_ip,
        "device_type": a.device_type, "device_type_ar": dev_label(a.device_type),
        "os_family": a.os_family, "status": a.status, "is_gateway": a.is_gateway,
        "open_services": len(svc_by_asset.get(a.id, [])), "open_alerts": alerts_by_asset.get(a.id, 0),
        "risk_score": round(device_score(a), 1), "risk_band": _risk_band(device_score(a)),
        "ports": sorted({s.port for s in svc_by_asset.get(a.id, [])})[:12],
    } for a in scored[:25] if device_score(a) > 0]

    # --- alerts detail ---
    serious = sorted(
        [al for al in open_alerts if al.severity in ("high", "critical")],
        key=lambda al: (SEVERITY_ORDER.index(al.severity), al.last_seen), reverse=True,
    )
    alerts_detail = [{
        "id": al.id, "severity": al.severity, "severity_ar": sev_label(al.severity),
        "title_ar": al.title_ar, "message_ar": al.message_ar, "asset_id": al.asset_id,
        "occurrences": al.occurrences, "last_seen": _dt(al.last_seen),
    } for al in serious[:40]]

    # --- scan history ---
    jobs = list(db.scalars(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(10)))
    scan_history = [{
        "id": j.id, "scope": j.scope.name if j.scope else None, "status": j.status,
        "alive_hosts": j.alive_hosts, "open_services": j.open_services, "total_hosts": j.total_hosts,
        "started_at": _dt(j.started_at), "finished_at": _dt(j.finished_at),
    } for j in jobs]
    last_scan = next((j for j in jobs if j.finished_at), None)

    # --- remote-management activity ---
    remote_total = db.scalar(select(func.count()).select_from(RemoteExecution)) or 0
    remote_recent = list(db.scalars(select(RemoteExecution).order_by(RemoteExecution.started_at.desc()).limit(10)))
    remote_activity = {
        "total": int(remote_total),
        "recent": [{
            "target": r.target, "label_ar": r.label_ar, "section": r.section, "status": r.status,
            "had_errors": r.had_errors, "started_at": _dt(r.started_at),
        } for r in remote_recent],
    }

    # --- vulnerabilities (CVE correlation) ---
    vulns = list(db.scalars(select(AssetVulnerability).where(AssetVulnerability.status == "open")))
    cve_total = db.scalar(select(func.count()).select_from(CveEntry)) or 0
    vuln_sev = Counter(v.severity for v in vulns)
    vuln_top = sorted(vulns, key=lambda v: (SEVERITY_ORDER.index(v.severity) if v.severity in SEVERITY_ORDER else 0, v.cvss_score), reverse=True)
    vulnerabilities = {
        "cve_entries": int(cve_total),
        "open_findings": len(vulns),
        "affected_assets": len({v.asset_id for v in vulns}),
        "by_severity": [{"key": k, "label_ar": sev_label(k), "count": vuln_sev.get(k, 0)}
                        for k in reversed(SEVERITY_ORDER) if vuln_sev.get(k, 0)],
        "top": [{
            "cve_id": v.cve_id, "severity": v.severity, "severity_ar": sev_label(v.severity),
            "cvss_score": v.cvss_score, "asset_id": v.asset_id, "product": v.product, "version": v.version,
            "matched_on": v.matched_on,
        } for v in vuln_top[:40]],
    }

    # --- physical links (SNMP/LLDP) ---
    phys_count = db.scalar(select(func.count()).select_from(PhysicalLink)) or 0

    report: dict[str, Any] = {
        "meta": {
            "title": ("RasedNet comprehensive network security-assessment report" if _en() else "تقرير راصد الشامل لتقييم أمن الشبكة"),
            "tool": "RasedNet — راصد",
            "version": __version__,
            "generated_at": _dt(now),
            "scope_count": len(scopes),
            "scopes": [{"name": sc.name, "cidr": sc.cidr, "sensitive": sc.is_sensitive} for sc in scopes],
        },
        "summary": {
            "total_assets": len(assets),
            "online": online,
            "offline": status_counts.get("offline", 0),
            "networks": len(net_members),
            "routers": type_counts.get("router", 0) + type_counts.get("network_device", 0)
            + type_counts.get("switch", 0) + type_counts.get("access_point", 0),
            "gateways": gateways,
            "open_services": len(services),
            "exposed_devices": len(exposed_assets),
            "high_risk_ports": sum(e["count"] for e in exposed_ports if e["high_risk"]),
            "open_alerts": len(open_alerts),
            "critical_alerts": sev_counts.get("critical", 0),
            "high_alerts": sev_counts.get("high", 0),
            "last_scan_at": _dt(last_scan.finished_at) if last_scan else None,
            "overall_risk_band": _risk_band(sum(device_score(a) for a in assets) / max(1, len(assets)) + len(serious)),
            "open_vulnerabilities": len(vulns),
            "physical_links": int(phys_count),
        },
        "distributions": {
            "device_types": [{"key": k, "label_ar": dev_label(k), "count": c} for k, c in type_counts.most_common()],
            "os_families": [{"key": k, "label_ar": os_label(k), "count": c} for k, c in os_counts.most_common()],
            "statuses": [{"key": k, "label_ar": status_label(k), "count": c} for k, c in status_counts.most_common()],
            "severities": [{"key": k, "label_ar": sev_label(k), "count": sev_counts.get(k, 0)}
                           for k in reversed(SEVERITY_ORDER) if sev_counts.get(k, 0)],
            "exposures": _exposure_distribution(services),
        },
        "networks": networks,
        "exposed_ports": exposed_ports,
        "top_exposed_devices": top_exposed,
        "alerts": alerts_detail,
        "vulnerabilities": vulnerabilities,
        "scan_history": scan_history,
        "remote_activity": remote_activity,
        "recommendations": _recommendations(exposed_ports, serious, exposed_assets, scopes, assets),
    }
    return report


def _exposure_distribution(services: list[Service]) -> list[dict[str, Any]]:
    c = Counter(s.exposure_category for s in services)
    return [{"key": k, "label_ar": exp_label(k), "count": n} for k, n in c.most_common()]


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _recommendations(exposed_ports: list[dict[str, Any]], serious: list[Alert],
                     exposed_assets: list[Asset], scopes: list[ScanScope], assets: list[Asset]) -> list[dict[str, str]]:
    en = _en()
    recs: list[dict[str, str]] = []
    present = {e["port"] for e in exposed_ports if e["high_risk"]}
    for port in sorted(present):
        note = high_risk_note(port) or ""
        count = next((e["count"] for e in exposed_ports if e["port"] == port), 0)
        recs.append({
            "priority": "high",
            "title_ar": (f"Port {port} exposed on {count} device(s)" if en else f"منفذ {port} مكشوف على {count} جهاز"),
            "detail_ar": note + (" See the “Exposed ports” section for per-device verify/close commands."
                                  if en else " راجع قسم «المنافذ المكشوفة» لأوامر التحقق والإغلاق لكل جهاز."),
        })
    if serious:
        recs.append({
            "priority": "high",
            "title_ar": (f"Remediate {len(serious)} high/critical alert(s)" if en else f"معالجة {len(serious)} تنبيهاً مرتفع/حرج الخطورة"),
            "detail_ar": ("Start with the critical alerts, then the high ones; details are in the alerts section."
                          if en else "ابدأ بالتنبيهات الحرجة ثم المرتفعة؛ تفاصيلها في قسم التنبيهات."),
        })
    if exposed_assets:
        recs.append({
            "priority": "medium",
            "title_ar": (f"{len(exposed_assets)} device(s) expose 5 or more open services" if en else f"{len(exposed_assets)} جهازاً يعرض 5 خدمات مفتوحة أو أكثر"),
            "detail_ar": ("Review these devices and close unnecessary services to reduce the attack surface."
                          if en else "راجع هذه الأجهزة وأغلق الخدمات غير الضرورية لتقليل سطح الهجوم."),
        })
    if not scopes:
        recs.append({
            "priority": "medium",
            "title_ar": ("No approved scan scopes" if en else "لا توجد نطاقات فحص معتمدة"),
            "detail_ar": ("Approve scan scopes from the “Network discovery” page for regular, documented coverage."
                          if en else "اعتمد نطاقات الفحص من صفحة «اكتشاف الشبكة» لتغطية منتظمة وموثّقة."),
        })
    unknown = sum(1 for a in assets if a.device_type == "unknown")
    if unknown:
        recs.append({
            "priority": "low",
            "title_ar": (f"{unknown} device(s) of unidentified type" if en else f"{unknown} جهازاً غير مُعرَّف النوع"),
            "detail_ar": ("Run a standard inventory scan so RasedNet can better identify the device type and OS."
                          if en else "شغّل فحص جرد قياسي ليحسّن راصد التعرف على نوع الجهاز ونظام تشغيله."),
        })
    if not recs:
        recs.append({"priority": "low",
                     "title_ar": ("No prominent risks" if en else "لا توجد مخاطر بارزة"),
                     "detail_ar": ("RasedNet found no high-risk ports or critical alerts in this data."
                                   if en else "لم يرصد راصد منافذ عالية الخطورة أو تنبيهات حرجة في هذه البيانات.")})
    return recs


# --- Excel workbook ---------------------------------------------------------------------


def build_workbook(report: dict[str, Any]) -> bytes:
    """Render the report as a native .xlsx workbook (Arabic RTL or English LTR)."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    en = _en()
    rtl = not en
    align = "left" if en else "right"

    def L(ar: str, eng: str) -> str:
        return eng if en else ar

    wb = Workbook()
    header_fill = PatternFill("solid", fgColor="0E7490")
    header_font = Font(bold=True, color="FFFFFF", name="Calibri")
    title_font = Font(bold=True, size=14, color="0E7490")

    def sheet(title: str):  # type: ignore[no-untyped-def]
        ws = wb.create_sheet(title=title[:31])
        ws.sheet_view.rightToLeft = rtl
        return ws

    def write_table(ws, headers: list[str], rows: list[list[Any]], start: int = 1) -> int:  # type: ignore[no-untyped-def]
        for ci, h in enumerate(headers, start=1):
            c = ws.cell(row=start, column=ci, value=h)
            c.fill, c.font = header_fill, header_font
            c.alignment = Alignment(horizontal=align)
        for ri, row in enumerate(rows, start=start + 1):
            for ci, val in enumerate(row, start=1):
                ws.cell(row=ri, column=ci, value=val).alignment = Alignment(horizontal=align)
        for ci in range(1, len(headers) + 1):
            width = max([len(str(headers[ci - 1]))] + [len(str(r[ci - 1])) for r in rows if ci - 1 < len(r)] + [8])
            ws.column_dimensions[get_column_letter(ci)].width = min(48, width + 4)
        return start + 1 + len(rows)

    ws = wb.active
    ws.title = L("الملخص", "Summary")
    ws.sheet_view.rightToLeft = rtl
    ws["A1"] = report["meta"]["title"]
    ws["A1"].font = title_font
    ws["A2"] = L(f"أُنشئ في: {report['meta']['generated_at']}  •  الإصدار: {report['meta']['version']}",
                 f"Generated: {report['meta']['generated_at']}  •  Version: {report['meta']['version']}")
    s = report["summary"]
    rows = [
        [L("إجمالي الأجهزة", "Total devices"), s["total_assets"]], [L("متصل الآن", "Online now"), s["online"]], [L("غير متصل", "Offline"), s["offline"]],
        [L("عدد الشبكات", "Networks"), s["networks"]], [L("الموجّهات وأجهزة الشبكة", "Routers & network gear"), s["routers"]], [L("البوابات", "Gateways"), s["gateways"]],
        [L("إجمالي المنافذ المفتوحة", "Total open ports"), s["open_services"]], [L("منافذ عالية الخطورة", "High-risk ports"), s["high_risk_ports"]],
        [L("أجهزة عالية التعرّض (≥5 خدمات)", "Highly exposed devices (≥5 services)"), s["exposed_devices"]], [L("تنبيهات مفتوحة", "Open alerts"), s["open_alerts"]],
        [L("تنبيهات حرجة", "Critical alerts"), s["critical_alerts"]], [L("تنبيهات مرتفعة", "High alerts"), s["high_alerts"]],
        [L("مستوى الخطورة العام", "Overall risk level"), sev_label(s["overall_risk_band"])],
        [L("آخر فحص", "Last scan"), s["last_scan_at"] or "—"],
    ]
    write_table(ws, [L("المؤشر", "Metric"), L("القيمة", "Value")], rows, start=4)

    ws = sheet(L("الشبكات", "Networks"))
    write_table(ws, [L("الشبكة", "Network"), L("الاسم", "Name"), L("أجهزة", "Devices"), L("متصل", "Online"), L("موجّهات", "Routers"), L("بوابات", "Gateways"), L("منافذ مفتوحة", "Open ports"), L("مستوى الخطورة", "Risk level")],
                [[n["cidr"], n["name"] or "—", n["devices"], n["online"], n["routers"], n["gateways"],
                  n["open_service_count"], sev_label(n["risk_band"])] for n in report["networks"]])

    ws = sheet(L("المنافذ المكشوفة", "Exposed ports"))
    write_table(ws, [L("المنفذ", "Port"), L("البروتوكول", "Protocol"), L("الخدمة", "Service"), L("التصنيف", "Category"), L("عدد الأجهزة", "Devices"), L("عالي الخطورة", "High risk"), L("ملاحظة", "Note")],
                [[e["port"], e["protocol"], e["service_name"], exp_label(e["exposure_category"]),
                  e["count"], L("نعم", "Yes") if e["high_risk"] else "", e.get("risk_note_ar") or ""] for e in report["exposed_ports"]])

    ws = sheet(L("الأجهزة عالية التعرّض", "Exposed devices"))
    write_table(ws, [L("المعرّف", "ID"), L("العنوان", "Address"), L("الاسم", "Name"), L("النوع", "Type"), L("النظام", "OS"), L("الحالة", "Status"), L("خدمات مفتوحة", "Open services"), L("تنبيهات", "Alerts"), L("درجة الخطورة", "Risk score"), L("المنافذ", "Ports")],
                [[d["id"], d["ip"], d["name"] or "—", d["device_type_ar"], os_label(d["os_family"]),
                  status_label(d["status"]), d["open_services"], d["open_alerts"], d["risk_score"],
                  ", ".join(map(str, d["ports"]))] for d in report["top_exposed_devices"]])

    ws = sheet(L("التنبيهات", "Alerts"))
    write_table(ws, [L("المعرّف", "ID"), L("الخطورة", "Severity"), L("العنوان", "Title"), L("التفاصيل", "Details"), L("التكرار", "Count"), L("آخر ظهور", "Last seen")],
                [[a["id"], a["severity_ar"], a["title_ar"], a["message_ar"], a["occurrences"], a["last_seen"]]
                 for a in report["alerts"]])

    ws = sheet(L("الثغرات", "Vulnerabilities"))
    write_table(ws, [L("المعرّف (CVE)", "CVE"), L("الخطورة", "Severity"), L("الدرجة", "Score"), L("المعرّف للجهاز", "Device ID"), L("المنتج", "Product"), L("الإصدار", "Version"), L("المطابقة", "Matched on")],
                [[v["cve_id"], v["severity_ar"], v["cvss_score"], v["asset_id"], v["product"],
                  v["version"] or "—", v["matched_on"]] for v in report["vulnerabilities"]["top"]])

    ws = sheet(L("التوصيات", "Recommendations"))
    pr = {"high": L("عالية", "High"), "medium": L("متوسطة", "Medium"), "low": L("منخفضة", "Low")}
    write_table(ws, [L("الأولوية", "Priority"), L("التوصية", "Recommendation"), L("التفاصيل", "Details")],
                [[pr.get(r["priority"], r["priority"]), r["title_ar"], r["detail_ar"]] for r in report["recommendations"]])

    ws = sheet(L("سجل الفحوصات", "Scan history"))
    write_table(ws, [L("المعرّف", "ID"), L("النطاق", "Scope"), L("الحالة", "Status"), L("أجهزة حيّة", "Live hosts"), L("منافذ مفتوحة", "Open ports"), L("بدأ", "Started"), L("انتهى", "Finished")],
                [[j["id"], j["scope"] or "—", j["status"], j["alive_hosts"], j["open_services"],
                  j["started_at"] or "—", j["finished_at"] or "—"] for j in report["scan_history"]])

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
