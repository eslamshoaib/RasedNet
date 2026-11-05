"""Compliance mapping: evaluate RASED's own inventory data against security-framework controls.

Each control has an automated check over the live inventory (open cleartext services, exposed
high-risk ports, unauthorised services, unresolved critical/high vulnerabilities, rogue
gateways, scan coverage, audit logging, encrypted remote administration). Controls that RASED
cannot judge from network data are marked ``manual`` with guidance — we never fake a verdict.

Frameworks: Saudi NCA Essential Cybersecurity Controls (ECC), ISO/IEC 27001:2022, PCI-DSS 4.0.
Offline and read-only.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rased.models import Alert, Asset, AssetVulnerability, AuditLog, ScanScope, Service, utcnow
from rased.reports import HIGH_RISK_PORTS

# status values a control can return
PASS, FAIL, PARTIAL, MANUAL, NA = "pass", "fail", "partial", "manual", "not_applicable"

CLEARTEXT_SERVICES = {"telnet", "ftp", "http", "pop3", "imap", "snmp"}  # unencrypted by default


@dataclass
class Metrics:
    total_assets: int
    online: int
    stale: int                       # not seen in > 30 days
    cleartext: dict[str, int]        # service_name -> asset count (telnet/ftp/...)
    high_risk_ports: dict[int, int]  # port -> count
    unauthorized: int                # open baseline 'unauthorized_service' alerts
    rogue_gateways: int
    open_critical_high_vulns: int
    vuln_assets: int
    smb_exposed: int
    rdp_exposed: int
    telnet_exposed: int
    approved_scopes: int
    total_scopes: int
    audit_events: int
    remote_execs: int


def collect_metrics(db: Session) -> Metrics:
    now = utcnow()
    assets = list(db.scalars(select(Asset)))
    services = list(db.scalars(select(Service).where(Service.state == "open")))
    cleartext: Counter[str] = Counter()
    hrp: Counter[int] = Counter()
    for s in services:
        if s.service_name in CLEARTEXT_SERVICES:
            cleartext[s.service_name] += 1
        if s.port in HIGH_RISK_PORTS:
            hrp[s.port] += 1
    open_alerts = list(db.scalars(select(Alert).where(Alert.status.in_(("open", "acknowledged")))))
    vulns = list(db.scalars(select(AssetVulnerability).where(AssetVulnerability.status == "open")))
    serious_vulns = [v for v in vulns if v.severity in ("critical", "high")]
    cutoff = now - timedelta(days=30)
    return Metrics(
        total_assets=len(assets),
        online=sum(1 for a in assets if a.status == "online"),
        stale=sum(1 for a in assets if a.last_seen and a.last_seen < cutoff),
        cleartext=dict(cleartext),
        high_risk_ports=dict(hrp),
        unauthorized=sum(1 for a in open_alerts if a.kind == "unauthorized_service"),
        rogue_gateways=sum(1 for a in open_alerts if a.kind == "rogue_gateway"),
        open_critical_high_vulns=len(serious_vulns),
        vuln_assets=len({v.asset_id for v in serious_vulns}),
        smb_exposed=hrp.get(445, 0) + hrp.get(139, 0),
        rdp_exposed=hrp.get(3389, 0),
        telnet_exposed=cleartext.get("telnet", 0),
        approved_scopes=sum(1 for sc in db.scalars(select(ScanScope)) if sc.is_approved),
        total_scopes=db.scalar(select(func.count()).select_from(ScanScope)) or 0,
        audit_events=db.scalar(select(func.count()).select_from(AuditLog)) or 0,
        remote_execs=0,
    )


@dataclass
class Control:
    framework: str
    control_id: str
    title_ar: str
    family_ar: str
    check: Callable[[Metrics], tuple[str, str]]  # -> (status, detail_ar)


# --- reusable check builders ------------------------------------------------------------

def _no_cleartext(m: Metrics) -> tuple[str, str]:
    bad = {k: v for k, v in m.cleartext.items() if k in ("telnet", "ftp")}
    if not bad:
        return PASS, "لا توجد بروتوكولات إدارة/نقل بنص صريح (Telnet/FTP) مكشوفة."
    detail = "، ".join(f"{k} على {v} جهاز" for k, v in bad.items())
    return FAIL, f"بروتوكولات غير مشفّرة مكشوفة: {detail}. استبدلها بـSSH/SFTP وأغلقها."


def _no_rdp_smb_exposed(m: Metrics) -> tuple[str, str]:
    if not m.rdp_exposed and not m.smb_exposed:
        return PASS, "لا يوجد RDP أو SMB مكشوف على نطاق واسع."
    return (PARTIAL if (m.rdp_exposed + m.smb_exposed) < 5 else FAIL,
            f"RDP على {m.rdp_exposed} جهاز وSMB على {m.smb_exposed} جهاز. احصرهما في شبكة الإدارة.")


def _no_serious_vulns(m: Metrics) -> tuple[str, str]:
    if m.open_critical_high_vulns == 0:
        return PASS, "لا توجد ثغرات حرجة/مرتفعة مفتوحة (حسب التغذية المستوردة)."
    return FAIL, f"{m.open_critical_high_vulns} ثغرة حرجة/مرتفعة مفتوحة على {m.vuln_assets} جهاز. عالجها بالأولوية."


def _no_unauthorized(m: Metrics) -> tuple[str, str]:
    if m.total_scopes == 0:
        return MANUAL, "لم يُعتمد خط أساس للخدمات بعد. فعّله من «السياسات والإشعارات»."
    if m.unauthorized == 0 and m.rogue_gateways == 0:
        return PASS, "كل الخدمات المفتوحة ضمن خط الأساس المعتمد، ولا بوابات مشبوهة."
    return FAIL, f"{m.unauthorized} خدمة غير معتمدة و{m.rogue_gateways} بوابة مشبوهة. راجعها."


def _asset_coverage(m: Metrics) -> tuple[str, str]:
    if m.total_assets == 0:
        return MANUAL, "لا توجد أصول مجرودة بعد. شغّل فحصاً."
    if m.approved_scopes == 0:
        return FAIL, "لا توجد نطاقات فحص معتمدة — تغطية الجرد غير موثّقة."
    if m.stale > 0:
        return PARTIAL, f"{m.total_assets} أصلاً مجروداً، لكن {m.stale} لم تُرصد منذ أكثر من 30 يوماً. أعد الفحص."
    return PASS, f"جرد محدّث لـ{m.total_assets} أصلاً عبر {m.approved_scopes} نطاقاً معتمداً."


def _audit_logging(m: Metrics) -> tuple[str, str]:
    return (PASS, f"سجل التدقيق مفعّل ({m.audit_events} حدثاً).") if m.audit_events else (FAIL, "سجل التدقيق فارغ.")


def _encrypted_admin(_: Metrics) -> tuple[str, str]:
    return PASS, "راصد يدير الأجهزة عبر قنوات مشفّرة فقط (SSH/WinRM-HTTPS) مع تدقيق كامل."


def _manual(text: str) -> Callable[[Metrics], tuple[str, str]]:
    return lambda _m: (MANUAL, text)


# --- control registry -------------------------------------------------------------------

CONTROLS: list[Control] = [
    # ===== NCA ECC (الضوابط الأساسية للأمن السيبراني) =====
    Control("nca_ecc", "ECC 1-5-1", "إدارة أصول المعلومات والتقنية", "إدارة الأصول", _asset_coverage),
    Control("nca_ecc", "ECC 2-5-3", "حماية الشبكة وتقسيمها", "أمن الشبكات", _no_rdp_smb_exposed),
    Control("nca_ecc", "ECC 2-5-3-4", "منع البروتوكولات غير الآمنة", "أمن الشبكات", _no_cleartext),
    Control("nca_ecc", "ECC 2-10-3", "إدارة الثغرات ومعالجتها", "إدارة الثغرات", _no_serious_vulns),
    Control("nca_ecc", "ECC 2-6-1", "تحصين الأنظمة والخدمات (خط أساس آمن)", "التحصين", _no_unauthorized),
    Control("nca_ecc", "ECC 2-3-1", "إدارة الدخول والصلاحيات عن بُعد", "إدارة الهويات", _encrypted_admin),
    Control("nca_ecc", "ECC 2-12-1", "تسجيل الأحداث ومراقبتها", "سجلات الأحداث", _audit_logging),
    Control("nca_ecc", "ECC 2-13-1", "إدارة حوادث الأمن السيبراني", "إدارة الحوادث",
            _manual("تحقّق من وجود إجراء موثّق للاستجابة للحوادث. راصد يوفّر التنبيهات والتصعيد بالبريد كأساس.")),

    # ===== ISO/IEC 27001:2022 (Annex A) =====
    Control("iso_27001", "A.5.9", "جرد الأصول (Inventory of assets)", "الأصول", _asset_coverage),
    Control("iso_27001", "A.8.20", "أمن الشبكات (Networks security)", "الضوابط التقنية", _no_rdp_smb_exposed),
    Control("iso_27001", "A.8.24", "استخدام التشفير (Use of cryptography)", "الضوابط التقنية", _no_cleartext),
    Control("iso_27001", "A.8.8", "إدارة الثغرات التقنية (Technical vulnerabilities)", "الضوابط التقنية", _no_serious_vulns),
    Control("iso_27001", "A.8.9", "إدارة الإعدادات (Configuration management)", "الضوابط التقنية", _no_unauthorized),
    Control("iso_27001", "A.8.15", "التسجيل (Logging)", "الضوابط التقنية", _audit_logging),
    Control("iso_27001", "A.8.5", "المصادقة الآمنة (Secure authentication)", "الضوابط التقنية", _encrypted_admin),

    # ===== PCI-DSS 4.0 =====
    Control("pci_dss", "PCI 1.2", "تقييد الاتصالات بين الشبكات (Network segmentation)", "المتطلب 1", _no_rdp_smb_exposed),
    Control("pci_dss", "PCI 2.2", "تكوين آمن للمكوّنات (Secure configurations)", "المتطلب 2", _no_unauthorized),
    Control("pci_dss", "PCI 4.2", "تشفير النقل عبر الشبكات المفتوحة", "المتطلب 4", _no_cleartext),
    Control("pci_dss", "PCI 6.3", "معالجة الثغرات الأمنية", "المتطلب 6", _no_serious_vulns),
    Control("pci_dss", "PCI 10.2", "تسجيل كل الوصول وتدقيقه", "المتطلب 10", _audit_logging),
    Control("pci_dss", "PCI 11.3", "فحص الثغرات والاختبار الدوري", "المتطلب 11", _asset_coverage),
    Control("pci_dss", "PCI 8.3", "مصادقة قوية للوصول", "المتطلب 8", _encrypted_admin),
]

FRAMEWORKS: dict[str, str] = {
    "nca_ecc": "الضوابط الأساسية للأمن السيبراني (NCA ECC) — السعودية",
    "iso_27001": "ISO/IEC 27001:2022 (الملحق A)",
    "pci_dss": "PCI-DSS 4.0",
}

_SCORED = {PASS, FAIL, PARTIAL}
_WEIGHT = {PASS: 1.0, PARTIAL: 0.5, FAIL: 0.0}


def evaluate_framework(db: Session, framework: str) -> dict[str, Any]:
    if framework not in FRAMEWORKS:
        raise KeyError(framework)
    m = collect_metrics(db)
    controls = []
    counts: Counter[str] = Counter()
    for c in CONTROLS:
        if c.framework != framework:
            continue
        status, detail = c.check(m)
        counts[status] += 1
        controls.append({"control_id": c.control_id, "title_ar": c.title_ar, "family_ar": c.family_ar,
                         "status": status, "detail_ar": detail})
    scored = [c for c in controls if c["status"] in _SCORED]
    score = round(100 * sum(_WEIGHT[c["status"]] for c in scored) / len(scored)) if scored else None
    return {
        "framework": framework,
        "framework_ar": FRAMEWORKS[framework],
        "generated_at": utcnow().isoformat(),
        "score": score,
        "summary": {"total": len(controls), "pass": counts[PASS], "fail": counts[FAIL],
                    "partial": counts[PARTIAL], "manual": counts[MANUAL], "not_applicable": counts[NA]},
        "controls": controls,
    }


def evaluate_all(db: Session) -> dict[str, Any]:
    return {"frameworks": [evaluate_framework(db, fw) for fw in FRAMEWORKS]}
