"""Idempotent seeding of reference data (roles, permissions, built-in scan profiles)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from rasednet.models import Permission, Role, ScanProfile, User, utcnow
from rasednet.security.passwords import hash_password
from rasednet.security.rbac import PERMISSIONS, ROLES

# Standard first-run administrator. Created only when the database has no users at all.
# The account is flagged ``must_change_password`` so the operator is forced to set a new
# password on first sign-in — the default credentials never survive first use.
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "RasedNet@2026"

DISCOVERY_PORTS = [22, 80, 135, 139, 443, 445, 3389, 8080]

STANDARD_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 515, 548, 554,
    587, 631, 636, 873, 902, 993, 995, 1433, 1521, 1883, 2049, 3268, 3306, 3389, 4443, 5000,
    5001, 5432, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8883, 8888, 9000, 9100,
    9200, 9443, 27017, 62078,
]

BUILTIN_PROFILES: list[dict[str, object]] = [
    {
        "code": "safe_discovery",
        "name_ar": "اكتشاف آمن",
        "description_ar": (
            "اكتشاف الأجهزة فقط عبر ICMP وجدول ARP واتصال TCP بعدد محدود من المنافذ، "
            "دون قراءة توقيعات الخدمات. مناسب للشبكات الحساسة."
        ),
        "discovery_ports": DISCOVERY_PORTS,
        "tcp_ports": [],
        "use_icmp": True,
        "use_arp": True,
        "resolve_dns": True,
        "grab_banners": False,
        # Concurrency only bounds in-flight connections; the packet rate is the network-safety limit.
        "max_concurrency": 256,
        "per_host_concurrency": 4,
        "rate_per_second": 150,
        "connect_timeout_ms": 2000,
        "retries": 0,
    },
    {
        "code": "standard_inventory",
        "name_ar": "جرد قياسي",
        "description_ar": (
            "اكتشاف الأجهزة ثم فحص اتصال TCP لقائمة المنافذ الشائعة وقراءة التوقيعات التي "
            "ترسلها الخدمات وبيانات شهادات TLS. لا يتضمن أي اختبار اختراق أو تخمين كلمات مرور."
        ),
        "discovery_ports": DISCOVERY_PORTS,
        "tcp_ports": STANDARD_TCP_PORTS,
        "use_icmp": True,
        "use_arp": True,
        "resolve_dns": True,
        "grab_banners": True,
        "max_concurrency": 512,
        "per_host_concurrency": 12,
        "rate_per_second": 400,
        "connect_timeout_ms": 2500,
        "retries": 1,
    },
]

PROFILE_FIELDS = (
    "code", "name_ar", "description_ar", "discovery_ports", "tcp_ports", "use_icmp", "use_arp",
    "resolve_dns", "grab_banners", "max_concurrency", "per_host_concurrency", "rate_per_second",
    "connect_timeout_ms", "retries", "is_intrusive",
)


def profile_snapshot(profile: ScanProfile) -> dict[str, object]:
    return {f: getattr(profile, f) for f in PROFILE_FIELDS}


def seed_reference_data(session: Session) -> None:
    perms = {p.code: p for p in session.scalars(select(Permission))}
    for code, desc in PERMISSIONS.items():
        if code not in perms:
            perms[code] = Permission(code=code, description_ar=desc)
            session.add(perms[code])
        else:
            perms[code].description_ar = desc
    session.flush()

    roles = {r.name: r for r in session.scalars(select(Role))}
    for name, (name_ar, desc, codes) in ROLES.items():
        role = roles.get(name)
        if role is None:
            role = Role(name=name, name_ar=name_ar, description_ar=desc)
            session.add(role)
        role.name_ar = name_ar
        role.description_ar = desc
        role.permissions = [perms[c] for c in sorted(codes)]

    existing = {p.code: p for p in session.scalars(select(ScanProfile))}
    for definition in BUILTIN_PROFILES:
        profile = existing.get(str(definition["code"]))
        if profile is None:
            profile = ScanProfile(code=definition["code"])
            session.add(profile)
        for key, value in definition.items():
            setattr(profile, key, value)
        profile.is_builtin = True
        profile.is_intrusive = False
    session.flush()

    _bootstrap_admin(session)


def _bootstrap_admin(session: Session) -> None:
    """Create the standard first-run administrator when no user accounts exist yet.

    Idempotent: once any user is present (including after the default password is
    changed), this does nothing. The seeded account must change its password on
    first sign-in, so the default credentials cannot be used for real access.
    """
    if session.scalar(select(User.id).limit(1)) is not None:
        return
    admin_role = session.scalar(select(Role).where(Role.name == "admin"))
    if admin_role is None:  # roles are seeded above; defensive only
        return
    now = utcnow()
    session.add(
        User(
            username=DEFAULT_ADMIN_USERNAME,
            display_name="Administrator",
            password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
            role=admin_role,
            is_active=True,
            must_change_password=True,
            failed_login_count=0,
            password_changed_at=now,
            created_at=now,
        )
    )
    session.flush()
