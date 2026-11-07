"""Active Directory / LDAP directory intelligence — authenticated, read-only enumeration.

When the operator supplies an authorised domain account (from the vault), RasedNet binds to the
domain controller over LDAP/LDAPS and *reads* the directory: users, groups, group membership
and each account's effective privileges (derived from the well-known privileged groups it
belongs to). This is a legitimate authenticated directory read, exactly what a domain admin
does with ``Get-ADUser``/``dsquery``.

It never writes to the directory, never extracts password material (no hashes, no DCSync), and
never guesses or attacks credentials — it binds once with the account the operator provides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# userAccountControl bit flags (subset we surface).
UAC_DISABLED = 0x0002
UAC_LOCKOUT = 0x0010
UAC_PASSWD_NOTREQD = 0x0020
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_SMARTCARD_REQUIRED = 0x40000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_PASSWORD_EXPIRED = 0x800000

# Well-known high-privilege AD groups → Arabic label. Membership marks an account as privileged.
PRIVILEGED_GROUPS: dict[str, str] = {
    "domain admins": "مسؤولو النطاق",
    "enterprise admins": "مسؤولو المؤسسة",
    "schema admins": "مسؤولو المخطط",
    "administrators": "المسؤولون",
    "account operators": "مشغّلو الحسابات",
    "backup operators": "مشغّلو النسخ الاحتياطي",
    "server operators": "مشغّلو الخوادم",
    "print operators": "مشغّلو الطباعة",
    "group policy creator owners": "منشئو سياسات المجموعة",
    "dnsadmins": "مسؤولو DNS",
    "domain controllers": "وحدات تحكم النطاق",
    "key admins": "مسؤولو المفاتيح",
    "enterprise key admins": "مسؤولو مفاتيح المؤسسة",
}

PRIVILEGED_GROUPS_EN: dict[str, str] = {
    "domain admins": "Domain Admins",
    "enterprise admins": "Enterprise Admins",
    "schema admins": "Schema Admins",
    "administrators": "Administrators",
    "account operators": "Account Operators",
    "backup operators": "Backup Operators",
    "server operators": "Server Operators",
    "print operators": "Print Operators",
    "group policy creator owners": "Group Policy Creator Owners",
    "dnsadmins": "DnsAdmins",
    "domain controllers": "Domain Controllers",
    "key admins": "Key Admins",
    "enterprise key admins": "Enterprise Key Admins",
}


def group_label(key: str | None) -> str:
    from rasednet.i18n import get_lang
    if key is None:
        return ""
    table = PRIVILEGED_GROUPS_EN if get_lang() == "en" else PRIVILEGED_GROUPS
    return table.get(key, "")


class DirectoryError(Exception):
    """Arabic, user-facing message for directory-query failures."""


@dataclass(frozen=True)
class DirectoryQuery:
    host: str
    port: int = 389
    use_ssl: bool = False
    base_dn: str | None = None
    scope: str = "all"  # users | groups | computers | all
    page_limit: int = 2000


def rdn_value(dn: str) -> str:
    """First RDN value of a distinguished name: 'CN=Domain Admins,CN=Users,DC=x' -> 'Domain Admins'."""
    if not dn:
        return dn
    first = dn.split(",", 1)[0]
    return first.split("=", 1)[1] if "=" in first else first


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def decode_uac(uac: int) -> dict[str, bool]:
    return {
        "enabled": not bool(uac & UAC_DISABLED),
        "locked_out": bool(uac & UAC_LOCKOUT),
        "password_not_required": bool(uac & UAC_PASSWD_NOTREQD),
        "password_never_expires": bool(uac & UAC_DONT_EXPIRE_PASSWD),
        "smartcard_required": bool(uac & UAC_SMARTCARD_REQUIRED),
        "trusted_for_delegation": bool(uac & UAC_TRUSTED_FOR_DELEGATION),
        "password_expired": bool(uac & UAC_PASSWORD_EXPIRED),
    }


def privileges_for(group_names: list[str], admin_count: int) -> list[dict[str, str]]:
    """Map a user's group CNs to the well-known privileges they confer (Arabic labels)."""
    privs: list[dict[str, str]] = []
    seen: set[str] = set()
    for name in group_names:
        key = rdn_value(name).strip().lower()
        if key in PRIVILEGED_GROUPS and key not in seen:
            seen.add(key)
            privs.append({"group": rdn_value(name), "label_ar": group_label(key)})
    if admin_count and not privs:
        # adminCount=1 without a matched group still means the account is (or was) protected/privileged.
        privs.append({"group": "adminCount", "label_ar": tr("حساب محمي (صلاحيات إدارية سابقة أو حالية)", "Protected account (past or present admin privileges)")})
    return privs


def parse_user(attrs: dict[str, Any]) -> dict[str, Any]:
    """Normalise one directory user entry (attribute dict) into report shape."""
    uac = _as_int(attrs.get("userAccountControl"))
    flags = decode_uac(uac)
    groups = [rdn_value(g) for g in _as_list(attrs.get("memberOf"))]
    admin_count = _as_int(attrs.get("adminCount"))
    privileges = privileges_for(_as_list(attrs.get("memberOf")), admin_count)
    return {
        "sam": str(attrs.get("sAMAccountName") or ""),
        "display_name": str(attrs.get("displayName") or attrs.get("name") or ""),
        "upn": str(attrs.get("userPrincipalName") or ""),
        "mail": str(attrs.get("mail") or ""),
        "description": str(attrs.get("description") or ""),
        "dn": str(attrs.get("distinguishedName") or ""),
        "enabled": flags["enabled"],
        "flags": flags,
        "admin_count": admin_count,
        "groups": groups,
        "group_count": len(groups),
        "privileges": privileges,
        "is_privileged": bool(privileges),
        "when_created": str(attrs.get("whenCreated") or ""),
        "last_logon": str(attrs.get("lastLogonTimestamp") or ""),
    }


def parse_group(attrs: dict[str, Any]) -> dict[str, Any]:
    members = _as_list(attrs.get("member"))
    name = str(attrs.get("cn") or attrs.get("sAMAccountName") or attrs.get("name") or "")
    key = name.strip().lower()
    return {
        "name": name,
        "sam": str(attrs.get("sAMAccountName") or ""),
        "description": str(attrs.get("description") or ""),
        "dn": str(attrs.get("distinguishedName") or ""),
        "member_count": len(members),
        "members": [rdn_value(m) for m in members[:200]],
        "admin_count": _as_int(attrs.get("adminCount")),
        "privileged": key in PRIVILEGED_GROUPS,
        "label_ar": group_label(key),
    }


def parse_computer(attrs: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(attrs.get("cn") or attrs.get("name") or ""),
        "dns": str(attrs.get("dNSHostName") or ""),
        "os": str(attrs.get("operatingSystem") or ""),
        "os_version": str(attrs.get("operatingSystemVersion") or ""),
        "dn": str(attrs.get("distinguishedName") or ""),
        "enabled": not bool(_as_int(attrs.get("userAccountControl")) & UAC_DISABLED),
    }


def summarise(users: list[dict[str, Any]], groups: list[dict[str, Any]],
              computers: list[dict[str, Any]], domain: dict[str, Any]) -> dict[str, Any]:
    privileged = [u for u in users if u["is_privileged"]]
    return {
        "domain": domain,
        "counts": {
            "users": len(users),
            "groups": len(groups),
            "computers": len(computers),
            "enabled_users": sum(1 for u in users if u["enabled"]),
            "disabled_users": sum(1 for u in users if not u["enabled"]),
            "privileged_users": len(privileged),
            "privileged_groups": sum(1 for g in groups if g["privileged"]),
            "password_never_expires": sum(1 for u in users if u["flags"]["password_never_expires"]),
        },
        "users": users,
        "groups": groups,
        "computers": computers,
    }


# --- live connection (ldap3) -------------------------------------------------------------

USER_ATTRS = ["sAMAccountName", "displayName", "name", "userPrincipalName", "mail", "description",
              "distinguishedName", "userAccountControl", "memberOf", "adminCount", "whenCreated",
              "lastLogonTimestamp"]
GROUP_ATTRS = ["cn", "sAMAccountName", "name", "description", "distinguishedName", "member", "adminCount", "groupType"]
COMPUTER_ATTRS = ["cn", "name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                  "distinguishedName", "userAccountControl"]


def enumerate_directory(query: DirectoryQuery, bind_user: str | None = None, password: str | None = None, *,
                        integrated: bool = False, verify_tls: bool = True, timeout: int = 15) -> dict[str, Any]:
    """Read the directory. ``integrated`` binds as the current Windows user (Kerberos, no password);
    otherwise it binds with ``bind_user``/``password``. Read-only; raises DirectoryError."""
    try:
        import ssl

        from ldap3 import ALL, GSSAPI, NTLM, SASL, SIMPLE, SUBTREE, Connection, Server, Tls
    except ImportError as exc:  # pragma: no cover - dependency is installed in production
        raise DirectoryError(tr("مكتبة LDAP غير متوفرة على الخادم.", "The LDAP library is not available on the server.")) from exc

    tls = None
    if query.use_ssl:
        tls = Tls(validate=ssl.CERT_REQUIRED if verify_tls else ssl.CERT_NONE)
    server = Server(query.host, port=query.port, use_ssl=query.use_ssl, get_info=ALL,
                    connect_timeout=timeout, tls=tls)
    try:
        if integrated:
            # Bind as the RasedNet host's current domain user via Kerberos — no stored password.
            conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI,
                              auto_bind=True, receive_timeout=timeout)
        else:
            if not bind_user:
                raise DirectoryError(tr("لا يوجد حساب للاتصال.", "No account to connect with."))
            # DOMAIN\user → NTLM; otherwise a simple bind (user@domain UPN or a full DN).
            auth = NTLM if "\\" in bind_user else SIMPLE
            conn = Connection(server, user=bind_user, password=password, authentication=auth,
                              auto_bind=True, receive_timeout=timeout)
    except DirectoryError:
        raise
    except Exception as exc:  # ldap3 raises a variety of bind errors
        hint = (tr("تعذّر الاتصال التلقائي بهوية المستخدم الحالي (تأكد أن خادم راصد منضمّ للدومين).", "Automatic current-user bind failed (ensure the RasedNet server is domain-joined).") if integrated \
            else tr("تعذر الاتصال بوحدة التحكم أو المصادقة", "Could not connect to the controller or authenticate"))
        raise DirectoryError(f"{hint}: {exc}") from exc

    base_dn = query.base_dn or _default_base_dn(server)
    if not base_dn:
        conn.unbind()
        raise DirectoryError(tr("تعذّر تحديد نطاق البحث (Base DN). حدّده يدوياً، مثل: DC=example,DC=local", "Could not determine the search base (Base DN). Set it manually, e.g. DC=example,DC=local"))

    want = query.scope
    users: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    computers: list[dict[str, Any]] = []
    try:
        if want in ("users", "all"):
            users = [parse_user(e) for e in _search(conn, base_dn, "(&(objectCategory=person)(objectClass=user))",
                                                     USER_ATTRS, query.page_limit, SUBTREE)]
        if want in ("groups", "all"):
            groups = [parse_group(e) for e in _search(conn, base_dn, "(objectClass=group)",
                                                       GROUP_ATTRS, query.page_limit, SUBTREE)]
        if want in ("computers", "all"):
            computers = [parse_computer(e) for e in _search(conn, base_dn, "(objectClass=computer)",
                                                            COMPUTER_ATTRS, query.page_limit, SUBTREE)]
    except Exception as exc:  # pragma: no cover - network/search failure
        raise DirectoryError((f"Directory search failed: {exc}" if get_lang()=="en" else f"فشل البحث في الدليل: {exc}")) from exc
    finally:
        conn.unbind()

    domain = {
        "base_dn": base_dn,
        "host": query.host,
        "naming_contexts": list(getattr(server.info, "naming_contexts", []) or []) if server.info else [],
        "dns_domain": _dc_to_dns(base_dn),
    }
    return summarise(users, groups, computers, domain)


def _default_base_dn(server: Any) -> str | None:
    info = getattr(server, "info", None)
    if not info:
        return None
    other = getattr(info, "other", {}) or {}
    for key in ("defaultNamingContext", "rootDomainNamingContext"):
        value = other.get(key)
        if value:
            return value[0] if isinstance(value, (list, tuple)) else str(value)
    ncs = getattr(info, "naming_contexts", None)
    return (ncs[0] if ncs else None)


def _dc_to_dns(base_dn: str) -> str:
    parts = [p.split("=", 1)[1] for p in base_dn.split(",") if p.strip().lower().startswith("dc=")]
    return ".".join(parts)


def _dns_to_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def integrated_available() -> bool:
    """True if a passwordless Kerberos bind is possible (winkerberos present + a domain is known)."""
    try:
        import winkerberos  # noqa: F401
    except Exception:
        return False
    import os
    return bool(os.environ.get("USERDNSDOMAIN"))


def discover_domain(inventory_controllers: list[str] | None = None) -> dict[str, Any]:
    """Auto-detect the AD domain, base DN and candidate domain controllers from the host + inventory.

    Sources: the server's own domain membership (environment), DNS resolution of the domain name
    and the logon server, and inventory assets that expose LDAP/Kerberos.
    """
    import os
    import socket

    env_domain = (os.environ.get("USERDNSDOMAIN") or "").lower().strip()
    logon = (os.environ.get("LOGONSERVER") or "").lstrip("\\").strip()
    controllers: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(host: str, source: str) -> None:
        host = host.strip()
        if host and host not in seen:
            seen.add(host)
            controllers.append({"host": host, "source": source})

    # Logon server (the DC that authenticated this host) and the domain name itself.
    for host in (candidate for candidate in (logon,) if candidate):
        try:
            add(socket.gethostbyname(host), "logon_server")
        except OSError:
            add(host, "logon_server")
    if env_domain:
        try:
            for _, _, _, _, sockaddr in socket.getaddrinfo(env_domain, 389, proto=socket.IPPROTO_TCP):
                add(sockaddr[0], "dns")
        except OSError:
            pass
    for ip in (inventory_controllers or []):
        add(ip, "inventory")

    return {
        "domain": env_domain or None,
        "base_dn": _dns_to_base_dn(env_domain) if env_domain else None,
        "controllers": controllers,
        "integrated_available": integrated_available(),
        "env": {"USERDNSDOMAIN": os.environ.get("USERDNSDOMAIN"),
                "USERDOMAIN": os.environ.get("USERDOMAIN"),
                "LOGONSERVER": os.environ.get("LOGONSERVER"),
                "USERNAME": os.environ.get("USERNAME")},
    }


def _search(conn: Any, base: str, flt: str, attrs: list[str], limit: int, scope: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for entry in conn.extend.standard.paged_search(search_base=base, search_filter=flt, search_scope=scope,
                                                    attributes=attrs, paged_size=200, generator=True):
        if entry.get("type") != "searchResEntry":
            continue
        raw = entry.get("attributes", {})
        entries.append({k: raw.get(k) for k in attrs})
        if len(entries) >= limit:
            break
    return entries
