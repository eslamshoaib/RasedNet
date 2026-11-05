"""Service identification from port number and (optionally) the banner a service volunteers.

Port-only identification is labelled with low confidence: a port number is a convention,
not proof of what is listening.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rased.text import sanitize_banner

WELL_KNOWN_TCP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 515: "lpd", 548: "afp", 554: "rtsp",
    587: "smtp-submission", 631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware-auth",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1883: "mqtt", 2049: "nfs",
    3268: "ldap-gc", 3306: "mysql", 3389: "rdp", 4443: "https-alt", 5000: "http-alt",
    5001: "https-alt", 5432: "postgresql", 5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
    6379: "redis", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8883: "mqtt-tls", 8888: "http-alt", 9000: "http-alt", 9100: "jetdirect",
    9200: "elasticsearch", 9443: "https-alt", 27017: "mongodb", 62078: "apple-lockdown",
}

EXPOSURE_BY_SERVICE: dict[str, str] = {
    "ssh": "remote_admin", "telnet": "remote_admin", "rdp": "remote_admin", "vnc": "remote_admin",
    "winrm-http": "remote_admin", "winrm-https": "remote_admin", "vmware-auth": "remote_admin",
    "ftp": "file_sharing", "smb": "file_sharing", "netbios-ssn": "file_sharing", "nfs": "file_sharing",
    "afp": "file_sharing", "rsync": "file_sharing",
    "http": "web", "https": "web", "http-alt": "web", "https-alt": "web", "http-proxy": "web",
    "mssql": "database", "oracle": "database", "mysql": "database", "postgresql": "database",
    "redis": "database", "mongodb": "database", "elasticsearch": "database",
    "kerberos": "directory", "ldap": "directory", "ldaps": "directory", "ldap-gc": "directory",
    "smtp": "mail", "smtps": "mail", "smtp-submission": "mail", "pop3": "mail", "pop3s": "mail",
    "imap": "mail", "imaps": "mail",
    "lpd": "printing", "ipp": "printing", "jetdirect": "printing",
    "dns": "infrastructure", "msrpc": "infrastructure", "rpcbind": "infrastructure",
    "rtsp": "media", "mqtt": "iot", "mqtt-tls": "iot", "apple-lockdown": "mobile",
}

# Observations (not vulnerabilities) about protocols that are weak by design.
EXPOSURE_NOTES_AR: dict[str, str] = {
    "telnet": "بروتوكول Telnet ينقل البيانات وكلمات المرور دون تشفير. يُنصح باستبداله بـ SSH.",
    "ftp": "بروتوكول FTP غير مشفر افتراضياً. يُنصح باستخدام SFTP أو FTPS وتقييد الوصول.",
    "vnc": "خدمة تحكم عن بعد. تحقق من وجود مصادقة قوية وتقييد الوصول بالشبكة.",
    "rdp": "سطح المكتب البعيد متاح. تحقق من تفعيل NLA وتقييد الوصول وأن الخدمة معتمدة.",
    "smb": "مشاركة ملفات SMB متاحة. تحقق من المجلدات المشتركة وصلاحياتها.",
    "netbios-ssn": "خدمة NetBIOS قديمة. عطّلها إن لم تكن مطلوبة.",
    "redis": "قاعدة بيانات Redis مكشوفة على الشبكة. تحقق من تفعيل المصادقة وتقييد الوصول.",
    "mongodb": "قاعدة بيانات MongoDB مكشوفة على الشبكة. تحقق من المصادقة وتقييد الوصول.",
    "elasticsearch": "خدمة Elasticsearch مكشوفة. تحقق من المصادقة وتقييد الوصول.",
    "mssql": "خدمة قاعدة بيانات مكشوفة. تأكد أنها معتمدة ومقيدة بالشبكات المسموح بها.",
    "mysql": "خدمة قاعدة بيانات مكشوفة. تأكد أنها معتمدة ومقيدة بالشبكات المسموح بها.",
    "postgresql": "خدمة قاعدة بيانات مكشوفة. تأكد أنها معتمدة ومقيدة بالشبكات المسموح بها.",
    "winrm-http": "WinRM عبر HTTP غير مشفر على مستوى النقل. يُفضّل WinRM عبر HTTPS.",
    "http": "واجهة ويب غير مشفرة. إن كانت واجهة إدارة فيُنصح باستخدام HTTPS.",
    "mqtt": "وسيط MQTT دون تشفير. تحقق من المصادقة واستخدم MQTT عبر TLS.",
}


@dataclass(frozen=True)
class ServiceIdentity:
    service_name: str
    product: str | None
    version: str | None
    confidence: float
    method: str  # "port" | "banner"
    exposure_category: str
    banner: str | None


_SSH_RE = re.compile(r"^SSH-(\d+\.\d+)-([^\s]+)(?:\s+(.*))?$")
_HTTP_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+\d{3}")
_SERVER_HDR_RE = re.compile(r"(?im)^server:\s*([^\r\n]+)")
_PRODUCT_VERSION_RE = re.compile(r"^([A-Za-z][\w.\- ]*?)[/ _-]v?(\d[\w.\-]*)")


def _split_product(token: str) -> tuple[str | None, str | None]:
    token = token.strip()
    if not token:
        return None, None
    match = _PRODUCT_VERSION_RE.match(token)
    if match:
        return match.group(1).strip()[:128], match.group(2)[:64]
    return token.split()[0][:128], None


def _parse_mysql_greeting(raw: bytes) -> str | None:
    # Handshake v10: 3-byte length, 1-byte seq, 0x0a, NUL-terminated server version.
    if len(raw) > 6 and raw[4] == 0x0A:
        end = raw.find(b"\x00", 5)
        if end > 5:
            version = raw[5:end].decode("ascii", "replace")
            if re.fullmatch(r"[\w.\-~+]{1,60}", version):
                return version
    return None


def identify_service(port: int, raw_banner: bytes | None, *, tls: bool = False) -> ServiceIdentity:
    name = WELL_KNOWN_TCP.get(port, "unknown")
    product: str | None = None
    version: str | None = None
    confidence = 0.35 if name != "unknown" else 0.1
    method = "port"
    banner = sanitize_banner(raw_banner)

    if raw_banner:
        mysql_version = _parse_mysql_greeting(raw_banner)
        if mysql_version:
            name, method, confidence = "mysql", "banner", 0.9
            product = "MariaDB" if "mariadb" in mysql_version.lower() else "MySQL"
            version = mysql_version.split("-")[0][:64]
            banner = f"MySQL handshake: {mysql_version}"

    if banner and method == "port":
        ssh = _SSH_RE.match(banner)
        if ssh:
            name, method, confidence = "ssh", "banner", 0.95
            product, version = _split_product(ssh.group(2).replace("_", "/", 1))
        elif _HTTP_STATUS_RE.match(banner) or (raw_banner and _SERVER_HDR_RE.search(raw_banner.decode("latin-1"))):
            name = "https" if tls else "http"
            method, confidence = "banner", 0.9
            server = _SERVER_HDR_RE.search(raw_banner.decode("latin-1")) if raw_banner else None
            if server:
                product, version = _split_product(sanitize_banner(server.group(1), 128) or "")
        elif banner.startswith("220"):
            lowered = banner.lower()
            if "ftp" in lowered or port == 21:
                name, method, confidence = "ftp", "banner", 0.85
            elif "smtp" in lowered or "mail" in lowered or port in (25, 587):
                name, method, confidence = "smtp", "banner", 0.85
            for known in ("vsFTPd", "ProFTPD", "FileZilla", "Pure-FTPd", "Postfix", "Exim", "Microsoft ESMTP"):
                if known.lower() in lowered:
                    product = known
                    vm = re.search(re.escape(known) + r"[ /]?(\d[\w.]*)", banner, re.IGNORECASE)
                    version = vm.group(1)[:64] if vm else None
                    break
        elif banner.startswith("+OK"):
            name, method, confidence = "pop3", "banner", 0.8
        elif banner.startswith("* OK"):
            name, method, confidence = "imap", "banner", 0.8
        elif banner.startswith("RFB "):
            name, method, confidence = "vnc", "banner", 0.9
            version = banner[4:11].strip() or None

    if tls and name in ("http", "http-alt", "unknown"):
        name = "https" if name == "http" else "https-alt" if name == "http-alt" else name

    return ServiceIdentity(
        service_name=name,
        product=product,
        version=version,
        confidence=confidence,
        method=method,
        exposure_category=EXPOSURE_BY_SERVICE.get(name, "other"),
        banner=banner,
    )
