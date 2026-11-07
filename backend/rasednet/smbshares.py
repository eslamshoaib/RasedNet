"""Anonymous (guest) SMB share browsing — read-only, no credentials, no exploitation.

This lists files on SMB shares that a device already exposes to the public (no username or
password). RasedNet only ever binds anonymously/guest: if a share needs authentication it is
reported as protected and skipped — RasedNet never guesses or supplies credentials, and never
reads file *contents*, only names/sizes/dates. Administrative shares (IPC$, ADMIN$, C$) are
never touched.
"""

from __future__ import annotations

import contextlib
from typing import Any

from rasednet.text import sanitize_banner
from rasednet.i18n import get_lang, tr

# Common public-share names to probe (SMB has no anonymous "list shares" without an RPC call).
COMMON_SHARES = [
    "Public", "public", "Shared", "shared", "Share", "share", "Files", "files", "Media", "media",
    "Downloads", "Download", "Guest", "guest", "www", "Videos", "Photos", "Music", "Documents",
    "Backup", "backup", "Data", "data", "usb", "USB", "Public Folder", "Transfer", "common", "pub",
]
ADMIN_SHARES = {"ipc$", "admin$", "c$", "d$", "print$"}
MAX_ENTRIES = 1000


class SmbError(Exception):
    """Arabic, user-facing SMB message."""


def _client():  # type: ignore[no-untyped-def]
    import smbclient
    return smbclient


def _register(ip: str, timeout: int) -> None:
    """Open an anonymous (then guest) session. Never sends a real password."""
    smbclient = _client()
    last: Exception | None = None
    for user in ("", "Guest"):
        try:
            smbclient.register_session(ip, username=user, password="", connection_timeout=timeout)
            return
        except Exception as exc:  # try the next anonymous identity
            last = exc
    raise SmbError((f"Could not open an anonymous (no-account) session with {ip}: {last}" if get_lang()=="en" else f"تعذر فتح جلسة مجهولة (بدون حساب) مع {ip}: {last}"))


def _reset(ip: str) -> None:
    with contextlib.suppress(Exception):
        _client().delete_session(ip)


def _entry(info: Any) -> dict[str, Any]:
    is_dir = False
    size = 0
    mtime: float | None = None
    with contextlib.suppress(Exception):
        is_dir = info.is_dir()
    with contextlib.suppress(Exception):
        st = info.stat()
        size = int(getattr(st, "st_size", 0))
        mtime = getattr(st, "st_mtime", None)
    return {"name": sanitize_banner(info.name)[:255], "is_dir": is_dir, "size": size, "mtime": mtime}


def list_accessible_shares(ip: str, *, timeout: int = 6, sample: int = 5) -> dict[str, Any]:
    """Probe common share names; return those readable anonymously, each with a few sample entries."""
    smbclient = _client()
    _register(ip, timeout)
    shares: list[dict[str, Any]] = []
    try:
        for name in COMMON_SHARES:
            if name.lower() in ADMIN_SHARES:
                continue
            path = rf"\\{ip}\{name}"
            try:
                entries = []
                for i, info in enumerate(smbclient.scandir(path)):
                    if i >= sample:
                        break
                    entries.append(_entry(info))
                shares.append({"share": name, "entries": entries, "truncated": len(entries) >= sample})
            except Exception:
                continue  # not present or not anonymously readable → skip silently
    finally:
        _reset(ip)
    return {"ip": ip, "shares": shares, "count": len(shares),
            "note_ar": tr("المشاركات التي يمكن فتحها بدون حساب فقط. المحمية بكلمة مرور لا تظهر هنا.", "Only shares openable without an account. Password-protected ones are not shown here.")}


def browse(ip: str, share: str, subpath: str = "", *, timeout: int = 6) -> dict[str, Any]:
    """List entries under a share path, anonymously. Read-only; names/sizes/dates only."""
    if share.strip().lower() in ADMIN_SHARES:
        raise SmbError(tr("لا يُسمح بتصفح المشاركات الإدارية.", "Browsing administrative shares is not allowed."))
    # A share name is a single path segment: reject separators and traversal in it.
    if not share.strip() or any(c in share for c in "\\/") or ".." in share:
        raise SmbError(tr("اسم مشاركة غير صالح.", "Invalid share name."))
    subpath = subpath.replace("/", "\\").strip("\\")
    if ".." in subpath.split("\\"):
        raise SmbError(tr("مسار غير صالح.", "Invalid path."))
    smbclient = _client()
    _register(ip, timeout)
    path = rf"\\{ip}\{share}" + (f"\\{subpath}" if subpath else "")
    entries: list[dict[str, Any]] = []
    try:
        for i, info in enumerate(smbclient.scandir(path)):
            if i >= MAX_ENTRIES:
                break
            entries.append(_entry(info))
    except Exception as exc:
        raise SmbError((f"Could not open the path (it may be protected or missing): {exc}" if get_lang()=="en" else f"تعذر فتح المسار (قد يكون محمياً أو غير موجود): {exc}")) from exc
    finally:
        _reset(ip)
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return {"ip": ip, "share": share, "path": subpath, "entries": entries, "count": len(entries)}
