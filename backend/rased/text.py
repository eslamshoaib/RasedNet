"""Sanitisation of untrusted strings received from the network (banners, hostnames)."""

from __future__ import annotations

import re
import unicodedata

_WS_RE = re.compile(r"\s+")
_HOSTNAME_ALLOWED = re.compile(r"^[\w.\-]+$", re.UNICODE)


def _strip_controls(value: str) -> str:
    # Remove C0/C1 controls, bidi overrides and other format characters (Cc, Cf, Co, Cs).
    return "".join(
        ch if unicodedata.category(ch)[0] != "C" else " " for ch in value
    )


def sanitize_banner(raw: bytes | str | None, max_len: int = 512) -> str | None:
    """Make an untrusted banner safe to store and display (never interpreted as markup)."""
    if raw is None:
        return None
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    text = _WS_RE.sub(" ", _strip_controls(text)).strip()
    if not text:
        return None
    return text[:max_len]


def sanitize_hostname(raw: str | None) -> str | None:
    if not raw:
        return None
    name = unicodedata.normalize("NFC", raw).strip().rstrip(".")
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C")
    if not name or len(name) > 253 or not _HOSTNAME_ALLOWED.match(name):
        return None
    return name.lower()
