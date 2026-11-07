"""Request-scoped UI language (Arabic default, English optional).

The web client sends its chosen language in the ``X-Lang`` header. A tiny middleware
stores it in a context variable for the duration of the request, so any code that builds
user-facing text — reports, compliance, service guidance, device-classification evidence,
alert/event messages, API error details — can call :func:`tr` without threading the
language through every function signature.

This module contains no security logic; it only selects between two fixed strings.
"""
from __future__ import annotations

from contextvars import ContextVar

Lang = str  # "ar" | "en"

_current: ContextVar[Lang] = ContextVar("rasednet_lang", default="ar")


def normalize(value: str | None) -> Lang:
    """Map a raw header value to a supported language, defaulting to Arabic."""
    if value and value.strip().lower().startswith("en"):
        return "en"
    return "ar"


def set_lang(value: str | None) -> None:
    _current.set(normalize(value))


def get_lang() -> Lang:
    try:
        return _current.get()
    except LookupError:
        return "ar"


def tr(ar: str, en: str) -> str:
    """Return the English or Arabic string for the active request language."""
    return en if get_lang() == "en" else ar


def pick(ar: str, en: str) -> str:
    """Alias of :func:`tr` for call sites that read better as a value picker."""
    return en if get_lang() == "en" else ar
