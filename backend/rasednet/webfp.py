"""Web fingerprinting: capture a device's HTTP identity (Server header, page title, favicon hash).

For each open web service RasedNet fetches the landing page and ``/favicon.ico`` from the device's
own address only, and computes the Shodan-style favicon hash via :mod:`rasednet.discovery.fphash`.
These signals identify device admin panels and can be pivoted/searched offline. Read-only GETs,
bounded in size and time; TLS certificate errors are tolerated (device self-signed certs are
normal), and no proxy is ever used.
"""

from __future__ import annotations

import re
import ssl
import urllib.parse
import urllib.request

from rasednet.discovery.fphash import favicon_hash
from rasednet.text import sanitize_banner

MAX_BYTES = 512 * 1024


def _build_opener() -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # device panels commonly use self-signed certs
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))


_NO_PROXY = _build_opener()
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ICON_RE = re.compile(rb'<link[^>]+rel=["\']?[^"\'>]*icon[^"\'>]*["\']?[^>]*>', re.IGNORECASE)
_HREF_RE = re.compile(rb'href=["\']?([^"\' >]+)', re.IGNORECASE)

WEB_PORTS = {80, 443, 8080, 8008, 8443, 8000, 8888, 5000, 9000, 9443, 7000, 1400, 631}


class WebFpError(Exception):
    """Arabic, user-facing web-fingerprint error."""


def _get(url: str, timeout: float) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "RasedNet/1.0 (+asset-inventory)"})
    with _NO_PROXY.open(req, timeout=timeout) as resp:
        body = resp.read(MAX_BYTES + 1)[:MAX_BYTES]
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, headers, body


def _title(html: bytes) -> str | None:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    try:
        text = m.group(1).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    return sanitize_banner(re.sub(r"\s+", " ", text)).strip()[:200] or None


def _favicon_url(base: str, html: bytes) -> str:
    """Prefer a <link rel=icon> href; else the conventional /favicon.ico."""
    link = _ICON_RE.search(html)
    if link:
        href = _HREF_RE.search(link.group(0))
        if href:
            return urllib.parse.urljoin(base, href.group(1).decode("ascii", "ignore"))
    return urllib.parse.urljoin(base, "/favicon.ico")


def fetch(ip: str, port: int, use_https: bool, *, timeout: float = 4.0) -> dict[str, object]:
    """Fetch one web service's identity. Raises WebFpError on connection failure."""
    base = f"{'https' if use_https else 'http'}://{ip}:{port}/"
    try:
        status, headers, html = _get(base, timeout)
    except Exception as exc:  # noqa: BLE001 - urllib raises many error types
        raise WebFpError(f"تعذّر فتح {base}: {exc}") from exc
    result: dict[str, object] = {
        "port": port, "scheme": "https" if use_https else "http", "status": status,
        "server": sanitize_banner(headers.get("server", ""))[:200] or None,
        "title": _title(html),
        "favicon_hash": None,
    }
    try:
        fav_url = _favicon_url(base, html)
        _, _, icon = _get(fav_url, timeout)
        if icon:
            result["favicon_hash"] = favicon_hash(icon)
    except Exception:  # noqa: BLE001 - a missing favicon is not an error
        pass
    return result


def fingerprint_asset(ip: str, open_ports: list[int], *, timeout: float = 4.0) -> list[dict[str, object]]:
    """Fetch web fingerprints for every open web port on an asset."""
    out: list[dict[str, object]] = []
    for port in sorted(p for p in open_ports if p in WEB_PORTS):
        https = port in (443, 8443, 9443)
        try:
            out.append(fetch(ip, port, https, timeout=timeout))
        except WebFpError as exc:
            out.append({"port": port, "scheme": "https" if https else "http", "error": str(exc)[:200]})
    return out
