"""Non-intrusive TCP connect probing with optional passive banner collection.

Safety properties:
* full TCP connect only (no raw packets, no stealth/evasion techniques);
* every connection attempt passes through a global token-bucket rate limiter, a global
  concurrency semaphore and a per-target semaphore;
* banner collection either reads what the server volunteers or sends a single
  ``HEAD / HTTP/1.0`` request to web ports; nothing else is ever sent.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC
from typing import Literal

from cryptography import x509
from cryptography.x509.oid import NameOID

ProbeState = Literal["open", "closed", "filtered"]

# Ports where the server speaks first; we only listen.
TALK_FIRST_PORTS = frozenset({21, 22, 23, 25, 110, 143, 587, 3306, 5900})
HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8081, 8888, 5000, 9000})
HTTPS_PORTS = frozenset({443, 8443, 4443, 5001, 9443})

MAX_BANNER_BYTES = 1024


class RateLimiter:
    """Async token bucket: at most ``rate`` acquisitions per second (burst of ``rate``)."""

    def __init__(self, rate: int) -> None:
        if rate < 1:
            raise ValueError("rate must be >= 1")
        self._rate = float(rate)
        self._tokens = float(rate)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(self._rate, self._tokens + (now - self._updated) * self._rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)


@dataclass
class ProbeLimits:
    rate: RateLimiter
    global_slots: asyncio.Semaphore
    per_host: int
    timeout_s: float
    retries: int
    _host_slots: dict[str, asyncio.Semaphore] = field(default_factory=dict)

    def host_slots(self, ip: str) -> asyncio.Semaphore:
        sem = self._host_slots.get(ip)
        if sem is None:
            sem = asyncio.Semaphore(self.per_host)
            self._host_slots[ip] = sem
        return sem

    def release_host(self, ip: str) -> None:
        self._host_slots.pop(ip, None)


@dataclass
class TcpProbeResult:
    port: int
    state: ProbeState
    banner: bytes | None = None
    tls: dict[str, object] | None = None
    rtt_ms: float | None = None


def _tls_client_context() -> ssl.SSLContext:
    # Inventory only: we record certificate metadata, we do not trust or authenticate it.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    if not attrs:
        return None
    value = attrs[0].value
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def describe_certificate(der: bytes) -> dict[str, object]:
    cert = x509.load_der_x509_certificate(der)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    info: dict[str, object] = {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "not_before": not_before.astimezone(UTC).isoformat(),
        "not_after": not_after.astimezone(UTC).isoformat(),
        "self_signed": cert.issuer == cert.subject,
        "serial": format(cert.serial_number, "x"),
        "signature_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
    }
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        info["san_dns"] = san.get_values_for_type(x509.DNSName)[:20]
    except x509.ExtensionNotFound:
        info["san_dns"] = []
    return info


async def _read_some(reader: asyncio.StreamReader, timeout: float) -> bytes:
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout
    while total < MAX_BANNER_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(MAX_BANNER_BYTES - total), remaining)
        except (TimeoutError, OSError, asyncio.IncompleteReadError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        # Talk-first services send one line; stop early once we have a line break.
        if b"\n" in chunk and total >= 4:
            break
    return b"".join(chunks)


def _http_head(ip: str) -> bytes:
    host = f"[{ip}]" if ":" in ip else ip
    return (
        f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: RASED-Inventory/0.1\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


async def _connect_once(
    ip: str, port: int, timeout: float, grab_banner: bool
) -> TcpProbeResult:
    use_tls = grab_banner and port in HTTPS_PORTS
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except ConnectionRefusedError:
        return TcpProbeResult(port, "closed", rtt_ms=(time.monotonic() - started) * 1000)
    except (TimeoutError, OSError):
        return TcpProbeResult(port, "filtered")

    rtt = (time.monotonic() - started) * 1000
    result = TcpProbeResult(port, "open", rtt_ms=rtt)
    try:
        if grab_banner:
            if use_tls:
                # The TCP port is open regardless of what happens during the TLS handshake.
                try:
                    await asyncio.wait_for(writer.start_tls(_tls_client_context()), timeout)
                except (OSError, TimeoutError, ssl.SSLError, ValueError):
                    result.tls = {"handshake": "failed"}
                    return result
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj is not None:
                    tls_info: dict[str, object] = {"handshake": "ok", "version": ssl_obj.version()}
                    cipher = ssl_obj.cipher()
                    tls_info["cipher"] = cipher[0] if cipher else None
                    der = ssl_obj.getpeercert(binary_form=True)
                    if der:
                        with contextlib.suppress(ValueError):
                            tls_info["certificate"] = describe_certificate(der)
                    result.tls = tls_info
            if port in HTTP_PORTS or use_tls:
                writer.write(_http_head(ip))
                with contextlib.suppress(OSError):
                    await asyncio.wait_for(writer.drain(), timeout)
                result.banner = await _read_some(reader, timeout) or None
            elif port in TALK_FIRST_PORTS:
                result.banner = await _read_some(reader, timeout) or None
    except (OSError, TimeoutError, ssl.SSLError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 2.0)
    return result


async def probe_tcp(
    ip: str,
    port: int,
    limits: ProbeLimits,
    *,
    grab_banner: bool,
    cancelled: asyncio.Event | None = None,
    timeout_s: float | None = None,
    retries: int | None = None,
) -> TcpProbeResult | None:
    """Probe one port, honouring rate/concurrency limits and retrying 'filtered' results.

    Returns ``None`` when cancellation prevented the port from being probed at all, so that
    callers never mistake "not probed" for "filtered".
    """
    attempts = (limits.retries if retries is None else retries) + 1
    timeout = limits.timeout_s if timeout_s is None else timeout_s
    result: TcpProbeResult | None = None
    for _ in range(attempts):
        if cancelled is not None and cancelled.is_set():
            return result
        async with limits.host_slots(ip), limits.global_slots:
            await limits.rate.acquire()
            result = await _connect_once(ip, port, timeout, grab_banner)
        if result.state != "filtered":
            return result
    return result
