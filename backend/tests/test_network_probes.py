"""Real network probes against local loopback services (actually executed, no mocks of sockets)."""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ipaddress
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from rased.discovery import engine as engine_mod
from rased.discovery import tcp_probe
from rased.discovery.arp import Neighbor
from rased.discovery.engine import EngineConfig, ScanEngine
from rased.discovery.icmp import PingResult
from rased.discovery.tcp_probe import ProbeLimits, RateLimiter, probe_tcp


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def limits(timeout: float = 3.0, retries: int = 0) -> ProbeLimits:
    return ProbeLimits(rate=RateLimiter(1000), global_slots=asyncio.Semaphore(16), per_host=4, timeout_s=timeout, retries=retries)


async def _serve(handler):  # type: ignore[no-untyped-def]
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_open_port_with_volunteered_banner(monkeypatch):
    async def main():  # type: ignore[no-untyped-def]
        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            writer.write(b"SSH-2.0-OpenSSH_9.6 test\r\n")
            await writer.drain()
            await asyncio.sleep(0.5)
            writer.close()

        server, port = await _serve(handler)
        monkeypatch.setattr(tcp_probe, "TALK_FIRST_PORTS", frozenset({port}))
        async with server:
            return await probe_tcp("127.0.0.1", port, limits(), grab_banner=True)

    result = asyncio.run(main())
    assert result is not None and result.state == "open"
    assert result.banner == b"SSH-2.0-OpenSSH_9.6 test\r\n"


def test_closed_port_reports_closed():
    port = free_port()  # nothing listens here any more
    result = asyncio.run(probe_tcp("127.0.0.1", port, limits(), grab_banner=False))
    assert result is not None and result.state == "closed"


def test_http_head_only(monkeypatch):
    received: list[bytes] = []

    async def main():  # type: ignore[no-untyped-def]
        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            data = await reader.read(1024)
            received.append(data)
            writer.write(b"HTTP/1.0 200 OK\r\nServer: TestServer/2.1\r\n\r\n")
            await writer.drain()
            writer.close()

        server, port = await _serve(handler)
        monkeypatch.setattr(tcp_probe, "HTTP_PORTS", frozenset({port}))
        async with server:
            return await probe_tcp("127.0.0.1", port, limits(), grab_banner=True)

    result = asyncio.run(main())
    assert result is not None and result.state == "open"
    assert received and received[0].startswith(b"HEAD / HTTP/1.0\r\n")
    assert b"Server: TestServer/2.1" in (result.banner or b"")


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "printer-01.corp.local")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("printer-01.corp.local"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


def test_tls_certificate_metadata(monkeypatch, tmp_path):
    cert_path, key_path = _self_signed(tmp_path)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(cert_path, key_path)

    async def main():  # type: ignore[no-untyped-def]
        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            with contextlib.suppress(Exception):
                await reader.read(1024)
                writer.write(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n")
                await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_ctx)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr(tcp_probe, "HTTPS_PORTS", frozenset({port}))
        async with server:
            return await probe_tcp("127.0.0.1", port, limits(), grab_banner=True)

    result = asyncio.run(main())
    assert result is not None and result.state == "open"
    assert result.tls is not None and result.tls["handshake"] == "ok"
    cert = result.tls["certificate"]
    assert cert["subject_cn"] == "printer-01.corp.local" and cert["self_signed"] is True
    assert "printer-01.corp.local" in cert["san_dns"]
    assert b"nginx/1.25.3" in (result.banner or b"")


def test_tls_handshake_failure_still_open(monkeypatch):
    async def main():  # type: ignore[no-untyped-def]
        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            writer.write(b"not tls at all\r\n")
            await writer.drain()
            writer.close()

        server, port = await _serve(handler)
        monkeypatch.setattr(tcp_probe, "HTTPS_PORTS", frozenset({port}))
        async with server:
            return await probe_tcp("127.0.0.1", port, limits(), grab_banner=True)

    result = asyncio.run(main())
    assert result is not None and result.state == "open" and result.tls == {"handshake": "failed"}


def test_rate_limiter_bounds_throughput():
    async def main() -> float:
        limiter = RateLimiter(10)
        start = time.monotonic()
        for _ in range(20):  # burst of 10, then 10 more at 10/s
            await limiter.acquire()
        return time.monotonic() - start

    elapsed = asyncio.run(main())
    assert 0.85 <= elapsed < 3.0


# --- engine ---------------------------------------------------------------------------------


def _config(**overrides):  # type: ignore[no-untyped-def]
    base = dict(
        discovery_ports=(), tcp_ports=(), use_icmp=True, use_arp=True, resolve_dns=True, grab_banners=True,
        max_concurrency=16, per_host_concurrency=4, rate_per_second=500, connect_timeout_ms=3000, retries=0,
    )
    base.update(overrides)
    return EngineConfig(**base)


class _Listener:
    """Background TCP server that volunteers an SSH banner."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            with contextlib.suppress(OSError):
                conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
                time.sleep(0.2)
                conn.close()

    def close(self) -> None:
        self._stop = True
        self.thread.join(2)
        self.sock.close()


@pytest.fixture
def listener():  # type: ignore[no-untyped-def]
    srv = _Listener()
    yield srv
    srv.close()


def test_engine_end_to_end_on_loopback(listener, monkeypatch):
    monkeypatch.setattr(tcp_probe, "TALK_FIRST_PORTS", frozenset({listener.port}))
    closed = free_port()

    async def no_ping(ip: str, t: int) -> PingResult:
        return PingResult(False, None)

    async def resolver(ip: str) -> str:
        return "loopback-host"

    cfg = _config(discovery_ports=(closed,), tcp_ports=(listener.port, closed))
    engine = ScanEngine(cfg, threading.Event(), pinger=no_ping, resolver=resolver,
                        neighbor_reader=lambda: {"127.0.0.1": Neighbor("AA:BB:CC:00:00:01", True)}, netbios_query=None, ssdp_discover=None)
    chunks: list = []
    completed = engine.run(iter(["127.0.0.1"]), lambda obs, n: chunks.append((obs, n)))
    assert completed is True
    (observations, processed), = chunks
    assert processed == 1
    obs = observations[0]
    # Alive because the closed port answered with RST (and the neighbour entry is reachable).
    assert "tcp" in obs.methods and "arp" in obs.methods and "icmp" not in obs.methods
    assert obs.ports[listener.port].state == "open"
    assert obs.ports[listener.port].banner == b"SSH-2.0-OpenSSH_9.6\r\n"
    assert obs.ports[closed].state == "closed"
    assert obs.mac == "AA:BB:CC:00:00:01" and obs.hostname == "loopback-host"


def test_stale_neighbor_entry_does_not_prove_liveness():
    async def no_ping(ip: str, t: int) -> PingResult:
        return PingResult(False, None)

    cfg = _config(tcp_ports=())
    engine = ScanEngine(cfg, threading.Event(), pinger=no_ping, resolver=lambda ip: asyncio.sleep(0, None),
                        neighbor_reader=lambda: {"127.0.0.1": Neighbor("AA:BB:CC:00:00:01", False)}, netbios_query=None, ssdp_discover=None)
    chunks: list = []
    assert engine.run(iter(["127.0.0.1"]), lambda obs, n: chunks.append((obs, n)))
    assert chunks == [([], 1)]


def test_engine_cancellation_stops_between_chunks(monkeypatch):
    monkeypatch.setattr(engine_mod, "CHUNK_SIZE", 4)
    cancel = threading.Event()

    async def slow_ping(ip: str, t: int) -> PingResult:
        await asyncio.sleep(0.05)
        return PingResult(True, 64)

    async def resolver(ip: str) -> None:
        return None

    engine = ScanEngine(_config(use_arp=False), cancel, pinger=slow_ping, resolver=resolver, neighbor_reader=dict, netbios_query=None, ssdp_discover=None)
    calls: list[int] = []

    def on_chunk(obs, n):  # type: ignore[no-untyped-def]
        calls.append(n)
        cancel.set()  # operator presses "stop" after the first chunk

    targets = iter([f"127.0.0.{i}" for i in range(1, 13)])
    assert engine.run(targets, on_chunk) is False
    assert calls == [4]


def test_engine_cancelled_before_start_does_nothing():
    cancel = threading.Event()
    cancel.set()
    engine = ScanEngine(_config(), cancel, neighbor_reader=dict, netbios_query=None, ssdp_discover=None)
    calls: list = []
    assert engine.run(iter(["127.0.0.1"]), lambda o, n: calls.append(n)) is False
    assert calls == []


def test_engine_from_profile_applies_port_exclusions():
    profile = dict(
        discovery_ports=[22, 80, 445], tcp_ports=[22, 80, 443, 445], use_icmp=True, use_arp=True, resolve_dns=True,
        grab_banners=False, max_concurrency=8, per_host_concurrency=2, rate_per_second=10, connect_timeout_ms=1000, retries=0,
    )
    cfg = EngineConfig.from_profile(profile, excluded_ports=[445])
    assert 445 not in cfg.discovery_ports and 445 not in cfg.tcp_ports
    assert cfg.tcp_ports == (22, 80, 443)


def test_real_system_ping_of_loopback():
    """Executes the OS ping utility; skipped only if no ping binary exists on this host."""
    from rased.discovery.icmp import ping, ping_executable

    if ping_executable() is None:
        pytest.skip("no ping executable on this host")
    result = asyncio.run(ping("127.0.0.1", 1000))
    assert result.alive and result.ttl is not None
