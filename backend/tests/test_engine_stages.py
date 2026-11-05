"""Staged discovery logic: which ports are probed for which targets, with which timing."""

from __future__ import annotations

import ipaddress
import threading

import pytest

from rased.discovery import engine as engine_mod
from rased.discovery.arp import Neighbor
from rased.discovery.engine import EngineConfig, ScanEngine
from rased.discovery.icmp import PingResult
from rased.discovery.tcp_probe import TcpProbeResult

LAN = ipaddress.ip_network("10.150.0.0/20")


def cfg(**kw):  # type: ignore[no-untyped-def]
    base = dict(
        discovery_ports=(22, 80, 135, 139, 443, 445, 3389, 8080), tcp_ports=(), use_icmp=True, use_arp=True,
        resolve_dns=False, grab_banners=False, max_concurrency=64, per_host_concurrency=8,
        rate_per_second=5000, connect_timeout_ms=2500, retries=1,
    )
    base.update(kw)
    return EngineConfig(**base)


@pytest.fixture
def probes(monkeypatch):  # type: ignore[no-untyped-def]
    """Replace TCP probing with a recorder; ``open_map`` defines which (ip, port) are open."""
    calls: list[tuple[str, int, float, int]] = []
    open_map: set[tuple[str, int]] = set()

    async def fake_probe(ip, port, limits, *, grab_banner, cancelled=None, timeout_s=None, retries=None):  # type: ignore[no-untyped-def]
        calls.append((ip, port, timeout_s, retries))
        return TcpProbeResult(port, "open" if (ip, port) in open_map else "filtered")

    monkeypatch.setattr(engine_mod, "probe_tcp", fake_probe)
    return calls, open_map


async def dead(ip: str, t: int) -> PingResult:
    return PingResult(False, None)


def run(engine: ScanEngine, targets: list[str]):  # type: ignore[no-untyped-def]
    out: list = []
    assert engine.run(iter(targets), lambda obs, n: out.extend(obs))
    return {o.ip: o for o in out}


def ports_for(calls, ip):  # type: ignore[no-untyped-def]
    return sorted(p for i, p, _, _ in calls if i == ip)


def test_local_address_without_arp_reply_is_not_probed_further(probes):
    calls, _ = probes
    neighbors = {"10.150.0.1": Neighbor("AA:BB:CC:00:00:01", True)}
    eng = ScanEngine(cfg(), threading.Event(), pinger=dead, neighbor_reader=lambda: neighbors, local_networks=[LAN], netbios_query=None, ssdp_discover=None)
    alive = run(eng, ["10.150.0.1", "10.150.0.77"])
    assert set(alive) == {"10.150.0.1"}  # gateway present via reachable ARP
    assert ports_for(calls, "10.150.0.77") == [80, 445]  # sweep only: 2 attempts instead of 8
    assert ports_for(calls, "10.150.0.1") == [22, 80, 135, 139, 443, 445, 3389, 8080]  # enriched


def test_routed_address_gets_every_discovery_port(probes):
    calls, open_map = probes
    open_map.add(("10.20.0.5", 3389))  # firewalled host: only RDP answers
    eng = ScanEngine(cfg(), threading.Event(), pinger=dead, neighbor_reader=lambda: {"10.150.0.1": Neighbor("AA:BB:CC:00:00:01", True)},
                     local_networks=[LAN], netbios_query=None, ssdp_discover=None)
    alive = run(eng, ["10.20.0.5", "10.20.0.6"])
    assert set(alive) == {"10.20.0.5"} and alive["10.20.0.5"].methods == ["tcp"]
    assert ports_for(calls, "10.20.0.6") == [22, 80, 135, 139, 443, 445, 3389, 8080]


def test_unusable_arp_never_skips_local_hosts(probes):
    calls, open_map = probes
    open_map.add(("10.150.0.9", 8080))
    eng = ScanEngine(cfg(), threading.Event(), pinger=dead, neighbor_reader=dict, local_networks=[LAN], netbios_query=None, ssdp_discover=None)
    alive = run(eng, ["10.150.0.9"])
    assert "10.150.0.9" in alive and 8080 in alive["10.150.0.9"].open_ports


def test_timing_local_vs_routed(probes):
    calls, open_map = probes
    open_map.update({("10.150.0.2", 445), ("10.30.0.2", 445)})
    eng = ScanEngine(cfg(tcp_ports=(80, 9100)), threading.Event(), pinger=dead, neighbor_reader=dict, local_networks=[LAN], netbios_query=None, ssdp_discover=None)
    run(eng, ["10.150.0.2", "10.30.0.2"])
    local = {(t, r) for i, _, t, r in calls if i == "10.150.0.2"}
    routed = {(t, r) for i, _, t, r in calls if i == "10.30.0.2"}
    assert local == {(engine_mod.LOCAL_TIMEOUT_MS / 1000, 0)}  # 1 s, no retries on the LAN
    assert routed == {(2.5, 1)}  # profile timeout and retries through routers
    assert 9100 in ports_for(calls, "10.150.0.2")  # service ports probed for live hosts


def test_icmp_alive_host_is_enriched_and_mac_attached(probes):
    calls, _ = probes

    async def alive_ping(ip: str, t: int) -> PingResult:
        return PingResult(ip == "10.150.0.3", 128 if ip == "10.150.0.3" else None)

    neighbors = {"10.150.0.3": Neighbor("00:1A:2B:3C:4D:5E", True)}
    eng = ScanEngine(cfg(), threading.Event(), pinger=alive_ping, neighbor_reader=lambda: neighbors, local_networks=[LAN], netbios_query=None, ssdp_discover=None)
    alive = run(eng, ["10.150.0.3"])
    obs = alive["10.150.0.3"]
    assert obs.methods[:2] == ["icmp", "arp"] and obs.mac == "00:1A:2B:3C:4D:5E" and obs.ttl == 128
    assert len(ports_for(calls, "10.150.0.3")) == 8


@pytest.mark.skipif(not __import__("sys").platform == "win32", reason="Windows IP Helper API")
def test_native_windows_apis_agree_with_os_tools():
    from rased.discovery import winnet
    from rased.discovery.icmp import parse_ping_output

    rows = winnet.neighbor_table()
    assert rows is not None and all(len(r) == 3 for r in rows)
    assert winnet.icmp_echo("127.0.0.1", 1000)[0] is True
    assert winnet.icmp_echo("192.0.2.1", 300) == (False, None)  # TEST-NET-1: never answers
    assert parse_ping_output("Reply from 127.0.0.1: bytes=32 time<1ms TTL=128").alive
