"""Scan orchestration: liveness → neighbour cache → reverse DNS → TCP services, in bounded chunks.

Targets are processed in chunks so memory stays bounded for large scopes and results are
persisted incrementally (an interrupted scan keeps everything already observed).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import sys
import threading
from collections.abc import Awaitable, Callable, Iterable, Iterator
from dataclasses import dataclass, field
from itertools import islice
from typing import Any

from rased.discovery import netbios as netbios_mod
from rased.discovery import ssdp as ssdp_mod
from rased.discovery.arp import Neighbor, read_neighbor_table
from rased.discovery.dns import reverse_lookup
from rased.discovery.icmp import PingResult, ping
from rased.discovery.netbios import NetbiosInfo
from rased.discovery.ssdp import UpnpDevice
from rased.discovery.tcp_probe import ProbeLimits, RateLimiter, TcpProbeResult, probe_tcp

log = logging.getLogger(__name__)

CHUNK_SIZE = 512
# Native ICMP (Windows IP Helper) is cheap; spawning ping.exe / ping is not.
MAX_PARALLEL_PINGS = 128 if sys.platform == "win32" else 32
# Timeout cap for targets on a directly attached network (LAN replies take milliseconds).
LOCAL_TIMEOUT_MS = 1000
# Stage-1 sweep: the discovery ports most likely to answer on typical enterprise hosts.
SWEEP_PRIORITY = (445, 80, 443, 22, 3389, 135, 139, 8080)
SWEEP_PORTS = 2

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network


def detect_local_networks() -> tuple[IPNet, ...]:
    try:
        from rased.discovery.networks import read_interfaces

        nets = []
        for a in read_interfaces():
            if not a.is_up:
                continue
            try:
                net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
            except ValueError:
                continue
            if not net.is_loopback and net.prefixlen < 32:
                nets.append(net)
        return tuple(nets)
    except Exception:  # noqa: BLE001 - detection failure only disables the local-segment shortcut
        return ()


@dataclass(frozen=True)
class EngineConfig:
    discovery_ports: tuple[int, ...]
    tcp_ports: tuple[int, ...]
    use_icmp: bool
    use_arp: bool
    resolve_dns: bool
    grab_banners: bool
    max_concurrency: int
    per_host_concurrency: int
    rate_per_second: int
    connect_timeout_ms: int
    retries: int

    @classmethod
    def from_profile(cls, profile: dict[str, Any], excluded_ports: Iterable[int] = ()) -> EngineConfig:
        excluded = set(excluded_ports)
        return cls(
            discovery_ports=tuple(sorted(set(profile["discovery_ports"]) - excluded)),
            tcp_ports=tuple(sorted(set(profile["tcp_ports"]) - excluded)),
            use_icmp=bool(profile["use_icmp"]),
            use_arp=bool(profile["use_arp"]),
            resolve_dns=bool(profile["resolve_dns"]),
            grab_banners=bool(profile["grab_banners"]),
            max_concurrency=int(profile["max_concurrency"]),
            per_host_concurrency=int(profile["per_host_concurrency"]),
            rate_per_second=int(profile["rate_per_second"]),
            connect_timeout_ms=int(profile["connect_timeout_ms"]),
            retries=int(profile["retries"]),
        )


@dataclass
class HostObservation:
    ip: str
    methods: list[str] = field(default_factory=list)
    ttl: int | None = None
    mac: str | None = None
    mac_reachable: bool = False
    hostname: str | None = None
    ports: dict[int, TcpProbeResult] = field(default_factory=dict)
    netbios: NetbiosInfo | None = None
    upnp: UpnpDevice | None = None

    @property
    def alive(self) -> bool:
        return bool(self.methods)

    @property
    def open_ports(self) -> list[int]:
        return sorted(p for p, r in self.ports.items() if r.state == "open")


Pinger = Callable[[str, int], Awaitable[PingResult]]
NetbiosQuery = Callable[[str, float], Awaitable["NetbiosInfo | None"]]
SsdpDiscover = Callable[[list[str]], Awaitable[dict[str, "UpnpDevice"]]]
Resolver = Callable[[str], Awaitable[str | None]]
NeighborReader = Callable[[], dict[str, Neighbor]]
ChunkCallback = Callable[[list[HostObservation], int], None]


def _chunks(it: Iterator[str], size: int) -> Iterator[list[str]]:
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            return
        yield chunk


class ScanEngine:
    def __init__(
        self,
        config: EngineConfig,
        cancel: threading.Event,
        *,
        pinger: Pinger = ping,
        resolver: Resolver = reverse_lookup,
        neighbor_reader: NeighborReader = read_neighbor_table,
        local_networks: Iterable[IPNet] | None = None,
        netbios_query: NetbiosQuery | None = netbios_mod.query,
        ssdp_discover: SsdpDiscover | None = ssdp_mod.discover,
    ) -> None:
        self.config = config
        self._netbios_query = netbios_query
        self._ssdp_discover = ssdp_discover
        self._upnp: dict[str, UpnpDevice] = {}
        self._cancel_thread = cancel
        self._pinger = pinger
        self._resolver = resolver
        self._neighbor_reader = neighbor_reader
        # Networks the scanner is directly attached to (None = detect from the OS).
        self._local_networks: tuple[IPNet, ...] = (
            tuple(local_networks) if local_networks is not None else detect_local_networks()
        )

    # -- public ------------------------------------------------------------------------
    def run(self, targets: Iterator[str], on_chunk: ChunkCallback) -> bool:
        """Blocking entry point. Returns False if the scan was cancelled."""
        return asyncio.run(self._run(targets, on_chunk))

    # -- internals ---------------------------------------------------------------------
    async def _run(self, targets: Iterator[str], on_chunk: ChunkCallback) -> bool:
        cfg = self.config
        cancelled = asyncio.Event()
        watcher = asyncio.create_task(self._watch_cancel(cancelled))
        limits = ProbeLimits(
            rate=RateLimiter(cfg.rate_per_second),
            global_slots=asyncio.Semaphore(cfg.max_concurrency),
            per_host=cfg.per_host_concurrency,
            timeout_s=cfg.connect_timeout_ms / 1000,
            retries=cfg.retries,
        )
        ping_slots = asyncio.Semaphore(min(MAX_PARALLEL_PINGS, cfg.max_concurrency))
        try:
            # UPnP devices on the attached segments describe themselves (make/model/type).
            if cfg.use_arp and self._ssdp_discover is not None and self._local_networks:
                local_ips = sorted(set(self._local_interface_ips()))
                if local_ips:
                    try:
                        self._upnp = await self._ssdp_discover(local_ips)
                    except Exception:  # noqa: BLE001 - enrichment only; never fails a scan
                        log.warning("ssdp discovery failed", exc_info=True)
            for chunk in _chunks(targets, CHUNK_SIZE):
                if self._cancel_thread.is_set():
                    cancelled.set()
                if cancelled.is_set():
                    return False
                observations = await self._scan_chunk(chunk, limits, ping_slots, cancelled)
                if cancelled.is_set():
                    # Persist what was fully observed before the stop request, then stop.
                    on_chunk([o for o in observations if o.alive], len(chunk))
                    return False
                on_chunk([o for o in observations if o.alive], len(chunk))
            return not (cancelled.is_set() or self._cancel_thread.is_set())
        finally:
            watcher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watcher

    async def _watch_cancel(self, cancelled: asyncio.Event) -> None:
        while not self._cancel_thread.is_set():
            await asyncio.sleep(0.2)
        cancelled.set()

    def _local_interface_ips(self) -> list[str]:
        try:
            from rased.discovery.networks import read_interfaces

            return [a.address for a in read_interfaces() if a.is_up and any(
                ipaddress.ip_address(a.address) in n for n in self._local_networks if n.version == 4)]
        except Exception:  # noqa: BLE001
            return []

    # -- target classification ----------------------------------------------------------
    def _is_local(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr.version == n.version and addr in n for n in self._local_networks)

    def _timing(self, ip: str) -> tuple[float, int]:
        """(timeout seconds, retries). LAN replies take milliseconds; routed paths keep the profile values."""
        cfg = self.config
        if self._is_local(ip):
            return min(cfg.connect_timeout_ms, LOCAL_TIMEOUT_MS) / 1000, 0
        return cfg.connect_timeout_ms / 1000, cfg.retries

    def _split_discovery_ports(self) -> tuple[list[int], list[int]]:
        ports = list(self.config.discovery_ports)
        ordered = [p for p in SWEEP_PRIORITY if p in ports] + [p for p in ports if p not in SWEEP_PRIORITY]
        return ordered[:SWEEP_PORTS], ordered[SWEEP_PORTS:]

    # -- stages -----------------------------------------------------------------------------
    async def _scan_chunk(
        self,
        chunk: list[str],
        limits: ProbeLimits,
        ping_slots: asyncio.Semaphore,
        cancelled: asyncio.Event,
    ) -> list[HostObservation]:
        cfg = self.config
        observations = {ip: HostObservation(ip) for ip in chunk}
        sweep_ports, rest_ports = self._split_discovery_ports()

        # Stage 1 — sweep every address: ICMP echo + the most informative discovery ports.
        # (This also makes the OS resolve ARP for every local address.)
        await asyncio.gather(
            *(self._probe_liveness(observations[ip], sweep_ports, limits, ping_slots, cancelled, ping=cfg.use_icmp)
              for ip in chunk)
        )
        if cancelled.is_set():
            return list(observations.values())

        # Stage 2 — neighbour cache: a *reachable* entry proves presence on the local segment.
        neighbors: dict[str, Neighbor] = {}
        if cfg.use_arp and any(ipaddress.ip_address(ip).version == 4 for ip in chunk):
            loop = asyncio.get_running_loop()
            neighbors = await loop.run_in_executor(None, self._neighbor_reader)
            self._apply_neighbors(observations, neighbors)
        # An empty table means the read failed or ARP is unusable: never skip hosts on that basis.
        arp_authoritative = bool(neighbors)

        # Stage 3 — liveness completion. A local address that did not even answer ARP does not
        # exist, so it is skipped; routed or ARP-less targets get the remaining discovery ports.
        pending = [
            o for o in observations.values()
            if not o.alive and not (arp_authoritative and self._is_local(o.ip))
        ]
        if pending and rest_ports:
            await asyncio.gather(
                *(self._probe_liveness(o, rest_ports, limits, ping_slots, cancelled, ping=False) for o in pending)
            )
        if cancelled.is_set():
            return list(observations.values())

        # UPnP responders inside this chunk are present even if they ignored every probe.
        for ip, obs in observations.items():
            device = self._upnp.get(ip)
            if device is not None:
                obs.upnp = device
                if "ssdp" not in obs.methods:
                    obs.methods.append("ssdp")
        # Stage 4 — enrichment of responsive hosts only: DNS + NetBIOS + remaining ports + service ports.
        alive = [o for o in observations.values() if o.alive]
        await asyncio.gather(*(self._enrich(o, rest_ports, limits, cancelled) for o in alive))
        for o in alive:
            if "tcp" not in o.methods and any(r.state in ("open", "closed") for r in o.ports.values()):
                o.methods.append("tcp")
        for ip in chunk:
            limits.release_host(ip)
        return list(observations.values())

    @staticmethod
    def _apply_neighbors(observations: dict[str, HostObservation], neighbors: dict[str, Neighbor]) -> None:
        for ip, obs in observations.items():
            entry = neighbors.get(ip)
            if entry is None:
                continue
            if entry.reachable and "arp" not in obs.methods:
                obs.methods.append("arp")
            if obs.alive:
                obs.mac = entry.mac
                obs.mac_reachable = entry.reachable

    async def _probe_liveness(
        self,
        obs: HostObservation,
        ports: list[int],
        limits: ProbeLimits,
        ping_slots: asyncio.Semaphore,
        cancelled: asyncio.Event,
        *,
        ping: bool,
    ) -> None:
        cfg = self.config
        timeout_s, retries = self._timing(obs.ip)

        async def do_ping() -> None:
            async with ping_slots:
                if cancelled.is_set():
                    return
                await limits.rate.acquire()
                result = await self._pinger(obs.ip, int(timeout_s * 1000) if self._is_local(obs.ip) else cfg.connect_timeout_ms)
            if result.alive and "icmp" not in obs.methods:
                obs.methods.append("icmp")
                obs.ttl = result.ttl

        async def do_tcp(port: int) -> None:
            result = await probe_tcp(obs.ip, port, limits, grab_banner=False, cancelled=cancelled,
                                     timeout_s=timeout_s, retries=retries)
            if result is not None:
                obs.ports[port] = result

        tasks: list[Awaitable[None]] = [do_tcp(p) for p in ports]
        if ping:
            tasks.append(do_ping())
        await asyncio.gather(*tasks)
        if "tcp" not in obs.methods and any(r.state in ("open", "closed") for r in obs.ports.values()):
            obs.methods.append("tcp")

    async def _enrich(self, obs: HostObservation, rest_ports: list[int], limits: ProbeLimits, cancelled: asyncio.Event) -> None:
        cfg = self.config
        timeout_s, retries = self._timing(obs.ip)
        jobs: list[Awaitable[None]] = []

        if cfg.resolve_dns:
            async def do_dns() -> None:
                obs.hostname = await self._resolver(obs.ip)
            jobs.append(do_dns())

        if self._netbios_query is not None and ipaddress.ip_address(obs.ip).version == 4:
            async def do_netbios() -> None:
                await limits.rate.acquire()
                obs.netbios = await self._netbios_query(obs.ip, timeout_s)
            jobs.append(do_netbios())

        wanted = list(dict.fromkeys([*rest_ports, *cfg.tcp_ports]))
        to_probe = [
            p for p in wanted
            if p not in obs.ports or (cfg.grab_banners and p in cfg.tcp_ports and obs.ports[p].state == "open")
        ]

        async def do_tcp(port: int) -> None:
            result = await probe_tcp(obs.ip, port, limits, grab_banner=cfg.grab_banners and port in cfg.tcp_ports,
                                     cancelled=cancelled, timeout_s=timeout_s, retries=retries)
            if result is None:  # cancelled before probing
                return
            previous = obs.ports.get(port)
            # A banner re-probe must never downgrade an "open" verdict from the discovery phase.
            if previous is not None and previous.state == "open" and result.state != "open":
                return
            obs.ports[port] = result

        jobs.extend(do_tcp(p) for p in to_probe)
        await asyncio.gather(*jobs)
