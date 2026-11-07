"""Automatic discovery of candidate scan scopes from the scanner host's own configuration.

Sources (read-only, nothing is sent on the network):
* interfaces: every IPv4 address configured on an *up* interface, with its real netmask;
* routing table: internal prefixes reachable through a gateway (other VLANs/subnets the
  routers have announced to this host).

Limitation: networks that this host neither sits on nor has a route to are invisible here.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import os
import socket
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

VIRTUAL_HINTS = (
    "vethernet", "hyper-v", "wsl", "virtualbox", "vmware", "vmnet", "docker", "br-", "veth",
    "virbr", "tailscale", "zerotier", "wireguard", "wg", "tun", "tap", "loopback", "vpn",
)

IPNet = ipaddress.IPv4Network


@dataclass
class InterfaceAddress:
    interface: str
    address: str
    netmask: str
    is_up: bool = True


@dataclass
class Route:
    prefix: str
    next_hop: str
    interface: str


@dataclass
class CandidateNetwork:
    cidr: str
    sources: list[str] = field(default_factory=list)  # "interface" | "route"
    interfaces: list[str] = field(default_factory=list)
    local_ips: list[str] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)
    is_virtual: bool = False

    @property
    def network(self) -> IPNet:
        return ipaddress.IPv4Network(self.cidr)


def is_virtual_interface(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in VIRTUAL_HINTS)


def _usable(network: IPNet) -> bool:
    return not (
        network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_unspecified
        or network.is_reserved
        or network.prefixlen == 0
        or network.prefixlen > 30
    )


def read_interfaces() -> list[InterfaceAddress]:
    import psutil

    stats = psutil.net_if_stats()
    result: list[InterfaceAddress] = []
    for name, addrs in psutil.net_if_addrs().items():
        up = bool(stats.get(name) and stats[name].isup)
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.netmask:
                result.append(InterfaceAddress(name, addr.address, addr.netmask, up))
    return result


def parse_windows_routes(output: str) -> list[Route]:
    routes = []
    for row in csv.DictReader(io.StringIO(output.strip())):
        prefix = (row.get("DestinationPrefix") or "").strip()
        if prefix:
            routes.append(Route(prefix, (row.get("NextHop") or "").strip(), (row.get("InterfaceAlias") or "").strip()))
    return routes


def parse_linux_routes(output: str) -> list[Route]:
    routes = []
    for line in output.splitlines():
        parts = line.split()
        if not parts or parts[0] in ("default", "broadcast", "local", "unreachable", "blackhole", "prohibit"):
            continue
        prefix = parts[0] if "/" in parts[0] else parts[0] + "/32"
        hop = parts[parts.index("via") + 1] if "via" in parts and parts.index("via") + 1 < len(parts) else "0.0.0.0"
        dev = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else ""
        routes.append(Route(prefix, hop, dev))
    return routes


def read_routes() -> list[Route]:
    kwargs: dict[str, object] = {"capture_output": True, "timeout": 20, "check": False}
    try:
        if sys.platform == "win32":
            kwargs["creationflags"] = 0x08000000
            ps = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
            done = subprocess.run(
                [ps, "-NoProfile", "-NonInteractive", "-Command",
                 "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-NetRoute -AddressFamily IPv4 | "
                 "Select-Object DestinationPrefix,NextHop,InterfaceAlias | ConvertTo-Csv -NoTypeInformation"],
                **kwargs,  # type: ignore[arg-type]
            )
            return parse_windows_routes(done.stdout.decode("utf-8", "replace")) if done.returncode == 0 else []
        for ip_cmd in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"):
            if os.path.isfile(ip_cmd):
                done = subprocess.run([ip_cmd, "-4", "route", "show", "table", "all"], **kwargs)  # type: ignore[arg-type]
                return parse_linux_routes(done.stdout.decode("utf-8", "replace")) if done.returncode == 0 else []
    except (OSError, subprocess.SubprocessError):
        pass
    return []


def build_candidates(interfaces: Iterable[InterfaceAddress], routes: Iterable[Route]) -> list[CandidateNetwork]:
    found: dict[str, CandidateNetwork] = {}

    def entry(network: IPNet) -> CandidateNetwork:
        key = str(network)
        if key not in found:
            found[key] = CandidateNetwork(cidr=key)
        return found[key]

    for addr in interfaces:
        if not addr.is_up:
            continue
        try:
            network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
        except ValueError:
            continue
        if not _usable(network):
            continue
        cand = entry(network)
        if "interface" not in cand.sources:
            cand.sources.append("interface")
        if addr.interface not in cand.interfaces:
            cand.interfaces.append(addr.interface)
        if addr.address not in cand.local_ips:
            cand.local_ips.append(addr.address)

    for route in routes:
        try:
            network = ipaddress.IPv4Network(route.prefix, strict=False)
        except ValueError:
            continue
        if not _usable(network):
            continue
        # A route to a network is only useful if the network itself is not already covered.
        cand = entry(network)
        if "route" not in cand.sources:
            cand.sources.append("route")
        if route.interface and route.interface not in cand.interfaces:
            cand.interfaces.append(route.interface)
        if route.next_hop and route.next_hop not in ("0.0.0.0", "") and route.next_hop not in cand.gateways:
            cand.gateways.append(route.next_hop)

    for cand in found.values():
        cand.is_virtual = bool(cand.interfaces) and all(is_virtual_interface(i) for i in cand.interfaces)
    # Physical networks first, then by address.
    return sorted(found.values(), key=lambda c: (c.is_virtual, c.network.network_address, c.network.prefixlen))


InterfaceReader = Callable[[], list[InterfaceAddress]]
RouteReader = Callable[[], list[Route]]


def discover_candidate_networks(
    interface_reader: InterfaceReader = read_interfaces, route_reader: RouteReader = read_routes
) -> list[CandidateNetwork]:
    return build_candidates(interface_reader(), route_reader())
