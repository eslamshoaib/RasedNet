"""Read the operating system neighbour (ARP) cache.

Only hosts on the scanner's own broadcast domain appear here; routed subnets do not expose
MAC addresses and that limitation is reported to the user.

An entry proves liveness only when the OS marks it *reachable* (recently confirmed).
Stale cache entries can outlive a device by hours, so they are used for MAC enrichment of
hosts already proven alive by another method, never as liveness evidence on their own.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
import subprocess
import sys
from dataclasses import dataclass

_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MAC_RE = re.compile(r"\b([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\b")
_REACHABLE_STATES = {"reachable", "delay", "probe"}


@dataclass(frozen=True)
class Neighbor:
    mac: str
    reachable: bool


def normalize_mac(value: str) -> str | None:
    """Return ``AA:BB:CC:DD:EE:FF`` or ``None`` for invalid / group / null addresses."""
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", value or "")
    if len(hexdigits) != 12:
        return None
    hexdigits = hexdigits.upper()
    if hexdigits in ("000000000000", "FFFFFFFFFFFF"):
        return None
    if int(hexdigits[0:2], 16) & 0x01:  # multicast / broadcast — not a device identity
        return None
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


def _valid_unicast_v4(ip: str) -> str | None:
    try:
        addr = ipaddress.IPv4Address(ip.strip())
    except ValueError:
        return None
    if addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"):
        return None
    return str(addr)


def parse_get_netneighbor_csv(output: str) -> dict[str, Neighbor]:
    """Parse ``Get-NetNeighbor | Select IPAddress,LinkLayerAddress,State | ConvertTo-Csv``."""
    result: dict[str, Neighbor] = {}
    reader = csv.DictReader(io.StringIO(output.strip()))
    for row in reader:
        ip = _valid_unicast_v4(row.get("IPAddress") or "")
        mac = normalize_mac(row.get("LinkLayerAddress") or "")
        state = (row.get("State") or "").strip().lower()
        if not ip or not mac or state in ("unreachable", "incomplete", "permanent"):
            continue
        result[ip] = Neighbor(mac, state in _REACHABLE_STATES)
    return result


def parse_ip_neigh(output: str) -> dict[str, Neighbor]:
    """Parse Linux ``ip -4 neigh show`` output."""
    result: dict[str, Neighbor] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts or "lladdr" not in parts:
            continue
        ip = _valid_unicast_v4(parts[0])
        mac = normalize_mac(parts[parts.index("lladdr") + 1]) if parts.index("lladdr") + 1 < len(parts) else None
        state = parts[-1].lower()
        if not ip or not mac or state in ("failed", "incomplete", "permanent", "noarp"):
            continue
        result[ip] = Neighbor(mac, state in _REACHABLE_STATES)
    return result


def parse_arp_a(output: str) -> dict[str, Neighbor]:
    """Parse Windows ``arp -a`` / BSD ``arp -an`` text. No state information: never reachable."""
    result: dict[str, Neighbor] = {}
    for line in output.splitlines():
        ip_match = _IPV4_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if not ip_match or not mac_match or "incomplete" in line.lower():
            continue
        ip = _valid_unicast_v4(ip_match.group(1))
        mac = normalize_mac(mac_match.group(1))
        if ip and mac:
            result[ip] = Neighbor(mac, False)
    return result


def _run(cmd: list[str]) -> str | None:
    kwargs: dict[str, object] = {"capture_output": True, "timeout": 20, "check": False}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        completed = subprocess.run(cmd, **kwargs)  # type: ignore[call-overload]
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", "replace")


def read_neighbor_table() -> dict[str, Neighbor]:
    """Return the current IPv4 neighbour cache. Failures yield an empty mapping."""
    if sys.platform == "win32":
        from rasednet.discovery import winnet

        rows = winnet.neighbor_table()
        if rows is not None:
            result: dict[str, Neighbor] = {}
            for ip_raw, mac_raw, state in rows:
                ip = _valid_unicast_v4(ip_raw)
                mac = normalize_mac(mac_raw)
                if not ip or not mac or state in ("unreachable", "incomplete", "permanent"):
                    continue
                result[ip] = Neighbor(mac, state in _REACHABLE_STATES)
            return result
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        powershell = os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        out = _run(
            [
                powershell, "-NoProfile", "-NonInteractive", "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
                "Get-NetNeighbor -AddressFamily IPv4 | "
                "Select-Object IPAddress,LinkLayerAddress,@{n='State';e={$_.State.ToString()}} | "
                "ConvertTo-Csv -NoTypeInformation",
            ]
        )
        if out:
            return parse_get_netneighbor_csv(out)
        out = _run([os.path.join(system_root, "System32", "ARP.EXE"), "-a"])
        return parse_arp_a(out) if out else {}
    for ip_cmd in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"):
        if os.path.isfile(ip_cmd):
            out = _run([ip_cmd, "-4", "neigh", "show"])
            if out is not None:
                return parse_ip_neigh(out)
    out = _run(["arp", "-an"])
    return parse_arp_a(out) if out else {}
