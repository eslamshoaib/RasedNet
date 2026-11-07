"""Path discovery (traceroute) to learn how the scanner's network reaches other networks."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class Hop:
    ttl: int
    ip: str | None
    rtt_ms: int | None


def _trace_windows(ip: str, max_hops: int, timeout_ms: int) -> list[Hop] | None:
    from rasednet.discovery import winnet

    hops: list[Hop] = []
    silent = 0
    for ttl in range(1, max_hops + 1):
        result = winnet.icmp_probe_ttl(ip, ttl, timeout_ms)
        if result is None:
            return None
        responder, rtt, reached = result
        hops.append(Hop(ttl, responder, rtt))
        if reached:
            break
        silent = silent + 1 if responder is None else 0
        if silent >= 3:  # three silent hops in a row: stop instead of waiting max_hops timeouts
            break
    return hops


_LINUX_HOP = re.compile(r"^\s*(\d+)\s+(\S+)(?:\s+([\d.]+)\s*ms)?")


def parse_unix_traceroute(output: str) -> list[Hop]:
    hops = []
    for line in output.splitlines()[1:]:
        m = _LINUX_HOP.match(line)
        if not m:
            continue
        addr = m.group(2)
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            addr = None  # "*"
        rtt = int(float(m.group(3))) if m.group(3) and addr else None
        hops.append(Hop(int(m.group(1)), addr, rtt))
    return hops


def _trace_unix(ip: str, max_hops: int, timeout_ms: int) -> list[Hop]:
    exe = shutil.which("traceroute")
    if exe is None:
        return []
    done = subprocess.run([exe, "-n", "-q", "1", "-w", str(max(1, timeout_ms // 1000)), "-m", str(max_hops), ip],
                          capture_output=True, timeout=max_hops * (timeout_ms / 1000 + 1) + 5, check=False)
    return parse_unix_traceroute(done.stdout.decode("utf-8", "replace"))


def trace(ip: str, max_hops: int = 15, timeout_ms: int = 800) -> list[Hop]:
    ipaddress.ip_address(ip)  # validated before anything is sent
    if sys.platform == "win32":
        hops = _trace_windows(ip, max_hops, timeout_ms)
        if hops is not None:
            return hops
    return _trace_unix(ip, max_hops, timeout_ms)


async def trace_many(ips: list[str], max_hops: int = 15, timeout_ms: int = 800) -> dict[str, list[Hop]]:
    loop = asyncio.get_running_loop()
    results = await asyncio.gather(*(loop.run_in_executor(None, trace, ip, max_hops, timeout_ms) for ip in ips))
    return dict(zip(ips, results, strict=True))
