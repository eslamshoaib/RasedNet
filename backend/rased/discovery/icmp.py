"""ICMP echo via the operating system's own ``ping`` utility (no raw sockets / admin rights)."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import re
import shutil
import sys
from dataclasses import dataclass

_TTL_RE = re.compile(r"ttl[=\s:]+(\d{1,3})", re.IGNORECASE)


@dataclass(frozen=True)
class PingResult:
    alive: bool
    ttl: int | None


def ping_executable() -> str | None:
    if sys.platform == "win32":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        path = os.path.join(system_root, "System32", "PING.EXE")
        return path if os.path.isfile(path) else None
    for candidate in ("/usr/bin/ping", "/bin/ping", "/sbin/ping", "/usr/sbin/ping"):
        if os.path.isfile(candidate):
            return candidate
    return shutil.which("ping")


def build_ping_command(executable: str, ip: str, timeout_ms: int) -> list[str]:
    version = ipaddress.ip_address(ip).version
    if sys.platform == "win32":
        cmd = [executable, "-n", "1", "-w", str(timeout_ms)]
        if version == 6:
            cmd.append("-6")
        return [*cmd, ip]
    seconds = max(1, round(timeout_ms / 1000))
    cmd = [executable, "-c", "1", "-W", str(seconds)]
    if version == 6:
        cmd.append("-6")
    return [*cmd, ip]


def parse_ping_output(output: str) -> PingResult:
    """A reply is only genuine when it carries a TTL.

    Windows ``ping`` exits with code 0 for "Destination host unreachable" replies sent by a
    router, so the exit code alone is not trustworthy. All locales keep the ASCII ``TTL=``.
    """
    match = _TTL_RE.search(output)
    if not match:
        return PingResult(alive=False, ttl=None)
    ttl = int(match.group(1))
    if not 1 <= ttl <= 255:
        return PingResult(alive=False, ttl=None)
    return PingResult(alive=True, ttl=ttl)


_ICMP_POOL = None


def _icmp_pool():  # type: ignore[no-untyped-def]
    global _ICMP_POOL
    if _ICMP_POOL is None:
        from concurrent.futures import ThreadPoolExecutor

        _ICMP_POOL = ThreadPoolExecutor(max_workers=128, thread_name_prefix="rased-icmp")
    return _ICMP_POOL


async def ping(ip: str, timeout_ms: int) -> PingResult:
    if sys.platform == "win32" and ipaddress.ip_address(ip).version == 4:
        from rased.discovery import winnet

        if winnet.AVAILABLE:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(_icmp_pool(), winnet.icmp_echo, ip, timeout_ms)
            if result is not None:
                return PingResult(alive=result[0], ttl=result[1])
    executable = ping_executable()
    if executable is None:
        return PingResult(alive=False, ttl=None)
    cmd = build_ping_command(executable, ip, timeout_ms)
    creationflags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL,
            creationflags=creationflags,
        )
    except OSError:
        return PingResult(alive=False, ttl=None)
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout_ms / 1000 + 5)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()
        return PingResult(alive=False, ttl=None)
    text = stdout.decode("utf-8", "replace") if stdout else ""
    if "\ufffd" in text and stdout:
        # Windows consoles may emit OEM code pages; TTL digits survive either way.
        text = stdout.decode("latin-1", "replace")
    return parse_ping_output(text)
