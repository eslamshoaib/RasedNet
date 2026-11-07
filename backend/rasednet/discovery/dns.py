"""Reverse DNS using the system resolver (internal DNS servers only, as configured on the host)."""

from __future__ import annotations

import asyncio
import socket

from rasednet.text import sanitize_hostname


async def reverse_lookup(ip: str, timeout_s: float = 2.0) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        host, _aliases, _addrs = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout_s
        )
    except (TimeoutError, OSError, UnicodeError):
        return None
    name = sanitize_hostname(host)
    if name is None or name == ip:
        return None
    return name
