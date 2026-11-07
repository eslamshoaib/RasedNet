"""NetBIOS node-status query (RFC 1002 NBSTAT, UDP 137): computer name, workgroup/domain, MAC.

This is a single, standard, read-only request — the same one Windows' ``nbtstat -A`` sends.
Windows hosts and Samba servers answer it; most other devices ignore it.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
from dataclasses import dataclass, field

from rasednet.text import sanitize_hostname

NBSTAT_PORT = 137


@dataclass
class NetbiosInfo:
    computer_name: str | None = None
    workgroup: str | None = None
    file_server: bool = False  # <20> "Server service" registered: SMB file sharing is active
    domain_controller: bool = False  # <1C> group name registered: domain controller
    mac: str | None = None
    names: list[tuple[str, int, bool]] = field(default_factory=list)


def build_request(transaction_id: int) -> bytes:
    header = struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0)
    raw = b"*" + b"\x00" * 15  # wildcard name
    encoded = bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    question = bytes([32]) + encoded + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, IN
    return header + question


def _skip_name(data: bytes, offset: int) -> int:
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return offset + 2
        offset += 1 + length
    raise ValueError("truncated name")


def parse_response(data: bytes, transaction_id: int | None = None) -> NetbiosInfo | None:
    """Parse an NBSTAT response; returns None for anything malformed or unrelated."""
    try:
        if len(data) < 12:
            return None
        tid, flags, _qd, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if transaction_id is not None and tid != transaction_id:
            return None
        if not flags & 0x8000 or ancount < 1:  # must be a response with an answer
            return None
        offset = _skip_name(data, 12)
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype != 0x0021 or offset + rdlength > len(data):
            return None
        count = data[offset]
        offset += 1
        info = NetbiosInfo()
        for _ in range(count):
            entry = data[offset:offset + 18]
            if len(entry) < 18:
                return None
            name = entry[:15].decode("latin-1").rstrip(" \x00")
            suffix = entry[15]
            group = bool(struct.unpack(">H", entry[16:18])[0] & 0x8000)
            info.names.append((name, suffix, group))
            offset += 18
        mac_bytes = data[offset:offset + 6]
        if len(mac_bytes) == 6 and any(mac_bytes) and not mac_bytes[0] & 0x01:
            info.mac = ":".join(f"{b:02X}" for b in mac_bytes)
        for name, suffix, group in info.names:
            if suffix == 0x00 and not group and info.computer_name is None:
                info.computer_name = sanitize_hostname(name)
            elif suffix == 0x00 and group and info.workgroup is None:
                info.workgroup = sanitize_hostname(name)
            elif suffix == 0x20 and not group:
                info.file_server = True
            elif suffix == 0x1C and group:
                info.domain_controller = True
        return info if info.names else None
    except (struct.error, ValueError, IndexError):
        return None


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, tid: int, future: asyncio.Future[NetbiosInfo | None]) -> None:
        self.tid = tid
        self.future = future

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[no-untyped-def]
        if not self.future.done():
            parsed = parse_response(data, self.tid)
            if parsed is not None:
                self.future.set_result(parsed)

    def error_received(self, exc: Exception) -> None:  # ICMP port unreachable etc.
        if not self.future.done():
            self.future.set_result(None)


async def query(ip: str, timeout_s: float = 1.0) -> NetbiosInfo | None:
    if ":" in ip:
        return None
    loop = asyncio.get_running_loop()
    tid = int.from_bytes(os.urandom(2), "big")
    future: asyncio.Future[NetbiosInfo | None] = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: _Protocol(tid, future), remote_addr=(ip, NBSTAT_PORT))
    except OSError:
        return None
    try:
        transport.sendto(build_request(tid))
        return await asyncio.wait_for(future, timeout_s)
    except (TimeoutError, OSError):
        return None
    finally:
        transport.close()
        with contextlib.suppress(Exception):
            await asyncio.sleep(0)
