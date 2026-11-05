"""Direct Windows IP Helper API access (no admin rights, no child processes).

* ``neighbor_table()`` — GetIpNetTable2: the IPv4 neighbour (ARP) cache *with its state*,
  in milliseconds instead of the ~4-5 s that spawning PowerShell costs.
* ``icmp_echo()``      — IcmpSendEcho: ICMP echo without spawning ``ping.exe`` per address.

Both return ``None`` when the API is unavailable so callers can fall back to the portable path.
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
from ctypes import wintypes

AVAILABLE = sys.platform == "win32"

# NL_NEIGHBOR_STATE
_STATE_NAMES = {0: "unreachable", 1: "incomplete", 2: "probe", 3: "delay", 4: "stale", 5: "reachable", 6: "permanent"}
IP_SUCCESS = 0


class _SOCKADDR_INET(ctypes.Union):
    # sockaddr_in6 is the largest member (28 bytes); IPv4 address bytes sit at offset 4.
    _fields_ = [("si_family", ctypes.c_ushort), ("raw", ctypes.c_ubyte * 28)]


class _MIB_IPNET_ROW2(ctypes.Structure):
    _fields_ = [
        ("Address", _SOCKADDR_INET),
        ("InterfaceIndex", ctypes.c_ulong),
        ("InterfaceLuid", ctypes.c_uint64),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PhysicalAddressLength", ctypes.c_ulong),
        ("State", ctypes.c_int),
        ("Flags", ctypes.c_ubyte),
        ("ReachabilityTime", ctypes.c_ulong),
    ]


class _MIB_IPNET_TABLE2(ctypes.Structure):
    _fields_ = [("NumEntries", ctypes.c_ulong), ("Table", _MIB_IPNET_ROW2 * 1)]


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ulong),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", _IP_OPTION_INFORMATION),
    ]


_iphlpapi = None
if AVAILABLE:
    try:
        _iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        _iphlpapi.GetIpNetTable2.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.POINTER(_MIB_IPNET_TABLE2))]
        _iphlpapi.GetIpNetTable2.restype = ctypes.c_ulong
        _iphlpapi.FreeMibTable.argtypes = [ctypes.c_void_p]
        _iphlpapi.FreeMibTable.restype = None
        _iphlpapi.IcmpCreateFile.argtypes = []
        _iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
        _iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        _iphlpapi.IcmpCloseHandle.restype = wintypes.BOOL
        _iphlpapi.IcmpSendEcho.argtypes = [
            wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
        ]
        _iphlpapi.IcmpSendEcho.restype = ctypes.c_ulong
    except (OSError, AttributeError):
        _iphlpapi = None
        AVAILABLE = False


def neighbor_table() -> list[tuple[str, str, str]] | None:
    """Return [(ipv4, MAC 'AA:BB:..', state)] or None if the API cannot be used."""
    if _iphlpapi is None:
        return None
    table = ctypes.POINTER(_MIB_IPNET_TABLE2)()
    if _iphlpapi.GetIpNetTable2(socket.AF_INET, ctypes.byref(table)) != 0:
        return None
    try:
        count = table.contents.NumEntries
        rows = ctypes.cast(
            ctypes.addressof(table.contents.Table), ctypes.POINTER(_MIB_IPNET_ROW2 * count)
        ).contents
        result = []
        for row in rows:
            if row.Address.si_family != socket.AF_INET:
                continue
            # Union members share offset 0: sockaddr_in = family(2) | port(2) | address(4) | zero(8).
            ip = socket.inet_ntoa(bytes(row.Address.raw[4:8]))
            length = min(row.PhysicalAddressLength, 32)
            mac = ":".join(f"{b:02X}" for b in row.PhysicalAddress[:length])
            result.append((ip, mac, _STATE_NAMES.get(row.State, "unknown")))
        return result
    finally:
        _iphlpapi.FreeMibTable(table)


_REPLY_BUFFER = ctypes.sizeof(_ICMP_ECHO_REPLY) + 32 + 8 + 64  # reply + payload + ICMP error room
_PAYLOAD = b"RASED-ICMP-ECHO\x00" * 2  # 32 bytes, same size as Windows ping


def icmp_echo(ip: str, timeout_ms: int) -> tuple[bool, int | None] | None:
    """Blocking ICMP echo for IPv4. Returns (alive, ttl) or None if the API is unavailable.

    Only an echo reply *from the target itself* with status IP_SUCCESS counts: "destination
    unreachable" answers sent by a router are rejected (the same trap as ping.exe's exit code).
    """
    if _iphlpapi is None:
        return None
    try:
        dest_bytes = socket.inet_aton(ip)
    except OSError:
        return None
    dest = struct.unpack("<L", dest_bytes)[0]  # IPAddr is the address in network byte order
    handle = _iphlpapi.IcmpCreateFile()
    if not handle or handle == wintypes.HANDLE(-1).value:
        return None
    try:
        buffer = ctypes.create_string_buffer(_REPLY_BUFFER)
        count = _iphlpapi.IcmpSendEcho(handle, dest, _PAYLOAD, len(_PAYLOAD), None, buffer, _REPLY_BUFFER, max(1, timeout_ms))
        if count == 0:
            return False, None
        reply = _ICMP_ECHO_REPLY.from_buffer(buffer)
        if reply.Status != IP_SUCCESS or reply.Address != dest:
            return False, None
        ttl = int(reply.Options.Ttl)
        return True, ttl if 1 <= ttl <= 255 else None
    finally:
        _iphlpapi.IcmpCloseHandle(handle)


IP_TTL_EXPIRED_TRANSIT = 11013


def icmp_probe_ttl(ip: str, ttl: int, timeout_ms: int) -> tuple[str | None, int | None, bool] | None:
    """One traceroute probe: (responder address, rtt ms, reached target) or None if unavailable.

    A router on the path answers "TTL expired in transit" with its own address; the target answers
    with an echo reply. No answer within the timeout yields (None, None, False).
    """
    if _iphlpapi is None:
        return None
    try:
        dest = struct.unpack("<L", socket.inet_aton(ip))[0]
    except OSError:
        return None
    handle = _iphlpapi.IcmpCreateFile()
    if not handle or handle == wintypes.HANDLE(-1).value:
        return None
    try:
        options = _IP_OPTION_INFORMATION(Ttl=max(1, min(255, ttl)), Tos=0, Flags=0, OptionsSize=0, OptionsData=None)
        buffer = ctypes.create_string_buffer(_REPLY_BUFFER)
        count = _iphlpapi.IcmpSendEcho(handle, dest, _PAYLOAD, len(_PAYLOAD), ctypes.byref(options), buffer,
                                       _REPLY_BUFFER, max(1, timeout_ms))
        if count == 0:
            return None, None, False
        reply = _ICMP_ECHO_REPLY.from_buffer(buffer)
        responder = socket.inet_ntoa(struct.pack("<L", reply.Address))
        if reply.Status == IP_SUCCESS:
            return responder, int(reply.RoundTripTime), True
        if reply.Status == IP_TTL_EXPIRED_TRANSIT:
            return responder, int(reply.RoundTripTime), False
        return None, None, False
    finally:
        _iphlpapi.IcmpCloseHandle(handle)
