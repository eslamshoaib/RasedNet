"""Active UDP service probing.

UDP is connectionless, so a silent port is ambiguous (open or filtered). To avoid false
positives RASED sends a *protocol-specific* probe to each well-known UDP port and marks the port
**open only when a real reply comes back**; an ICMP port-unreachable marks it closed, and silence
is reported as ``filtered`` (never as open). No raw sockets or special privileges are needed.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

from rased.discovery.netbios import build_request as netbios_request
from rased.discovery.ssdp import msearch

# --- protocol probe builders (pure) -----------------------------------------------------

def _ber(tag: int, value: bytes) -> bytes:
    # Short-form length only (every field here is < 128 bytes).
    return bytes([tag, len(value)]) + value


def snmp_get_sysdescr(community: str = "public", request_id: int = 0x52534544) -> bytes:
    """A minimal SNMPv2c GET for sysDescr.0 (1.3.6.1.2.1.1.1.0)."""
    oid = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])  # 1.3.6.1.2.1.1.1.0
    varbind = _ber(0x30, _ber(0x06, oid) + _ber(0x05, b""))        # SEQ { OID, NULL }
    varbind_list = _ber(0x30, varbind)
    pdu_body = (_ber(0x02, struct.pack(">I", request_id)) + _ber(0x02, b"\x00")
                + _ber(0x02, b"\x00") + varbind_list)              # req-id, err-status, err-index, vbl
    pdu = _ber(0xA0, pdu_body)                                     # GetRequest PDU
    message = _ber(0x02, b"\x01") + _ber(0x04, community.encode()) + pdu  # version v2c(1), community
    return _ber(0x30, message)


def dns_query(name: str = "version.bind", qtype: int = 16, qclass: int = 3) -> bytes:
    """A DNS query (default: CHAOS TXT version.bind — any DNS server replies with something)."""
    header = struct.pack(">HHHHHH", 0x1A2B, 0x0100, 1, 0, 0, 0)  # id, RD=1, qd=1
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, qclass)


def mdns_query(name: str = "_services._dns-sd._udp.local") -> bytes:
    return dns_query(name, qtype=12, qclass=1)  # PTR, IN


def ntp_client_request() -> bytes:
    """48-byte NTP client packet (LI=0, VN=3, Mode=3)."""
    return b"\x1b" + b"\x00" * 47


def tftp_rrq(filename: str = "rased-probe") -> bytes:
    return struct.pack(">H", 1) + filename.encode() + b"\x00" + b"octet\x00"  # RRQ, mode octet


# port -> (service name, probe bytes)
UDP_PROBES: dict[int, tuple[str, bytes]] = {
    53: ("dns", dns_query()),
    123: ("ntp", ntp_client_request()),
    137: ("netbios-ns", netbios_request(0x4242)),
    161: ("snmp", snmp_get_sysdescr()),
    500: ("isakmp", b"\x00" * 8 + b"\x01\x10\x02\x00" + b"\x00" * 20),
    1900: ("ssdp", msearch()),
    5353: ("mdns", mdns_query()),
    69: ("tftp", tftp_rrq()),
}
DEFAULT_UDP_PORTS = [53, 69, 123, 137, 161, 500, 1900, 5353]


@dataclass
class UdpResult:
    port: int
    service: str
    state: str  # "open" | "closed" | "filtered"


class _Probe(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future[str]) -> None:
        self.fut = fut

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[no-untyped-def]
        if not self.fut.done():
            self.fut.set_result("open")

    def error_received(self, exc: Exception) -> None:  # ICMP port unreachable → connection refused
        if not self.fut.done():
            self.fut.set_result("closed")


async def probe_port(ip: str, port: int, payload: bytes, timeout: float = 2.0) -> str:
    """Send one probe and classify: 'open' (reply), 'closed' (ICMP unreachable) or 'filtered' (silence)."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[str] = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: _Probe(fut), remote_addr=(ip, port))
    except OSError:
        return "filtered"
    try:
        transport.sendto(payload)
        try:
            return await asyncio.wait_for(fut, timeout)
        except TimeoutError:
            return "filtered"
    finally:
        transport.close()


async def scan_host(ip: str, ports: list[int] | None = None, *, timeout: float = 2.0,
                    concurrency: int = 16) -> list[UdpResult]:
    """Probe the given UDP ports on one host. Only ports with a known probe are sent."""
    targets = [p for p in (ports or DEFAULT_UDP_PORTS) if p in UDP_PROBES]
    sem = asyncio.Semaphore(concurrency)

    async def one(port: int) -> UdpResult:
        name, payload = UDP_PROBES[port]
        async with sem:
            state = await probe_port(ip, port, payload, timeout)
        return UdpResult(port=port, service=name, state=state)

    return list(await asyncio.gather(*(one(p) for p in targets)))
