"""SSDP / UPnP discovery: routers, printers, TVs, cameras and NAS boxes describe themselves.

One M-SEARCH multicast per local interface, then each responder's own description XML is read
(only from the responder's own address — never a third party). XML is parsed with defusedxml.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from defusedxml import ElementTree

from rasednet.text import sanitize_banner

SSDP_ADDR = ("239.255.255.250", 1900)
MAX_DESCRIPTION_BYTES = 128 * 1024
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@dataclass
class UpnpDevice:
    ip: str
    server: str | None = None
    location: str | None = None
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    device_type: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {k: v for k, v in self.__dict__.items() if k != "ip"}


def msearch(mx: int = 2) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
        f"MX: {mx}\r\nST: ssdp:all\r\nUSER-AGENT: RasedNet/0.2 UPnP/1.1\r\n\r\n"
    ).encode("ascii")


def parse_ssdp_response(data: bytes) -> dict[str, str] | None:
    try:
        text = data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    lines = text.split("\r\n")
    if not lines or not lines[0].upper().startswith(("HTTP/1.1 200", "NOTIFY")):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def parse_description(xml: bytes) -> dict[str, str | None]:
    """Extract the root device identity from a UPnP description document."""
    root = ElementTree.fromstring(xml)
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    device = root.find(f"{ns}device")
    if device is None:
        return {}

    def get(tag: str) -> str | None:
        el = device.find(f"{ns}{tag}")
        return sanitize_banner(el.text, 128) if el is not None and el.text else None

    return {
        "friendly_name": get("friendlyName"), "manufacturer": get("manufacturer"), "model_name": get("modelName"),
        "model_number": get("modelNumber"), "device_type": get("deviceType"),
    }


def _fetch_description(url: str, expected_ip: str, timeout: float) -> bytes | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or parts.hostname != expected_ip:
        return None  # never follow a LOCATION that points somewhere else
    try:
        with _NO_PROXY.open(url, timeout=timeout) as resp:  # noqa: S310 - scheme and host validated above
            return resp.read(MAX_DESCRIPTION_BYTES)
    except Exception:  # noqa: BLE001 - devices with broken descriptions are common
        return None


class _Collector(asyncio.DatagramProtocol):
    def __init__(self, found: dict[str, dict[str, str]]) -> None:
        self.found = found

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[no-untyped-def]
        headers = parse_ssdp_response(data)
        if headers is not None and addr[0] not in self.found:
            self.found[addr[0]] = headers


async def discover(local_ips: Iterable[str], wait_s: float = 3.0, fetch_timeout: float = 3.0) -> dict[str, UpnpDevice]:
    loop = asyncio.get_running_loop()
    found: dict[str, dict[str, str]] = {}
    transports = []
    for local_ip in local_ips:
        try:
            if ipaddress.ip_address(local_ip).version != 4:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            sock.bind((local_ip, 0))
            sock.setblocking(False)
            transport, _ = await loop.create_datagram_endpoint(lambda: _Collector(found), sock=sock)
            transport.sendto(msearch(), SSDP_ADDR)
            transports.append(transport)
        except OSError:
            continue
    if not transports:
        return {}
    await asyncio.sleep(wait_s)
    for t in transports:
        t.close()

    devices: dict[str, UpnpDevice] = {}

    async def describe(ip: str, headers: dict[str, str]) -> None:
        dev = UpnpDevice(ip=ip, server=sanitize_banner(headers.get("server"), 128), location=headers.get("location"))
        if dev.location:
            xml = await loop.run_in_executor(None, _fetch_description, dev.location, ip, fetch_timeout)
            if xml:
                try:
                    for key, value in parse_description(xml).items():
                        setattr(dev, key, value)
                except Exception:  # noqa: BLE001 - malformed / hostile XML is ignored
                    pass
        devices[ip] = dev

    await asyncio.gather(*(describe(ip, h) for ip, h in found.items()))
    return devices
