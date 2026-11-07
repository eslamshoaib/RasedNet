"""Scan-scope validation: the safety boundary that keeps scanning inside authorised ranges."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from rasednet.i18n import get_lang, tr

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Internal address space accepted by default. Public ranges need RASEDNET_ALLOW_PUBLIC_SCOPES=true.
_INTERNAL_V4 = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8")
]
_INTERNAL_V6 = [ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128")]

# IPv6 networks larger than this are never enumerated (no brute-force of IPv6 space).
MIN_IPV6_PREFIX = 120


class ScopeError(ValueError):
    """Raised with an Arabic, user-facing explanation."""


@dataclass(frozen=True)
class ValidatedScope:
    network: IPNetwork
    exclusions: tuple[IPNetwork, ...]
    excluded_ports: frozenset[int]

    @property
    def cidr(self) -> str:
        return str(self.network)

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.version != self.network.version or addr not in self.network:
            return False
        return not any(addr in ex for ex in self.exclusions if ex.version == addr.version)

    def targets(self) -> Iterator[str]:
        """Yield every scannable host address (network/broadcast excluded where applicable)."""
        for addr in _hosts(self.network):
            if not any(addr in ex for ex in self.exclusions if ex.version == addr.version):
                yield str(addr)

    def target_count(self) -> int:
        return sum(1 for _ in self.targets())


def _hosts(network: IPNetwork) -> Iterator[IPAddress]:
    # ip_network.hosts() returns the single address for /32 (/128) and both for /31 (/127).
    return iter(network.hosts())


def _is_internal(network: IPNetwork) -> bool:
    candidates = _INTERNAL_V4 if network.version == 4 else _INTERNAL_V6
    return any(network.subnet_of(c) for c in candidates if c.version == network.version)  # type: ignore[arg-type]


def parse_network(cidr: str, *, allow_public: bool, max_hosts: int) -> IPNetwork:
    raw = (cidr or "").strip()
    if not raw:
        raise ScopeError(tr("يجب إدخال نطاق الشبكة بصيغة CIDR مثل 192.168.1.0/24", "Enter the network range in CIDR form, e.g. 192.168.1.0/24"))
    if "/" not in raw:
        # A bare address is accepted as a single host (/32 or /128).
        raw = raw + ("/128" if ":" in raw else "/32")
    try:
        network = ipaddress.ip_network(raw, strict=True)
    except ValueError as exc:
        try:
            suggestion = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ScopeError((f"Invalid range format: {cidr}" if get_lang()=="en" else f"صيغة النطاق غير صالحة: {cidr}")) from exc
        raise ScopeError(
            (f"Range {cidr} has host bits set. Did you mean {suggestion}?" if get_lang()=="en" else f"النطاق {cidr} يحتوي على بتات مضيف. هل تقصد {suggestion}؟")
        ) from exc

    if network.version == 6 and network.prefixlen < MIN_IPV6_PREFIX:
        raise ScopeError(
            (f"IPv6 ranges larger than /{MIN_IPV6_PREFIX} cannot be enumerated. Use neighbour-table or DNS discovery instead." if get_lang()=="en" else f"نطاقات IPv6 الأكبر من /{MIN_IPV6_PREFIX} غير مسموح بفحصها تعدادياً. استخدم الاكتشاف عبر جدول الجيران أو DNS بدلاً من ذلك.")
        )
    if network.is_multicast or network.is_unspecified or network.is_reserved:
        raise ScopeError((f"Range {network} is not scannable (multicast or reserved addresses)." if get_lang()=="en" else f"النطاق {network} غير قابل للفحص (عناوين بث متعدد أو محجوزة)."))
    if not allow_public and not _is_internal(network):
        raise ScopeError(
            (f"Range {network} is not within private internal addresses. Scanning public addresses is disabled by default and requires explicit administrator enablement." if get_lang()=="en" else f"النطاق {network} ليس ضمن العناوين الداخلية الخاصة. فحص العناوين العامة معطل افتراضياً ويتطلب تفعيلاً صريحاً من المسؤول.")
        )
    host_count = network.num_addresses if network.prefixlen >= network.max_prefixlen - 1 else network.num_addresses - (2 if network.version == 4 else 1)
    if host_count > max_hosts:
        raise ScopeError(
            (f"Range {network} has {host_count} addresses, larger than the allowed limit ({max_hosts})." if get_lang()=="en" else f"النطاق {network} يحتوي على {host_count} عنواناً، وهو أكبر من الحد المسموح ({max_hosts}).")
        )
    return network


def parse_exclusions(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    result: list[IPNetwork] = []
    for value in values:
        raw = (value or "").strip()
        if not raw:
            continue
        try:
            result.append(ipaddress.ip_network(raw, strict=False))
        except ValueError as exc:
            raise ScopeError((f"Invalid exclusion address: {value}" if get_lang()=="en" else f"عنوان الاستثناء غير صالح: {value}")) from exc
    return tuple(result)


def parse_ports(values: Iterable[int]) -> frozenset[int]:
    ports: set[int] = set()
    for p in values:
        if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
            raise ScopeError((f"Invalid port number: {p}" if get_lang()=="en" else f"رقم المنفذ غير صالح: {p}"))
        ports.add(p)
    return frozenset(ports)


def validate_scope(
    cidr: str,
    excluded_hosts: Iterable[str],
    excluded_ports: Iterable[int],
    *,
    allow_public: bool,
    max_hosts: int,
) -> ValidatedScope:
    network = parse_network(cidr, allow_public=allow_public, max_hosts=max_hosts)
    exclusions = parse_exclusions(excluded_hosts)
    return ValidatedScope(network=network, exclusions=exclusions, excluded_ports=parse_ports(excluded_ports))
