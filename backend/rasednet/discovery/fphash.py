"""Fingerprint hash primitives: JA3 (TLS), favicon (MurmurHash3), DHCP option-55, SSH host key.

Pure, dependency-free building blocks for high-accuracy device/service identification. Each
turns an observed artefact into a stable fingerprint that can be matched against known databases
(ja3er, Shodan favicon hashes, fingerbank DHCP fingerprints, SSH host-key sets). The scan engine
can feed these once it captures the underlying inputs; the functions themselves are standalone.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable

_MASK = 0xFFFFFFFF


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 (unsigned). Matches the mmh3 reference implementation."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & _MASK
    rounded = (length // 4) * 4
    for i in range(0, rounded, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & _MASK
        k1 = ((k1 << 15) | (k1 >> 17)) & _MASK
        k1 = (k1 * c2) & _MASK
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & _MASK
        h1 = (h1 * 5 + 0xE6546B64) & _MASK
    k1 = 0
    tail = length & 3
    if tail >= 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & _MASK
        k1 = ((k1 << 15) | (k1 >> 17)) & _MASK
        k1 = (k1 * c2) & _MASK
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _MASK
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _MASK
    h1 ^= h1 >> 16
    return h1


def _signed32(v: int) -> int:
    return v - 0x100000000 if v & 0x80000000 else v


def favicon_hash(data: bytes) -> int:
    """Shodan-style favicon hash: signed MurmurHash3 of the base64 (with line breaks) of the icon."""
    b64 = base64.encodebytes(data)  # matches python base64.encodestring (76-col lines + trailing \n)
    return _signed32(murmur3_32(b64))


def ja3_string(tls_version: int, ciphers: Iterable[int], extensions: Iterable[int],
               curves: Iterable[int], point_formats: Iterable[int]) -> str:
    """Build the canonical JA3 string from a TLS ClientHello's parsed fields."""
    def join(xs: Iterable[int]) -> str:
        return "-".join(str(int(x)) for x in xs)
    return f"{int(tls_version)},{join(ciphers)},{join(extensions)},{join(curves)},{join(point_formats)}"


def ja3_hash(ja3: str) -> str:
    """The JA3 fingerprint = MD5 of the JA3 string (as used by ja3er / Suricata / Zeek)."""
    # JA3 is defined as the MD5 of the JA3 string — a fingerprint, not a security primitive.
    return hashlib.md5(ja3.encode("ascii", "ignore"), usedforsecurity=False).hexdigest()  # noqa: S324


def dhcp_fingerprint(option55: Iterable[int]) -> dict[str, str]:
    """A DHCP fingerprint (fingerbank-style): the ordered option-55 (Parameter Request List)."""
    seq = ",".join(str(int(o)) for o in option55)
    return {"option55": seq, "hash": hashlib.sha256(seq.encode()).hexdigest()}


def ssh_hostkey_sha256(key_blob_b64: str) -> str:
    """OpenSSH-style host-key fingerprint: 'SHA256:' + base64(sha256(raw key)), no padding."""
    try:
        raw = base64.b64decode(key_blob_b64, validate=False)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("مفتاح SSH غير صالح") from exc
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"
