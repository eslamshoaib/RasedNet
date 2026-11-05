"""Fingerprint hash primitives: MurmurHash3 / favicon, JA3, DHCP option-55, SSH host key."""

from __future__ import annotations

import base64
import hashlib

from rased.discovery.fphash import (
    dhcp_fingerprint,
    favicon_hash,
    ja3_hash,
    ja3_string,
    murmur3_32,
    ssh_hostkey_sha256,
)


def test_murmur3_known_vectors():
    # Reference MurmurHash3 x86_32 values (seed 0).
    assert murmur3_32(b"") == 0
    assert murmur3_32(b"hello") == 613153351
    assert murmur3_32(b"The quick brown fox jumps over the lazy dog") == 776992547


def test_favicon_hash_is_deterministic_signed():
    assert favicon_hash(b"") == 0
    h = favicon_hash(b"\x89PNG\r\n\x1a\n fake icon bytes")
    assert isinstance(h, int) and -(2 ** 31) <= h < 2 ** 31
    assert favicon_hash(b"\x89PNG\r\n\x1a\n fake icon bytes") == h  # stable


def test_ja3_string_and_hash():
    s = ja3_string(771, [4865, 4866], [0, 11, 10], [29, 23], [0])
    assert s == "771,4865-4866,0-11-10,29-23,0"
    assert ja3_hash(s) == hashlib.md5(s.encode()).hexdigest()


def test_dhcp_fingerprint():
    fp = dhcp_fingerprint([1, 3, 6, 15, 31, 33, 43, 44])
    assert fp["option55"] == "1,3,6,15,31,33,43,44"
    assert fp["hash"] == hashlib.sha256(fp["option55"].encode()).hexdigest()


def test_ssh_hostkey_sha256_matches_openssh_format():
    raw = b"\x00\x00\x00\x07ssh-rsa fake-key-material"
    blob = base64.b64encode(raw).decode()
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    assert ssh_hostkey_sha256(blob) == expected
