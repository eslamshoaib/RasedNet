"""MAC address intelligence: vendor (from the offline IEEE registry) and randomisation hints."""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable

# Well-documented virtualisation OUIs. These are facts about the registry, not guesses.
VIRTUALIZATION_PREFIXES: dict[str, str] = {
    "005056": "VMware",
    "000C29": "VMware",
    "000569": "VMware",
    "001C14": "VMware",
    "00155D": "Microsoft Hyper-V",
    "080027": "Oracle VirtualBox",
    "525400": "QEMU/KVM",
    "00163E": "Xen",
}


def mac_prefix(mac: str) -> str:
    return mac.replace(":", "").upper()[:6]


def is_locally_administered(mac: str) -> bool:
    """Second-least-significant bit of the first octet (x2, x6, xA, xE)."""
    return bool(int(mac.replace(":", "")[0:2], 16) & 0x02)


def is_probably_randomized(mac: str) -> bool:
    """Locally administered and not a known virtualisation prefix.

    Modern phones/tablets and Windows "random hardware addresses" use locally administered
    MACs. This is an *inference*: some lab or VPN adapters also use such addresses.
    """
    return is_locally_administered(mac) and mac_prefix(mac) not in VIRTUALIZATION_PREFIXES


def parse_ieee_oui_csv(content: str) -> Iterable[tuple[str, str]]:
    """Parse the IEEE MA-L CSV export (columns: Registry, Assignment, Organization Name, ...)."""
    reader = csv.reader(io.StringIO(content))
    header = next(reader, None)
    if not header or len(header) < 3:
        raise ValueError("ملف OUI غير صالح: الترويسة مفقودة")
    normalized = [h.strip().lower() for h in header]
    try:
        assign_idx = normalized.index("assignment")
        org_idx = normalized.index("organization name")
    except ValueError as exc:
        raise ValueError("ملف OUI غير صالح: الأعمدة المطلوبة غير موجودة") from exc
    for row in reader:
        if len(row) <= max(assign_idx, org_idx):
            continue
        prefix = row[assign_idx].strip().upper()
        vendor = row[org_idx].strip()
        if re.fullmatch(r"[0-9A-F]{6}", prefix) and vendor:
            yield prefix, vendor[:256]
