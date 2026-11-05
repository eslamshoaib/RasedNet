"""Parsers for OS tool output and untrusted network data (synthetic fixtures)."""

import sys

from rased.discovery.arp import normalize_mac, parse_arp_a, parse_get_netneighbor_csv, parse_ip_neigh
from rased.discovery.icmp import build_ping_command, parse_ping_output
from rased.discovery.oui import is_probably_randomized, parse_ieee_oui_csv
from rased.text import sanitize_banner, sanitize_hostname

WIN_PING_OK = """
Pinging 192.168.1.10 with 32 bytes of data:
Reply from 192.168.1.10: bytes=32 time<1ms TTL=128

Ping statistics for 192.168.1.10:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
"""
WIN_PING_UNREACHABLE = """
Pinging 192.168.5.10 with 32 bytes of data:
Reply from 192.168.1.1: Destination host unreachable.

Ping statistics for 192.168.5.10:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
"""
WIN_PING_ARABIC = "الرد من 10.0.0.1: البايت=32 الوقت=1ms TTL=64"
LINUX_PING = "64 bytes from 10.0.0.1: icmp_seq=1 ttl=63 time=0.512 ms"


def test_ping_parsing():
    assert parse_ping_output(WIN_PING_OK).alive and parse_ping_output(WIN_PING_OK).ttl == 128
    # Windows returns exit code 0 here; only a TTL proves a genuine echo reply.
    assert not parse_ping_output(WIN_PING_UNREACHABLE).alive
    assert parse_ping_output(WIN_PING_ARABIC).ttl == 64
    assert parse_ping_output(LINUX_PING).ttl == 63
    assert not parse_ping_output("").alive
    assert not parse_ping_output("TTL=999").alive


def test_ping_command_is_single_echo():
    cmd = build_ping_command("ping", "10.0.0.1", 1500)
    if sys.platform == "win32":
        assert cmd == ["ping", "-n", "1", "-w", "1500", "10.0.0.1"]
    else:
        assert cmd == ["ping", "-c", "1", "-W", "2", "10.0.0.1"]


NETNEIGHBOR_CSV = '''"IPAddress","LinkLayerAddress","State"
"192.168.1.1","AA-BB-CC-00-11-22","Reachable"
"192.168.1.20","AA-BB-CC-00-11-33","Stale"
"192.168.1.30","00-00-00-00-00-00","Unreachable"
"192.168.1.255","FF-FF-FF-FF-FF-FF","Permanent"
"224.0.0.22","01-00-5E-00-00-16","Permanent"
"192.168.1.40","AA-BB-CC-00-11-44","Permanent"
'''


def test_get_netneighbor_parsing():
    result = parse_get_netneighbor_csv(NETNEIGHBOR_CSV)
    assert set(result) == {"192.168.1.1", "192.168.1.20"}
    assert result["192.168.1.1"].reachable is True
    assert result["192.168.1.20"].reachable is False  # stale cache entries never prove liveness
    assert result["192.168.1.1"].mac == "AA:BB:CC:00:11:22"


def test_ip_neigh_parsing():
    out = (
        "10.0.0.1 dev eth0 lladdr 52:54:00:12:34:56 REACHABLE\n"
        "10.0.0.2 dev eth0 lladdr 52:54:00:12:34:57 STALE\n"
        "10.0.0.3 dev eth0  FAILED\n"
        "10.0.0.4 dev eth0 INCOMPLETE\n"
    )
    result = parse_ip_neigh(out)
    assert set(result) == {"10.0.0.1", "10.0.0.2"}
    assert result["10.0.0.1"].reachable and not result["10.0.0.2"].reachable


def test_arp_a_parsing():
    out = """
Interface: 192.168.1.5 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
    result = parse_arp_a(out)
    assert list(result) == ["192.168.1.1"]
    assert result["192.168.1.1"].reachable is False


def test_normalize_mac():
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("01:00:5e:00:00:01") is None  # multicast
    assert normalize_mac("00:00:00:00:00:00") is None
    assert normalize_mac("zz:zz") is None


def test_randomized_mac_detection():
    assert is_probably_randomized("DA:A1:19:00:00:01")  # locally administered
    assert not is_probably_randomized("00:1A:2B:3C:4D:5E")  # globally unique
    assert not is_probably_randomized("52:54:00:12:34:56")  # QEMU/KVM prefix, not randomisation


def test_oui_csv():
    content = (
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,001A2B,"Example Networks, Inc.",Somewhere\n'
        "MA-L,BADROW,Bad,Nowhere\n"
    )
    assert list(parse_ieee_oui_csv(content)) == [("001A2B", "Example Networks, Inc.")]


def test_banner_sanitisation():
    hostile = b"SSH-2.0-OpenSSH_9.6\x1b[2J\x00\x07<script>alert(1)</script>\xe2\x80\xae" + b"A" * 2000
    clean = sanitize_banner(hostile)
    assert clean is not None
    assert "\x1b" not in clean and "\x00" not in clean and "‮" not in clean
    assert len(clean) <= 512
    assert clean.startswith("SSH-2.0-OpenSSH_9.6")
    assert sanitize_banner(b"\xff\xfe\xfa") is not None  # invalid UTF-8 replaced, not raised
    assert sanitize_banner(b"\x00\x01") is None


def test_hostname_sanitisation():
    assert sanitize_hostname("PC-014.corp.local.") == "pc-014.corp.local"
    assert sanitize_hostname("خادم-الملفات.local") == "خادم-الملفات.local"
    assert sanitize_hostname("evil host<script>") is None
    assert sanitize_hostname("a" * 300) is None
    assert sanitize_hostname("pc‮-01") == "pc-01"
