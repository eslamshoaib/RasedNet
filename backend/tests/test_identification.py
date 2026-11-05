"""Service identification and device fingerprinting (pure functions)."""

import struct

from rased.discovery.fingerprint import FingerprintInput, classify
from rased.discovery.services import identify_service


def test_ssh_banner():
    ident = identify_service(22, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    assert (ident.service_name, ident.product, ident.version, ident.method) == ("ssh", "OpenSSH", "8.9p1", "banner")
    assert ident.exposure_category == "remote_admin"


def test_ssh_on_nonstandard_port():
    ident = identify_service(2222, b"SSH-2.0-dropbear_2022.83\r\n")
    assert ident.service_name == "ssh" and ident.product == "dropbear" and ident.version == "2022.83"


def test_http_server_headers():
    nginx = identify_service(80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n")
    assert (nginx.service_name, nginx.product, nginx.version) == ("http", "nginx", "1.24.0")
    iis = identify_service(443, b"HTTP/1.1 404 Not Found\r\nServer: Microsoft-IIS/10.0\r\n\r\n", tls=True)
    assert (iis.service_name, iis.product, iis.version) == ("https", "Microsoft-IIS", "10.0")
    no_version = identify_service(8080, b"HTTP/1.0 302 Found\r\nServer: Apache\r\n\r\n")
    assert no_version.product == "Apache" and no_version.version is None


def test_ftp_and_smtp():
    ftp = identify_service(21, b"220 (vsFTPd 3.0.5)\r\n")
    assert (ftp.service_name, ftp.product, ftp.version) == ("ftp", "vsFTPd", "3.0.5")
    smtp = identify_service(25, b"220 mail.corp.local ESMTP Postfix (Ubuntu)\r\n")
    assert smtp.service_name == "smtp" and smtp.product == "Postfix"


def test_mysql_greeting():
    version = b"8.0.36-0ubuntu0.22.04.1"
    payload = b"\x0a" + version + b"\x00" + b"\x01\x00\x00\x00" + b"abcdefgh\x00"
    packet = struct.pack("<I", len(payload))[:3] + b"\x00" + payload
    ident = identify_service(3306, packet)
    assert (ident.service_name, ident.product, ident.version) == ("mysql", "MySQL", "8.0.36")


def test_port_only_identification_is_low_confidence():
    rdp = identify_service(3389, None)
    assert rdp.service_name == "rdp" and rdp.method == "port" and rdp.confidence < 0.5
    unknown = identify_service(12345, None)
    assert unknown.service_name == "unknown" and unknown.exposure_category == "other"


def test_malicious_banner_is_neutralised():
    ident = identify_service(22, b"SSH-2.0-Evil\x1b[31m<img src=x onerror=alert(1)>\r\n")
    assert ident.banner is not None and "\x1b" not in ident.banner
    assert ident.product == "Evil"


def fp(**kw):  # type: ignore[no-untyped-def]
    kw.setdefault("open_ports", frozenset())
    return classify(FingerprintInput(**kw))


def test_windows_workstation():
    c = fp(open_ports=frozenset({135, 139, 445, 3389}), ttl=128)
    assert c.os_family == "windows" and c.device_type == "computer"
    assert 0.5 <= c.os_confidence < 1.0
    assert any(e.signal == "port" for e in c.evidence)


def test_domain_controller_is_server():
    c = fp(open_ports=frozenset({53, 88, 135, 389, 445, 636, 3268}))
    assert c.device_type == "server" and c.os_family == "windows"


def test_printer():
    c = fp(open_ports=frozenset({80, 443, 9100, 515, 631}))
    assert c.device_type == "printer" and c.device_confidence > 0.8


def test_ios_device():
    c = fp(open_ports=frozenset({62078}), mac_randomized=True, mac="DA:A1:19:00:00:01")
    assert c.device_type == "mobile" and c.os_family == "ios"


def test_virtual_machine_oui():
    c = fp(mac="00:50:56:12:34:56", open_ports=frozenset({22}), products=("OpenSSH 9.6p1 Ubuntu",))
    assert c.device_type == "virtual_machine" and c.os_family == "linux"


def test_no_evidence_is_unknown_not_a_guess():
    c = fp()
    assert (c.device_type, c.device_confidence, c.os_family, c.os_confidence) == ("unknown", 0.0, "unknown", 0.0)


def test_weak_evidence_stays_unknown():
    c = fp(mac_randomized=True, mac="DA:A1:19:00:00:01")
    assert c.device_type == "unknown"


def test_confidence_never_reaches_certainty():
    c = fp(open_ports=frozenset({9100, 515, 631, 80}), banners=("JetDirect printer cups",), hostname="printer-3", vendor="Hewlett Packard")
    assert c.device_type == "printer" and c.device_confidence < 1.0


def test_mikrotik_winbox_is_router():
    c = fp(open_ports=frozenset({8291, 80}))
    assert c.device_type == "router" and c.device_confidence > 0.8


def test_roku_port_is_tv():
    c = fp(open_ports=frozenset({8060, 8008}))
    assert c.device_type == "tv" and c.device_confidence > 0.7


def test_tv_vendor_plus_cast_port():
    c = fp(open_ports=frozenset({8008, 9000}), vendor="Hisense Electric Co Ltd", hostname="livingroom-smarttv")
    assert c.device_type == "tv" and c.device_confidence > 0.7


def test_nfs_afp_is_nas():
    c = fp(open_ports=frozenset({111, 2049, 548}))
    assert c.device_type == "nas"


def test_android_adb_os():
    c = fp(open_ports=frozenset({5555, 8008}), hostname="mibox-salon")
    assert c.os_family == "android" and c.device_type == "tv"
