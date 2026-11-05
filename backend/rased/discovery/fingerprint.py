"""Evidence-based device classification.

Each signal contributes a weight in (0, 1) to a candidate class. Weights for the same class
are combined with a noisy-OR (1 - Π(1 - w)), so independent signals raise confidence while
no amount of weak evidence ever reaches certainty. Below ``MIN_CONFIDENCE`` the result is
"unknown — requires review" rather than a guess.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from rased.discovery.oui import VIRTUALIZATION_PREFIXES, mac_prefix

MIN_CONFIDENCE = 0.5

DEVICE_TYPES = (
    "computer", "server", "mobile", "tablet", "printer", "nas", "router", "switch",
    "access_point", "network_device", "camera", "tv", "iot", "virtual_machine", "hypervisor", "unknown",
)
OS_FAMILIES = ("windows", "linux", "macos", "ios", "android", "unix", "network_os", "unknown")

PRINTER_VENDORS = ("hewlett", "hp inc", "canon", "epson", "brother", "kyocera", "ricoh", "xerox", "lexmark", "konica", "sharp")
NETWORK_VENDORS = ("cisco", "juniper", "mikrotik", "routerboard", "tp-link", "ubiquiti", "aruba", "netgear", "fortinet", "huawei technologies", "d-link", "zyxel", "ruckus", "meraki")
CAMERA_VENDORS = ("hikvision", "dahua", "axis communications", "hanwha", "uniview")
NAS_VENDORS = ("synology", "qnap")
# Brands that make (almost) only TVs/displays — safe-ish to weight toward a TV.
TV_VENDORS = ("hisense", "tcl", "skyworth", "konka", "changhong", "vizio", "amtran", "sceptre", "funai", "vestel")
MOBILE_VENDORS = ("samsung", "xiaomi", "oppo", "vivo", "oneplus", "realme", "motorola", "honor")
# Mostly desktops/laptops (HP is deliberately absent: its OUIs are shared with printers and switches).
PC_VENDORS = ("dell inc", "lenovo", "fujitsu", "asustek", "acer", "micro-star", "giga-byte", "gigabyte", "intel corporate",
              "azurewave", "liteon", "pegatron", "quanta", "wistron", "compal")


@dataclass(frozen=True)
class Evidence:
    signal: str
    value: str
    target: str  # e.g. "device:printer" or "os:windows"
    weight: float
    detail_ar: str

    def as_dict(self) -> dict[str, object]:
        return {
            "signal": self.signal,
            "value": self.value,
            "target": self.target,
            "weight": round(self.weight, 3),
            "detail_ar": self.detail_ar,
        }


@dataclass(frozen=True)
class FingerprintInput:
    open_ports: frozenset[int]
    products: tuple[str, ...] = ()
    banners: tuple[str, ...] = ()
    ttl: int | None = None
    mac: str | None = None
    mac_randomized: bool = False
    vendor: str | None = None
    hostname: str | None = None
    # NetBIOS node status (UDP 137)
    netbios: bool = False
    netbios_file_server: bool = False
    netbios_domain_controller: bool = False
    netbios_null_mac: bool = False  # Samba answers with an all-zero MAC
    # UPnP self-description (SSDP)
    upnp_type: str | None = None
    upnp_manufacturer: str | None = None
    upnp_model: str | None = None
    upnp_server: str | None = None
    # Default gateway of a network the scanner is attached to
    is_gateway: bool = False


@dataclass
class Classification:
    device_type: str
    device_confidence: float
    os_family: str
    os_confidence: float
    evidence: list[Evidence] = field(default_factory=list)


def _noisy_or(weights: Iterable[float]) -> float:
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - max(0.0, min(0.95, w))
    return 1.0 - remaining


def _collect(data: FingerprintInput) -> list[Evidence]:
    ev: list[Evidence] = []
    ports = data.open_ports
    text = " ".join(data.products + data.banners).lower()
    vendor = (data.vendor or "").lower()
    host = (data.hostname or "").lower()

    def add(signal: str, value: str, target: str, weight: float, detail: str) -> None:
        ev.append(Evidence(signal, value, target, weight, detail))

    # --- infrastructure role / self-description (strongest signals) -------------------
    if data.is_gateway:
        add("gateway", "default route", "device:router", 0.85, "العنوان هو البوابة الافتراضية (الموجّه) لشبكة خادم الفحص")
    upnp_type = (data.upnp_type or "").lower()
    upnp_text = " ".join(x for x in (data.upnp_manufacturer, data.upnp_model) if x).strip()
    model_lower = upnp_text.lower()
    for marker, target, weight, detail in (
        ("internetgatewaydevice", "device:router", 0.9, "يعرّف نفسه عبر UPnP كموجّه إنترنت"),
        ("wfadevice", "device:access_point", 0.6, "يعلن عن خدمة إعداد Wi-Fi (WPS) عبر UPnP"),
        ("printer", "device:printer", 0.9, "يعرّف نفسه عبر UPnP كطابعة"),
        ("digitalsecuritycamera", "device:camera", 0.9, "يعرّف نفسه عبر UPnP ككاميرا مراقبة"),
        ("mediarenderer", "device:tv", 0.6, "جهاز عرض وسائط عبر UPnP (تلفاز أو مشغل)"),
        ("dial-multiscreen", "device:tv", 0.75, "يدعم بروتوكول DIAL للبث (تلفاز ذكي / Chromecast)"),
        ("mediaserver", "device:nas", 0.35, "خادم وسائط عبر UPnP (قد يكون جهاز تخزين)"),
    ):
        if marker in upnp_type:
            add("upnp", data.upnp_type or "", target, weight, detail)
    if upnp_text:
        if any(m in model_lower for m in ("tl-wr", "archer", "router", "hg8", "zte f6", "mikrotik", "routerboard")):
            add("upnp_model", upnp_text, "device:router", 0.6, f"طراز الجهاز المعلن: {upnp_text}")
        if any(m in model_lower for m in ("tl-wa", "eap", "access point", "unifi ap")):
            add("upnp_model", upnp_text, "device:access_point", 0.7, f"طراز الجهاز المعلن: {upnp_text}")
        if any(m in model_lower for m in ("smart tv", "hismart", "hisense", "bravia", "aquos", "webos", "tizen",
                                          "android tv", "google tv", "chromecast", "mitv", "mi tv", "mibox", "firetv",
                                          "fire tv", "roku", "shield", "apple tv", "appletv", "viera", "philips")):
            add("upnp_model", upnp_text, "device:tv", 0.65, f"طراز الجهاز المعلن: {upnp_text}")
    server = (data.upnp_server or "").lower()
    if "microsoft-windows" in server:
        add("upnp_server", data.upnp_server or "", "os:windows", 0.7, "خادم UPnP الخاص بويندوز")
    elif "linux" in server and "device:router" not in {e.target for e in ev}:
        add("upnp_server", data.upnp_server or "", "os:linux", 0.35, "خادم UPnP يعمل على لينكس")
    if data.netbios:
        if data.netbios_null_mac:
            add("netbios", "samba", "os:linux", 0.55, "يستجيب لـ NetBIOS بعنوان فيزيائي صفري (نمط خادم Samba على لينكس)")
        else:
            add("netbios", "nbstat", "os:windows", 0.55, "يستجيب لاستعلام NetBIOS (نمط ويندوز)")
        if data.netbios_domain_controller:
            add("netbios", "<1C>", "device:server", 0.9, "مسجل كوحدة تحكم بالمجال (NetBIOS <1C>)")

    # --- MAC / vendor ---------------------------------------------------------------
    if data.mac and mac_prefix(data.mac) in VIRTUALIZATION_PREFIXES:
        platform = VIRTUALIZATION_PREFIXES[mac_prefix(data.mac)]
        add("mac_oui", platform, "device:virtual_machine", 0.85, f"بادئة MAC خاصة بمنصة افتراضية ({platform})")
    if data.mac_randomized:
        add("mac_randomized", data.mac or "", "device:mobile", 0.3, "عنوان MAC عشوائي (شائع في الهواتف الحديثة، وقد تستخدمه أنظمة أخرى)")
    if vendor:
        if any(v in vendor for v in PRINTER_VENDORS):
            add("mac_vendor", data.vendor or "", "device:printer", 0.35, "الشركة المصنعة لبطاقة الشبكة تنتج طابعات (وأجهزة أخرى)")
        if any(v in vendor for v in NETWORK_VENDORS):
            add("mac_vendor", data.vendor or "", "device:network_device", 0.5, "الشركة المصنعة متخصصة في معدات الشبكات")
        if any(v in vendor for v in CAMERA_VENDORS):
            add("mac_vendor", data.vendor or "", "device:camera", 0.75, "الشركة المصنعة متخصصة في كاميرات المراقبة")
        if any(v in vendor for v in NAS_VENDORS):
            add("mac_vendor", data.vendor or "", "device:nas", 0.8, "الشركة المصنعة متخصصة في أجهزة التخزين الشبكي")
        if any(v in vendor for v in MOBILE_VENDORS):
            add("mac_vendor", data.vendor or "", "device:mobile", 0.4, "الشركة المصنعة تنتج هواتف (وأجهزة أخرى)")
        if any(v in vendor for v in TV_VENDORS):
            add("mac_vendor", data.vendor or "", "device:tv", 0.55, "الشركة المصنعة متخصصة في التلفزيونات والشاشات")
        if any(v in vendor for v in PC_VENDORS):
            add("mac_vendor", data.vendor or "", "device:computer", 0.5, "الشركة المصنعة لبطاقة الشبكة تنتج الحواسيب المكتبية والمحمولة في الغالب")
            if data.ttl is not None and 64 < data.ttl <= 128:
                add("mac_vendor+ttl", f"{data.vendor} / TTL {data.ttl}", "os:windows", 0.3,
                    "حاسوب من مصنع حواسيب مع قيمة TTL افتراضية لويندوز")
        if "apple" in vendor:
            add("mac_vendor", data.vendor or "", "os:macos", 0.25, "الشركة المصنعة Apple (قد يكون حاسوباً أو هاتفاً أو جهازاً لوحياً)")

    # --- open ports -----------------------------------------------------------------
    if 62078 in ports:
        add("port", "62078", "device:mobile", 0.75, "المنفذ 62078 (خدمة مزامنة أجهزة Apple المحمولة)")
        add("port", "62078", "os:ios", 0.8, "المنفذ 62078 خاص بأجهزة iOS/iPadOS")
    if 9100 in ports:
        add("port", "9100", "device:printer", 0.7, "المنفذ 9100 (طباعة مباشرة JetDirect)")
    if 515 in ports:
        add("port", "515", "device:printer", 0.45, "المنفذ 515 (بروتوكول LPD للطباعة)")
    if 631 in ports:
        add("port", "631", "device:printer", 0.35, "المنفذ 631 (IPP؛ يوجد أيضاً في أنظمة لينكس التي تشغل CUPS)")
    if 554 in ports:
        add("port", "554", "device:camera", 0.55, "المنفذ 554 (بث فيديو RTSP)")
    if 902 in ports:
        add("port", "902", "device:hypervisor", 0.7, "المنفذ 902 (خدمة إدارة VMware ESXi)")
    if {135, 445} <= ports:
        add("port", "135,445", "os:windows", 0.65, "المنفذان 135 و445 معاً (RPC وSMB) نمط شائع في ويندوز")
    elif 135 in ports:
        add("port", "135", "os:windows", 0.45, "المنفذ 135 (Microsoft RPC)")
    if 3389 in ports:
        add("port", "3389", "os:windows", 0.5, "المنفذ 3389 (سطح المكتب البعيد)")
    if {88, 389} <= ports:
        add("port", "88,389", "device:server", 0.85, "منافذ Kerberos وLDAP معاً تدل على وحدة تحكم بالمجال أو خادم دليل")
    server_ports = ports & {1433, 1521, 3306, 5432, 27017, 25, 3268}
    if server_ports:
        add("port", ",".join(map(str, sorted(server_ports))), "device:server", 0.55, "خدمات قواعد بيانات أو بريد أو دليل")
    if ports & {139, 445} and ports & {5000, 5001} and not ports & {135, 3389}:
        add("port", "smb+5000/5001", "device:nas", 0.45, "مشاركة SMB مع واجهة إدارة على 5000/5001 (نمط أجهزة NAS)")
    if 53 in ports and ports & {80, 443} and not ports & {135, 445, 3389}:
        add("port", "53+web", "device:router", 0.4, "خدمة DNS مع واجهة ويب (نمط أجهزة التوجيه المنزلية والمكتبية)")
    if 1883 in ports or 8883 in ports:
        add("port", "1883/8883", "device:iot", 0.4, "وسيط MQTT (شائع في أنظمة إنترنت الأشياء)")
    # --- smart-TV / streaming control ports ---
    if ports & {8008, 8009}:
        add("port", "8008/8009", "device:tv", 0.6, "منفذ بث Chromecast / Android TV (DIAL)")
    if 8060 in ports:
        add("port", "8060", "device:tv", 0.8, "منفذ Roku (External Control Protocol)")
    if 7000 in ports and ports & {5000, 7100, 49152}:
        add("port", "7000", "device:tv", 0.45, "خدمة AirPlay (Apple TV أو تلفاز يدعم AirPlay)")
    if 5555 in ports:
        add("port", "5555", "os:android", 0.6, "منفذ ADB (خاص بأندرويد / أندرويد TV)")
    if 9080 in ports or 55000 in ports:
        add("port", "9080/55000", "device:tv", 0.4, "منفذ تحكم شائع في تلفزيونات سامسونج")
    # --- infrastructure / storage ports ---
    if 8291 in ports:
        add("port", "8291", "device:router", 0.85, "منفذ Winbox الخاص بأجهزة MikroTik")
        add("port", "8291", "os:network_os", 0.6, "نظام RouterOS (MikroTik)")
    if 5357 in ports:
        add("port", "5357", "os:windows", 0.5, "منفذ WSD (خدمات ويندوز للأجهزة)")
    if 2049 in ports:
        add("port", "2049", "device:nas", 0.4, "مشاركة NFS (نمط أجهزة التخزين والخوادم)")
    if 548 in ports:
        add("port", "548", "device:nas", 0.45, "بروتوكول AFP لمشاركة ملفات Apple (نمط أجهزة التخزين)")
    if 32400 in ports:
        add("port", "32400", "device:nas", 0.3, "خادم وسائط Plex")
    if 3283 in ports or 5900 in ports and "apple" in vendor:
        add("port", "3283/5900", "os:macos", 0.4, "خدمة إدارة أجهزة Apple عن بُعد")
    if 161 in ports and any(v in vendor for v in NETWORK_VENDORS):
        add("port", "161+network-vendor", "device:network_device", 0.55, "SNMP على جهاز من مصنّع معدات شبكات")

    # --- service products / banners -------------------------------------------------
    if "microsoft-iis" in text or "microsoft-httpapi" in text or "microsoft esmtp" in text:
        add("banner", "Microsoft", "os:windows", 0.6, "توقيع خدمة من مايكروسوفت في استجابة الخدمة")
    if "microsoft-iis" in text or "microsoft esmtp" in text:
        add("banner", "Microsoft server", "device:server", 0.5, "خادم ويب أو بريد من مايكروسوفت")
    for distro in ("ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "raspbian", "alpine"):
        if distro in text:
            add("banner", distro, "os:linux", 0.75, f"اسم توزيعة لينكس ({distro}) في توقيع الخدمة")
            break
    if "openssh" in text and "os:linux" not in {e.target for e in ev}:
        add("banner", "OpenSSH", "os:unix", 0.4, "خادم OpenSSH (يوجد في لينكس ويونكس وأنظمة أخرى)")
    if "cisco" in text or "routeros" in text or "mikrotik" in text:
        add("banner", "network OS", "os:network_os", 0.7, "توقيع نظام تشغيل معدات شبكات")
        add("banner", "network OS", "device:network_device", 0.6, "توقيع نظام تشغيل معدات شبكات")
    if "esxi" in text or "vmware" in text:
        add("banner", "VMware", "device:hypervisor", 0.6, "توقيع VMware في استجابة الخدمة")
    if "printer" in text or "jetdirect" in text or "cups" in text:
        add("banner", "printer", "device:printer", 0.5, "توقيع خدمة طباعة")

    # --- TTL (weak, hop-count dependent) ---------------------------------------------
    if data.ttl is not None:
        if 64 < data.ttl <= 128:
            add("ttl", str(data.ttl), "os:windows", 0.3, "قيمة TTL قريبة من 128 (افتراضي ويندوز) — مؤشر ضعيف")
        elif data.ttl <= 64:
            add("ttl", str(data.ttl), "os:unix", 0.2, "قيمة TTL قريبة من 64 (لينكس/يونكس/أندرويد/iOS) — مؤشر ضعيف")
        else:
            add("ttl", str(data.ttl), "os:network_os", 0.3, "قيمة TTL قريبة من 255 (شائعة في معدات الشبكات) — مؤشر ضعيف")

    # --- hostname conventions ---------------------------------------------------------
    for token, target, weight in (
        ("iphone", "device:mobile", 0.6), ("android", "device:mobile", 0.6), ("galaxy", "device:mobile", 0.5),
        ("ipad", "device:tablet", 0.6), ("printer", "device:printer", 0.5), ("prn", "device:printer", 0.3),
        ("macbook", "device:computer", 0.6), ("desktop-", "device:computer", 0.5), ("laptop", "device:computer", 0.5),
        ("srv", "device:server", 0.35), ("server", "device:server", 0.4), ("cam", "device:camera", 0.3),
        ("nas", "device:nas", 0.35), ("switch", "device:switch", 0.4), ("ap-", "device:access_point", 0.3),
        ("roku", "device:tv", 0.6), ("chromecast", "device:tv", 0.6), ("firetv", "device:tv", 0.6),
        ("appletv", "device:tv", 0.55), ("apple-tv", "device:tv", 0.55), ("mibox", "device:tv", 0.5),
        ("smarttv", "device:tv", 0.6), ("smart-tv", "device:tv", 0.6), ("bravia", "device:tv", 0.6),
        ("hisense", "device:tv", 0.5), ("samsung-tv", "device:tv", 0.5), ("shield", "device:tv", 0.4),
    ):
        if token in host:
            add("hostname", data.hostname or "", target, weight, f"اسم الجهاز يحتوي على «{token}» (تسمية اصطلاحية وليست دليلاً قاطعاً)")
    if host.startswith("iphone") or "iphone" in host:
        add("hostname", data.hostname or "", "os:ios", 0.5, "اسم الجهاز يشير إلى iPhone")
    if "android" in host:
        add("hostname", data.hostname or "", "os:android", 0.5, "اسم الجهاز يشير إلى أندرويد")
    if "desktop-" in host or "laptop-" in host:
        add("hostname", data.hostname or "", "os:windows", 0.35, "نمط التسمية الافتراضي في ويندوز")

    return ev


def classify(data: FingerprintInput) -> Classification:
    evidence = _collect(data)
    device_scores: dict[str, list[float]] = defaultdict(list)
    os_scores: dict[str, list[float]] = defaultdict(list)
    for e in evidence:
        kind, _, name = e.target.partition(":")
        (device_scores if kind == "device" else os_scores)[name].append(e.weight)

    os_family, os_conf = "unknown", 0.0
    if os_scores:
        os_family, weights = max(os_scores.items(), key=lambda kv: (_noisy_or(kv[1]), kv[0]))
        os_conf = _noisy_or(weights)
        if os_conf < MIN_CONFIDENCE:
            os_family, os_conf = "unknown", 0.0

    device_type, dev_conf = "unknown", 0.0
    if device_scores:
        device_type, weights = max(device_scores.items(), key=lambda kv: (_noisy_or(kv[1]), kv[0]))
        dev_conf = _noisy_or(weights)
    # A Windows host with no stronger device signal is most likely a computer.
    if os_family == "windows" and (device_type == "unknown" or dev_conf < MIN_CONFIDENCE):
        device_type, dev_conf = "computer", min(os_conf, 0.6)
        evidence.append(
            Evidence("inference", "windows", "device:computer", dev_conf, "نظام ويندوز دون مؤشرات خادم واضحة ← حاسوب (استنتاج)")
        )
    if dev_conf < MIN_CONFIDENCE:
        device_type, dev_conf = "unknown", 0.0

    return Classification(
        device_type=device_type,
        device_confidence=round(dev_conf, 3),
        os_family=os_family,
        os_confidence=round(os_conf, 3),
        evidence=evidence,
    )
