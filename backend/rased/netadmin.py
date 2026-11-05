"""Administrative control of routers and network devices over their management channel (SSH).

Every action is a fixed command template filled only with strictly-validated parameters
(IP, MAC, interface name). Nothing from the network is ever substituted into a command, and
nothing here bypasses authentication or exploits a service — control happens through the
device's own admin CLI with an authorised account from the vault.

Platforms:
* ``routeros``  — MikroTik RouterOS (its own CLI, no shell / sudo).
* ``cisco_ios`` — Cisco IOS (its own CLI; read-only here — changes need a config session).
* ``linux``     — OpenWrt / BusyBox / generic Linux-based routers and gateways (shell).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field

NETWORK_DEVICE_TYPES = frozenset({"router", "access_point", "switch", "network_device"})

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,32}$")


class NetAdminError(Exception):
    """Arabic, user-facing validation message."""


@dataclass(frozen=True)
class NetParam:
    name: str
    label_ar: str
    kind: str  # "ip" | "mac" | "interface"
    placeholder: str = ""


@dataclass
class NetAction:
    id: str
    label_ar: str
    category: str  # "info" (read-only) | "change" (modifies the device)
    command: str
    description_ar: str = ""
    warning_ar: str | None = None
    params: tuple[NetParam, ...] = ()

    def public(self) -> dict[str, object]:
        d = asdict(self)
        d.pop("command")  # the exact command is built server-side after validation
        return d


@dataclass
class Platform:
    key: str
    name_ar: str
    note_ar: str
    actions: list[NetAction] = field(default_factory=list)


def _norm_mac(value: str) -> str:
    if not _MAC_RE.match(value.strip()):
        raise NetAdminError("عنوان MAC غير صالح (الصيغة AA:BB:CC:DD:EE:FF)")
    return value.strip().replace("-", ":").upper()


def validate_param(param: NetParam, raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise NetAdminError(f"يجب إدخال: {param.label_ar}")
    if param.kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise NetAdminError(f"{param.label_ar}: عنوان IP غير صالح") from exc
    if param.kind == "mac":
        return _norm_mac(value)
    if param.kind == "interface":
        if not _IFACE_RE.match(value):
            raise NetAdminError(f"{param.label_ar}: اسم واجهة غير صالح")
        return value
    raise NetAdminError("نوع مُدخل غير معروف")


def build_command(action: NetAction, params: dict[str, str]) -> str:
    # Explicit token replacement (not str.format): literal braces in commands, e.g. awk
    # '{print $2}', must pass through untouched. Validated values never contain braces.
    command = action.command
    for param in action.params:
        value = validate_param(param, params.get(param.name, ""))
        token = "{" + param.name + "}"
        if token not in command:  # pragma: no cover - guards template/param mismatch
            raise NetAdminError("نقص في معطيات الأمر")
        command = command.replace(token, value)
    return command


# ---------------------------------------------------------------------------------------
# Platform command sets
# ---------------------------------------------------------------------------------------

_MAC_PARAM = NetParam("mac", "عنوان MAC للجهاز", "mac", "AA:BB:CC:DD:EE:FF")
_IFACE_PARAM = NetParam("iface", "اسم الواجهة", "interface", "ether1 / eth0 / GigabitEthernet0/1")


def _routeros() -> Platform:
    p = Platform("routeros", "ميكروتيك (RouterOS)",
                 "يتصل راصد بـ RouterOS عبر SSH وينفّذ أوامر CLI الخاصة به. استخدم حساباً له صلاحية كافية.")
    p.actions = [
        NetAction("identity", "اسم الجهاز والإصدار", "info", "/system identity print; /system resource print"),
        NetAction("dhcp_leases", "الأجهزة المتصلة (حجوزات DHCP)", "info", "/ip dhcp-server lease print"),
        NetAction("arp", "جدول ARP", "info", "/ip arp print"),
        NetAction("wifi_clients", "الأجهزة اللاسلكية المتصلة", "info", "/interface wireless registration-table print",
                  description_ar="يعمل على الأجهزة التي تملك واجهات لاسلكية."),
        NetAction("routes", "جدول التوجيه", "info", "/ip route print"),
        NetAction("interfaces", "الواجهات وحالتها", "info", "/interface print"),
        NetAction("firewall", "قواعد الجدار الناري", "info", "/ip firewall filter print"),
        NetAction("dhcp_server", "خوادم DHCP والنطاقات", "info", "/ip dhcp-server print; /ip pool print"),
        NetAction("block_mac", "حظر جهاز حسب MAC", "change",
                  "/ip firewall filter add chain=forward src-mac-address={mac} action=drop comment=RASED-block",
                  warning_ar="يمنع الجهاز من المرور عبر الموجّه. القاعدة تبقى حتى تحذفها.", params=(_MAC_PARAM,)),
        NetAction("unblock_mac", "رفع الحظر عن جهاز", "change",
                  '/ip firewall filter remove [find comment=RASED-block src-mac-address={mac}]', params=(_MAC_PARAM,)),
        NetAction("disable_iface", "تعطيل واجهة", "change", "/interface disable {iface}",
                  warning_ar="قد يقطع الاتصال عن جزء من الشبكة.", params=(_IFACE_PARAM,)),
        NetAction("enable_iface", "تفعيل واجهة", "change", "/interface enable {iface}", params=(_IFACE_PARAM,)),
        NetAction("backup", "حفظ نسخة احتياطية من الإعدادات", "change", "/system backup save name=rased-backup",
                  description_ar="يحفظ ملف إعدادات على الموجّه باسم rased-backup."),
        NetAction("reboot", "إعادة تشغيل الموجّه", "change", "/system reboot",
                  warning_ar="سيُقطع الاتصال بالموجّه أثناء إعادة التشغيل."),
    ]
    return p


def _cisco() -> Platform:
    p = Platform("cisco_ios", "سيسكو (IOS)",
                 "أوامر العرض فقط عبر SSH (تتطلب صلاحية مناسبة). تغيير الإعدادات يحتاج جلسة تهيئة (configure) من وحدة التحكم.")
    p.actions = [
        NetAction("version", "معلومات النظام والإصدار", "info", "show version"),
        NetAction("dhcp", "الأجهزة المتصلة (حجوزات DHCP)", "info", "show ip dhcp binding"),
        NetAction("arp", "جدول ARP", "info", "show arp"),
        NetAction("mac_table", "جدول عناوين MAC على المنافذ", "info", "show mac address-table"),
        NetAction("routes", "جدول التوجيه", "info", "show ip route"),
        NetAction("interfaces", "حالة الواجهات", "info", "show ip interface brief"),
        NetAction("cdp", "الأجهزة المجاورة (CDP)", "info", "show cdp neighbors detail",
                  description_ar="يكشف أجهزة سيسكو المتصلة مباشرة."),
        NetAction("run_brief", "ملخص الإعدادات الجارية", "info", "show running-config | include hostname|interface|ip address"),
    ]
    return p


def _linux() -> Platform:
    p = Platform("linux", "موجّه/جهاز شبكة بنظام لينكس (OpenWrt / BusyBox / عام)",
                 "يتصل راصد عبر SSH وينفّذ أوامر لينكس. على OpenWrt تسجّل الدخول عادةً بحساب root.")
    leases = ("cat /tmp/dhcp.leases 2>/dev/null || cat /var/lib/misc/dnsmasq.leases 2>/dev/null || "
              "cat /var/lib/dhcp/dhcpd.leases 2>/dev/null || echo 'لا يوجد ملف حجوزات DHCP معروف'")
    wifi = ("for i in $(iw dev 2>/dev/null | awk '$1==\"Interface\"{print $2}'); do "
            "echo \"== $i ==\"; iw dev \"$i\" station dump 2>/dev/null; done; "
            "command -v iw >/dev/null 2>&1 || echo 'الأمر iw غير متوفر على هذا الجهاز'")
    firewall = "nft list ruleset 2>/dev/null || iptables -L -n -v 2>/dev/null || echo 'تعذر قراءة قواعد الجدار الناري'"
    p.actions = [
        NetAction("system", "معلومات النظام", "info",
                  "uname -a; uptime; cat /etc/openwrt_release 2>/dev/null; free 2>/dev/null | head -n2"),
        NetAction("dhcp_leases", "الأجهزة المتصلة (حجوزات DHCP)", "info", leases),
        NetAction("neighbors", "جدول الجيران (ARP)", "info", "ip neigh show 2>/dev/null || arp -an"),
        NetAction("wifi_clients", "الأجهزة اللاسلكية المتصلة", "info", wifi),
        NetAction("routes", "جدول التوجيه", "info", "ip route show 2>/dev/null || route -n"),
        NetAction("interfaces", "الواجهات وعناوينها", "info", "ip -br addr 2>/dev/null || ifconfig -a"),
        NetAction("firewall", "قواعد الجدار الناري", "info", firewall),
        NetAction("block_mac", "حظر جهاز حسب MAC", "change",
                  "iptables -I FORWARD -m mac --mac-source {mac} -j DROP && echo 'تم الحظر'",
                  warning_ar="يمنع الجهاز من المرور عبر الموجّه. لا تدوم القاعدة بعد إعادة التشغيل ما لم تُحفظ في إعداد الجهاز.",
                  params=(_MAC_PARAM,)),
        NetAction("unblock_mac", "رفع الحظر عن جهاز", "change",
                  "iptables -D FORWARD -m mac --mac-source {mac} -j DROP && echo 'تم رفع الحظر'", params=(_MAC_PARAM,)),
        NetAction("iface_down", "تعطيل واجهة", "change", "ip link set {iface} down && echo 'تم التعطيل'",
                  warning_ar="قد يقطع الاتصال عن جزء من الشبكة.", params=(_IFACE_PARAM,)),
        NetAction("iface_up", "تفعيل واجهة", "change", "ip link set {iface} up && echo 'تم التفعيل'", params=(_IFACE_PARAM,)),
        NetAction("reboot", "إعادة تشغيل الجهاز", "change", "reboot",
                  warning_ar="سيُقطع الاتصال بالجهاز أثناء إعادة التشغيل."),
    ]
    return p


_PLATFORMS = {p.key: p for p in (_routeros(), _cisco(), _linux())}


def detect_platform(vendor: str | None, model: str | None, ssh_banner: str | None) -> str:
    text = " ".join(x for x in (vendor, model, ssh_banner) if x).lower()
    if "mikrotik" in text or "routerboard" in text or "routeros" in text or "rosssh" in text:
        return "routeros"
    if "cisco" in text or "ios-xe" in text or "catalyst" in text:
        return "cisco_ios"
    return "linux"


def platform_for(key: str) -> Platform:
    return _PLATFORMS[key]


def get_action(platform_key: str, action_id: str) -> NetAction | None:
    platform = _PLATFORMS.get(platform_key)
    if platform is None:
        return None
    return next((a for a in platform.actions if a.id == action_id), None)


def platform_payload(key: str) -> dict[str, object]:
    platform = _PLATFORMS[key]
    return {
        "platform": platform.key,
        "platform_ar": platform.name_ar,
        "note_ar": platform.note_ar,
        "actions": [a.public() for a in platform.actions],
    }
