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
from dataclasses import dataclass, field

from rasednet.i18n import get_lang

NETWORK_DEVICE_TYPES = frozenset({"router", "access_point", "switch", "network_device"})


def _L(ar: str, en: str) -> str:
    return en if get_lang() == "en" else ar

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
    label_en: str = ""


@dataclass
class NetAction:
    id: str
    label_ar: str
    category: str  # "info" (read-only) | "change" (modifies the device)
    command: str
    description_ar: str = ""
    warning_ar: str | None = None
    params: tuple[NetParam, ...] = ()
    label_en: str = ""
    description_en: str = ""
    warning_en: str | None = None

    def public(self) -> dict[str, object]:
        # Localized for the active request language; the exact command stays server-side.
        return {
            "id": self.id,
            "label_ar": _L(self.label_ar, self.label_en or self.label_ar),
            "category": self.category,
            "description_ar": _L(self.description_ar, self.description_en or self.description_ar),
            "warning_ar": (_L(self.warning_ar, self.warning_en or self.warning_ar) if self.warning_ar else None),
            "params": [{"name": p.name, "label_ar": _L(p.label_ar, p.label_en or p.label_ar),
                        "kind": p.kind, "placeholder": p.placeholder} for p in self.params],
        }


@dataclass
class Platform:
    key: str
    name_ar: str
    note_ar: str
    actions: list[NetAction] = field(default_factory=list)
    name_en: str = ""
    note_en: str = ""


def _norm_mac(value: str) -> str:
    if not _MAC_RE.match(value.strip()):
        raise NetAdminError(_L("عنوان MAC غير صالح (الصيغة AA:BB:CC:DD:EE:FF)", "Invalid MAC address (format AA:BB:CC:DD:EE:FF)"))
    return value.strip().replace("-", ":").upper()


def validate_param(param: NetParam, raw: str) -> str:
    label = _L(param.label_ar, param.label_en or param.label_ar)
    value = (raw or "").strip()
    if not value:
        raise NetAdminError(_L(f"يجب إدخال: {label}", f"Required: {label}"))
    if param.kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise NetAdminError(_L(f"{label}: عنوان IP غير صالح", f"{label}: invalid IP address")) from exc
    if param.kind == "mac":
        return _norm_mac(value)
    if param.kind == "interface":
        if not _IFACE_RE.match(value):
            raise NetAdminError(_L(f"{label}: اسم واجهة غير صالح", f"{label}: invalid interface name"))
        return value
    raise NetAdminError(_L("نوع مُدخل غير معروف", "Unknown input type"))


def build_command(action: NetAction, params: dict[str, str]) -> str:
    # Explicit token replacement (not str.format): literal braces in commands, e.g. awk
    # '{print $2}', must pass through untouched. Validated values never contain braces.
    command = action.command
    for param in action.params:
        value = validate_param(param, params.get(param.name, ""))
        token = "{" + param.name + "}"
        if token not in command:  # pragma: no cover - guards template/param mismatch
            raise NetAdminError(_L("نقص في معطيات الأمر", "Missing command parameter"))
        command = command.replace(token, value)
    return command


# ---------------------------------------------------------------------------------------
# Platform command sets
# ---------------------------------------------------------------------------------------

_MAC_PARAM = NetParam("mac", "عنوان MAC للجهاز", "mac", "AA:BB:CC:DD:EE:FF", label_en="Device MAC address")
_IFACE_PARAM = NetParam("iface", "اسم الواجهة", "interface", "ether1 / eth0 / GigabitEthernet0/1", label_en="Interface name")


def _routeros() -> Platform:
    p = Platform("routeros", "ميكروتيك (RouterOS)",
                 "يتصل راصد بـ RouterOS عبر SSH وينفّذ أوامر CLI الخاصة به. استخدم حساباً له صلاحية كافية.",
                 name_en="MikroTik (RouterOS)",
                 note_en="RasedNet connects to RouterOS over SSH and runs its own CLI commands. Use an account with sufficient privilege.")
    p.actions = [
        NetAction("identity", "اسم الجهاز والإصدار", "info", "/system identity print; /system resource print", label_en="Device name & version"),
        NetAction("dhcp_leases", "الأجهزة المتصلة (حجوزات DHCP)", "info", "/ip dhcp-server lease print", label_en="Connected devices (DHCP leases)"),
        NetAction("arp", "جدول ARP", "info", "/ip arp print", label_en="ARP table"),
        NetAction("wifi_clients", "الأجهزة اللاسلكية المتصلة", "info", "/interface wireless registration-table print",
                  description_ar="يعمل على الأجهزة التي تملك واجهات لاسلكية.", label_en="Connected wireless clients",
                  description_en="Works on devices that have wireless interfaces."),
        NetAction("routes", "جدول التوجيه", "info", "/ip route print", label_en="Routing table"),
        NetAction("interfaces", "الواجهات وحالتها", "info", "/interface print", label_en="Interfaces and their status"),
        NetAction("firewall", "قواعد الجدار الناري", "info", "/ip firewall filter print", label_en="Firewall rules"),
        NetAction("dhcp_server", "خوادم DHCP والنطاقات", "info", "/ip dhcp-server print; /ip pool print", label_en="DHCP servers and pools"),
        NetAction("block_mac", "حظر جهاز حسب MAC", "change",
                  "/ip firewall filter add chain=forward src-mac-address={mac} action=drop comment=RasedNet-block",
                  warning_ar="يمنع الجهاز من المرور عبر الموجّه. القاعدة تبقى حتى تحذفها.", params=(_MAC_PARAM,),
                  label_en="Block a device by MAC",
                  warning_en="Prevents the device from passing through the router. The rule stays until you remove it."),
        NetAction("unblock_mac", "رفع الحظر عن جهاز", "change",
                  '/ip firewall filter remove [find comment=RasedNet-block src-mac-address={mac}]', params=(_MAC_PARAM,),
                  label_en="Unblock a device"),
        NetAction("disable_iface", "تعطيل واجهة", "change", "/interface disable {iface}",
                  warning_ar="قد يقطع الاتصال عن جزء من الشبكة.", params=(_IFACE_PARAM,),
                  label_en="Disable an interface", warning_en="May cut off part of the network."),
        NetAction("enable_iface", "تفعيل واجهة", "change", "/interface enable {iface}", params=(_IFACE_PARAM,), label_en="Enable an interface"),
        NetAction("backup", "حفظ نسخة احتياطية من الإعدادات", "change", "/system backup save name=rasednet-backup",
                  description_ar="يحفظ ملف إعدادات على الموجّه باسم rasednet-backup.", label_en="Save a configuration backup",
                  description_en="Saves a config file named rasednet-backup on the router."),
        NetAction("reboot", "إعادة تشغيل الموجّه", "change", "/system reboot",
                  warning_ar="سيُقطع الاتصال بالموجّه أثناء إعادة التشغيل.", label_en="Reboot the router",
                  warning_en="Connection to the router will drop during the reboot."),
    ]
    return p


def _cisco() -> Platform:
    p = Platform("cisco_ios", "سيسكو (IOS)",
                 "أوامر العرض فقط عبر SSH (تتطلب صلاحية مناسبة). تغيير الإعدادات يحتاج جلسة تهيئة (configure) من وحدة التحكم.",
                 name_en="Cisco (IOS)",
                 note_en="Read-only show commands over SSH (require sufficient privilege). Changing settings needs a configure session from the console.")
    p.actions = [
        NetAction("version", "معلومات النظام والإصدار", "info", "show version", label_en="System info & version"),
        NetAction("dhcp", "الأجهزة المتصلة (حجوزات DHCP)", "info", "show ip dhcp binding", label_en="Connected devices (DHCP bindings)"),
        NetAction("arp", "جدول ARP", "info", "show arp", label_en="ARP table"),
        NetAction("mac_table", "جدول عناوين MAC على المنافذ", "info", "show mac address-table", label_en="MAC address table per port"),
        NetAction("routes", "جدول التوجيه", "info", "show ip route", label_en="Routing table"),
        NetAction("interfaces", "حالة الواجهات", "info", "show ip interface brief", label_en="Interface status"),
        NetAction("cdp", "الأجهزة المجاورة (CDP)", "info", "show cdp neighbors detail",
                  description_ar="يكشف أجهزة سيسكو المتصلة مباشرة.", label_en="Neighbour devices (CDP)",
                  description_en="Reveals directly connected Cisco devices."),
        NetAction("run_brief", "ملخص الإعدادات الجارية", "info", "show running-config | include hostname|interface|ip address", label_en="Running-config summary"),
    ]
    return p


def _linux() -> Platform:
    p = Platform("linux", "موجّه/جهاز شبكة بنظام لينكس (OpenWrt / BusyBox / عام)",
                 "يتصل راصد عبر SSH وينفّذ أوامر لينكس. على OpenWrt تسجّل الدخول عادةً بحساب root.",
                 name_en="Linux-based router/network device (OpenWrt / BusyBox / generic)",
                 note_en="RasedNet connects over SSH and runs Linux commands. On OpenWrt you usually sign in as root.")
    leases = ("cat /tmp/dhcp.leases 2>/dev/null || cat /var/lib/misc/dnsmasq.leases 2>/dev/null || "
              "cat /var/lib/dhcp/dhcpd.leases 2>/dev/null || echo 'no known DHCP leases file'")
    wifi = ("for i in $(iw dev 2>/dev/null | awk '$1==\"Interface\"{print $2}'); do "
            "echo \"== $i ==\"; iw dev \"$i\" station dump 2>/dev/null; done; "
            "command -v iw >/dev/null 2>&1 || echo 'the iw command is not available on this device'")
    firewall = "nft list ruleset 2>/dev/null || iptables -L -n -v 2>/dev/null || echo 'could not read firewall rules'"
    p.actions = [
        NetAction("system", "معلومات النظام", "info",
                  "uname -a; uptime; cat /etc/openwrt_release 2>/dev/null; free 2>/dev/null | head -n2", label_en="System info"),
        NetAction("dhcp_leases", "الأجهزة المتصلة (حجوزات DHCP)", "info", leases, label_en="Connected devices (DHCP leases)"),
        NetAction("neighbors", "جدول الجيران (ARP)", "info", "ip neigh show 2>/dev/null || arp -an", label_en="Neighbour table (ARP)"),
        NetAction("wifi_clients", "الأجهزة اللاسلكية المتصلة", "info", wifi, label_en="Connected wireless clients"),
        NetAction("routes", "جدول التوجيه", "info", "ip route show 2>/dev/null || route -n", label_en="Routing table"),
        NetAction("interfaces", "الواجهات وعناوينها", "info", "ip -br addr 2>/dev/null || ifconfig -a", label_en="Interfaces and their addresses"),
        NetAction("firewall", "قواعد الجدار الناري", "info", firewall, label_en="Firewall rules"),
        NetAction("block_mac", "حظر جهاز حسب MAC", "change",
                  "iptables -I FORWARD -m mac --mac-source {mac} -j DROP && echo 'blocked'",
                  warning_ar="يمنع الجهاز من المرور عبر الموجّه. لا تدوم القاعدة بعد إعادة التشغيل ما لم تُحفظ في إعداد الجهاز.",
                  params=(_MAC_PARAM,), label_en="Block a device by MAC",
                  warning_en="Prevents the device from passing through the router. The rule does not survive a reboot unless saved to the device config."),
        NetAction("unblock_mac", "رفع الحظر عن جهاز", "change",
                  "iptables -D FORWARD -m mac --mac-source {mac} -j DROP && echo 'unblocked'", params=(_MAC_PARAM,),
                  label_en="Unblock a device"),
        NetAction("iface_down", "تعطيل واجهة", "change", "ip link set {iface} down && echo 'disabled'",
                  warning_ar="قد يقطع الاتصال عن جزء من الشبكة.", params=(_IFACE_PARAM,),
                  label_en="Disable an interface", warning_en="May cut off part of the network."),
        NetAction("iface_up", "تفعيل واجهة", "change", "ip link set {iface} up && echo 'enabled'", params=(_IFACE_PARAM,), label_en="Enable an interface"),
        NetAction("reboot", "إعادة تشغيل الجهاز", "change", "reboot",
                  warning_ar="سيُقطع الاتصال بالجهاز أثناء إعادة التشغيل.", label_en="Reboot the device",
                  warning_en="Connection to the device will drop during the reboot."),
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
        "platform_ar": _L(platform.name_ar, platform.name_en or platform.name_ar),
        "note_ar": _L(platform.note_ar, platform.note_en or platform.note_ar),
        "actions": [a.public() for a in platform.actions],
    }
