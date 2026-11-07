"""Administrator guidance per observed service: how to verify it and how to close or harden it.

Commands are built only from validated values (an IP address parsed by ``ipaddress`` and an
integer port) — never from banners or other network-supplied text — so they are safe to copy.
Firewall rule groups are referenced by their resource IDs (``@FirewallAPI.dll,-NNNNN``), which
work on every Windows display language, including Arabic.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field

from rasednet.i18n import get_lang

FW_FILE_PRINTER_SHARING = "@FirewallAPI.dll,-28502"
FW_REMOTE_DESKTOP = "@FirewallAPI.dll,-28752"

def _L(ar: str, en: str) -> str:
    return en if get_lang() == "en" else ar


APPLIANCE_TYPES = {"printer", "camera", "router", "switch", "access_point", "network_device", "iot", "nas"}
HTTP_LIKE = {"http", "https", "http-alt", "https-alt", "http-proxy"}


@dataclass
class Command:
    label_ar: str
    command: str
    shell: str = "powershell"  # powershell | bash
    run_on: str = "device"  # device | admin_pc


def _cmd(ar: str, en: str, command: str, shell: str = "powershell", run_on: str = "device") -> "Command":
    return Command(_L(ar, en), command, shell=shell, run_on=run_on)


@dataclass
class PlatformGuide:
    platform: str  # windows | linux | appliance
    platform_ar: str
    verify: list[Command] = field(default_factory=list)
    disable: list[Command] = field(default_factory=list)
    harden: list[Command] = field(default_factory=list)
    warnings_ar: list[str] = field(default_factory=list)
    notes_ar: list[str] = field(default_factory=list)


def _svc_check(name: str, missing: str) -> str:
    """Print the service state, or an explicit message when it is not installed (never empty output)."""
    return f"$s = Get-Service {name} -ErrorAction SilentlyContinue; if ($s) {{ $s | Select-Object Name, DisplayName, Status, StartType }} else {{ '{missing}' }}"


def _network_checks(ip: str, port: int, service: str) -> list[Command]:
    checks = [
        _cmd("هل المنفذ مفتوح فعلاً؟ (TcpTestSucceeded : True تعني مفتوح)", "Is the port actually open? (TcpTestSucceeded: True means open)", f"Test-NetConnection {ip} -Port {port}", run_on="admin_pc"),
    ]
    if service in HTTP_LIKE:
        scheme = "https" if service.startswith("https") or port in (443, 8443, 4443, 9443) else "http"
        checks.append(_cmd("ما البرنامج الذي يرد؟ (انظر سطر Server)", "Which software answers? (see the Server line)", f"curl.exe -skI {scheme}://{ip}:{port}/", run_on="admin_pc"))
    if service in ("smb", "netbios-ssn"):
        checks.append(_cmd("عرض المجلدات المشتركة الظاهرة على الشبكة", "List the shares visible on the network", f"net view \\\\{ip} /all", shell="powershell", run_on="admin_pc"))
    if service == "rdp":
        checks.append(_cmd("تجربة الاتصال بسطح المكتب البعيد", "Try connecting to Remote Desktop", f"mstsc /v:{ip}", run_on="admin_pc"))
    return checks


def _access_commands(service: str, ip: str, port: int) -> list[Command]:
    """Legitimate administration through the service, with an authorised account (never guessing)."""
    a = lambda ar, en, cmd, shell="powershell": _cmd(ar, en, cmd, shell=shell, run_on="admin_pc")  # noqa: E731
    url_scheme = "https" if service.startswith("https") or port in (443, 8443, 4443, 9443, 5001) else "http"
    table: dict[str, list[Command]] = {
        "rdp": [a("فتح سطح المكتب البعيد للجهاز", "Open the device Remote Desktop", f"mstsc /v:{ip}")],
        "smb": [
            a("عرض المجلدات المشتركة في مستكشف الملفات", "Browse the shares in File Explorer", f'explorer.exe "\\\\{ip}"'),
            a("فتح القرص C الإداري (يتطلب حساب مسؤول على الجهاز)", "Open the administrative C$ share (requires a device admin account)", f'explorer.exe "\\\\{ip}\\C$"'),
        ],
        "netbios-ssn": [a("عرض المجلدات المشتركة في مستكشف الملفات", "Browse the shares in File Explorer", f'explorer.exe "\\\\{ip}"')],
        "msrpc": [
            a("إدارة الكمبيوتر عن بعد (الخدمات، الأقراص، السجلات)", "Remote computer management (services, disks, logs)", f"compmgmt.msc /computer={ip}"),
            a("قراءة معلومات النظام عبر WMI/DCOM", "Read system info over WMI/DCOM",
              f"Get-CimInstance Win32_OperatingSystem -CimSession (New-CimSession -ComputerName {ip} -Credential (Get-Credential) "
              "-SessionOption (New-CimSessionOption -Protocol Dcom)) | Select-Object CSName, Caption, Version, LastBootUpTime"),
        ],
        "winrm-http": [a("جلسة PowerShell عن بعد (يتطلب TrustedHosts عند استخدام عنوان IP)", "Remote PowerShell session (needs TrustedHosts when using an IP)",
                         f"Enter-PSSession -ComputerName {ip} -Credential (Get-Credential)")],
        "winrm-https": [a("جلسة PowerShell عن بعد مشفرة", "Encrypted remote PowerShell session", f"Enter-PSSession -ComputerName {ip} -UseSSL -Credential (Get-Credential)")],
        "ssh": [a("اتصال SSH (استبدل USER باسم المستخدم)", "SSH connection (replace USER with the username)", f"ssh USER@{ip}" + (f" -p {port}" if port != 22 else ""))],
        "ftp": [a("فتح FTP", "Open FTP", f"ftp {ip}")],
        "telnet": [a("اتصال Telnet (غير مشفر؛ يُفضّل SSH)", "Telnet connection (unencrypted; prefer SSH)", f"telnet {ip} {port}")],
        "mssql": [a("الاتصال بقاعدة SQL Server", "Connect to the SQL Server database", f"sqlcmd -S {ip},{port} -U USER")],
        "mysql": [a("الاتصال بقاعدة MySQL", "Connect to the MySQL database", f"mysql -h {ip} -P {port} -u USER -p")],
        "postgresql": [a("الاتصال بقاعدة PostgreSQL", "Connect to the PostgreSQL database", f"psql -h {ip} -p {port} -U USER -d postgres")],
        "mongodb": [a("الاتصال بقاعدة MongoDB", "Connect to the MongoDB database", f'mongosh "mongodb://{ip}:{port}" -u USER')],
        "redis": [a("الاتصال بـ Redis", "Connect to Redis", f"redis-cli -h {ip} -p {port}")],
        "rtsp": [a("فتح بث الكاميرا (VLC)", "Open the camera stream (VLC)", f"vlc rtsp://{ip}:{port}/")],
        "dns": [a("اختبار خادم DNS", "Test the DNS server", f"Resolve-DnsName example.com -Server {ip}")],
        "vnc": [],
    }
    if service in HTTP_LIKE or service in ("ipp", "jetdirect", "lpd", "elasticsearch"):
        commands = [a("فتح واجهة الإدارة في المتصفح", "Open the admin interface in a browser", f'Start-Process "{url_scheme}://{ip}:{port}/"')]
    else:
        commands = table.get(service, [])
    return commands


def _windows_generic(port: int) -> PlatformGuide:
    who = (
        f"$c = Get-NetTCPConnection -State Listen -LocalPort {port} -ErrorAction SilentlyContinue; "
        "if ($c) { $c | Select-Object LocalAddress, LocalPort, OwningProcess, "
        "@{n='Process';e={(Get-Process -Id $_.OwningProcess).ProcessName}} } else { 'Port is not listening' }"
    )
    service = (
        f"$p = (Get-NetTCPConnection -State Listen -LocalPort {port} -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess; "
        "if ($p) { $s = Get-CimInstance Win32_Service -Filter \"ProcessId=$p\"; "
        "if ($s) { $s | Select-Object Name, DisplayName, State, StartMode } "
        "else { \"No Windows service owns this port (process: $((Get-Process -Id $p).ProcessName), PID $p)\" } } "
        "else { 'Port is not listening' }"
    )
    return PlatformGuide(
        platform="windows",
        platform_ar=_L("ويندوز (PowerShell كمسؤول)", "Windows (PowerShell as administrator)"),
        verify=[
            _cmd("هل المنفذ مفتوح على الجهاز، وما البرنامج الذي يفتحه؟", "Is the port open on the device, and which program opens it?", who),
            _cmd("ما خدمة ويندوز المرتبطة بهذا المنفذ؟ (احفظ قيمة Name)", "Which Windows service owns this port? (save the Name value)", service),
        ],
        disable=[
            _cmd("إيقاف الخدمة ومنع تشغيلها تلقائياً (ضع اسم الخدمة من الخطوة السابقة)", "Stop the service and disable autostart (use the Name from the previous step)",
                    "Stop-Service -Name '<ServiceName>' -Force; Set-Service -Name '<ServiceName>' -StartupType Disabled"),
            _cmd("أو: حجب المنفذ في جدار حماية ويندوز مع إبقاء الخدمة تعمل محلياً", "Or: block the port in Windows Firewall while the service keeps running locally",
                    f"New-NetFirewallRule -DisplayName 'RasedNet block TCP {port}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block"),
            _cmd("للتراجع عن قاعدة الحجب", "To undo the block rule", f"Remove-NetFirewallRule -DisplayName 'RasedNet block TCP {port}'"),
        ],
        notes_ar=[_L("إذا كان البرنامج المالك هو System (المعرف 4) فالمنفذ تابع لمكوّن من ويندوز نفسه؛ راجع الأوامر الخاصة بالخدمة.", "If the owning process is System (PID 4), the port belongs to a Windows component itself; see the service-specific commands.")],
    )


def _linux_generic(port: int) -> PlatformGuide:
    return PlatformGuide(
        platform="linux",
        platform_ar=_L("لينكس (طرفية بصلاحية sudo)", "Linux (terminal with sudo)"),
        verify=[
            _cmd("هل المنفذ مفتوح وما البرنامج الذي يفتحه؟", "Is the port open and which program opens it?", f"sudo ss -ltnp 'sport = :{port}' 2>/dev/null || sudo netstat -ltnp 2>/dev/null | grep ':{port} '", shell="bash"),
            _cmd("ما خدمة systemd المرتبطة به؟", "Which systemd service owns it?",
                    f"sudo systemctl status $(sudo ss -ltnpH 'sport = :{port}' | grep -oP 'pid=\\K[0-9]+' | head -n1)", shell="bash"),
        ],
        disable=[
            _cmd("إيقاف الخدمة ومنع تشغيلها تلقائياً (ضع اسم الوحدة من الخطوة السابقة)", "Stop the service and disable autostart (use the unit name from the previous step)",
                    "sudo systemctl disable --now '<unit-name>'", shell="bash"),
            _cmd("أو: حجب المنفذ بجدار الحماية (أوبونتو/ديبيان)", "Or: block the port in the firewall (Ubuntu/Debian)", f"sudo ufw deny {port}/tcp", shell="bash"),
            _cmd("أو: حجب المنفذ بجدار الحماية (ريدهات/روكي/ألما)", "Or: block the port in the firewall (RHEL/Rocky/Alma)",
                    f"sudo firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" port port=\"{port}\" protocol=\"tcp\" reject' && sudo firewall-cmd --reload",
                    shell="bash"),
        ],
    )


def _windows_specific(guide: PlatformGuide, service: str, port: int) -> None:
    if service == "smb":
        guide.verify += [
            _cmd("المجلدات المشتركة على الجهاز", "Shares on the device", "Get-SmbShare | Select-Object Name, Path, Description"),
            _cmd("إعدادات SMB (SMB1 يجب أن يكون False)", "SMB settings (SMB1 should be False)",
                    "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature"),
            _cmd("حالة خدمة مشاركة الملفات", "File-sharing service status", "Get-Service LanmanServer"),
        ]
        guide.disable = [
            _cmd("إغلاق مشاركة الملفات والطابعات في جدار الحماية (كل لغات ويندوز)", "Block File & Printer Sharing in the firewall (all Windows languages)",
                    f"Disable-NetFirewallRule -Group '{FW_FILE_PRINTER_SHARING}'"),
            _cmd("أو: إيقاف خدمة مشاركة الملفات بالكامل", "Or: stop the file-sharing service entirely",
                    "Stop-Service LanmanServer -Force; Set-Service LanmanServer -StartupType Disabled"),
            _cmd("للتراجع", "To undo", f"Set-Service LanmanServer -StartupType Automatic; Start-Service LanmanServer; Enable-NetFirewallRule -Group '{FW_FILE_PRINTER_SHARING}'"),
        ]
        guide.harden = [
            _cmd("تعطيل SMB1 القديم", "Disable legacy SMB1", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"),
            _cmd("إلزام التوقيع الرقمي لاتصالات SMB", "Require digital signing for SMB connections", "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"),
        ]
        guide.warnings_ar.append(_L("لا تُغلق SMB على خوادم الملفات أو وحدات التحكم بالمجال؛ تعتمد عليه المشاركات وسياسات المجموعة.", "Do not disable SMB on file servers or domain controllers; shares and group policy depend on it."))
    elif service == "netbios-ssn":
        guide.verify = [
            _cmd("حالة NetBIOS لكل بطاقة شبكة (0 = حسب DHCP، 1 = مفعّل، 2 = معطّل)", "NetBIOS state per adapter (0 = per DHCP, 1 = enabled, 2 = disabled)",
                    "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Select-Object Description, TcpipNetbiosOptions"),
        ]
        guide.disable = [
            _cmd("تعطيل NetBIOS على كل بطاقات الشبكة", "Disable NetBIOS on all adapters",
                    "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}"),
            _cmd("للتراجع (العودة لإعداد DHCP)", "To undo (back to the DHCP setting)",
                    "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=0}"),
        ]
        guide.notes_ar.append(_L("مشاركة الملفات الحديثة تعمل عبر المنفذ 445 ولا تحتاج NetBIOS في الغالب.", "Modern file sharing works over port 445 and usually does not need NetBIOS."))
    elif service == "rdp":
        guide.verify += [
            _cmd("هل سطح المكتب البعيد مفعّل؟ (0 = مفعّل، 1 = معطّل)", "Is Remote Desktop enabled? (0 = enabled, 1 = disabled)",
                    "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"),
            _cmd("هل مصادقة مستوى الشبكة NLA مفعّلة؟ (1 = مفعّلة)", "Is Network Level Authentication (NLA) enabled? (1 = enabled)",
                    "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication"),
        ]
        guide.disable = [
            _cmd("تعطيل سطح المكتب البعيد", "Disable Remote Desktop",
                    "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1"),
            _cmd("وإغلاق قواعده في جدار الحماية", "And block its firewall rules", f"Disable-NetFirewallRule -Group '{FW_REMOTE_DESKTOP}'"),
            _cmd("للتراجع", "To undo",
                    f"Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0; Enable-NetFirewallRule -Group '{FW_REMOTE_DESKTOP}'"),
        ]
        guide.harden = [
            _cmd("تفعيل NLA", "Enable NLA",
                    "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"),
            _cmd("قصر الوصول على شبكة الإدارة فقط (استبدل ADMIN_SUBNET مثل 10.0.10.0/24)", "Restrict access to the management network only (replace ADMIN_SUBNET, e.g. 10.0.10.0/24)",
                    f"Set-NetFirewallRule -Group '{FW_REMOTE_DESKTOP}' -RemoteAddress 'ADMIN_SUBNET'"),
        ]
        guide.warnings_ar.append(_L("إذا كنت متصلاً بالجهاز عبر سطح المكتب البعيد فسيُقطع اتصالك ولن تستطيع العودة بهذه الطريقة.", "If you are connected to the device over Remote Desktop, your session will drop and you will not be able to return this way."))
    elif service == "msrpc":
        guide.verify += [_cmd("حالة خدمات RPC", "RPC services status", "Get-Service RpcSs, RpcEptMapper")]
        guide.disable = [
            _cmd("لا تُعطَّل الخدمة. يمكن فقط حجب المنفذ عن شبكات غير موثوقة (استبدل UNTRUSTED_SUBNET)", "Do not disable the service. You may only block the port from untrusted networks (replace UNTRUSTED_SUBNET)",
                    f"New-NetFirewallRule -DisplayName 'RasedNet block RPC {port} from untrusted' -Direction Inbound -Protocol TCP -LocalPort {port} -RemoteAddress 'UNTRUSTED_SUBNET' -Action Block"),
            _cmd("للتراجع", "To undo", f"Remove-NetFirewallRule -DisplayName 'RasedNet block RPC {port} from untrusted'"),
        ]
        guide.warnings_ar.append(_L("خدمة RPC أساسية في ويندوز؛ إيقافها يعطل النظام. حجبها عن كل الشبكة يعطل الإدارة عن بعد وWMI وبعض وظائف المجال.", "RPC is core to Windows; stopping it breaks the system. Blocking it from the whole network breaks remote management, WMI and some domain functions."))
    elif service in HTTP_LIKE:
        guide.verify += [
            _cmd("هل خادم IIS مثبت ويعمل؟", "Is IIS installed and running?", _svc_check("W3SVC", "IIS is not installed")),
            _cmd("البرامج المسجلة على HTTP.sys (مفيد إذا كان المالك System)", "Programs registered on HTTP.sys (useful if the owner is System)", "netsh http show servicestate view=requestq"),
        ]
        guide.disable.insert(0, _cmd("إذا كان IIS: إيقافه ومنع تشغيله تلقائياً", "If IIS: stop it and disable autostart",
                                        "Stop-Service W3SVC -Force; Set-Service W3SVC -StartupType Disabled"))
    elif service in ("winrm-http", "winrm-https"):
        guide.verify += [
            _cmd("حالة خدمة WinRM", "WinRM service status", "Get-Service WinRM"),
            _cmd("منافذ الاستماع المعرفة (إذا ظهرت رسالة خطأ فخدمة WinRM متوقفة)", "Defined listeners (an error means the WinRM service is stopped)", "winrm enumerate winrm/config/listener"),
        ]
        guide.disable = [
            _cmd("تعطيل الإدارة عن بعد عبر PowerShell", "Disable PowerShell remoting", "Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"),
            _cmd("للتراجع", "To undo", "Enable-PSRemoting -Force"),
        ]
        guide.warnings_ar.append(_L("أدوات الإدارة المركزية قد تعتمد على WinRM؛ نسّق مع فريق الأنظمة قبل التعطيل.", "Central management tools may rely on WinRM; coordinate with the systems team before disabling."))
    elif service == "ssh":
        guide.verify += [_cmd("حالة خدمة OpenSSH", "OpenSSH service status", _svc_check("sshd", "OpenSSH server is not installed"))]
        guide.disable.insert(0, _cmd("إيقاف خادم OpenSSH", "Stop the OpenSSH server", "Stop-Service sshd; Set-Service sshd -StartupType Disabled"))
    elif service == "ftp":
        guide.verify += [_cmd("هل خدمة FTP التابعة لـ IIS تعمل؟", "Is the IIS FTP service running?", _svc_check("FTPSVC", "IIS FTP is not installed"))]
        guide.disable.insert(0, _cmd("إيقاف خدمة FTP التابعة لـ IIS", "Stop the IIS FTP service", "Stop-Service FTPSVC; Set-Service FTPSVC -StartupType Disabled"))


def _linux_specific(guide: PlatformGuide, service: str) -> None:
    if service == "ssh":
        guide.verify.append(_cmd("حالة خادم SSH", "SSH server status", "systemctl status ssh 2>/dev/null || systemctl status sshd", shell="bash"))
        guide.warnings_ar.append(_L("إذا كانت إدارتك للجهاز عبر SSH فإيقافه سيقطع وصولك؛ يُفضّل قصره على شبكة الإدارة بدلاً من إيقافه.", "If you manage the device over SSH, stopping it will cut your access; prefer restricting it to the management network rather than stopping it."))
    elif service in ("smb", "netbios-ssn"):
        guide.verify.append(_cmd("حالة Samba والمجلدات المشتركة", "Samba status and shares", "systemctl status smbd; sudo smbstatus --shares", shell="bash"))
        guide.disable.insert(0, _cmd("إيقاف Samba", "Stop Samba", "sudo systemctl disable --now smbd nmbd", shell="bash"))


DATABASE_NOTES_AR = {
    "mongodb": "الأفضل: اجعل net.bindIp في ملف mongod.cfg يساوي 127.0.0.1 (أو عنوان الخوادم المسموح لها فقط) وفعّل security.authorization.",
    "mysql": "الأفضل: اضبط bind-address في my.ini أو my.cnf على 127.0.0.1 إذا كانت التطبيقات على نفس الجهاز.",
    "postgresql": "الأفضل: اضبط listen_addresses في postgresql.conf وقيّد العناوين المسموح بها في pg_hba.conf.",
    "redis": "الأفضل: bind 127.0.0.1 و protected-mode yes وكلمة مرور requirepass في ملف redis.conf.",
    "mssql": "الأفضل: قيّد المنفذ في جدار الحماية على خوادم التطبيقات فقط، وعطّل حساب sa إن لم يكن مستخدماً.",
    "elasticsearch": "الأفضل: network.host: 127.0.0.1 وتفعيل xpack.security في elasticsearch.yml.",
}
DATABASE_NOTES_EN = {
    "mongodb": "Best: set net.bindIp in mongod.cfg to 127.0.0.1 (or only the allowed server addresses) and enable security.authorization.",
    "mysql": "Best: set bind-address in my.ini or my.cnf to 127.0.0.1 if the applications are on the same host.",
    "postgresql": "Best: set listen_addresses in postgresql.conf and restrict the allowed addresses in pg_hba.conf.",
    "redis": "Best: bind 127.0.0.1, protected-mode yes, and a requirepass password in redis.conf.",
    "mssql": "Best: restrict the firewall port to application servers only, and disable the sa account if unused.",
    "elasticsearch": "Best: network.host: 127.0.0.1 and enable xpack.security in elasticsearch.yml.",
}


def build_guidance(service: str, port: int, ip: str | None, os_family: str, device_type: str) -> dict[str, object] | None:
    if ip is None:
        return None
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return None

    platforms: list[PlatformGuide] = []
    if os_family == "windows":
        targets = ["windows"]
    elif os_family in ("linux", "unix"):
        targets = ["linux"]
    elif device_type in APPLIANCE_TYPES:
        targets = ["appliance"]
    else:
        targets = ["windows", "linux"]  # OS not confirmed: show both

    for target in targets:
        if target == "windows":
            guide = _windows_generic(port)
            _windows_specific(guide, service, port)
        elif target == "linux":
            guide = _linux_generic(port)
            _linux_specific(guide, service)
        else:
            guide = PlatformGuide(
                platform="appliance",
                platform_ar=_L("جهاز مدمج (طابعة / كاميرا / معدات شبكات)", "Embedded device (printer / camera / network gear)"),
                notes_ar=[
                    _L("هذه الأجهزة لا تُدار بأوامر ويندوز أو لينكس. ادخل إلى لوحة إدارة الجهاز من المتصفح "
                       f"(عادة http://{ip} أو https://{ip}) ثم إعدادات الشبكة أو البروتوكولات وعطّل الخدمة غير المطلوبة.",
                       f"These devices are not managed with Windows or Linux commands. Open the device admin panel in a browser "
                       f"(usually http://{ip} or https://{ip}), then network or protocol settings, and disable the unneeded service."),
                    _L("إن لم يتوفر الخيار في الجهاز: احجب المنفذ على المحول أو الجدار الناري بين الشبكات، وحدّث برنامج الجهاز الثابت.", "If the option is not available on the device: block the port on the switch or inter-network firewall, and update the device firmware."),
                ],
            )
        if service in DATABASE_NOTES_AR:
            guide.notes_ar.append((DATABASE_NOTES_EN if get_lang() == "en" else DATABASE_NOTES_AR)[service])
        platforms.append(guide)

    return {
        "network_checks": [asdict(c) for c in _network_checks(ip, port, service)],
        "access": [asdict(c) for c in _access_commands(service, ip, port)],
        "access_note_ar": _L("استخدم حساباً مصرحاً له بإدارة هذا الجهاز فقط. لا يتضمن راصد أي تخمين لكلمات المرور أو تجاوز للحماية.", "Use an account authorized to manage this device only. RasedNet never guesses passwords or bypasses protection."),
        "platforms": [asdict(p) for p in platforms],
        "recheck_ar": _L("بعد التنفيذ أعد فحص هذا الجهاز من راصد؛ إذا أُغلق المنفذ ستتحول حالة الخدمة إلى «مغلق» ويُسجَّل التغيير.", "After applying, re-scan this device from RasedNet; if the port is closed, the service state becomes “closed” and the change is logged."),
    }
