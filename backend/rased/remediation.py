"""Administrator guidance per observed service: how to verify it and how to close or harden it.

Commands are built only from validated values (an IP address parsed by ``ipaddress`` and an
integer port) — never from banners or other network-supplied text — so they are safe to copy.
Firewall rule groups are referenced by their resource IDs (``@FirewallAPI.dll,-NNNNN``), which
work on every Windows display language, including Arabic.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field

FW_FILE_PRINTER_SHARING = "@FirewallAPI.dll,-28502"
FW_REMOTE_DESKTOP = "@FirewallAPI.dll,-28752"

APPLIANCE_TYPES = {"printer", "camera", "router", "switch", "access_point", "network_device", "iot", "nas"}
HTTP_LIKE = {"http", "https", "http-alt", "https-alt", "http-proxy"}


@dataclass
class Command:
    label_ar: str
    command: str
    shell: str = "powershell"  # powershell | bash
    run_on: str = "device"  # device | admin_pc


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
        Command("هل المنفذ مفتوح فعلاً؟ (TcpTestSucceeded : True تعني مفتوح)", f"Test-NetConnection {ip} -Port {port}", run_on="admin_pc"),
    ]
    if service in HTTP_LIKE:
        scheme = "https" if service.startswith("https") or port in (443, 8443, 4443, 9443) else "http"
        checks.append(Command("ما البرنامج الذي يرد؟ (انظر سطر Server)", f"curl.exe -skI {scheme}://{ip}:{port}/", run_on="admin_pc"))
    if service in ("smb", "netbios-ssn"):
        checks.append(Command("عرض المجلدات المشتركة الظاهرة على الشبكة", f"net view \\\\{ip} /all", shell="powershell", run_on="admin_pc"))
    if service == "rdp":
        checks.append(Command("تجربة الاتصال بسطح المكتب البعيد", f"mstsc /v:{ip}", run_on="admin_pc"))
    return checks


def _access_commands(service: str, ip: str, port: int) -> list[Command]:
    """Legitimate administration through the service, with an authorised account (never guessing)."""
    a = lambda label, cmd, shell="powershell": Command(label, cmd, shell=shell, run_on="admin_pc")  # noqa: E731
    url_scheme = "https" if service.startswith("https") or port in (443, 8443, 4443, 9443, 5001) else "http"
    table: dict[str, list[Command]] = {
        "rdp": [a("فتح سطح المكتب البعيد للجهاز", f"mstsc /v:{ip}")],
        "smb": [
            a("عرض المجلدات المشتركة في مستكشف الملفات", f'explorer.exe "\\\\{ip}"'),
            a("فتح القرص C الإداري (يتطلب حساب مسؤول على الجهاز)", f'explorer.exe "\\\\{ip}\\C$"'),
        ],
        "netbios-ssn": [a("عرض المجلدات المشتركة في مستكشف الملفات", f'explorer.exe "\\\\{ip}"')],
        "msrpc": [
            a("إدارة الكمبيوتر عن بعد (الخدمات، الأقراص، السجلات)", f"compmgmt.msc /computer={ip}"),
            a("قراءة معلومات النظام عبر WMI/DCOM",
              f"Get-CimInstance Win32_OperatingSystem -CimSession (New-CimSession -ComputerName {ip} -Credential (Get-Credential) "
              "-SessionOption (New-CimSessionOption -Protocol Dcom)) | Select-Object CSName, Caption, Version, LastBootUpTime"),
        ],
        "winrm-http": [a("جلسة PowerShell عن بعد (يتطلب TrustedHosts عند استخدام عنوان IP)",
                         f"Enter-PSSession -ComputerName {ip} -Credential (Get-Credential)")],
        "winrm-https": [a("جلسة PowerShell عن بعد مشفرة", f"Enter-PSSession -ComputerName {ip} -UseSSL -Credential (Get-Credential)")],
        "ssh": [a("اتصال SSH (استبدل USER باسم المستخدم)", f"ssh USER@{ip}" + (f" -p {port}" if port != 22 else ""))],
        "ftp": [a("فتح FTP", f"ftp {ip}")],
        "telnet": [a("اتصال Telnet (غير مشفر؛ يُفضّل SSH)", f"telnet {ip} {port}")],
        "mssql": [a("الاتصال بقاعدة SQL Server", f"sqlcmd -S {ip},{port} -U USER")],
        "mysql": [a("الاتصال بقاعدة MySQL", f"mysql -h {ip} -P {port} -u USER -p")],
        "postgresql": [a("الاتصال بقاعدة PostgreSQL", f"psql -h {ip} -p {port} -U USER -d postgres")],
        "mongodb": [a("الاتصال بقاعدة MongoDB", f'mongosh "mongodb://{ip}:{port}" -u USER')],
        "redis": [a("الاتصال بـ Redis", f"redis-cli -h {ip} -p {port}")],
        "rtsp": [a("فتح بث الكاميرا (VLC)", f"vlc rtsp://{ip}:{port}/")],
        "dns": [a("اختبار خادم DNS", f"Resolve-DnsName example.com -Server {ip}")],
        "vnc": [],
    }
    if service in HTTP_LIKE or service in ("ipp", "jetdirect", "lpd", "elasticsearch"):
        commands = [a("فتح واجهة الإدارة في المتصفح", f'Start-Process "{url_scheme}://{ip}:{port}/"')]
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
        platform_ar="ويندوز (PowerShell كمسؤول)",
        verify=[
            Command("هل المنفذ مفتوح على الجهاز، وما البرنامج الذي يفتحه؟", who),
            Command("ما خدمة ويندوز المرتبطة بهذا المنفذ؟ (احفظ قيمة Name)", service),
        ],
        disable=[
            Command("إيقاف الخدمة ومنع تشغيلها تلقائياً (ضع اسم الخدمة من الخطوة السابقة)",
                    "Stop-Service -Name '<ServiceName>' -Force; Set-Service -Name '<ServiceName>' -StartupType Disabled"),
            Command("أو: حجب المنفذ في جدار حماية ويندوز مع إبقاء الخدمة تعمل محلياً",
                    f"New-NetFirewallRule -DisplayName 'RASED block TCP {port}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block"),
            Command("للتراجع عن قاعدة الحجب", f"Remove-NetFirewallRule -DisplayName 'RASED block TCP {port}'"),
        ],
        notes_ar=["إذا كان البرنامج المالك هو System (المعرف 4) فالمنفذ تابع لمكوّن من ويندوز نفسه؛ راجع الأوامر الخاصة بالخدمة."],
    )


def _linux_generic(port: int) -> PlatformGuide:
    return PlatformGuide(
        platform="linux",
        platform_ar="لينكس (طرفية بصلاحية sudo)",
        verify=[
            Command("هل المنفذ مفتوح وما البرنامج الذي يفتحه؟", f"sudo ss -ltnp 'sport = :{port}' 2>/dev/null || sudo netstat -ltnp 2>/dev/null | grep ':{port} '", shell="bash"),
            Command("ما خدمة systemd المرتبطة به؟",
                    f"sudo systemctl status $(sudo ss -ltnpH 'sport = :{port}' | grep -oP 'pid=\\K[0-9]+' | head -n1)", shell="bash"),
        ],
        disable=[
            Command("إيقاف الخدمة ومنع تشغيلها تلقائياً (ضع اسم الوحدة من الخطوة السابقة)",
                    "sudo systemctl disable --now '<unit-name>'", shell="bash"),
            Command("أو: حجب المنفذ بجدار الحماية (أوبونتو/ديبيان)", f"sudo ufw deny {port}/tcp", shell="bash"),
            Command("أو: حجب المنفذ بجدار الحماية (ريدهات/روكي/ألما)",
                    f"sudo firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" port port=\"{port}\" protocol=\"tcp\" reject' && sudo firewall-cmd --reload",
                    shell="bash"),
        ],
    )


def _windows_specific(guide: PlatformGuide, service: str, port: int) -> None:
    if service == "smb":
        guide.verify += [
            Command("المجلدات المشتركة على الجهاز", "Get-SmbShare | Select-Object Name, Path, Description"),
            Command("إعدادات SMB (SMB1 يجب أن يكون False)",
                    "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature"),
            Command("حالة خدمة مشاركة الملفات", "Get-Service LanmanServer"),
        ]
        guide.disable = [
            Command("إغلاق مشاركة الملفات والطابعات في جدار الحماية (كل لغات ويندوز)",
                    f"Disable-NetFirewallRule -Group '{FW_FILE_PRINTER_SHARING}'"),
            Command("أو: إيقاف خدمة مشاركة الملفات بالكامل",
                    "Stop-Service LanmanServer -Force; Set-Service LanmanServer -StartupType Disabled"),
            Command("للتراجع", f"Set-Service LanmanServer -StartupType Automatic; Start-Service LanmanServer; Enable-NetFirewallRule -Group '{FW_FILE_PRINTER_SHARING}'"),
        ]
        guide.harden = [
            Command("تعطيل SMB1 القديم", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"),
            Command("إلزام التوقيع الرقمي لاتصالات SMB", "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"),
        ]
        guide.warnings_ar.append("لا تُغلق SMB على خوادم الملفات أو وحدات التحكم بالمجال؛ تعتمد عليه المشاركات وسياسات المجموعة.")
    elif service == "netbios-ssn":
        guide.verify = [
            Command("حالة NetBIOS لكل بطاقة شبكة (0 = حسب DHCP، 1 = مفعّل، 2 = معطّل)",
                    "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Select-Object Description, TcpipNetbiosOptions"),
        ]
        guide.disable = [
            Command("تعطيل NetBIOS على كل بطاقات الشبكة",
                    "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}"),
            Command("للتراجع (العودة لإعداد DHCP)",
                    "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=0}"),
        ]
        guide.notes_ar.append("مشاركة الملفات الحديثة تعمل عبر المنفذ 445 ولا تحتاج NetBIOS في الغالب.")
    elif service == "rdp":
        guide.verify += [
            Command("هل سطح المكتب البعيد مفعّل؟ (0 = مفعّل، 1 = معطّل)",
                    "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"),
            Command("هل مصادقة مستوى الشبكة NLA مفعّلة؟ (1 = مفعّلة)",
                    "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication"),
        ]
        guide.disable = [
            Command("تعطيل سطح المكتب البعيد",
                    "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1"),
            Command("وإغلاق قواعده في جدار الحماية", f"Disable-NetFirewallRule -Group '{FW_REMOTE_DESKTOP}'"),
            Command("للتراجع",
                    f"Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0; Enable-NetFirewallRule -Group '{FW_REMOTE_DESKTOP}'"),
        ]
        guide.harden = [
            Command("تفعيل NLA",
                    "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"),
            Command("قصر الوصول على شبكة الإدارة فقط (استبدل ADMIN_SUBNET مثل 10.0.10.0/24)",
                    f"Set-NetFirewallRule -Group '{FW_REMOTE_DESKTOP}' -RemoteAddress 'ADMIN_SUBNET'"),
        ]
        guide.warnings_ar.append("إذا كنت متصلاً بالجهاز عبر سطح المكتب البعيد فسيُقطع اتصالك ولن تستطيع العودة بهذه الطريقة.")
    elif service == "msrpc":
        guide.verify += [Command("حالة خدمات RPC", "Get-Service RpcSs, RpcEptMapper")]
        guide.disable = [
            Command("لا تُعطَّل الخدمة. يمكن فقط حجب المنفذ عن شبكات غير موثوقة (استبدل UNTRUSTED_SUBNET)",
                    f"New-NetFirewallRule -DisplayName 'RASED block RPC {port} from untrusted' -Direction Inbound -Protocol TCP -LocalPort {port} -RemoteAddress 'UNTRUSTED_SUBNET' -Action Block"),
            Command("للتراجع", f"Remove-NetFirewallRule -DisplayName 'RASED block RPC {port} from untrusted'"),
        ]
        guide.warnings_ar.append("خدمة RPC أساسية في ويندوز؛ إيقافها يعطل النظام. حجبها عن كل الشبكة يعطل الإدارة عن بعد وWMI وبعض وظائف المجال.")
    elif service in HTTP_LIKE:
        guide.verify += [
            Command("هل خادم IIS مثبت ويعمل؟", _svc_check("W3SVC", "IIS is not installed")),
            Command("البرامج المسجلة على HTTP.sys (مفيد إذا كان المالك System)", "netsh http show servicestate view=requestq"),
        ]
        guide.disable.insert(0, Command("إذا كان IIS: إيقافه ومنع تشغيله تلقائياً",
                                        "Stop-Service W3SVC -Force; Set-Service W3SVC -StartupType Disabled"))
    elif service in ("winrm-http", "winrm-https"):
        guide.verify += [
            Command("حالة خدمة WinRM", "Get-Service WinRM"),
            Command("منافذ الاستماع المعرفة (إذا ظهرت رسالة خطأ فخدمة WinRM متوقفة)", "winrm enumerate winrm/config/listener"),
        ]
        guide.disable = [
            Command("تعطيل الإدارة عن بعد عبر PowerShell", "Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"),
            Command("للتراجع", "Enable-PSRemoting -Force"),
        ]
        guide.warnings_ar.append("أدوات الإدارة المركزية قد تعتمد على WinRM؛ نسّق مع فريق الأنظمة قبل التعطيل.")
    elif service == "ssh":
        guide.verify += [Command("حالة خدمة OpenSSH", _svc_check("sshd", "OpenSSH server is not installed"))]
        guide.disable.insert(0, Command("إيقاف خادم OpenSSH", "Stop-Service sshd; Set-Service sshd -StartupType Disabled"))
    elif service == "ftp":
        guide.verify += [Command("هل خدمة FTP التابعة لـ IIS تعمل؟", _svc_check("FTPSVC", "IIS FTP is not installed"))]
        guide.disable.insert(0, Command("إيقاف خدمة FTP التابعة لـ IIS", "Stop-Service FTPSVC; Set-Service FTPSVC -StartupType Disabled"))


def _linux_specific(guide: PlatformGuide, service: str) -> None:
    if service == "ssh":
        guide.verify.append(Command("حالة خادم SSH", "systemctl status ssh 2>/dev/null || systemctl status sshd", shell="bash"))
        guide.warnings_ar.append("إذا كانت إدارتك للجهاز عبر SSH فإيقافه سيقطع وصولك؛ يُفضّل قصره على شبكة الإدارة بدلاً من إيقافه.")
    elif service in ("smb", "netbios-ssn"):
        guide.verify.append(Command("حالة Samba والمجلدات المشتركة", "systemctl status smbd; sudo smbstatus --shares", shell="bash"))
        guide.disable.insert(0, Command("إيقاف Samba", "sudo systemctl disable --now smbd nmbd", shell="bash"))


DATABASE_NOTES_AR = {
    "mongodb": "الأفضل: اجعل net.bindIp في ملف mongod.cfg يساوي 127.0.0.1 (أو عنوان الخوادم المسموح لها فقط) وفعّل security.authorization.",
    "mysql": "الأفضل: اضبط bind-address في my.ini أو my.cnf على 127.0.0.1 إذا كانت التطبيقات على نفس الجهاز.",
    "postgresql": "الأفضل: اضبط listen_addresses في postgresql.conf وقيّد العناوين المسموح بها في pg_hba.conf.",
    "redis": "الأفضل: bind 127.0.0.1 و protected-mode yes وكلمة مرور requirepass في ملف redis.conf.",
    "mssql": "الأفضل: قيّد المنفذ في جدار الحماية على خوادم التطبيقات فقط، وعطّل حساب sa إن لم يكن مستخدماً.",
    "elasticsearch": "الأفضل: network.host: 127.0.0.1 وتفعيل xpack.security في elasticsearch.yml.",
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
                platform_ar="جهاز مدمج (طابعة / كاميرا / معدات شبكات)",
                notes_ar=[
                    "هذه الأجهزة لا تُدار بأوامر ويندوز أو لينكس. ادخل إلى لوحة إدارة الجهاز من المتصفح "
                    f"(عادة http://{ip} أو https://{ip}) ثم إعدادات الشبكة أو البروتوكولات وعطّل الخدمة غير المطلوبة.",
                    "إن لم يتوفر الخيار في الجهاز: احجب المنفذ على المحول أو الجدار الناري بين الشبكات، وحدّث برنامج الجهاز الثابت.",
                ],
            )
        if service in DATABASE_NOTES_AR:
            guide.notes_ar.append(DATABASE_NOTES_AR[service])
        platforms.append(guide)

    return {
        "network_checks": [asdict(c) for c in _network_checks(ip, port, service)],
        "access": [asdict(c) for c in _access_commands(service, ip, port)],
        "access_note_ar": "استخدم حساباً مصرحاً له بإدارة هذا الجهاز فقط. لا يتضمن راصد أي تخمين لكلمات المرور أو تجاوز للحماية.",
        "platforms": [asdict(p) for p in platforms],
        "recheck_ar": "بعد التنفيذ أعد فحص هذا الجهاز من راصد؛ إذا أُغلق المنفذ ستتحول حالة الخدمة إلى «مغلق» ويُسجَّل التغيير.",
    }
