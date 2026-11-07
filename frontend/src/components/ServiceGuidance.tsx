import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage } from "../api";
import { useCan } from "../auth";
import { getLang, t } from "../i18n";
import type { Credential, Execution, GuidanceCommand, PlatformGuide, ServiceGuidance } from "../types";
import { IconDownload, IconPlay } from "./icons";
import { Badge } from "./ui";

const NON_EXECUTABLE = ["mstsc", "explorer", "compmgmt", "Enter-PSSession", "ssh ", "ftp ", "telnet", "Start-Process", "sqlcmd", "mysql ", "psql ", "mongosh", "redis-cli", "vlc "];
const PLACEHOLDERS: { token: string; param: string; prompt: string; promptEn: string }[] = [
  { token: "<ServiceName>", param: "service_name", prompt: "اسم خدمة ويندوز (قيمة Name من خطوة التحقق):", promptEn: "Windows service name (the Name value from the verify step):" },
  { token: "ADMIN_SUBNET", param: "subnet", prompt: "شبكة الإدارة المسموح لها بصيغة CIDR (مثال 10.0.10.0/24):", promptEn: "Allowed admin subnet in CIDR (e.g. 10.0.10.0/24):" },
  { token: "UNTRUSTED_SUBNET", param: "subnet", prompt: "الشبكة غير الموثوقة المراد حجبها بصيغة CIDR:", promptEn: "Untrusted subnet to block, in CIDR:" },
  { token: "<unit-name>", param: "unit_name", prompt: "اسم وحدة systemd (مثال nginx.service):", promptEn: "systemd unit name (e.g. nginx.service):" },
];

export const isExecutable = (command: string) => !NON_EXECUTABLE.some((p) => command.trim().startsWith(p));

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    return ok;
  }
}

/** A ready-to-open .rdp file: double-click → Remote Desktop to the device. */
export function downloadRdp(ip: string): void {
  const blob = new Blob([`full address:s:${ip}\r\nprompt for credentials:i:1\r\nadministrative session:i:1\r\n`], { type: "application/x-rdp" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${ip}.rdp`;
  a.click();
  URL.revokeObjectURL(url);
}

function OutputBox({ result }: { result: Execution }) {
  return (
    <div className="mt-1 rounded-md border border-slate-200 bg-white">
      <div className="flex items-center gap-2 border-b border-slate-100 px-2 py-1 text-[11px] text-slate-500">
        <Badge tone={result.status === "ok" && !result.had_errors ? "green" : result.status === "ok" ? "amber" : "red"}>
          {result.status === "error" ? t("فشل التنفيذ", "Execution failed") : result.had_errors ? t("نُفذ مع أخطاء", "Ran with errors") : t("نُفذ بنجاح", "Ran successfully")}
        </Badge>
        <span>{result.target === "scanner" ? t("على خادم راصد", "On the RasedNet server") : `${t("على الجهاز", "On device")} ${result.target}`}</span>
      </div>
      <pre dir="ltr" className="ltr max-h-72 overflow-auto whitespace-pre-wrap break-all px-2 py-1.5 text-[11px] text-slate-800">{result.output || t("(لا توجد مخرجات)", "(no output)")}</pre>
    </div>
  );
}

interface RunCtx {
  assetId: number;
  serviceId: number;
  credentials: Credential[];
}

export function CommandBox({ cmd, section, index, platform, run }: {
  cmd: GuidanceCommand; section?: string; index?: number; platform?: string; run?: RunCtx;
}) {
  const can = useCan();
  const [copied, setCopied] = useState(false);
  const [credId, setCredId] = useState<number | "">("");
  const [result, setResult] = useState<Execution | null>(null);
  const [error, setError] = useState<string | null>(null);
  const changes = section === "disable" || section === "harden";
  const onDevice = cmd.run_on === "device";
  const kind = platform === "linux" ? "ssh" : "winrm";
  const usable = (run?.credentials ?? []).filter((c) => c.kind === kind);
  const allowed = run && section && index !== undefined && isExecutable(cmd.command)
    && (changes ? can("remote:change") : can("remote:verify")) && (!onDevice || platform !== "appliance");
  const exec = useMutation({
    mutationFn: (body: object) => api<Execution>(`/api/assets/${run?.assetId}/services/${run?.serviceId}/execute`, { method: "POST", body }),
    onSuccess: (r) => { setResult(r); setError(null); },
    onError: (e) => setError(errorMessage(e)),
  });

  const execute = () => {
    const params: Record<string, string> = {};
    const en = getLang() === "en";
    for (const p of PLACEHOLDERS) {
      if (cmd.command.includes(p.token) && !params[p.param]) {
        const value = window.prompt(en ? p.promptEn : p.prompt);
        if (!value) return;
        params[p.param] = value.trim();
      }
    }
    if (changes && !window.confirm((en ? `A command that changes the device's settings will run:\n\n${cmd.command}\n\nAre you sure?` : `سيتم تنفيذ أمر يغيّر إعدادات الجهاز:\n\n${cmd.command}\n\nهل أنت متأكد؟`))) return;
    exec.mutate({ section, index, credential_id: onDevice ? credId || null : null, params, confirm: changes });
  };

  return (
    <div className="mb-2">
      <div className="mb-1 flex flex-wrap items-center gap-1 text-xs text-slate-600">
        {cmd.label_ar}
        <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-500">
          {cmd.shell === "bash" ? "Bash" : "PowerShell"} — {cmd.run_on === "admin_pc" ? t("من جهازك", "From your PC") : t("على الجهاز نفسه", "On the device itself")}
        </span>
      </div>
      <div className="flex items-stretch gap-1" dir="ltr">
        <pre className="ltr flex-1 overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-slate-900 px-3 py-2 text-xs text-emerald-100">{cmd.command}</pre>
        <button type="button" aria-label={t("نسخ الأمر", "Copy command")}
          className="shrink-0 rounded-lg border border-slate-300 bg-white px-2 text-xs text-slate-700 hover:bg-slate-50"
          onClick={async () => { if (await copyText(cmd.command)) { setCopied(true); window.setTimeout(() => setCopied(false), 1500); } }}>
          {copied ? t("تم النسخ", "Copied") : t("نسخ", "Copy")}
        </button>
      </div>
      {allowed && (
        <div className="mt-1 flex flex-wrap items-center gap-2">
          {onDevice && (
            <select className="rounded-lg border border-slate-300 px-2 py-1 text-xs" value={credId} aria-label={t("حساب الدخول", "Credential")}
              onChange={(e) => setCredId(e.target.value ? Number(e.target.value) : "")}>
              <option value="">{usable.length ? t("اختر حساب الدخول…", "Choose a credential…") : (getLang() === "en" ? `No ${kind === "ssh" ? "SSH" : "WinRM"} account in the vault` : `لا يوجد حساب ${kind === "ssh" ? "SSH" : "WinRM"} في الخزنة`)}</option>
              {usable.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.username})</option>)}
            </select>
          )}
          <button type="button" disabled={exec.isPending || (onDevice && !credId)} onClick={execute}
            className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-semibold text-white disabled:opacity-40 ${changes ? "bg-red-600 hover:bg-red-700" : "bg-cyan-700 hover:bg-cyan-800"}`}>
            <IconPlay className="h-3 w-3" /> {exec.isPending ? t("جارٍ التنفيذ…", "Running…") : onDevice ? t("تشغيل على الجهاز", "Run on the device") : t("تشغيل من خادم راصد", "Run from the RasedNet server")}
          </button>
        </div>
      )}
      {error && <div className="mt-1 text-xs text-red-700">{error}</div>}
      {result && <OutputBox result={result} />}
    </div>
  );
}

function Section({ title, tone, commands, section, platform, run }: {
  title: string; tone: string; commands: GuidanceCommand[]; section?: string; platform?: string; run?: RunCtx;
}) {
  if (!commands.length) return null;
  return (
    <div className="mb-3">
      <h4 className={`mb-2 text-sm font-bold ${tone}`}>{title}</h4>
      {commands.map((c, i) => <CommandBox key={i} cmd={c} section={section} index={i} platform={platform} run={run} />)}
    </div>
  );
}

function AccessSection({ guidance, ip }: { guidance: ServiceGuidance; ip?: string | null }) {
  if (!guidance.access?.length) return null;
  return (
    <div className="rounded-xl border border-cyan-200 bg-cyan-50/50 p-3">
      <h4 className="mb-1 text-sm font-bold text-cyan-900">{t("الدخول والإدارة", "Access & management")}</h4>
      <p className="mb-2 text-[11px] text-cyan-900/80">{guidance.access_note_ar}</p>
      <div className="mb-2 flex flex-wrap gap-2">
        {guidance.access.map((c, i) => {
          const url = c.command.match(/^Start-Process "(https?:\/\/[^"]+)"$/)?.[1];
          return url ? (
            <a key={i} href={url} target="_blank" rel="noopener noreferrer" className="rounded-lg bg-cyan-700 px-3 py-1 text-xs font-semibold text-white hover:bg-cyan-800">{t("فتح واجهة الإدارة ↗", "Open admin interface ↗")}</a>
          ) : null;
        })}
        {ip && guidance.access.some((c) => c.command.startsWith("mstsc")) && (
          <button type="button" onClick={() => downloadRdp(ip)} className="inline-flex items-center gap-1 rounded-lg bg-cyan-700 px-3 py-1 text-xs font-semibold text-white hover:bg-cyan-800">
            <IconDownload className="h-3.5 w-3.5" /> {t("تنزيل ملف سطح المكتب البعيد (RDP)", "Download Remote Desktop file (RDP)")}
          </button>
        )}
      </div>
      {guidance.access.map((c, i) => <CommandBox key={i} cmd={c} />)}
    </div>
  );
}

export function ServiceGuidancePanel({ guidance, run, ip }: { guidance: ServiceGuidance; run?: RunCtx; ip?: string | null }) {
  return (
    <div className="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-3">
      <AccessSection guidance={guidance} ip={ip} />
      <Section title={t("1) التحقق من جهازك: هل المنفذ مفتوح فعلاً؟", "1) Check from your PC: is the port really open?")} tone="text-sky-800" commands={guidance.network_checks} section="network_checks" run={run} />
      {guidance.platforms.map((p: PlatformGuide) => (
        <div key={p.platform} className="rounded-xl border border-slate-200 bg-white p-3">
          <div className="mb-2 text-sm font-semibold text-slate-800">{t("إذا كان الجهاز:", "If the device is:")} {p.platform_ar}</div>
          {p.warnings_ar.map((w, i) => (
            <div key={i} role="alert" className="mb-2 rounded border border-amber-300 bg-amber-50 px-2 py-1 text-xs text-amber-900">{t("تحذير:", "Warning:")} {w}</div>
          ))}
          <Section title={t("2) التحقق على الجهاز نفسه: هل الخدمة تعمل؟", "2) Verify on the device itself: is the service running?")} tone="text-cyan-800" commands={p.verify} section="verify" platform={p.platform} run={run} />
          <Section title={t("3) طريقة الإغلاق", "3) How to disable it")} tone="text-red-700" commands={p.disable} section="disable" platform={p.platform} run={run} />
          <Section title={t("بديل: تأمين الخدمة إذا كانت مطلوبة", "Alternative: harden the service if it is needed")} tone="text-violet-800" commands={p.harden} section="harden" platform={p.platform} run={run} />
          {p.notes_ar.map((n, i) => <p key={i} className="text-xs text-slate-600">• {n}</p>)}
        </div>
      ))}
      <p className="text-xs text-slate-600">{guidance.recheck_ar}</p>
    </div>
  );
}
