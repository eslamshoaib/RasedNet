import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr } from "../components/ui";
import { formatDate } from "../format";
import { getLang, t } from "../i18n";
import type { Credential, SshHostKey } from "../types";

function NewCredential({ onDone }: { onDone: () => void }) {
  const [kind, setKind] = useState<"winrm" | "ssh" | "snmp">("winrm");
  const [snmpV3, setSnmpV3] = useState(false);
  const [v3, setV3] = useState({ user: "", auth_key: "", auth_proto: "sha", priv_key: "", priv_proto: "aes" });
  const [form, setForm] = useState({ name: "", username: "", password: "", use_https: false, port: "", verify_tls: true });
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => api<Credential>("/api/credentials", { method: "POST", body: {
      name: form.name, kind,
      username: kind === "snmp" && snmpV3 ? (v3.user || "snmpv3") : (kind === "snmp" ? (form.username || "snmp") : form.username),
      password: kind === "snmp" && snmpV3 ? JSON.stringify({ version: "v3", ...v3 }) : form.password,
      use_https: kind === "winrm" && form.use_https, verify_tls: form.verify_tls, port: form.port ? Number(form.port) : null,
    } }),
    onSuccess: () => { setForm({ name: "", username: "", password: "", use_https: false, port: "", verify_tls: true }); setError(null); onDone(); },
    onError: (e) => setError(errorMessage(e)),
  });
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  const defaultPort = kind === "ssh" ? 22 : kind === "snmp" ? 161 : form.use_https ? 5986 : 5985;
  const isSnmp = kind === "snmp";
  return (
    <form onSubmit={submit} className="grid gap-3 md:grid-cols-3">
      <Field label={t("النوع", "Type")}>
        <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value as "winrm" | "ssh" | "snmp")}>
          <option value="winrm">{t("WinRM (أجهزة ويندوز)", "WinRM (Windows devices)")}</option>
          <option value="ssh">{t("SSH (لينكس، الموجّهات، أجهزة التخزين)", "SSH (Linux, routers, storage)")}</option>
          <option value="snmp">{t("SNMP (الموجّهات والمحوّلات — للتوبولوجي الفيزيائي)", "SNMP (routers & switches — for physical topology)")}</option>
        </select>
      </Field>
      <Field label={t("اسم الحساب في الخزنة", "Account name in the vault")}><input className={inputClass} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={t("مثال: مسؤول أجهزة المكتب", "e.g. Office devices admin")} /></Field>
      {isSnmp && (
        <Field label={t("إصدار SNMP", "SNMP version")}>
          <select className={inputClass} value={snmpV3 ? "v3" : "v2c"} onChange={(e) => setSnmpV3(e.target.value === "v3")}>
            <option value="v2c">{t("v2c (سلسلة مجتمع)", "v2c (community string)")}</option>
            <option value="v3">{t("v3 (مستخدم + تشفير)", "v3 (user + encryption)")}</option>
          </select>
        </Field>
      )}
      {!(isSnmp && snmpV3) && (
        <Field label={isSnmp ? t("وصف (أي اسم)", "Label (any name)") : t("اسم المستخدم", "Username")} hint={isSnmp ? t("مثال: snmp-ro", "e.g. snmp-ro") : kind === "winrm" ? t("مثال: CORP\\admin أو .\\Administrator", "e.g. CORP\\admin or .\\Administrator") : t("مثال: admin أو root", "e.g. admin or root")}>
          <input className={inputClass} dir="ltr" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
        </Field>
      )}
      {!(isSnmp && snmpV3) && (
        <Field label={isSnmp ? t("سلسلة المجتمع (Community)", "Community string") : t("كلمة المرور", "Password")} hint={t("تُخزّن مشفرة ولا تُعرض مرة أخرى", "Stored encrypted and never shown again")}>
          <input className={inputClass} dir="ltr" type="password" autoComplete="new-password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </Field>
      )}
      {isSnmp && snmpV3 && (
        <>
          <Field label={t("اسم مستخدم SNMPv3", "SNMPv3 username")}><input className={inputClass} dir="ltr" required value={v3.user} onChange={(e) => setV3({ ...v3, user: e.target.value })} /></Field>
          <Field label={t("مفتاح المصادقة (Auth)", "Authentication key (Auth)")}><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={v3.auth_key} onChange={(e) => setV3({ ...v3, auth_key: e.target.value })} /></Field>
          <Field label={t("خوارزمية المصادقة", "Auth algorithm")}><select className={inputClass} value={v3.auth_proto} onChange={(e) => setV3({ ...v3, auth_proto: e.target.value })}><option value="sha">SHA</option><option value="md5">MD5</option></select></Field>
          <Field label={t("مفتاح التشفير (Priv)", "Privacy key (Priv)")}><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={v3.priv_key} onChange={(e) => setV3({ ...v3, priv_key: e.target.value })} /></Field>
          <Field label={t("خوارزمية التشفير", "Privacy algorithm")}><select className={inputClass} value={v3.priv_proto} onChange={(e) => setV3({ ...v3, priv_proto: e.target.value })}><option value="aes">AES</option><option value="des">DES</option></select></Field>
        </>
      )}
      <Field label={t("المنفذ", "Port")} hint={`${t("الافتراضي", "Default")} ${defaultPort}`}><input className={inputClass} dir="ltr" type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} /></Field>
      {kind === "winrm" && (
        <div className="flex flex-col justify-end gap-1 text-sm">
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={form.use_https} onChange={(e) => setForm({ ...form, use_https: e.target.checked })} /> {t("استخدام HTTPS (5986)", "Use HTTPS (5986)")}</label>
          {form.use_https && <label className="flex items-center gap-1.5"><input type="checkbox" checked={form.verify_tls} onChange={(e) => setForm({ ...form, verify_tls: e.target.checked })} /> {t("التحقق من شهادة الجهاز", "Verify the device certificate")}</label>}
        </div>
      )}
      <div className="md:col-span-3"><ErrorBox error={error} /></div>
      <div><Button type="submit" disabled={create.isPending}>{t("إضافة إلى الخزنة", "Add to the vault")}</Button></div>
    </form>
  );
}

export function VaultPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const creds = useQuery({ queryKey: ["credentials"], queryFn: () => api<Credential[]>("/api/credentials") });
  const keys = useQuery({ queryKey: ["ssh-host-keys"], queryFn: () => api<SshHostKey[]>("/api/ssh-host-keys") });
  const del = useMutation({ mutationFn: (id: number) => api(`/api/credentials/${id}`, { method: "DELETE" }), onSuccess: () => void qc.invalidateQueries({ queryKey: ["credentials"] }) });
  const forget = useMutation({ mutationFn: (id: number) => api(`/api/ssh-host-keys/${id}`, { method: "DELETE" }), onSuccess: () => void qc.invalidateQueries({ queryKey: ["ssh-host-keys"] }) });
  const manage = can("credential:manage");

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">{t("خزنة الدخول للأجهزة", "Device credential vault")}</h1>
        <p className="text-sm text-slate-500">{t("حسابات الإدارة المستخدمة لتنفيذ أوامر التحقق والإغلاق على الأجهزة. كلمات المرور مشفرة (AES) ولا تغادر الخادم.", "Management accounts used to run verify/close commands on devices. Passwords are encrypted (AES) and never leave the server.")}</p>
      </div>
      {manage && <Card title={t("إضافة حساب", "Add account")}><NewCredential onDone={() => void qc.invalidateQueries({ queryKey: ["credentials"] })} /></Card>}
      <Card title={t("الحسابات المحفوظة", "Saved accounts")}>
        {creds.isLoading ? <Loading /> : creds.error ? <ErrorBox error={creds.error} /> : creds.data?.length === 0 ? <p className="text-sm text-slate-500">{t("لا توجد حسابات بعد.", "No accounts yet.")}</p> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b bg-slate-50">{[t("الاسم", "Name"), t("النوع", "Type"), t("المستخدم", "User"), t("المنفذ", "Port"), t("آخر استخدام", "Last used"), ""].map((h, i) => <th key={i} className="px-3 py-2 text-start">{h}</th>)}</tr></thead>
              <tbody>
                {creds.data?.map((c) => (
                  <tr key={c.id} className="border-b border-slate-100">
                    <td className="px-3 py-2 font-medium">{c.name}</td>
                    <td className="px-3 py-2"><Badge tone={c.kind === "ssh" ? "purple" : c.kind === "snmp" ? "teal" : "blue"}>{c.kind === "ssh" ? "SSH" : c.kind === "snmp" ? "SNMP" : c.use_https ? "WinRM HTTPS" : "WinRM"}</Badge></td>
                    <td className="px-3 py-2"><Ltr>{c.username}</Ltr></td>
                    <td className="px-3 py-2"><Ltr>{c.port}</Ltr></td>
                    <td className="px-3 py-2">{formatDate(c.last_used_at)}</td>
                    <td className="px-3 py-2">{manage && <Button variant="ghost" onClick={() => window.confirm(getLang() === "en" ? `Delete the account “${c.name}”?` : `حذف الحساب «${c.name}»؟`) && del.mutate(c.id)}>{t("حذف", "Delete")}</Button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title={t("مفاتيح SSH المعتمدة للأجهزة", "Pinned SSH host keys")}>
        <p className="mb-2 text-xs text-slate-500">{t("يُحفظ مفتاح كل جهاز عند أول اتصال. إذا تغيّر المفتاح لاحقاً يرفض راصد الاتصال (حماية من الانتحال). احذف المفتاح فقط إذا تأكدت أن الجهاز أعيد تثبيته.", "Each device's key is saved on first connection. If the key later changes, RasedNet refuses to connect (protection against spoofing). Delete a key only if you are sure the device was reinstalled.")}</p>
        {keys.data?.length === 0 ? <p className="text-sm text-slate-500">{t("لا توجد مفاتيح محفوظة.", "No saved keys.")}</p> : (
          <ul className="space-y-1 text-sm">
            {keys.data?.map((k) => (
              <li key={k.id} className="flex flex-wrap items-center gap-2">
                <Ltr>{`${k.ip}:${k.port}`}</Ltr> <Ltr className="text-xs text-slate-500">{`${k.key_type} ${k.fingerprint}`}</Ltr>
                <span className="text-xs text-slate-400">{formatDate(k.first_seen)}</span>
                {manage && <Button variant="ghost" onClick={() => window.confirm(t("حذف المفتاح المحفوظ لهذا الجهاز؟", "Delete the saved key for this device?")) && forget.mutate(k.id)}>{t("حذف", "Delete")}</Button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title={t("تجهيز الأجهزة للإدارة عن بعد", "Preparing devices for remote management")}>
        <div className="space-y-2 text-sm text-slate-700">
          <p><b>{t("ويندوز (WinRM):", "Windows (WinRM):")}</b> {t("على الجهاز المُدار شغّل في PowerShell كمسؤول:", "On the managed device, run in PowerShell as administrator:")} <Ltr>Enable-PSRemoting -Force</Ltr>. {t("داخل مجال Active Directory يعمل الحساب مباشرة؛ في مجموعة عمل استخدم حساب المسؤول المحلي.", "Inside an Active Directory domain the account works directly; in a workgroup use the local administrator account.")}</p>
          <p><b>{t("لينكس / الموجّهات (SSH):", "Linux / routers (SSH):")}</b> {t("فعّل خدمة SSH واستخدم حساباً له صلاحية sudo. يمرر راصد كلمة المرور لـ sudo مرة واحدة لكل أمر.", "Enable the SSH service and use an account with sudo. RasedNet passes the password to sudo once per command.")}</p>
        </div>
      </Card>
    </div>
  );
}
