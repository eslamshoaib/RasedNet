import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr } from "../components/ui";
import { formatDate } from "../format";
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
      <Field label="النوع">
        <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value as "winrm" | "ssh" | "snmp")}>
          <option value="winrm">WinRM (أجهزة ويندوز)</option>
          <option value="ssh">SSH (لينكس، الموجّهات، أجهزة التخزين)</option>
          <option value="snmp">SNMP (الموجّهات والمحوّلات — للتوبولوجي الفيزيائي)</option>
        </select>
      </Field>
      <Field label="اسم الحساب في الخزنة"><input className={inputClass} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="مثال: مسؤول أجهزة المكتب" /></Field>
      {isSnmp && (
        <Field label="إصدار SNMP">
          <select className={inputClass} value={snmpV3 ? "v3" : "v2c"} onChange={(e) => setSnmpV3(e.target.value === "v3")}>
            <option value="v2c">v2c (سلسلة مجتمع)</option>
            <option value="v3">v3 (مستخدم + تشفير)</option>
          </select>
        </Field>
      )}
      {!(isSnmp && snmpV3) && (
        <Field label={isSnmp ? "وصف (أي اسم)" : "اسم المستخدم"} hint={isSnmp ? "مثال: snmp-ro" : kind === "winrm" ? "مثال: CORP\\admin أو .\\Administrator" : "مثال: admin أو root"}>
          <input className={inputClass} dir="ltr" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
        </Field>
      )}
      {!(isSnmp && snmpV3) && (
        <Field label={isSnmp ? "سلسلة المجتمع (Community)" : "كلمة المرور"} hint="تُخزّن مشفرة ولا تُعرض مرة أخرى">
          <input className={inputClass} dir="ltr" type="password" autoComplete="new-password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </Field>
      )}
      {isSnmp && snmpV3 && (
        <>
          <Field label="اسم مستخدم SNMPv3"><input className={inputClass} dir="ltr" required value={v3.user} onChange={(e) => setV3({ ...v3, user: e.target.value })} /></Field>
          <Field label="مفتاح المصادقة (Auth)"><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={v3.auth_key} onChange={(e) => setV3({ ...v3, auth_key: e.target.value })} /></Field>
          <Field label="خوارزمية المصادقة"><select className={inputClass} value={v3.auth_proto} onChange={(e) => setV3({ ...v3, auth_proto: e.target.value })}><option value="sha">SHA</option><option value="md5">MD5</option></select></Field>
          <Field label="مفتاح التشفير (Priv)"><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={v3.priv_key} onChange={(e) => setV3({ ...v3, priv_key: e.target.value })} /></Field>
          <Field label="خوارزمية التشفير"><select className={inputClass} value={v3.priv_proto} onChange={(e) => setV3({ ...v3, priv_proto: e.target.value })}><option value="aes">AES</option><option value="des">DES</option></select></Field>
        </>
      )}
      <Field label="المنفذ" hint={`الافتراضي ${defaultPort}`}><input className={inputClass} dir="ltr" type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} /></Field>
      {kind === "winrm" && (
        <div className="flex flex-col justify-end gap-1 text-sm">
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={form.use_https} onChange={(e) => setForm({ ...form, use_https: e.target.checked })} /> استخدام HTTPS (5986)</label>
          {form.use_https && <label className="flex items-center gap-1.5"><input type="checkbox" checked={form.verify_tls} onChange={(e) => setForm({ ...form, verify_tls: e.target.checked })} /> التحقق من شهادة الجهاز</label>}
        </div>
      )}
      <div className="md:col-span-3"><ErrorBox error={error} /></div>
      <div><Button type="submit" disabled={create.isPending}>إضافة إلى الخزنة</Button></div>
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
        <h1 className="text-2xl font-bold">خزنة الدخول للأجهزة</h1>
        <p className="text-sm text-slate-500">حسابات الإدارة المستخدمة لتنفيذ أوامر التحقق والإغلاق على الأجهزة. كلمات المرور مشفرة (AES) ولا تغادر الخادم.</p>
      </div>
      {manage && <Card title="إضافة حساب"><NewCredential onDone={() => void qc.invalidateQueries({ queryKey: ["credentials"] })} /></Card>}
      <Card title="الحسابات المحفوظة">
        {creds.isLoading ? <Loading /> : creds.error ? <ErrorBox error={creds.error} /> : creds.data?.length === 0 ? <p className="text-sm text-slate-500">لا توجد حسابات بعد.</p> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b bg-slate-50">{["الاسم", "النوع", "المستخدم", "المنفذ", "آخر استخدام", ""].map((h) => <th key={h} className="px-3 py-2 text-start">{h}</th>)}</tr></thead>
              <tbody>
                {creds.data?.map((c) => (
                  <tr key={c.id} className="border-b border-slate-100">
                    <td className="px-3 py-2 font-medium">{c.name}</td>
                    <td className="px-3 py-2"><Badge tone={c.kind === "ssh" ? "purple" : c.kind === "snmp" ? "teal" : "blue"}>{c.kind === "ssh" ? "SSH" : c.kind === "snmp" ? "SNMP" : c.use_https ? "WinRM HTTPS" : "WinRM"}</Badge></td>
                    <td className="px-3 py-2"><Ltr>{c.username}</Ltr></td>
                    <td className="px-3 py-2"><Ltr>{c.port}</Ltr></td>
                    <td className="px-3 py-2">{formatDate(c.last_used_at)}</td>
                    <td className="px-3 py-2">{manage && <Button variant="ghost" onClick={() => window.confirm(`حذف الحساب «${c.name}»؟`) && del.mutate(c.id)}>حذف</Button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="مفاتيح SSH المعتمدة للأجهزة">
        <p className="mb-2 text-xs text-slate-500">يُحفظ مفتاح كل جهاز عند أول اتصال. إذا تغيّر المفتاح لاحقاً يرفض راصد الاتصال (حماية من الانتحال). احذف المفتاح فقط إذا تأكدت أن الجهاز أعيد تثبيته.</p>
        {keys.data?.length === 0 ? <p className="text-sm text-slate-500">لا توجد مفاتيح محفوظة.</p> : (
          <ul className="space-y-1 text-sm">
            {keys.data?.map((k) => (
              <li key={k.id} className="flex flex-wrap items-center gap-2">
                <Ltr>{`${k.ip}:${k.port}`}</Ltr> <Ltr className="text-xs text-slate-500">{`${k.key_type} ${k.fingerprint}`}</Ltr>
                <span className="text-xs text-slate-400">{formatDate(k.first_seen)}</span>
                {manage && <Button variant="ghost" onClick={() => window.confirm("حذف المفتاح المحفوظ لهذا الجهاز؟") && forget.mutate(k.id)}>حذف</Button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="تجهيز الأجهزة للإدارة عن بعد">
        <div className="space-y-2 text-sm text-slate-700">
          <p><b>ويندوز (WinRM):</b> على الجهاز المُدار شغّل في PowerShell كمسؤول: <Ltr>Enable-PSRemoting -Force</Ltr>. داخل مجال Active Directory يعمل الحساب مباشرة؛ في مجموعة عمل استخدم حساب المسؤول المحلي.</p>
          <p><b>لينكس / الموجّهات (SSH):</b> فعّل خدمة SSH واستخدم حساباً له صلاحية sudo. يمرر راصد كلمة المرور لـ sudo مرة واحدة لكل أمر.</p>
        </div>
      </Card>
    </div>
  );
}
