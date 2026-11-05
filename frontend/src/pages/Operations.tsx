import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api, errorMessage } from "../api";
import { IconRefresh } from "../components/icons";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr } from "../components/ui";
import type { Tone } from "../components/ui";
import { DEVICE_TYPES, label } from "../labels";
import type { AgentTokenCreated, AgentTokenRow, MaintenanceWindow, NotificationConfig, PolicyFinding, PolicyRule, PolicyStats } from "../types";

const SEV_TONE: Record<string, Tone> = { critical: "red", high: "orange", medium: "amber", low: "green" };

function PolicySection() {
  const qc = useQueryClient();
  const rules = useQuery({ queryKey: ["policy-rules"], queryFn: () => api<PolicyRule[]>("/api/policy/rules") });
  const findings = useQuery({ queryKey: ["policy-findings"], queryFn: () => api<PolicyFinding[]>("/api/policy/findings") });
  const [msg, setMsg] = useState<string | null>(null);
  const [form, setForm] = useState({ port: "", protocol: "tcp", device_type: "", note_ar: "" });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["policy-rules"] }); void qc.invalidateQueries({ queryKey: ["policy-findings"] }); };

  const seed = useMutation({ mutationFn: () => api<{ added: number }>("/api/policy/seed", { method: "POST" }),
    onSuccess: (r) => { setMsg(`أُضيفت ${r.added} قاعدة من الخدمات الحالية.`); refresh(); } });
  const evaluate = useMutation({ mutationFn: () => api<PolicyStats>("/api/policy/evaluate", { method: "POST" }),
    onSuccess: (r) => { setMsg(`التقييم: ${r.unauthorized} خدمة غير معتمدة، ${r.rogue_gateways} بوابة مشبوهة، ${r.resolved} أُغلقت.`); refresh(); } });
  const addRule = useMutation({
    mutationFn: () => api("/api/policy/rules", { method: "POST", body: {
      port: form.port ? Number(form.port) : null, protocol: form.protocol,
      device_type: form.device_type || null, note_ar: form.note_ar } }),
    onSuccess: () => { setForm({ port: "", protocol: "tcp", device_type: "", note_ar: "" }); refresh(); },
  });
  const delRule = useMutation({ mutationFn: (id: number) => api(`/api/policy/rules/${id}`, { method: "DELETE" }), onSuccess: refresh });

  return (
    <Card title="خط الأساس للخدمات المعتمدة" actions={
      <div className="flex gap-2">
        <Button variant="secondary" onClick={() => seed.mutate()} disabled={seed.isPending}>اعتمد الوضع الحالي كخط أساس</Button>
        <Button onClick={() => evaluate.mutate()} disabled={evaluate.isPending}><IconRefresh className="h-4 w-4" /> أعد التقييم</Button>
      </div>
    }>
      <p className="mb-2 text-sm text-slate-500">كل خدمة مفتوحة لا تطابق قاعدة معتمدة تُرصد كخدمة غير معتمدة. المنفذ الفارغ = أي منفذ؛ النوع الفارغ = أي جهاز.</p>
      {msg && <p className="mb-2 rounded-lg bg-emerald-50 px-3 py-1.5 text-sm text-emerald-800">{msg}</p>}
      {(seed.error || evaluate.error || addRule.error) && <ErrorBox error={errorMessage(seed.error ?? evaluate.error ?? addRule.error)} />}

      {findings.data && findings.data.length > 0 && (
        <div className="mb-3 rounded-xl border border-red-200 bg-red-50/40 p-2">
          <div className="mb-1 text-sm font-semibold text-red-800">نتائج مفتوحة ({findings.data.length})</div>
          <div className="space-y-1">
            {findings.data.map((f) => (
              <div key={f.id} className="flex items-start gap-2 text-sm">
                <Badge tone={SEV_TONE[f.severity] ?? "slate"}>{f.kind === "rogue_gateway" ? "بوابة مشبوهة" : "غير معتمد"}</Badge>
                <span>{f.message_ar}{f.asset_id ? <> — <Link className="text-cyan-700 underline" to={`/assets/${f.asset_id}`}>الجهاز</Link></> : null}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <form className="mb-3 flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); addRule.mutate(); }}>
        <Field label="المنفذ (فارغ = أي)"><input className={`${inputClass} w-28`} dir="ltr" type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} /></Field>
        <Field label="البروتوكول"><select className={inputClass} value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}><option value="tcp">tcp</option><option value="udp">udp</option></select></Field>
        <Field label="نوع الجهاز (اختياري)">
          <select className={inputClass} value={form.device_type} onChange={(e) => setForm({ ...form, device_type: e.target.value })}>
            <option value="">أي جهاز</option>
            {Object.keys(DEVICE_TYPES).map((t) => <option key={t} value={t}>{label(DEVICE_TYPES, t)}</option>)}
          </select>
        </Field>
        <Field label="ملاحظة"><input className={`${inputClass} w-40`} value={form.note_ar} onChange={(e) => setForm({ ...form, note_ar: e.target.value })} /></Field>
        <Button type="submit" disabled={addRule.isPending}>أضف قاعدة</Button>
      </form>

      {rules.isLoading ? <Loading /> : (
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b text-slate-500"><th className="p-2 text-start">المنفذ</th><th className="p-2">البروتوكول</th><th className="p-2 text-start">نوع الجهاز</th><th className="p-2 text-start">ملاحظة</th><th className="p-2"></th></tr></thead>
            <tbody>
              {rules.data?.map((r) => (
                <tr key={r.id} className="border-b border-slate-100">
                  <td className="p-2"><Ltr>{r.port ?? "أي"}</Ltr></td>
                  <td className="p-2 text-center">{r.protocol}</td>
                  <td className="p-2">{r.device_type ? label(DEVICE_TYPES, r.device_type) : "أي"}</td>
                  <td className="p-2 text-slate-500">{r.note_ar}</td>
                  <td className="p-2 text-center"><button type="button" className="text-xs text-red-700 underline" onClick={() => delRule.mutate(r.id)}>حذف</button></td>
                </tr>
              ))}
              {!rules.data?.length && <tr><td colSpan={5} className="p-3 text-center text-slate-500">لا قواعد بعد. اضغط «اعتمد الوضع الحالي كخط أساس» للبدء.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function MaintenanceSection() {
  const qc = useQueryClient();
  const windows = useQuery({ queryKey: ["maint-windows"], queryFn: () => api<MaintenanceWindow[]>("/api/maintenance/windows") });
  const [form, setForm] = useState({ name: "", starts_at: "", ends_at: "", cidr: "", note_ar: "" });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["maint-windows"] });
  const add = useMutation({
    mutationFn: () => api("/api/maintenance/windows", { method: "POST", body: {
      name: form.name, starts_at: new Date(form.starts_at).toISOString(), ends_at: new Date(form.ends_at).toISOString(),
      cidr: form.cidr || null, note_ar: form.note_ar } }),
    onSuccess: () => { setForm({ name: "", starts_at: "", ends_at: "", cidr: "", note_ar: "" }); refresh(); },
  });
  const del = useMutation({ mutationFn: (id: number) => api(`/api/maintenance/windows/${id}`, { method: "DELETE" }), onSuccess: refresh });

  return (
    <Card title="نوافذ الصيانة">
      <p className="mb-2 text-sm text-slate-500">أثناء نافذة الصيانة لا تُرسل إشعارات التنبيهات للأجهزة المشمولة (نطاق فارغ = كل الشبكة).</p>
      <form className="mb-3 flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
        <Field label="الاسم"><input className={inputClass} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
        <Field label="من"><input className={inputClass} type="datetime-local" required value={form.starts_at} onChange={(e) => setForm({ ...form, starts_at: e.target.value })} /></Field>
        <Field label="إلى"><input className={inputClass} type="datetime-local" required value={form.ends_at} onChange={(e) => setForm({ ...form, ends_at: e.target.value })} /></Field>
        <Field label="النطاق (اختياري)"><input className={`${inputClass} w-40`} dir="ltr" placeholder="10.0.0.0/24" value={form.cidr} onChange={(e) => setForm({ ...form, cidr: e.target.value })} /></Field>
        <Button type="submit" disabled={add.isPending}>إضافة</Button>
      </form>
      {add.error && <ErrorBox error={errorMessage(add.error)} />}
      {windows.isLoading ? <Loading /> : (
        <div className="space-y-1">
          {windows.data?.map((w) => (
            <div key={w.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-200 p-2 text-sm">
              {w.active ? <Badge tone="amber">نشطة الآن</Badge> : <Badge tone="slate">مجدولة</Badge>}
              <span className="font-medium">{w.name}</span>
              <span className="text-slate-500">{new Date(w.starts_at).toLocaleString("ar-EG")} ← {new Date(w.ends_at).toLocaleString("ar-EG")}</span>
              {w.cidr && <Ltr className="text-xs text-slate-500">{w.cidr}</Ltr>}
              <button type="button" className="ms-auto text-xs text-red-700 underline" onClick={() => del.mutate(w.id)}>حذف</button>
            </div>
          ))}
          {!windows.data?.length && <p className="text-sm text-slate-500">لا نوافذ صيانة.</p>}
        </div>
      )}
    </Card>
  );
}

function NotificationsSection() {
  const qc = useQueryClient();
  const cfg = useQuery({ queryKey: ["notif-config"], queryFn: () => api<NotificationConfig>("/api/notifications/config") });
  const [form, setForm] = useState<Record<string, string | boolean>>({});
  const [msg, setMsg] = useState<string | null>(null);
  const val = <T,>(k: keyof NotificationConfig, fallback: T): T => (k in form ? (form[k as string] as T) : ((cfg.data?.[k] as T) ?? fallback));
  const save = useMutation({
    mutationFn: () => api<NotificationConfig>("/api/notifications/config", { method: "PUT", body: {
      enabled: val("enabled", false), smtp_host: val("smtp_host", ""), smtp_port: Number(val("smtp_port", 587)),
      use_tls: val("use_tls", true), from_addr: val("from_addr", ""),
      to_addrs: String(val("to_addrs", (cfg.data?.to_addrs ?? []).join(", "))).split(",").map((x) => x.trim()).filter(Boolean),
      username: val("username", ""), password: form.password ? String(form.password) : null,
      min_severity: val("min_severity", "high"), escalation_minutes: Number(val("escalation_minutes", 60)) } }),
    onSuccess: () => { setMsg("حُفظ الإعداد."); setForm({}); void qc.invalidateQueries({ queryKey: ["notif-config"] }); },
  });
  const test = useMutation({ mutationFn: () => api<{ sent: boolean }>("/api/notifications/test", { method: "POST" }),
    onSuccess: () => setMsg("أُرسلت رسالة الاختبار بنجاح."), onError: () => setMsg(null) });

  if (cfg.isLoading) return <Card title="إشعارات البريد"><Loading /></Card>;
  const toText = "to_addrs" in form ? String(form.to_addrs) : (cfg.data?.to_addrs ?? []).join(", ");

  return (
    <Card title="إشعارات البريد (SMTP) والتصعيد">
      <p className="mb-2 text-sm text-slate-500">يرسل راصد تنبيهاً بالبريد عبر خادمك الداخلي عند ظهور تنبيهات بالخطورة المحددة فأعلى، ويصعّد التنبيهات الحرجة التي تبقى مفتوحة.</p>
      <div className="grid gap-3 md:grid-cols-3">
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={val("enabled", false)} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> تفعيل الإشعارات</label>
        <Field label="خادم SMTP"><input className={inputClass} dir="ltr" value={val("smtp_host", "")} onChange={(e) => setForm({ ...form, smtp_host: e.target.value })} /></Field>
        <Field label="المنفذ"><input className={inputClass} dir="ltr" type="number" value={val("smtp_port", 587)} onChange={(e) => setForm({ ...form, smtp_port: e.target.value })} /></Field>
        <Field label="المُرسِل (From)"><input className={inputClass} dir="ltr" value={val("from_addr", "")} onChange={(e) => setForm({ ...form, from_addr: e.target.value })} /></Field>
        <Field label="المستلمون (يفصلهم فاصلة)"><input className={inputClass} dir="ltr" value={toText} onChange={(e) => setForm({ ...form, to_addrs: e.target.value })} /></Field>
        <Field label="اسم المستخدم (اختياري)"><input className={inputClass} dir="ltr" value={val("username", "")} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>
        <Field label={`كلمة المرور ${cfg.data?.has_password ? "(محفوظة — اتركها فارغة للإبقاء)" : ""}`}><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={String(form.password ?? "")} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
        <Field label="أدنى خطورة للإشعار"><select className={inputClass} value={val("min_severity", "high")} onChange={(e) => setForm({ ...form, min_severity: e.target.value })}><option value="low">منخفض</option><option value="medium">متوسط</option><option value="high">مرتفع</option><option value="critical">حرِج</option></select></Field>
        <Field label="تصعيد الحرج بعد (دقائق)"><input className={inputClass} dir="ltr" type="number" min={5} value={val("escalation_minutes", 60)} onChange={(e) => setForm({ ...form, escalation_minutes: e.target.value })} /></Field>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={val("use_tls", true)} onChange={(e) => setForm({ ...form, use_tls: e.target.checked })} /> استخدام STARTTLS</label>
      </div>
      <div className="mt-3 flex gap-2">
        <Button onClick={() => save.mutate()} disabled={save.isPending}>حفظ</Button>
        <Button variant="secondary" onClick={() => test.mutate()} disabled={test.isPending}>إرسال رسالة اختبار</Button>
      </div>
      {msg && <p className="mt-2 rounded-lg bg-emerald-50 px-3 py-1.5 text-sm text-emerald-800">{msg}</p>}
      {(save.error || test.error) && <div className="mt-2"><ErrorBox error={errorMessage(save.error ?? test.error)} /></div>}
    </Card>
  );
}

function AgentsSection() {
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: ["agent-tokens"], queryFn: () => api<AgentTokenRow[]>("/api/agents/tokens") });
  const [label, setLabel] = useState("");
  const [created, setCreated] = useState<AgentTokenCreated | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["agent-tokens"] });
  const create = useMutation({ mutationFn: () => api<AgentTokenCreated>("/api/agents/tokens", { method: "POST", body: { label } }),
    onSuccess: (r) => { setCreated(r); setLabel(""); refresh(); } });
  const del = useMutation({ mutationFn: (id: number) => api(`/api/agents/tokens/${id}`, { method: "DELETE" }), onSuccess: refresh });

  return (
    <Card title="وكلاء النهايات (Endpoint Agents)">
      <p className="mb-2 text-sm text-slate-500">
        أنشئ رمز تسجيل، وشغّل وكيل راصد على الجهاز ليبلّغ عن نفسه (الاسم، النظام، العنوان، المنافذ المستمعة) — دون فحص.
        السكربت المرجعي في <Ltr>agent/rased_agent.py</Ltr>.
      </p>
      <form className="mb-2 flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
        <Field label="وصف الرمز"><input className={inputClass} required value={label} onChange={(e) => setLabel(e.target.value)} placeholder="مثال: لابتوبات القسم" /></Field>
        <Button type="submit" disabled={create.isPending}>إنشاء رمز</Button>
      </form>
      {created && (
        <div className="mb-2 rounded-lg border border-emerald-200 bg-emerald-50 p-2 text-sm">
          <div className="mb-1 font-semibold text-emerald-800">انسخ الرمز الآن — لن يظهر مرة أخرى:</div>
          <pre dir="ltr" className="ltr overflow-auto rounded bg-slate-900 px-2 py-1.5 text-xs text-slate-100">{created.token}</pre>
          <div className="mt-1 text-xs text-slate-600">التشغيل على الجهاز:</div>
          <pre dir="ltr" className="ltr overflow-auto rounded bg-slate-100 px-2 py-1.5 text-[11px]">python rased_agent.py --server https://HOST:8765 --token {created.token} --interval 3600</pre>
        </div>
      )}
      {tokens.isLoading ? <Loading /> : (
        <div className="space-y-1">
          {tokens.data?.map((t) => (
            <div key={t.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-200 p-2 text-sm">
              <span className="font-medium">{t.label}</span>
              {t.last_seen_at ? <Badge tone="green">آخر تبليغ: {new Date(t.last_seen_at).toLocaleString("ar-EG")}{t.last_host ? ` — ${t.last_host}` : ""}</Badge> : <Badge tone="slate">لم يُستخدم بعد</Badge>}
              <button type="button" className="ms-auto text-xs text-red-700 underline" onClick={() => del.mutate(t.id)}>حذف</button>
            </div>
          ))}
          {!tokens.data?.length && <p className="text-sm text-slate-500">لا رموز بعد.</p>}
        </div>
      )}
      {(create.error || del.error) && <div className="mt-2"><ErrorBox error={errorMessage(create.error ?? del.error)} /></div>}
    </Card>
  );
}

export function OperationsPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">السياسات والإشعارات</h1>
        <p className="text-sm text-slate-500">خط أساس الخدمات المعتمدة وكشف غير المصرّح به، نوافذ الصيانة، إشعارات البريد، ووكلاء النهايات.</p>
      </div>
      <PolicySection />
      <MaintenanceSection />
      <NotificationsSection />
      <AgentsSection />
    </div>
  );
}
