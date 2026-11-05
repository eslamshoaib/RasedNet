import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { IconRefresh } from "../components/icons";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, Stat } from "../components/ui";
import type { AttackPathSummary, DirectoryCredential, DirectoryDiscovery, DirectoryResult, DirUser } from "../types";

function AddDomainAccount({ onAdded }: { onAdded: () => void }) {
  const [form, setForm] = useState({ name: "", username: "", password: "" });
  const [err, setErr] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => api("/api/credentials", { method: "POST", body: {
      name: form.name, kind: "winrm", username: form.username, password: form.password, use_https: false, verify_tls: true } }),
    onSuccess: () => { setForm({ name: "", username: "", password: "" }); setErr(null); onAdded(); },
    onError: (e) => setErr(errorMessage(e)),
  });
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  return (
    <form onSubmit={submit} className="mt-2 grid gap-2 rounded-xl border border-slate-200 bg-slate-50 p-3 md:grid-cols-4">
      <Field label="اسم الحساب"><input className={inputClass} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="حساب الدومين" /></Field>
      <Field label="المستخدم" hint="DOMAIN\\user أو user@domain"><input className={inputClass} dir="ltr" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>
      <Field label="كلمة المرور"><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
      <div className="flex items-end"><Button type="submit" disabled={create.isPending}>أضف الحساب</Button></div>
      {err && <div className="md:col-span-4"><ErrorBox error={err} /></div>}
    </form>
  );
}

type Scope = "all" | "users" | "groups" | "computers";

function UserRow({ u }: { u: DirUser }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className="border-b border-slate-100 hover:bg-slate-50">
        <td className="p-2"><button type="button" className="text-cyan-800 underline" onClick={() => setOpen(!open)}><Ltr>{u.sam}</Ltr></button></td>
        <td className="p-2">{u.display_name || "—"}</td>
        <td className="p-2 text-center">{u.enabled ? <Badge tone="green">مُفعّل</Badge> : <Badge tone="slate">معطّل</Badge>}</td>
        <td className="p-2 text-center">
          {u.is_privileged ? <Badge tone="red">صلاحيات إدارية</Badge> : <span className="text-xs text-slate-400">عادي</span>}
        </td>
        <td className="p-2 text-center">{u.group_count}</td>
        <td className="p-2 text-xs text-slate-500">{u.privileges.map((p) => p.label_ar).join("، ") || "—"}</td>
      </tr>
      {open && (
        <tr className="border-b border-slate-100 bg-slate-50/60">
          <td colSpan={6} className="p-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1 text-sm">
                {u.upn && <div>الاسم الأساسي: <Ltr>{u.upn}</Ltr></div>}
                {u.mail && <div>البريد: <Ltr>{u.mail}</Ltr></div>}
                {u.description && <div className="text-slate-600">{u.description}</div>}
                <div className="text-xs text-slate-500"><Ltr>{u.dn}</Ltr></div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {u.flags.password_never_expires && <Badge tone="amber">كلمة المرور لا تنتهي</Badge>}
                  {u.flags.password_not_required && <Badge tone="red">لا تتطلب كلمة مرور</Badge>}
                  {u.flags.locked_out && <Badge tone="red">محظور</Badge>}
                  {u.flags.trusted_for_delegation && <Badge tone="orange">موثوق للتفويض</Badge>}
                  {u.flags.smartcard_required && <Badge tone="blue">يتطلب بطاقة ذكية</Badge>}
                  {u.admin_count > 0 && <Badge tone="purple">حساب محمي (adminCount)</Badge>}
                </div>
              </div>
              <div>
                <div className="mb-1 text-xs font-semibold text-slate-700">العضوية في المجموعات ({u.groups.length})</div>
                <div className="flex flex-wrap gap-1">
                  {u.groups.length ? u.groups.map((g) => (
                    <span key={g} className={`rounded px-1.5 py-0.5 text-xs ${u.privileges.some((p) => p.group === g) ? "bg-red-100 text-red-800" : "bg-slate-200 text-slate-700"}`}>{g}</span>
                  )) : <span className="text-xs text-slate-400">لا توجد</span>}
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export function DirectoryPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const creds = useQuery({ queryKey: ["dir-creds"], queryFn: () => api<DirectoryCredential[]>("/api/directory/credentials") });
  const discovery = useQuery({ queryKey: ["dir-discover"], queryFn: () => api<DirectoryDiscovery>("/api/directory/discover") });
  const [credId, setCredId] = useState<number | "">("");
  const [mode, setMode] = useState<"integrated" | "credential">("credential");
  const [host, setHost] = useState("");
  const [baseDn, setBaseDn] = useState("");
  const [useSsl, setUseSsl] = useState(false);
  const [scope, setScope] = useState<Scope>("all");
  const [filter, setFilter] = useState("");
  const [tab, setTab] = useState<"users" | "groups" | "computers">("users");
  const [showAdd, setShowAdd] = useState(false);

  // Prefill the host + base DN from auto-discovery, and prefer the current-user bind when available.
  useEffect(() => {
    const d = discovery.data;
    if (!d) return;
    if (!host && d.controllers[0]) setHost(d.controllers[0].host);
    if (!baseDn && d.base_dn) setBaseDn(d.base_dn);
    if (d.integrated_available) setMode("integrated");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [discovery.data]);

  const body = () => ({ credential_id: mode === "integrated" ? null : credId, host: host.trim(), base_dn: baseDn.trim() || null, use_ssl: useSsl, scope });
  const run = useMutation({
    mutationFn: (opts?: { hostOverride?: string }) => api<DirectoryResult>("/api/directory/query", {
      method: "POST", body: { ...body(), host: (opts?.hostOverride ?? host).trim() },
    }),
  });
  const attack = useMutation({
    mutationFn: () => api<AttackPathSummary>("/api/directory/attack-paths", { method: "POST", body: { ...body(), scope: "all" } }),
  });
  const result = run.data;

  const ft = filter.trim().toLowerCase();
  const users = useMemo(() => (result?.users ?? []).filter((u) =>
    !ft || [u.sam, u.display_name, u.upn, u.description].some((v) => v?.toLowerCase().includes(ft))), [result, ft]);
  const groups = useMemo(() => (result?.groups ?? []).filter((g) =>
    !ft || [g.name, g.description].some((v) => v?.toLowerCase().includes(ft))), [result, ft]);
  const computers = useMemo(() => (result?.computers ?? []).filter((c) =>
    !ft || [c.name, c.dns, c.os].some((v) => v?.toLowerCase().includes(ft))), [result, ft]);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">مستخدمو ومجموعات الدومين</h1>
        <p className="text-sm text-slate-500">
          استعلام قراءة فقط عن Active Directory بحساب مصرّح له من الخزنة: كل المستخدمين وصلاحية كل واحد والمجموعات.
          لا يكتب راصد في الدليل ولا يستخرج كلمات المرور.
        </p>
      </div>

      <Card title="الاتصال بالدومين" actions={
        <Button variant="secondary" onClick={() => discovery.refetch()} disabled={discovery.isFetching}>
          <IconRefresh className="h-4 w-4" /> إعادة الاكتشاف
        </Button>
      }>
        {discovery.isLoading ? <Loading /> : (
          <>
            {/* Auto-discovery banner */}
            {discovery.data?.domain ? (
              <div className="mb-3 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm">
                اكتشف راصد الدومين: <b dir="ltr">{discovery.data.domain}</b>
                {discovery.data.env.USERNAME && <> — المستخدم الحالي <Ltr>{discovery.data.env.USERNAME}</Ltr></>}
                {discovery.data.integrated_available
                  ? <div className="mt-1 text-emerald-800">سيُستخدم حساب المستخدم الحالي تلقائياً (بدون كلمة مرور).</div>
                  : <div className="mt-1 text-amber-800">الربط التلقائي بالمستخدم الحالي غير متاح (خادم راصد غير منضمّ للدومين) — اختر حساباً بالأسفل.</div>}
              </div>
            ) : (
              <div className="mb-3 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
                لم يُكتشف دومين من بيئة الخادم. لو شبكتك فيها Active Directory، اختر وحدة تحكم وحساباً بالأسفل.
              </div>
            )}

            {/* Discovered controllers as quick-pick */}
            {(discovery.data?.controllers.length ?? 0) > 0 && (
              <div className="mb-3">
                <div className="mb-1 text-xs font-semibold text-slate-700">وحدات التحكم المكتشفة</div>
                <div className="flex flex-wrap gap-1.5">
                  {discovery.data!.controllers.map((c) => (
                    <button key={c.host} type="button" onClick={() => setHost(c.host)}
                      className={`rounded-lg border px-2 py-1 text-xs ${host === c.host ? "border-cyan-600 bg-cyan-600 text-white" : "border-slate-300 bg-white hover:border-cyan-400"}`}>
                      <Ltr>{c.host}</Ltr> <span className="opacity-60">({c.source})</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <label className="text-sm">
                <span className="mb-0.5 block text-slate-600">طريقة الدخول</span>
                <select className={inputClass} value={mode} onChange={(e) => setMode(e.target.value as "integrated" | "credential")}>
                  <option value="integrated" disabled={!discovery.data?.integrated_available}>المستخدم الحالي (تلقائي)</option>
                  <option value="credential">حساب من الخزنة</option>
                </select>
              </label>
              {mode === "credential" && (
                <label className="text-sm">
                  <span className="mb-0.5 block text-slate-600">حساب الدخول</span>
                  <select className={inputClass} value={credId} onChange={(e) => setCredId(e.target.value ? Number(e.target.value) : "")}>
                    <option value="">اختر حساباً…</option>
                    {creds.data?.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.username})</option>)}
                  </select>
                </label>
              )}
              <label className="text-sm">
                <span className="mb-0.5 block text-slate-600">وحدة التحكم (IP أو اسم)</span>
                <input dir="ltr" className={inputClass} placeholder="dc01.example.local" value={host} onChange={(e) => setHost(e.target.value)} />
              </label>
              <label className="text-sm">
                <span className="mb-0.5 block text-slate-600">نطاق البحث (اختياري)</span>
                <input dir="ltr" className={inputClass} placeholder="DC=example,DC=local" value={baseDn} onChange={(e) => setBaseDn(e.target.value)} />
              </label>
              <label className="text-sm">
                <span className="mb-0.5 block text-slate-600">ماذا نجلب</span>
                <select className={inputClass} value={scope} onChange={(e) => setScope(e.target.value as Scope)}>
                  <option value="all">المستخدمون والمجموعات والأجهزة</option>
                  <option value="users">المستخدمون فقط</option>
                  <option value="groups">المجموعات فقط</option>
                  <option value="computers">أجهزة الدومين فقط</option>
                </select>
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={useSsl} onChange={(e) => setUseSsl(e.target.checked)} />
                استخدام LDAPS (منفذ 636)
              </label>
              <div className="flex items-end gap-2">
                <Button onClick={() => run.mutate(undefined)}
                  disabled={run.isPending || !host.trim() || (mode === "credential" && !credId)}>
                  <IconRefresh className="h-4 w-4" /> {run.isPending ? "جارٍ الجلب…" : "اكتشف مستخدمي الدومين"}
                </Button>
                <Button variant="secondary" onClick={() => attack.mutate()}
                  disabled={attack.isPending || !host.trim() || (mode === "credential" && !credId)}
                  title="تحليل من يمكنه الوصول لمجموعات الصلاحيات العليا">
                  {attack.isPending ? "جارٍ التحليل…" : "🛡️ مسارات الهجوم"}
                </Button>
              </div>
            </div>
            {attack.error && <div className="mt-2"><ErrorBox error={errorMessage(attack.error)} /></div>}

            {/* Inline add-account (admins), shown when a credential is needed and none chosen */}
            {mode === "credential" && can("credential:manage") && (
              <div className="mt-2">
                <button type="button" className="text-xs text-cyan-800 underline" onClick={() => setShowAdd(!showAdd)}>
                  {showAdd ? "إخفاء" : "+ إضافة حساب دومين من هنا"}
                </button>
                {showAdd && <AddDomainAccount onAdded={() => { setShowAdd(false); void qc.invalidateQueries({ queryKey: ["dir-creds"] }); }} />}
              </div>
            )}
          </>
        )}
        {run.error && <div className="mt-2"><ErrorBox error={errorMessage(run.error)} /></div>}
      </Card>

      {attack.data && (
        <Card title="🛡️ مسارات الهجوم إلى الصلاحيات العليا">
          <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="حسابات بصلاحيات عليا" value={attack.data.privileged_users} tone={attack.data.privileged_users ? "red" : "green"} />
            <Stat label="تصعيد عبر عضوية متداخلة" value={attack.data.nested_escalations} tone={attack.data.nested_escalations ? "orange" : "slate"} hint="يصعب كشفه يدوياً" />
            <Stat label="حسابات عالية الخطورة" value={attack.data.risky.length} tone={attack.data.risky.length ? "red" : "green"} />
            <Stat label="مجموعات مستهدَفة" value={attack.data.targets.length} tone="purple" />
          </div>
          {attack.data.risky.length > 0 && (
            <div className="mb-3 rounded-xl border border-red-200 bg-red-50/40 p-2">
              <div className="mb-1 text-sm font-semibold text-red-800">حسابات عالية الخطورة</div>
              {attack.data.risky.map((r, i) => (
                <div key={i} className="text-sm"><Ltr className="font-mono">{r.user}</Ltr> → {r.target}: <span className="text-xs text-red-700">{r.reasons_ar.join("، ")}</span></div>
              ))}
            </div>
          )}
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2 text-start">الحساب</th><th className="p-2">الحالة</th><th className="p-2">النوع</th>
                <th className="p-2">القفزات</th><th className="p-2 text-start">المسار إلى الصلاحية</th>
              </tr></thead>
              <tbody>
                {attack.data.paths.map((p, i) => (
                  <tr key={i} className="border-b border-slate-100">
                    <td className="p-2"><Ltr className="font-medium">{p.user}</Ltr> <span className="text-xs text-slate-500">{p.display_name}</span></td>
                    <td className="p-2 text-center">{p.enabled ? <Badge tone="green">مُفعّل</Badge> : <Badge tone="red">معطّل!</Badge>}</td>
                    <td className="p-2 text-center">{p.direct ? <Badge tone="amber">مباشر</Badge> : <Badge tone="orange">متداخل ({p.hops})</Badge>}</td>
                    <td className="p-2 text-center font-mono">{p.hops}</td>
                    <td className="p-2"><Ltr className="text-xs text-slate-600">{p.path.join(" → ")}</Ltr> <Badge tone="red">{p.label_ar}</Badge></td>
                  </tr>
                ))}
                {attack.data.paths.length === 0 && <tr><td colSpan={5} className="p-3 text-center text-emerald-700">لا توجد حسابات تصل لمجموعات الصلاحيات العليا.</td></tr>}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {result && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
            <Stat label="المستخدمون" value={result.counts.users} tone="blue" />
            <Stat label="مُفعّل" value={result.counts.enabled_users} tone="green" hint={`معطّل: ${result.counts.disabled_users}`} />
            <Stat label="بصلاحيات إدارية" value={result.counts.privileged_users} tone="red" />
            <Stat label="المجموعات" value={result.counts.groups} tone="teal" hint={`مميّزة: ${result.counts.privileged_groups}`} />
            <Stat label="أجهزة الدومين" value={result.counts.computers} tone="purple" />
            <Stat label="كلمة مرور لا تنتهي" value={result.counts.password_never_expires} tone="amber" />
          </div>

          <Card title={`الدومين: ${result.domain.dns_domain || result.domain.base_dn}`}>
            <p className="mb-3 text-xs text-slate-500"><Ltr>{result.domain.base_dn}</Ltr> — عبر <Ltr>{result.domain.host}</Ltr></p>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              {(["users", "groups", "computers"] as const).map((t) => (
                <button key={t} type="button" onClick={() => setTab(t)}
                  className={`rounded-lg px-3 py-1 text-sm ${tab === t ? "bg-cyan-600 text-white" : "bg-slate-100 text-slate-700"}`}>
                  {t === "users" ? `المستخدمون (${result.counts.users})` : t === "groups" ? `المجموعات (${result.counts.groups})` : `الأجهزة (${result.counts.computers})`}
                </button>
              ))}
              <input className={`${inputClass} ms-auto max-w-xs`} placeholder="بحث…" value={filter} onChange={(e) => setFilter(e.target.value)} />
            </div>

            {tab === "users" && (
              <div className="overflow-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b text-slate-500">
                    <th className="p-2 text-start">الحساب</th><th className="p-2 text-start">الاسم</th><th className="p-2">الحالة</th>
                    <th className="p-2">الصلاحية</th><th className="p-2">المجموعات</th><th className="p-2 text-start">الامتيازات</th>
                  </tr></thead>
                  <tbody>{users.map((u) => <UserRow key={u.dn || u.sam} u={u} />)}</tbody>
                </table>
                {!users.length && <p className="p-3 text-sm text-slate-500">لا نتائج.</p>}
              </div>
            )}

            {tab === "groups" && (
              <div className="overflow-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b text-slate-500">
                    <th className="p-2 text-start">المجموعة</th><th className="p-2">الأعضاء</th><th className="p-2">مميّزة</th><th className="p-2 text-start">الوصف</th>
                  </tr></thead>
                  <tbody>
                    {groups.map((g) => (
                      <tr key={g.dn || g.name} className="border-b border-slate-100">
                        <td className="p-2 font-medium">{g.name}{g.label_ar && <span className="ms-1 text-xs text-red-700">({g.label_ar})</span>}</td>
                        <td className="p-2 text-center">{g.member_count}</td>
                        <td className="p-2 text-center">{g.privileged ? <Badge tone="red">نعم</Badge> : "—"}</td>
                        <td className="p-2 text-xs text-slate-500">{g.description || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!groups.length && <p className="p-3 text-sm text-slate-500">لا نتائج.</p>}
              </div>
            )}

            {tab === "computers" && (
              <div className="overflow-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b text-slate-500">
                    <th className="p-2 text-start">الجهاز</th><th className="p-2 text-start">اسم DNS</th><th className="p-2 text-start">نظام التشغيل</th><th className="p-2">الحالة</th>
                  </tr></thead>
                  <tbody>
                    {computers.map((c) => (
                      <tr key={c.dn || c.name} className="border-b border-slate-100">
                        <td className="p-2 font-medium">{c.name}</td>
                        <td className="p-2"><Ltr className="text-xs">{c.dns || "—"}</Ltr></td>
                        <td className="p-2">{c.os || "—"} <span className="text-xs text-slate-400">{c.os_version}</span></td>
                        <td className="p-2 text-center">{c.enabled ? <Badge tone="green">مُفعّل</Badge> : <Badge tone="slate">معطّل</Badge>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!computers.length && <p className="p-3 text-sm text-slate-500">لا نتائج.</p>}
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
