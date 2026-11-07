import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { IconRefresh } from "../components/icons";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, Stat } from "../components/ui";
import { t } from "../i18n";
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
      <Field label={t("اسم الحساب", "Account name")}><input className={inputClass} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={t("حساب الدومين", "Domain account")} /></Field>
      <Field label={t("المستخدم", "User")} hint="DOMAIN\\user أو user@domain"><input className={inputClass} dir="ltr" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>
      <Field label={t("كلمة المرور", "Password")}><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
      <div className="flex items-end"><Button type="submit" disabled={create.isPending}>{t("أضف الحساب", "Add account")}</Button></div>
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
        <td className="p-2 text-center">{u.enabled ? <Badge tone="green">{t("مُفعّل", "Enabled")}</Badge> : <Badge tone="slate">{t("معطّل", "Disabled")}</Badge>}</td>
        <td className="p-2 text-center">
          {u.is_privileged ? <Badge tone="red">{t("صلاحيات إدارية", "Administrative")}</Badge> : <span className="text-xs text-slate-400">{t("عادي", "Standard")}</span>}
        </td>
        <td className="p-2 text-center">{u.group_count}</td>
        <td className="p-2 text-xs text-slate-500">{u.privileges.map((p) => p.label_ar).join(t("، ", ", ")) || "—"}</td>
      </tr>
      {open && (
        <tr className="border-b border-slate-100 bg-slate-50/60">
          <td colSpan={6} className="p-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1 text-sm">
                {u.upn && <div>{t("الاسم الأساسي:", "UPN:")} <Ltr>{u.upn}</Ltr></div>}
                {u.mail && <div>{t("البريد:", "Email:")} <Ltr>{u.mail}</Ltr></div>}
                {u.description && <div className="text-slate-600">{u.description}</div>}
                <div className="text-xs text-slate-500"><Ltr>{u.dn}</Ltr></div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {u.flags.password_never_expires && <Badge tone="amber">{t("كلمة المرور لا تنتهي", "Password never expires")}</Badge>}
                  {u.flags.password_not_required && <Badge tone="red">{t("لا تتطلب كلمة مرور", "Password not required")}</Badge>}
                  {u.flags.locked_out && <Badge tone="red">{t("محظور", "Locked out")}</Badge>}
                  {u.flags.trusted_for_delegation && <Badge tone="orange">{t("موثوق للتفويض", "Trusted for delegation")}</Badge>}
                  {u.flags.smartcard_required && <Badge tone="blue">{t("يتطلب بطاقة ذكية", "Smartcard required")}</Badge>}
                  {u.admin_count > 0 && <Badge tone="purple">{t("حساب محمي (adminCount)", "Protected account (adminCount)")}</Badge>}
                </div>
              </div>
              <div>
                <div className="mb-1 text-xs font-semibold text-slate-700">{t("العضوية في المجموعات", "Group membership")} ({u.groups.length})</div>
                <div className="flex flex-wrap gap-1">
                  {u.groups.length ? u.groups.map((g) => (
                    <span key={g} className={`rounded px-1.5 py-0.5 text-xs ${u.privileges.some((p) => p.group === g) ? "bg-red-100 text-red-800" : "bg-slate-200 text-slate-700"}`}>{g}</span>
                  )) : <span className="text-xs text-slate-400">{t("لا توجد", "None")}</span>}
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
        <h1 className="text-2xl font-bold">{t("مستخدمو ومجموعات الدومين", "Domain users & groups")}</h1>
        <p className="text-sm text-slate-500">
          {t("استعلام قراءة فقط عن Active Directory بحساب مصرّح له من الخزنة: كل المستخدمين وصلاحية كل واحد والمجموعات. لا يكتب راصد في الدليل ولا يستخرج كلمات المرور.",
            "Read-only Active Directory query with an authorized vault account: all users, each one's privileges, and the groups. RasedNet never writes to the directory and never extracts passwords.")}
        </p>
      </div>

      <Card title={t("الاتصال بالدومين", "Domain connection")} actions={
        <Button variant="secondary" onClick={() => discovery.refetch()} disabled={discovery.isFetching}>
          <IconRefresh className="h-4 w-4" /> {t("إعادة الاكتشاف", "Re-discover")}
        </Button>
      }>
        {discovery.isLoading ? <Loading /> : (
          <>
            {/* Auto-discovery banner */}
            {discovery.data?.domain ? (
              <div className="mb-3 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm">
                {t("اكتشف راصد الدومين:", "RasedNet discovered the domain:")} <b dir="ltr">{discovery.data.domain}</b>
                {discovery.data.env.USERNAME && <> — {t("المستخدم الحالي", "current user")} <Ltr>{discovery.data.env.USERNAME}</Ltr></>}
                {discovery.data.integrated_available
                  ? <div className="mt-1 text-emerald-800">{t("سيُستخدم حساب المستخدم الحالي تلقائياً (بدون كلمة مرور).", "The current user's account will be used automatically (no password).")}</div>
                  : <div className="mt-1 text-amber-800">{t("الربط التلقائي بالمستخدم الحالي غير متاح (خادم راصد غير منضمّ للدومين) — اختر حساباً بالأسفل.", "Automatic current-user bind is unavailable (the RasedNet server is not domain-joined) — choose an account below.")}</div>}
              </div>
            ) : (
              <div className="mb-3 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
                {t("لم يُكتشف دومين من بيئة الخادم. لو شبكتك فيها Active Directory، اختر وحدة تحكم وحساباً بالأسفل.", "No domain was discovered from the server's environment. If your network has Active Directory, choose a controller and an account below.")}
              </div>
            )}

            {/* Discovered controllers as quick-pick */}
            {(discovery.data?.controllers.length ?? 0) > 0 && (
              <div className="mb-3">
                <div className="mb-1 text-xs font-semibold text-slate-700">{t("وحدات التحكم المكتشفة", "Discovered controllers")}</div>
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
                <span className="mb-0.5 block text-slate-600">{t("طريقة الدخول", "Sign-in method")}</span>
                <select className={inputClass} value={mode} onChange={(e) => setMode(e.target.value as "integrated" | "credential")}>
                  <option value="integrated" disabled={!discovery.data?.integrated_available}>{t("المستخدم الحالي (تلقائي)", "Current user (automatic)")}</option>
                  <option value="credential">{t("حساب من الخزنة", "Account from the vault")}</option>
                </select>
              </label>
              {mode === "credential" && (
                <label className="text-sm">
                  <span className="mb-0.5 block text-slate-600">{t("حساب الدخول", "Credential")}</span>
                  <select className={inputClass} value={credId} onChange={(e) => setCredId(e.target.value ? Number(e.target.value) : "")}>
                    <option value="">{t("اختر حساباً…", "Choose an account…")}</option>
                    {creds.data?.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.username})</option>)}
                  </select>
                </label>
              )}
              <label className="text-sm">
                <span className="mb-0.5 block text-slate-600">{t("وحدة التحكم (IP أو اسم)", "Controller (IP or name)")}</span>
                <input dir="ltr" className={inputClass} placeholder="dc01.example.local" value={host} onChange={(e) => setHost(e.target.value)} />
              </label>
              <label className="text-sm">
                <span className="mb-0.5 block text-slate-600">{t("نطاق البحث (اختياري)", "Search base (optional)")}</span>
                <input dir="ltr" className={inputClass} placeholder="DC=example,DC=local" value={baseDn} onChange={(e) => setBaseDn(e.target.value)} />
              </label>
              <label className="text-sm">
                <span className="mb-0.5 block text-slate-600">{t("ماذا نجلب", "What to fetch")}</span>
                <select className={inputClass} value={scope} onChange={(e) => setScope(e.target.value as Scope)}>
                  <option value="all">{t("المستخدمون والمجموعات والأجهزة", "Users, groups & computers")}</option>
                  <option value="users">{t("المستخدمون فقط", "Users only")}</option>
                  <option value="groups">{t("المجموعات فقط", "Groups only")}</option>
                  <option value="computers">{t("أجهزة الدومين فقط", "Domain computers only")}</option>
                </select>
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={useSsl} onChange={(e) => setUseSsl(e.target.checked)} />
                {t("استخدام LDAPS (منفذ 636)", "Use LDAPS (port 636)")}
              </label>
              <div className="flex items-end gap-2">
                <Button onClick={() => run.mutate(undefined)}
                  disabled={run.isPending || !host.trim() || (mode === "credential" && !credId)}>
                  <IconRefresh className="h-4 w-4" /> {run.isPending ? t("جارٍ الجلب…", "Fetching…") : t("اكتشف مستخدمي الدومين", "Discover domain users")}
                </Button>
                <Button variant="secondary" onClick={() => attack.mutate()}
                  disabled={attack.isPending || !host.trim() || (mode === "credential" && !credId)}
                  title={t("تحليل من يمكنه الوصول لمجموعات الصلاحيات العليا", "Analyse who can reach high-privilege groups")}>
                  {attack.isPending ? t("جارٍ التحليل…", "Analysing…") : t("🛡️ مسارات الهجوم", "🛡️ Attack paths")}
                </Button>
              </div>
            </div>
            {attack.error && <div className="mt-2"><ErrorBox error={errorMessage(attack.error)} /></div>}

            {/* Inline add-account (admins), shown when a credential is needed and none chosen */}
            {mode === "credential" && can("credential:manage") && (
              <div className="mt-2">
                <button type="button" className="text-xs text-cyan-800 underline" onClick={() => setShowAdd(!showAdd)}>
                  {showAdd ? t("إخفاء", "Hide") : t("+ إضافة حساب دومين من هنا", "+ Add a domain account here")}
                </button>
                {showAdd && <AddDomainAccount onAdded={() => { setShowAdd(false); void qc.invalidateQueries({ queryKey: ["dir-creds"] }); }} />}
              </div>
            )}
          </>
        )}
        {run.error && <div className="mt-2"><ErrorBox error={errorMessage(run.error)} /></div>}
      </Card>

      {attack.data && (
        <Card title={t("🛡️ مسارات الهجوم إلى الصلاحيات العليا", "🛡️ Attack paths to high privileges")}>
          <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label={t("حسابات بصلاحيات عليا", "High-privilege accounts")} value={attack.data.privileged_users} tone={attack.data.privileged_users ? "red" : "green"} />
            <Stat label={t("تصعيد عبر عضوية متداخلة", "Escalation via nested membership")} value={attack.data.nested_escalations} tone={attack.data.nested_escalations ? "orange" : "slate"} hint={t("يصعب كشفه يدوياً", "Hard to spot manually")} />
            <Stat label={t("حسابات عالية الخطورة", "High-risk accounts")} value={attack.data.risky.length} tone={attack.data.risky.length ? "red" : "green"} />
            <Stat label={t("مجموعات مستهدَفة", "Target groups")} value={attack.data.targets.length} tone="purple" />
          </div>
          {attack.data.risky.length > 0 && (
            <div className="mb-3 rounded-xl border border-red-200 bg-red-50/40 p-2">
              <div className="mb-1 text-sm font-semibold text-red-800">{t("حسابات عالية الخطورة", "High-risk accounts")}</div>
              {attack.data.risky.map((r, i) => (
                <div key={i} className="text-sm"><Ltr className="font-mono">{r.user}</Ltr> → {r.target}: <span className="text-xs text-red-700">{r.reasons_ar.join(t("، ", ", "))}</span></div>
              ))}
            </div>
          )}
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2 text-start">{t("الحساب", "Account")}</th><th className="p-2">{t("الحالة", "Status")}</th><th className="p-2">{t("النوع", "Type")}</th>
                <th className="p-2">{t("القفزات", "Hops")}</th><th className="p-2 text-start">{t("المسار إلى الصلاحية", "Path to privilege")}</th>
              </tr></thead>
              <tbody>
                {attack.data.paths.map((p, i) => (
                  <tr key={i} className="border-b border-slate-100">
                    <td className="p-2"><Ltr className="font-medium">{p.user}</Ltr> <span className="text-xs text-slate-500">{p.display_name}</span></td>
                    <td className="p-2 text-center">{p.enabled ? <Badge tone="green">{t("مُفعّل", "Enabled")}</Badge> : <Badge tone="red">{t("معطّل!", "Disabled!")}</Badge>}</td>
                    <td className="p-2 text-center">{p.direct ? <Badge tone="amber">{t("مباشر", "Direct")}</Badge> : <Badge tone="orange">{t("متداخل", "Nested")} ({p.hops})</Badge>}</td>
                    <td className="p-2 text-center font-mono">{p.hops}</td>
                    <td className="p-2"><Ltr className="text-xs text-slate-600">{p.path.join(" → ")}</Ltr> <Badge tone="red">{p.label_ar}</Badge></td>
                  </tr>
                ))}
                {attack.data.paths.length === 0 && <tr><td colSpan={5} className="p-3 text-center text-emerald-700">{t("لا توجد حسابات تصل لمجموعات الصلاحيات العليا.", "No accounts reach high-privilege groups.")}</td></tr>}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {result && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
            <Stat label={t("المستخدمون", "Users")} value={result.counts.users} tone="blue" />
            <Stat label={t("مُفعّل", "Enabled")} value={result.counts.enabled_users} tone="green" hint={`${t("معطّل:", "Disabled:")} ${result.counts.disabled_users}`} />
            <Stat label={t("بصلاحيات إدارية", "Privileged")} value={result.counts.privileged_users} tone="red" />
            <Stat label={t("المجموعات", "Groups")} value={result.counts.groups} tone="teal" hint={`${t("مميّزة:", "Privileged:")} ${result.counts.privileged_groups}`} />
            <Stat label={t("أجهزة الدومين", "Domain computers")} value={result.counts.computers} tone="purple" />
            <Stat label={t("كلمة مرور لا تنتهي", "Password never expires")} value={result.counts.password_never_expires} tone="amber" />
          </div>

          <Card title={`${t("الدومين:", "Domain:")} ${result.domain.dns_domain || result.domain.base_dn}`}>
            <p className="mb-3 text-xs text-slate-500"><Ltr>{result.domain.base_dn}</Ltr> — {t("عبر", "via")} <Ltr>{result.domain.host}</Ltr></p>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              {(["users", "groups", "computers"] as const).map((tabKey) => (
                <button key={tabKey} type="button" onClick={() => setTab(tabKey)}
                  className={`rounded-lg px-3 py-1 text-sm ${tab === tabKey ? "bg-cyan-600 text-white" : "bg-slate-100 text-slate-700"}`}>
                  {tabKey === "users" ? `${t("المستخدمون", "Users")} (${result.counts.users})` : tabKey === "groups" ? `${t("المجموعات", "Groups")} (${result.counts.groups})` : `${t("الأجهزة", "Computers")} (${result.counts.computers})`}
                </button>
              ))}
              <input className={`${inputClass} ms-auto max-w-xs`} placeholder={t("بحث…", "Search…")} value={filter} onChange={(e) => setFilter(e.target.value)} />
            </div>

            {tab === "users" && (
              <div className="overflow-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b text-slate-500">
                    <th className="p-2 text-start">{t("الحساب", "Account")}</th><th className="p-2 text-start">{t("الاسم", "Name")}</th><th className="p-2">{t("الحالة", "Status")}</th>
                    <th className="p-2">{t("الصلاحية", "Privilege")}</th><th className="p-2">{t("المجموعات", "Groups")}</th><th className="p-2 text-start">{t("الامتيازات", "Privileges")}</th>
                  </tr></thead>
                  <tbody>{users.map((u) => <UserRow key={u.dn || u.sam} u={u} />)}</tbody>
                </table>
                {!users.length && <p className="p-3 text-sm text-slate-500">{t("لا نتائج.", "No results.")}</p>}
              </div>
            )}

            {tab === "groups" && (
              <div className="overflow-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b text-slate-500">
                    <th className="p-2 text-start">{t("المجموعة", "Group")}</th><th className="p-2">{t("الأعضاء", "Members")}</th><th className="p-2">{t("مميّزة", "Privileged")}</th><th className="p-2 text-start">{t("الوصف", "Description")}</th>
                  </tr></thead>
                  <tbody>
                    {groups.map((g) => (
                      <tr key={g.dn || g.name} className="border-b border-slate-100">
                        <td className="p-2 font-medium">{g.name}{g.label_ar && <span className="ms-1 text-xs text-red-700">({g.label_ar})</span>}</td>
                        <td className="p-2 text-center">{g.member_count}</td>
                        <td className="p-2 text-center">{g.privileged ? <Badge tone="red">{t("نعم", "Yes")}</Badge> : "—"}</td>
                        <td className="p-2 text-xs text-slate-500">{g.description || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!groups.length && <p className="p-3 text-sm text-slate-500">{t("لا نتائج.", "No results.")}</p>}
              </div>
            )}

            {tab === "computers" && (
              <div className="overflow-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b text-slate-500">
                    <th className="p-2 text-start">{t("الجهاز", "Computer")}</th><th className="p-2 text-start">{t("اسم DNS", "DNS name")}</th><th className="p-2 text-start">{t("نظام التشغيل", "Operating system")}</th><th className="p-2">{t("الحالة", "Status")}</th>
                  </tr></thead>
                  <tbody>
                    {computers.map((c) => (
                      <tr key={c.dn || c.name} className="border-b border-slate-100">
                        <td className="p-2 font-medium">{c.name}</td>
                        <td className="p-2"><Ltr className="text-xs">{c.dns || "—"}</Ltr></td>
                        <td className="p-2">{c.os || "—"} <span className="text-xs text-slate-400">{c.os_version}</span></td>
                        <td className="p-2 text-center">{c.enabled ? <Badge tone="green">{t("مُفعّل", "Enabled")}</Badge> : <Badge tone="slate">{t("معطّل", "Disabled")}</Badge>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!computers.length && <p className="p-3 text-sm text-slate-500">{t("لا نتائج.", "No results.")}</p>}
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
