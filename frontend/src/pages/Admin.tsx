import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, Pager } from "../components/ui";
import { formatDate } from "../format";
import { getLang, t } from "../i18n";
import { AUDIT_ACTIONS, label } from "../labels";
import type { AuditEntry, Page, Role, User } from "../types";

const ROLE_EN: Record<string, string> = { admin: "Administrator", operator: "Operator", auditor: "Auditor" };
const roleName = (r: Pick<Role, "name" | "name_ar">): string => (getLang() === "en" ? (ROLE_EN[r.name] ?? r.name_ar) : r.name_ar);

function CreateUser({ roles, onDone }: { roles: Role[]; onDone: () => void }) {
  const [form, setForm] = useState({ username: "", display_name: "", password: "", role: "operator" });
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => api<User>("/api/users", { method: "POST", body: form }),
    onSuccess: () => { setForm({ username: "", display_name: "", password: "", role: "operator" }); setError(null); onDone(); },
    onError: (e) => setError(errorMessage(e)),
  });
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  return (
    <form onSubmit={submit} className="grid gap-3 md:grid-cols-4">
      <Field label={t("اسم المستخدم", "Username")} hint={t("أحرف إنجليزية وأرقام و . _ -", "Latin letters, digits and . _ -")}>
        <input className={inputClass} dir="ltr" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required pattern="[A-Za-z0-9_.\-]{3,64}" />
      </Field>
      <Field label={t("الاسم الظاهر", "Display name")}><input className={inputClass} value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} required /></Field>
      <Field label={t("كلمة المرور", "Password")} hint={t("12 حرفاً على الأقل وثلاثة أنواع من الأحرف", "At least 12 characters and three character types")}>
        <input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
      </Field>
      <Field label={t("الدور", "Role")}>
        <select className={inputClass} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
          {roles.map((r) => <option key={r.id} value={r.name}>{roleName(r)}</option>)}
        </select>
      </Field>
      <div className="md:col-span-4"><ErrorBox error={error} /></div>
      <div><Button type="submit" disabled={create.isPending}>{t("إنشاء المستخدم", "Create user")}</Button></div>
    </form>
  );
}

export function UsersPage() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("/api/users") });
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api<Role[]>("/api/roles") });
  const [error, setError] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: object }) => api<User>(`/api/users/${id}`, { method: "PATCH", body }),
    onSuccess: () => { setError(null); void qc.invalidateQueries({ queryKey: ["users"] }); },
    onError: (e) => setError(errorMessage(e)),
  });
  const resetPassword = (u: User) => {
    const password = window.prompt(getLang() === "en" ? `New password for user ${u.username} (at least 12 characters):` : `كلمة مرور جديدة للمستخدم ${u.username} (12 حرفاً على الأقل):`);
    if (password) update.mutate({ id: u.id, body: { password } });
  };

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">{t("إدارة المستخدمين والصلاحيات", "Users & permissions")}</h1>
      <Card title={t("المستخدمون", "Users")}>
        <ErrorBox error={error} />
        {users.isLoading ? <Loading /> : users.error ? <ErrorBox error={users.error} /> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b bg-slate-50">
                <th className="px-3 py-2 text-start">{t("المستخدم", "User")}</th><th className="px-3 py-2 text-start">{t("الدور", "Role")}</th><th className="px-3 py-2 text-start">{t("الحالة", "Status")}</th>
                <th className="px-3 py-2 text-start">{t("آخر دخول", "Last sign-in")}</th><th className="px-3 py-2 text-start">{t("الإجراءات", "Actions")}</th>
              </tr></thead>
              <tbody>
                {users.data?.map((u) => {
                  const locked = !!u.locked_until && new Date(u.locked_until) > new Date();
                  const self = u.id === me?.user.id;
                  return (
                    <tr key={u.id} className="border-b border-slate-100">
                      <td className="px-3 py-2">{u.display_name} <Ltr className="text-xs text-slate-500">{u.username}</Ltr></td>
                      <td className="px-3 py-2">
                        <select className={`${inputClass} w-auto`} value={u.role.name} disabled={self || update.isPending} aria-label={t("الدور", "Role")}
                          onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}>
                          {roles.data?.map((r) => <option key={r.id} value={r.name}>{roleName(r)}</option>)}
                        </select>
                      </td>
                      <td className="px-3 py-2 space-x-1">
                        {u.is_active ? <Badge tone="green">{t("نشط", "Active")}</Badge> : <Badge tone="slate">{t("معطل", "Disabled")}</Badge>}
                        {locked && <Badge tone="red">{t("مقفل مؤقتاً", "Temporarily locked")}</Badge>}
                      </td>
                      <td className="px-3 py-2">{formatDate(u.last_login_at)}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {!self && <Button variant="secondary" disabled={update.isPending} onClick={() => update.mutate({ id: u.id, body: { is_active: !u.is_active } })}>{u.is_active ? t("تعطيل", "Disable") : t("تفعيل", "Enable")}</Button>}
                          {locked && <Button variant="secondary" disabled={update.isPending} onClick={() => update.mutate({ id: u.id, body: { unlock: true } })}>{t("فك القفل", "Unlock")}</Button>}
                          <Button variant="ghost" disabled={update.isPending} onClick={() => resetPassword(u)}>{t("إعادة تعيين كلمة المرور", "Reset password")}</Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {roles.data && (
        <>
          <Card title={t("إضافة مستخدم", "Add user")}><CreateUser roles={roles.data} onDone={() => void qc.invalidateQueries({ queryKey: ["users"] })} /></Card>
          <Card title={t("الأدوار", "Roles")}>
            <ul className="space-y-1 text-sm">{roles.data.map((r) => <li key={r.id}><span className="font-semibold">{roleName(r)}:</span> {r.description_ar}</li>)}</ul>
          </Card>
        </>
      )}
    </div>
  );
}

export function AuditPage() {
  const [page, setPage] = useState(1);
  const [action, setAction] = useState("");
  const [success, setSuccess] = useState("");
  const query = useQuery({
    queryKey: ["audit", page, action, success],
    queryFn: () => api<Page<AuditEntry>>("/api/audit", { query: { page, page_size: 50, action, success } }),
    placeholderData: keepPreviousData,
  });
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">{t("سجل التدقيق", "Audit log")}</h1>
      <Card>
        <div className="mb-3 grid gap-2 md:grid-cols-3">
          <select className={inputClass} value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} aria-label={t("العملية", "Action")}>
            <option value="">{t("كل العمليات", "All actions")}</option>
            {Object.keys(AUDIT_ACTIONS).map((k) => <option key={k} value={k}>{label(AUDIT_ACTIONS, k)}</option>)}
          </select>
          <select className={inputClass} value={success} onChange={(e) => { setSuccess(e.target.value); setPage(1); }} aria-label={t("النتيجة", "Result")}>
            <option value="">{t("كل النتائج", "All results")}</option>
            <option value="true">{t("ناجحة", "Successful")}</option>
            <option value="false">{t("مرفوضة / فاشلة", "Denied / failed")}</option>
          </select>
        </div>
        {query.isLoading ? <Loading /> : query.error ? <ErrorBox error={query.error} /> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b bg-slate-50">
                <th className="px-3 py-2 text-start">{t("الوقت", "Time")}</th><th className="px-3 py-2 text-start">{t("المستخدم", "User")}</th><th className="px-3 py-2 text-start">{t("العملية", "Action")}</th>
                <th className="px-3 py-2 text-start">{t("الهدف", "Target")}</th><th className="px-3 py-2 text-start">{t("النتيجة", "Result")}</th><th className="px-3 py-2 text-start">{t("العنوان", "IP")}</th><th className="px-3 py-2 text-start">{t("التفاصيل", "Details")}</th>
              </tr></thead>
              <tbody>
                {query.data?.items.map((e) => (
                  <tr key={e.id} className="border-b border-slate-100 align-top">
                    <td className="px-3 py-2 whitespace-nowrap">{formatDate(e.created_at)}</td>
                    <td className="px-3 py-2"><Ltr>{e.actor_username ?? "—"}</Ltr></td>
                    <td className="px-3 py-2">{label(AUDIT_ACTIONS, e.action)}</td>
                    <td className="px-3 py-2"><Ltr>{e.target_type ? `${e.target_type}#${e.target_id}` : "—"}</Ltr></td>
                    <td className="px-3 py-2">{e.success ? <Badge tone="green">{t("نجاح", "Success")}</Badge> : <Badge tone="red">{t("رفض", "Denied")}</Badge>}</td>
                    <td className="px-3 py-2"><Ltr>{e.client_ip ?? "—"}</Ltr></td>
                    <td className="px-3 py-2 max-w-sm"><Ltr className="block break-all text-xs text-slate-500">{Object.keys(e.details).length ? JSON.stringify(e.details) : ""}</Ltr></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {query.data && <Pager page={page} pageSize={query.data.page_size} total={query.data.total} onPage={setPage} />}
      </Card>
    </div>
  );
}

export function AccountPage() {
  const { me } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const change = useMutation({
    mutationFn: () => api("/api/auth/change-password", { method: "POST", body: { current_password: current, new_password: next } }),
    onSuccess: () => { setCurrent(""); setNext(""); setConfirm(""); setError(null); },
    onError: (e) => setError(errorMessage(e)),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (next !== confirm) return setError(t("كلمتا المرور الجديدتان غير متطابقتين", "The new passwords do not match"));
    change.mutate();
  };
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">{t("حسابي", "My account")}</h1>
      <Card title={t("بيانات الحساب", "Account details")}>
        <p className="text-sm">{me?.user.display_name} — <Ltr>{me?.user.username}</Ltr> — {me ? roleName(me.user.role) : ""}</p>
      </Card>
      <Card title={t("تغيير كلمة المرور", "Change password")}>
        <form onSubmit={submit} className="grid max-w-md gap-3">
          <Field label={t("كلمة المرور الحالية", "Current password")}><input className={inputClass} dir="ltr" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required /></Field>
          <Field label={t("كلمة المرور الجديدة", "New password")}><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required /></Field>
          <Field label={t("تأكيد كلمة المرور الجديدة", "Confirm new password")}><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required /></Field>
          <ErrorBox error={error} />
          {change.isSuccess && <p className="text-sm text-emerald-700">{t("تم تغيير كلمة المرور وإنهاء جلساتك الأخرى.", "Password changed and your other sessions were ended.")}</p>}
          <div><Button type="submit" disabled={change.isPending}>{t("تغيير كلمة المرور", "Change password")}</Button></div>
        </form>
      </Card>
    </div>
  );
}
