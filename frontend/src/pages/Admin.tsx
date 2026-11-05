import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, Pager } from "../components/ui";
import { formatDate } from "../format";
import { AUDIT_ACTIONS, label } from "../labels";
import type { AuditEntry, Page, Role, User } from "../types";

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
      <Field label="اسم المستخدم" hint="أحرف إنجليزية وأرقام و . _ -">
        <input className={inputClass} dir="ltr" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required pattern="[A-Za-z0-9_.\-]{3,64}" />
      </Field>
      <Field label="الاسم الظاهر"><input className={inputClass} value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} required /></Field>
      <Field label="كلمة المرور" hint="12 حرفاً على الأقل وثلاثة أنواع من الأحرف">
        <input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
      </Field>
      <Field label="الدور">
        <select className={inputClass} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
          {roles.map((r) => <option key={r.id} value={r.name}>{r.name_ar}</option>)}
        </select>
      </Field>
      <div className="md:col-span-4"><ErrorBox error={error} /></div>
      <div><Button type="submit" disabled={create.isPending}>إنشاء المستخدم</Button></div>
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
    const password = window.prompt(`كلمة مرور جديدة للمستخدم ${u.username} (12 حرفاً على الأقل):`);
    if (password) update.mutate({ id: u.id, body: { password } });
  };

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">إدارة المستخدمين والصلاحيات</h1>
      <Card title="المستخدمون">
        <ErrorBox error={error} />
        {users.isLoading ? <Loading /> : users.error ? <ErrorBox error={users.error} /> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b bg-slate-50">
                <th className="px-3 py-2 text-start">المستخدم</th><th className="px-3 py-2 text-start">الدور</th><th className="px-3 py-2 text-start">الحالة</th>
                <th className="px-3 py-2 text-start">آخر دخول</th><th className="px-3 py-2 text-start">الإجراءات</th>
              </tr></thead>
              <tbody>
                {users.data?.map((u) => {
                  const locked = !!u.locked_until && new Date(u.locked_until) > new Date();
                  const self = u.id === me?.user.id;
                  return (
                    <tr key={u.id} className="border-b border-slate-100">
                      <td className="px-3 py-2">{u.display_name} <Ltr className="text-xs text-slate-500">{u.username}</Ltr></td>
                      <td className="px-3 py-2">
                        <select className={`${inputClass} w-auto`} value={u.role.name} disabled={self || update.isPending} aria-label="الدور"
                          onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}>
                          {roles.data?.map((r) => <option key={r.id} value={r.name}>{r.name_ar}</option>)}
                        </select>
                      </td>
                      <td className="px-3 py-2 space-x-1">
                        {u.is_active ? <Badge tone="green">نشط</Badge> : <Badge tone="slate">معطل</Badge>}
                        {locked && <Badge tone="red">مقفل مؤقتاً</Badge>}
                      </td>
                      <td className="px-3 py-2">{formatDate(u.last_login_at)}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {!self && <Button variant="secondary" disabled={update.isPending} onClick={() => update.mutate({ id: u.id, body: { is_active: !u.is_active } })}>{u.is_active ? "تعطيل" : "تفعيل"}</Button>}
                          {locked && <Button variant="secondary" disabled={update.isPending} onClick={() => update.mutate({ id: u.id, body: { unlock: true } })}>فك القفل</Button>}
                          <Button variant="ghost" disabled={update.isPending} onClick={() => resetPassword(u)}>إعادة تعيين كلمة المرور</Button>
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
          <Card title="إضافة مستخدم"><CreateUser roles={roles.data} onDone={() => void qc.invalidateQueries({ queryKey: ["users"] })} /></Card>
          <Card title="الأدوار">
            <ul className="space-y-1 text-sm">{roles.data.map((r) => <li key={r.id}><span className="font-semibold">{r.name_ar}:</span> {r.description_ar}</li>)}</ul>
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
      <h1 className="text-2xl font-bold">سجل التدقيق</h1>
      <Card>
        <div className="mb-3 grid gap-2 md:grid-cols-3">
          <select className={inputClass} value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} aria-label="العملية">
            <option value="">كل العمليات</option>
            {Object.entries(AUDIT_ACTIONS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select className={inputClass} value={success} onChange={(e) => { setSuccess(e.target.value); setPage(1); }} aria-label="النتيجة">
            <option value="">كل النتائج</option>
            <option value="true">ناجحة</option>
            <option value="false">مرفوضة / فاشلة</option>
          </select>
        </div>
        {query.isLoading ? <Loading /> : query.error ? <ErrorBox error={query.error} /> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b bg-slate-50">
                <th className="px-3 py-2 text-start">الوقت</th><th className="px-3 py-2 text-start">المستخدم</th><th className="px-3 py-2 text-start">العملية</th>
                <th className="px-3 py-2 text-start">الهدف</th><th className="px-3 py-2 text-start">النتيجة</th><th className="px-3 py-2 text-start">العنوان</th><th className="px-3 py-2 text-start">التفاصيل</th>
              </tr></thead>
              <tbody>
                {query.data?.items.map((e) => (
                  <tr key={e.id} className="border-b border-slate-100 align-top">
                    <td className="px-3 py-2 whitespace-nowrap">{formatDate(e.created_at)}</td>
                    <td className="px-3 py-2"><Ltr>{e.actor_username ?? "—"}</Ltr></td>
                    <td className="px-3 py-2">{label(AUDIT_ACTIONS, e.action)}</td>
                    <td className="px-3 py-2"><Ltr>{e.target_type ? `${e.target_type}#${e.target_id}` : "—"}</Ltr></td>
                    <td className="px-3 py-2">{e.success ? <Badge tone="green">نجاح</Badge> : <Badge tone="red">رفض</Badge>}</td>
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
    if (next !== confirm) return setError("كلمتا المرور الجديدتان غير متطابقتين");
    change.mutate();
  };
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">حسابي</h1>
      <Card title="بيانات الحساب">
        <p className="text-sm">{me?.user.display_name} — <Ltr>{me?.user.username}</Ltr> — {me?.user.role.name_ar}</p>
      </Card>
      <Card title="تغيير كلمة المرور">
        <form onSubmit={submit} className="grid max-w-md gap-3">
          <Field label="كلمة المرور الحالية"><input className={inputClass} dir="ltr" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required /></Field>
          <Field label="كلمة المرور الجديدة"><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required /></Field>
          <Field label="تأكيد كلمة المرور الجديدة"><input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required /></Field>
          <ErrorBox error={error} />
          {change.isSuccess && <p className="text-sm text-emerald-700">تم تغيير كلمة المرور وإنهاء جلساتك الأخرى.</p>}
          <div><Button type="submit" disabled={change.isPending}>تغيير كلمة المرور</Button></div>
        </form>
      </Card>
    </div>
  );
}
