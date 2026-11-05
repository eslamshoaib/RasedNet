import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, ProgressBar, STATUS_TONE } from "../components/ui";
import { formatDate, parsePorts, progress, splitList } from "../format";
import { JOB_STATUS, label, TRIGGERS } from "../labels";
import type { Job, Page, Profile, Scope } from "../types";
import { NetworkCandidates } from "./NetworkCandidates";

function NewScopeForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState("");
  const [description, setDescription] = useState("");
  const [excluded, setExcluded] = useState("");
  const [ports, setPorts] = useState("");
  const [sensitive, setSensitive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: (body: object) => api<Scope>("/api/scopes", { method: "POST", body }),
    onSuccess: () => {
      setName(""); setCidr(""); setDescription(""); setExcluded(""); setPorts(""); setSensitive(false);
      onDone();
    },
    onError: (e) => setError(errorMessage(e)),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const excludedPorts = ports.trim() ? parsePorts(ports) : [];
    if (excludedPorts === null) return setError("أرقام المنافذ المستثناة غير صالحة (1–65535)");
    create.mutate({ name, cidr, description, excluded_hosts: splitList(excluded), excluded_ports: excludedPorts, is_sensitive: sensitive });
  }

  return (
    <form onSubmit={submit} className="grid gap-3 md:grid-cols-2">
      <Field label="اسم النطاق"><input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} /></Field>
      <Field label="نطاق الشبكة (CIDR)" hint="مثال: 192.168.1.0/24 — العناوين الداخلية فقط">
        <input className={inputClass} dir="ltr" value={cidr} onChange={(e) => setCidr(e.target.value)} required placeholder="192.168.1.0/24" />
      </Field>
      <Field label="عناوين مستثناة من الفحص" hint="عناوين أو نطاقات مفصولة بفاصلة أو سطر جديد">
        <textarea className={inputClass} dir="ltr" rows={2} value={excluded} onChange={(e) => setExcluded(e.target.value)} />
      </Field>
      <Field label="منافذ مستثناة" hint="مثال: 9100, 515">
        <input className={inputClass} dir="ltr" value={ports} onChange={(e) => setPorts(e.target.value)} />
      </Field>
      <Field label="الوصف"><input className={inputClass} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={2000} /></Field>
      <label className="flex items-center gap-2 self-end pb-2 text-sm">
        <input type="checkbox" checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} />
        شريحة حساسة (يُسمح عليها بالاكتشاف الآمن فقط)
      </label>
      <div className="md:col-span-2"><ErrorBox error={error} /></div>
      <div className="md:col-span-2 flex items-center gap-3">
        <Button type="submit" disabled={create.isPending}>إضافة النطاق</Button>
        <span className="text-xs text-slate-500">لن يمكن الفحص قبل اعتماد النطاق من مسؤول النظام.</span>
      </div>
    </form>
  );
}

function ScopeRow({ scope, profiles, refresh }: { scope: Scope; profiles: Profile[]; refresh: () => void }) {
  const { can } = useAuth();
  const [chosen, setProfileId] = useState<number | null>(null);
  // Profiles may load after this row mounts, so the default is derived on every render.
  const preferred = profiles.find((p) => (scope.is_sensitive ? p.code === "safe_discovery" : p.code === "standard_inventory"));
  const profileId: number | null = chosen ?? preferred?.id ?? profiles[0]?.id ?? null;
  const [error, setError] = useState<string | null>(null);
  const action = useMutation({
    mutationFn: (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => { setError(null); refresh(); },
    onError: (e) => setError(errorMessage(e)),
  });

  const approve = () => {
    const ok = window.confirm(`اعتماد النطاق ${scope.cidr}؟\nبالاعتماد تؤكد أن المؤسسة تملك هذا النطاق أو تديره وأن فحصه مصرح به.`);
    if (ok) action.mutate(() => api(`/api/scopes/${scope.id}/approve`, { method: "POST", body: { confirm: true } }));
  };

  return (
    <tr className="border-b border-slate-100 align-top">
      <td className="px-3 py-2 font-medium">
        {scope.name}
        {scope.description && <div className="text-xs text-slate-500">{scope.description}</div>}
      </td>
      <td className="px-3 py-2"><Ltr>{scope.cidr}</Ltr>
        {scope.excluded_hosts.length > 0 && <div className="text-xs text-slate-500">مستثنى: <Ltr>{scope.excluded_hosts.join(", ")}</Ltr></div>}
        {scope.excluded_ports.length > 0 && <div className="text-xs text-slate-500">منافذ مستثناة: <Ltr>{scope.excluded_ports.join(", ")}</Ltr></div>}
      </td>
      <td className="px-3 py-2">{scope.target_count}</td>
      <td className="px-3 py-2 space-y-1">
        {scope.is_approved ? <Badge tone="green">معتمد</Badge> : <Badge tone="amber">بانتظار الاعتماد</Badge>}
        {scope.is_sensitive && <div><Badge tone="purple">حساس</Badge></div>}
        {scope.has_active_job && <div><Badge tone="blue">فحص جارٍ</Badge></div>}
        {scope.schedule_interval_minutes && (
          <div className="text-xs text-slate-600">
            <Badge tone="teal">مجدول: {SCHEDULES[String(scope.schedule_interval_minutes)] ?? `كل ${scope.schedule_interval_minutes} دقيقة`}</Badge>
            <div>التالي: {formatDate(scope.schedule_next_run_at)}</div>
            {scope.schedule_last_error && <div className="text-red-700">آخر محاولة: {scope.schedule_last_error}</div>}
          </div>
        )}
      </td>
      <td className="px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          {can("scan:run") && scope.is_approved && (
            <>
              <select className={`${inputClass} w-auto`} value={profileId ?? ""} onChange={(e) => setProfileId(Number(e.target.value))} aria-label="ملف الفحص">
                {profiles.map((p) => <option key={p.id} value={p.id}>{p.name_ar}</option>)}
              </select>
              <Button
                disabled={scope.has_active_job || profileId === null || action.isPending}
                onClick={() => action.mutate(() => api<Job>("/api/scans", { method: "POST", body: { scope_id: scope.id, profile_id: profileId } }))}
              >
                بدء الفحص
              </Button>
            </>
          )}
          {can("scan:run") && scope.is_approved && (
            <select className={`${inputClass} w-auto`} aria-label="جدولة الفحص" value={String(scope.schedule_interval_minutes ?? "")}
              onChange={(e) => action.mutate(() => api(`/api/scopes/${scope.id}/schedule`, { method: "PUT",
                body: e.target.value ? { profile_id: profileId, interval_minutes: Number(e.target.value) } : { interval_minutes: null } }))}>
              <option value="">بدون جدولة</option>
              {Object.entries(SCHEDULES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          )}
          {can("scope:approve") && !scope.is_approved && <Button variant="secondary" onClick={approve} disabled={action.isPending}>اعتماد</Button>}
          {can("scope:approve") && scope.is_approved && (
            <Button variant="ghost" disabled={action.isPending} onClick={() => action.mutate(() => api(`/api/scopes/${scope.id}/revoke`, { method: "POST" }))}>سحب الاعتماد</Button>
          )}
          {can("scope:manage") && (
            <Button
              variant="ghost"
              disabled={scope.has_active_job || action.isPending}
              onClick={() => window.confirm(`حذف النطاق «${scope.name}»؟ سيبقى سجل فحوصه محفوظاً.`) && action.mutate(() => api(`/api/scopes/${scope.id}`, { method: "DELETE" }))}
            >
              حذف
            </Button>
          )}
        </div>
        <ErrorBox error={error} />
      </td>
    </tr>
  );
}

const SCHEDULES: Record<string, string> = { "60": "كل ساعة", "360": "كل 6 ساعات", "720": "كل 12 ساعة", "1440": "يومياً", "10080": "أسبوعياً" };

export function JobsList({ jobs, onChange }: { jobs: Job[]; onChange: () => void }) {
  const { can } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const cancel = useMutation({ mutationFn: (id: number) => api(`/api/scans/${id}/cancel`, { method: "POST" }), onSettled: onChange });
  const act = useMutation({
    mutationFn: (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => { setError(null); onChange(); },
    onError: (e) => setError(errorMessage(e)),
  });
  if (!jobs.length) return <p className="text-sm text-slate-500">لم يُنفذ أي فحص بعد.</p>;
  return (
    <div className="space-y-3">
      <ErrorBox error={error} />
      {jobs.map((job) => {
        const active = job.status === "queued" || job.status === "running";
        const resumable = ["interrupted", "cancelled", "failed"].includes(job.status) && job.processed_hosts < job.total_hosts;
        return (
          <div key={job.id} className="rounded-lg border border-slate-200 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Link to={`/scans/${job.id}`} className="font-semibold text-cyan-800 underline">فحص #{job.id}</Link>
                <span>{job.scope_name}</span>
                <Ltr className="text-xs text-slate-500">{job.scope_cidr}</Ltr>
                <Badge tone={STATUS_TONE[job.status]}>{label(JOB_STATUS, job.status)}</Badge>
                <span className="text-xs text-slate-500">{job.profile_name_ar}</span>
                {job.trigger !== "manual" && <Badge tone="purple">{label(TRIGGERS, job.trigger)}</Badge>}
                {job.resumed_from_id && <span className="text-xs text-slate-500">استكمال للفحص #{job.resumed_from_id} من العنوان رقم {job.resume_offset + 1}</span>}
              </div>
              <div className="flex flex-wrap gap-1">
                {active && can("scan:run") && (
                  <Button variant="secondary" disabled={job.cancel_requested || cancel.isPending} onClick={() => cancel.mutate(job.id)}>
                    {job.cancel_requested ? "جارٍ الإيقاف…" : "إيقاف"}
                  </Button>
                )}
                {!active && resumable && can("scan:run") && (
                  <Button disabled={act.isPending} onClick={() => act.mutate(() => api(`/api/scans/${job.id}/rerun`, { method: "POST", body: { mode: "resume" } }))}>استكمال من حيث توقف</Button>
                )}
                {!active && can("scan:run") && (
                  <Button variant="secondary" disabled={act.isPending} onClick={() => act.mutate(() => api(`/api/scans/${job.id}/rerun`, { method: "POST", body: { mode: "restart" } }))}>إعادة الفحص</Button>
                )}
                {!active && can("data:manage") && (
                  <Button variant="ghost" disabled={act.isPending} onClick={() => window.confirm(`حذف الفحص #${job.id} من السجل؟`) && act.mutate(() => api(`/api/scans/${job.id}`, { method: "DELETE" }))}>حذف</Button>
                )}
              </div>
            </div>
            <div className="mt-2"><ProgressBar value={progress(job.processed_hosts, job.total_hosts)} /></div>
            <div className="mt-1 flex flex-wrap gap-4 text-xs text-slate-600">
              <span>تم فحص {job.processed_hosts} من {job.total_hosts} عنوان</span>
              <span>أجهزة مستجيبة: {job.alive_hosts}</span>
              <span>خدمات مفتوحة: {job.open_services}</span>
              <span>بدأ: {formatDate(job.started_at)}</span>
              {job.finished_at && <span>انتهى: {formatDate(job.finished_at)}</span>}
            </div>
            {job.error_message && <div className="mt-2"><ErrorBox error={job.error_message} /></div>}
          </div>
        );
      })}
    </div>
  );
}

interface Reachability {
  ip: string; in_scope: boolean; reachable: boolean; verdict: string; reason_ar: string;
  icmp: { alive: boolean; ttl: number | null }; tcp: Record<string, string>; udp: Record<string, string>;
  traceroute: { ttl: number; ip: string | null; rtt_ms: number | null }[];
  reached_target: boolean; last_responder: string | null;
}

function ReachabilityDiagnostic() {
  const [ip, setIp] = useState("");
  const check = useMutation({ mutationFn: () => api<Reachability>("/api/diagnostics/reachability", { method: "POST", body: { ip: ip.trim() } }) });
  const r = check.data;
  const tone = (v: string): "green" | "amber" | "red" | "slate" =>
    v === "reachable" ? "green" : v === "reachable_out_of_scope" ? "amber" : v === "silent" ? "amber" : "red";
  return (
    <Card title="لماذا لا يظهر جهاز؟ (تشخيص الاكتشاف)">
      <p className="mb-2 text-sm text-slate-500">اكتب عنوان IP لجهاز متوقع ولا يظهر؛ يفحص راصد قابلية الوصول إليه (ICMP/TCP/UDP + تتبّع المسار) ويخبرك بالسبب والحل.</p>
      <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); check.mutate(); }}>
        <input dir="ltr" className={`${inputClass} w-48`} placeholder="10.0.0.5" value={ip} onChange={(e) => setIp(e.target.value)} />
        <Button type="submit" disabled={!ip.trim() || check.isPending}>{check.isPending ? "جارٍ الفحص…" : "شخّص"}</Button>
      </form>
      {check.error && <div className="mt-2"><ErrorBox error={errorMessage(check.error)} /></div>}
      {r && (
        <div className="mt-3 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={tone(r.verdict)}>{r.reachable ? "قابل للوصول" : "غير قابل للوصول"}</Badge>
            {!r.in_scope && <Badge tone="amber">خارج النطاقات المعتمدة</Badge>}
            {r.icmp.alive && <Badge tone="green">يرد على ICMP</Badge>}
          </div>
          <p className="rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-700">{r.reason_ar}</p>
          <div className="grid gap-2 text-xs text-slate-600 md:grid-cols-2">
            <div>TCP: {Object.entries(r.tcp).map(([p, s]) => `${p}:${s}`).join("، ")}</div>
            <div>UDP: {Object.entries(r.udp).map(([p, s]) => `${p}:${s}`).join("، ")}</div>
          </div>
          {r.traceroute.length > 0 && (
            <div className="text-xs text-slate-500">
              المسار: {r.traceroute.map((h) => (h.ip ? h.ip : "*")).join(" → ")}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

export function DiscoveryPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const scopes = useQuery({ queryKey: ["scopes"], queryFn: () => api<Scope[]>("/api/scopes") });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api<Profile[]>("/api/profiles"), enabled: can("scan:read") });
  const jobs = useQuery({
    queryKey: ["jobs", "recent"],
    queryFn: () => api<Page<Job>>("/api/scans", { query: { page_size: 10 } }),
    enabled: can("scan:read"),
    refetchInterval: (q) => (q.state.data?.items.some((j) => j.status === "queued" || j.status === "running") ? 2000 : 15000),
  });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["scopes"] });
    void qc.invalidateQueries({ queryKey: ["jobs"] });
    void qc.invalidateQueries({ queryKey: ["dashboard"] });
  };

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-bold">اكتشاف الشبكة</h1>
      {can("scope:manage") && <NetworkCandidates profiles={profiles.data ?? []} onChanged={refresh} />}
      <Card title="نطاقات الفحص المعتمدة">
        {scopes.isLoading ? <Loading /> : scopes.error ? <ErrorBox error={scopes.error} /> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b border-slate-200 bg-slate-50 text-start">
                <th className="px-3 py-2 text-start">الاسم</th><th className="px-3 py-2 text-start">النطاق</th>
                <th className="px-3 py-2 text-start">عدد العناوين</th><th className="px-3 py-2 text-start">الحالة</th><th className="px-3 py-2 text-start">الإجراءات</th>
              </tr></thead>
              <tbody>
                {(scopes.data ?? []).map((s) => <ScopeRow key={s.id} scope={s} profiles={profiles.data ?? []} refresh={refresh} />)}
              </tbody>
            </table>
            {scopes.data?.length === 0 && <p className="py-4 text-center text-sm text-slate-500">لا توجد نطاقات. أضف نطاقاً ثم اطلب اعتماده.</p>}
          </div>
        )}
      </Card>
      {can("scope:manage") && <Card title="إضافة نطاق يدوياً"><NewScopeForm onDone={refresh} /></Card>}
      <ReachabilityDiagnostic />
      {can("scan:read") && (
        <Card title="أحدث مهام الفحص" actions={<Link className="text-sm text-cyan-800 underline" to="/scans">السجل الكامل</Link>}>
          {jobs.isLoading ? <Loading /> : <JobsList jobs={jobs.data?.items ?? []} onChange={refresh} />}
        </Card>
      )}
      {profiles.data && (
        <Card title="ملفات الفحص المتاحة">
          <div className="grid gap-3 md:grid-cols-2">
            {profiles.data.map((p) => (
              <div key={p.id} className="rounded-lg border border-slate-200 p-3 text-sm">
                <div className="font-semibold">{p.name_ar}</div>
                <p className="mt-1 text-slate-600">{p.description_ar}</p>
                <ul className="mt-2 space-y-0.5 text-xs text-slate-500">
                  <li>منافذ الاكتشاف: <Ltr>{p.discovery_ports.join(", ")}</Ltr></li>
                  <li>منافذ فحص الخدمات: {p.tcp_ports.length ? `${p.tcp_ports.length} منفذاً` : "لا يوجد"}</li>
                  <li>الحد الأقصى: {p.rate_per_second} اتصال/ثانية، {p.max_concurrency} اتصالاً متزامناً، {p.per_host_concurrency} لكل جهاز</li>
                  <li>قراءة توقيعات الخدمات: {p.grab_banners ? "نعم" : "لا"} — مهلة الاتصال: {p.connect_timeout_ms} ms</li>
                </ul>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-500">
            حدود الاكتشاف: عناوين MAC تظهر فقط للأجهزة في نفس الشريحة المحلية لخادم الفحص. الأجهزة التي تحجب ICMP وجميع منافذ الاكتشاف قد لا تظهر.
            لا يتضمن أي ملف فحصاً تدخلياً أو تخميناً لكلمات المرور.
          </p>
        </Card>
      )}
    </div>
  );
}
