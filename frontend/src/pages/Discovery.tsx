import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, ProgressBar, STATUS_TONE } from "../components/ui";
import { formatDate, parsePorts, progress, splitList } from "../format";
import { getLang, t } from "../i18n";
import { JOB_STATUS, label, TRIGGERS } from "../labels";
import type { Job, Page, Profile, Scope } from "../types";
import { NetworkCandidates } from "./NetworkCandidates";

const schedules = (): Record<string, string> => ({
  "60": t("كل ساعة", "Hourly"), "360": t("كل 6 ساعات", "Every 6 hours"), "720": t("كل 12 ساعة", "Every 12 hours"),
  "1440": t("يومياً", "Daily"), "10080": t("أسبوعياً", "Weekly"),
});

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
    if (excludedPorts === null) return setError(t("أرقام المنافذ المستثناة غير صالحة (1–65535)", "Invalid excluded port numbers (1–65535)"));
    create.mutate({ name, cidr, description, excluded_hosts: splitList(excluded), excluded_ports: excludedPorts, is_sensitive: sensitive });
  }

  return (
    <form onSubmit={submit} className="grid gap-3 md:grid-cols-2">
      <Field label={t("اسم النطاق", "Scope name")}><input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} /></Field>
      <Field label={t("نطاق الشبكة (CIDR)", "Network range (CIDR)")} hint={t("مثال: 192.168.1.0/24 — العناوين الداخلية فقط", "e.g. 192.168.1.0/24 — internal addresses only")}>
        <input className={inputClass} dir="ltr" value={cidr} onChange={(e) => setCidr(e.target.value)} required placeholder="192.168.1.0/24" />
      </Field>
      <Field label={t("عناوين مستثناة من الفحص", "Addresses excluded from the scan")} hint={t("عناوين أو نطاقات مفصولة بفاصلة أو سطر جديد", "Addresses or ranges separated by comma or newline")}>
        <textarea className={inputClass} dir="ltr" rows={2} value={excluded} onChange={(e) => setExcluded(e.target.value)} />
      </Field>
      <Field label={t("منافذ مستثناة", "Excluded ports")} hint={t("مثال: 9100, 515", "e.g. 9100, 515")}>
        <input className={inputClass} dir="ltr" value={ports} onChange={(e) => setPorts(e.target.value)} />
      </Field>
      <Field label={t("الوصف", "Description")}><input className={inputClass} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={2000} /></Field>
      <label className="flex items-center gap-2 self-end pb-2 text-sm">
        <input type="checkbox" checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} />
        {t("شريحة حساسة (يُسمح عليها بالاكتشاف الآمن فقط)", "Sensitive segment (safe discovery only)")}
      </label>
      <div className="md:col-span-2"><ErrorBox error={error} /></div>
      <div className="md:col-span-2 flex items-center gap-3">
        <Button type="submit" disabled={create.isPending}>{t("إضافة النطاق", "Add scope")}</Button>
        <span className="text-xs text-slate-500">{t("لن يمكن الفحص قبل اعتماد النطاق من مسؤول النظام.", "Scanning is not possible until an administrator approves the scope.")}</span>
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
    const ok = window.confirm(getLang() === "en"
      ? `Approve the scope ${scope.cidr}?\nBy approving you confirm the organisation owns or administers this range and that scanning it is authorized.`
      : `اعتماد النطاق ${scope.cidr}؟\nبالاعتماد تؤكد أن المؤسسة تملك هذا النطاق أو تديره وأن فحصه مصرح به.`);
    if (ok) action.mutate(() => api(`/api/scopes/${scope.id}/approve`, { method: "POST", body: { confirm: true } }));
  };

  return (
    <tr className="border-b border-slate-100 align-top">
      <td className="px-3 py-2 font-medium">
        {scope.name}
        {scope.description && <div className="text-xs text-slate-500">{scope.description}</div>}
      </td>
      <td className="px-3 py-2"><Ltr>{scope.cidr}</Ltr>
        {scope.excluded_hosts.length > 0 && <div className="text-xs text-slate-500">{t("مستثنى:", "Excluded:")} <Ltr>{scope.excluded_hosts.join(", ")}</Ltr></div>}
        {scope.excluded_ports.length > 0 && <div className="text-xs text-slate-500">{t("منافذ مستثناة:", "Excluded ports:")} <Ltr>{scope.excluded_ports.join(", ")}</Ltr></div>}
      </td>
      <td className="px-3 py-2">{scope.target_count}</td>
      <td className="px-3 py-2 space-y-1">
        {scope.is_approved ? <Badge tone="green">{t("معتمد", "Approved")}</Badge> : <Badge tone="amber">{t("بانتظار الاعتماد", "Awaiting approval")}</Badge>}
        {scope.is_sensitive && <div><Badge tone="purple">{t("حساس", "Sensitive")}</Badge></div>}
        {scope.has_active_job && <div><Badge tone="blue">{t("فحص جارٍ", "Scan running")}</Badge></div>}
        {scope.schedule_interval_minutes && (
          <div className="text-xs text-slate-600">
            <Badge tone="teal">{t("مجدول:", "Scheduled:")} {schedules()[String(scope.schedule_interval_minutes)] ?? (getLang() === "en" ? `every ${scope.schedule_interval_minutes} min` : `كل ${scope.schedule_interval_minutes} دقيقة`)}</Badge>
            <div>{t("التالي:", "Next:")} {formatDate(scope.schedule_next_run_at)}</div>
            {scope.schedule_last_error && <div className="text-red-700">{t("آخر محاولة:", "Last attempt:")} {scope.schedule_last_error}</div>}
          </div>
        )}
      </td>
      <td className="px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          {can("scan:run") && scope.is_approved && (
            <>
              <select className={`${inputClass} w-auto`} value={profileId ?? ""} onChange={(e) => setProfileId(Number(e.target.value))} aria-label={t("ملف الفحص", "Scan profile")}>
                {profiles.map((p) => <option key={p.id} value={p.id}>{p.name_ar}</option>)}
              </select>
              <Button
                disabled={scope.has_active_job || profileId === null || action.isPending}
                onClick={() => action.mutate(() => api<Job>("/api/scans", { method: "POST", body: { scope_id: scope.id, profile_id: profileId } }))}
              >
                {t("بدء الفحص", "Start scan")}
              </Button>
            </>
          )}
          {can("scan:run") && scope.is_approved && (
            <select className={`${inputClass} w-auto`} aria-label={t("جدولة الفحص", "Scan schedule")} value={String(scope.schedule_interval_minutes ?? "")}
              onChange={(e) => action.mutate(() => api(`/api/scopes/${scope.id}/schedule`, { method: "PUT",
                body: e.target.value ? { profile_id: profileId, interval_minutes: Number(e.target.value) } : { interval_minutes: null } }))}>
              <option value="">{t("بدون جدولة", "No schedule")}</option>
              {Object.entries(schedules()).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          )}
          {can("scope:approve") && !scope.is_approved && <Button variant="secondary" onClick={approve} disabled={action.isPending}>{t("اعتماد", "Approve")}</Button>}
          {can("scope:approve") && scope.is_approved && (
            <Button variant="ghost" disabled={action.isPending} onClick={() => action.mutate(() => api(`/api/scopes/${scope.id}/revoke`, { method: "POST" }))}>{t("سحب الاعتماد", "Revoke approval")}</Button>
          )}
          {can("scope:manage") && (
            <Button
              variant="ghost"
              disabled={scope.has_active_job || action.isPending}
              onClick={() => window.confirm(getLang() === "en" ? `Delete the scope “${scope.name}”? Its scan history is kept.` : `حذف النطاق «${scope.name}»؟ سيبقى سجل فحوصه محفوظاً.`) && action.mutate(() => api(`/api/scopes/${scope.id}`, { method: "DELETE" }))}
            >
              {t("حذف", "Delete")}
            </Button>
          )}
        </div>
        <ErrorBox error={error} />
      </td>
    </tr>
  );
}

export function JobsList({ jobs, onChange }: { jobs: Job[]; onChange: () => void }) {
  const { can } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const cancel = useMutation({ mutationFn: (id: number) => api(`/api/scans/${id}/cancel`, { method: "POST" }), onSettled: onChange });
  const act = useMutation({
    mutationFn: (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => { setError(null); onChange(); },
    onError: (e) => setError(errorMessage(e)),
  });
  if (!jobs.length) return <p className="text-sm text-slate-500">{t("لم يُنفذ أي فحص بعد.", "No scan has run yet.")}</p>;
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
                <Link to={`/scans/${job.id}`} className="font-semibold text-cyan-800 underline">{t("فحص", "Scan")} #{job.id}</Link>
                <span>{job.scope_name}</span>
                <Ltr className="text-xs text-slate-500">{job.scope_cidr}</Ltr>
                <Badge tone={STATUS_TONE[job.status]}>{label(JOB_STATUS, job.status)}</Badge>
                <span className="text-xs text-slate-500">{job.profile_name_ar}</span>
                {job.trigger !== "manual" && <Badge tone="purple">{label(TRIGGERS, job.trigger)}</Badge>}
                {job.resumed_from_id && <span className="text-xs text-slate-500">{getLang() === "en" ? `resumes scan #${job.resumed_from_id} from address #${job.resume_offset + 1}` : `استكمال للفحص #${job.resumed_from_id} من العنوان رقم ${job.resume_offset + 1}`}</span>}
              </div>
              <div className="flex flex-wrap gap-1">
                {active && can("scan:run") && (
                  <Button variant="secondary" disabled={job.cancel_requested || cancel.isPending} onClick={() => cancel.mutate(job.id)}>
                    {job.cancel_requested ? t("جارٍ الإيقاف…", "Stopping…") : t("إيقاف", "Stop")}
                  </Button>
                )}
                {!active && resumable && can("scan:run") && (
                  <Button disabled={act.isPending} onClick={() => act.mutate(() => api(`/api/scans/${job.id}/rerun`, { method: "POST", body: { mode: "resume" } }))}>{t("استكمال من حيث توقف", "Resume where it stopped")}</Button>
                )}
                {!active && can("scan:run") && (
                  <Button variant="secondary" disabled={act.isPending} onClick={() => act.mutate(() => api(`/api/scans/${job.id}/rerun`, { method: "POST", body: { mode: "restart" } }))}>{t("إعادة الفحص", "Re-run scan")}</Button>
                )}
                {!active && can("data:manage") && (
                  <Button variant="ghost" disabled={act.isPending} onClick={() => window.confirm(getLang() === "en" ? `Delete scan #${job.id} from the history?` : `حذف الفحص #${job.id} من السجل؟`) && act.mutate(() => api(`/api/scans/${job.id}`, { method: "DELETE" }))}>{t("حذف", "Delete")}</Button>
                )}
              </div>
            </div>
            <div className="mt-2"><ProgressBar value={progress(job.processed_hosts, job.total_hosts)} /></div>
            <div className="mt-1 flex flex-wrap gap-4 text-xs text-slate-600">
              <span>{getLang() === "en" ? `Scanned ${job.processed_hosts} of ${job.total_hosts} addresses` : `تم فحص ${job.processed_hosts} من ${job.total_hosts} عنوان`}</span>
              <span>{t("أجهزة مستجيبة:", "Responsive devices:")} {job.alive_hosts}</span>
              <span>{t("خدمات مفتوحة:", "Open services:")} {job.open_services}</span>
              <span>{t("بدأ:", "Started:")} {formatDate(job.started_at)}</span>
              {job.finished_at && <span>{t("انتهى:", "Finished:")} {formatDate(job.finished_at)}</span>}
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
    <Card title={t("لماذا لا يظهر جهاز؟ (تشخيص الاكتشاف)", "Why isn't a device showing? (discovery diagnostic)")}>
      <p className="mb-2 text-sm text-slate-500">{t("اكتب عنوان IP لجهاز متوقع ولا يظهر؛ يفحص راصد قابلية الوصول إليه (ICMP/TCP/UDP + تتبّع المسار) ويخبرك بالسبب والحل.", "Enter the IP of a device you expect but don't see; RasedNet tests reachability (ICMP/TCP/UDP + traceroute) and tells you the cause and the fix.")}</p>
      <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); check.mutate(); }}>
        <input dir="ltr" className={`${inputClass} w-48`} placeholder="10.0.0.5" value={ip} onChange={(e) => setIp(e.target.value)} />
        <Button type="submit" disabled={!ip.trim() || check.isPending}>{check.isPending ? t("جارٍ الفحص…", "Checking…") : t("شخّص", "Diagnose")}</Button>
      </form>
      {check.error && <div className="mt-2"><ErrorBox error={errorMessage(check.error)} /></div>}
      {r && (
        <div className="mt-3 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={tone(r.verdict)}>{r.reachable ? t("قابل للوصول", "Reachable") : t("غير قابل للوصول", "Unreachable")}</Badge>
            {!r.in_scope && <Badge tone="amber">{t("خارج النطاقات المعتمدة", "Outside approved scopes")}</Badge>}
            {r.icmp.alive && <Badge tone="green">{t("يرد على ICMP", "Responds to ICMP")}</Badge>}
          </div>
          <p className="rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-700">{r.reason_ar}</p>
          <div className="grid gap-2 text-xs text-slate-600 md:grid-cols-2">
            <div>TCP: {Object.entries(r.tcp).map(([p, s]) => `${p}:${s}`).join(t("، ", ", "))}</div>
            <div>UDP: {Object.entries(r.udp).map(([p, s]) => `${p}:${s}`).join(t("، ", ", "))}</div>
          </div>
          {r.traceroute.length > 0 && (
            <div className="text-xs text-slate-500">
              {t("المسار:", "Path:")} {r.traceroute.map((h) => (h.ip ? h.ip : "*")).join(" → ")}
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
      <h1 className="text-2xl font-bold">{t("اكتشاف الشبكة", "Network discovery")}</h1>
      {can("scope:manage") && <NetworkCandidates profiles={profiles.data ?? []} onChanged={refresh} />}
      <Card title={t("نطاقات الفحص المعتمدة", "Approved scan scopes")}>
        {scopes.isLoading ? <Loading /> : scopes.error ? <ErrorBox error={scopes.error} /> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b border-slate-200 bg-slate-50 text-start">
                <th className="px-3 py-2 text-start">{t("الاسم", "Name")}</th><th className="px-3 py-2 text-start">{t("النطاق", "Range")}</th>
                <th className="px-3 py-2 text-start">{t("عدد العناوين", "Address count")}</th><th className="px-3 py-2 text-start">{t("الحالة", "Status")}</th><th className="px-3 py-2 text-start">{t("الإجراءات", "Actions")}</th>
              </tr></thead>
              <tbody>
                {(scopes.data ?? []).map((s) => <ScopeRow key={s.id} scope={s} profiles={profiles.data ?? []} refresh={refresh} />)}
              </tbody>
            </table>
            {scopes.data?.length === 0 && <p className="py-4 text-center text-sm text-slate-500">{t("لا توجد نطاقات. أضف نطاقاً ثم اطلب اعتماده.", "No scopes. Add a scope, then request approval.")}</p>}
          </div>
        )}
      </Card>
      {can("scope:manage") && <Card title={t("إضافة نطاق يدوياً", "Add scope manually")}><NewScopeForm onDone={refresh} /></Card>}
      <ReachabilityDiagnostic />
      {can("scan:read") && (
        <Card title={t("أحدث مهام الفحص", "Latest scan jobs")} actions={<Link className="text-sm text-cyan-800 underline" to="/scans">{t("السجل الكامل", "Full history")}</Link>}>
          {jobs.isLoading ? <Loading /> : <JobsList jobs={jobs.data?.items ?? []} onChange={refresh} />}
        </Card>
      )}
      {profiles.data && (
        <Card title={t("ملفات الفحص المتاحة", "Available scan profiles")}>
          <div className="grid gap-3 md:grid-cols-2">
            {profiles.data.map((p) => (
              <div key={p.id} className="rounded-lg border border-slate-200 p-3 text-sm">
                <div className="font-semibold">{p.name_ar}</div>
                <p className="mt-1 text-slate-600">{p.description_ar}</p>
                <ul className="mt-2 space-y-0.5 text-xs text-slate-500">
                  <li>{t("منافذ الاكتشاف:", "Discovery ports:")} <Ltr>{p.discovery_ports.join(", ")}</Ltr></li>
                  <li>{t("منافذ فحص الخدمات:", "Service-scan ports:")} {p.tcp_ports.length ? (getLang() === "en" ? `${p.tcp_ports.length} ports` : `${p.tcp_ports.length} منفذاً`) : t("لا يوجد", "none")}</li>
                  <li>{getLang() === "en" ? `Limits: ${p.rate_per_second} conn/s, ${p.max_concurrency} concurrent, ${p.per_host_concurrency} per device` : `الحد الأقصى: ${p.rate_per_second} اتصال/ثانية، ${p.max_concurrency} اتصالاً متزامناً، ${p.per_host_concurrency} لكل جهاز`}</li>
                  <li>{t("قراءة توقيعات الخدمات:", "Read service banners:")} {p.grab_banners ? t("نعم", "yes") : t("لا", "no")} — {t("مهلة الاتصال:", "connect timeout:")} {p.connect_timeout_ms} ms</li>
                </ul>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-500">
            {t("حدود الاكتشاف: عناوين MAC تظهر فقط للأجهزة في نفس الشريحة المحلية لخادم الفحص. الأجهزة التي تحجب ICMP وجميع منافذ الاكتشاف قد لا تظهر. لا يتضمن أي ملف فحصاً تدخلياً أو تخميناً لكلمات المرور.",
              "Discovery limits: MAC addresses appear only for devices on the scanner's own local segment. Devices that block ICMP and all discovery ports may not appear. No profile performs intrusive scanning or password guessing.")}
          </p>
        </Card>
      )}
    </div>
  );
}
