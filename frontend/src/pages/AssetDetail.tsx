import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState } from "react";
import { RouterControl } from "../components/RouterControl";
import { ServiceGuidancePanel } from "../components/ServiceGuidance";
import { Link, useParams } from "react-router";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, SEVERITY_TONE, STATUS_TONE } from "../components/ui";
import { deviceTypeSentence, formatDate, percent } from "../format";
import { ASSET_STATUS, CRITICALITY, EVENT_KINDS, EXPOSURE, ID_METHOD, label, METHODS, OS_FAMILIES, SEVERITY } from "../labels";
import type { AssetDetail, Credential, Execution, Job, Profile, SmbBrowse, SmbShares } from "../types";

const ID_KIND: Record<string, string> = { mac: "عنوان MAC", hostname: "اسم الجهاز", ipv4: "IPv4", ipv6: "IPv6" };

function RescanButton({ asset }: { asset: AssetDetail }) {
  const qc = useQueryClient();
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api<Profile[]>("/api/profiles") });
  const [profileId, setProfileId] = useState<number | null>(null);
  const chosen = profileId ?? profiles.data?.find((p) => p.code === "standard_inventory")?.id ?? null;
  const run = useMutation({
    mutationFn: () => api<Job>(`/api/assets/${asset.id}/rescan`, { method: "POST", body: { profile_id: chosen } }),
    onSuccess: () => {
      window.setTimeout(() => void qc.invalidateQueries({ queryKey: ["asset", asset.id] }), 4000);
      window.setTimeout(() => void qc.invalidateQueries({ queryKey: ["asset", asset.id] }), 15000);
    },
  });
  return (
    <div className="flex flex-wrap items-center gap-2">
      <select className={`${inputClass} w-auto`} value={chosen ?? ""} onChange={(e) => setProfileId(Number(e.target.value))} aria-label="ملف الفحص">
        {profiles.data?.map((p) => <option key={p.id} value={p.id}>{p.name_ar}</option>)}
      </select>
      <Button disabled={!chosen || run.isPending} onClick={() => run.mutate()}>فحص هذا الجهاز الآن</Button>
      {run.data && <Link className="text-xs text-cyan-800 underline" to={`/scans/${run.data.id}`}>متابعة الفحص #{run.data.id}</Link>}
      {run.error && <span className="text-xs text-red-700">{errorMessage(run.error)}</span>}
    </div>
  );
}

const WEB_PORTS = [80, 443, 8080, 8008, 8060, 8443, 5000, 8888, 3000, 9000, 1400];

function screenUrl(ip: string, s: { port: number; service_name: string }): string {
  const https = s.port === 443 || s.port === 8443 || /https/.test(s.service_name);
  return `${https ? "https" : "http"}://${ip}:${s.port}/`;
}

function ScreenPreview({ asset }: { asset: AssetDetail }) {
  const webs = asset.services.filter(
    (s) => s.state === "open" && s.protocol === "tcp" && (WEB_PORTS.includes(s.port) || /http/.test(s.service_name)),
  );
  const [active, setActive] = useState<string | null>(asset.current_ip && webs[0] ? screenUrl(asset.current_ip, webs[0]) : null);
  if (!asset.current_ip) return null;
  return (
    <Card title="معاينة الشاشة">
      <p className="mb-2 text-xs text-slate-500">
        عرض ما تبثّه هذه الشاشة من واجهتها المتاحة على الشبكة — دون تجاوز أي حماية. مناسب للشاشات واللوحات العامة التابعة للشبكة.
      </p>
      {webs.length === 0 ? (
        <p className="text-sm text-slate-500">لا توجد واجهة ويب مفتوحة على هذه الشاشة لعرض محتواها. إن كانت تعرض عبر HDMI/تطبيق فقط فلا يمكن التقاط صورتها عن بُعد.</p>
      ) : (
        <>
          <div className="mb-2 flex flex-wrap gap-1.5">
            {webs.map((s) => {
              const u = screenUrl(asset.current_ip!, s);
              return (
                <button key={s.id} type="button" onClick={() => setActive(u)}
                  className={`rounded-lg border px-2 py-1 text-xs ${active === u ? "border-cyan-600 bg-cyan-600 text-white" : "border-slate-300 bg-white hover:border-cyan-400"}`}>
                  <Ltr>{s.port}/{s.service_name}</Ltr>
                </button>
              );
            })}
            {active && <a href={active} target="_blank" rel="noreferrer" className="rounded-lg border border-slate-300 px-2 py-1 text-xs text-cyan-800 hover:bg-cyan-50">↗ فتح في تبويب</a>}
          </div>
          {active && (
            <>
              <iframe title="معاينة الشاشة" src={active} className="h-[460px] w-full rounded-lg border border-slate-200 bg-white"
                sandbox="allow-scripts allow-same-origin allow-forms" referrerPolicy="no-referrer" />
              <p className="mt-1 text-[11px] text-slate-400">لو ظهرت المعاينة فارغة فالجهاز يمنع التضمين (X-Frame-Options)؛ استخدم «فتح في تبويب».</p>
            </>
          )}
        </>
      )}
    </Card>
  );
}

function SharedFiles({ asset }: { asset: AssetDetail }) {
  const [loc, setLoc] = useState<{ share: string; sub: string } | null>(null);
  const shares = useQuery({ queryKey: ["smb-shares", asset.id], queryFn: () => api<SmbShares>(`/api/assets/${asset.id}/smb/shares`), enabled: false });
  const list = useQuery({
    queryKey: ["smb-browse", asset.id, loc?.share, loc?.sub],
    queryFn: () => api<SmbBrowse>(`/api/assets/${asset.id}/smb/browse`, { query: { share: loc!.share, path: loc!.sub } }),
    enabled: !!loc,
  });
  const crumbs = loc ? loc.sub.split("\\").filter(Boolean) : [];
  const goUp = () => { if (loc) setLoc({ share: loc.share, sub: crumbs.slice(0, -1).join("\\") }); };
  return (
    <Card title="الملفات المشتركة للعامة (SMB)">
      <p className="mb-2 text-xs text-slate-500">
        تصفّح قراءة فقط لما يشاركه الجهاز <b>بدون حساب</b>. لا يرسل راصد أي كلمة مرور؛ المشاركات المحميّة لا تظهر، ولا تُقرأ محتويات الملفات.
      </p>
      {!shares.data && <Button variant="secondary" disabled={shares.isFetching} onClick={() => shares.refetch()}>{shares.isFetching ? "جارٍ الفحص…" : "اعرض المشاركات العامة"}</Button>}
      {shares.error && <div className="mt-2"><ErrorBox error={errorMessage(shares.error)} /></div>}
      {shares.data && shares.data.shares.length === 0 && <p className="text-sm text-amber-700">لا توجد مشاركات متاحة بدون حساب على هذا الجهاز (كلها محميّة).</p>}
      {shares.data && shares.data.shares.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {shares.data.shares.map((s) => (
            <button key={s.share} type="button" onClick={() => setLoc({ share: s.share, sub: "" })}
              className={`rounded-lg border px-2 py-1 text-sm ${loc?.share === s.share ? "border-cyan-600 bg-cyan-600 text-white" : "border-slate-300 bg-white hover:border-cyan-400"}`}>
              📁 {s.share} <span className="text-xs opacity-70">({s.entries.length}{s.truncated ? "+" : ""})</span>
            </button>
          ))}
        </div>
      )}
      {loc && (
        <div className="mt-3 rounded-xl border border-slate-200 p-2">
          <div className="mb-1 flex items-center gap-1 text-xs text-slate-600">
            <button type="button" className="text-cyan-800 underline" onClick={() => setLoc({ share: loc.share, sub: "" })}>{loc.share}</button>
            {crumbs.map((c, i) => <span key={i}>\ <button type="button" className="text-cyan-800 underline" onClick={() => setLoc({ share: loc.share, sub: crumbs.slice(0, i + 1).join("\\") })}>{c}</button></span>)}
            {crumbs.length > 0 && <button type="button" className="ms-2 text-slate-500 underline" onClick={goUp}>▲ للأعلى</button>}
          </div>
          {list.isLoading ? <Loading /> : list.error ? <ErrorBox error={errorMessage(list.error)} /> : (
            <div className="max-h-80 overflow-auto">
              {list.data!.entries.length === 0 ? <p className="p-2 text-sm text-slate-400">مجلد فارغ.</p> : (
                <table className="w-full text-sm">
                  <tbody>
                    {list.data!.entries.map((e) => (
                      <tr key={e.name} className="border-b border-slate-100">
                        <td className="px-2 py-1">
                          {e.is_dir ? (
                            <button type="button" className="text-cyan-800 hover:underline" onClick={() => setLoc({ share: loc.share, sub: (loc.sub ? loc.sub + "\\" : "") + e.name })}>📁 {e.name}</button>
                          ) : <span className="text-slate-700">📄 {e.name}</span>}
                        </td>
                        <td className="px-2 py-1 text-end text-xs text-slate-500">{e.is_dir ? "" : `${Math.max(1, Math.round(e.size / 1024))} ك.ب`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

const WEB_FP_PORTS = [80, 443, 8080, 8008, 8443, 8000, 8888, 5000, 9000, 9443, 7000, 1400, 631];
interface WebFpService { port: number; scheme: string; status?: number; server: string | null; title: string | null; favicon_hash: number | null; error?: string }
function WebFingerprint({ asset }: { asset: AssetDetail }) {
  const [res, setRes] = useState<WebFpService[] | null>(null);
  const run = useMutation({
    mutationFn: () => api<{ services: WebFpService[] }>(`/api/assets/${asset.id}/web-fingerprint`, { method: "POST", body: {} }),
    onSuccess: (r) => setRes(r.services),
  });
  return (
    <Card title="بصمة الويب">
      <p className="mb-2 text-xs text-slate-500">
        يلتقط هوية واجهات الويب على الجهاز: ترويسة الخادم، عنوان الصفحة، وبصمة الأيقونة (favicon hash بأسلوب Shodan) — للتعرّف على لوحات الإدارة والبحث عنها. قراءة فقط.
      </p>
      <Button disabled={run.isPending} onClick={() => run.mutate()}>{run.isPending ? "جارٍ…" : "التقط بصمة الويب"}</Button>
      {run.error && <div className="mt-2"><ErrorBox error={errorMessage(run.error)} /></div>}
      {res && (
        <div className="mt-2 overflow-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b text-slate-500"><th className="p-2">المنفذ</th><th className="p-2 text-start">الخادم</th><th className="p-2 text-start">العنوان</th><th className="p-2 text-start">favicon</th></tr></thead>
            <tbody>
              {res.map((s) => (
                <tr key={s.port} className="border-b border-slate-100">
                  <td className="p-2 text-center font-mono">{s.scheme}/{s.port}</td>
                  <td className="p-2">{s.error ? <span className="text-xs text-red-600">{s.error}</span> : (s.server ?? "—")}</td>
                  <td className="p-2">{s.title ?? "—"}</td>
                  <td className="p-2"><Ltr className="font-mono text-xs">{s.favicon_hash ?? "—"}</Ltr></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

interface UdpResult { port: number; service: string; state: string }
function UdpScan({ asset }: { asset: AssetDetail }) {
  const qc = useQueryClient();
  const [res, setRes] = useState<{ open: number; results: UdpResult[] } | null>(null);
  const run = useMutation({
    mutationFn: () => api<{ open: number; results: UdpResult[] }>(`/api/assets/${asset.id}/udp-scan`, { method: "POST", body: {} }),
    onSuccess: (r) => { setRes(r); void qc.invalidateQueries({ queryKey: ["asset", asset.id] }); },
  });
  const tone = (s: string) => (s === "open" ? "green" : s === "closed" ? "slate" : "amber");
  const ar = (s: string) => (s === "open" ? "مفتوح" : s === "closed" ? "مغلق" : "صامت/مُرشَّح");
  return (
    <Card title="فحص منافذ UDP">
      <p className="mb-2 text-xs text-slate-500">
        فحص نشط للمنافذ الشائعة (DNS، NTP، SNMP، NetBIOS، SSDP، mDNS…) بإرسال طلب خاص بكل بروتوكول.
        المنفذ يُعدّ مفتوحاً فقط عند وصول رد — لا ادّعاء كاذب. يتطلب أن يكون الجهاز داخل نطاق معتمد.
      </p>
      <Button disabled={run.isPending} onClick={() => run.mutate()}>{run.isPending ? "جارٍ الفحص…" : "افحص منافذ UDP"}</Button>
      {run.error && <div className="mt-2"><ErrorBox error={errorMessage(run.error)} /></div>}
      {res && (
        <div className="mt-2">
          <div className="mb-1 text-sm text-slate-600">منافذ UDP مفتوحة: {res.open}</div>
          <div className="flex flex-wrap gap-1.5">
            {res.results.map((r) => (
              <span key={r.port} className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-0.5 text-xs">
                <Ltr className="font-mono">{r.port}</Ltr> {r.service} <Badge tone={tone(r.state)}>{ar(r.state)}</Badge>
              </span>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

function Console({ asset, credentials }: { asset: AssetDetail; credentials: Credential[] }) {
  const qc = useQueryClient();
  const [credId, setCredId] = useState<number | "">("");
  const [command, setCommand] = useState("");
  const [result, setResult] = useState<Execution | null>(null);
  const run = useMutation({
    mutationFn: () => api<Execution>(`/api/assets/${asset.id}/console`, { method: "POST", body: { credential_id: credId, command, confirm: true } }),
    onSuccess: (r) => { setResult(r); void qc.invalidateQueries({ queryKey: ["executions", asset.id] }); },
  });
  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-500">ينفذ الأمر على الجهاز بالحساب المختار (WinRM: PowerShell، SSH: Shell). كل أمر يُسجّل في سجل التدقيق مع مخرجاته.</p>
      <select className={`${inputClass} w-auto`} value={credId} onChange={(e) => setCredId(e.target.value ? Number(e.target.value) : "")} aria-label="حساب الدخول">
        <option value="">اختر حساب الدخول…</option>
        {credentials.map((c) => <option key={c.id} value={c.id}>{c.name} — {c.kind === "ssh" ? "SSH" : "WinRM"} ({c.username})</option>)}
      </select>
      <textarea dir="ltr" className={`${inputClass} ltr min-h-24`} value={command} onChange={(e) => setCommand(e.target.value)}
        placeholder="Get-Service | Where-Object Status -eq Running   |   uptime; df -h" aria-label="الأمر" />
      <Button variant="danger" disabled={!credId || !command.trim() || run.isPending}
        onClick={() => window.confirm("تنفيذ الأمر على " + (asset.current_ip ?? "") + "؟") && run.mutate()}>
        {run.isPending ? "جارٍ التنفيذ…" : "تنفيذ على الجهاز"}
      </Button>
      {run.error && <ErrorBox error={errorMessage(run.error)} />}
      {result && <ExecutionView e={result} />}
    </div>
  );
}

function ExecutionView({ e }: { e: Execution }) {
  return (
    <div className="rounded-lg border border-slate-200">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 bg-slate-50 px-2 py-1 text-xs">
        <Badge tone={e.status === "ok" && !e.had_errors ? "green" : e.status === "ok" ? "amber" : "red"}>{e.status === "error" ? "فشل" : e.had_errors ? "مع أخطاء" : "نجاح"}</Badge>
        <span>{e.label_ar}</span><span className="text-slate-400">{formatDate(e.started_at)}</span>
      </div>
      <pre dir="ltr" className="ltr border-b border-slate-100 bg-slate-900 px-2 py-1 text-[11px] text-emerald-100">{e.command}</pre>
      <pre dir="ltr" className="ltr max-h-64 overflow-auto whitespace-pre-wrap break-all px-2 py-1 text-[11px]">{e.output || "(لا توجد مخرجات)"}</pre>
    </div>
  );
}

function EditAsset({ asset }: { asset: AssetDetail }) {
  const qc = useQueryClient();
  const [displayName, setDisplayName] = useState(asset.display_name ?? "");
  const [criticality, setCriticality] = useState(asset.criticality);
  const [notes, setNotes] = useState(asset.notes);
  const save = useMutation({
    mutationFn: () => api(`/api/assets/${asset.id}`, { method: "PATCH", body: { display_name: displayName, criticality, notes } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["asset", asset.id] }),
  });
  return (
    <div className="grid gap-3 md:grid-cols-3">
      <Field label="الاسم المعتمد"><input className={inputClass} value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={128} /></Field>
      <Field label="أهمية الجهاز">
        <select className={inputClass} value={criticality} onChange={(e) => setCriticality(e.target.value as AssetDetail["criticality"])}>
          {Object.entries(CRITICALITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
      </Field>
      <Field label="ملاحظات"><input className={inputClass} value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={5000} /></Field>
      <div className="md:col-span-3 flex items-center gap-3">
        <Button onClick={() => save.mutate()} disabled={save.isPending}>حفظ</Button>
        {save.isSuccess && <span className="text-sm text-emerald-700">تم الحفظ</span>}
        {save.error && <span className="text-sm text-red-700">{errorMessage(save.error)}</span>}
      </div>
    </div>
  );
}

export function AssetDetailPage() {
  const { id } = useParams();
  const assetId = Number(id);
  const { can } = useAuth();
  const [open, setOpen] = useState<Record<number, boolean>>({});
  const { data: a, error, isLoading } = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => api<AssetDetail>(`/api/assets/${assetId}`),
    enabled: Number.isInteger(assetId),
  });
  const credentials = useQuery({ queryKey: ["credentials"], queryFn: () => api<Credential[]>("/api/credentials"), enabled: can("remote:verify") });
  const executions = useQuery({ queryKey: ["executions", assetId], queryFn: () => api<Execution[]>(`/api/assets/${assetId}/executions`), enabled: can("remote:verify") });
  if (isLoading) return <Loading />;
  if (error || !a) return <ErrorBox error={error ?? "الجهاز غير موجود"} />;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Link to="/assets" className="text-sm text-cyan-800 underline">الأجهزة المتصلة</Link>
        <h1 className="text-2xl font-bold">{a.display_name ?? a.hostname ?? <Ltr>{a.current_ip}</Ltr>}</h1>
        <Badge tone={STATUS_TONE[a.status]}>{label(ASSET_STATUS, a.status)}</Badge>
        {a.is_gateway && <Badge tone="amber">بوابة الشبكة</Badge>}
        {a.model && <span className="text-sm text-slate-500">{a.model}</span>}
        {can("scan:run") && <div className="ms-auto"><RescanButton asset={a} /></div>}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="بيانات الجهاز">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-slate-500">عنوان IP الحالي</dt><dd><Ltr>{a.current_ip ?? "—"}</Ltr></dd>
            <dt className="text-slate-500">اسم الجهاز (DNS)</dt><dd>{a.hostname ? <Ltr>{a.hostname}</Ltr> : "غير متوفر"}</dd>
            <dt className="text-slate-500">عنوان MAC</dt>
            <dd>{a.mac ? <Ltr>{a.mac}</Ltr> : "غير مرئي (الجهاز خارج الشريحة المحلية لخادم الفحص أو لم يُرصد)"}{a.mac_randomized && <span className="ms-2"><Badge tone="purple">عنوان عشوائي محتمل</Badge></span>}</dd>
            <dt className="text-slate-500">الشركة المصنعة</dt><dd>{a.vendor ?? "غير محددة"}</dd>
            {a.model && <><dt className="text-slate-500">الطراز (UPnP)</dt><dd>{a.model}</dd></>}
            {a.upnp?.friendly_name && <><dt className="text-slate-500">الاسم المعلن</dt><dd>{a.upnp.friendly_name}</dd></>}
            {a.netbios_name && <><dt className="text-slate-500">اسم NetBIOS</dt><dd><Ltr>{a.netbios_name.toUpperCase()}</Ltr></dd></>}
            {a.workgroup && <><dt className="text-slate-500">مجموعة العمل / المجال</dt><dd><Ltr>{a.workgroup.toUpperCase()}</Ltr></dd></>}
            {a.upnp?.server && <><dt className="text-slate-500">خادم UPnP</dt><dd><Ltr className="text-xs">{a.upnp.server}</Ltr></dd></>}
            <dt className="text-slate-500">طرق الاكتشاف</dt><dd>{a.discovery_methods.map((m) => label(METHODS, m)).join("، ") || "—"}</dd>
            <dt className="text-slate-500">أهمية الجهاز</dt><dd>{label(CRITICALITY, a.criticality)}</dd>
            <dt className="text-slate-500">أول ظهور</dt><dd>{formatDate(a.first_seen)}</dd>
            <dt className="text-slate-500">آخر ظهور</dt><dd>{formatDate(a.last_seen)}</dd>
          </dl>
        </Card>

        <Card title="تصنيف الجهاز والأدلة">
          <p className="font-semibold">{deviceTypeSentence(a.device_type, a.device_type_confidence)}</p>
          <p className="mt-1 text-sm">
            نظام التشغيل: {a.os_family === "unknown" ? "غير مؤكد — يتطلب مراجعة" : `${label(OS_FAMILIES, a.os_family)} — الثقة ${percent(a.os_confidence)}`}
          </p>
          <p className="mt-2 text-xs text-slate-500">التصنيف استنتاج قائم على الأدلة أدناه وليس تحققاً مؤكداً. لا يُستنتج طراز الجهاز دون دليل موثوق.</p>
          {a.fingerprint && a.fingerprint.evidence.length > 0 ? (
            <ul className="mt-3 space-y-1 text-sm">
              {a.fingerprint.evidence.map((e, i) => (
                <li key={i} className="rounded border border-slate-100 bg-slate-50 px-2 py-1">
                  {e.detail_ar} <span className="text-xs text-slate-500">(وزن الدليل {percent(e.weight)})</span>
                </li>
              ))}
            </ul>
          ) : <p className="mt-3 text-sm text-slate-500">لا توجد أدلة كافية للتصنيف.</p>}
        </Card>
      </div>

      <Card title="الخدمات والمنافذ">
        {a.services.length === 0 ? <p className="text-sm text-slate-500">لم تُرصد خدمات مفتوحة.</p> : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead><tr className="border-b bg-slate-50">
                <th className="px-3 py-2 text-start">المنفذ</th><th className="px-3 py-2 text-start">الخدمة</th><th className="px-3 py-2 text-start">المنتج والإصدار</th>
                <th className="px-3 py-2 text-start">طريقة التعرف</th><th className="px-3 py-2 text-start">الفئة</th><th className="px-3 py-2 text-start">الحالة</th><th className="px-3 py-2 text-start">ملاحظة أمنية</th>
              </tr></thead>
              <tbody>
                {a.services.map((s) => (
                  <Fragment key={s.id}>
                  <tr className="border-b border-slate-100 align-top">
                    <td className="px-3 py-2"><Ltr>{`${s.port}/${s.protocol}`}</Ltr></td>
                    <td className="px-3 py-2"><Ltr>{s.service_name}</Ltr></td>
                    <td className="px-3 py-2">
                      {s.product ? <Ltr>{`${s.product}${s.version ? " " + s.version : ""}`}</Ltr> : "—"}
                      {s.banner && <div className="mt-1 max-w-xs truncate text-xs text-slate-500" title={s.banner}><Ltr>{s.banner}</Ltr></div>}
                      {s.tls && typeof s.tls === "object" && "certificate" in s.tls && (
                        <div className="mt-1 text-xs text-slate-500">شهادة TLS: <Ltr>{String((s.tls.certificate as Record<string, unknown>).subject_cn ?? "—")}</Ltr></div>
                      )}
                    </td>
                    <td className="px-3 py-2">{label(ID_METHOD, s.identification_method)} ({percent(s.identification_confidence)})</td>
                    <td className="px-3 py-2">{label(EXPOSURE, s.exposure_category)}</td>
                    <td className="px-3 py-2"><Badge tone={s.state === "open" ? "orange" : "slate"}>{s.state === "open" ? "مفتوح" : "مغلق"}</Badge></td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {s.exposure_note_ar ?? "—"}
                      {s.guidance && (
                        <div className="mt-2">
                          <Button variant="ghost" className="px-2 py-1 text-xs" aria-expanded={!!open[s.id]}
                            onClick={() => setOpen({ ...open, [s.id]: !open[s.id] })}>
                            {open[s.id] ? "إخفاء الخطوات" : "كيف أتحقق منها وأقفلها"}
                          </Button>
                        </div>
                      )}
                    </td>
                  </tr>
                  {s.guidance && open[s.id] && (
                    <tr className="border-b border-slate-100">
                      <td colSpan={7} className="px-3 pb-4">
                        <ServiceGuidancePanel guidance={s.guidance} ip={a.current_ip}
                          run={can("remote:verify") ? { assetId: a.id, serviceId: s.id, credentials: credentials.data ?? [] } : undefined} />
                      </td>
                    </tr>
                  )}
                  </Fragment>
                ))}
              </tbody>
            </table>
            <p className="mt-2 text-xs text-slate-500">وجود منفذ مفتوح ليس دليلاً على وجود ثغرة؛ الملاحظات أعلاه توصيات للمراجعة.</p>
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="المعرفات المرصودة">
          <ul className="space-y-1 text-sm">
            {a.identifiers.map((i) => (
              <li key={`${i.kind}-${i.value}`}>{label(ID_KIND, i.kind)}: <Ltr>{i.value}</Ltr> <span className="text-xs text-slate-500">— آخر ظهور {formatDate(i.last_seen)}</span></li>
            ))}
          </ul>
        </Card>
        <Card title="سجل عناوين IP">
          <ul className="space-y-1 text-sm">
            {a.ip_history.map((o) => (
              <li key={o.ip}><Ltr>{o.ip}</Ltr> <span className="text-xs text-slate-500">— من {formatDate(o.first_seen)} إلى {formatDate(o.last_seen)} ({o.sightings} مرة)</span></li>
            ))}
          </ul>
        </Card>
        <Card title="التنبيهات المفتوحة">
          {a.alerts.length === 0 ? <p className="text-sm text-slate-500">لا توجد.</p> : (
            <ul className="space-y-2 text-sm">{a.alerts.map((al) => (
              <li key={al.id}><Badge tone={SEVERITY_TONE[al.severity]}>{label(SEVERITY, al.severity)}</Badge> <span className="font-medium">{al.title_ar}</span><div className="text-xs text-slate-600">{al.message_ar}</div></li>
            ))}</ul>
          )}
        </Card>
        <Card title="سجل تغييرات الجهاز">
          <ul className="space-y-1 text-sm">{a.events.map((e) => (
            <li key={e.id}><Badge>{label(EVENT_KINDS, e.kind)}</Badge> {e.message_ar} <span className="text-xs text-slate-500">— {formatDate(e.created_at)}</span></li>
          ))}</ul>
        </Card>
      </div>

      {["tv", "iot"].includes(a.device_type) && <ScreenPreview asset={a} />}
      {can("remote:verify") && a.services.some((s) => s.state === "open" && (s.port === 445 || s.port === 139)) && <SharedFiles asset={a} />}
      {can("remote:verify") && a.services.some((s) => s.state === "open" && WEB_FP_PORTS.includes(s.port)) && <WebFingerprint asset={a} />}
      {can("scan:run") && <UdpScan asset={a} />}
      {can("remote:verify") && ["router", "access_point", "switch", "network_device"].includes(a.device_type) && (
        <RouterControl assetId={a.id} credentials={credentials.data ?? []} />
      )}
      {can("remote:change") && (
        <Card title="وحدة التحكم بالجهاز (أوامر مخصصة)"><Console asset={a} credentials={credentials.data ?? []} /></Card>
      )}
      {can("remote:verify") && (executions.data?.length ?? 0) > 0 && (
        <Card title="سجل الأوامر المنفذة على هذا الجهاز">
          <div className="space-y-2">{executions.data?.slice(0, 10).map((e) => <ExecutionView key={e.id} e={e} />)}</div>
        </Card>
      )}
      {can("asset:write") && <Card title="تعديل بيانات الجهاز"><EditAsset key={a.id} asset={a} /></Card>}
    </div>
  );
}
