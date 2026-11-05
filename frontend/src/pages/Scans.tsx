import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, ErrorBox, Loading, Ltr, Pager, STATUS_TONE } from "../components/ui";
import { formatDate } from "../format";
import { JOB_STATUS, label, METHODS } from "../labels";
import type { Job, Page, ScanDiff, ScanResult } from "../types";
import { JobsList } from "./Discovery";

function readCsrf(): string | null {
  for (const part of document.cookie.split(";")) {
    const [k, ...r] = part.trim().split("=");
    if (k === "rased_csrf") return decodeURIComponent(r.join("="));
  }
  return null;
}

interface Adapter { key: string; title: string; accept: string; contentType: string; hint: string; summary: (d: Record<string, number>) => string }

const ADAPTERS: Adapter[] = [
  { key: "nmap", title: "نتائج Nmap (XML)", accept: ".xml,application/xml", contentType: "application/xml",
    hint: "ملف nmap -oX — يُدمج في الجرد دون فحص.",
    summary: (d) => `أجهزة: جديد ${d.assets_new}، محدّث ${d.assets_updated}؛ منافذ جديدة ${d.services_new}.` },
  { key: "dhcp", title: "حجوزات DHCP", accept: ".leases,.txt,text/plain", contentType: "text/plain",
    hint: "ملف dhcpd.leases أو dnsmasq.leases.",
    summary: (d) => `أجهزة: جديد ${d.assets_new}، محدّث ${d.assets_updated}.` },
  { key: "csv", title: "جرد أجهزة (CSV)", accept: ".csv,text/csv", contentType: "text/plain",
    hint: "تصدير من متحكّم واي-فاي أو MDM أو جدول (أعمدة ip/mac/hostname/type/os).",
    summary: (d) => `أجهزة: جديد ${d.assets_new}، محدّث ${d.assets_updated}.` },
  { key: "greenbone", title: "تقرير ثغرات Greenbone/OpenVAS", accept: ".xml,application/xml", contentType: "application/xml",
    hint: "تقرير OpenVAS XML — يربط الثغرات بالأجهزة المعروفة.",
    summary: (d) => `نتائج: ${d.findings} على ${d.matched_assets} جهازاً (غير مطابق ${d.unmatched}).` },
  { key: "nessus", title: "تقرير ثغرات Nessus", accept: ".nessus,.xml,application/xml", contentType: "application/xml",
    hint: "ملف ‎.nessus‎ — يربط الثغرات بالأجهزة المعروفة.",
    summary: (d) => `نتائج: ${d.findings} على ${d.matched_assets} جهازاً (غير مطابق ${d.unmatched}).` },
  { key: "wazuh", title: "ثغرات Wazuh (JSON)", accept: ".json,application/json", contentType: "application/json",
    hint: "تصدير كاشف ثغرات Wazuh (JSON).",
    summary: (d) => `نتائج: ${d.findings} على ${d.matched_assets} جهازاً (غير مطابق ${d.unmatched}).` },
  { key: "osquery", title: "جرد osquery (JSON)", accept: ".json,application/json", contentType: "application/json",
    hint: "نتائج osquery (system_info / interface_addresses).",
    summary: (d) => `أجهزة: جديد ${d.assets_new}، محدّث ${d.assets_updated}.` },
];

function FileImport({ ad }: { ad: Adapter }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const qc = useQueryClient();
  const upload = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true); setMsg(null); setErr(null);
    try {
      const token = readCsrf();
      const resp = await fetch(`/api/imports/${ad.key}`, {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": ad.contentType, ...(token ? { "X-CSRF-Token": token } : {}) },
        body: await file.text(),
      });
      const data = await resp.json().catch(() => null);
      if (!resp.ok) throw new ApiError(resp.status, typeof data?.detail === "string" ? data.detail : "تعذر الاستيراد");
      setMsg(ad.summary(data));
      void qc.invalidateQueries();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "تعذر الاستيراد");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="rounded-xl border border-slate-200 p-3">
      <div className="text-sm font-semibold text-slate-800">{ad.title}</div>
      <p className="mb-2 text-xs text-slate-500">{ad.hint}</p>
      <input type="file" accept={ad.accept} disabled={busy} className="text-sm"
        onChange={(e) => void upload(e.target.files?.[0])} />
      {busy && <span className="ms-2 text-sm text-slate-500">جارٍ الاستيراد…</span>}
      {msg && <p className="mt-2 rounded-lg bg-emerald-50 px-2 py-1 text-xs text-emerald-800">{msg}</p>}
      {err && <div className="mt-2"><ErrorBox error={err} /></div>}
    </div>
  );
}

function ImportCard() {
  return (
    <Card title="استيراد بيانات خارجية">
      <p className="mb-3 text-sm text-slate-500">ادمج بيانات جمعتها أدوات أخرى في جرد راصد — دون إجراء أي فحص جديد.</p>
      <div className="grid gap-3 md:grid-cols-2">{ADAPTERS.map((ad) => <FileImport key={ad.key} ad={ad} />)}</div>
    </Card>
  );
}

export function ScansPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const query = useQuery({
    queryKey: ["jobs", "history", page],
    queryFn: () => api<Page<Job>>("/api/scans", { query: { page, page_size: 20 } }),
    placeholderData: keepPreviousData,
    refetchInterval: (q) => (q.state.data?.items.some((j) => j.status === "queued" || j.status === "running") ? 2000 : false),
  });
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">سجل الفحوصات</h1>
      {can("scan:run") && <ImportCard />}
      <Card>
        {query.isLoading ? <Loading /> : query.error ? <ErrorBox error={query.error} /> : (
          <>
            <JobsList jobs={query.data?.items ?? []} onChange={() => void qc.invalidateQueries({ queryKey: ["jobs"] })} />
            {query.data && <Pager page={page} pageSize={query.data.page_size} total={query.data.total} onPage={setPage} />}
          </>
        )}
      </Card>
    </div>
  );
}

function DiffList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <div className="text-sm font-semibold">{title} ({items.length})</div>
      {items.length === 0 ? <div className="text-xs text-slate-500">لا يوجد</div> : (
        <ul className="mt-1 max-h-48 overflow-y-auto text-xs">{items.map((i) => <li key={i}><Ltr>{i}</Ltr></li>)}</ul>
      )}
    </div>
  );
}

export function ScanDetailPage() {
  const { id } = useParams();
  const jobId = Number(id);
  const [page, setPage] = useState(1);
  const job = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api<Job>(`/api/scans/${jobId}`),
    refetchInterval: (q) => (q.state.data && (q.state.data.status === "queued" || q.state.data.status === "running") ? 2000 : false),
  });
  const finished = !!job.data && job.data.status !== "queued" && job.data.status !== "running";
  const results = useQuery({
    queryKey: ["job-results", jobId, page, job.data?.processed_hosts],
    queryFn: () => api<Page<ScanResult>>(`/api/scans/${jobId}/results`, { query: { page, page_size: 50 } }),
    enabled: !!job.data,
    placeholderData: keepPreviousData,
  });
  const diff = useQuery({ queryKey: ["job-diff", jobId], queryFn: () => api<ScanDiff>(`/api/scans/${jobId}/diff`), enabled: finished });

  if (job.isLoading) return <Loading />;
  if (job.error || !job.data) return <ErrorBox error={job.error ?? "الفحص غير موجود"} />;
  const j = job.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Link to="/scans" className="text-sm text-cyan-800 underline">سجل الفحوصات</Link>
        <h1 className="text-2xl font-bold">فحص #{j.id}</h1>
        <Badge tone={STATUS_TONE[j.status]}>{label(JOB_STATUS, j.status)}</Badge>
      </div>
      <JobsList jobs={[j]} onChange={() => void job.refetch()} />
      {finished && diff.data && (
        <Card title={diff.data.previous_job_id ? `مقارنة مع الفحص المكتمل السابق #${diff.data.previous_job_id}` : "مقارنة الفحوص"}>
          {diff.data.previous_job_id === null ? <p className="text-sm text-slate-500">لا يوجد فحص مكتمل سابق على هذا النطاق للمقارنة.</p> : (
            <div className="grid gap-4 md:grid-cols-4">
              <DiffList title="أجهزة جديدة" items={diff.data.new_hosts} />
              <DiffList title="أجهزة لم تستجب" items={diff.data.missing_hosts} />
              <DiffList title="خدمات جديدة" items={diff.data.new_services} />
              <DiffList title="خدمات لم تعد مفتوحة" items={diff.data.closed_services} />
            </div>
          )}
          {j.status !== "completed" && <p className="mt-2 text-xs text-amber-700">هذا الفحص لم يكتمل؛ قد تكون الفروق ناتجة عن عدم فحص كل العناوين.</p>}
        </Card>
      )}
      <Card title="الأجهزة المستجيبة في هذا الفحص">
        {results.isLoading ? <Loading /> : results.error ? <ErrorBox error={results.error} /> : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead><tr className="border-b bg-slate-50">
                  <th className="px-3 py-2 text-start">العنوان</th><th className="px-3 py-2 text-start">الاسم</th><th className="px-3 py-2 text-start">MAC</th>
                  <th className="px-3 py-2 text-start">طريقة الاستجابة</th><th className="px-3 py-2 text-start">المنافذ المفتوحة</th><th className="px-3 py-2 text-start">الوقت</th>
                </tr></thead>
                <tbody>
                  {results.data?.items.map((r) => (
                    <tr key={r.id} className="border-b border-slate-100">
                      <td className="px-3 py-2">{r.asset_id ? <Link to={`/assets/${r.asset_id}`} className="text-cyan-800 underline"><Ltr>{r.ip}</Ltr></Link> : <Ltr>{r.ip}</Ltr>}</td>
                      <td className="px-3 py-2">{r.hostname ? <Ltr>{r.hostname}</Ltr> : "—"}</td>
                      <td className="px-3 py-2">{r.mac ? <Ltr>{r.mac}</Ltr> : "—"}</td>
                      <td className="px-3 py-2">{r.liveness_methods.map((m) => label(METHODS, m)).join("، ")}</td>
                      <td className="px-3 py-2"><Ltr>{r.open_ports.join(", ") || "—"}</Ltr></td>
                      <td className="px-3 py-2 whitespace-nowrap">{formatDate(r.observed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {results.data && results.data.total === 0 && <p className="py-4 text-center text-sm text-slate-500">لم يستجب أي جهاز حتى الآن.</p>}
            {results.data && <Pager page={page} pageSize={results.data.page_size} total={results.data.total} onPage={setPage} />}
          </>
        )}
      </Card>
    </div>
  );
}
