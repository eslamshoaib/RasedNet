import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, ErrorBox, Loading, Ltr, Pager, STATUS_TONE } from "../components/ui";
import { formatDate } from "../format";
import { getLang, t } from "../i18n";
import { JOB_STATUS, label, METHODS } from "../labels";
import type { Job, Page, ScanDiff, ScanResult } from "../types";
import { JobsList } from "./Discovery";

function readCsrf(): string | null {
  for (const part of document.cookie.split(";")) {
    const [k, ...r] = part.trim().split("=");
    if (k === "rasednet_csrf") return decodeURIComponent(r.join("="));
  }
  return null;
}

interface Adapter { key: string; title: string; accept: string; contentType: string; hint: string; summary: (d: Record<string, number>) => string }

const assetSummary = (d: Record<string, number>) => getLang() === "en"
  ? `Devices: new ${d.assets_new}, updated ${d.assets_updated}.`
  : `أجهزة: جديد ${d.assets_new}، محدّث ${d.assets_updated}.`;
const vulnSummary = (d: Record<string, number>) => getLang() === "en"
  ? `Findings: ${d.findings} on ${d.matched_assets} device(s) (unmatched ${d.unmatched}).`
  : `نتائج: ${d.findings} على ${d.matched_assets} جهازاً (غير مطابق ${d.unmatched}).`;

function adapters(): Adapter[] {
  return [
    { key: "nmap", title: t("نتائج Nmap (XML)", "Nmap results (XML)"), accept: ".xml,application/xml", contentType: "application/xml",
      hint: t("ملف nmap -oX — يُدمج في الجرد دون فحص.", "An nmap -oX file — merged into the inventory without scanning."),
      summary: (d) => getLang() === "en" ? `Devices: new ${d.assets_new}, updated ${d.assets_updated}; new ports ${d.services_new}.` : `أجهزة: جديد ${d.assets_new}، محدّث ${d.assets_updated}؛ منافذ جديدة ${d.services_new}.` },
    { key: "dhcp", title: t("حجوزات DHCP", "DHCP leases"), accept: ".leases,.txt,text/plain", contentType: "text/plain",
      hint: t("ملف dhcpd.leases أو dnsmasq.leases.", "A dhcpd.leases or dnsmasq.leases file."), summary: assetSummary },
    { key: "csv", title: t("جرد أجهزة (CSV)", "Device inventory (CSV)"), accept: ".csv,text/csv", contentType: "text/plain",
      hint: t("تصدير من متحكّم واي-فاي أو MDM أو جدول (أعمدة ip/mac/hostname/type/os).", "Export from a Wi-Fi controller, MDM or spreadsheet (ip/mac/hostname/type/os columns)."), summary: assetSummary },
    { key: "greenbone", title: t("تقرير ثغرات Greenbone/OpenVAS", "Greenbone/OpenVAS vulnerability report"), accept: ".xml,application/xml", contentType: "application/xml",
      hint: t("تقرير OpenVAS XML — يربط الثغرات بالأجهزة المعروفة.", "An OpenVAS XML report — links vulnerabilities to known devices."), summary: vulnSummary },
    { key: "nessus", title: t("تقرير ثغرات Nessus", "Nessus vulnerability report"), accept: ".nessus,.xml,application/xml", contentType: "application/xml",
      hint: t("ملف ‎.nessus‎ — يربط الثغرات بالأجهزة المعروفة.", "A .nessus file — links vulnerabilities to known devices."), summary: vulnSummary },
    { key: "wazuh", title: t("ثغرات Wazuh (JSON)", "Wazuh vulnerabilities (JSON)"), accept: ".json,application/json", contentType: "application/json",
      hint: t("تصدير كاشف ثغرات Wazuh (JSON).", "Wazuh vulnerability-detector export (JSON)."), summary: vulnSummary },
    { key: "osquery", title: t("جرد osquery (JSON)", "osquery inventory (JSON)"), accept: ".json,application/json", contentType: "application/json",
      hint: t("نتائج osquery (system_info / interface_addresses).", "osquery results (system_info / interface_addresses)."), summary: assetSummary },
  ];
}

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
        headers: { "Content-Type": ad.contentType, "X-Lang": getLang(), ...(token ? { "X-CSRF-Token": token } : {}) },
        body: await file.text(),
      });
      const data = await resp.json().catch(() => null);
      if (!resp.ok) throw new ApiError(resp.status, typeof data?.detail === "string" ? data.detail : t("تعذر الاستيراد", "Import failed"));
      setMsg(ad.summary(data));
      void qc.invalidateQueries();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("تعذر الاستيراد", "Import failed"));
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
      {busy && <span className="ms-2 text-sm text-slate-500">{t("جارٍ الاستيراد…", "Importing…")}</span>}
      {msg && <p className="mt-2 rounded-lg bg-emerald-50 px-2 py-1 text-xs text-emerald-800">{msg}</p>}
      {err && <div className="mt-2"><ErrorBox error={err} /></div>}
    </div>
  );
}

function ImportCard() {
  return (
    <Card title={t("استيراد بيانات خارجية", "Import external data")}>
      <p className="mb-3 text-sm text-slate-500">{t("ادمج بيانات جمعتها أدوات أخرى في جرد راصد — دون إجراء أي فحص جديد.", "Merge data collected by other tools into RasedNet's inventory — without running any new scan.")}</p>
      <div className="grid gap-3 md:grid-cols-2">{adapters().map((ad) => <FileImport key={ad.key} ad={ad} />)}</div>
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
      <h1 className="text-2xl font-bold">{t("سجل الفحوصات", "Scan history")}</h1>
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
      {items.length === 0 ? <div className="text-xs text-slate-500">{t("لا يوجد", "None")}</div> : (
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
  if (job.error || !job.data) return <ErrorBox error={job.error ?? t("الفحص غير موجود", "Scan not found")} />;
  const j = job.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Link to="/scans" className="text-sm text-cyan-800 underline">{t("سجل الفحوصات", "Scan history")}</Link>
        <h1 className="text-2xl font-bold">{t("فحص", "Scan")} #{j.id}</h1>
        <Badge tone={STATUS_TONE[j.status]}>{label(JOB_STATUS, j.status)}</Badge>
      </div>
      <JobsList jobs={[j]} onChange={() => void job.refetch()} />
      {finished && diff.data && (
        <Card title={diff.data.previous_job_id ? (getLang() === "en" ? `Comparison with the previous completed scan #${diff.data.previous_job_id}` : `مقارنة مع الفحص المكتمل السابق #${diff.data.previous_job_id}`) : t("مقارنة الفحوص", "Scan comparison")}>
          {diff.data.previous_job_id === null ? <p className="text-sm text-slate-500">{t("لا يوجد فحص مكتمل سابق على هذا النطاق للمقارنة.", "No previous completed scan on this scope to compare with.")}</p> : (
            <div className="grid gap-4 md:grid-cols-4">
              <DiffList title={t("أجهزة جديدة", "New devices")} items={diff.data.new_hosts} />
              <DiffList title={t("أجهزة لم تستجب", "Devices that did not respond")} items={diff.data.missing_hosts} />
              <DiffList title={t("خدمات جديدة", "New services")} items={diff.data.new_services} />
              <DiffList title={t("خدمات لم تعد مفتوحة", "Services no longer open")} items={diff.data.closed_services} />
            </div>
          )}
          {j.status !== "completed" && <p className="mt-2 text-xs text-amber-700">{t("هذا الفحص لم يكتمل؛ قد تكون الفروق ناتجة عن عدم فحص كل العناوين.", "This scan did not finish; the differences may be because not all addresses were scanned.")}</p>}
        </Card>
      )}
      <Card title={t("الأجهزة المستجيبة في هذا الفحص", "Devices that responded in this scan")}>
        {results.isLoading ? <Loading /> : results.error ? <ErrorBox error={results.error} /> : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead><tr className="border-b bg-slate-50">
                  <th className="px-3 py-2 text-start">{t("العنوان", "Address")}</th><th className="px-3 py-2 text-start">{t("الاسم", "Name")}</th><th className="px-3 py-2 text-start">MAC</th>
                  <th className="px-3 py-2 text-start">{t("طريقة الاستجابة", "Liveness method")}</th><th className="px-3 py-2 text-start">{t("المنافذ المفتوحة", "Open ports")}</th><th className="px-3 py-2 text-start">{t("الوقت", "Time")}</th>
                </tr></thead>
                <tbody>
                  {results.data?.items.map((r) => (
                    <tr key={r.id} className="border-b border-slate-100">
                      <td className="px-3 py-2">{r.asset_id ? <Link to={`/assets/${r.asset_id}`} className="text-cyan-800 underline"><Ltr>{r.ip}</Ltr></Link> : <Ltr>{r.ip}</Ltr>}</td>
                      <td className="px-3 py-2">{r.hostname ? <Ltr>{r.hostname}</Ltr> : "—"}</td>
                      <td className="px-3 py-2">{r.mac ? <Ltr>{r.mac}</Ltr> : "—"}</td>
                      <td className="px-3 py-2">{r.liveness_methods.map((m) => label(METHODS, m)).join(t("، ", ", "))}</td>
                      <td className="px-3 py-2"><Ltr>{r.open_ports.join(", ") || "—"}</Ltr></td>
                      <td className="px-3 py-2 whitespace-nowrap">{formatDate(r.observed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {results.data && results.data.total === 0 && <p className="py-4 text-center text-sm text-slate-500">{t("لم يستجب أي جهاز حتى الآن.", "No device has responded yet.")}</p>}
            {results.data && <Pager page={page} pageSize={results.data.page_size} total={results.data.total} onPage={setPage} />}
          </>
        )}
      </Card>
    </div>
  );
}
