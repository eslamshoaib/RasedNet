import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api, downloadGet, errorMessage } from "../api";
import { useAuth } from "../auth";
import { IconRefresh } from "../components/icons";
import { Badge, Button, Card, ErrorBox, inputClass, Loading, Ltr, Stat } from "../components/ui";
import type { Tone } from "../components/ui";
import type { CveImportResult, Vulnerability, VulnSummary } from "../types";

const SEV_TONE: Record<string, Tone> = { critical: "red", high: "orange", medium: "amber", low: "green", unknown: "slate" };
const SEV_AR: Record<string, string> = { critical: "حرِج", high: "مرتفع", medium: "متوسط", low: "منخفض", unknown: "غير محدد" };

export function VulnerabilitiesPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const summary = useQuery({ queryKey: ["vuln-summary"], queryFn: () => api<VulnSummary>("/api/cve/summary") });
  const [sev, setSev] = useState("");
  const [statusFilter, setStatusFilter] = useState("open");
  const vulns = useQuery({
    queryKey: ["vulns", sev, statusFilter],
    queryFn: () => api<Vulnerability[]>("/api/cve/vulnerabilities", { query: { severity: sev || undefined, status_filter: statusFilter } }),
  });
  const [feedText, setFeedText] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const refreshAll = () => { void qc.invalidateQueries({ queryKey: ["vuln-summary"] }); void qc.invalidateQueries({ queryKey: ["vulns"] }); };

  const importFeed = useMutation({
    mutationFn: (payload: unknown) => api<CveImportResult>("/api/cve/import", { method: "POST", body: payload }),
    onSuccess: (r) => { setMsg(`استُوردت ${r.import.total} ثغرة (جديدة ${r.import.added}، محدّثة ${r.import.updated})، وطُوبقت ${r.correlation.matched} نتيجة على الأجهزة.`); setErr(null); setFeedText(""); refreshAll(); },
    onError: (e) => { setErr(errorMessage(e)); setMsg(null); },
  });
  const correlate = useMutation({
    mutationFn: () => api<CveImportResult["correlation"]>("/api/cve/correlate", { method: "POST" }),
    onSuccess: (r) => { setMsg(`أُعيدت المطابقة: ${r.matched} نتيجة مفتوحة، ${r.resolved} أُغلقت.`); setErr(null); refreshAll(); },
    onError: (e) => { setErr(errorMessage(e)); setMsg(null); },
  });

  const submitText = () => {
    setErr(null);
    let parsed: unknown;
    try { parsed = JSON.parse(feedText); } catch { setErr("النص ليس JSON صالحاً."); return; }
    importFeed.mutate(parsed);
  };
  const onFile = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { try { importFeed.mutate(JSON.parse(String(reader.result))); } catch { setErr("الملف ليس JSON صالحاً."); } };
    reader.readAsText(file);
  };
  const uploadKev = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      let data: unknown;
      try { data = JSON.parse(String(reader.result)); } catch { setErr("ملف KEV ليس JSON صالحاً."); return; }
      api<{ flagged: number }>("/api/cve/kev", { method: "POST", body: data })
        .then((r) => { setMsg(`عُلِّمت ${r.flagged} ثغرة كمُستغَلّة فعلياً (KEV).`); setErr(null); refreshAll(); })
        .catch((e) => setErr(errorMessage(e)));
    };
    reader.readAsText(file);
  };
  const uploadEpss = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const token = document.cookie.split(";").map((c) => c.trim()).find((c) => c.startsWith("rased_csrf="))?.split("=")[1];
        const resp = await fetch("/api/cve/epss", { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "text/csv", ...(token ? { "X-CSRF-Token": decodeURIComponent(token) } : {}) },
          body: String(reader.result) });
        const d = await resp.json();
        if (!resp.ok) throw new Error(typeof d?.detail === "string" ? d.detail : "تعذر الاستيراد");
        setMsg(`حُدِّثت درجات EPSS لـ${d.updated} ثغرة.`); setErr(null); refreshAll();
      } catch (e) { setErr(e instanceof Error ? e.message : "تعذر استيراد EPSS"); }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">الثغرات الأمنية (CVE)</h1>
        <p className="text-sm text-slate-500">
          استورد تغذية ثغرات محليّة (JSON) — يطابقها راصد مع المنتجات والإصدارات المكتشفة في الشبكة. يعمل دون اتصال بالكامل.
        </p>
      </div>

      {summary.isLoading ? <Loading /> : summary.data && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
          <Stat label="سجلات CVE المستوردة" value={summary.data.cve_entries} tone="blue" />
          <Stat label="نتائج مفتوحة" value={summary.data.open_findings} tone={summary.data.open_findings ? "amber" : "green"} />
          <Stat label="مُستغَلّة فعلياً (KEV)" value={summary.data.kev_open_findings ?? 0} tone={(summary.data.kev_open_findings ?? 0) ? "red" : "green"} hint="CISA KEV" />
          <Stat label="أجهزة متأثرة" value={summary.data.affected_assets} tone="purple" />
          {summary.data.by_severity.map((s) => (
            <Stat key={s.severity} label={SEV_AR[s.severity] ?? s.severity} value={s.count} tone={SEV_TONE[s.severity] ?? "slate"} />
          ))}
        </div>
      )}

      {can("data:manage") && (
        <Card title="استيراد تغذية الثغرات">
          <div className="grid gap-3 lg:grid-cols-2">
            <div>
              <label className="mb-1 block text-sm text-slate-600">رفع ملف JSON</label>
              <input type="file" accept="application/json,.json" className="text-sm" onChange={(e) => onFile(e.target.files?.[0])} />
              <p className="mt-2 text-xs text-slate-500">
                الصيغة: قائمة من العناصر، كل عنصر <Ltr>{`{cve_id, cvss_score, description, affected:[{product, version_start, version_end, version_exact}]}`}</Ltr>.
                يقبل راصد أيضاً صيغة NVD المبسّطة.
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button variant="secondary" onClick={() => correlate.mutate()} disabled={correlate.isPending}>
                  <IconRefresh className="h-4 w-4" /> إعادة المطابقة الآن
                </Button>
                <Button variant="secondary" onClick={() => downloadGet("/api/cve/export", "rased-cve-feed.json").catch((e) => setErr(errorMessage(e)))}>
                  ⬇ تنزيل التغذية (JSON) للتعديل
                </Button>
              </div>
              <p className="mt-1 text-xs text-slate-500">
                نزّل الملف، عدّله أو أضف ثغرات جديدة (بآخر تحديثات NVD مثلاً)، ثم ارفعه هنا من جديد. العمل دون اتصال — لا يجلب راصد التحديثات من الإنترنت تلقائياً.
              </p>
              <div className="mt-3 grid gap-2 border-t border-slate-100 pt-2 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-semibold text-slate-600">تحديث EPSS (CSV من FIRST.org)</label>
                  <input type="file" accept=".csv,text/csv" className="text-xs" onChange={(e) => uploadEpss(e.target.files?.[0])} />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-semibold text-slate-600">تحديث CISA KEV (JSON)</label>
                  <input type="file" accept=".json,application/json" className="text-xs" onChange={(e) => uploadKev(e.target.files?.[0])} />
                </div>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">EPSS = احتمالية الاستغلال، KEV = ثغرات مُستغَلّة فعلياً — يرفعان أولوية المعالجة تلقائياً.</p>
            </div>
            <div>
              <label className="mb-1 block text-sm text-slate-600">أو ألصق JSON مباشرة</label>
              <textarea dir="ltr" className={`${inputClass} h-28 font-mono text-xs`} value={feedText} onChange={(e) => setFeedText(e.target.value)}
                placeholder='[{"cve_id":"CVE-2023-1111","cvss_score":9.8,"affected":[{"product":"OpenSSH","version_end":"8.0"}]}]' />
              <div className="mt-2"><Button onClick={submitText} disabled={importFeed.isPending || !feedText.trim()}>استيراد ومطابقة</Button></div>
            </div>
          </div>
          {msg && <p className="mt-2 rounded-lg bg-emerald-50 px-3 py-1.5 text-sm text-emerald-800">{msg}</p>}
          {err && <div className="mt-2"><ErrorBox error={err} /></div>}
        </Card>
      )}

      <Card title="النتائج" actions={
        <div className="flex gap-2">
          <select className={`${inputClass} w-auto`} value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">كل الخطورات</option>
            {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{SEV_AR[s]}</option>)}
          </select>
          <select className={`${inputClass} w-auto`} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="open">مفتوحة</option>
            <option value="resolved">مُغلقة</option>
            <option value="all">الكل</option>
          </select>
        </div>
      }>
        {vulns.isLoading ? <Loading /> : vulns.error ? <ErrorBox error={vulns.error} /> : !vulns.data?.length ? (
          <p className="text-sm text-slate-500">لا توجد نتائج. استورد تغذية ثغرات لتبدأ المطابقة.</p>
        ) : (
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2">الأولوية</th><th className="p-2 text-start">CVE</th><th className="p-2">الخطورة</th><th className="p-2">CVSS</th><th className="p-2">EPSS</th>
                <th className="p-2 text-start">الجهاز</th><th className="p-2 text-start">المنتج</th><th className="p-2 text-start">المطابقة</th>
              </tr></thead>
              <tbody>
                {vulns.data.map((v) => (
                  <tr key={v.id} className="border-b border-slate-100 align-top">
                    <td className="p-2 text-center"><Badge tone={SEV_TONE[v.priority_band] ?? "slate"}>{v.priority}</Badge></td>
                    <td className="p-2"><Ltr className="font-mono font-medium">{v.cve_id}</Ltr>
                      {v.kev && <Badge tone="red">مُستغَلّة فعلياً (KEV)</Badge>}
                      {v.description && <div className="max-w-md text-xs text-slate-500">{v.description}</div>}
                      {v.references[0] && <Ltr className="block max-w-md truncate text-xs text-cyan-700">{v.references[0]}</Ltr>}
                    </td>
                    <td className="p-2 text-center"><Badge tone={SEV_TONE[v.severity] ?? "slate"}>{SEV_AR[v.severity] ?? v.severity}</Badge></td>
                    <td className="p-2 text-center font-mono">{v.cvss_score || "—"}</td>
                    <td className="p-2 text-center font-mono text-xs">{v.epss ? `${Math.round(v.epss * 100)}%` : "—"}</td>
                    <td className="p-2">{v.asset_id ? <Link className="text-cyan-800 underline" to={`/assets/${v.asset_id}`}><Ltr>{v.asset_ip ?? v.asset_name ?? `#${v.asset_id}`}</Ltr></Link> : "—"}</td>
                    <td className="p-2"><Ltr>{v.product}{v.version ? ` ${v.version}` : ""}</Ltr></td>
                    <td className="p-2 text-xs text-slate-500">{v.matched_on}{v.status === "resolved" && <Badge tone="slate">مُغلقة</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
