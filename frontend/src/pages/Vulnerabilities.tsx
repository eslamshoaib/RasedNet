import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api, downloadGet, errorMessage } from "../api";
import { useAuth } from "../auth";
import { IconRefresh } from "../components/icons";
import { Badge, Button, Card, ErrorBox, inputClass, Loading, Ltr, Stat } from "../components/ui";
import type { Tone } from "../components/ui";
import { getLang, t } from "../i18n";
import type { CveImportResult, Vulnerability, VulnSummary } from "../types";

const SEV_TONE: Record<string, Tone> = { critical: "red", high: "orange", medium: "amber", low: "green", unknown: "slate" };
const SEV_AR: Record<string, string> = { critical: "حرِج", high: "مرتفع", medium: "متوسط", low: "منخفض", unknown: "غير محدد" };
const SEV_EN: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", unknown: "Unknown" };
const sevName = (s: string): string => (getLang() === "en" ? (SEV_EN[s] ?? s) : (SEV_AR[s] ?? s));

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
    onSuccess: (r) => { setMsg(getLang() === "en" ? `Imported ${r.import.total} CVE(s) (new ${r.import.added}, updated ${r.import.updated}); matched ${r.correlation.matched} finding(s) on devices.` : `استُوردت ${r.import.total} ثغرة (جديدة ${r.import.added}، محدّثة ${r.import.updated})، وطُوبقت ${r.correlation.matched} نتيجة على الأجهزة.`); setErr(null); setFeedText(""); refreshAll(); },
    onError: (e) => { setErr(errorMessage(e)); setMsg(null); },
  });
  const correlate = useMutation({
    mutationFn: () => api<CveImportResult["correlation"]>("/api/cve/correlate", { method: "POST" }),
    onSuccess: (r) => { setMsg(getLang() === "en" ? `Re-matched: ${r.matched} open finding(s), ${r.resolved} closed.` : `أُعيدت المطابقة: ${r.matched} نتيجة مفتوحة، ${r.resolved} أُغلقت.`); setErr(null); refreshAll(); },
    onError: (e) => { setErr(errorMessage(e)); setMsg(null); },
  });

  const submitText = () => {
    setErr(null);
    let parsed: unknown;
    try { parsed = JSON.parse(feedText); } catch { setErr(t("النص ليس JSON صالحاً.", "The text is not valid JSON.")); return; }
    importFeed.mutate(parsed);
  };
  const onFile = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { try { importFeed.mutate(JSON.parse(String(reader.result))); } catch { setErr(t("الملف ليس JSON صالحاً.", "The file is not valid JSON.")); } };
    reader.readAsText(file);
  };
  const uploadKev = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      let data: unknown;
      try { data = JSON.parse(String(reader.result)); } catch { setErr(t("ملف KEV ليس JSON صالحاً.", "The KEV file is not valid JSON.")); return; }
      api<{ flagged: number }>("/api/cve/kev", { method: "POST", body: data })
        .then((r) => { setMsg(getLang() === "en" ? `Flagged ${r.flagged} CVE(s) as known-exploited (KEV).` : `عُلِّمت ${r.flagged} ثغرة كمُستغَلّة فعلياً (KEV).`); setErr(null); refreshAll(); })
        .catch((e) => setErr(errorMessage(e)));
    };
    reader.readAsText(file);
  };
  const uploadEpss = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const token = document.cookie.split(";").map((c) => c.trim()).find((c) => c.startsWith("rasednet_csrf="))?.split("=")[1];
        const resp = await fetch("/api/cve/epss", { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "text/csv", "X-Lang": getLang(), ...(token ? { "X-CSRF-Token": decodeURIComponent(token) } : {}) },
          body: String(reader.result) });
        const d = await resp.json();
        if (!resp.ok) throw new Error(typeof d?.detail === "string" ? d.detail : t("تعذر الاستيراد", "Import failed"));
        setMsg(getLang() === "en" ? `Updated EPSS scores for ${d.updated} CVE(s).` : `حُدِّثت درجات EPSS لـ${d.updated} ثغرة.`); setErr(null); refreshAll();
      } catch (e) { setErr(e instanceof Error ? e.message : t("تعذر استيراد EPSS", "Could not import EPSS")); }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">{t("الثغرات الأمنية (CVE)", "Vulnerabilities (CVE)")}</h1>
        <p className="text-sm text-slate-500">
          {t("استورد تغذية ثغرات محليّة (JSON) — يطابقها راصد مع المنتجات والإصدارات المكتشفة في الشبكة. يعمل دون اتصال بالكامل.", "Import a local vulnerability feed (JSON) — RasedNet matches it against the products and versions discovered on the network. Fully offline.")}
        </p>
      </div>

      {summary.isLoading ? <Loading /> : summary.data && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
          <Stat label={t("سجلات CVE المستوردة", "Imported CVE records")} value={summary.data.cve_entries} tone="blue" />
          <Stat label={t("نتائج مفتوحة", "Open findings")} value={summary.data.open_findings} tone={summary.data.open_findings ? "amber" : "green"} />
          <Stat label={t("مُستغَلّة فعلياً (KEV)", "Known-exploited (KEV)")} value={summary.data.kev_open_findings ?? 0} tone={(summary.data.kev_open_findings ?? 0) ? "red" : "green"} hint="CISA KEV" />
          <Stat label={t("أجهزة متأثرة", "Affected devices")} value={summary.data.affected_assets} tone="purple" />
          {summary.data.by_severity.map((s) => (
            <Stat key={s.severity} label={sevName(s.severity)} value={s.count} tone={SEV_TONE[s.severity] ?? "slate"} />
          ))}
        </div>
      )}

      {can("data:manage") && (
        <Card title={t("استيراد تغذية الثغرات", "Import vulnerability feed")}>
          <div className="grid gap-3 lg:grid-cols-2">
            <div>
              <label className="mb-1 block text-sm text-slate-600">{t("رفع ملف JSON", "Upload a JSON file")}</label>
              <input type="file" accept="application/json,.json" className="text-sm" onChange={(e) => onFile(e.target.files?.[0])} />
              <p className="mt-2 text-xs text-slate-500">
                {t("الصيغة: قائمة من العناصر، كل عنصر", "Format: a list of items, each one")} <Ltr>{`{cve_id, cvss_score, description, affected:[{product, version_start, version_end, version_exact}]}`}</Ltr>.
                {t("يقبل راصد أيضاً صيغة NVD المبسّطة.", "RasedNet also accepts a simplified NVD shape.")}
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button variant="secondary" onClick={() => correlate.mutate()} disabled={correlate.isPending}>
                  <IconRefresh className="h-4 w-4" /> {t("إعادة المطابقة الآن", "Re-match now")}
                </Button>
                <Button variant="secondary" onClick={() => downloadGet("/api/cve/export", "rasednet-cve-feed.json").catch((e) => setErr(errorMessage(e)))}>
                  {t("⬇ تنزيل التغذية (JSON) للتعديل", "⬇ Download feed (JSON) to edit")}
                </Button>
              </div>
              <p className="mt-1 text-xs text-slate-500">
                {t("نزّل الملف، عدّله أو أضف ثغرات جديدة (بآخر تحديثات NVD مثلاً)، ثم ارفعه هنا من جديد. العمل دون اتصال — لا يجلب راصد التحديثات من الإنترنت تلقائياً.", "Download the file, edit it or add new CVEs (e.g. the latest NVD updates), then re-upload it here. Offline operation — RasedNet does not fetch updates from the internet automatically.")}
              </p>
              <div className="mt-3 grid gap-2 border-t border-slate-100 pt-2 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-semibold text-slate-600">{t("تحديث EPSS (CSV من FIRST.org)", "Update EPSS (CSV from FIRST.org)")}</label>
                  <input type="file" accept=".csv,text/csv" className="text-xs" onChange={(e) => uploadEpss(e.target.files?.[0])} />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-semibold text-slate-600">{t("تحديث CISA KEV (JSON)", "Update CISA KEV (JSON)")}</label>
                  <input type="file" accept=".json,application/json" className="text-xs" onChange={(e) => uploadKev(e.target.files?.[0])} />
                </div>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">{t("EPSS = احتمالية الاستغلال، KEV = ثغرات مُستغَلّة فعلياً — يرفعان أولوية المعالجة تلقائياً.", "EPSS = exploitation probability, KEV = known-exploited vulnerabilities — both automatically raise remediation priority.")}</p>
            </div>
            <div>
              <label className="mb-1 block text-sm text-slate-600">{t("أو ألصق JSON مباشرة", "Or paste JSON directly")}</label>
              <textarea dir="ltr" className={`${inputClass} h-28 font-mono text-xs`} value={feedText} onChange={(e) => setFeedText(e.target.value)}
                placeholder='[{"cve_id":"CVE-2023-1111","cvss_score":9.8,"affected":[{"product":"OpenSSH","version_end":"8.0"}]}]' />
              <div className="mt-2"><Button onClick={submitText} disabled={importFeed.isPending || !feedText.trim()}>{t("استيراد ومطابقة", "Import & match")}</Button></div>
            </div>
          </div>
          {msg && <p className="mt-2 rounded-lg bg-emerald-50 px-3 py-1.5 text-sm text-emerald-800">{msg}</p>}
          {err && <div className="mt-2"><ErrorBox error={err} /></div>}
        </Card>
      )}

      <Card title={t("النتائج", "Findings")} actions={
        <div className="flex gap-2">
          <select className={`${inputClass} w-auto`} value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">{t("كل الخطورات", "All severities")}</option>
            {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{sevName(s)}</option>)}
          </select>
          <select className={`${inputClass} w-auto`} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="open">{t("مفتوحة", "Open")}</option>
            <option value="resolved">{t("مُغلقة", "Resolved")}</option>
            <option value="all">{t("الكل", "All")}</option>
          </select>
        </div>
      }>
        {vulns.isLoading ? <Loading /> : vulns.error ? <ErrorBox error={vulns.error} /> : !vulns.data?.length ? (
          <p className="text-sm text-slate-500">{t("لا توجد نتائج. استورد تغذية ثغرات لتبدأ المطابقة.", "No findings. Import a vulnerability feed to start matching.")}</p>
        ) : (
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2">{t("الأولوية", "Priority")}</th><th className="p-2 text-start">CVE</th><th className="p-2">{t("الخطورة", "Severity")}</th><th className="p-2">CVSS</th><th className="p-2">EPSS</th>
                <th className="p-2 text-start">{t("الجهاز", "Device")}</th><th className="p-2 text-start">{t("المنتج", "Product")}</th><th className="p-2 text-start">{t("المطابقة", "Matched on")}</th>
              </tr></thead>
              <tbody>
                {vulns.data.map((v) => (
                  <tr key={v.id} className="border-b border-slate-100 align-top">
                    <td className="p-2 text-center"><Badge tone={SEV_TONE[v.priority_band] ?? "slate"}>{v.priority}</Badge></td>
                    <td className="p-2"><Ltr className="font-mono font-medium">{v.cve_id}</Ltr>
                      {v.kev && <Badge tone="red">{t("مُستغَلّة فعلياً (KEV)", "Known-exploited (KEV)")}</Badge>}
                      {v.description && <div className="max-w-md text-xs text-slate-500">{v.description}</div>}
                      {v.references[0] && <Ltr className="block max-w-md truncate text-xs text-cyan-700">{v.references[0]}</Ltr>}
                    </td>
                    <td className="p-2 text-center"><Badge tone={SEV_TONE[v.severity] ?? "slate"}>{sevName(v.severity)}</Badge></td>
                    <td className="p-2 text-center font-mono">{v.cvss_score || "—"}</td>
                    <td className="p-2 text-center font-mono text-xs">{v.epss ? `${Math.round(v.epss * 100)}%` : "—"}</td>
                    <td className="p-2">{v.asset_id ? <Link className="text-cyan-800 underline" to={`/assets/${v.asset_id}`}><Ltr>{v.asset_ip ?? v.asset_name ?? `#${v.asset_id}`}</Ltr></Link> : "—"}</td>
                    <td className="p-2"><Ltr>{v.product}{v.version ? ` ${v.version}` : ""}</Ltr></td>
                    <td className="p-2 text-xs text-slate-500">{v.matched_on}{v.status === "resolved" && <Badge tone="slate">{t("مُغلقة", "Resolved")}</Badge>}</td>
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
