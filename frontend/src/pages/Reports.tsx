import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api, downloadGet, errorMessage } from "../api";
import { Chart } from "../components/Chart";
import { IconDownload, IconRefresh } from "../components/icons";
import { Badge, Button, Card, ErrorBox, Loading, Ltr, Stat } from "../components/ui";
import type { Tone } from "../components/ui";
import { getLang, t } from "../i18n";
import type { ExposedPort, GuidanceCommand, NetworkReport } from "../types";
// GuidanceCommand / ServiceGuidance are shared with the asset-detail guidance view.

const RISK_TONE: Record<string, Tone> = { critical: "red", high: "orange", medium: "amber", low: "green" };
const RISK_EN: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const RISK_AR: Record<string, string> = { critical: "حرِج", high: "مرتفع", medium: "متوسط", low: "منخفض" };
const PRIORITY_EN: Record<string, string> = { high: "High", medium: "Medium", low: "Low" };
const PRIORITY_AR: Record<string, string> = { high: "عالية", medium: "متوسطة", low: "منخفضة" };
const PRIORITY_TONE: Record<string, Tone> = { high: "red", medium: "amber", low: "slate" };
const PIE = ["#0ea5e9", "#e11d48", "#f59e0b", "#16a34a", "#7c3aed", "#0d9488", "#be185d", "#64748b", "#9333ea", "#4f46e5"];

const riskName = (b: string): string => (getLang() === "en" ? (RISK_EN[b] ?? b) : (RISK_AR[b] ?? b));
const priorityName = (p: string): string => (getLang() === "en" ? (PRIORITY_EN[p] ?? p) : (PRIORITY_AR[p] ?? p));

function fmt(iso: string | null): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(getLang() === "en" ? "en-GB" : "ar-EG", { dateStyle: "medium", timeStyle: "short" }); } catch { return iso; }
}

function CommandBlock({ cmd }: { cmd: GuidanceCommand }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-2">
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-slate-700">{cmd.label_ar}</span>
        <div className="flex items-center gap-1">
          <span className="rounded bg-slate-200 px-1.5 py-0.5 text-[10px] text-slate-600">{cmd.shell === "bash" ? "Bash" : "PowerShell"}</span>
          <button type="button" className="rounded bg-white px-1.5 py-0.5 text-[10px] text-cyan-800 ring-1 ring-slate-200 hover:bg-cyan-50 no-print"
            onClick={() => { void navigator.clipboard?.writeText(cmd.command); setCopied(true); window.setTimeout(() => setCopied(false), 1200); }}>
            {copied ? t("تم النسخ", "Copied") : t("نسخ", "Copy")}
          </button>
        </div>
      </div>
      <pre dir="ltr" className="ltr overflow-auto whitespace-pre-wrap break-all rounded bg-slate-900 px-2 py-1.5 text-[11px] text-slate-100">{cmd.command}</pre>
    </div>
  );
}

function PortGuidance({ port }: { port: ExposedPort }) {
  const g = port.guidance;
  if (!g) return <p className="text-xs text-slate-500">{t("لا توجد إرشادات لهذا المنفذ.", "No guidance for this port.")}</p>;
  return (
    <div className="space-y-3">
      {g.network_checks.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-semibold text-slate-700">{t("التحقق من بُعد (من خادم راصد)", "Remote check (from the RasedNet server)")}</div>
          <div className="grid gap-2 md:grid-cols-2">{g.network_checks.map((c, i) => <CommandBlock key={i} cmd={c} />)}</div>
        </div>
      )}
      {g.platforms.map((p, pi) => (
        <div key={pi} className="rounded-xl border border-slate-200 p-2">
          <div className="mb-1 text-sm font-semibold text-slate-800">{p.platform_ar}</div>
          {p.warnings_ar.map((w, i) => <p key={i} className="mb-1 rounded bg-amber-50 px-2 py-1 text-xs text-amber-900">{t("تحذير:", "Warning:")} {w}</p>)}
          {p.verify.length > 0 && <>
            <div className="mb-1 mt-1 text-xs font-semibold text-emerald-700">{t("التأكد أن الخدمة تعمل", "Confirm the service is running")}</div>
            <div className="grid gap-2 md:grid-cols-2">{p.verify.map((c, i) => <CommandBlock key={i} cmd={c} />)}</div>
          </>}
          {(p.disable.length > 0 || p.harden.length > 0) && <>
            <div className="mb-1 mt-2 text-xs font-semibold text-red-700">{t("الإغلاق والتأمين", "Disable & harden")}</div>
            <div className="grid gap-2 md:grid-cols-2">{[...p.disable, ...p.harden].map((c, i) => <CommandBlock key={i} cmd={c} />)}</div>
          </>}
          {p.notes_ar.map((n, i) => <p key={i} className="mt-1 text-xs text-slate-600">• {n}</p>)}
        </div>
      ))}
      <p className="text-xs text-emerald-800">{g.recheck_ar}</p>
    </div>
  );
}

export function ReportsPage() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["report", "network"], queryFn: () => api<NetworkReport>("/api/reports/network"),
  });
  const [openPort, setOpenPort] = useState<number | null>(null);
  const [dlError, setDlError] = useState<string | null>(null);
  const download = (fmtKind: "xlsx" | "json") => {
    setDlError(null);
    downloadGet(`/api/reports/network.${fmtKind}`, `rasednet-report.${fmtKind}`).catch((e) => setDlError(errorMessage(e)));
  };

  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorBox error={error ?? t("تعذر إنشاء التقرير", "Could not generate the report")} />;
  const s = data.summary;

  const pie = (items: { label_ar: string; count: number }[]) => ({
    tooltip: { trigger: "item" },
    legend: { bottom: 0, type: "scroll", textStyle: { fontSize: 11 } },
    series: [{ type: "pie", radius: ["40%", "70%"], center: ["50%", "45%"], data: items.map((d, i) => ({ name: d.label_ar, value: d.count, itemStyle: { color: PIE[i % PIE.length] } })), label: { show: false } }],
  });
  const bar = (items: { label_ar: string; count: number }[], color: string) => ({
    tooltip: { trigger: "axis" },
    grid: { left: 8, right: 16, top: 16, bottom: 8, containLabel: true },
    xAxis: { type: "value" },
    yAxis: { type: "category", data: items.map((d) => d.label_ar).reverse(), axisLabel: { fontSize: 11 } },
    series: [{ type: "bar", data: items.map((d) => d.count).reverse(), itemStyle: { color, borderRadius: [0, 4, 4, 0] } }],
  });

  return (
    <div className="space-y-4">
      <style>{`@media print {
        body * { visibility: hidden !important; }
        .rasednet-print, .rasednet-print * { visibility: visible !important; }
        .rasednet-print { position: absolute; inset: 0; width: 100%; padding: 0; }
        .no-print { display: none !important; }
        .print-break { break-inside: avoid; }
      }`}</style>

      <div className="flex flex-wrap items-end justify-between gap-3 no-print">
        <div>
          <h1 className="text-2xl font-bold">{t("التقارير", "Reports")}</h1>
          <p className="text-sm text-slate-500">{t("تقرير شامل لتقييم أمن الشبكة — يمكن طباعته حفظاً بصيغة PDF أو تنزيله Excel/JSON.", "A comprehensive network security-assessment report — printable to PDF or downloadable as Excel/JSON.")}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => refetch()} disabled={isFetching}><IconRefresh className="h-4 w-4" /> {t("تحديث", "Refresh")}</Button>
          <Button variant="secondary" onClick={() => window.print()}>🖨️ {t("طباعة / حفظ PDF", "Print / save PDF")}</Button>
          <Button onClick={() => download("xlsx")}><IconDownload className="h-4 w-4" /> {t("تنزيل Excel", "Download Excel")}</Button>
          <Button variant="secondary" onClick={() => download("json")}><IconDownload className="h-4 w-4" /> {t("تنزيل JSON", "Download JSON")}</Button>
        </div>
      </div>
      {dlError && <ErrorBox error={dlError} />}

      <div className="rasednet-print space-y-4">
        {/* Report header */}
        <Card className="print-break">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-xl font-bold text-cyan-900">{data.meta.title}</h2>
              <p className="text-sm text-slate-600">{data.meta.tool} — {t("الإصدار", "version")} {data.meta.version}</p>
              <p className="text-xs text-slate-500">{t("تاريخ الإنشاء:", "Generated:")} {fmt(data.meta.generated_at)}</p>
            </div>
            <div className="text-end">
              <Badge tone={RISK_TONE[s.overall_risk_band]}>{t("مستوى الخطورة العام:", "Overall risk level:")} {riskName(s.overall_risk_band)}</Badge>
              <p className="mt-1 text-xs text-slate-500">{t("النطاقات المعتمدة:", "Approved scopes:")} {data.meta.scope_count}</p>
            </div>
          </div>
          {data.meta.integrity_sha256 && (
            <p className="mt-2 break-all border-t border-slate-100 pt-2 text-[11px] text-slate-400">
              {t("بصمة السلامة (SHA-256):", "Integrity digest (SHA-256):")} <Ltr>{data.meta.integrity_sha256}</Ltr>
            </p>
          )}
        </Card>

        {/* Executive summary */}
        <section className="print-break">
          <h3 className="mb-2 text-lg font-bold">{t("الملخص التنفيذي", "Executive summary")}</h3>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label={t("إجمالي الأجهزة", "Total devices")} value={s.total_assets} tone="blue" />
            <Stat label={t("متصل الآن", "Online now")} value={s.online} tone="green" hint={`${t("غير متصل:", "Offline:")} ${s.offline}`} />
            <Stat label={t("الشبكات", "Networks")} value={s.networks} tone="teal" />
            <Stat label={t("الموجّهات وأجهزة الشبكة", "Routers & network gear")} value={s.routers} tone="purple" hint={`${t("بوابات:", "Gateways:")} ${s.gateways}`} />
            <Stat label={t("المنافذ المفتوحة", "Open ports")} value={s.open_services} tone="amber" hint={`${t("عالية الخطورة:", "High-risk:")} ${s.high_risk_ports}`} />
            <Stat label={t("أجهزة عالية التعرّض", "Highly exposed devices")} value={s.exposed_devices} tone="red" hint={t("‏5 خدمات مفتوحة أو أكثر", "5+ open services")} />
            <Stat label={t("ثغرات مفتوحة (CVE)", "Open vulnerabilities (CVE)")} value={s.open_vulnerabilities} tone={s.open_vulnerabilities ? "red" : "green"} />
            <Stat label={t("روابط فيزيائية", "Physical links")} value={s.physical_links} tone="teal" hint="SNMP/LLDP" />
            <Stat label={t("تنبيهات مفتوحة", "Open alerts")} value={s.open_alerts} tone={s.open_alerts ? "amber" : "green"} />
            <Stat label={t("تنبيهات حرجة", "Critical alerts")} value={s.critical_alerts} tone={s.critical_alerts ? "red" : "slate"} />
            <Stat label={t("تنبيهات مرتفعة", "High alerts")} value={s.high_alerts} tone={s.high_alerts ? "amber" : "slate"} />
            <Stat label={t("آخر فحص", "Last scan")} value={<span className="text-sm">{fmt(s.last_scan_at)}</span>} tone="slate" />
          </div>
        </section>

        {/* Distributions */}
        <section className="grid gap-4 lg:grid-cols-3 print-break">
          <Card title={t("توزيع أنواع الأجهزة", "Device-type distribution")}><Chart label={t("أنواع الأجهزة", "Device types")} height={240} option={pie(data.distributions.device_types)} /></Card>
          <Card title={t("أنظمة التشغيل", "Operating systems")}><Chart label={t("أنظمة التشغيل", "Operating systems")} height={240} option={pie(data.distributions.os_families)} /></Card>
          <Card title={t("تصنيف المنافذ المكشوفة", "Exposed-port categories")}><Chart label={t("تصنيف التعرّض", "Exposure categories")} height={240} option={bar(data.distributions.exposures, "#0ea5e9")} /></Card>
        </section>

        {/* Networks */}
        <Card title={t("تحليل الشبكات", "Network analysis")} className="print-break">
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2 text-start">{t("الشبكة", "Network")}</th><th className="p-2 text-start">{t("الاسم", "Name")}</th>
                <th className="p-2">{t("أجهزة", "Devices")}</th><th className="p-2">{t("متصل", "Online")}</th><th className="p-2">{t("موجّهات", "Routers")}</th>
                <th className="p-2">{t("بوابات", "Gateways")}</th><th className="p-2">{t("منافذ مفتوحة", "Open ports")}</th><th className="p-2">{t("الخطورة", "Risk")}</th>
                <th className="p-2 text-start">{t("أكثر المنافذ شيوعاً", "Most common ports")}</th>
              </tr></thead>
              <tbody>
                {data.networks.map((n) => (
                  <tr key={n.cidr} className="border-b border-slate-100">
                    <td className="p-2"><Ltr className="font-medium">{n.cidr}</Ltr></td>
                    <td className="p-2">{n.name ?? "—"}{!n.in_scope && <span className="ms-1 text-[10px] text-slate-400">{t("(غير معتمدة)", "(not approved)")}</span>}</td>
                    <td className="p-2 text-center">{n.devices}</td>
                    <td className="p-2 text-center">{n.online}</td>
                    <td className="p-2 text-center">{n.routers}</td>
                    <td className="p-2 text-center">{n.gateways}</td>
                    <td className="p-2 text-center">{n.open_service_count}</td>
                    <td className="p-2 text-center"><Badge tone={RISK_TONE[n.risk_band]}>{riskName(n.risk_band)}</Badge></td>
                    <td className="p-2"><Ltr className="text-xs text-slate-500">{n.top_ports.map((p) => `${p.port}×${p.count}`).join(t("، ", ", "))}</Ltr></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Recommendations */}
        <Card title={t("التوصيات ذات الأولوية", "Prioritised recommendations")} className="print-break">
          <ol className="space-y-2">
            {data.recommendations.map((r, i) => (
              <li key={i} className="flex items-start gap-2 rounded-xl border border-slate-200 p-2.5">
                <Badge tone={PRIORITY_TONE[r.priority]}>{priorityName(r.priority)}</Badge>
                <div><div className="font-semibold text-slate-800">{r.title_ar}</div><div className="text-sm text-slate-600">{r.detail_ar}</div></div>
              </li>
            ))}
          </ol>
        </Card>

        {/* Exposed ports with admin commands */}
        <Card title={t("المنافذ المكشوفة وأوامر التحقق والإغلاق", "Exposed ports with verify/close commands")}>
          <p className="mb-2 text-xs text-slate-500 no-print">{t("اضغط أي صف لعرض أوامر المسؤول: التأكد أن الخدمة تعمل، وكيفية إغلاقها وتأمينها.", "Click any row for admin commands: confirm the service is running, and how to disable and harden it.")}</p>
          <div className="space-y-2">
            {data.exposed_ports.map((p) => (
              <div key={`${p.port}-${p.service_name}`} className="rounded-xl border border-slate-200 print-break">
                <button type="button" onClick={() => setOpenPort(openPort === p.port ? null : p.port)}
                  className="flex w-full flex-wrap items-center justify-between gap-2 p-3 text-start hover:bg-slate-50">
                  <span className="flex items-center gap-2">
                    <Ltr className="font-mono font-bold text-cyan-900">{p.port}/{p.protocol}</Ltr>
                    <span className="font-medium">{p.service_name}</span>
                    {p.high_risk && <Badge tone="red">{t("عالي الخطورة", "High risk")}</Badge>}
                  </span>
                  <span className="flex items-center gap-2 text-sm text-slate-500">
                    <span>{getLang() === "en" ? `${p.count} device(s)` : `${p.count} جهاز`}</span>
                    <span className="no-print text-cyan-700">{openPort === p.port ? "▲" : "▼"}</span>
                  </span>
                </button>
                {p.risk_note_ar && <p className="px-3 pb-2 text-xs text-red-700">{p.risk_note_ar}</p>}
                {(openPort === p.port) && (
                  <div className="border-t border-slate-100 p-3">
                    <div className="mb-2 text-xs text-slate-600">{t("الأجهزة:", "Devices:")} {p.assets.map((a) => a.ip).filter(Boolean).slice(0, 20).join(t("، ", ", "))}{p.assets.length > 20 ? "…" : ""}</div>
                    <PortGuidance port={p} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>

        {/* Top exposed devices */}
        <Card title={t("أكثر الأجهزة تعرّضاً", "Most exposed devices")} className="print-break">
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2 text-start">{t("العنوان", "Address")}</th><th className="p-2 text-start">{t("الاسم", "Name")}</th><th className="p-2">{t("النوع", "Type")}</th>
                <th className="p-2">{t("خدمات", "Services")}</th><th className="p-2">{t("تنبيهات", "Alerts")}</th><th className="p-2">{t("الخطورة", "Risk")}</th><th className="p-2 text-start">{t("المنافذ", "Ports")}</th>
              </tr></thead>
              <tbody>
                {data.top_exposed_devices.map((d) => (
                  <tr key={d.id} className="border-b border-slate-100">
                    <td className="p-2"><Link className="text-cyan-800 underline" to={`/assets/${d.id}`}><Ltr>{d.ip}</Ltr></Link></td>
                    <td className="p-2">{d.name ?? "—"}{d.is_gateway && <Badge tone="amber">{t("بوابة", "Gateway")}</Badge>}</td>
                    <td className="p-2 text-center">{d.device_type_ar}</td>
                    <td className="p-2 text-center">{d.open_services}</td>
                    <td className="p-2 text-center">{d.open_alerts || "—"}</td>
                    <td className="p-2 text-center"><Badge tone={RISK_TONE[d.risk_band]}>{riskName(d.risk_band)}</Badge></td>
                    <td className="p-2"><Ltr className="text-xs text-slate-500">{d.ports.join(t("، ", ", "))}</Ltr></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Alerts */}
        {data.alerts.length > 0 && (
          <Card title={t("التنبيهات المرتفعة والحرجة", "High & critical alerts")} className="print-break">
            <div className="space-y-2">
              {data.alerts.map((a) => (
                <div key={a.id} className="flex items-start gap-2 rounded-xl border border-slate-200 p-2.5">
                  <Badge tone={a.severity === "critical" ? "red" : "amber"}>{a.severity_ar}</Badge>
                  <div>
                    <div className="font-semibold text-slate-800">{a.title_ar} {a.occurrences > 1 && <span className="text-xs text-slate-400">(×{a.occurrences})</span>}</div>
                    <div className="text-sm text-slate-600">{a.message_ar}</div>
                    <div className="text-xs text-slate-400">{t("آخر ظهور:", "Last seen:")} {fmt(a.last_seen)}{a.asset_id ? <> • <Link className="text-cyan-700 underline" to={`/assets/${a.asset_id}`}>{t("الجهاز", "Device")}</Link></> : null}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Vulnerabilities */}
        {data.vulnerabilities.open_findings > 0 && (
          <Card title={t("الثغرات الأمنية (CVE)", "Vulnerabilities (CVE)")} className="print-break">
            <p className="mb-2 text-sm text-slate-600">
              {getLang() === "en"
                ? `${data.vulnerabilities.open_findings} open finding(s) on ${data.vulnerabilities.affected_assets} device(s), out of ${data.vulnerabilities.cve_entries} imported CVE record(s).`
                : `${data.vulnerabilities.open_findings} نتيجة مفتوحة على ${data.vulnerabilities.affected_assets} جهازاً، من أصل ${data.vulnerabilities.cve_entries} سجل CVE مستورد.`}
            </p>
            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-slate-500">
                  <th className="p-2 text-start">CVE</th><th className="p-2">{t("الخطورة", "Severity")}</th><th className="p-2">{t("الدرجة", "Score")}</th>
                  <th className="p-2 text-start">{t("الجهاز", "Device")}</th><th className="p-2 text-start">{t("المنتج", "Product")}</th><th className="p-2 text-start">{t("المطابقة", "Matched on")}</th>
                </tr></thead>
                <tbody>
                  {data.vulnerabilities.top.map((v) => (
                    <tr key={`${v.cve_id}-${v.asset_id}`} className="border-b border-slate-100">
                      <td className="p-2"><Ltr className="font-mono">{v.cve_id}</Ltr></td>
                      <td className="p-2 text-center"><Badge tone={RISK_TONE[v.severity] ?? "slate"}>{v.severity_ar}</Badge></td>
                      <td className="p-2 text-center font-mono">{v.cvss_score || "—"}</td>
                      <td className="p-2"><Link className="text-cyan-800 underline" to={`/assets/${v.asset_id}`}>#{v.asset_id}</Link></td>
                      <td className="p-2"><Ltr>{v.product}{v.version ? ` ${v.version}` : ""}</Ltr></td>
                      <td className="p-2 text-xs text-slate-500">{v.matched_on}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* Scan history */}
        <Card title={t("آخر الفحوصات", "Recent scans")} className="print-break">
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2 text-start">#</th><th className="p-2 text-start">{t("النطاق", "Scope")}</th><th className="p-2">{t("الحالة", "Status")}</th>
                <th className="p-2">{t("أجهزة حيّة", "Live hosts")}</th><th className="p-2">{t("منافذ مفتوحة", "Open ports")}</th><th className="p-2 text-start">{t("انتهى", "Finished")}</th>
              </tr></thead>
              <tbody>
                {data.scan_history.map((j) => (
                  <tr key={j.id} className="border-b border-slate-100">
                    <td className="p-2"><Link className="text-cyan-800 underline" to={`/scans/${j.id}`}>{j.id}</Link></td>
                    <td className="p-2">{j.scope ?? "—"}</td>
                    <td className="p-2 text-center">{j.status}</td>
                    <td className="p-2 text-center">{j.alive_hosts}</td>
                    <td className="p-2 text-center">{j.open_services}</td>
                    <td className="p-2 text-center">{fmt(j.finished_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <p className="pb-4 text-center text-xs text-slate-400">{t("أُنشئ هذا التقرير بواسطة راصد (RasedNet) — أداة اكتشاف ومراقبة الشبكة. العمل دون اتصال، وكل البيانات محلية.", "This report was generated by RasedNet — a network discovery & monitoring tool. Offline operation, all data local.")}</p>
      </div>
    </div>
  );
}
