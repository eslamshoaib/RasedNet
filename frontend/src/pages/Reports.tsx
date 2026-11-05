import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api, downloadGet, errorMessage } from "../api";
import { Chart } from "../components/Chart";
import { IconDownload, IconRefresh } from "../components/icons";
import { Badge, Button, Card, ErrorBox, Loading, Ltr, Stat } from "../components/ui";
import type { Tone } from "../components/ui";
import type { ExposedPort, GuidanceCommand, NetworkReport } from "../types";
// GuidanceCommand / ServiceGuidance are shared with the asset-detail guidance view.

const RISK_TONE: Record<string, Tone> = { critical: "red", high: "orange", medium: "amber", low: "green" };
const RISK_AR: Record<string, string> = { critical: "حرِج", high: "مرتفع", medium: "متوسط", low: "منخفض" };
const PRIORITY_AR: Record<string, string> = { high: "عالية", medium: "متوسطة", low: "منخفضة" };
const PRIORITY_TONE: Record<string, Tone> = { high: "red", medium: "amber", low: "slate" };
const PIE = ["#0ea5e9", "#e11d48", "#f59e0b", "#16a34a", "#7c3aed", "#0d9488", "#be185d", "#64748b", "#9333ea", "#4f46e5"];

function fmt(iso: string | null): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString("ar-EG", { dateStyle: "medium", timeStyle: "short" }); } catch { return iso; }
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
            {copied ? "تم النسخ" : "نسخ"}
          </button>
        </div>
      </div>
      <pre dir="ltr" className="ltr overflow-auto whitespace-pre-wrap break-all rounded bg-slate-900 px-2 py-1.5 text-[11px] text-slate-100">{cmd.command}</pre>
    </div>
  );
}

function PortGuidance({ port }: { port: ExposedPort }) {
  const g = port.guidance;
  if (!g) return <p className="text-xs text-slate-500">لا توجد إرشادات لهذا المنفذ.</p>;
  return (
    <div className="space-y-3">
      {g.network_checks.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-semibold text-slate-700">التحقق من بُعد (من خادم راصد)</div>
          <div className="grid gap-2 md:grid-cols-2">{g.network_checks.map((c, i) => <CommandBlock key={i} cmd={c} />)}</div>
        </div>
      )}
      {g.platforms.map((p, pi) => (
        <div key={pi} className="rounded-xl border border-slate-200 p-2">
          <div className="mb-1 text-sm font-semibold text-slate-800">{p.platform_ar}</div>
          {p.warnings_ar.map((w, i) => <p key={i} className="mb-1 rounded bg-amber-50 px-2 py-1 text-xs text-amber-900">تحذير: {w}</p>)}
          {p.verify.length > 0 && <>
            <div className="mb-1 mt-1 text-xs font-semibold text-emerald-700">التأكد أن الخدمة تعمل</div>
            <div className="grid gap-2 md:grid-cols-2">{p.verify.map((c, i) => <CommandBlock key={i} cmd={c} />)}</div>
          </>}
          {(p.disable.length > 0 || p.harden.length > 0) && <>
            <div className="mb-1 mt-2 text-xs font-semibold text-red-700">الإغلاق والتأمين</div>
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
    downloadGet(`/api/reports/network.${fmtKind}`, `rased-report.${fmtKind}`).catch((e) => setDlError(errorMessage(e)));
  };

  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorBox error={error ?? "تعذر إنشاء التقرير"} />;
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
        .rased-print, .rased-print * { visibility: visible !important; }
        .rased-print { position: absolute; inset: 0; width: 100%; padding: 0; }
        .no-print { display: none !important; }
        .print-break { break-inside: avoid; }
      }`}</style>

      <div className="flex flex-wrap items-end justify-between gap-3 no-print">
        <div>
          <h1 className="text-2xl font-bold">التقارير</h1>
          <p className="text-sm text-slate-500">تقرير شامل لتقييم أمن الشبكة — يمكن طباعته حفظاً بصيغة PDF أو تنزيله Excel/JSON.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => refetch()} disabled={isFetching}><IconRefresh className="h-4 w-4" /> تحديث</Button>
          <Button variant="secondary" onClick={() => window.print()}>🖨️ طباعة / حفظ PDF</Button>
          <Button onClick={() => download("xlsx")}><IconDownload className="h-4 w-4" /> تنزيل Excel</Button>
          <Button variant="secondary" onClick={() => download("json")}><IconDownload className="h-4 w-4" /> تنزيل JSON</Button>
        </div>
      </div>
      {dlError && <ErrorBox error={dlError} />}

      <div className="rased-print space-y-4">
        {/* Report header */}
        <Card className="print-break">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-xl font-bold text-cyan-900">{data.meta.title}</h2>
              <p className="text-sm text-slate-600">{data.meta.tool} — الإصدار {data.meta.version}</p>
              <p className="text-xs text-slate-500">تاريخ الإنشاء: {fmt(data.meta.generated_at)}</p>
            </div>
            <div className="text-end">
              <Badge tone={RISK_TONE[s.overall_risk_band]}>مستوى الخطورة العام: {RISK_AR[s.overall_risk_band]}</Badge>
              <p className="mt-1 text-xs text-slate-500">النطاقات المعتمدة: {data.meta.scope_count}</p>
            </div>
          </div>
          {data.meta.integrity_sha256 && (
            <p className="mt-2 break-all border-t border-slate-100 pt-2 text-[11px] text-slate-400">
              بصمة السلامة (SHA-256): <Ltr>{data.meta.integrity_sha256}</Ltr>
            </p>
          )}
        </Card>

        {/* Executive summary */}
        <section className="print-break">
          <h3 className="mb-2 text-lg font-bold">الملخص التنفيذي</h3>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label="إجمالي الأجهزة" value={s.total_assets} tone="blue" />
            <Stat label="متصل الآن" value={s.online} tone="green" hint={`غير متصل: ${s.offline}`} />
            <Stat label="الشبكات" value={s.networks} tone="teal" />
            <Stat label="الموجّهات وأجهزة الشبكة" value={s.routers} tone="purple" hint={`بوابات: ${s.gateways}`} />
            <Stat label="المنافذ المفتوحة" value={s.open_services} tone="amber" hint={`عالية الخطورة: ${s.high_risk_ports}`} />
            <Stat label="أجهزة عالية التعرّض" value={s.exposed_devices} tone="red" hint="‏5 خدمات مفتوحة أو أكثر" />
            <Stat label="ثغرات مفتوحة (CVE)" value={s.open_vulnerabilities} tone={s.open_vulnerabilities ? "red" : "green"} />
            <Stat label="روابط فيزيائية" value={s.physical_links} tone="teal" hint="SNMP/LLDP" />
            <Stat label="تنبيهات مفتوحة" value={s.open_alerts} tone={s.open_alerts ? "amber" : "green"} />
            <Stat label="تنبيهات حرجة" value={s.critical_alerts} tone={s.critical_alerts ? "red" : "slate"} />
            <Stat label="تنبيهات مرتفعة" value={s.high_alerts} tone={s.high_alerts ? "amber" : "slate"} />
            <Stat label="آخر فحص" value={<span className="text-sm">{fmt(s.last_scan_at)}</span>} tone="slate" />
          </div>
        </section>

        {/* Distributions */}
        <section className="grid gap-4 lg:grid-cols-3 print-break">
          <Card title="توزيع أنواع الأجهزة"><Chart label="أنواع الأجهزة" height={240} option={pie(data.distributions.device_types)} /></Card>
          <Card title="أنظمة التشغيل"><Chart label="أنظمة التشغيل" height={240} option={pie(data.distributions.os_families)} /></Card>
          <Card title="تصنيف المنافذ المكشوفة"><Chart label="تصنيف التعرّض" height={240} option={bar(data.distributions.exposures, "#0ea5e9")} /></Card>
        </section>

        {/* Networks */}
        <Card title="تحليل الشبكات" className="print-break">
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2 text-start">الشبكة</th><th className="p-2 text-start">الاسم</th>
                <th className="p-2">أجهزة</th><th className="p-2">متصل</th><th className="p-2">موجّهات</th>
                <th className="p-2">بوابات</th><th className="p-2">منافذ مفتوحة</th><th className="p-2">الخطورة</th>
                <th className="p-2 text-start">أكثر المنافذ شيوعاً</th>
              </tr></thead>
              <tbody>
                {data.networks.map((n) => (
                  <tr key={n.cidr} className="border-b border-slate-100">
                    <td className="p-2"><Ltr className="font-medium">{n.cidr}</Ltr></td>
                    <td className="p-2">{n.name ?? "—"}{!n.in_scope && <span className="ms-1 text-[10px] text-slate-400">(غير معتمدة)</span>}</td>
                    <td className="p-2 text-center">{n.devices}</td>
                    <td className="p-2 text-center">{n.online}</td>
                    <td className="p-2 text-center">{n.routers}</td>
                    <td className="p-2 text-center">{n.gateways}</td>
                    <td className="p-2 text-center">{n.open_service_count}</td>
                    <td className="p-2 text-center"><Badge tone={RISK_TONE[n.risk_band]}>{RISK_AR[n.risk_band]}</Badge></td>
                    <td className="p-2"><Ltr className="text-xs text-slate-500">{n.top_ports.map((p) => `${p.port}×${p.count}`).join("، ")}</Ltr></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Recommendations */}
        <Card title="التوصيات ذات الأولوية" className="print-break">
          <ol className="space-y-2">
            {data.recommendations.map((r, i) => (
              <li key={i} className="flex items-start gap-2 rounded-xl border border-slate-200 p-2.5">
                <Badge tone={PRIORITY_TONE[r.priority]}>{PRIORITY_AR[r.priority]}</Badge>
                <div><div className="font-semibold text-slate-800">{r.title_ar}</div><div className="text-sm text-slate-600">{r.detail_ar}</div></div>
              </li>
            ))}
          </ol>
        </Card>

        {/* Exposed ports with admin commands */}
        <Card title="المنافذ المكشوفة وأوامر التحقق والإغلاق">
          <p className="mb-2 text-xs text-slate-500 no-print">اضغط أي صف لعرض أوامر المسؤول: التأكد أن الخدمة تعمل، وكيفية إغلاقها وتأمينها.</p>
          <div className="space-y-2">
            {data.exposed_ports.map((p) => (
              <div key={`${p.port}-${p.service_name}`} className="rounded-xl border border-slate-200 print-break">
                <button type="button" onClick={() => setOpenPort(openPort === p.port ? null : p.port)}
                  className="flex w-full flex-wrap items-center justify-between gap-2 p-3 text-start hover:bg-slate-50">
                  <span className="flex items-center gap-2">
                    <Ltr className="font-mono font-bold text-cyan-900">{p.port}/{p.protocol}</Ltr>
                    <span className="font-medium">{p.service_name}</span>
                    {p.high_risk && <Badge tone="red">عالي الخطورة</Badge>}
                  </span>
                  <span className="flex items-center gap-2 text-sm text-slate-500">
                    <span>{p.count} جهاز</span>
                    <span className="no-print text-cyan-700">{openPort === p.port ? "▲" : "▼"}</span>
                  </span>
                </button>
                {p.risk_note_ar && <p className="px-3 pb-2 text-xs text-red-700">{p.risk_note_ar}</p>}
                {(openPort === p.port) && (
                  <div className="border-t border-slate-100 p-3">
                    <div className="mb-2 text-xs text-slate-600">الأجهزة: {p.assets.map((a) => a.ip).filter(Boolean).slice(0, 20).join("، ")}{p.assets.length > 20 ? "…" : ""}</div>
                    <PortGuidance port={p} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>

        {/* Top exposed devices */}
        <Card title="أكثر الأجهزة تعرّضاً" className="print-break">
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2 text-start">العنوان</th><th className="p-2 text-start">الاسم</th><th className="p-2">النوع</th>
                <th className="p-2">خدمات</th><th className="p-2">تنبيهات</th><th className="p-2">الخطورة</th><th className="p-2 text-start">المنافذ</th>
              </tr></thead>
              <tbody>
                {data.top_exposed_devices.map((d) => (
                  <tr key={d.id} className="border-b border-slate-100">
                    <td className="p-2"><Link className="text-cyan-800 underline" to={`/assets/${d.id}`}><Ltr>{d.ip}</Ltr></Link></td>
                    <td className="p-2">{d.name ?? "—"}{d.is_gateway && <Badge tone="amber">بوابة</Badge>}</td>
                    <td className="p-2 text-center">{d.device_type_ar}</td>
                    <td className="p-2 text-center">{d.open_services}</td>
                    <td className="p-2 text-center">{d.open_alerts || "—"}</td>
                    <td className="p-2 text-center"><Badge tone={RISK_TONE[d.risk_band]}>{RISK_AR[d.risk_band]}</Badge></td>
                    <td className="p-2"><Ltr className="text-xs text-slate-500">{d.ports.join("، ")}</Ltr></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Alerts */}
        {data.alerts.length > 0 && (
          <Card title="التنبيهات المرتفعة والحرجة" className="print-break">
            <div className="space-y-2">
              {data.alerts.map((a) => (
                <div key={a.id} className="flex items-start gap-2 rounded-xl border border-slate-200 p-2.5">
                  <Badge tone={a.severity === "critical" ? "red" : "amber"}>{a.severity_ar}</Badge>
                  <div>
                    <div className="font-semibold text-slate-800">{a.title_ar} {a.occurrences > 1 && <span className="text-xs text-slate-400">(×{a.occurrences})</span>}</div>
                    <div className="text-sm text-slate-600">{a.message_ar}</div>
                    <div className="text-xs text-slate-400">آخر ظهور: {fmt(a.last_seen)}{a.asset_id ? <> • <Link className="text-cyan-700 underline" to={`/assets/${a.asset_id}`}>الجهاز</Link></> : null}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Vulnerabilities */}
        {data.vulnerabilities.open_findings > 0 && (
          <Card title="الثغرات الأمنية (CVE)" className="print-break">
            <p className="mb-2 text-sm text-slate-600">
              {data.vulnerabilities.open_findings} نتيجة مفتوحة على {data.vulnerabilities.affected_assets} جهازاً،
              من أصل {data.vulnerabilities.cve_entries} سجل CVE مستورد.
            </p>
            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-slate-500">
                  <th className="p-2 text-start">CVE</th><th className="p-2">الخطورة</th><th className="p-2">الدرجة</th>
                  <th className="p-2 text-start">الجهاز</th><th className="p-2 text-start">المنتج</th><th className="p-2 text-start">المطابقة</th>
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
        <Card title="آخر الفحوصات" className="print-break">
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-slate-500">
                <th className="p-2 text-start">#</th><th className="p-2 text-start">النطاق</th><th className="p-2">الحالة</th>
                <th className="p-2">أجهزة حيّة</th><th className="p-2">منافذ مفتوحة</th><th className="p-2 text-start">انتهى</th>
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

        <p className="pb-4 text-center text-xs text-slate-400">أُنشئ هذا التقرير بواسطة راصد (RASED) — أداة اكتشاف ومراقبة الشبكة. العمل دون اتصال، وكل البيانات محلية.</p>
      </div>
    </div>
  );
}
