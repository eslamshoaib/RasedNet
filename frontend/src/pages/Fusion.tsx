import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { api, downloadFile, errorMessage } from "../api";
import { Chart } from "../components/Chart";
import { IconDownload, IconTrash } from "../components/icons";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, Pager, SEVERITY_TONE, STATUS_TONE } from "../components/ui";
import { formatDate, parsePorts } from "../format";
import { t } from "../i18n";
import { ASSET_STATUS, CRITICALITY, DEVICE_TYPES, EXPOSURE, label, type LabelMap, OS_FAMILIES, SEVERITY } from "../labels";
import type { FusionFilters, FusionQuery, FusionResult, FusionView } from "../types";

const COLUMN_LABELS: LabelMap = {
  ip: ["عنوان IP", "IP address"], hostname: ["اسم الجهاز", "Hostname"], display_name: ["الاسم المعتمد", "Display name"],
  mac: ["عنوان MAC", "MAC address"], vendor: ["الشركة المصنعة", "Vendor"], model: ["الطراز", "Model"],
  workgroup: ["مجموعة العمل / المجال", "Workgroup / domain"], is_gateway: ["بوابة", "Gateway"],
  device_type: ["نوع الجهاز", "Device type"], os_family: ["نظام التشغيل", "Operating system"], status: ["الحالة", "Status"],
  criticality: ["الأهمية", "Criticality"], open_ports: ["المنافذ المفتوحة", "Open ports"], open_service_count: ["عدد الخدمات", "Service count"],
  exposures: ["فئات التعرض", "Exposure categories"], services: ["الخدمات", "Services"], open_alerts: ["تنبيهات مفتوحة", "Open alerts"],
  max_alert_severity: ["أعلى خطورة", "Max severity"], first_seen: ["أول ظهور", "First seen"], last_seen: ["آخر ظهور", "Last seen"],
};
const SORTS: LabelMap = {
  ip: ["عنوان IP", "IP address"], hostname: ["الاسم", "Name"], device_type: ["نوع الجهاز", "Device type"],
  os_family: ["النظام", "OS"], status: ["الحالة", "Status"], first_seen: ["أول ظهور", "First seen"],
  last_seen: ["آخر ظهور", "Last seen"], open_service_count: ["عدد الخدمات المفتوحة", "Open service count"],
};
const GROUPS: LabelMap = {
  device_type: ["نوع الجهاز", "Device type"], os_family: ["نظام التشغيل", "Operating system"], status: ["الحالة", "Status"],
  vendor: ["الشركة المصنعة", "Vendor"], model: ["الطراز", "Model"], workgroup: ["مجموعة العمل / المجال", "Workgroup / domain"],
  criticality: ["الأهمية", "Criticality"], subnet24: ["الشبكة الفرعية /24", "Subnet /24"], port: ["المنفذ المفتوح", "Open port"],
  exposure: ["فئة التعرض", "Exposure category"], max_alert_severity: ["أعلى خطورة تنبيه", "Max alert severity"],
};
const GROUP_VALUE_LABELS: Record<string, LabelMap> = {
  device_type: DEVICE_TYPES, os_family: OS_FAMILIES, status: ASSET_STATUS, criticality: CRITICALITY, exposure: EXPOSURE, max_alert_severity: SEVERITY,
};

const DEFAULT_QUERY: FusionQuery = {
  filters: {}, columns: ["ip", "hostname", "device_type", "os_family", "model", "status", "open_ports", "open_alerts", "last_seen"],
  sort: "ip", order: "asc", group_by: "device_type", page: 1, page_size: 50,
};

function presets(): { name: string; filters: FusionFilters; group_by: string }[] {
  return [
    { name: t("ويندوز + SMB مفتوح + تنبيه عالي الخطورة", "Windows + open SMB + high-severity alert"), filters: { os_families: ["windows"], open_ports_all: [445], min_alert_severity: "high" }, group_by: "subnet24" },
    { name: t("إدارة عن بعد مكشوفة (RDP/SSH/VNC/WinRM)", "Exposed remote admin (RDP/SSH/VNC/WinRM)"), filters: { exposures_any: ["remote_admin"] }, group_by: "port" },
    { name: t("قواعد بيانات مكشوفة", "Exposed databases"), filters: { exposures_any: ["database"] }, group_by: "port" },
    { name: t("مشاركة ملفات مكشوفة", "Exposed file sharing"), filters: { exposures_any: ["file_sharing"] }, group_by: "os_family" },
    { name: t("أجهزة جديدة خلال 7 أيام", "New devices in the last 7 days"), filters: { first_seen_within_days: 7 }, group_by: "device_type" },
    { name: t("أجهزة غير مصنفة تحتاج مراجعة", "Unclassified devices needing review"), filters: { device_types: ["unknown"] }, group_by: "vendor" },
    { name: t("موجّهات ونقاط وصول ومعدات شبكات", "Routers, access points & network gear"), filters: { device_types: ["router", "access_point", "switch", "network_device"] }, group_by: "model" },
    { name: t("أجهزة لم تظهر منذ 3 أيام", "Devices not seen for 3 days"), filters: { not_seen_for_days: 3 }, group_by: "subnet24" },
  ];
}

function Chips<T extends string>({ options, value, onChange }: { options: LabelMap; value: T[]; onChange: (v: T[]) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {(Object.keys(options) as T[]).map((k) => {
        const on = value.includes(k);
        return (
          <button key={k} type="button" aria-pressed={on} onClick={() => onChange(on ? value.filter((x) => x !== k) : [...value, k])}
            className={`rounded-full border px-2.5 py-0.5 text-xs transition ${on ? "border-cyan-600 bg-cyan-600 text-white" : "border-slate-300 bg-white text-slate-600 hover:border-cyan-400"}`}>
            {label(options, k)}
          </button>
        );
      })}
    </div>
  );
}

function PortInput({ label: text, value, onChange }: { label: string; value: number[] | undefined; onChange: (v: number[] | undefined) => void }) {
  const [raw, setRaw] = useState((value ?? []).join(", "));
  const invalid = raw.trim() !== "" && parsePorts(raw) === null;
  return (
    <Field label={text} hint={invalid ? t("أرقام منافذ غير صالحة", "Invalid port numbers") : t("مثال: 445, 3389", "e.g. 445, 3389")}>
      <input className={`${inputClass} ${invalid ? "border-red-400" : ""}`} dir="ltr" value={raw}
        onChange={(e) => { setRaw(e.target.value); const p = e.target.value.trim() ? parsePorts(e.target.value) : []; if (p) onChange(p.length ? p : undefined); }} />
    </Field>
  );
}

function renderCell(column: string, value: unknown, row: Record<string, unknown>): ReactNode {
  if (value === null || value === undefined || value === "") return <span className="text-slate-300">—</span>;
  switch (column) {
    case "ip":
      return <Link to={`/assets/${row.id}`} className="text-cyan-800 underline"><Ltr>{String(value)}</Ltr></Link>;
    case "mac": case "hostname": return <Ltr>{String(value)}</Ltr>;
    case "device_type": return label(DEVICE_TYPES, String(value));
    case "os_family": return label(OS_FAMILIES, String(value));
    case "status": return <Badge tone={STATUS_TONE[String(value)]}>{label(ASSET_STATUS, String(value))}</Badge>;
    case "criticality": return label(CRITICALITY, String(value));
    case "max_alert_severity": return <Badge tone={SEVERITY_TONE[String(value)]}>{label(SEVERITY, String(value))}</Badge>;
    case "exposures": return (value as string[]).map((x) => label(EXPOSURE, x)).join(t("، ", ", "));
    case "open_ports": return <Ltr>{(value as number[]).join(", ")}</Ltr>;
    case "services": return <Ltr className="text-xs">{(value as string[]).join(" | ")}</Ltr>;
    case "is_gateway": return value ? <Badge tone="amber">{t("بوابة", "Gateway")}</Badge> : "—";
    case "first_seen": case "last_seen": return <span className="whitespace-nowrap">{formatDate(String(value))}</span>;
    default: return Array.isArray(value) ? value.join(t("، ", ", ")) : String(value);
  }
}

export function FusionPage() {
  const qc = useQueryClient();
  const [query, setQuery] = useState<FusionQuery>(DEFAULT_QUERY);
  const [chartType, setChartType] = useState<"bar" | "pie">("bar");
  const [viewName, setViewName] = useState("");
  const [shared, setShared] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const f = query.filters;
  const setFilters = (patch: Partial<FusionFilters>) => setQuery({ ...query, filters: { ...f, ...patch }, page: 1 });

  const result = useQuery({
    queryKey: ["fusion", query],
    queryFn: () => api<FusionResult>("/api/fusion/query", { method: "POST", body: query }),
    placeholderData: keepPreviousData,
  });
  const views = useQuery({ queryKey: ["fusion-views"], queryFn: () => api<FusionView[]>("/api/fusion/views") });
  const saveView = useMutation({
    mutationFn: () => api<FusionView>("/api/fusion/views", { method: "POST", body: { name: viewName, definition: { ...query, page: 1 }, is_shared: shared } }),
    onSuccess: () => { setViewName(""); void qc.invalidateQueries({ queryKey: ["fusion-views"] }); },
  });
  const deleteView = useMutation({
    mutationFn: (id: number) => api(`/api/fusion/views/${id}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["fusion-views"] }),
  });

  const chartOption = useMemo(() => {
    const groups = (result.data?.groups ?? []).slice(0, 25);
    const map = query.group_by ? GROUP_VALUE_LABELS[query.group_by] : undefined;
    const names = groups.map((g) => (map ? label(map, g.key) : g.key));
    const palette = ["#0891b2", "#7c3aed", "#e11d48", "#f59e0b", "#16a34a", "#0284c7", "#db2777", "#65a30d", "#475569", "#9333ea"];
    if (chartType === "pie") {
      return { color: palette, tooltip: { trigger: "item" as const }, legend: { type: "scroll" as const, bottom: 0 },
        series: [{ type: "pie" as const, radius: ["35%", "68%"], data: groups.map((g, i) => ({ name: names[i], value: g.count })),
          label: { formatter: "{b}: {c}" } }] };
    }
    return { color: palette, tooltip: { trigger: "axis" as const }, grid: { left: 40, right: 150, top: 10, bottom: 20 },
      xAxis: { type: "value" as const, minInterval: 1, inverse: true },
      yAxis: { type: "category" as const, position: "right" as const, data: names, inverse: true },
      series: [{ type: "bar" as const, data: groups.map((g) => g.count), itemStyle: { borderRadius: 6 }, label: { show: true, position: "left" as const } }] };
  }, [result.data, chartType, query.group_by]);

  const runExport = async () => {
    setExportError(null);
    try {
      await downloadFile("/api/fusion/export", query, "rasednet-fusion.csv");
    } catch (e) {
      setExportError(errorMessage(e));
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">{t("جداول الدمج والتحليل", "Fusion & analytics")}</h1>
          <p className="text-sm text-slate-500">{t("ادمج بيانات الأجهزة والخدمات والمنافذ والتنبيهات في استعلام واحد من قاعدة البيانات مباشرة.", "Combine device, service, port and alert data in a single query, straight from the database.")}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={() => setQuery(DEFAULT_QUERY)}>{t("إعادة الضبط", "Reset")}</Button>
          <Button onClick={() => void runExport()}><IconDownload className="h-4 w-4" /> {t("تصدير CSV", "Export CSV")}</Button>
        </div>
      </div>
      {exportError && <ErrorBox error={exportError} />}

      <Card title={t("تحليلات جاهزة", "Ready-made analytics")}>
        <div className="flex flex-wrap gap-2">
          {presets().map((p) => (
            <button key={p.name} type="button" onClick={() => setQuery({ ...query, filters: p.filters, group_by: p.group_by, page: 1 })}
              className="card-hover rounded-xl border border-slate-200 bg-gradient-to-br from-white to-slate-50 px-3 py-2 text-sm text-slate-700 hover:border-cyan-400">
              {p.name}
            </button>
          ))}
        </div>
        {views.data && views.data.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3">
            <span className="text-xs text-slate-500">{t("العروض المحفوظة:", "Saved views:")}</span>
            {views.data.map((v) => (
              <span key={v.id} className="inline-flex items-center gap-1 rounded-full bg-cyan-50 px-2 py-0.5 text-xs text-cyan-900">
                <button type="button" onClick={() => setQuery({ ...DEFAULT_QUERY, ...v.definition, page: 1 })} className="underline">{v.name}</button>
                {v.is_shared && <span className="text-[10px] text-cyan-700">{t("(مشترك)", "(shared)")}</span>}
                {v.is_mine && <button type="button" aria-label={t("حذف العرض", "Delete view")} onClick={() => deleteView.mutate(v.id)}><IconTrash className="h-3.5 w-3.5" /></button>}
              </span>
            ))}
          </div>
        )}
      </Card>

      <div className="grid gap-4 2xl:grid-cols-[420px_1fr]">
        <Card title={t("عوامل التصفية", "Filters")}>
          <div className="space-y-3">
            <Field label={t("بحث نصي", "Text search")}><input className={inputClass} value={f.text ?? ""} onChange={(e) => setFilters({ text: e.target.value || undefined })} placeholder={t("عنوان، اسم، MAC، شركة، طراز…", "IP, name, MAC, vendor, model…")} /></Field>
            <Field label={t("نطاق عناوين (CIDR)", "Address range (CIDR)")}><input className={inputClass} dir="ltr" value={f.ip_cidr ?? ""} onChange={(e) => setFilters({ ip_cidr: e.target.value || undefined })} placeholder="10.150.0.0/20" /></Field>
            <Field label={t("الحالة", "Status")}><Chips options={ASSET_STATUS} value={(f.statuses ?? []) as string[]} onChange={(v) => setFilters({ statuses: v })} /></Field>
            <Field label={t("نوع الجهاز", "Device type")}><Chips options={DEVICE_TYPES} value={(f.device_types ?? []) as string[]} onChange={(v) => setFilters({ device_types: v })} /></Field>
            <Field label={t("نظام التشغيل", "Operating system")}><Chips options={OS_FAMILIES} value={(f.os_families ?? []) as string[]} onChange={(v) => setFilters({ os_families: v })} /></Field>
            <Field label={t("فئة الخدمات المكشوفة (أي منها)", "Exposure category (any of)")}><Chips options={EXPOSURE} value={(f.exposures_any ?? []) as string[]} onChange={(v) => setFilters({ exposures_any: v })} /></Field>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 2xl:grid-cols-1">
              <PortInput label={t("منافذ مفتوحة كلها", "All these ports open")} value={f.open_ports_all} onChange={(v) => setFilters({ open_ports_all: v })} />
              <PortInput label={t("أي من هذه المنافذ", "Any of these ports")} value={f.open_ports_any} onChange={(v) => setFilters({ open_ports_any: v })} />
              <PortInput label={t("منافذ يجب أن تكون مغلقة", "Ports that must be closed")} value={f.open_ports_none} onChange={(v) => setFilters({ open_ports_none: v })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label={t("أدنى خطورة تنبيه مفتوح", "Min open-alert severity")}>
                <select className={inputClass} value={f.min_alert_severity ?? ""} onChange={(e) => setFilters({ min_alert_severity: e.target.value || null })}>
                  <option value="">—</option>
                  {Object.keys(SEVERITY).map((k) => <option key={k} value={k}>{label(SEVERITY, k)}</option>)}
                </select>
              </Field>
              <Field label={t("تنبيهات مفتوحة", "Open alerts")}>
                <select className={inputClass} value={f.has_open_alerts == null ? "" : String(f.has_open_alerts)} onChange={(e) => setFilters({ has_open_alerts: e.target.value === "" ? null : e.target.value === "true" })}>
                  <option value="">—</option><option value="true">{t("يوجد", "Yes")}</option><option value="false">{t("لا يوجد", "No")}</option>
                </select>
              </Field>
              <Field label={t("ظهر أول مرة خلال (أيام)", "First seen within (days)")}><input type="number" min={0} className={inputClass} value={f.first_seen_within_days ?? ""} onChange={(e) => setFilters({ first_seen_within_days: e.target.value === "" ? null : Number(e.target.value) })} /></Field>
              <Field label={t("لم يظهر منذ (أيام)", "Not seen for (days)")}><input type="number" min={0} className={inputClass} value={f.not_seen_for_days ?? ""} onChange={(e) => setFilters({ not_seen_for_days: e.target.value === "" ? null : Number(e.target.value) })} /></Field>
              <Field label={t("خدمة / منتج يحتوي", "Service / product contains")}><input className={inputClass} value={f.service_contains ?? ""} onChange={(e) => setFilters({ service_contains: e.target.value || undefined })} /></Field>
              <Field label={t("الشركة المصنعة تحتوي", "Vendor contains")}><input className={inputClass} value={f.vendor_contains ?? ""} onChange={(e) => setFilters({ vendor_contains: e.target.value || undefined })} /></Field>
            </div>
          </div>
        </Card>

        <div className="space-y-4">
          <Card title={`${t("التجميع والرسم البياني", "Grouping & chart")}${query.group_by ? ` — ${t("حسب", "by")} ${label(GROUPS, query.group_by)}` : ""}`}
            actions={
              <div className="flex flex-wrap gap-2">
                <select className={`${inputClass} w-auto`} value={query.group_by ?? ""} onChange={(e) => setQuery({ ...query, group_by: e.target.value || null })} aria-label={t("التجميع حسب", "Group by")}>
                  <option value="">{t("بدون تجميع", "No grouping")}</option>
                  {Object.keys(GROUPS).map((k) => <option key={k} value={k}>{label(GROUPS, k)}</option>)}
                </select>
                <select className={`${inputClass} w-auto`} value={chartType} onChange={(e) => setChartType(e.target.value as "bar" | "pie")} aria-label={t("نوع الرسم", "Chart type")}>
                  <option value="bar">{t("أعمدة", "Bar")}</option><option value="pie">{t("دائري", "Pie")}</option>
                </select>
              </div>
            }>
            {query.group_by && result.data?.groups?.length ? <Chart option={chartOption} height={Math.max(260, Math.min(25, result.data.groups.length) * (chartType === "bar" ? 26 : 0) + 60)} label={t("رسم التجميع", "Grouping chart")} />
              : <p className="text-sm text-slate-500">{query.group_by ? t("لا توجد بيانات مطابقة.", "No matching data.") : t("اختر حقلاً للتجميع لعرض الرسم البياني.", "Pick a grouping field to show the chart.")}</p>}
          </Card>

          <Card title={`${t("النتائج", "Results")}${result.data ? ` (${result.data.total})` : ""}`}
            actions={
              <div className="flex flex-wrap gap-2">
                <select className={`${inputClass} w-auto`} value={query.sort} onChange={(e) => setQuery({ ...query, sort: e.target.value })} aria-label={t("الترتيب", "Sort")}>
                  {Object.keys(SORTS).map((k) => <option key={k} value={k}>{t("ترتيب:", "Sort:")} {label(SORTS, k)}</option>)}
                </select>
                <Button variant="secondary" onClick={() => setQuery({ ...query, order: query.order === "asc" ? "desc" : "asc" })}>{query.order === "asc" ? t("تصاعدي ↑", "Ascending ↑") : t("تنازلي ↓", "Descending ↓")}</Button>
              </div>
            }>
            <details className="mb-3">
              <summary className="cursor-pointer text-sm text-cyan-800">{t("اختيار الأعمدة", "Choose columns")}</summary>
              <div className="mt-2"><Chips options={COLUMN_LABELS} value={query.columns} onChange={(v) => v.length && setQuery({ ...query, columns: v })} /></div>
            </details>
            {result.isLoading ? <Loading /> : result.error ? <ErrorBox error={result.error} /> : (
              <>
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead><tr className="border-b bg-slate-50">{query.columns.map((c) => <th key={c} className="whitespace-nowrap px-3 py-2 text-start font-semibold text-slate-600">{label(COLUMN_LABELS, c)}</th>)}</tr></thead>
                    <tbody>
                      {result.data?.rows.map((row) => (
                        <tr key={String(row.id)} className="border-b border-slate-100 hover:bg-cyan-50/40">
                          {query.columns.map((c) => <td key={c} className="px-3 py-2 align-top">{renderCell(c, row[c], row)}</td>)}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {result.data && result.data.total === 0 && <p className="py-6 text-center text-sm text-slate-500">{t("لا توجد أجهزة مطابقة لعوامل التصفية.", "No devices match the filters.")}</p>}
                {result.data && <Pager page={query.page} pageSize={query.page_size} total={result.data.total} onPage={(p) => setQuery({ ...query, page: p })} />}
              </>
            )}
          </Card>

          <Card title={t("حفظ هذا العرض", "Save this view")}>
            <div className="flex flex-wrap items-center gap-2">
              <input className={`${inputClass} max-w-xs`} placeholder={t("اسم العرض", "View name")} value={viewName} onChange={(e) => setViewName(e.target.value)} />
              <label className="flex items-center gap-1.5 text-sm"><input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} /> {t("مشاركة مع باقي المستخدمين", "Share with other users")}</label>
              <Button disabled={!viewName.trim() || saveView.isPending} onClick={() => saveView.mutate()}>{t("حفظ", "Save")}</Button>
              {saveView.error && <span className="text-sm text-red-700">{errorMessage(saveView.error)}</span>}
              {saveView.isSuccess && <span className="text-sm text-emerald-700">{t("تم الحفظ", "Saved")}</span>}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
