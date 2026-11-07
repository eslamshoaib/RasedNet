import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { Link } from "react-router";
import { api } from "../api";
import { Chart } from "../components/Chart";
import { Badge, Card, ErrorBox, Loading, Stat, STATUS_TONE } from "../components/ui";
import { formatDate, formatNumber } from "../format";
import { t } from "../i18n";
import { DEVICE_TYPES, EXPOSURE, JOB_STATUS, label, SEVERITY } from "../labels";
import type { DashboardSummary } from "../types";

const PALETTE = ["#0f766e", "#0369a1", "#7c3aed", "#ea580c", "#ca8a04", "#be123c", "#15803d", "#475569", "#0891b2", "#9333ea"];

export function DashboardPage() {
  const tzOffset = new Date().getTimezoneOffset();
  const { data, error, isLoading } = useQuery({
    queryKey: ["dashboard", tzOffset],
    queryFn: () => api<DashboardSummary>("/api/dashboard/summary", { query: { tz_offset: tzOffset } }),
    refetchInterval: 15000,
  });

  const charts = useMemo(() => {
    if (!data) return null;
    const types = Object.entries(data.device_types).map(([k, v]) => ({ name: label(DEVICE_TYPES, k), value: v }));
    const exposure = Object.entries(data.exposure).sort((a, b) => b[1] - a[1]);
    const severities = ["critical", "high", "medium", "low", "info"];
    return {
      types: {
        color: PALETTE,
        tooltip: { trigger: "item" as const },
        legend: { bottom: 0, type: "scroll" as const },
        series: [{ type: "pie" as const, radius: ["40%", "70%"], data: types, label: { formatter: "{b}: {c}" } }],
      },
      exposure: {
        color: PALETTE,
        tooltip: {},
        grid: { left: 40, right: 110, top: 10, bottom: 20 },
        xAxis: { type: "value" as const, minInterval: 1, inverse: true },
        yAxis: { type: "category" as const, position: "right" as const, data: exposure.map(([k]) => label(EXPOSURE, k)) },
        series: [{ type: "bar" as const, data: exposure.map(([, v]) => v) }],
      },
      ports: {
        color: ["#0369a1"],
        tooltip: {},
        grid: { left: 30, right: 20, top: 10, bottom: 40 },
        xAxis: { type: "category" as const, data: data.top_ports.map((p) => `${p.port}/${p.service}`), axisLabel: { rotate: 30 } },
        yAxis: { type: "value" as const, minInterval: 1 },
        series: [{ type: "bar" as const, data: data.top_ports.map((p) => p.count) }],
      },
      history: {
        color: ["#0f766e"],
        tooltip: { trigger: "axis" as const },
        grid: { left: 30, right: 20, top: 10, bottom: 30 },
        xAxis: { type: "category" as const, data: data.discovery_history.map((d) => d.date.slice(5)) },
        yAxis: { type: "value" as const, minInterval: 1 },
        series: [{ type: "line" as const, name: t("أجهزة جديدة", "New devices"), smooth: true, areaStyle: {}, data: data.discovery_history.map((d) => d.new_assets) }],
      },
      alerts: {
        color: ["#be123c", "#ea580c", "#ca8a04", "#64748b", "#0369a1"],
        tooltip: { trigger: "item" as const },
        legend: { bottom: 0 },
        series: [
          {
            type: "pie" as const,
            radius: "65%",
            data: severities.filter((s) => data.alerts_by_severity[s]).map((s) => ({ name: label(SEVERITY, s), value: data.alerts_by_severity[s] })),
          },
        ],
      },
    };
  }, [data]);

  if (isLoading) return <Loading />;
  if (error || !data || !charts) return <ErrorBox error={error ?? t("تعذر تحميل لوحة التحكم", "Could not load the dashboard")} />;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <h1 className="text-2xl font-bold">{t("لوحة التحكم الرئيسية", "Dashboard")}</h1>
        <p className="text-xs text-slate-500">{t("جميع الأرقام محسوبة مباشرة من قاعدة البيانات — آخر تحديث", "All figures are computed directly from the database — last updated")} {formatDate(data.generated_at)}</p>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-5">
        <Stat label={t("إجمالي الأجهزة المكتشفة", "Total discovered devices")} value={formatNumber(data.total_assets)} tone="teal" />
        <Stat label={t("الأجهزة المتصلة", "Online devices")} value={formatNumber(data.online)} tone="green" />
        <Stat label={t("الأجهزة غير المتصلة", "Offline devices")} value={formatNumber(data.offline)} tone="red" />
        <Stat label={t("أجهزة جديدة (24 ساعة)", "New devices (24h)")} value={formatNumber(data.new_24h)} tone="blue" />
        <Stat label={t("أجهزة غير مصنفة", "Unclassified devices")} value={formatNumber(data.unknown_type)} tone="amber" hint={t("تتطلب مراجعة", "Need review")} />
        <Stat label={t("الهواتف والأجهزة المحمولة", "Phones & mobile devices")} value={formatNumber(data.mobile)} tone="purple" />
        <Stat label={t("الخوادم", "Servers")} value={formatNumber(data.servers)} tone="slate" />
        <Stat label={t("الخدمات المفتوحة", "Open services")} value={formatNumber(data.open_services)} tone="orange" />
        <Stat label={t("التنبيهات المفتوحة", "Open alerts")} value={formatNumber(data.active_alerts)} tone="red" />
        <Stat
          label={t("آخر فحص", "Last scan")}
          value={data.last_scan ? <Link to={`/scans/${data.last_scan.id}`} className="text-base text-cyan-800 underline">{formatDate(data.last_scan.finished_at)}</Link> : "—"}
          hint={data.last_scan ? undefined : t("لم يُنفذ أي فحص بعد", "No scan has run yet")}
        />
      </div>
      {data.last_scan && (
        <p className="text-sm text-slate-600">
          {t("حالة آخر فحص:", "Last scan status:")} <Badge tone={STATUS_TONE[data.last_scan.status]}>{label(JOB_STATUS, data.last_scan.status)}</Badge>
          {data.running_jobs > 0 && <span className="ms-3">{t("فحوص جارية:", "Scans running:")} {data.running_jobs}</span>}
        </p>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={t("فئات الأجهزة", "Device categories")}>{data.total_assets ? <Chart option={charts.types} label={t("توزيع فئات الأجهزة", "Device category distribution")} /> : <p className="text-sm text-slate-500">{t("لا توجد أجهزة بعد.", "No devices yet.")}</p>}</Card>
        <Card title={t("الاكتشاف خلال آخر 30 يوماً", "Discovery over the last 30 days")}><Chart option={charts.history} label={t("عدد الأجهزة الجديدة يومياً", "New devices per day")} /></Card>
        <Card title={t("تعرض الخدمات حسب الفئة", "Service exposure by category")}>{data.open_services ? <Chart option={charts.exposure} label={t("الخدمات المفتوحة حسب الفئة", "Open services by category")} /> : <p className="text-sm text-slate-500">{t("لا توجد خدمات مفتوحة مسجلة.", "No open services recorded.")}</p>}</Card>
        <Card title={t("أكثر المنافذ انتشاراً", "Most common ports")}>{data.top_ports.length ? <Chart option={charts.ports} label={t("أكثر المنافذ المفتوحة", "Most common open ports")} /> : <p className="text-sm text-slate-500">{t("لا توجد بيانات.", "No data.")}</p>}</Card>
        <Card title={t("التنبيهات المفتوحة حسب الخطورة", "Open alerts by severity")}>{data.active_alerts ? <Chart option={charts.alerts} label={t("التنبيهات حسب الخطورة", "Alerts by severity")} /> : <p className="text-sm text-slate-500">{t("لا توجد تنبيهات مفتوحة.", "No open alerts.")}</p>}</Card>
      </div>
    </div>
  );
}
