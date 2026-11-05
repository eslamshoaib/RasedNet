import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { Link } from "react-router";
import { api } from "../api";
import { Chart } from "../components/Chart";
import { Badge, Card, ErrorBox, Loading, Stat, STATUS_TONE } from "../components/ui";
import { formatDate, formatNumber } from "../format";
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
        series: [{ type: "line" as const, name: "أجهزة جديدة", smooth: true, areaStyle: {}, data: data.discovery_history.map((d) => d.new_assets) }],
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
  if (error || !data || !charts) return <ErrorBox error={error ?? "تعذر تحميل لوحة التحكم"} />;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <h1 className="text-2xl font-bold">لوحة التحكم الرئيسية</h1>
        <p className="text-xs text-slate-500">جميع الأرقام محسوبة مباشرة من قاعدة البيانات — آخر تحديث {formatDate(data.generated_at)}</p>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-5">
        <Stat label="إجمالي الأجهزة المكتشفة" value={formatNumber(data.total_assets)} tone="teal" />
        <Stat label="الأجهزة المتصلة" value={formatNumber(data.online)} tone="green" />
        <Stat label="الأجهزة غير المتصلة" value={formatNumber(data.offline)} tone="red" />
        <Stat label="أجهزة جديدة (24 ساعة)" value={formatNumber(data.new_24h)} tone="blue" />
        <Stat label="أجهزة غير مصنفة" value={formatNumber(data.unknown_type)} tone="amber" hint="تتطلب مراجعة" />
        <Stat label="الهواتف والأجهزة المحمولة" value={formatNumber(data.mobile)} tone="purple" />
        <Stat label="الخوادم" value={formatNumber(data.servers)} tone="slate" />
        <Stat label="الخدمات المفتوحة" value={formatNumber(data.open_services)} tone="orange" />
        <Stat label="التنبيهات المفتوحة" value={formatNumber(data.active_alerts)} tone="red" />
        <Stat
          label="آخر فحص"
          value={data.last_scan ? <Link to={`/scans/${data.last_scan.id}`} className="text-base text-cyan-800 underline">{formatDate(data.last_scan.finished_at)}</Link> : "—"}
          hint={data.last_scan ? undefined : "لم يُنفذ أي فحص بعد"}
        />
      </div>
      {data.last_scan && (
        <p className="text-sm text-slate-600">
          حالة آخر فحص: <Badge tone={STATUS_TONE[data.last_scan.status]}>{label(JOB_STATUS, data.last_scan.status)}</Badge>
          {data.running_jobs > 0 && <span className="ms-3">فحوص جارية: {data.running_jobs}</span>}
        </p>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="فئات الأجهزة">{data.total_assets ? <Chart option={charts.types} label="توزيع فئات الأجهزة" /> : <p className="text-sm text-slate-500">لا توجد أجهزة بعد.</p>}</Card>
        <Card title="الاكتشاف خلال آخر 30 يوماً"><Chart option={charts.history} label="عدد الأجهزة الجديدة يومياً" /></Card>
        <Card title="تعرض الخدمات حسب الفئة">{data.open_services ? <Chart option={charts.exposure} label="الخدمات المفتوحة حسب الفئة" /> : <p className="text-sm text-slate-500">لا توجد خدمات مفتوحة مسجلة.</p>}</Card>
        <Card title="أكثر المنافذ انتشاراً">{data.top_ports.length ? <Chart option={charts.ports} label="أكثر المنافذ المفتوحة" /> : <p className="text-sm text-slate-500">لا توجد بيانات.</p>}</Card>
        <Card title="التنبيهات المفتوحة حسب الخطورة">{data.active_alerts ? <Chart option={charts.alerts} label="التنبيهات حسب الخطورة" /> : <p className="text-sm text-slate-500">لا توجد تنبيهات مفتوحة.</p>}</Card>
      </div>
    </div>
  );
}
