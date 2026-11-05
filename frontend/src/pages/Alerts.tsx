import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, Empty, ErrorBox, inputClass, Loading, Pager, SEVERITY_TONE, STATUS_TONE } from "../components/ui";
import { formatDate } from "../format";
import { ALERT_STATUS, EVENT_KINDS, label, SEVERITY } from "../labels";
import type { Alert, ChangeEvent, Page } from "../types";

export function AlertsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const query = useQuery({
    queryKey: ["alerts", page, status, severity],
    queryFn: () => api<Page<Alert>>("/api/alerts", { query: { page, page_size: 25, status, severity } }),
    placeholderData: keepPreviousData,
    refetchInterval: 15000,
  });
  const act = useMutation({
    mutationFn: ({ id, action }: { id: number; action: "acknowledge" | "resolve" }) => api(`/api/alerts/${id}/${action}`, { method: "POST" }),
    onSettled: () => { void qc.invalidateQueries({ queryKey: ["alerts"] }); void qc.invalidateQueries({ queryKey: ["dashboard"] }); },
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">التنبيهات والأحداث</h1>
      <Card>
        <div className="mb-3 grid gap-2 md:grid-cols-3">
          <select className={inputClass} value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="الحالة">
            <option value="">كل الحالات</option>
            {Object.entries(ALERT_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select className={inputClass} value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} aria-label="الخطورة">
            <option value="">كل درجات الخطورة</option>
            {Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        {act.error && <ErrorBox error={errorMessage(act.error)} />}
        {query.isLoading ? <Loading /> : query.error ? <ErrorBox error={query.error} /> : query.data?.items.length === 0 ? <Empty>لا توجد تنبيهات مطابقة</Empty> : (
          <ul className="space-y-2">
            {query.data?.items.map((a) => (
              <li key={a.id} className="rounded-lg border border-slate-200 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={SEVERITY_TONE[a.severity]}>{label(SEVERITY, a.severity)}</Badge>
                    <span className="font-semibold">{a.title_ar}</span>
                    <Badge tone={STATUS_TONE[a.status]}>{label(ALERT_STATUS, a.status)}</Badge>
                    {a.occurrences > 1 && <span className="text-xs text-slate-500">تكرر {a.occurrences} مرات</span>}
                  </div>
                  {can("alert:manage") && a.status !== "resolved" && (
                    <div className="flex gap-2">
                      {a.status === "open" && <Button variant="secondary" disabled={act.isPending} onClick={() => act.mutate({ id: a.id, action: "acknowledge" })}>إقرار</Button>}
                      <Button variant="ghost" disabled={act.isPending} onClick={() => act.mutate({ id: a.id, action: "resolve" })}>إغلاق</Button>
                    </div>
                  )}
                </div>
                <p className="mt-1 text-sm text-slate-700">{a.message_ar}</p>
                <div className="mt-1 flex flex-wrap gap-4 text-xs text-slate-500">
                  <span>أول رصد: {formatDate(a.first_seen)}</span>
                  <span>آخر رصد: {formatDate(a.last_seen)}</span>
                  {a.asset_id && <Link className="text-cyan-800 underline" to={`/assets/${a.asset_id}`}>عرض الجهاز</Link>}
                  {a.job_id && <Link className="text-cyan-800 underline" to={`/scans/${a.job_id}`}>الفحص المصدر #{a.job_id}</Link>}
                </div>
              </li>
            ))}
          </ul>
        )}
        {query.data && <Pager page={page} pageSize={query.data.page_size} total={query.data.total} onPage={setPage} />}
      </Card>
    </div>
  );
}

export function EventsPage() {
  const [page, setPage] = useState(1);
  const [kind, setKind] = useState("");
  const query = useQuery({
    queryKey: ["events", page, kind],
    queryFn: () => api<Page<ChangeEvent>>("/api/events", { query: { page, page_size: 50, kind } }),
    placeholderData: keepPreviousData,
  });
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">سجل التغييرات</h1>
      <Card>
        <select className={`${inputClass} mb-3 max-w-xs`} value={kind} onChange={(e) => { setKind(e.target.value); setPage(1); }} aria-label="نوع التغيير">
          <option value="">كل التغييرات</option>
          {Object.entries(EVENT_KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        {query.isLoading ? <Loading /> : query.error ? <ErrorBox error={query.error} /> : query.data?.items.length === 0 ? <Empty>لا توجد تغييرات مسجلة</Empty> : (
          <ul className="divide-y divide-slate-100 text-sm">
            {query.data?.items.map((e) => (
              <li key={e.id} className="flex flex-wrap items-center gap-2 py-2">
                <Badge>{label(EVENT_KINDS, e.kind)}</Badge>
                <span>{e.message_ar}</span>
                <span className="text-xs text-slate-500">{formatDate(e.created_at)}</span>
                {e.asset_id && <Link className="text-xs text-cyan-800 underline" to={`/assets/${e.asset_id}`}>الجهاز</Link>}
                {e.job_id && <Link className="text-xs text-cyan-800 underline" to={`/scans/${e.job_id}`}>فحص #{e.job_id}</Link>}
              </li>
            ))}
          </ul>
        )}
        {query.data && <Pager page={page} pageSize={query.data.page_size} total={query.data.total} onPage={setPage} />}
      </Card>
    </div>
  );
}
