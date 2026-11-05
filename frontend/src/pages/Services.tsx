import { createColumnHelper } from "@tanstack/react-table";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api } from "../api";
import { DataTable, type Features } from "../components/DataTable";
import { Card, ErrorBox, inputClass, Loading, Ltr, Pager } from "../components/ui";
import { formatDate, percent } from "../format";
import { EXPOSURE, ID_METHOD, label } from "../labels";
import type { Page, Service } from "../types";

const helper = createColumnHelper<Features, Service>();
const columns = helper.columns([
  helper.display({
    id: "asset", header: "الجهاز",
    cell: ({ row }) => (
      <Link to={`/assets/${row.original.asset_id}`} className="text-cyan-800 underline">
        {row.original.asset_label ?? "—"} <Ltr className="text-xs text-slate-500">{row.original.asset_ip ?? ""}</Ltr>
      </Link>
    ),
  }),
  helper.display({ id: "port", header: "المنفذ", cell: ({ row }) => <Ltr>{`${row.original.port}/${row.original.protocol}`}</Ltr> }),
  helper.display({ id: "service", header: "الخدمة", cell: ({ row }) => <Ltr>{row.original.service_name}</Ltr> }),
  helper.display({
    id: "product", header: "المنتج والإصدار",
    cell: ({ row }) => (row.original.product ? <Ltr>{`${row.original.product} ${row.original.version ?? ""}`.trim()}</Ltr> : "—"),
  }),
  helper.display({ id: "method", header: "طريقة التعرف", cell: ({ row }) => `${label(ID_METHOD, row.original.identification_method)} (${percent(row.original.identification_confidence)})` }),
  helper.display({ id: "exposure", header: "الفئة", cell: ({ row }) => label(EXPOSURE, row.original.exposure_category) }),
  helper.display({ id: "note", header: "ملاحظة أمنية", cell: ({ row }) => <span className="text-xs text-slate-600">{row.original.exposure_note_ar ?? "—"}</span> }),
  helper.display({ id: "first_seen", header: "أول رصد", cell: ({ row }) => <span className="whitespace-nowrap">{formatDate(row.original.first_seen)}</span> }),
]);

export function ServicesPage() {
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [port, setPort] = useState("");
  const [exposure, setExposure] = useState("");
  const [state, setState] = useState("open");
  const portNumber = /^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535 ? Number(port) : undefined;
  const query = useQuery({
    queryKey: ["services", page, q, portNumber, exposure, state],
    queryFn: () => api<Page<Service>>("/api/services", { query: { page, page_size: 50, q, port: portNumber, exposure, state } }),
    placeholderData: keepPreviousData,
  });
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">المنافذ والبروتوكولات</h1>
      <Card>
        <div className="mb-3 grid gap-2 md:grid-cols-4">
          <input className={inputClass} placeholder="بحث بالخدمة أو المنتج أو العنوان" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} aria-label="بحث" />
          <input className={inputClass} dir="ltr" placeholder="رقم المنفذ" value={port} onChange={(e) => { setPort(e.target.value); setPage(1); }} aria-label="رقم المنفذ" />
          <select className={inputClass} value={exposure} onChange={(e) => { setExposure(e.target.value); setPage(1); }} aria-label="الفئة">
            <option value="">كل الفئات</option>
            {Object.entries(EXPOSURE).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select className={inputClass} value={state} onChange={(e) => { setState(e.target.value); setPage(1); }} aria-label="الحالة">
            <option value="open">مفتوحة</option>
            <option value="closed">مغلقة حالياً</option>
          </select>
        </div>
        {query.isLoading ? <Loading /> : query.error ? <ErrorBox error={query.error} /> : (
          <>
            <DataTable data={query.data?.items ?? []} columns={columns} rowKey={(s) => s.id} empty="لا توجد خدمات مطابقة" />
            {query.data && <Pager page={page} pageSize={query.data.page_size} total={query.data.total} onPage={setPage} />}
          </>
        )}
        <p className="mt-3 text-xs text-slate-500">التعرف بناءً على رقم المنفذ فقط تقديري؛ التعرف بتوقيع الخدمة أدق لكنه لا يثبت وجود ثغرة.</p>
      </Card>
    </div>
  );
}
