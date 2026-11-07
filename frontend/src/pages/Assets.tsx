import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { RescanAllButton } from "../components/RescanAllButton";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr, STATUS_TONE } from "../components/ui";
import { formatDate, percent } from "../format";
import { getLang, t } from "../i18n";
import { ASSET_STATUS, DEVICE_TYPES, label, METHODS, OS_FAMILIES } from "../labels";
import type { Asset, Page } from "../types";
import { OS_COLORS, STATUS_COLORS, TYPE_COLORS } from "./topologyModel";

type View = "table" | "cards" | "points";
type PointColor = "type" | "status" | "os" | "exposure";

const pointColors = (): Record<PointColor, string> => ({
  type: t("حسب النوع", "By type"), status: t("حسب الحالة", "By status"), os: t("حسب النظام", "By OS"), exposure: t("حسب التعرض", "By exposure"),
});
const EXPOSURE_COLORS = { none: "#16a34a", some: "#f59e0b", high: "#dc2626" } as const;
const OTHER = "أخرى";
const subnetLabel = (s: string): string => (s === OTHER ? t("أخرى", "Other") : s);

export function dotColor(a: Asset, mode: PointColor): string {
  switch (mode) {
    case "status": return STATUS_COLORS[a.status] ?? STATUS_COLORS.unknown;
    case "os": return OS_COLORS[a.os_family] ?? OS_COLORS.unknown;
    case "exposure": return a.open_service_count === 0 ? EXPOSURE_COLORS.none : a.open_service_count >= 5 ? EXPOSURE_COLORS.high : EXPOSURE_COLORS.some;
    default: return TYPE_COLORS[a.device_type] ?? TYPE_COLORS.unknown;
  }
}

export function subnetOf(ip: string | null): string {
  if (!ip || ip.includes(":")) return OTHER;
  const parts = ip.split(".");
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : OTHER;
}

function sortBySubnet(a: string, b: string): number {
  if (a === OTHER) return 1;
  if (b === OTHER) return -1;
  const na = a.split(".").map(Number);
  const nb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (na[i] !== nb[i]) return na[i] - nb[i];
  return 0;
}

function ipSortKey(ip: string | null): number {
  if (!ip || ip.includes(":")) return 2 ** 32;
  return ip.split(".").reduce((acc, p) => acc * 256 + Number(p), 0);
}

function TypeDot({ a }: { a: Asset }) {
  return <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: TYPE_COLORS[a.device_type] ?? TYPE_COLORS.unknown }} />;
}

function NameCell({ a }: { a: Asset }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 font-medium">
        {a.display_name ?? a.hostname ?? <span className="text-slate-400">{t("بدون اسم", "No name")}</span>}
        {a.is_gateway && <Badge tone="amber">{t("بوابة", "Gateway")}</Badge>}
        {a.mac_randomized && <Badge tone="purple">{t("MAC عشوائي", "Random MAC")}</Badge>}
      </div>
      {a.display_name && a.hostname && <Ltr className="text-xs text-slate-500">{a.hostname}</Ltr>}
      {a.model && <div className="truncate text-xs text-cyan-800">{a.model}</div>}
      {!a.model && a.vendor && <div className="truncate text-xs text-slate-500">{a.vendor}</div>}
      {a.workgroup && <div className="text-[11px] text-slate-500">{t("مجموعة:", "Group:")} <Ltr>{a.workgroup.toUpperCase()}</Ltr></div>}
    </div>
  );
}

function TypeCell({ a }: { a: Asset }) {
  if (a.device_type === "unknown") return <Badge tone="amber">{t("غير مؤكد", "Unconfirmed")}</Badge>;
  return <span className="flex items-center gap-1.5"><TypeDot a={a} />{label(DEVICE_TYPES, a.device_type)} <span className="text-xs text-slate-400">({percent(a.device_type_confidence)})</span></span>;
}

function ServiceMeter({ n }: { n: number }) {
  if (!n) return <span className="text-slate-300">—</span>;
  const tone = n >= 5 ? "bg-red-500" : n >= 2 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <span className="flex items-center gap-1.5">
      <span className="h-2 w-14 overflow-hidden rounded-full bg-slate-100"><span className={`block h-full ${tone}`} style={{ width: `${Math.min(100, n * 12)}%` }} /></span>
      <span className="text-xs text-slate-600">{n}</span>
    </span>
  );
}

interface Column { key: string; label: string; sort: (a: Asset) => string | number; cell: (a: Asset) => React.ReactNode }

function columns(): Column[] {
  return [
    { key: "ip", label: t("عنوان IP", "IP address"), sort: (a) => ipSortKey(a.current_ip), cell: (a) => <Ltr>{a.current_ip ?? "—"}</Ltr> },
    { key: "name", label: t("الاسم", "Name"), sort: (a) => (a.display_name ?? a.hostname ?? "").toLowerCase(), cell: (a) => <NameCell a={a} /> },
    { key: "mac", label: t("عنوان MAC", "MAC address"), sort: (a) => a.mac ?? "￿", cell: (a) => (a.mac ? <Ltr>{a.mac}</Ltr> : <span className="text-slate-400">{t("غير مرئي", "Not visible")}</span>) },
    { key: "type", label: t("النوع", "Type"), sort: (a) => label(DEVICE_TYPES, a.device_type), cell: (a) => <TypeCell a={a} /> },
    { key: "os", label: t("النظام", "OS"), sort: (a) => a.os_family, cell: (a) => (a.os_family === "unknown" ? <span className="text-slate-400">—</span> : label(OS_FAMILIES, a.os_family)) },
    { key: "services", label: t("خدمات مفتوحة", "Open services"), sort: (a) => a.open_service_count, cell: (a) => <ServiceMeter n={a.open_service_count} /> },
    { key: "discovery", label: t("الاكتشاف", "Discovery"), sort: (a) => a.discovery_methods.join(","), cell: (a) => <span className="text-xs text-slate-500">{a.discovery_methods.map((m) => label(METHODS, m)).join(t("، ", ", ")) || "—"}</span> },
    { key: "status", label: t("الحالة", "Status"), sort: (a) => a.status, cell: (a) => <Badge tone={STATUS_TONE[a.status]}>{label(ASSET_STATUS, a.status)}</Badge> },
    { key: "last_seen", label: t("آخر ظهور", "Last seen"), sort: (a) => new Date(a.last_seen).getTime(), cell: (a) => <span className="whitespace-nowrap text-xs">{formatDate(a.last_seen)}</span> },
  ];
}

function TableView({ rows, onOpen }: { rows: Asset[]; onOpen: (a: Asset) => void }) {
  const cols = useMemo(() => columns(), []);
  const [sortKey, setSortKey] = useState("last_seen");
  const [dir, setDir] = useState<"asc" | "desc">("desc");
  const col = cols.find((c) => c.key === sortKey) ?? cols[0];
  const sorted = useMemo(() => {
    const factor = dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = col.sort(a), vb = col.sort(b);
      if (va < vb) return -factor;
      if (va > vb) return factor;
      return 0;
    });
  }, [rows, col, dir]);
  const click = (key: string) => {
    if (key === sortKey) setDir(dir === "asc" ? "desc" : "asc");
    else { setSortKey(key); setDir(key === "last_seen" || key === "services" ? "desc" : "asc"); }
  };
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead><tr className="border-b bg-slate-50 text-start">
          {cols.map((c) => (
            <th key={c.key} onClick={() => click(c.key)} aria-sort={sortKey === c.key ? (dir === "asc" ? "ascending" : "descending") : "none"}
              className="cursor-pointer select-none whitespace-nowrap px-3 py-2 text-start font-semibold text-slate-600 hover:bg-slate-100">
              <span className="inline-flex items-center gap-1">{c.label}<span className="text-cyan-600">{sortKey === c.key ? (dir === "asc" ? "▲" : "▼") : <span className="text-slate-300">↕</span>}</span></span>
            </th>
          ))}
        </tr></thead>
        <tbody>
          {sorted.map((a) => (
            <tr key={a.id} onClick={() => onOpen(a)} className="cursor-pointer border-b border-slate-100 align-top hover:bg-cyan-50/50">
              {cols.map((c) => <td key={c.key} className="px-3 py-2">{c.cell(a)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CardsView({ rows, onOpen }: { rows: Asset[]; onOpen: (a: Asset) => void }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {rows.map((a) => (
        <button key={a.id} type="button" onClick={() => onOpen(a)}
          className="card-hover rounded-2xl border border-slate-200 border-s-4 bg-white p-3 text-start" style={{ borderInlineStartColor: TYPE_COLORS[a.device_type] ?? TYPE_COLORS.unknown }}>
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0"><NameCell a={a} /></div>
            <Badge tone={STATUS_TONE[a.status]}>{label(ASSET_STATUS, a.status)}</Badge>
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-sm"><TypeDot a={a} />{label(DEVICE_TYPES, a.device_type)}{a.os_family !== "unknown" && <span className="text-xs text-slate-500">· {label(OS_FAMILIES, a.os_family)}</span>}</div>
          <div className="mt-1 text-sm"><Ltr>{a.current_ip ?? "—"}</Ltr></div>
          <div className="mt-2 flex items-center justify-between"><ServiceMeter n={a.open_service_count} /><span className="text-[11px] text-slate-400">{formatDate(a.last_seen)}</span></div>
        </button>
      ))}
    </div>
  );
}

function PointsView({ rows, mode, onOpen }: { rows: Asset[]; mode: PointColor; onOpen: (a: Asset) => void }) {
  const groups = useMemo(() => {
    const map = new Map<string, Asset[]>();
    for (const a of rows) {
      const key = subnetOf(a.current_ip);
      (map.get(key) ?? map.set(key, []).get(key)!).push(a);
    }
    return [...map.entries()].sort((x, y) => sortBySubnet(x[0], y[0]))
      .map(([subnet, list]) => [subnet, list.sort((p, q) => ipSortKey(p.current_ip) - ipSortKey(q.current_ip))] as const);
  }, [rows]);

  return (
    <div className="space-y-4">
      {groups.map(([subnet, list]) => (
        <div key={subnet}>
          <div className="mb-1.5 flex items-center gap-2 text-sm font-semibold text-slate-700">
            <Ltr>{subnetLabel(subnet)}</Ltr><span className="text-xs font-normal text-slate-400">({list.length})</span>
            <span className="text-xs font-normal text-emerald-600">{t("متصل:", "Online:")} {list.filter((a) => a.status === "online").length}</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {list.map((a) => {
              const size = 14 + Math.min(14, Math.sqrt(a.open_service_count) * 5);
              return (
                <button key={a.id} type="button" onClick={() => onOpen(a)} aria-label={`${a.current_ip} ${label(DEVICE_TYPES, a.device_type)}`}
                  title={`${a.current_ip ?? ""}\n${a.display_name ?? a.hostname ?? ""}\n${label(DEVICE_TYPES, a.device_type)} — ${label(ASSET_STATUS, a.status)}\n${t("خدمات مفتوحة:", "Open services:")} ${a.open_service_count}${a.model ? "\n" + a.model : ""}`}
                  className="grid place-items-center rounded-md transition hover:scale-125 hover:ring-2 hover:ring-cyan-400"
                  style={{ width: size, height: size, background: dotColor(a, mode), opacity: a.status === "offline" ? 0.4 : 1,
                    boxShadow: a.is_gateway ? "0 0 0 2px #facc15" : undefined }}>
                  {a.is_gateway && <span className="text-[9px] font-bold text-white">G</span>}
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

function PointsLegend({ mode, rows }: { mode: PointColor; rows: Asset[] }) {
  const entries: [string, string][] = mode === "status"
    ? Object.entries(STATUS_COLORS).map(([k, v]) => [label(ASSET_STATUS, k), v])
    : mode === "os"
      ? [...new Set(rows.map((a) => a.os_family))].map((k) => [label(OS_FAMILIES, k), OS_COLORS[k] ?? OS_COLORS.unknown])
      : mode === "exposure"
        ? [[t("لا خدمات مفتوحة", "No open services"), EXPOSURE_COLORS.none], [t("1–4 خدمات", "1–4 services"), EXPOSURE_COLORS.some], [t("5 خدمات أو أكثر", "5+ services"), EXPOSURE_COLORS.high]]
        : [...new Set(rows.map((a) => a.device_type))].map((k) => [label(DEVICE_TYPES, k), TYPE_COLORS[k] ?? TYPE_COLORS.unknown]);
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600">
      {entries.map(([name, color]) => <span key={name}><span className="me-1 inline-block h-2.5 w-2.5 rounded-full align-middle" style={{ background: color }} />{name}</span>)}
      <span>{t("• الحجم يكبر بعدد الخدمات المفتوحة • إطار أصفر = بوابة (G) • الباهت = غير متصل", "• size grows with open services • yellow ring = gateway (G) • faded = offline")}</span>
    </div>
  );
}

const MAX_ROWS = 1000;

async function fetchAll(params: Record<string, string>): Promise<{ items: Asset[]; total: number }> {
  // One request, up to 1000 rows — no pagination, for speed.
  const r = await api<Page<Asset>>("/api/assets", { query: { ...params, page: 1, page_size: MAX_ROWS } });
  return { items: r.items, total: r.total };
}

function AddDevice({ onAdded }: { onAdded: () => void }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ current_ip: "", display_name: "", mac: "", device_type: "unknown", notes: "" });
  const create = useMutation({
    mutationFn: () => api<Asset>("/api/assets", { method: "POST", body: {
      current_ip: form.current_ip.trim(), display_name: form.display_name || null, mac: form.mac || null,
      device_type: form.device_type, notes: form.notes } }),
    onSuccess: () => { setForm({ current_ip: "", display_name: "", mac: "", device_type: "unknown", notes: "" }); setOpen(false); onAdded(); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  if (!open) return <Button variant="secondary" onClick={() => setOpen(true)}>{t("+ إضافة جهاز يدوياً", "+ Add device manually")}</Button>;
  return (
    <Card title={t("إضافة جهاز يدوياً", "Add device manually")}>
      <p className="mb-2 text-xs text-slate-500">{t("لتسجيل جهاز تعرفه لكن لا يصل إليه الفحص (مثلاً على شبكة معزولة). يُعلَّم «مُضاف يدوياً».", "To register a device you know but the scan cannot reach (e.g. on an isolated network). Tagged “manually added”.")}</p>
      <form onSubmit={submit} className="grid gap-2 md:grid-cols-5">
        <Field label={t("عنوان IP", "IP address")}><input dir="ltr" className={inputClass} required placeholder="10.235.0.223" value={form.current_ip} onChange={(e) => setForm({ ...form, current_ip: e.target.value })} /></Field>
        <Field label={t("الاسم (اختياري)", "Name (optional)")}><input className={inputClass} value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
        <Field label={t("MAC (اختياري)", "MAC (optional)")}><input dir="ltr" className={inputClass} value={form.mac} onChange={(e) => setForm({ ...form, mac: e.target.value })} /></Field>
        <Field label={t("النوع", "Type")}>
          <select className={inputClass} value={form.device_type} onChange={(e) => setForm({ ...form, device_type: e.target.value })}>
            {Object.keys(DEVICE_TYPES).map((k) => <option key={k} value={k}>{label(DEVICE_TYPES, k)}</option>)}
          </select>
        </Field>
        <div className="flex items-end gap-2"><Button type="submit" disabled={!form.current_ip.trim() || create.isPending}>{t("حفظ", "Save")}</Button><Button type="button" variant="ghost" onClick={() => setOpen(false)}>{t("إلغاء", "Cancel")}</Button></div>
      </form>
      {create.error && <div className="mt-2"><ErrorBox error={errorMessage(create.error)} /></div>}
    </Card>
  );
}

export function AssetsPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [view, setView] = useState<View>("table");
  const [pointColor, setPointColor] = useState<PointColor>("type");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [deviceType, setDeviceType] = useState("");
  const open = (a: Asset) => navigate(`/assets/${a.id}`);
  const common = { q, status, device_type: deviceType };

  const all = useQuery({
    queryKey: ["assets-all", q, status, deviceType],
    queryFn: () => fetchAll(common),
    placeholderData: keepPreviousData,
  });
  const rows = all.data?.items ?? [];
  const total = all.data?.total ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">{t("الأجهزة المتصلة", "Devices")}</h1>
        <div className="flex items-center gap-2">
        <RescanAllButton />
        <div className="flex rounded-xl border border-slate-200 bg-white p-0.5 text-sm">
          {([["table", t("جدول", "Table")], ["cards", t("بطاقات", "Cards")], ["points", t("نقاط", "Dots")]] as const).map(([v, labelText]) => (
            <button key={v} type="button" onClick={() => setView(v)} className={`rounded-lg px-3 py-1 ${view === v ? "bg-cyan-600 text-white" : "text-slate-600 hover:bg-slate-50"}`}>{labelText}</button>
          ))}
        </div>
        </div>
      </div>

      {can("asset:write") && <AddDevice onAdded={() => { void qc.invalidateQueries({ queryKey: ["assets"] }); void qc.invalidateQueries({ queryKey: ["assets-all"] }); }} />}

      <Card>
        <div className="mb-3 grid gap-2 md:grid-cols-4">
          <input className={inputClass} placeholder={t("بحث: عنوان، اسم، MAC، شركة، طراز", "Search: IP, name, MAC, vendor, model")} value={q} onChange={(e) => setQ(e.target.value)} aria-label={t("بحث", "Search")} />
          <select className={inputClass} value={status} onChange={(e) => setStatus(e.target.value)} aria-label={t("الحالة", "Status")}>
            <option value="">{t("كل الحالات", "All statuses")}</option>
            {Object.keys(ASSET_STATUS).map((k) => <option key={k} value={k}>{label(ASSET_STATUS, k)}</option>)}
          </select>
          <select className={inputClass} value={deviceType} onChange={(e) => setDeviceType(e.target.value)} aria-label={t("نوع الجهاز", "Device type")}>
            <option value="">{t("كل الأنواع", "All types")}</option>
            {Object.keys(DEVICE_TYPES).map((k) => <option key={k} value={k}>{label(DEVICE_TYPES, k)}</option>)}
          </select>
          {view === "points" ? (
            <select className={inputClass} value={pointColor} onChange={(e) => setPointColor(e.target.value as PointColor)} aria-label={t("تلوين النقاط", "Dot colouring")}>
              {Object.entries(pointColors()).map(([k, v]) => <option key={k} value={k}>{t("تلوين", "Colour")} {v}</option>)}
            </select>
          ) : <div />}
        </div>

        {view === "points" && rows.length > 0 && <div className="mb-3"><PointsLegend mode={pointColor} rows={rows} /></div>}

        {all.isLoading ? <Loading /> : all.error ? <ErrorBox error={all.error} /> : rows.length === 0 ? (
          <p className="py-8 text-center text-sm text-slate-500">{t("لا توجد أجهزة مطابقة", "No matching devices")}</p>
        ) : (
          <>
            <p className="mb-2 text-xs text-slate-500">
              {getLang() === "en"
                ? `Showing ${rows.length} device(s)${total > rows.length ? ` of ${total} (max ${MAX_ROWS} — narrow the search to see the rest)` : ""}`
                : `عرض ${rows.length} جهاز${total > rows.length ? ` من ${total} (الحد الأقصى ${MAX_ROWS} — ضيّق البحث لعرض الباقي)` : ""}`}
              {view === "table" && t(" • اضغط رأس أي عمود للترتيب به", " • click a column header to sort by it")}
              {view === "points" && t(" • كل نقطة جهاز، مجمّعة حسب الشبكة الفرعية", " • each dot is a device, grouped by subnet")}
            </p>
            {view === "table" && <TableView rows={rows} onOpen={open} />}
            {view === "cards" && <CardsView rows={rows} onOpen={open} />}
            {view === "points" && <PointsView rows={rows} mode={pointColor} onOpen={open} />}
          </>
        )}
      </Card>
    </div>
  );
}
