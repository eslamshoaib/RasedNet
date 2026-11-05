import { useMutation, useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { IconDownload, IconRefresh } from "../components/icons";
import { RescanAllButton } from "../components/RescanAllButton";
import { Badge, Button, Card, ErrorBox, inputClass, Loading, Ltr, STATUS_TONE } from "../components/ui";
import { ASSET_STATUS, DEVICE_TYPES, label, OS_FAMILIES } from "../labels";
import type { Job, Profile, TopoEdge, TopoNode, Topology } from "../types";
import {
  applyFilters, clearHighlight, clearPositions, COLOR_MODES, type ColorMode, coverage, emptyFilters, type Filters,
  focusNeighborhood, highlightPath, LABEL_MODES, type LabelMode, loadPositions, OS_COLORS, type Positions, RISK_COLORS,
  savePositions, searchNodes, STATUS_COLORS, toElements, TYPE_COLORS,
} from "./topologyModel";

const FONT = '"Cairo", "Segoe UI", Tahoma, sans-serif';

const LAYOUTS: Record<string, string> = {
  fusion: "نقاط متفرّعة (فيوجن)",
  cose: "تلقائي (قوى متوازنة)",
  concentric: "دوائر حول خادم الفحص",
  breadthfirst: "شجري من خادم الفحص",
  grid: "شبكي منتظم",
  circle: "دائري",
};

export const EDGE_KINDS: Record<string, string> = {
  attached: "اتصال مباشر بخادم الفحص",
  member: "عضو في الشبكة",
  gateway: "بوابة الشبكة",
  path: "مسار توجيه مرصود",
  routes: "يوصل إلى الشبكة",
  multihomed: "جهاز بعناوين في أكثر من شبكة",
};

const STYLE: cytoscape.StylesheetJson = [
  {
    selector: "node",
    style: {
      label: "data(display)", "font-family": FONT, "font-size": 10, "text-wrap": "wrap", "text-max-width": "140px",
      "text-valign": "bottom", "text-margin-y": 4, color: "#1e293b", "text-background-color": "#ffffff",
      "text-background-opacity": 0.85, "text-background-padding": "2px", "text-background-shape": "roundrectangle",
      "min-zoomed-font-size": 7,
    },
  },
  { selector: "node[type = 'scanner']", style: { shape: "star", width: 50, height: 50, "background-color": "#0891b2", "border-width": 3, "border-color": "#cffafe", "font-weight": "bold" } },
  {
    selector: "node[type = 'network']",
    style: { shape: "round-rectangle", width: 92, height: 42, "background-color": "#e0f2fe", "border-width": 2, "border-color": "#0284c7",
      "text-valign": "center", "text-margin-y": 0, "font-weight": "bold", "text-background-opacity": 0 },
  },
  {
    selector: "node[type = 'network']:parent",
    style: { shape: "round-rectangle", "background-color": "#0284c7", "background-opacity": 0.06, "border-width": 2, "border-style": "solid",
      "border-color": "#0284c7", padding: "18px", "text-valign": "top", "text-halign": "center", "text-margin-y": -4, "font-size": 12,
      "text-background-opacity": 0.9, color: "#075985" },
  },
  // Fusion (radial dots) mode: a network is drawn as a sized circle, not a box.
  {
    selector: "node[type = 'network'][?dot]",
    style: { shape: "ellipse", width: "data(size)", height: "data(size)", "background-color": "#0ea5e9", "background-opacity": 1,
      "border-width": 3, "border-color": "#e0f2fe", "text-valign": "bottom", "text-margin-y": 3, "font-size": 11, "font-weight": "bold",
      color: "#075985", "text-background-opacity": 0.9 },
  },
  { selector: "node[kind = 'observed']", style: { "border-style": "dashed", "border-color": "#64748b" } },
  { selector: "node[kind = 'local']", style: { "border-color": "#0891b2", "border-width": 3 } },
  { selector: "node[type = 'device'], node[type = 'hop']", style: { width: "data(size)", height: "data(size)", "background-color": "data(color)", "border-width": 2, "border-color": "#ffffff" } },
  { selector: "node[device_type = 'router'], node[type = 'hop']", style: { shape: "diamond" } },
  { selector: "node[device_type = 'access_point']", style: { shape: "triangle" } },
  { selector: "node[device_type = 'server']", style: { shape: "round-rectangle" } },
  { selector: "node[?is_gateway]", style: { "border-color": "#facc15", "border-width": 4 } },
  { selector: "node[status = 'offline']", style: { opacity: 0.5 } },
  { selector: "node[open_alerts > 0]", style: { "border-color": "#dc2626", "border-width": 3 } },
  { selector: "edge", style: { width: 1.4, "line-color": "#94a3b8", "curve-style": "bezier", opacity: 0.75 } },
  { selector: "edge[!verified]", style: { "line-style": "dashed", "line-dash-pattern": [6, 4] } },
  { selector: "edge[kind = 'path'], edge[kind = 'routes']", style: { width: 3, "line-color": "#e11d48", "target-arrow-shape": "triangle", "target-arrow-color": "#e11d48" } },
  { selector: "edge[kind = 'attached']", style: { width: 3, "line-color": "#0891b2" } },
  { selector: "edge[kind = 'gateway']", style: { width: 2.5, "line-color": "#eab308" } },
  { selector: "edge[kind = 'multihomed']", style: { "line-color": "#7c3aed", width: 2 } },
  { selector: ".hidden", style: { display: "none" } },
  { selector: ".faded", style: { opacity: 0.1 } },
  { selector: ".match", style: { "border-color": "#f59e0b", "border-width": 5, "z-index": 99 } },
  { selector: "node.onpath", style: { "border-color": "#f59e0b", "border-width": 5, "z-index": 98 } },
  { selector: "edge.onpath", style: { width: 5, "line-color": "#f59e0b", "target-arrow-color": "#f59e0b", "z-index": 98, opacity: 1 } },
  { selector: "node.focus", style: { "z-index": 97 } },
  { selector: ":selected", style: { "overlay-color": "#0891b2", "overlay-opacity": 0.2, "overlay-padding": 6 } },
];

function layoutOptions(name: string): cytoscape.LayoutOptions {
  const common = { animate: true, animationDuration: 450, fit: true, padding: 40 };
  if (name === "fusion") {
    // Radial cascade rooted at the scanner: scanner in the centre, networks on the
    // first ring, their devices fanning out on the next — the Fusion network-graph look.
    return { name: "breadthfirst", ...common, roots: "#scanner", directed: false, circle: true,
      spacingFactor: 1.35, avoidOverlap: true, animationDuration: 600 } as cytoscape.LayoutOptions;
  }
  if (name === "concentric") {
    return { name: "concentric", ...common, minNodeSpacing: 18,
      concentric: (n: cytoscape.NodeSingular) => (n.data("type") === "scanner" ? 4 : n.data("type") === "network" ? 3 : n.data("type") === "hop" ? 2 : 1),
      levelWidth: () => 1 } as cytoscape.LayoutOptions;
  }
  if (name === "breadthfirst") return { name: "breadthfirst", ...common, roots: "#scanner", directed: false, spacingFactor: 1.1 } as cytoscape.LayoutOptions;
  if (name === "grid") return { name: "grid", ...common, avoidOverlap: true } as cytoscape.LayoutOptions;
  if (name === "circle") return { name: "circle", ...common } as cytoscape.LayoutOptions;
  return { name: "cose", ...common, animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, gravity: 0.25,
    numIter: 1500, nestingFactor: 1.2 } as cytoscape.LayoutOptions;
}

type Selected = { kind: "node"; data: TopoNode } | { kind: "edge"; data: TopoEdge } | null;

function ToolButton({ title, onClick, active, children }: { title: string; onClick: () => void; active?: boolean; children: ReactNode }) {
  return (
    <button type="button" title={title} aria-label={title} aria-pressed={active} onClick={onClick}
      className={`grid h-9 min-w-9 place-items-center rounded-xl border px-2 text-sm transition ${active ? "border-cyan-600 bg-cyan-600 text-white" : "border-slate-200 bg-white text-slate-700 hover:border-cyan-400"}`}>
      {children}
    </button>
  );
}

function download(name: string, href: string): void {
  const a = document.createElement("a");
  a.href = href;
  a.download = name;
  a.click();
}

export function TopologyPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [includeDevices, setIncludeDevices] = useState(true);
  const [group, setGroup] = useState(true);
  const [colorMode, setColorMode] = useState<ColorMode>("type");
  const [labelMode, setLabelMode] = useState<LabelMode>("both");
  const [layout, setLayout] = useState("fusion");
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [selected, setSelected] = useState<Selected>(null);
  const [locked, setLocked] = useState(false);
  const [live, setLive] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [traceTarget, setTraceTarget] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [visibleCount, setVisibleCount] = useState(0);
  const wrapper = useRef<HTMLDivElement>(null);
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  const kept = useRef<Positions>({});

  const query = useQuery({
    queryKey: ["topology", includeDevices],
    queryFn: () => api<Topology>("/api/topology", { query: { include_devices: includeDevices } }),
    refetchInterval: live ? 30000 : false,
  });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api<Profile[]>("/api/profiles"), enabled: can("scan:run") });
  const trace = useMutation({
    mutationFn: (targets: string[]) => api<{ traced: number }>("/api/topology/trace", { method: "POST", body: { targets } }),
    onSuccess: (r) => { setNotice(`تم تتبع ${r.traced} مساراً. الشبكات المكتشفة على المسار تظهر في «اكتشاف الشبكة» لاعتمادها وفحصها.`); void query.refetch(); },
  });
  const rescan = useMutation({
    mutationFn: (assetId: number) => {
      const pid = profiles.data?.find((p) => p.code === "standard_inventory")?.id ?? profiles.data?.[0]?.id;
      return api<Job>(`/api/assets/${assetId}/rescan`, { method: "POST", body: { profile_id: pid } });
    },
    onSuccess: (job) => setNotice(`بدأ فحص الجهاز (#${job.id}). ستتحدث الخريطة بعد انتهائه.`),
  });

  const fusion = layout === "fusion";
  const elements = useMemo(
    () => (query.data ? toElements(query.data, { group: group && !fusion, colorMode, labelMode, fusion }) : []),
    [query.data, group, colorMode, labelMode, fusion],
  );

  // Counts for the filter panel.
  const typeCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of query.data?.nodes ?? []) if (n.type === "device") c[n.device_type ?? "unknown"] = (c[n.device_type ?? "unknown"] ?? 0) + 1;
    return c;
  }, [query.data]);
  const networks = useMemo(() => (query.data?.nodes ?? []).filter((n) => n.type === "network"), [query.data]);

  // (Re)build the graph; current positions survive refreshes and display-mode changes.
  useEffect(() => {
    if (!container.current || !elements.length) return;
    if (cy.current) {
      cy.current.nodes().filter((n) => !n.isParent()).forEach((n) => { kept.current[n.id()] = { ...n.position() }; });
      cy.current.destroy();
    }
    const known: Positions = { ...loadPositions(), ...kept.current };
    // In Fusion mode always run the radial layout — saved positions would defeat the cascade.
    const usePreset = !fusion && coverage(elements, known) >= 0.8;
    const instance = cytoscape({
      container: container.current, elements, style: STYLE, wheelSensitivity: 0.25, minZoom: 0.05, maxZoom: 5,
      layout: usePreset
        ? { name: "preset", fit: true, padding: 40, positions: (n: cytoscape.NodeSingular) => known[n.id()] ?? { x: 0, y: 0 } } as cytoscape.LayoutOptions
        : layoutOptions(layout),
    });
    if (usePreset) {
      // New nodes without a stored position are placed beside their network (or the scanner).
      instance.nodes().filter((n) => !n.isParent() && !known[n.id()]).forEach((n, i) => {
        const anchor = (n.parent().nonempty() ? n.parent().first() : n.neighborhood("node").first()) as cytoscape.NodeSingular;
        const base = anchor && anchor.nonempty() ? anchor.position() : instance.getElementById("scanner").position();
        n.position({ x: base.x + 40 * Math.cos(i), y: base.y + 40 * Math.sin(i) });
      });
    }
    instance.on("tap", "node", (e) => setSelected({ kind: "node", data: e.target.data() as TopoNode }));
    instance.on("tap", "edge", (e) => setSelected({ kind: "edge", data: e.target.data() as TopoEdge }));
    instance.on("tap", (e) => { if (e.target === instance) { setSelected(null); clearHighlight(instance); } });
    instance.on("dbltap", "node[asset_id]", (e) => navigate(`/assets/${e.target.data("asset_id")}`));
    cy.current = instance;
    instance.autoungrabify(locked);
    setVisibleCount(applyFilters(instance, filters));
    return () => {
      if (cy.current === instance) {
        instance.nodes().filter((n) => !n.isParent()).forEach((n) => { kept.current[n.id()] = { ...n.position() }; });
      }
    };
    // filters / locked are applied by their own effects
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [elements, navigate]);

  useEffect(() => () => { cy.current?.destroy(); cy.current = null; }, []);
  useEffect(() => { if (cy.current) setVisibleCount(applyFilters(cy.current, filters)); }, [filters]);
  useEffect(() => { cy.current?.autoungrabify(locked); }, [locked]);
  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    const matches = searchNodes(c, search);
    if (matches.length) c.animate({ fit: { eles: matches.union(matches.closedNeighborhood()), padding: 80 } }, { duration: 300 });
  }, [search, elements]);

  // Full screen + resize.
  useEffect(() => {
    const onChange = () => { setFullscreen(document.fullscreenElement === wrapper.current); window.setTimeout(() => cy.current?.resize(), 50); };
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && cy.current) { clearHighlight(cy.current); cy.current.elements().unselect(); setSelected(null); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const runLayout = useCallback((name: string) => {
    const c = cy.current;
    if (!c) return;
    c.elements().not(".hidden").layout(layoutOptions(name)).run();
  }, []);

  const zoomBy = (factor: number) => {
    const c = cy.current;
    if (!c) return;
    c.animate({ zoom: { level: c.zoom() * factor, renderedPosition: { x: c.width() / 2, y: c.height() / 2 } } }, { duration: 200 });
  };

  const exportJson = () => {
    if (!query.data) return;
    download("rased-network-map.json", URL.createObjectURL(new Blob([JSON.stringify(query.data, null, 2)], { type: "application/json" })));
  };

  const legendColors: Record<string, [string, string][]> = {
    type: Object.entries(TYPE_COLORS).filter(([k]) => typeCounts[k]).map(([k, v]) => [label(DEVICE_TYPES, k), v]),
    status: Object.entries(STATUS_COLORS).map(([k, v]) => [label(ASSET_STATUS, k), v]),
    os: Object.entries(OS_COLORS).map(([k, v]) => [label(OS_FAMILIES, k), v]),
    risk: [["عليه تنبيهات مفتوحة", RISK_COLORS.alert], ["5 خدمات مفتوحة أو أكثر", RISK_COLORS.exposed], ["لا ملاحظات", RISK_COLORS.ok]],
  };
  const stats = query.data?.stats;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">خريطة الشبكة</h1>
          <p className="text-sm text-slate-500">اسحب العناصر لترتيبها • عجلة الفأرة للتكبير • نقرة لعرض التفاصيل • نقرتان لفتح صفحة الجهاز • Esc لإلغاء التمييز</p>
        </div>
        {stats && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <RescanAllButton />
            <Badge tone="blue">شبكات: {stats.networks}</Badge>
            <Badge tone="teal">أجهزة: {stats.devices} (ظاهر {visibleCount})</Badge>
            <Badge tone="red">موجّهات: {stats.routers}</Badge>
            <Badge tone="purple">مسارات مرصودة: {stats.paths}</Badge>
          </div>
        )}
      </div>

      <div ref={wrapper} className={fullscreen ? "h-screen overflow-auto bg-slate-50 p-3" : ""}>
        <Card>
          {/* Display controls */}
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <input className={`${inputClass} max-w-xs`} placeholder="بحث: عنوان، اسم، طراز، MAC، شبكة…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="بحث في الخريطة" />
            <select className={`${inputClass} w-auto`} value={layout} onChange={(e) => {
              const next = e.target.value;
              // Toggling Fusion rebuilds the graph (different elements) and runs the layout itself;
              // switching between non-Fusion layouts keeps the elements, so run it here.
              const sameMode = (next === "fusion") === fusion;
              setLayout(next);
              if (sameMode) runLayout(next);
            }} aria-label="طريقة الترتيب">
              {Object.entries(LAYOUTS).map(([k, v]) => <option key={k} value={k}>ترتيب: {v}</option>)}
            </select>
            <select className={`${inputClass} w-auto`} value={colorMode} onChange={(e) => setColorMode(e.target.value as ColorMode)} aria-label="التلوين">
              {Object.entries(COLOR_MODES).map(([k, v]) => <option key={k} value={k}>تلوين {v}</option>)}
            </select>
            <select className={`${inputClass} w-auto`} value={labelMode} onChange={(e) => setLabelMode(e.target.value as LabelMode)} aria-label="التسميات">
              {Object.entries(LABEL_MODES).map(([k, v]) => <option key={k} value={k}>تسميات: {v}</option>)}
            </select>
            <label className={`flex items-center gap-1.5 text-sm ${fusion ? "opacity-40" : ""}`} title={fusion ? "غير متاح في نمط النقاط المتفرّعة" : ""}><input type="checkbox" checked={group && !fusion} disabled={fusion} onChange={(e) => setGroup(e.target.checked)} /> تجميع الأجهزة داخل شبكاتها</label>
            <label className="flex items-center gap-1.5 text-sm"><input type="checkbox" checked={includeDevices} onChange={(e) => setIncludeDevices(e.target.checked)} /> كل الأجهزة</label>
          </div>
          {/* Navigation & actions */}
          <div className="mb-3 flex flex-wrap items-center gap-1.5">
            <ToolButton title="تكبير" onClick={() => zoomBy(1.3)}>＋</ToolButton>
            <ToolButton title="تصغير" onClick={() => zoomBy(1 / 1.3)}>－</ToolButton>
            <ToolButton title="ملاءمة الخريطة للشاشة" onClick={() => cy.current?.animate({ fit: { eles: cy.current.elements().not(".hidden"), padding: 40 } }, { duration: 300 })}>⤢</ToolButton>
            <ToolButton title="التركيز على خادم راصد" onClick={() => { const s = cy.current?.getElementById("scanner"); if (s?.nonempty()) cy.current?.animate({ center: { eles: s }, zoom: 1.2 }, { duration: 300 }); }}>★</ToolButton>
            <ToolButton title={fullscreen ? "إنهاء ملء الشاشة" : "ملء الشاشة"} active={fullscreen}
              onClick={() => (document.fullscreenElement ? void document.exitFullscreen() : void wrapper.current?.requestFullscreen())}>⛶</ToolButton>
            <span className="mx-1 h-6 w-px bg-slate-200" />
            <ToolButton title="إعادة الترتيب التلقائي" onClick={() => { kept.current = {}; clearPositions(); runLayout(layout); setNotice("أُعيد ترتيب الخريطة."); }}>↻ ترتيب</ToolButton>
            <ToolButton title="تثبيت مواقع العناصر" active={locked} onClick={() => setLocked(!locked)}>{locked ? "🔒 مثبتة" : "🔓 تثبيت"}</ToolButton>
            <ToolButton title="حفظ الترتيب الحالي" onClick={() => { if (cy.current) setNotice(`تم حفظ مواقع ${savePositions(cy.current)} عنصراً، وستُستخدم عند فتح الخريطة.`); }}>💾 حفظ الترتيب</ToolButton>
            <ToolButton title="تحديث مباشر كل 30 ثانية" active={live} onClick={() => setLive(!live)}>{live ? "● مباشر" : "○ مباشر"}</ToolButton>
            <ToolButton title="إظهار كل العناصر وإلغاء التمييز" onClick={() => { setFilters(emptyFilters()); if (cy.current) clearHighlight(cy.current); setSearch(""); }}>إظهار الكل</ToolButton>
            <span className="mx-1 h-6 w-px bg-slate-200" />
            <Button variant="secondary" onClick={() => { const uri = cy.current?.png({ full: true, scale: 2, bg: "#ffffff" }); if (uri) download("rased-network-map.png", uri); }}>
              <IconDownload className="h-4 w-4" /> صورة
            </Button>
            <Button variant="secondary" onClick={exportJson}><IconDownload className="h-4 w-4" /> بيانات JSON</Button>
            {can("scan:run") && (
              <div className="ms-auto flex flex-wrap items-center gap-1.5">
                <input className={`${inputClass} w-40`} dir="ltr" placeholder="عنوان داخلي لتتبعه" value={traceTarget} onChange={(e) => setTraceTarget(e.target.value)} aria-label="عنوان لتتبع المسار إليه" />
                <Button onClick={() => trace.mutate(traceTarget.trim() ? [traceTarget.trim()] : [])} disabled={trace.isPending}>
                  <IconRefresh className="h-4 w-4" /> {trace.isPending ? "جارٍ التتبع…" : "اكتشاف المسارات"}
                </Button>
              </div>
            )}
          </div>
          {(trace.error || rescan.error) && <ErrorBox error={errorMessage(trace.error ?? rescan.error)} />}
          {notice && <p className="mb-2 rounded-lg bg-emerald-50 px-3 py-1.5 text-xs text-emerald-800">{notice}</p>}

          <div className="grid gap-4 xl:grid-cols-[250px_1fr_300px]">
            {/* Filters */}
            <div className="space-y-3 text-sm">
              <div>
                <div className="mb-1 font-semibold text-slate-700">العرض</div>
                <label className="flex items-center gap-1.5"><input type="checkbox" checked={filters.hideOffline} onChange={(e) => setFilters({ ...filters, hideOffline: e.target.checked })} /> إخفاء غير المتصلة</label>
                <label className="flex items-center gap-1.5"><input type="checkbox" checked={filters.infraOnly} onChange={(e) => setFilters({ ...filters, infraOnly: e.target.checked })} /> الموجّهات والمسارات فقط</label>
                {filters.hiddenIds.size > 0 && (
                  <button type="button" className="mt-1 text-xs text-cyan-800 underline" onClick={() => setFilters({ ...filters, hiddenIds: new Set() })}>إظهار العناصر المخفية يدوياً ({filters.hiddenIds.size})</button>
                )}
              </div>
              <div>
                <div className="mb-1 font-semibold text-slate-700">أنواع الأجهزة</div>
                <div className="max-h-56 space-y-0.5 overflow-auto">
                  {Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).map(([t, n]) => (
                    <label key={t} className="flex items-center gap-1.5">
                      <input type="checkbox" checked={!filters.hiddenTypes.has(t)} onChange={(e) => {
                        const next = new Set(filters.hiddenTypes);
                        if (e.target.checked) next.delete(t); else next.add(t);
                        setFilters({ ...filters, hiddenTypes: next });
                      }} />
                      <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: TYPE_COLORS[t] ?? TYPE_COLORS.unknown }} />
                      {label(DEVICE_TYPES, t)} <span className="text-xs text-slate-400">({n})</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <div className="mb-1 font-semibold text-slate-700">الشبكات</div>
                <div className="max-h-56 space-y-0.5 overflow-auto">
                  {networks.map((n) => (
                    <label key={n.id} className="flex items-center gap-1.5">
                      <input type="checkbox" checked={!filters.hiddenNetworks.has(n.id)} onChange={(e) => {
                        const next = new Set(filters.hiddenNetworks);
                        if (e.target.checked) next.delete(n.id); else next.add(n.id);
                        setFilters({ ...filters, hiddenNetworks: next });
                      }} />
                      <Ltr className="text-xs">{n.cidr}</Ltr> <span className="text-xs text-slate-400">({n.devices ?? 0})</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <div className="mb-1 font-semibold text-slate-700">الألوان ({COLOR_MODES[colorMode]})</div>
                <ul className="space-y-0.5 text-xs text-slate-600">
                  {legendColors[colorMode].map(([name, color]) => (
                    <li key={name}><span className="me-1.5 inline-block h-2.5 w-2.5 rounded-full align-middle" style={{ background: color }} />{name}</li>
                  ))}
                </ul>
                <ul className="mt-2 space-y-0.5 text-[11px] text-slate-500">
                  <li>◆ موجّه / قفزة مسار — ▲ نقطة وصول — ■ خادم</li>
                  <li><span className="me-1 inline-block h-0.5 w-5 bg-[#e11d48] align-middle" />مسار توجيه مرصود</li>
                  <li><span className="me-1 inline-block w-5 border-t-2 border-dashed border-slate-400 align-middle" />علاقة مستنتجة</li>
                  <li>إطار أصفر = بوابة الشبكة • إطار أحمر = تنبيهات</li>
                  <li>حجم الجهاز يكبر بعدد خدماته المفتوحة</li>
                </ul>
              </div>
            </div>

            {/* Map */}
            <div className="relative overflow-hidden rounded-2xl border border-slate-200 bg-[radial-gradient(circle_at_1px_1px,#e2e8f0_1px,transparent_0)] [background-size:22px_22px]">
              {query.isLoading && <div className="absolute inset-0 grid place-items-center"><Loading /></div>}
              {query.error && <div className="p-4"><ErrorBox error={query.error} /></div>}
              {locked && <div className="absolute start-3 top-3 z-10 rounded-lg bg-slate-800/80 px-2 py-0.5 text-xs text-white">المواقع مثبتة</div>}
              <div ref={container} dir="ltr" style={{ height: fullscreen ? "calc(100vh - 210px)" : "70vh", minHeight: 480 }} aria-label="خريطة الشبكة التفاعلية" />
            </div>

            {/* Details */}
            <Card title="التفاصيل">
              {!selected ? <p className="text-sm text-slate-500">اختر عنصراً من الخريطة.</p> : selected.kind === "edge" ? (
                <div className="space-y-1 text-sm">
                  <div className="font-semibold">{EDGE_KINDS[selected.data.kind] ?? selected.data.kind}</div>
                  <div>{selected.data.label_ar}</div>
                  <Badge tone={selected.data.verified ? "green" : "amber"}>{selected.data.verified ? "علاقة مؤكدة (مرصودة)" : "علاقة مستنتجة"}</Badge>
                </div>
              ) : (
                <div className="space-y-3">
                  <NodeDetails node={selected.data} />
                  <div className="flex flex-wrap gap-1.5">
                    {selected.data.id !== "scanner" && (
                      <Button variant="secondary" onClick={() => { if (cy.current) { const hops = highlightPath(cy.current, selected.data.id); setNotice(hops < 0 ? "لا يوجد مسار معروف من خادم راصد إلى هذا العنصر." : `المسار من خادم راصد: ${hops} وصلة.`); } }}>إظهار المسار من راصد</Button>
                    )}
                    <Button variant="secondary" onClick={() => { if (cy.current) { focusNeighborhood(cy.current, selected.data.id, 1); cy.current.animate({ fit: { eles: cy.current.elements(".focus"), padding: 60 } }, { duration: 300 }); } }}>الجيران فقط</Button>
                    {selected.data.id !== "scanner" && (
                      <Button variant="ghost" onClick={() => {
                        const next = new Set(filters.hiddenIds);
                        next.add(selected.data.id);
                        if (selected.data.type === "network") setFilters({ ...filters, hiddenNetworks: new Set([...filters.hiddenNetworks, selected.data.id]) });
                        else setFilters({ ...filters, hiddenIds: next });
                        setSelected(null);
                      }}>إخفاء من الخريطة</Button>
                    )}
                    {selected.data.asset_id && can("scan:run") && (
                      <Button disabled={rescan.isPending} onClick={() => rescan.mutate(selected.data.asset_id as number)}>فحص هذا الجهاز</Button>
                    )}
                    {selected.data.ip && can("scan:run") && (
                      <Button variant="secondary" disabled={trace.isPending} onClick={() => trace.mutate([selected.data.ip as string])}>تتبع المسار إليه</Button>
                    )}
                  </div>
                </div>
              )}
            </Card>
          </div>
        </Card>
      </div>
    </div>
  );
}

function NodeDetails({ node }: { node: TopoNode }) {
  if (node.type === "network") {
    return (
      <div className="space-y-1 text-sm">
        <div className="font-semibold"><Ltr>{node.cidr}</Ltr></div>
        {node.scope_name && <div>النطاق: {node.scope_name}</div>}
        <div>النوع: {node.kind === "local" ? "متصلة مباشرة بخادم الفحص" : node.kind === "scope" ? "نطاق فحص" : "مستنتجة من الأجهزة المرصودة"}</div>
        <div>الأجهزة: {node.devices ?? 0} (متصل الآن: {node.online ?? 0})</div>
      </div>
    );
  }
  if (node.type === "scanner") {
    return <div className="text-sm">خادم راصد — العناوين: <Ltr>{(node.ips ?? []).join(", ")}</Ltr></div>;
  }
  return (
    <div className="space-y-1.5 text-sm">
      <div className="font-semibold">{node.label}</div>
      <div><Ltr>{node.ip}</Ltr>{node.mac && <> — <Ltr className="text-xs">{node.mac}</Ltr></>}</div>
      <div>{label(DEVICE_TYPES, node.device_type)}{node.os_family && node.os_family !== "unknown" ? ` — ${label(OS_FAMILIES, node.os_family)}` : ""}</div>
      {(node.model || node.vendor) && <div className="text-slate-600">{node.model ?? node.vendor}</div>}
      {node.type === "device" && <div className="text-xs text-slate-600">خدمات مفتوحة: {node.open_services ?? 0}</div>}
      <div className="flex flex-wrap gap-1">
        {node.status && <Badge tone={STATUS_TONE[node.status]}>{label(ASSET_STATUS, node.status)}</Badge>}
        {node.is_gateway && <Badge tone="amber">بوابة الشبكة</Badge>}
        {node.type === "hop" && <Badge tone="red">قفزة توجيه (غير مفحوصة)</Badge>}
        {(node.open_alerts ?? 0) > 0 && <Badge tone="red">تنبيهات: {node.open_alerts}</Badge>}
      </div>
      {node.asset_id && <Link className="text-cyan-800 underline" to={`/assets/${node.asset_id}`}>فتح صفحة الجهاز</Link>}
    </div>
  );
}
