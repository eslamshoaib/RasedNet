import { useMutation, useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { IconDownload, IconRefresh } from "../components/icons";
import { Badge, Button, Card, ErrorBox, inputClass, Loading } from "../components/ui";
import type { Asset, Page, PhysicalGraph, SnmpCollectResult, SnmpCredential } from "../types";
import { TYPE_COLORS } from "./topologyModel";

const FONT = '"Cairo", "Segoe UI", Tahoma, sans-serif';
const INFRA_TYPES = ["switch", "router", "access_point", "network_device"];

const STYLE: cytoscape.StylesheetJson = [
  { selector: "node", style: {
    label: "data(label)", "font-family": FONT, "font-size": 10, "text-valign": "bottom", "text-margin-y": 3,
    color: "#1e293b", "text-background-color": "#fff", "text-background-opacity": 0.85, "text-background-padding": "2px",
    width: 34, height: 34, "background-color": "data(color)", "border-width": 2, "border-color": "#fff", "min-zoomed-font-size": 7,
  } },
  { selector: "node[kind = 'external']", style: { shape: "round-rectangle", "background-color": "#94a3b8", "border-style": "dashed", "border-color": "#64748b" } },
  { selector: "node[device_type = 'switch'], node[device_type = 'network_device']", style: { shape: "round-rectangle" } },
  { selector: "node[device_type = 'router']", style: { shape: "diamond" } },
  { selector: "node[device_type = 'access_point']", style: { shape: "triangle" } },
  { selector: "edge", style: {
    width: 2, "line-color": "#0891b2", "curve-style": "bezier", label: "data(label)", "font-family": FONT,
    "font-size": 8, color: "#475569", "text-background-color": "#fff", "text-background-opacity": 0.8, "text-rotation": "autorotate",
  } },
  { selector: "edge[source_kind = 'fdb']", style: { "line-color": "#94a3b8", "line-style": "dashed" } },
  { selector: "edge[source_kind = 'cdp']", style: { "line-color": "#7c3aed" } },
  { selector: ":selected", style: { "overlay-color": "#0891b2", "overlay-opacity": 0.2, "overlay-padding": 6 } },
];

function CollectPanel({ onDone }: { onDone: () => void }) {
  const assets = useQuery({
    queryKey: ["infra-assets"],
    queryFn: async () => {
      const pages = await Promise.all(INFRA_TYPES.map((t) =>
        api<Page<Asset>>("/api/assets", { query: { device_type: t, page_size: 200 } })));
      return pages.flatMap((p) => p.items);
    },
  });
  const creds = useQuery({ queryKey: ["snmp-creds"], queryFn: () => api<SnmpCredential[]>("/api/physical/credentials") });
  const [assetId, setAssetId] = useState<number | "">("");
  const [credId, setCredId] = useState<number | "">("");
  const [result, setResult] = useState<SnmpCollectResult | null>(null);
  const collect = useMutation({
    mutationFn: () => api<SnmpCollectResult>(`/api/physical/assets/${assetId}/collect`, { method: "POST", body: { credential_id: credId } }),
    onSuccess: (r) => { setResult(r); onDone(); },
  });
  const noCreds = (creds.data?.length ?? 0) === 0;

  return (
    <Card title="جمع الاتصالات الفيزيائية عبر SNMP">
      {noCreds && <ErrorBox error="لا يوجد حساب SNMP في الخزنة. أضف حساب SNMP v2c (سلسلة المجتمع) من «خزنة الدخول للأجهزة»." />}
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-sm">
          <span className="mb-0.5 block text-slate-600">المحوّل / الموجّه</span>
          <select className={`${inputClass} w-64`} value={assetId} onChange={(e) => setAssetId(e.target.value ? Number(e.target.value) : "")}>
            <option value="">اختر جهاز شبكة…</option>
            {assets.data?.map((a) => <option key={a.id} value={a.id}>{(a.display_name || a.hostname || a.current_ip)} — {a.current_ip}</option>)}
          </select>
        </label>
        <label className="text-sm">
          <span className="mb-0.5 block text-slate-600">حساب SNMP</span>
          <select className={`${inputClass} w-48`} value={credId} onChange={(e) => setCredId(e.target.value ? Number(e.target.value) : "")}>
            <option value="">اختر حساباً…</option>
            {creds.data?.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <Button onClick={() => collect.mutate()} disabled={!assetId || !credId || collect.isPending}>
          <IconRefresh className="h-4 w-4" /> {collect.isPending ? "جارٍ القراءة…" : "اقرأ الجهاز"}
        </Button>
      </div>
      {collect.error && <div className="mt-2"><ErrorBox error={errorMessage(collect.error)} /></div>}
      {result && (
        <p className="mt-2 rounded-lg bg-emerald-50 px-3 py-1.5 text-sm text-emerald-800">
          {result.sys_name || "الجهاز"}: LLDP {result.counts.lldp}، CDP {result.counts.cdp}، FDB {result.counts.fdb}.
          خُزِّن {result.stored.total} رابطاً، منها {result.stored.resolved} مرتبطة بأجهزة معروفة.
        </p>
      )}
    </Card>
  );
}

export function PhysicalPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const graph = useQuery({ queryKey: ["physical-graph"], queryFn: () => api<PhysicalGraph>("/api/physical/graph") });
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<cytoscape.Core | null>(null);

  const elements = useMemo<cytoscape.ElementDefinition[]>(() => {
    if (!graph.data) return [];
    const nodes = graph.data.nodes.map((n) => ({ data: {
      ...n, color: n.kind === "external" ? "#94a3b8" : (TYPE_COLORS[n.device_type ?? "unknown"] ?? TYPE_COLORS.unknown),
    } }));
    const edges = graph.data.edges.map((e) => ({ data: { ...e } }));
    return [...nodes, ...edges];
  }, [graph.data]);

  useEffect(() => {
    if (!container.current || !elements.length) return;
    cy.current?.destroy();
    const instance = cytoscape({
      container: container.current, elements, style: STYLE, wheelSensitivity: 0.25, minZoom: 0.1, maxZoom: 4,
      layout: { name: "cose", animate: false, nodeRepulsion: () => 8000, idealEdgeLength: () => 90, padding: 40 } as cytoscape.LayoutOptions,
    });
    instance.on("dbltap", "node[asset_id]", (e) => navigate(`/assets/${e.target.data("asset_id")}`));
    cy.current = instance;
    return () => { instance.destroy(); };
  }, [elements, navigate]);

  useEffect(() => () => { cy.current?.destroy(); cy.current = null; }, []);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">التوبولوجي الفيزيائي (SNMP/LLDP)</h1>
          <p className="text-sm text-slate-500">الروابط الفعلية بين المنافذ كما تقرؤها المحوّلات: من متصل بأي منفذ. نقرتان على جهاز لفتح صفحته.</p>
        </div>
        {graph.data && (
          <div className="flex gap-2 text-xs">
            <Badge tone="teal">روابط: {graph.data.stats.links}</Badge>
            <Badge tone="blue">عناصر: {graph.data.stats.nodes}</Badge>
            <Badge tone="green">مرتبطة بأجهزة معروفة: {graph.data.stats.resolved}</Badge>
          </div>
        )}
      </div>

      {can("remote:verify") && <CollectPanel onDone={() => graph.refetch()} />}

      <Card>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <Button variant="secondary" onClick={() => graph.refetch()}><IconRefresh className="h-4 w-4" /> تحديث</Button>
          <Button variant="secondary" onClick={() => cy.current?.fit(undefined, 40)}>⤢ ملاءمة</Button>
          <Button variant="secondary" onClick={() => { const uri = cy.current?.png({ full: true, scale: 2, bg: "#fff" }); if (uri) { const a = document.createElement("a"); a.href = uri; a.download = "rased-physical-map.png"; a.click(); } }}>
            <IconDownload className="h-4 w-4" /> صورة
          </Button>
          <span className="text-xs text-slate-500">◆ موجّه — ▲ نقطة وصول — ▢ محوّل — خط متصل = LLDP، بنفسجي = CDP، متقطّع = جدول التوجيه</span>
        </div>
        <div className="relative overflow-hidden rounded-2xl border border-slate-200 bg-[radial-gradient(circle_at_1px_1px,#e2e8f0_1px,transparent_0)] [background-size:22px_22px]">
          {graph.isLoading && <div className="absolute inset-0 grid place-items-center"><Loading /></div>}
          {graph.error && <div className="p-4"><ErrorBox error={graph.error} /></div>}
          {!graph.isLoading && !elements.length && (
            <div className="grid h-72 place-items-center p-4 text-center text-sm text-slate-500">
              لا توجد روابط فيزيائية بعد. اختر محوّلاً وحساب SNMP بالأعلى واضغط «اقرأ الجهاز» لرسم الاتصالات.
            </div>
          )}
          <div ref={container} dir="ltr" style={{ height: "66vh", minHeight: 420, display: elements.length ? "block" : "none" }} aria-label="الخريطة الفيزيائية" />
        </div>
      </Card>
    </div>
  );
}
