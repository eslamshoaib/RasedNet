/** Network-map model: element building, colouring, labels, filters, focus and saved layouts.
 *  Pure functions over plain data or a Cytoscape Core, so they are testable headless. */
import type cytoscape from "cytoscape";
import { getLang, t } from "../i18n";
import type { TopoNode, Topology } from "../types";

export type ColorMode = "type" | "status" | "risk" | "os";
export type LabelMode = "both" | "name" | "ip" | "none";

export const TYPE_COLORS: Record<string, string> = {
  router: "#e11d48", access_point: "#f97316", switch: "#f59e0b", network_device: "#f59e0b", server: "#7c3aed",
  computer: "#0284c7", mobile: "#16a34a", tablet: "#16a34a", printer: "#0d9488", camera: "#be185d", tv: "#9333ea",
  nas: "#4f46e5", iot: "#65a30d", virtual_machine: "#64748b", hypervisor: "#475569", unknown: "#94a3b8",
};
export const STATUS_COLORS: Record<string, string> = { online: "#16a34a", offline: "#94a3b8", unknown: "#64748b" };
export const OS_COLORS: Record<string, string> = {
  windows: "#0284c7", linux: "#ea580c", unix: "#c2410c", macos: "#6b7280", ios: "#6b7280", android: "#16a34a",
  network_os: "#e11d48", unknown: "#94a3b8",
};
export const RISK_COLORS = { alert: "#dc2626", exposed: "#f97316", ok: "#16a34a" } as const;

export const colorModes = (): Record<ColorMode, string> => ({
  type: t("حسب نوع الجهاز", "By device type"), status: t("حسب الحالة", "By status"),
  risk: t("حسب الخطورة", "By risk"), os: t("حسب نظام التشغيل", "By operating system"),
});
export const labelModes = (): Record<LabelMode, string> => ({
  both: t("الاسم والعنوان", "Name & address"), name: t("الاسم فقط", "Name only"),
  ip: t("العنوان فقط", "Address only"), none: t("بدون تسميات", "No labels"),
});

const INFRA_TYPES = new Set(["router", "access_point", "switch", "network_device"]);

export function colorFor(node: Pick<TopoNode, "device_type" | "status" | "os_family" | "open_alerts" | "open_services">, mode: ColorMode): string {
  switch (mode) {
    case "status": return STATUS_COLORS[node.status ?? "unknown"] ?? STATUS_COLORS.unknown;
    case "os": return OS_COLORS[node.os_family ?? "unknown"] ?? OS_COLORS.unknown;
    case "risk":
      if ((node.open_alerts ?? 0) > 0) return RISK_COLORS.alert;
      if ((node.open_services ?? 0) >= 5) return RISK_COLORS.exposed;
      return RISK_COLORS.ok;
    default: return TYPE_COLORS[node.device_type ?? "unknown"] ?? TYPE_COLORS.unknown;
  }
}

export function labelFor(node: TopoNode, mode: LabelMode): string {
  if (node.type === "network") return `${node.cidr ?? node.label}${node.devices ? `\n${node.devices} ${getLang() === "en" ? "devices" : "جهاز"}` : ""}`;
  if (node.type === "scanner") return mode === "none" ? "" : node.label;
  const name = node.label && node.label !== node.ip ? node.label : "";
  switch (mode) {
    case "none": return "";
    case "ip": return node.ip ?? name;
    case "name": return name || node.ip || "";
    default: return name && node.ip ? `${name}\n${node.ip}` : name || node.ip || "";
  }
}

/** Node size grows with exposure (open services), bounded so the map stays readable. */
export function sizeFor(node: TopoNode): number {
  if (node.type !== "device" && node.type !== "hop") return 0;
  return Math.min(46, 20 + 3 * Math.sqrt(node.open_services ?? 0) * 2);
}

/** In Fusion (radial dots) mode a network is a dot whose size grows with its device count. */
export function networkDotSize(devices: number | undefined): number {
  return Math.min(78, 30 + 5 * Math.sqrt(devices ?? 0));
}

export interface BuildOptions {
  group: boolean; // devices drawn inside their network box (compound nodes)
  colorMode: ColorMode;
  labelMode: LabelMode;
  fusion?: boolean; // radial "Fusion" graph: every node is a dot, lines cascade from the scanner
}

export function toElements(data: Topology, opts: BuildOptions): cytoscape.ElementDefinition[] {
  // A device's network = target of its verified "member" edge.
  // Fusion (radial dots) mode never groups: devices stay separate dots linked by member edges.
  const parentOf = new Map<string, string>();
  if (opts.group && !opts.fusion) {
    for (const e of data.edges) {
      if (e.kind === "member" && e.source.startsWith("a:") && e.target.startsWith("net:") && !parentOf.has(e.source)) {
        parentOf.set(e.source, e.target);
      }
    }
  }
  const nodes: cytoscape.ElementDefinition[] = data.nodes.map((n) => ({
    group: "nodes",
    data: {
      ...n,
      display: labelFor(n, opts.labelMode),
      color: n.type === "device" || n.type === "hop" ? colorFor(n, opts.colorMode) : undefined,
      // In Fusion mode a network becomes a sized dot instead of a box.
      size: opts.fusion && n.type === "network" ? networkDotSize(n.devices) : sizeFor(n) || undefined,
      dot: opts.fusion && n.type === "network" ? 1 : undefined,
      infra: n.type === "hop" || INFRA_TYPES.has(n.device_type ?? "") || n.is_gateway ? 1 : 0,
      ...(parentOf.has(n.id) ? { parent: parentOf.get(n.id) } : {}),
    },
  }));
  const edges: cytoscape.ElementDefinition[] = data.edges
    // In grouped mode membership is shown by containment, so the member edge is redundant.
    .filter((e) => !(opts.group && e.kind === "member" && parentOf.get(e.source) === e.target))
    .map((e) => ({ group: "edges", data: { ...e } }));
  return [...nodes, ...edges];
}

export interface Filters {
  hiddenTypes: Set<string>;
  hiddenNetworks: Set<string>;
  hideOffline: boolean;
  infraOnly: boolean;
  hiddenIds: Set<string>;
}

export const emptyFilters = (): Filters => ({
  hiddenTypes: new Set(), hiddenNetworks: new Set(), hideOffline: false, infraOnly: false, hiddenIds: new Set(),
});

/** Hide (display:none) every node excluded by the filters; edges of hidden nodes disappear with them. */
export function applyFilters(cy: cytoscape.Core, f: Filters): number {
  cy.batch(() => {
    cy.nodes().forEach((n) => {
      const type = n.data("type") as string;
      let hide = f.hiddenIds.has(n.id());
      if (type === "network") {
        hide = hide || f.hiddenNetworks.has(n.id());
      } else if (type === "device") {
        const parent = n.data("parent") as string | undefined;
        hide = hide
          || f.hiddenTypes.has(n.data("device_type") ?? "unknown")
          || (f.hideOffline && n.data("status") === "offline")
          || (f.infraOnly && !n.data("infra"))
          || (!!parent && f.hiddenNetworks.has(parent));
      }
      if (hide) n.addClass("hidden");
      else n.removeClass("hidden");
    });
    // Ungrouped devices are hidden together with their network (via the member edge).
    cy.edges("[kind = 'member']").forEach((e) => {
      if (e.target().hasClass("hidden") && e.source().data("type") === "device") e.source().addClass("hidden");
    });
  });
  return cy.nodes("[type = 'device'], [type = 'hop']").not(".hidden").length;
}

export function clearHighlight(cy: cytoscape.Core): void {
  cy.elements().removeClass("faded onpath match focus");
}

/** Highlight the shortest path from the RasedNet server to the given element. Returns hop count or -1. */
export function highlightPath(cy: cytoscape.Core, targetId: string): number {
  clearHighlight(cy);
  const root = cy.getElementById("scanner");
  const target = cy.getElementById(targetId);
  if (root.empty() || target.empty()) return -1;
  const visible = cy.elements().not(".hidden");
  const result = visible.dijkstra({ root, directed: false });
  let path = result.pathTo(target);
  if (path.length <= 1 && targetId !== "scanner") {
    // A grouped device has no edges of its own: route to the network box that contains it.
    const container = target.parent();
    if (container.nonempty()) path = result.pathTo(container.first());
    if (path.length <= 1) return -1;
    path = path.union(target);
  }
  cy.elements().addClass("faded");
  path.removeClass("faded").addClass("onpath");
  target.ancestors().removeClass("faded");
  return path.edges().length;
}

/** Keep only the element, its neighbours up to ``depth`` hops, and their containing networks. */
export function focusNeighborhood(cy: cytoscape.Core, id: string, depth = 1): number {
  clearHighlight(cy);
  let set = cy.getElementById(id) as cytoscape.CollectionReturnValue;
  if (set.empty()) return 0;
  for (let i = 0; i < depth; i++) set = set.union(set.closedNeighborhood());
  set = set.union(set.ancestors()).union(set.descendants());
  cy.elements().addClass("faded");
  set.removeClass("faded").addClass("focus");
  return set.nodes().length;
}

export function searchNodes(cy: cytoscape.Core, term: string): cytoscape.NodeCollection {
  const t = term.trim().toLowerCase();
  clearHighlight(cy);
  if (!t) return cy.collection() as cytoscape.NodeCollection;
  const matches = cy.nodes().filter((n) => !n.hasClass("hidden") && ["label", "ip", "cidr", "model", "vendor", "hostname", "mac"]
    .some((k) => typeof n.data(k) === "string" && (n.data(k) as string).toLowerCase().includes(t)));
  if (matches.length) {
    cy.elements().addClass("faded");
    matches.removeClass("faded").addClass("match");
    matches.closedNeighborhood().removeClass("faded");
    matches.ancestors().removeClass("faded");
  }
  return matches;
}

// --- saved layouts ---------------------------------------------------------------------------

export type Positions = Record<string, { x: number; y: number }>;
const STORAGE_KEY = "rasednet.topology.positions.v1";

export function loadPositions(storage: Pick<Storage, "getItem"> | null = safeStorage()): Positions {
  try {
    const raw = storage?.getItem(STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? parsed as Positions : {};
  } catch {
    return {};
  }
}

export function savePositions(cy: cytoscape.Core, storage: Pick<Storage, "setItem"> | null = safeStorage()): number {
  const positions: Positions = {};
  // Compound (parent) positions derive from their children, so only leaf nodes are stored.
  cy.nodes().filter((n) => !n.isParent()).forEach((n) => { positions[n.id()] = { ...n.position() }; });
  try {
    storage?.setItem(STORAGE_KEY, JSON.stringify(positions));
  } catch {
    return 0;
  }
  return Object.keys(positions).length;
}

export function clearPositions(storage: Pick<Storage, "removeItem"> | null = safeStorage()): void {
  try {
    storage?.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable */
  }
}

/** Saved positions are reused when they cover most of the current leaf nodes. */
export function coverage(elements: cytoscape.ElementDefinition[], positions: Positions): number {
  const parents = new Set(elements.map((e) => e.data.parent as string | undefined).filter(Boolean));
  const leaves = elements.filter((e) => e.group === "nodes" && !parents.has(e.data.id as string));
  if (!leaves.length) return 0;
  return leaves.filter((e) => positions[e.data.id as string]).length / leaves.length;
}

function safeStorage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
}
