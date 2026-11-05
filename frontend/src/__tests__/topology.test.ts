import cytoscape from "cytoscape";
import { describe, expect, it } from "vitest";
import {
  applyFilters, colorFor, coverage, emptyFilters, focusNeighborhood, highlightPath, labelFor, loadPositions,
  networkDotSize, RISK_COLORS, savePositions, searchNodes, sizeFor, toElements, TYPE_COLORS,
} from "../pages/topologyModel";
import type { TopoNode, Topology } from "../types";

const DATA: Topology = {
  nodes: [
    { id: "scanner", type: "scanner", label: "خادم راصد", ips: ["10.150.12.85"] },
    { id: "net:10.150.0.0/20", type: "network", kind: "local", label: "lan", cidr: "10.150.0.0/20", devices: 3 },
    { id: "net:10.20.0.0/24", type: "network", kind: "scope", label: "remote", cidr: "10.20.0.0/24", devices: 1 },
    { id: "a:1", type: "device", label: "gw", ip: "10.150.0.1", device_type: "router", status: "online", is_gateway: true, open_services: 2, asset_id: 1 },
    { id: "a:2", type: "device", label: "crimedata", ip: "10.150.0.10", device_type: "computer", os_family: "windows", status: "online", open_alerts: 2, open_services: 9, asset_id: 2 },
    { id: "a:3", type: "device", label: "10.150.3.3", ip: "10.150.3.3", device_type: "printer", status: "offline", open_services: 0, asset_id: 3 },
    { id: "a:4", type: "device", label: "srv", ip: "10.20.0.9", device_type: "server", status: "online", asset_id: 4 },
    { id: "hop:10.10.10.29", type: "hop", label: "10.10.10.29", ip: "10.10.10.29", device_type: "router" },
  ],
  edges: [
    { id: "e1", source: "scanner", target: "net:10.150.0.0/20", kind: "attached", verified: true, label_ar: "" },
    { id: "e2", source: "a:1", target: "net:10.150.0.0/20", kind: "member", verified: true, label_ar: "" },
    { id: "e3", source: "a:2", target: "net:10.150.0.0/20", kind: "member", verified: true, label_ar: "" },
    { id: "e4", source: "a:3", target: "net:10.150.0.0/20", kind: "member", verified: true, label_ar: "" },
    { id: "e5", source: "a:4", target: "net:10.20.0.0/24", kind: "member", verified: true, label_ar: "" },
    { id: "e6", source: "scanner", target: "a:1", kind: "path", verified: true, label_ar: "" },
    { id: "e7", source: "a:1", target: "hop:10.10.10.29", kind: "path", verified: false, label_ar: "" },
    { id: "e8", source: "hop:10.10.10.29", target: "net:10.20.0.0/24", kind: "routes", verified: true, label_ar: "" },
  ],
  stats: { networks: 2, devices: 4, routers: 2, paths: 1, truncated: false },
};

const build = (group = true) =>
  cytoscape({ headless: true, styleEnabled: false, elements: toElements(DATA, { group, colorMode: "type", labelMode: "both" }) });

describe("colours, labels, sizes", () => {
  it("colours by mode", () => {
    const pc = DATA.nodes[4];
    expect(colorFor(pc, "type")).toBe(TYPE_COLORS.computer);
    expect(colorFor(pc, "risk")).toBe(RISK_COLORS.alert);
    expect(colorFor({ ...pc, open_alerts: 0 }, "risk")).toBe(RISK_COLORS.exposed);
    expect(colorFor({ ...pc, open_alerts: 0, open_services: 1 }, "risk")).toBe(RISK_COLORS.ok);
    expect(colorFor(DATA.nodes[5], "status")).not.toBe(colorFor(pc, "status"));
  });

  it("labels by mode and never duplicates an IP used as name", () => {
    const pc = DATA.nodes[4] as TopoNode;
    expect(labelFor(pc, "both")).toBe("crimedata\n10.150.0.10");
    expect(labelFor(pc, "ip")).toBe("10.150.0.10");
    expect(labelFor(pc, "none")).toBe("");
    expect(labelFor(DATA.nodes[5], "both")).toBe("10.150.3.3");
    expect(labelFor(DATA.nodes[1], "none")).toContain("10.150.0.0/20"); // networks always labelled
  });

  it("sizes grow with exposure but stay bounded", () => {
    expect(sizeFor(DATA.nodes[5])).toBe(20);
    expect(sizeFor(DATA.nodes[4])).toBeGreaterThan(sizeFor(DATA.nodes[3]));
    expect(sizeFor({ ...DATA.nodes[4], open_services: 10_000 })).toBe(46);
  });

  it("network dot size grows with device count but stays bounded", () => {
    expect(networkDotSize(0)).toBe(30);
    expect(networkDotSize(9)).toBeGreaterThan(networkDotSize(1));
    expect(networkDotSize(100_000)).toBe(78);
  });
});

describe("Fusion (radial dots) mode", () => {
  it("turns networks into sized dots and never groups devices into boxes", () => {
    const cy = cytoscape({ headless: true, styleEnabled: false,
      elements: toElements(DATA, { group: true, fusion: true, colorMode: "type", labelMode: "both" }) });
    const net = cy.getElementById("net:10.150.0.0/20");
    expect(net.isParent()).toBe(false); // no compound boxes in Fusion mode
    expect(net.data("dot")).toBe(1);
    expect(net.data("size")).toBe(networkDotSize(3));
    // Every device keeps its own member edge so lines cascade network → devices.
    expect(cy.edges("[kind = 'member']").length).toBe(4);
    expect(cy.getElementById("a:2").parent().empty()).toBe(true);
  });
});

describe("graph behaviour (headless Cytoscape)", () => {
  it("groups devices inside their networks and drops redundant member edges", () => {
    const cy = build(true);
    expect(cy.getElementById("a:2").parent().id()).toBe("net:10.150.0.0/20");
    expect(cy.getElementById("net:10.150.0.0/20").isParent()).toBe(true);
    expect(cy.edges("[kind = 'member']").length).toBe(0);
    expect(build(false).edges("[kind = 'member']").length).toBe(4);
  });

  it("filters by type, status, network and infrastructure-only", () => {
    for (const group of [true, false]) {
      const cy = build(group);
      expect(applyFilters(cy, emptyFilters())).toBe(5);
      expect(applyFilters(cy, { ...emptyFilters(), hiddenTypes: new Set(["printer"]) })).toBe(4);
      expect(applyFilters(cy, { ...emptyFilters(), hideOffline: true })).toBe(4);
      expect(applyFilters(cy, { ...emptyFilters(), hiddenNetworks: new Set(["net:10.20.0.0/24"]) })).toBe(4);
      expect(cy.getElementById("a:4").hasClass("hidden")).toBe(true);
      expect(applyFilters(cy, { ...emptyFilters(), infraOnly: true })).toBe(2); // gateway router + hop
    }
  });

  it("highlights the path from the scanner through observed hops", () => {
    const cy = build();
    expect(highlightPath(cy, "a:4")).toBeGreaterThanOrEqual(3);
    expect(cy.getElementById("hop:10.10.10.29").hasClass("onpath")).toBe(true);
    expect(cy.getElementById("a:3").hasClass("faded")).toBe(true);
    expect(highlightPath(cy, "missing")).toBe(-1);
  });

  it("focuses on a node's neighbourhood", () => {
    const cy = build(false);
    focusNeighborhood(cy, "hop:10.10.10.29");
    expect(cy.getElementById("a:1").hasClass("focus")).toBe(true);
    expect(cy.getElementById("a:3").hasClass("faded")).toBe(true);
  });

  it("searches names, IPs and models", () => {
    const cy = build();
    expect(searchNodes(cy, "CRIME").map((n) => n.id())).toEqual(["a:2"]);
    expect(searchNodes(cy, "10.20.0").map((n) => n.id()).sort()).toEqual(["a:4", "net:10.20.0.0/24"]);
    expect(searchNodes(cy, "").length).toBe(0);
  });

  it("saves and restores leaf positions", () => {
    const cy = build();
    cy.nodes().forEach((n, i) => { if (!n.isParent()) n.position({ x: i * 10, y: i }); });
    const store = new Map<string, string>();
    const storage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) };
    expect(savePositions(cy, storage)).toBe(6); // 8 nodes − 2 network boxes
    const positions = loadPositions(storage);
    expect(positions["a:2"]).toEqual(cy.getElementById("a:2").position());
    const elements = toElements(DATA, { group: true, colorMode: "type", labelMode: "both" });
    expect(coverage(elements, positions)).toBe(1);
    expect(coverage(elements, {})).toBe(0);
    expect(loadPositions({ getItem: () => "not json" })).toEqual({});
  });
});
