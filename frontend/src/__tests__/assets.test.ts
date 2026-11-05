import { describe, expect, it } from "vitest";
import { dotColor, subnetOf } from "../pages/Assets";
import { OS_COLORS, STATUS_COLORS, TYPE_COLORS } from "../pages/topologyModel";
import type { Asset } from "../types";

const base: Asset = {
  id: 1, display_name: null, current_ip: "10.150.3.7", hostname: "pc", mac: null, mac_randomized: false, vendor: "Dell Inc.",
  device_type: "computer", device_type_confidence: 0.6, os_family: "windows", os_confidence: 0.6, status: "online",
  criticality: "normal", discovery_methods: ["tcp"], netbios_name: null, workgroup: null, model: null, is_gateway: false,
  upnp: null, first_seen: "2026-11-04T00:00:00Z", last_seen: "2026-11-04T00:00:00Z", open_service_count: 3,
};

describe("assets points view", () => {
  it("groups by /24 subnet", () => {
    expect(subnetOf("10.150.3.7")).toBe("10.150.3.0/24");
    expect(subnetOf("192.168.1.255")).toBe("192.168.1.0/24");
    expect(subnetOf(null)).toBe("أخرى");
    expect(subnetOf("fe80::1")).toBe("أخرى");
  });

  it("colours a device by each mode", () => {
    expect(dotColor(base, "type")).toBe(TYPE_COLORS.computer);
    expect(dotColor(base, "status")).toBe(STATUS_COLORS.online);
    expect(dotColor(base, "os")).toBe(OS_COLORS.windows);
    expect(dotColor({ ...base, open_service_count: 0 }, "exposure")).toBe("#16a34a");
    expect(dotColor({ ...base, open_service_count: 2 }, "exposure")).toBe("#f59e0b");
    expect(dotColor({ ...base, open_service_count: 9 }, "exposure")).toBe("#dc2626");
  });
});
