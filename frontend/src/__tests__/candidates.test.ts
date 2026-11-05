import { describe, expect, it } from "vitest";
import { defaultSelected, effectiveCidr, hostsOf } from "../pages/NetworkCandidates";
import type { CandidateNetwork } from "../types";

const base: CandidateNetwork = {
  cidr: "10.150.0.0/20", sources: ["interface"], interfaces: ["Ethernet"], local_ips: ["10.150.12.85"], gateways: [],
  is_virtual: false, host_count: 4094, allowed: true, reason_ar: null, suggested_cidr: null,
  existing_scope_id: null, existing_scope_name: null, existing_scope_approved: false, overlaps_scope_names: [],
};

describe("network candidates", () => {
  it("pre-selects only new, allowed, physical networks", () => {
    expect(defaultSelected(base)).toBe(true);
    expect(defaultSelected({ ...base, is_virtual: true })).toBe(false);
    expect(defaultSelected({ ...base, existing_scope_id: 3 })).toBe(false);
    expect(defaultSelected({ ...base, allowed: false })).toBe(false);
  });

  it("uses the narrower suggestion for oversized networks and nothing for forbidden ones", () => {
    expect(effectiveCidr(base)).toBe("10.150.0.0/20");
    expect(effectiveCidr({ ...base, cidr: "10.0.0.0/8", allowed: false, suggested_cidr: "10.150.0.0/16" })).toBe("10.150.0.0/16");
    expect(effectiveCidr({ ...base, cidr: "8.8.8.0/24", allowed: false })).toBeNull();
  });

  it("counts usable host addresses", () => {
    expect(hostsOf("10.150.0.0/20")).toBe(4094);
    expect(hostsOf("10.0.0.0/16")).toBe(65534);
    expect(hostsOf("10.0.0.4/31")).toBe(2);
    expect(hostsOf("10.0.0.1/32")).toBe(1);
    expect(hostsOf("bad")).toBe(0);
  });
});
