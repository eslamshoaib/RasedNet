import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, buildUrl, setCsrfToken } from "../api";
import { Ltr } from "../components/ui";
import { deviceTypeSentence, parsePorts, percent, progress, splitList } from "../format";
import { DEVICE_TYPES, label } from "../labels";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  setCsrfToken(null);
});

describe("formatting", () => {
  it("renders the classification sentence required by the specification", () => {
    expect(deviceTypeSentence("mobile", 0.82)).toBe("نوع الجهاز: هاتف محمول — الثقة 82%");
    expect(deviceTypeSentence("unknown", 0)).toBe("نوع الجهاز: غير مؤكد — يتطلب مراجعة");
    expect(deviceTypeSentence("printer", 0)).toBe("نوع الجهاز: غير مؤكد — يتطلب مراجعة");
  });

  it("clamps percentages and progress", () => {
    expect(percent(1.7)).toBe("100%");
    expect(percent(-1)).toBe("0%");
    expect(progress(5, 0)).toBe(0);
    expect(progress(127, 254)).toBe(50);
  });

  it("parses lists and ports, rejecting invalid ports", () => {
    expect(splitList("10.0.0.1, 10.0.0.2\n10.0.0.0/30،10.0.0.9")).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.0/30", "10.0.0.9"]);
    expect(parsePorts("22, 80 443")).toEqual([22, 80, 443]);
    expect(parsePorts("22, 70000")).toBeNull();
    expect(parsePorts("abc")).toBeNull();
  });

  it("has an Arabic label for every device type and falls back safely", () => {
    for (const value of Object.values(DEVICE_TYPES)) expect(value).toMatch(/[؀-ۿ]/);
    expect(label(DEVICE_TYPES, "brand_new_type")).toBe("brand_new_type");
    expect(label(DEVICE_TYPES, null)).toBe("—");
  });
});

describe("api client", () => {
  it("drops empty query parameters", () => {
    expect(buildUrl("/api/assets", { q: "", page: 2, status: undefined, x: null })).toBe("/api/assets?page=2");
  });

  it("sends the CSRF token on state-changing requests only", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("token-123");
    await api("/api/scopes", { method: "POST", body: { name: "x" } });
    await api("/api/scopes");
    const [, postInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const [, getInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect((postInit.headers as Record<string, string>)["X-CSRF-Token"]).toBe("token-123");
    expect((postInit.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(postInit.credentials).toBe("same-origin");
    expect((getInit.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
  });

  it("surfaces the server's Arabic error message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "النطاق غير معتمد" }), { status: 409 })));
    await expect(api("/api/scans", { method: "POST", body: {} })).rejects.toEqual(new ApiError(409, "النطاق غير معتمد"));
  });

  it("reports a network failure in Arabic", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    await expect(api("/api/health")).rejects.toMatchObject({ status: 0, message: expect.stringMatching(/تعذر الاتصال/) });
  });
});

describe("RTL handling", () => {
  it("isolates technical identifiers as LTR inside RTL text", () => {
    render(<p dir="rtl">العنوان: <Ltr>192.168.1.10:445/tcp</Ltr></p>);
    const el = screen.getByText("192.168.1.10:445/tcp");
    expect(el.tagName).toBe("BDI");
    expect(el.getAttribute("dir")).toBe("ltr");
  });

  it("ships an RTL Arabic document shell", async () => {
    const { readFileSync } = await import("node:fs");
    const html = readFileSync("index.html", "utf8");
    expect(html).toMatch(/<html lang="ar" dir="rtl">/);
    expect(html).not.toMatch(/https?:\/\//);
  });
});
