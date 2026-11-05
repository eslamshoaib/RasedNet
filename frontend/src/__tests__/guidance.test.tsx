import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render as rtlRender, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServiceGuidancePanel } from "../components/ServiceGuidance";
import type { ServiceGuidance } from "../types";

const render = (ui: ReactElement) => rtlRender(<QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>);

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const guidance: ServiceGuidance = {
  access: [],
  access_note_ar: "",
  network_checks: [{ label_ar: "هل المنفذ مفتوح؟", command: "Test-NetConnection 10.0.0.7 -Port 3389", shell: "powershell", run_on: "admin_pc" }],
  platforms: [
    {
      platform: "windows",
      platform_ar: "ويندوز",
      verify: [{ label_ar: "تحقق", command: "Get-Service TermService", shell: "powershell", run_on: "device" }],
      disable: [{ label_ar: "إغلاق", command: "Disable-NetFirewallRule -Group '@FirewallAPI.dll,-28752'", shell: "powershell", run_on: "device" }],
      harden: [],
      warnings_ar: ["سيُقطع اتصالك"],
      notes_ar: [],
    },
  ],
  recheck_ar: "أعد الفحص",
};

describe("service guidance panel", () => {
  it("shows verify / close sections, warnings and LTR commands", () => {
    render(<ServiceGuidancePanel guidance={guidance} />);
    expect(screen.getByText(/التحقق من جهازك/)).toBeTruthy();
    expect(screen.getByText(/طريقة الإغلاق/)).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("سيُقطع اتصالك");
    const cmd = screen.getByText("Test-NetConnection 10.0.0.7 -Port 3389");
    expect(cmd.tagName).toBe("PRE");
    expect(cmd.parentElement?.getAttribute("dir")).toBe("ltr");
    expect(screen.queryByText(/بديل: تأمين/)).toBeNull(); // empty sections are hidden
  });

  it("copies the exact command", async () => {
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(<ServiceGuidancePanel guidance={guidance} />);
    fireEvent.click(screen.getAllByRole("button", { name: "نسخ الأمر" })[2]);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("Disable-NetFirewallRule -Group '@FirewallAPI.dll,-28752'"));
    expect(await screen.findByText("تم النسخ")).toBeTruthy();
  });
});

describe("access section", () => {
  it("offers browser and RDP shortcuts for the device", () => {
    render(<ServiceGuidancePanel ip="10.0.0.7" guidance={{ ...guidance, access_note_ar: "حساب مصرح فقط",
      access: [
        { label_ar: "واجهة", command: 'Start-Process "http://10.0.0.7:8080/"', shell: "powershell", run_on: "admin_pc" },
        { label_ar: "سطح المكتب", command: "mstsc /v:10.0.0.7", shell: "powershell", run_on: "admin_pc" },
      ] }} />);
    expect(screen.getByRole("link", { name: /فتح واجهة الإدارة/ }).getAttribute("href")).toBe("http://10.0.0.7:8080/");
    expect(screen.getByRole("button", { name: /RDP/ })).toBeTruthy();
    expect(screen.getByText("حساب مصرح فقط")).toBeTruthy();
  });
});
