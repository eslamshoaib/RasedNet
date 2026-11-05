import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Suspense, useEffect, useRef, useState, type ComponentType } from "react";
import { NavLink, Outlet } from "react-router";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import type { DashboardSummary, VulnSummary } from "../types";

function playAlarm(): void {
  try {
    const AC = window.AudioContext ?? (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
    const ctx = new AC();
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    o.type = "square"; o.frequency.value = 880; g.gain.value = 0.08;
    o.start();
    o.frequency.setValueAtTime(660, ctx.currentTime + 0.18);
    o.frequency.setValueAtTime(880, ctx.currentTime + 0.36);
    o.stop(ctx.currentTime + 0.55);
    o.onended = () => void ctx.close();
  } catch {
    /* audio unavailable */
  }
}

function VulnAlarm() {
  const { can } = useAuth();
  const [muted, setMuted] = useState<boolean>(() => { try { return localStorage.getItem("rased.vulnMute") === "1"; } catch { return false; } });
  const prev = useRef<number | null>(null);
  const q = useQuery({
    queryKey: ["vuln-alarm"], enabled: can("asset:read"), refetchInterval: 30000,
    queryFn: () => api<VulnSummary>("/api/cve/summary"),
  });
  useEffect(() => {
    if (!q.data) return;
    const serious = q.data.by_severity.filter((s) => s.severity === "critical" || s.severity === "high").reduce((a, s) => a + s.count, 0);
    if (prev.current !== null && serious > prev.current && !muted) playAlarm();
    prev.current = serious;
  }, [q.data, muted]);
  if (!can("asset:read")) return null;
  const toggle = () => {
    const nm = !muted;
    setMuted(nm);
    try { localStorage.setItem("rased.vulnMute", nm ? "1" : "0"); } catch { /* ignore */ }
    if (!nm) playAlarm();  // a click unlocks audio + previews the sound
  };
  return (
    <button type="button" onClick={toggle} aria-pressed={muted}
      title={muted ? "تنبيه الثغرات الصوتي: مكتوم — اضغط للتفعيل" : "تنبيه الثغرات الصوتي: مفعّل — اضغط للكتم"}
      className={`rounded-xl border px-2.5 py-1.5 text-sm ${muted ? "border-slate-200 bg-white text-slate-400" : "border-amber-300 bg-amber-50 text-amber-700"}`}>
      {muted ? "🔕" : "🔔"}
    </button>
  );
}
import {
  IconBell, IconBug, IconClipboard, IconDashboard, IconDevices, IconDomain, IconHistory, IconKey, IconLink, IconList,
  IconLogout, IconMap, IconPlug, IconRadar, IconReport, IconSettings, IconShield, IconSliders, IconStop, IconTable,
  IconUser, IconUsers,
} from "./icons";
import { Loading } from "./ui";

interface NavItem {
  to: string;
  label: string;
  permission: string;
  icon: ComponentType<{ className?: string }>;
}

export const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: "المراقبة",
    items: [
      { to: "/", label: "لوحة التحكم الرئيسية", permission: "dashboard:read", icon: IconDashboard },
      { to: "/topology", label: "خريطة الشبكة", permission: "asset:read", icon: IconMap },
      { to: "/physical", label: "التوبولوجي الفيزيائي", permission: "asset:read", icon: IconLink },
      { to: "/fusion", label: "جداول الدمج والتحليل", permission: "asset:read", icon: IconTable },
      { to: "/vulnerabilities", label: "الثغرات الأمنية", permission: "asset:read", icon: IconBug },
      { to: "/reports", label: "التقارير", permission: "report:read", icon: IconReport },
      { to: "/compliance", label: "الامتثال للمعايير", permission: "report:read", icon: IconShield },
      { to: "/alerts", label: "التنبيهات والأحداث", permission: "alert:read", icon: IconBell },
    ],
  },
  {
    title: "الجرد والاكتشاف",
    items: [
      { to: "/discovery", label: "اكتشاف الشبكة", permission: "scope:read", icon: IconRadar },
      { to: "/assets", label: "الأجهزة المتصلة", permission: "asset:read", icon: IconDevices },
      { to: "/services", label: "المنافذ والبروتوكولات", permission: "asset:read", icon: IconPlug },
      { to: "/scans", label: "سجل الفحوصات", permission: "scan:read", icon: IconHistory },
      { to: "/events", label: "سجل التغييرات", permission: "alert:read", icon: IconList },
    ],
  },
  {
    title: "الإدارة",
    items: [
      { to: "/profiles", label: "ملفات الفحص", permission: "scan:read", icon: IconSliders },
      { to: "/vault", label: "خزنة الدخول للأجهزة", permission: "remote:verify", icon: IconKey },
      { to: "/directory", label: "مستخدمو الدومين", permission: "directory:read", icon: IconDomain },
      { to: "/users", label: "المستخدمون والصلاحيات", permission: "user:manage", icon: IconUsers },
      { to: "/audit", label: "سجل التدقيق", permission: "audit:read", icon: IconShield },
      { to: "/operations", label: "السياسات والإشعارات", permission: "data:manage", icon: IconClipboard },
      { to: "/settings", label: "الإعدادات والصيانة", permission: "data:manage", icon: IconSettings },
      { to: "/account", label: "حسابي", permission: "", icon: IconUser },
    ],
  },
];

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const { can } = useAuth();
  return (
    <nav aria-label="القائمة الرئيسية" className="space-y-5 px-3 pb-6">
      {NAV_GROUPS.map((group) => {
        const items = group.items.filter((i) => !i.permission || can(i.permission));
        if (!items.length) return null;
        return (
          <div key={group.title}>
            <div className="mb-1.5 px-3 text-[11px] font-semibold tracking-wide text-slate-500">{group.title}</div>
            {items.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === "/"}
                onClick={onNavigate}
                className={({ isActive }) =>
                  `mb-0.5 flex items-center gap-3 rounded-xl px-3 py-2 text-sm transition ${
                    isActive ? "bg-gradient-to-l from-cyan-600 to-sky-600 font-semibold text-white shadow-lg shadow-cyan-900/30" : "text-slate-300 hover:bg-white/5 hover:text-white"
                  }`
                }
              >
                <Icon className="h-[18px] w-[18px] shrink-0" />
                {label}
              </NavLink>
            ))}
          </div>
        );
      })}
    </nav>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-3 px-6 py-6">
      <div className="grid h-10 w-10 place-items-center rounded-2xl bg-gradient-to-br from-cyan-400 to-sky-700 shadow-lg shadow-cyan-900/40">
        <IconRadar className="h-6 w-6 text-white" />
      </div>
      <div>
        <div className="text-xl font-bold leading-tight text-white">راصد</div>
        <div className="text-[11px] text-slate-400">رصد الشبكة واستخباراتها</div>
      </div>
    </div>
  );
}

export function Layout() {
  const { me, logout, can } = useAuth();
  const queryClient = useQueryClient();
  const [mobileOpen, setMobileOpen] = useState(false);
  const live = useQuery({
    queryKey: ["dashboard", "live"],
    queryFn: () => api<DashboardSummary>("/api/dashboard/summary"),
    refetchInterval: 10000,
    enabled: can("dashboard:read"),
  });
  const stop = useMutation({
    mutationFn: () => api<number[]>("/api/scans/emergency-stop", { method: "POST" }),
    onSuccess: (ids) => {
      void queryClient.invalidateQueries();
      window.alert(ids.length ? `تم طلب إيقاف ${ids.length} فحص.` : "لا توجد فحوص قيد التنفيذ.");
    },
    onError: (e) => window.alert(errorMessage(e)),
  });
  const running = live.data?.running_jobs ?? 0;

  return (
    <div className="flex min-h-screen text-slate-800">
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 overflow-y-auto bg-gradient-to-b from-ink-900 to-ink-800 lg:block">
        <Brand />
        <NavLinks />
      </aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true">
          <div className="absolute inset-0 bg-black/50" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 start-0 w-72 overflow-y-auto bg-ink-900">
            <Brand />
            <NavLinks onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex flex-wrap items-center justify-between gap-3 border-b border-slate-200/70 bg-white/80 px-4 py-3 backdrop-blur md:px-6">
          <div className="flex items-center gap-3">
            <button type="button" className="rounded-lg border border-slate-200 px-2 py-1 text-sm lg:hidden" onClick={() => setMobileOpen(true)} aria-label="فتح القائمة">☰</button>
            {running > 0 ? (
              <span className="flex items-center gap-2 rounded-full bg-cyan-50 px-3 py-1 text-xs font-semibold text-cyan-800">
                <span className="live-dot h-2 w-2 rounded-full bg-cyan-500" /> فحوص جارية: {running}
              </span>
            ) : (
              <span className="text-xs text-slate-500">لا توجد فحوص جارية</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden text-sm text-slate-600 sm:inline">
              {me?.user.display_name} <span className="text-slate-400">— {me?.user.role.name_ar}</span>
            </span>
            <VulnAlarm />
            {can("scan:run") && (
              <button
                type="button"
                disabled={stop.isPending}
                onClick={() => window.confirm("إيقاف طارئ لجميع الفحوص الجارية والمنتظرة؟") && stop.mutate()}
                className="inline-flex items-center gap-1.5 rounded-xl bg-red-600 px-3 py-1.5 text-sm font-semibold text-white shadow hover:bg-red-700 disabled:opacity-50"
              >
                <IconStop className="h-4 w-4" /> إيقاف طارئ
              </button>
            )}
            <button type="button" onClick={() => void logout()} className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50">
              <IconLogout className="h-4 w-4" /> خروج
            </button>
          </div>
        </header>
        <main className="flex-1 p-4 md:p-6">
          <Suspense fallback={<Loading />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  );
}
