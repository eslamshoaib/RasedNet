import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { getLang, t } from "../i18n";
import { Badge, Card, ErrorBox, Loading } from "./ui";
import type { Credential, Execution, NetAction, NetAdmin } from "../types";

function ActionRunner({ assetId, action, credentials }: { assetId: number; action: NetAction; credentials: Credential[] }) {
  const { can } = useAuth();
  const [credId, setCredId] = useState<number | "">(credentials[0]?.id ?? "");
  const [params, setParams] = useState<Record<string, string>>({});
  const [result, setResult] = useState<Execution | null>(null);
  const changes = action.category === "change";
  const run = useMutation({
    mutationFn: () => api<Execution>(`/api/assets/${assetId}/netadmin/${action.id}`, {
      method: "POST", body: { credential_id: credId, params, confirm: changes },
    }),
    onSuccess: setResult,
  });
  const ready = credId !== "" && action.params.every((p) => (params[p.name] ?? "").trim());

  return (
    <div className={`rounded-xl border p-3 ${changes ? "border-red-200 bg-red-50/40" : "border-slate-200 bg-white"}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold text-slate-800">{action.label_ar}</span>
        {changes && <Badge tone="red">{t("يغيّر الجهاز", "Changes the device")}</Badge>}
      </div>
      {action.description_ar && <p className="mt-0.5 text-xs text-slate-500">{action.description_ar}</p>}
      {action.warning_ar && <p className="mt-1 rounded bg-amber-50 px-2 py-1 text-xs text-amber-900">{t("تحذير:", "Warning:")} {action.warning_ar}</p>}
      <div className="mt-2 flex flex-wrap items-end gap-2">
        {action.params.map((p) => (
          <label key={p.name} className="text-xs text-slate-600">
            <span className="mb-0.5 block">{p.label_ar}</span>
            <input dir="ltr" className="w-44 rounded-lg border border-slate-300 px-2 py-1 text-sm" placeholder={p.placeholder}
              value={params[p.name] ?? ""} onChange={(e) => setParams({ ...params, [p.name]: e.target.value })} />
          </label>
        ))}
        <select className="rounded-lg border border-slate-300 px-2 py-1 text-xs" value={credId} aria-label={t("حساب الدخول", "Credential")}
          onChange={(e) => setCredId(e.target.value ? Number(e.target.value) : "")}>
          <option value="">{t("اختر حساب SSH…", "Choose an SSH account…")}</option>
          {credentials.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.username})</option>)}
        </select>
        <button type="button" disabled={!ready || run.isPending || (changes && !can("remote:change"))}
          onClick={() => { if (!changes || window.confirm(getLang() === "en" ? `Run “${action.label_ar}” on the device?` : `تنفيذ «${action.label_ar}» على الجهاز؟`)) run.mutate(); }}
          className={`rounded-lg px-3 py-1 text-xs font-semibold text-white disabled:opacity-40 ${changes ? "bg-red-600 hover:bg-red-700" : "bg-cyan-700 hover:bg-cyan-800"}`}>
          {run.isPending ? t("جارٍ…", "Working…") : t("تشغيل", "Run")}
        </button>
      </div>
      {run.error && <div className="mt-1 text-xs text-red-700">{errorMessage(run.error)}</div>}
      {result && (
        <div className="mt-2 rounded-md border border-slate-200 bg-white">
          <div className="border-b border-slate-100 bg-slate-50 px-2 py-1 text-[11px]">
            <Badge tone={result.status === "ok" && !result.had_errors ? "green" : result.status === "ok" ? "amber" : "red"}>
              {result.status === "error" ? t("فشل", "Failed") : result.had_errors ? t("مع أخطاء", "With errors") : t("نجاح", "Success")}
            </Badge>
          </div>
          <pre dir="ltr" className="ltr max-h-72 overflow-auto whitespace-pre-wrap break-all px-2 py-1.5 text-[11px]">{result.output || t("(لا توجد مخرجات)", "(no output)")}</pre>
        </div>
      )}
    </div>
  );
}

export function RouterControl({ assetId, credentials }: { assetId: number; credentials: Credential[] }) {
  const net = useQuery({ queryKey: ["netadmin", assetId], queryFn: () => api<NetAdmin>(`/api/assets/${assetId}/netadmin`) });
  const [tab, setTab] = useState<"info" | "change">("info");
  if (net.isLoading) return <Loading />;
  if (net.error || !net.data) return <ErrorBox error={net.error ?? t("تعذر التحميل", "Could not load")} />;
  if (!net.data.is_network_device) return null;

  const ssh = credentials.filter((c) => c.kind === "ssh");
  const actions = net.data.actions.filter((a) => a.category === tab);
  return (
    <Card title={`${t("لوحة تحكم الموجّه", "Router control panel")} — ${net.data.platform_ar}`}>
      <p className="mb-2 text-xs text-slate-500">{net.data.note_ar}</p>
      {!net.data.has_ssh && <ErrorBox error={t("لم يُرصد منفذ SSH مفتوح على هذا الجهاز. فعّل SSH على الموجّه، ثم أعد فحصه.", "No open SSH port was observed on this device. Enable SSH on the router, then re-scan it.")} />}
      {ssh.length === 0 && <ErrorBox error={t("لا يوجد حساب SSH في الخزنة. أضف حساباً من «خزنة الدخول للأجهزة».", "No SSH account in the vault. Add one from “Device credential vault”.")} />}
      <div className="mb-3 flex gap-2">
        <button type="button" onClick={() => setTab("info")} className={`rounded-lg px-3 py-1 text-sm ${tab === "info" ? "bg-cyan-600 text-white" : "bg-slate-100 text-slate-700"}`}>{t("عرض المعلومات", "View info")}</button>
        <button type="button" onClick={() => setTab("change")} className={`rounded-lg px-3 py-1 text-sm ${tab === "change" ? "bg-cyan-600 text-white" : "bg-slate-100 text-slate-700"}`}>{t("أوامر التحكم", "Control commands")}</button>
      </div>
      {actions.length === 0 ? <p className="text-sm text-slate-500">{t("لا توجد أوامر في هذه الفئة لهذا النوع من الأجهزة.", "No commands in this category for this device type.")}</p> : (
        <div className="grid gap-2 lg:grid-cols-2">
          {actions.map((a) => <ActionRunner key={a.id} assetId={assetId} action={a} credentials={ssh} />)}
        </div>
      )}
    </Card>
  );
}
