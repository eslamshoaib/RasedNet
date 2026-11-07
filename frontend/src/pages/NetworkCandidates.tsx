import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, inputClass, Loading, Ltr } from "../components/ui";
import { formatNumber } from "../format";
import { getLang, t } from "../i18n";
import type { BulkScopeResult, CandidateNetwork, Profile } from "../types";

/** The CIDR that would actually be added for a candidate (the narrower suggestion if too large). */
export function effectiveCidr(c: CandidateNetwork): string | null {
  if (c.allowed) return c.cidr;
  return c.suggested_cidr;
}

/** Usable IPv4 host addresses in a CIDR (network/broadcast excluded below /31). */
export function hostsOf(cidr: string): number {
  const prefix = Number(cidr.split("/")[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return 0;
  const size = 2 ** (32 - prefix);
  return prefix >= 31 ? size : size - 2;
}

export function defaultSelected(c: CandidateNetwork): boolean {
  return c.allowed && !c.is_virtual && c.existing_scope_id === null;
}

function interfaceLabel(c: CandidateNetwork): string {
  return c.interfaces.join(t("، ", ", ")) || "—";
}

export function NetworkCandidates({ profiles, onChanged }: { profiles: Profile[]; onChanged: () => void }) {
  const { can } = useAuth();
  const candidates = useQuery({
    queryKey: ["scope-candidates"],
    queryFn: () => api<CandidateNetwork[]>("/api/scopes/candidates"),
  });
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [profileId, setProfileId] = useState<number | null>(null);
  const [results, setResults] = useState<BulkScopeResult[] | null>(null);

  useEffect(() => {
    if (candidates.data) {
      setSelected(Object.fromEntries(candidates.data.map((c) => [c.cidr, defaultSelected(c)])));
    }
  }, [candidates.data]);

  const safe = profiles.find((p) => p.code === "safe_discovery");
  const chosenProfile = profileId ?? safe?.id ?? profiles[0]?.id ?? null;

  const bulk = useMutation({
    mutationFn: (body: object) => api<BulkScopeResult[]>("/api/scopes/bulk", { method: "POST", body }),
    onSuccess: (r) => {
      setResults(r);
      void candidates.refetch();
      onChanged();
    },
  });

  const chosen = (candidates.data ?? []).filter((c) => selected[c.cidr] && effectiveCidr(c));
  const items = chosen.map((c) => ({ cidr: effectiveCidr(c) as string, name: `${c.interfaces[0] ?? t("شبكة", "Network")} — ${effectiveCidr(c)}` }));
  const totalHosts = chosen.reduce((sum, c) => sum + (c.allowed ? c.host_count : hostsOf(effectiveCidr(c) as string)), 0);

  function addAndScan() {
    const list = items.map((i) => i.cidr).join("\n");
    const ok = window.confirm(getLang() === "en"
      ? `The following networks will be added, approved and scanned:\n${list}\n\nBy continuing you confirm that the organisation owns or administers these networks and that scanning them is authorized.`
      : `سيتم إضافة واعتماد وفحص الشبكات التالية:\n${list}\n\nبالمتابعة تؤكد أن المؤسسة تملك هذه الشبكات أو تديرها وأن فحصها مصرح به.`,
    );
    if (ok) bulk.mutate({ items, approve: true, confirm: true, start_scan_profile_id: chosenProfile });
  }

  const canApproveAndScan = can("scope:approve") && can("scan:run");

  return (
    <Card
      title={t("الشبكات المكتشفة تلقائياً", "Automatically discovered networks")}
      actions={<Button variant="secondary" onClick={() => void candidates.refetch()} disabled={candidates.isFetching}>{candidates.isFetching ? t("جارٍ البحث…", "Searching…") : t("إعادة البحث", "Search again")}</Button>}
    >
      <p className="mb-3 text-sm text-slate-600">
        {t("هذه الشبكات قرأها النظام من إعدادات خادم الفحص نفسه (بطاقات الشبكة وجدول التوجيه) دون إرسال أي حزم على الشبكة.", "These networks were read from the scanner server's own configuration (network cards and routing table) without sending any packets on the network.")}
      </p>
      {candidates.isLoading ? <Loading /> : candidates.error ? <ErrorBox error={candidates.error} /> : (candidates.data ?? []).length === 0 ? (
        <p className="text-sm text-slate-500">{t("لم يُعثر على شبكات داخلية متصلة بهذا الخادم.", "No internal networks connected to this server were found.")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead><tr className="border-b bg-slate-50">
              <th className="px-3 py-2 text-start">{t("اختيار", "Select")}</th><th className="px-3 py-2 text-start">{t("الشبكة", "Network")}</th><th className="px-3 py-2 text-start">{t("بطاقة الشبكة", "Interface")}</th>
              <th className="px-3 py-2 text-start">{t("المصدر", "Source")}</th><th className="px-3 py-2 text-start">{t("عدد العناوين", "Address count")}</th><th className="px-3 py-2 text-start">{t("الحالة", "Status")}</th>
            </tr></thead>
            <tbody>
              {candidates.data?.map((c) => {
                const target = effectiveCidr(c);
                return (
                  <tr key={c.cidr} className="border-b border-slate-100 align-top">
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        aria-label={`${t("اختيار", "Select")} ${c.cidr}`}
                        disabled={!target}
                        checked={!!selected[c.cidr] && !!target}
                        onChange={(e) => setSelected({ ...selected, [c.cidr]: e.target.checked })}
                      />
                    </td>
                    <td className="px-3 py-2">
                      <Ltr>{c.cidr}</Ltr>
                      {!c.allowed && c.suggested_cidr && (
                        <div className="text-xs text-amber-700">{t("كبيرة جداً؛ سيُضاف الجزء المحيط بالخادم:", "Too large; the part around the server will be added:")} <Ltr>{c.suggested_cidr}</Ltr></div>
                      )}
                      {c.local_ips.length > 0 && <div className="text-xs text-slate-500">{t("عنوان الخادم:", "Server address:")} <Ltr>{c.local_ips.join(", ")}</Ltr></div>}
                    </td>
                    <td className="px-3 py-2">{interfaceLabel(c)}</td>
                    <td className="px-3 py-2 text-xs">
                      {c.sources.includes("interface") && <div>{t("متصلة مباشرة بالخادم", "Directly connected to the server")}</div>}
                      {c.sources.includes("route") && c.gateways.length > 0 && <div>{t("عبر موجّه", "Via router")} <Ltr>{c.gateways.join(", ")}</Ltr></div>}
                      {c.sources.includes("trace") && <div className="text-violet-700">{t("مكتشفة من مسار التوجيه", "Discovered from the routing path")}{c.gateways.length > 0 && <> {t("بعد", "after")} <Ltr>{c.gateways[0]}</Ltr></>} {t("(مستنتجة /24)", "(inferred /24)")}</div>}
                    </td>
                    <td className="px-3 py-2">{formatNumber(c.host_count)}</td>
                    <td className="px-3 py-2 space-y-1">
                      {c.existing_scope_id !== null ? (
                        c.existing_scope_approved ? <Badge tone="green">{t("مضافة ومعتمدة", "Added & approved")}</Badge> : <Badge tone="amber">{t("مضافة — بانتظار الاعتماد", "Added — awaiting approval")}</Badge>
                      ) : c.allowed ? <Badge tone="blue">{t("جديدة", "New")}</Badge> : <Badge tone="red">{t("غير مسموحة", "Not allowed")}</Badge>}
                      {c.is_virtual && <div><Badge tone="purple">{t("شبكة افتراضية (Hyper-V/WSL/VPN)", "Virtual network (Hyper-V/WSL/VPN)")}</Badge></div>}
                      {c.overlaps_scope_names.length > 0 && <div className="text-xs text-slate-500">{t("تتداخل مع:", "Overlaps with:")} {c.overlaps_scope_names.join(t("، ", ", "))}</div>}
                      {!c.allowed && !c.suggested_cidr && c.reason_ar && <div className="text-xs text-red-700">{c.reason_ar}</div>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {canApproveAndScan && (
          <>
            <select className={`${inputClass} w-auto`} value={chosenProfile ?? ""} onChange={(e) => setProfileId(Number(e.target.value))} aria-label={t("ملف الفحص", "Scan profile")}>
              {profiles.map((p) => <option key={p.id} value={p.id}>{p.name_ar}</option>)}
            </select>
            <Button disabled={items.length === 0 || bulk.isPending || chosenProfile === null} onClick={addAndScan}>
              {t("إضافة واعتماد وفحص المحدد", "Add, approve & scan selected")} ({items.length})
            </Button>
          </>
        )}
        <Button variant="secondary" disabled={items.length === 0 || bulk.isPending} onClick={() => bulk.mutate({ items })}>
          {t("إضافة المحدد فقط", "Add selected only")}
        </Button>
        {items.length > 0 && <span className="text-xs text-slate-500">{t("إجمالي العناوين:", "Total addresses:")} {formatNumber(totalHosts)}</span>}
      </div>
      {bulk.error && <div className="mt-2"><ErrorBox error={errorMessage(bulk.error)} /></div>}
      {results && (
        <ul className="mt-3 space-y-1 text-sm">
          {results.map((r) => (
            <li key={r.cidr}>
              <Ltr>{r.cidr}</Ltr>:{" "}
              {r.error_ar ? <span className="text-red-700">{r.error_ar}</span> : (
                <span className="text-emerald-700">
                  {r.created ? t("أُضيفت", "Added") : t("موجودة مسبقاً", "Already existed")}{r.approved ? t(" ومعتمدة", " & approved") : ""}{r.job_id ? ` — ${t("بدأ الفحص", "scan started")} #${r.job_id}` : ""}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-xs text-slate-500">
        {t("الشبكات الداخلية الأخرى (شبكات VLAN خلف الموجّه) لا تظهر إلا إذا كان لها مسار في جدول التوجيه لهذا الخادم؛ يمكن إضافتها يدوياً بالأسفل. ملف «اكتشاف آمن» هو الافتراضي لأول فحص.",
          "Other internal networks (VLANs behind the router) appear only if they have a route in this server's routing table; they can be added manually below. The “Safe discovery” profile is the default for the first scan.")}
      </p>
    </Card>
  );
}
