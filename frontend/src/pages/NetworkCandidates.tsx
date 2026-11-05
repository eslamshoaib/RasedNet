import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, inputClass, Loading, Ltr } from "../components/ui";
import { formatNumber } from "../format";
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
  return c.interfaces.join("، ") || "—";
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
  const items = chosen.map((c) => ({ cidr: effectiveCidr(c) as string, name: `${c.interfaces[0] ?? "شبكة"} — ${effectiveCidr(c)}` }));
  const totalHosts = chosen.reduce((sum, c) => sum + (c.allowed ? c.host_count : hostsOf(effectiveCidr(c) as string)), 0);

  function addAndScan() {
    const list = items.map((i) => i.cidr).join("\n");
    const ok = window.confirm(
      `سيتم إضافة واعتماد وفحص الشبكات التالية:\n${list}\n\nبالمتابعة تؤكد أن المؤسسة تملك هذه الشبكات أو تديرها وأن فحصها مصرح به.`,
    );
    if (ok) bulk.mutate({ items, approve: true, confirm: true, start_scan_profile_id: chosenProfile });
  }

  const canApproveAndScan = can("scope:approve") && can("scan:run");

  return (
    <Card
      title="الشبكات المكتشفة تلقائياً"
      actions={<Button variant="secondary" onClick={() => void candidates.refetch()} disabled={candidates.isFetching}>{candidates.isFetching ? "جارٍ البحث…" : "إعادة البحث"}</Button>}
    >
      <p className="mb-3 text-sm text-slate-600">
        هذه الشبكات قرأها النظام من إعدادات خادم الفحص نفسه (بطاقات الشبكة وجدول التوجيه) دون إرسال أي حزم على الشبكة.
      </p>
      {candidates.isLoading ? <Loading /> : candidates.error ? <ErrorBox error={candidates.error} /> : (candidates.data ?? []).length === 0 ? (
        <p className="text-sm text-slate-500">لم يُعثر على شبكات داخلية متصلة بهذا الخادم.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead><tr className="border-b bg-slate-50">
              <th className="px-3 py-2 text-start">اختيار</th><th className="px-3 py-2 text-start">الشبكة</th><th className="px-3 py-2 text-start">بطاقة الشبكة</th>
              <th className="px-3 py-2 text-start">المصدر</th><th className="px-3 py-2 text-start">عدد العناوين</th><th className="px-3 py-2 text-start">الحالة</th>
            </tr></thead>
            <tbody>
              {candidates.data?.map((c) => {
                const target = effectiveCidr(c);
                return (
                  <tr key={c.cidr} className="border-b border-slate-100 align-top">
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        aria-label={`اختيار ${c.cidr}`}
                        disabled={!target}
                        checked={!!selected[c.cidr] && !!target}
                        onChange={(e) => setSelected({ ...selected, [c.cidr]: e.target.checked })}
                      />
                    </td>
                    <td className="px-3 py-2">
                      <Ltr>{c.cidr}</Ltr>
                      {!c.allowed && c.suggested_cidr && (
                        <div className="text-xs text-amber-700">كبيرة جداً؛ سيُضاف الجزء المحيط بالخادم: <Ltr>{c.suggested_cidr}</Ltr></div>
                      )}
                      {c.local_ips.length > 0 && <div className="text-xs text-slate-500">عنوان الخادم: <Ltr>{c.local_ips.join(", ")}</Ltr></div>}
                    </td>
                    <td className="px-3 py-2">{interfaceLabel(c)}</td>
                    <td className="px-3 py-2 text-xs">
                      {c.sources.includes("interface") && <div>متصلة مباشرة بالخادم</div>}
                      {c.sources.includes("route") && c.gateways.length > 0 && <div>عبر موجّه <Ltr>{c.gateways.join(", ")}</Ltr></div>}
                      {c.sources.includes("trace") && <div className="text-violet-700">مكتشفة من مسار التوجيه{c.gateways.length > 0 && <> بعد <Ltr>{c.gateways[0]}</Ltr></>} (مستنتجة /24)</div>}
                    </td>
                    <td className="px-3 py-2">{formatNumber(c.host_count)}</td>
                    <td className="px-3 py-2 space-y-1">
                      {c.existing_scope_id !== null ? (
                        c.existing_scope_approved ? <Badge tone="green">مضافة ومعتمدة</Badge> : <Badge tone="amber">مضافة — بانتظار الاعتماد</Badge>
                      ) : c.allowed ? <Badge tone="blue">جديدة</Badge> : <Badge tone="red">غير مسموحة</Badge>}
                      {c.is_virtual && <div><Badge tone="purple">شبكة افتراضية (Hyper-V/WSL/VPN)</Badge></div>}
                      {c.overlaps_scope_names.length > 0 && <div className="text-xs text-slate-500">تتداخل مع: {c.overlaps_scope_names.join("، ")}</div>}
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
            <select className={`${inputClass} w-auto`} value={chosenProfile ?? ""} onChange={(e) => setProfileId(Number(e.target.value))} aria-label="ملف الفحص">
              {profiles.map((p) => <option key={p.id} value={p.id}>{p.name_ar}</option>)}
            </select>
            <Button disabled={items.length === 0 || bulk.isPending || chosenProfile === null} onClick={addAndScan}>
              إضافة واعتماد وفحص المحدد ({items.length})
            </Button>
          </>
        )}
        <Button variant="secondary" disabled={items.length === 0 || bulk.isPending} onClick={() => bulk.mutate({ items })}>
          إضافة المحدد فقط
        </Button>
        {items.length > 0 && <span className="text-xs text-slate-500">إجمالي العناوين: {formatNumber(totalHosts)}</span>}
      </div>
      {bulk.error && <div className="mt-2"><ErrorBox error={errorMessage(bulk.error)} /></div>}
      {results && (
        <ul className="mt-3 space-y-1 text-sm">
          {results.map((r) => (
            <li key={r.cidr}>
              <Ltr>{r.cidr}</Ltr>:{" "}
              {r.error_ar ? <span className="text-red-700">{r.error_ar}</span> : (
                <span className="text-emerald-700">
                  {r.created ? "أُضيفت" : "موجودة مسبقاً"}{r.approved ? " ومعتمدة" : ""}{r.job_id ? ` — بدأ الفحص #${r.job_id}` : ""}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-xs text-slate-500">
        الشبكات الداخلية الأخرى (شبكات VLAN خلف الموجّه) لا تظهر إلا إذا كان لها مسار في جدول التوجيه لهذا الخادم؛ يمكن إضافتها يدوياً بالأسفل.
        ملف «اكتشاف آمن» هو الافتراضي لأول فحص.
      </p>
    </Card>
  );
}
