import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, downloadGet, errorMessage } from "../api";
import { IconDownload } from "../components/icons";
import { Badge, Button, Card, ErrorBox, Loading } from "../components/ui";
import type { Tone } from "../components/ui";
import type { ComplianceFramework, ComplianceReport } from "../types";

const STATUS: Record<string, { ar: string; tone: Tone }> = {
  pass: { ar: "متوافق", tone: "green" },
  fail: { ar: "غير متوافق", tone: "red" },
  partial: { ar: "جزئي", tone: "amber" },
  manual: { ar: "يدوي", tone: "blue" },
  not_applicable: { ar: "لا ينطبق", tone: "slate" },
};

function scoreTone(score: number | null): string {
  if (score === null) return "#64748b";
  return score >= 80 ? "#16a34a" : score >= 50 ? "#f59e0b" : "#dc2626";
}

export function CompliancePage() {
  const frameworks = useQuery({ queryKey: ["compliance-fw"], queryFn: () => api<ComplianceFramework[]>("/api/compliance/frameworks") });
  const [fw, setFw] = useState<string | null>(null);
  const active = fw ?? frameworks.data?.[0]?.key ?? null;
  const report = useQuery({
    queryKey: ["compliance", active], enabled: !!active,
    queryFn: () => api<ComplianceReport>(`/api/compliance/${active}`),
  });
  const [err, setErr] = useState<string | null>(null);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">الامتثال للمعايير</h1>
        <p className="text-sm text-slate-500">تقييم آلي لضوابط الأمن من بيانات راصد — NCA ECC وISO 27001 وPCI-DSS. الضوابط غير القابلة للتقييم آلياً تُعلَّم «يدوي».</p>
      </div>

      {frameworks.isLoading ? <Loading /> : frameworks.error ? <ErrorBox error={frameworks.error} /> : (
        <div className="flex flex-wrap gap-2">
          {frameworks.data!.map((f) => (
            <button key={f.key} type="button" onClick={() => setFw(f.key)}
              className={`rounded-xl px-3 py-1.5 text-sm ${active === f.key ? "bg-cyan-600 text-white" : "bg-slate-100 text-slate-700 hover:bg-slate-200"}`}>
              {f.name_ar}
            </button>
          ))}
        </div>
      )}

      {report.isLoading ? <Loading /> : report.error ? <ErrorBox error={report.error} /> : report.data && (
        <>
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className="grid h-24 w-24 place-items-center rounded-full border-8" style={{ borderColor: scoreTone(report.data.score) }}>
                  <span className="text-2xl font-bold" style={{ color: scoreTone(report.data.score) }}>{report.data.score ?? "—"}%</span>
                </div>
                <div>
                  <div className="font-bold">{report.data.framework_ar}</div>
                  <div className="mt-1 flex flex-wrap gap-1.5 text-xs">
                    <Badge tone="green">متوافق: {report.data.summary.pass}</Badge>
                    <Badge tone="red">غير متوافق: {report.data.summary.fail}</Badge>
                    {report.data.summary.partial > 0 && <Badge tone="amber">جزئي: {report.data.summary.partial}</Badge>}
                    {report.data.summary.manual > 0 && <Badge tone="blue">يدوي: {report.data.summary.manual}</Badge>}
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="secondary" onClick={() => window.print()}>🖨️ طباعة</Button>
                <Button variant="secondary" onClick={() => downloadGet(`/api/compliance/${active}/export`, `rased-compliance-${active}.json`).catch((e) => setErr(errorMessage(e)))}>
                  <IconDownload className="h-4 w-4" /> تنزيل JSON
                </Button>
                <Button variant="secondary" onClick={() => downloadGet("/api/compliance/all/export", "rased-compliance-all.json").catch((e) => setErr(errorMessage(e)))}>
                  تنزيل الكل
                </Button>
              </div>
            </div>
            {err && <div className="mt-2"><ErrorBox error={err} /></div>}
          </Card>

          <Card title="الضوابط">
            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b text-slate-500">
                  <th className="p-2 text-start">الضابط</th><th className="p-2 text-start">العنوان</th>
                  <th className="p-2 text-start">المجال</th><th className="p-2">الحالة</th><th className="p-2 text-start">التفاصيل</th>
                </tr></thead>
                <tbody>
                  {report.data.controls.map((c) => {
                    const st = STATUS[c.status] ?? { ar: c.status, tone: "slate" as Tone };
                    return (
                      <tr key={c.control_id} className="border-b border-slate-100 align-top">
                        <td className="p-2 font-mono text-xs">{c.control_id}</td>
                        <td className="p-2">{c.title_ar}</td>
                        <td className="p-2 text-xs text-slate-500">{c.family_ar}</td>
                        <td className="p-2 text-center"><Badge tone={st.tone}>{st.ar}</Badge></td>
                        <td className="p-2 text-xs text-slate-600">{c.detail_ar}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
