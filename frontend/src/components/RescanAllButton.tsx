import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Button } from "./ui";

interface RescanResult { started: { job_id: number; name: string }[]; skipped: { name: string; reason: string }[] }

/** One-click re-scan of every approved scope (the last/standing scan target of each network). */
export function RescanAllButton() {
  const { can } = useAuth();
  const [msg, setMsg] = useState<string | null>(null);
  const run = useMutation({
    mutationFn: () => api<RescanResult>("/api/scans/rescan-all", { method: "POST", body: {} }),
    onSuccess: (r) => setMsg(`بدأ فحص ${r.started.length} نطاقاً${r.skipped.length ? `، وتُخطّي ${r.skipped.length} (قيد التنفيذ)` : ""}.`),
    onError: (e) => setMsg(errorMessage(e)),
  });
  if (!can("scan:run")) return null;
  return (
    <span className="inline-flex items-center gap-2">
      <Button variant="secondary" disabled={run.isPending}
        onClick={() => { setMsg(null); run.mutate(); }} title="إعادة فحص كل النطاقات المعتمدة">
        {run.isPending ? "جارٍ بدء الفحص…" : "↻ إعادة فحص الكل"}
      </Button>
      {msg && <span className="text-xs text-slate-500">{msg}</span>}
    </span>
  );
}
