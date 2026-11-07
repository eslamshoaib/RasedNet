import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Badge, Button, Card, ErrorBox, Field, inputClass, Loading, Ltr } from "../components/ui";
import { getLang, t } from "../i18n";
import type { Profile } from "../types";

export const MAX_PORTS = 2048;

/** "22, 80, 8000-8010" → sorted unique ports, or a localized error. */
export function parsePortSpec(text: string): number[] | string {
  const en = getLang() === "en";
  const tooMany = en ? `Maximum ${MAX_PORTS} ports` : `الحد الأقصى ${MAX_PORTS} منفذاً`;
  const out = new Set<number>();
  for (const part of text.split(/[\s,،]+/).map((p) => p.trim()).filter(Boolean)) {
    const range = part.match(/^(\d{1,5})-(\d{1,5})$/);
    if (range) {
      const a = Number(range[1]);
      const b = Number(range[2]);
      if (a < 1 || b > 65535 || a > b) return en ? `Invalid range: ${part}` : `نطاق غير صالح: ${part}`;
      if (b - a + 1 + out.size > MAX_PORTS) return tooMany;
      for (let p = a; p <= b; p++) out.add(p);
    } else if (/^\d{1,5}$/.test(part) && Number(part) >= 1 && Number(part) <= 65535) {
      out.add(Number(part));
    } else {
      return en ? `Invalid value: ${part}` : `قيمة غير صالحة: ${part}`;
    }
  }
  if (out.size > MAX_PORTS) return tooMany;
  return [...out].sort((x, y) => x - y);
}

/** Compact display: consecutive ports collapse into ranges. */
export function portSpec(ports: number[]): string {
  const parts: string[] = [];
  let i = 0;
  while (i < ports.length) {
    let j = i;
    while (j + 1 < ports.length && ports[j + 1] === ports[j] + 1) j++;
    parts.push(j > i + 1 ? `${ports[i]}-${ports[j]}` : j === i + 1 ? `${ports[i]}, ${ports[j]}` : `${ports[i]}`);
    i = j + 1;
  }
  return parts.join(", ");
}

interface Draft {
  id: number | null;
  name_ar: string;
  description_ar: string;
  discovery: string;
  tcp: string;
  use_icmp: boolean;
  use_arp: boolean;
  resolve_dns: boolean;
  grab_banners: boolean;
  max_concurrency: number;
  per_host_concurrency: number;
  rate_per_second: number;
  connect_timeout_ms: number;
  retries: number;
}

const fromProfile = (p: Profile, copy: boolean): Draft => ({
  id: copy ? null : p.id, name_ar: copy ? `${p.name_ar} ${t("(نسخة)", "(copy)")}` : p.name_ar, description_ar: p.description_ar,
  discovery: portSpec(p.discovery_ports), tcp: portSpec(p.tcp_ports), use_icmp: p.use_icmp, use_arp: p.use_arp,
  resolve_dns: p.resolve_dns, grab_banners: p.grab_banners, max_concurrency: p.max_concurrency,
  per_host_concurrency: p.per_host_concurrency, rate_per_second: p.rate_per_second, connect_timeout_ms: p.connect_timeout_ms, retries: p.retries,
});

function Editor({ draft, onDone }: { draft: Draft; onDone: () => void }) {
  const [d, setD] = useState(draft);
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (body: object) => api<Profile>(d.id ? `/api/profiles/${d.id}` : "/api/profiles", { method: d.id ? "PUT" : "POST", body }),
    onSuccess: onDone,
    onError: (e) => setError(errorMessage(e)),
  });
  const num = (key: keyof Draft) => (e: { target: { value: string } }) => setD({ ...d, [key]: Number(e.target.value) });

  function submit(e: FormEvent) {
    e.preventDefault();
    const discovery = parsePortSpec(d.discovery);
    const tcp = parsePortSpec(d.tcp);
    if (typeof discovery === "string") return setError(`${t("منافذ الاكتشاف:", "Discovery ports:")} ${discovery}`);
    if (typeof tcp === "string") return setError(`${t("منافذ الخدمات:", "Service ports:")} ${tcp}`);
    if (!discovery.length || discovery.length > 32) return setError(t("منافذ الاكتشاف: من 1 إلى 32 منفذاً", "Discovery ports: between 1 and 32 ports"));
    setError(null);
    save.mutate({ name_ar: d.name_ar, description_ar: d.description_ar, discovery_ports: discovery, tcp_ports: tcp,
      use_icmp: d.use_icmp, use_arp: d.use_arp, resolve_dns: d.resolve_dns, grab_banners: d.grab_banners,
      max_concurrency: d.max_concurrency, per_host_concurrency: d.per_host_concurrency, rate_per_second: d.rate_per_second,
      connect_timeout_ms: d.connect_timeout_ms, retries: d.retries });
  }

  const tcpCount = typeof parsePortSpec(d.tcp) === "string" ? null : (parsePortSpec(d.tcp) as number[]).length;
  return (
    <form onSubmit={submit} className="grid gap-3 md:grid-cols-2">
      <Field label={t("اسم الملف", "Profile name")}><input className={inputClass} required maxLength={128} value={d.name_ar} onChange={(e) => setD({ ...d, name_ar: e.target.value })} /></Field>
      <Field label={t("الوصف", "Description")}><input className={inputClass} maxLength={2000} value={d.description_ar} onChange={(e) => setD({ ...d, description_ar: e.target.value })} /></Field>
      <Field label={t("منافذ الاكتشاف (لمعرفة هل الجهاز موجود)", "Discovery ports (to detect if a device exists)")} hint={t("1–32 منفذاً", "1–32 ports")}><input className={inputClass} dir="ltr" value={d.discovery} onChange={(e) => setD({ ...d, discovery: e.target.value })} /></Field>
      <Field label={t("منافذ فحص الخدمات", "Service-scan ports")} hint={getLang() === "en" ? `Ranges like 1-1024 are accepted — current count: ${tcpCount ?? "invalid"} (limit ${MAX_PORTS})` : `تقبل النطاقات مثل 1-1024 — العدد الحالي: ${tcpCount ?? "غير صالح"} (الحد ${MAX_PORTS})`}>
        <textarea className={inputClass} dir="ltr" rows={2} value={d.tcp} onChange={(e) => setD({ ...d, tcp: e.target.value })} />
      </Field>
      <div className="flex flex-wrap gap-4 text-sm md:col-span-2">
        {([["use_icmp", "ICMP (ping)"], ["use_arp", t("جدول ARP + UPnP", "ARP table + UPnP")], ["resolve_dns", t("أسماء DNS", "DNS names")], ["grab_banners", t("قراءة توقيعات الخدمات وشهادات TLS", "Read service banners & TLS certificates")]] as const).map(([k, lbl]) => (
          <label key={k} className="flex items-center gap-1.5"><input type="checkbox" checked={d[k]} onChange={(e) => setD({ ...d, [k]: e.target.checked })} /> {lbl}</label>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-3 md:col-span-2 md:grid-cols-5">
        <Field label={t("اتصالات/ثانية", "Connections/sec")} hint={t("حد حماية الشبكة", "Network-protection limit")}><input type="number" min={1} max={2000} className={inputClass} value={d.rate_per_second} onChange={num("rate_per_second")} /></Field>
        <Field label={t("اتصالات متزامنة", "Concurrent connections")}><input type="number" min={1} max={1024} className={inputClass} value={d.max_concurrency} onChange={num("max_concurrency")} /></Field>
        <Field label={t("لكل جهاز", "Per device")}><input type="number" min={1} max={64} className={inputClass} value={d.per_host_concurrency} onChange={num("per_host_concurrency")} /></Field>
        <Field label={t("المهلة (ms)", "Timeout (ms)")}><input type="number" min={200} max={30000} className={inputClass} value={d.connect_timeout_ms} onChange={num("connect_timeout_ms")} /></Field>
        <Field label={t("إعادة المحاولة", "Retries")}><input type="number" min={0} max={3} className={inputClass} value={d.retries} onChange={num("retries")} /></Field>
      </div>
      <div className="md:col-span-2"><ErrorBox error={error} /></div>
      <div className="flex gap-2 md:col-span-2">
        <Button type="submit" disabled={save.isPending}>{d.id ? t("حفظ التعديلات", "Save changes") : t("إنشاء الملف", "Create profile")}</Button>
        <Button variant="secondary" onClick={onDone}>{t("إلغاء", "Cancel")}</Button>
      </div>
    </form>
  );
}

export function ProfilesPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api<Profile[]>("/api/profiles") });
  const [draft, setDraft] = useState<Draft | null>(null);
  const del = useMutation({
    mutationFn: (id: number) => api(`/api/profiles/${id}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["profiles"] }),
    onError: (e) => window.alert(errorMessage(e)),
  });
  const done = () => { setDraft(null); void qc.invalidateQueries({ queryKey: ["profiles"] }); };
  const manage = can("profile:manage");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <h1 className="text-2xl font-bold">{t("ملفات الفحص", "Scan profiles")}</h1>
        {manage && !draft && (
          <Button onClick={() => setDraft({ id: null, name_ar: "", description_ar: "", discovery: "22, 80, 135, 139, 443, 445, 3389, 8080", tcp: "1-1024",
            use_icmp: true, use_arp: true, resolve_dns: true, grab_banners: true, max_concurrency: 512, per_host_concurrency: 16,
            rate_per_second: 300, connect_timeout_ms: 1500, retries: 0 })}>{t("ملف فحص جديد", "New scan profile")}</Button>
        )}
      </div>
      {draft && <Card title={draft.id ? t("تعديل ملف الفحص", "Edit scan profile") : t("ملف فحص جديد", "New scan profile")}><Editor key={draft.id ?? "new"} draft={draft} onDone={done} /></Card>}
      {profiles.isLoading ? <Loading /> : profiles.error ? <ErrorBox error={profiles.error} /> : (
        <div className="grid gap-4 lg:grid-cols-2">
          {profiles.data?.map((p) => (
            <Card key={p.id} title={<span className="flex items-center gap-2">{p.name_ar} {p.code.startsWith("custom_") ? <Badge tone="purple">{t("مخصص", "Custom")}</Badge> : <Badge>{t("أساسي", "Built-in")}</Badge>}</span>}
              actions={manage && (
                <div className="flex gap-1">
                  <Button variant="ghost" onClick={() => setDraft(fromProfile(p, true))}>{t("نسخ وتعديل", "Copy & edit")}</Button>
                  {p.code.startsWith("custom_") && <Button variant="ghost" onClick={() => setDraft(fromProfile(p, false))}>{t("تعديل", "Edit")}</Button>}
                  {p.code.startsWith("custom_") && <Button variant="ghost" onClick={() => window.confirm(getLang() === "en" ? `Delete “${p.name_ar}”?` : `حذف «${p.name_ar}»؟`) && del.mutate(p.id)}>{t("حذف", "Delete")}</Button>}
                </div>
              )}>
              <p className="text-sm text-slate-600">{p.description_ar || "—"}</p>
              <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs text-slate-600">
                <dt>{t("منافذ الاكتشاف", "Discovery ports")}</dt><dd><Ltr>{portSpec(p.discovery_ports)}</Ltr></dd>
                <dt>{t("منافذ الخدمات", "Service ports")}</dt><dd>{p.tcp_ports.length ? <><Ltr>{portSpec(p.tcp_ports).slice(0, 160)}</Ltr> ({p.tcp_ports.length})</> : t("لا يوجد", "None")}</dd>
                <dt>{t("السرعة", "Speed")}</dt><dd>{getLang() === "en" ? `${p.rate_per_second} conn/s — ${p.max_concurrency} concurrent — ${p.per_host_concurrency} per device` : `${p.rate_per_second} اتصال/ث — ${p.max_concurrency} متزامن — ${p.per_host_concurrency} لكل جهاز`}</dd>
                <dt>{t("المهلة", "Timeout")}</dt><dd>{p.connect_timeout_ms} ms — {t("إعادة", "retries")} {p.retries}</dd>
                <dt>{t("المزايا", "Features")}</dt><dd>{[p.use_icmp && "ICMP", p.use_arp && "ARP/UPnP/NetBIOS", p.resolve_dns && "DNS", p.grab_banners && t("توقيعات وTLS", "banners & TLS")].filter(Boolean).join(" • ")}</dd>
              </dl>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
