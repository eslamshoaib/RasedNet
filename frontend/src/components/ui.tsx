import type { ButtonHTMLAttributes, ReactNode } from "react";
import { errorMessage } from "../api";
import { getLang, t } from "../i18n";

export function Ltr({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <bdi dir="ltr" className={`ltr ${className}`}>
      {children}
    </bdi>
  );
}

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-2xl border border-slate-200/80 bg-white shadow-sm ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 px-5 py-3.5">
          <h2 className="text-[15px] font-bold text-slate-800">{title}</h2>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export type Tone = "slate" | "green" | "red" | "amber" | "blue" | "teal" | "orange" | "purple";
const TONES: Record<Tone, string> = {
  slate: "bg-slate-100 text-slate-700",
  green: "bg-emerald-100 text-emerald-800",
  red: "bg-red-100 text-red-800",
  amber: "bg-amber-100 text-amber-800",
  blue: "bg-sky-100 text-sky-800",
  teal: "bg-teal-100 text-cyan-800",
  orange: "bg-orange-100 text-orange-800",
  purple: "bg-violet-100 text-violet-800",
};

export function Badge({ tone = "slate", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ${TONES[tone]}`}>{children}</span>;
}

export const SEVERITY_TONE: Record<string, Tone> = { info: "blue", low: "slate", medium: "amber", high: "orange", critical: "red" };
export const STATUS_TONE: Record<string, Tone> = {
  online: "green", offline: "red", unknown: "slate",
  queued: "slate", running: "blue", completed: "green", cancelled: "amber", failed: "red", interrupted: "orange",
  open: "red", acknowledged: "amber", resolved: "green",
};

type Variant = "primary" | "secondary" | "danger" | "ghost";
const VARIANTS: Record<Variant, string> = {
  primary: "bg-gradient-to-l from-cyan-600 to-sky-600 text-white shadow-sm hover:from-cyan-700 hover:to-sky-700",
  secondary: "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50",
  danger: "bg-red-600 text-white hover:bg-red-700",
  ghost: "text-cyan-800 hover:bg-cyan-50",
};

export function Button({ variant = "primary", className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 rounded-xl px-3.5 py-1.5 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-50 ${VARIANTS[variant]} ${className}`}
    />
  );
}

export const inputClass =
  "w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm focus:border-cyan-600 focus:outline-none focus:ring-2 focus:ring-cyan-100";

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-medium text-slate-700">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div role="alert" className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
      {typeof error === "string" ? error : errorMessage(error)}
    </div>
  );
}

export function Loading() {
  return <div className="py-8 text-center text-sm text-slate-500">{t("جارٍ التحميل…", "Loading…")}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-8 text-center text-sm text-slate-500">{children}</div>;
}

export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="mt-3 flex items-center justify-between text-sm text-slate-600">
      <span>
        {getLang() === "en" ? `Total: ${total} — page ${page} of ${pages}` : `الإجمالي: ${total} — صفحة ${page} من ${pages}`}
      </span>
      <div className="flex gap-2">
        <Button variant="secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          {t("السابق", "Previous")}
        </Button>
        <Button variant="secondary" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          {t("التالي", "Next")}
        </Button>
      </div>
    </div>
  );
}

export function Stat({ label, value, tone = "slate", hint }: { label: string; value: ReactNode; tone?: Tone; hint?: string }) {
  const ring: Record<Tone, string> = {
    slate: "border-s-slate-400", green: "border-s-emerald-500", red: "border-s-red-500", amber: "border-s-amber-500",
    blue: "border-s-sky-500", teal: "border-s-teal-600", orange: "border-s-orange-500", purple: "border-s-violet-500",
  };
  return (
    <div className={`card-hover rounded-2xl border border-slate-200/80 border-s-4 bg-white p-4 shadow-sm ${ring[tone]}`}>
      <div className="text-xs font-medium text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-bold text-slate-800">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function ProgressBar({ value }: { value: number }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200" role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      <div className="h-full bg-gradient-to-l from-cyan-500 to-sky-600 transition-all" style={{ width: `${value}%` }} />
    </div>
  );
}
