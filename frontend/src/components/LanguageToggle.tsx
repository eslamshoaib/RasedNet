import { useI18n } from "../i18n";

/**
 * Switches the whole interface between Arabic (RTL) and English (LTR).
 * The button always shows the language it will switch TO.
 */
export function LanguageToggle({ variant = "header" }: { variant?: "header" | "plain" }) {
  const { lang, toggle } = useI18n();
  const next = lang === "ar" ? "English" : "العربية";
  const title = lang === "ar" ? "Switch to English" : "التبديل إلى العربية";

  const base =
    variant === "plain"
      ? "rounded-lg border border-slate-300 px-2.5 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-50"
      : "inline-flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-semibold text-slate-700 hover:bg-slate-50";

  return (
    <button type="button" onClick={toggle} title={title} aria-label={title} className={base}>
      {variant === "plain" ? next : <span>{lang === "ar" ? "EN" : "ع"}</span>}
    </button>
  );
}
