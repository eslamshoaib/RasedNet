/**
 * Bilingual (Arabic / English) support.
 *
 * - Arabic is RTL and the default; English is LTR (sidebar moves to the left automatically
 *   because the layout uses logical CSS and the document `dir` attribute is switched).
 * - `t(ar, en)` is a plain function so it works both inside components and in helper modules
 *   (format.ts, api.ts, labels.ts). The whole app subtree is remounted on a language change,
 *   so every string — including lazy-loaded pages — is re-evaluated with the new language.
 */
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

export type Lang = "ar" | "en";

const STORAGE_KEY = "rasednet.lang";

function readInitialLang(): Lang {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "ar" || stored === "en") return stored;
  } catch {
    /* storage may be unavailable (private mode) — fall back to Arabic */
  }
  return "ar";
}

// Module-level current language, readable by non-React helpers via getLang()/t().
let currentLang: Lang = readInitialLang();

export const getLang = (): Lang => currentLang;
export const dirFor = (lang: Lang): "rtl" | "ltr" => (lang === "ar" ? "rtl" : "ltr");

/** Pick the string for the active language. Usable anywhere (component or module). */
export function t(ar: string, en: string): string {
  return currentLang === "en" ? en : ar;
}

interface I18nState {
  lang: Lang;
  dir: "rtl" | "ltr";
  setLang: (lang: Lang) => void;
  toggle: () => void;
}

const I18nContext = createContext<I18nState | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(currentLang);

  // Keep the module-level value in sync on every render so t() is correct during this render.
  currentLang = lang;

  useEffect(() => {
    const doc = document.documentElement;
    doc.lang = lang;
    doc.dir = dirFor(lang);
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      /* ignore storage failures */
    }
  }, [lang]);

  const setLang = useCallback((next: Lang) => {
    currentLang = next;
    setLangState(next);
  }, []);

  const toggle = useCallback(() => setLang(currentLang === "ar" ? "en" : "ar"), [setLang]);

  const value: I18nState = { lang, dir: dirFor(lang), setLang, toggle };

  // Remounting on language change guarantees every subtree (incl. lazy pages) re-reads t().
  return (
    <I18nContext.Provider value={value}>
      <LangBoundary key={lang}>{children}</LangBoundary>
    </I18nContext.Provider>
  );
}

function LangBoundary({ children }: { children: ReactNode }) {
  return <>{children}</>;
}

export function useI18n(): I18nState {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}
