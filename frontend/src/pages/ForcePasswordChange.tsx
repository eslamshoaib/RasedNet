import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";
import { useAuth } from "../auth";
import { Button, ErrorBox, Field, inputClass } from "../components/ui";
import { t, useI18n } from "../i18n";
import { LanguageToggle } from "../components/LanguageToggle";

/**
 * Mandatory password change shown when the signed-in account still carries the
 * default first-run credentials (must_change_password). The rest of the app is
 * unreachable until a new password is set, so the standard default can never be
 * used for real access.
 */
export function ForcePasswordChange() {
  const { me, refresh, logout } = useAuth();
  const { dir } = useI18n();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (next !== confirm) {
      setError(t("كلمتا المرور غير متطابقتين", "The two passwords do not match"));
      return;
    }
    setBusy(true);
    try {
      await api("/api/auth/change-password", { method: "POST", body: { current_password: current, new_password: next } });
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <div dir={dir} className="flex min-h-screen items-center justify-center bg-gradient-to-br from-ink-900 via-ink-800 to-cyan-900 p-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-3xl bg-white p-7 shadow-2xl">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <img src="/favicon.svg" alt="" className="h-10 w-10" />
            <div>
              <h1 className="text-lg font-bold text-slate-800">{t("يجب تغيير كلمة المرور", "Change your password")}</h1>
              <p className="text-xs text-slate-500">
                {t(
                  `مرحباً ${me?.user.display_name ?? ""}. هذه كلمة مرور افتراضية — عيّن كلمة مرور جديدة للمتابعة.`,
                  `Welcome ${me?.user.display_name ?? ""}. This is a default password — set a new one to continue.`,
                )}
              </p>
            </div>
          </div>
          <LanguageToggle variant="plain" />
        </div>
        <Field label={t("كلمة المرور الحالية", "Current password")}>
          <input className={inputClass} dir="ltr" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        </Field>
        <Field label={t("كلمة المرور الجديدة", "New password")}>
          <input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required />
        </Field>
        <Field label={t("تأكيد كلمة المرور الجديدة", "Confirm new password")}>
          <input className={inputClass} dir="ltr" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
        </Field>
        <p className="text-xs text-slate-500">
          {t(
            "يجب ألا تقل كلمة المرور عن 12 حرفاً وتجمع بين حروف كبيرة وصغيرة وأرقام ورموز.",
            "Use at least 12 characters with upper- and lower-case letters, digits and a symbol.",
          )}
        </p>
        <ErrorBox error={error} />
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? t("جارٍ الحفظ…", "Saving…") : t("تغيير كلمة المرور", "Change password")}
        </Button>
        <button type="button" onClick={() => void logout()} className="w-full text-xs text-slate-500 hover:text-slate-700">
          {t("تسجيل الخروج", "Sign out")}
        </button>
      </form>
    </div>
  );
}
