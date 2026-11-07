import { useState, type FormEvent } from "react";
import { errorMessage } from "../api";
import { useAuth } from "../auth";
import { Button, ErrorBox, Field, inputClass } from "../components/ui";
import { t, useI18n } from "../i18n";
import { LanguageToggle } from "../components/LanguageToggle";

export function LoginPage() {
  const { login } = useAuth();
  const { dir } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError(errorMessage(err));
      setPassword("");
    } finally {
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
              <h1 className="text-xl font-bold text-slate-800">{t("راصد", "RasedNet")}</h1>
              <p className="text-xs text-slate-500">{t("منصة رصد الشبكة وتقييم أمنها — تعمل محلياً بالكامل", "Network monitoring & security-assessment — fully on-premises")}</p>
            </div>
          </div>
          <LanguageToggle variant="plain" />
        </div>
        <Field label={t("اسم المستخدم", "Username")}>
          <input className={inputClass} dir="ltr" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </Field>
        <Field label={t("كلمة المرور", "Password")}>
          <input className={inputClass} dir="ltr" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </Field>
        <ErrorBox error={error} />
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? t("جارٍ التحقق…", "Verifying…") : t("تسجيل الدخول", "Sign in")}
        </Button>
        <p className="text-xs text-slate-500">{t("الاستخدام مقصور على المصرح لهم. يتم تسجيل جميع العمليات في سجل التدقيق.", "Authorized use only. All operations are recorded in the audit log.")}</p>
      </form>
    </div>
  );
}
