import { useState, type FormEvent } from "react";
import { errorMessage } from "../api";
import { useAuth } from "../auth";
import { Button, ErrorBox, Field, inputClass } from "../components/ui";

export function LoginPage() {
  const { login } = useAuth();
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
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-ink-900 via-ink-800 to-cyan-900 p-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-3xl bg-white p-7 shadow-2xl">
        <div className="flex items-center gap-3">
          <img src="/favicon.svg" alt="" className="h-10 w-10" />
          <div>
            <h1 className="text-xl font-bold text-slate-800">راصد</h1>
            <p className="text-xs text-slate-500">منصة رصد الشبكة وتقييم أمنها — تعمل محلياً بالكامل</p>
          </div>
        </div>
        <Field label="اسم المستخدم">
          <input className={inputClass} dir="ltr" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </Field>
        <Field label="كلمة المرور">
          <input className={inputClass} dir="ltr" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </Field>
        <ErrorBox error={error} />
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? "جارٍ التحقق…" : "تسجيل الدخول"}
        </Button>
        <p className="text-xs text-slate-500">الاستخدام مقصور على المصرح لهم. يتم تسجيل جميع العمليات في سجل التدقيق.</p>
      </form>
    </div>
  );
}
