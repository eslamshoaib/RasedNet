import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage } from "../api";
import { Button, Card, ErrorBox, Field, inputClass } from "../components/ui";
import { getLang, t } from "../i18n";

export function SettingsPage() {
  const qc = useQueryClient();
  const phrase = t("حذف كل البيانات", "DELETE ALL DATA");
  const [text, setText] = useState("");
  const reset = useMutation({
    mutationFn: () => api<{ assets: number; scans: number; alerts: number }>("/api/maintenance/reset-inventory", { method: "POST", body: { confirm_text: text } }),
    onSuccess: () => { setText(""); void qc.invalidateQueries(); },
  });
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">{t("الإعدادات والصيانة", "Settings & maintenance")}</h1>
      <Card title={t("مسح بيانات الفحص والبدء من جديد", "Reset scan data and start fresh")}>
        <div className="space-y-3 text-sm">
          <p>{t("يحذف هذا الإجراء كل الأجهزة والخدمات وسجل الفحوصات والتنبيهات وسجل التغييرات.", "This action deletes all devices, services, scan history, alerts and the change log.")}</p>
          <p className="text-slate-600">{t("يبقى كما هو: المستخدمون، نطاقات الشبكة واعتمادها، ملفات الفحص، الجدولة، خزنة الدخول، العروض المحفوظة، وسجل التدقيق (لا يُحذف أبداً).", "Preserved: users, network scopes and their approval, scan profiles, schedules, the credential vault, saved views, and the audit log (never deleted).")}</p>
          <p className="text-slate-600">{t("لحذف فحص واحد فقط استخدم زر الحذف في «سجل الفحوصات».", "To delete a single scan, use the delete button in “Scan history”.")}</p>
          <Field label={`${t("للتأكيد اكتب:", "To confirm, type:")} ${phrase}`}>
            <input className={`${inputClass} max-w-sm`} value={text} onChange={(e) => setText(e.target.value)} />
          </Field>
          <Button variant="danger" disabled={text.trim() !== phrase || reset.isPending}
            onClick={() => window.confirm(t("هل أنت متأكد؟ لا يمكن التراجع عن هذا الإجراء إلا من نسخة احتياطية.", "Are you sure? This can only be undone from a backup.")) && reset.mutate()}>
            {t("مسح كل بيانات الفحص", "Delete all scan data")}
          </Button>
          {reset.error && <ErrorBox error={errorMessage(reset.error)} />}
          {reset.data && <p className="text-emerald-700">{getLang() === "en"
            ? `Deleted: ${reset.data.assets} devices, ${reset.data.scans} scans, ${reset.data.alerts} alerts. You can now start a new scan from “Network discovery”.`
            : `تم الحذف: ${reset.data.assets} جهاز، ${reset.data.scans} فحص، ${reset.data.alerts} تنبيه. يمكنك الآن بدء فحص جديد من «اكتشاف الشبكة».`}</p>}
        </div>
      </Card>
      <Card title={t("النسخ الاحتياطي", "Backup")}>
        <p className="text-sm text-slate-600">{t("قبل المسح يُنصح بأخذ نسخة احتياطية مشفرة:", "Before resetting, take an encrypted backup:")} <span dir="ltr" className="ltr">.\scripts\backup.ps1</span></p>
      </Card>
    </div>
  );
}
