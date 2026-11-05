import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage } from "../api";
import { Button, Card, ErrorBox, Field, inputClass } from "../components/ui";

const PHRASE = "حذف كل البيانات";

export function SettingsPage() {
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const reset = useMutation({
    mutationFn: () => api<{ assets: number; scans: number; alerts: number }>("/api/maintenance/reset-inventory", { method: "POST", body: { confirm_text: text } }),
    onSuccess: () => { setText(""); void qc.invalidateQueries(); },
  });
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">الإعدادات والصيانة</h1>
      <Card title="مسح بيانات الفحص والبدء من جديد">
        <div className="space-y-3 text-sm">
          <p>يحذف هذا الإجراء <b>كل الأجهزة والخدمات وسجل الفحوصات والتنبيهات وسجل التغييرات</b>.</p>
          <p className="text-slate-600">يبقى كما هو: المستخدمون، نطاقات الشبكة واعتمادها، ملفات الفحص، الجدولة، خزنة الدخول، العروض المحفوظة، و<b>سجل التدقيق</b> (لا يُحذف أبداً).</p>
          <p className="text-slate-600">لحذف فحص واحد فقط استخدم زر الحذف في «سجل الفحوصات».</p>
          <Field label={`للتأكيد اكتب: ${PHRASE}`}>
            <input className={`${inputClass} max-w-sm`} value={text} onChange={(e) => setText(e.target.value)} />
          </Field>
          <Button variant="danger" disabled={text.trim() !== PHRASE || reset.isPending}
            onClick={() => window.confirm("هل أنت متأكد؟ لا يمكن التراجع عن هذا الإجراء إلا من نسخة احتياطية.") && reset.mutate()}>
            مسح كل بيانات الفحص
          </Button>
          {reset.error && <ErrorBox error={errorMessage(reset.error)} />}
          {reset.data && <p className="text-emerald-700">تم الحذف: {reset.data.assets} جهاز، {reset.data.scans} فحص، {reset.data.alerts} تنبيه. يمكنك الآن بدء فحص جديد من «اكتشاف الشبكة».</p>}
        </div>
      </Card>
      <Card title="النسخ الاحتياطي">
        <p className="text-sm text-slate-600">قبل المسح يُنصح بأخذ نسخة احتياطية مشفرة: <span dir="ltr" className="ltr">.\scripts\backup.ps1</span></p>
      </Card>
    </div>
  );
}
