/** Arabic labels for every enumerated value returned by the API. */

export const DEVICE_TYPES: Record<string, string> = {
  computer: "حاسوب",
  server: "خادم",
  mobile: "هاتف محمول",
  tablet: "جهاز لوحي",
  printer: "طابعة",
  nas: "جهاز تخزين شبكي",
  router: "جهاز توجيه",
  switch: "محول شبكة",
  access_point: "نقطة وصول لاسلكية",
  network_device: "جهاز شبكات",
  camera: "كاميرا مراقبة",
  tv: "تلفاز ذكي / جهاز وسائط",
  iot: "جهاز إنترنت أشياء",
  virtual_machine: "جهاز افتراضي",
  hypervisor: "منصة افتراضية",
  unknown: "غير مؤكد",
};

export const OS_FAMILIES: Record<string, string> = {
  windows: "ويندوز",
  linux: "لينكس",
  macos: "macOS",
  ios: "iOS / iPadOS",
  android: "أندرويد",
  unix: "لينكس/يونكس",
  network_os: "نظام معدات شبكات",
  unknown: "غير مؤكد",
};

export const ASSET_STATUS: Record<string, string> = {
  online: "متصل",
  offline: "غير متصل",
  unknown: "غير معروف",
};

export const CRITICALITY: Record<string, string> = {
  low: "منخفضة",
  normal: "عادية",
  high: "عالية",
  critical: "حرجة",
};

export const SEVERITY: Record<string, string> = {
  info: "معلومة",
  low: "منخفضة",
  medium: "متوسطة",
  high: "عالية",
  critical: "حرجة",
};

export const ALERT_STATUS: Record<string, string> = {
  open: "مفتوح",
  acknowledged: "تم الإقرار",
  resolved: "مغلق",
};

export const JOB_STATUS: Record<string, string> = {
  queued: "في الانتظار",
  running: "قيد التنفيذ",
  completed: "مكتمل",
  cancelled: "أُلغي",
  failed: "فشل",
  interrupted: "توقف بشكل غير متوقع",
};

export const EXPOSURE: Record<string, string> = {
  remote_admin: "إدارة عن بعد",
  file_sharing: "مشاركة ملفات",
  web: "ويب",
  database: "قواعد بيانات",
  directory: "خدمات الدليل",
  mail: "بريد",
  printing: "طباعة",
  infrastructure: "بنية تحتية",
  media: "وسائط",
  iot: "إنترنت الأشياء",
  mobile: "أجهزة محمولة",
  other: "أخرى",
};

export const METHODS: Record<string, string> = {
  icmp: "ICMP",
  tcp: "اتصال TCP",
  arp: "جدول ARP",
  ssdp: "UPnP/SSDP",
};

export const ID_METHOD: Record<string, string> = {
  port: "رقم المنفذ فقط (تقديري)",
  banner: "توقيع الخدمة",
};

export const EVENT_KINDS: Record<string, string> = {
  asset_new: "جهاز جديد",
  asset_offline: "توقف عن الاستجابة",
  asset_online: "عاد للاستجابة",
  ip_changed: "تغير العنوان",
  service_opened: "منفذ جديد",
  service_reopened: "إعادة فتح منفذ",
  service_closed: "إغلاق منفذ",
  classification_changed: "تغير التصنيف",
};

export const AUDIT_ACTIONS: Record<string, string> = {
  "auth.login": "تسجيل دخول",
  "auth.logout": "تسجيل خروج",
  "auth.change_password": "تغيير كلمة المرور",
  "authorization.denied": "رفض صلاحية",
  "user.create": "إنشاء مستخدم",
  "user.update": "تعديل مستخدم",
  "scope.create": "إنشاء نطاق",
  "scope.update": "تعديل نطاق",
  "scope.approve": "اعتماد نطاق",
  "scope.revoke": "سحب اعتماد نطاق",
  "scope.delete": "حذف نطاق",
  "scan.start": "بدء فحص",
  "scan.cancel": "إلغاء فحص",
  "scan.emergency_stop": "إيقاف طارئ",
  "asset.update": "تعديل جهاز",
  "alert.acknowledged": "إقرار تنبيه",
  "alert.resolved": "إغلاق تنبيه",
  "scan.rerun": "إعادة فحص",
  "scan.resume": "استكمال فحص",
  "scan.delete": "حذف فحص",
  "scope.schedule": "جدولة فحص",
  "profile.create": "إنشاء ملف فحص",
  "profile.update": "تعديل ملف فحص",
  "profile.delete": "حذف ملف فحص",
  "credential.create": "إضافة حساب دخول",
  "credential.delete": "حذف حساب دخول",
  "remote.execute": "تنفيذ أمر على جهاز",
  "netadmin.execute": "أمر إدارة جهاز شبكة",
  "ssh_host_key.forget": "حذف مفتاح SSH محفوظ",
  "fusion.export": "تصدير جدول دمج",
  "fusion.save_view": "حفظ عرض دمج",
  "fusion.delete_view": "حذف عرض دمج",
  "topology.trace": "اكتشاف مسارات الشبكة",
  "maintenance.reset_inventory": "مسح بيانات الجرد",
};

export const TRIGGERS: Record<string, string> = {
  manual: "يدوي",
  schedule: "مجدول",
  resume: "استكمال تلقائي",
  rerun: "إعادة",
  asset: "جهاز واحد",
};

export const label = (map: Record<string, string>, key: string | null | undefined): string =>
  key == null ? "—" : (map[key] ?? key);
