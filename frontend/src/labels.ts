/** Bilingual (Arabic / English) labels for every enumerated value returned by the API. */
import { getLang } from "./i18n";

/** Each value is a tuple [arabic, english]. */
export type Pair = readonly [string, string];
/** A label map may hold bilingual pairs or (for small local maps) plain strings. */
export type LabelMap = Record<string, Pair | string>;
type Dict = Record<string, Pair>;

export const DEVICE_TYPES: Dict = {
  computer: ["حاسوب", "Computer"],
  server: ["خادم", "Server"],
  mobile: ["هاتف محمول", "Mobile phone"],
  tablet: ["جهاز لوحي", "Tablet"],
  printer: ["طابعة", "Printer"],
  nas: ["جهاز تخزين شبكي", "Network storage (NAS)"],
  router: ["جهاز توجيه", "Router"],
  switch: ["محول شبكة", "Switch"],
  access_point: ["نقطة وصول لاسلكية", "Wireless access point"],
  network_device: ["جهاز شبكات", "Network device"],
  camera: ["كاميرا مراقبة", "Surveillance camera"],
  tv: ["تلفاز ذكي / جهاز وسائط", "Smart TV / media device"],
  iot: ["جهاز إنترنت أشياء", "IoT device"],
  virtual_machine: ["جهاز افتراضي", "Virtual machine"],
  hypervisor: ["منصة افتراضية", "Hypervisor"],
  unknown: ["غير مؤكد", "Unknown"],
};

export const OS_FAMILIES: Dict = {
  windows: ["ويندوز", "Windows"],
  linux: ["لينكس", "Linux"],
  macos: ["macOS", "macOS"],
  ios: ["iOS / iPadOS", "iOS / iPadOS"],
  android: ["أندرويد", "Android"],
  unix: ["لينكس/يونكس", "Linux / Unix"],
  network_os: ["نظام معدات شبكات", "Network OS"],
  unknown: ["غير مؤكد", "Unknown"],
};

export const ASSET_STATUS: Dict = {
  online: ["متصل", "Online"],
  offline: ["غير متصل", "Offline"],
  unknown: ["غير معروف", "Unknown"],
};

export const CRITICALITY: Dict = {
  low: ["منخفضة", "Low"],
  normal: ["عادية", "Normal"],
  high: ["عالية", "High"],
  critical: ["حرجة", "Critical"],
};

export const SEVERITY: Dict = {
  info: ["معلومة", "Info"],
  low: ["منخفضة", "Low"],
  medium: ["متوسطة", "Medium"],
  high: ["عالية", "High"],
  critical: ["حرجة", "Critical"],
};

export const ALERT_STATUS: Dict = {
  open: ["مفتوح", "Open"],
  acknowledged: ["تم الإقرار", "Acknowledged"],
  resolved: ["مغلق", "Resolved"],
};

export const JOB_STATUS: Dict = {
  queued: ["في الانتظار", "Queued"],
  running: ["قيد التنفيذ", "Running"],
  completed: ["مكتمل", "Completed"],
  cancelled: ["أُلغي", "Cancelled"],
  failed: ["فشل", "Failed"],
  interrupted: ["توقف بشكل غير متوقع", "Interrupted"],
};

export const EXPOSURE: Dict = {
  remote_admin: ["إدارة عن بعد", "Remote administration"],
  file_sharing: ["مشاركة ملفات", "File sharing"],
  web: ["ويب", "Web"],
  database: ["قواعد بيانات", "Database"],
  directory: ["خدمات الدليل", "Directory services"],
  mail: ["بريد", "Mail"],
  printing: ["طباعة", "Printing"],
  infrastructure: ["بنية تحتية", "Infrastructure"],
  media: ["وسائط", "Media"],
  iot: ["إنترنت الأشياء", "IoT"],
  mobile: ["أجهزة محمولة", "Mobile"],
  other: ["أخرى", "Other"],
};

export const METHODS: Dict = {
  icmp: ["ICMP", "ICMP"],
  tcp: ["اتصال TCP", "TCP connect"],
  arp: ["جدول ARP", "ARP table"],
  ssdp: ["UPnP/SSDP", "UPnP/SSDP"],
};

export const ID_METHOD: Dict = {
  port: ["رقم المنفذ فقط (تقديري)", "Port number only (heuristic)"],
  banner: ["توقيع الخدمة", "Service banner"],
};

export const EVENT_KINDS: Dict = {
  asset_new: ["جهاز جديد", "New device"],
  asset_offline: ["توقف عن الاستجابة", "Went offline"],
  asset_online: ["عاد للاستجابة", "Came back online"],
  ip_changed: ["تغير العنوان", "IP address changed"],
  service_opened: ["منفذ جديد", "New open port"],
  service_reopened: ["إعادة فتح منفذ", "Port re-opened"],
  service_closed: ["إغلاق منفذ", "Port closed"],
  classification_changed: ["تغير التصنيف", "Classification changed"],
};

export const AUDIT_ACTIONS: Dict = {
  "auth.login": ["تسجيل دخول", "Sign in"],
  "auth.logout": ["تسجيل خروج", "Sign out"],
  "auth.change_password": ["تغيير كلمة المرور", "Change password"],
  "authorization.denied": ["رفض صلاحية", "Permission denied"],
  "user.create": ["إنشاء مستخدم", "Create user"],
  "user.update": ["تعديل مستخدم", "Update user"],
  "scope.create": ["إنشاء نطاق", "Create scope"],
  "scope.update": ["تعديل نطاق", "Update scope"],
  "scope.approve": ["اعتماد نطاق", "Approve scope"],
  "scope.revoke": ["سحب اعتماد نطاق", "Revoke scope"],
  "scope.delete": ["حذف نطاق", "Delete scope"],
  "scan.start": ["بدء فحص", "Start scan"],
  "scan.cancel": ["إلغاء فحص", "Cancel scan"],
  "scan.emergency_stop": ["إيقاف طارئ", "Emergency stop"],
  "asset.update": ["تعديل جهاز", "Update device"],
  "alert.acknowledged": ["إقرار تنبيه", "Acknowledge alert"],
  "alert.resolved": ["إغلاق تنبيه", "Resolve alert"],
  "scan.rerun": ["إعادة فحص", "Re-run scan"],
  "scan.resume": ["استكمال فحص", "Resume scan"],
  "scan.delete": ["حذف فحص", "Delete scan"],
  "scope.schedule": ["جدولة فحص", "Schedule scan"],
  "profile.create": ["إنشاء ملف فحص", "Create scan profile"],
  "profile.update": ["تعديل ملف فحص", "Update scan profile"],
  "profile.delete": ["حذف ملف فحص", "Delete scan profile"],
  "credential.create": ["إضافة حساب دخول", "Add credential"],
  "credential.delete": ["حذف حساب دخول", "Delete credential"],
  "remote.execute": ["تنفيذ أمر على جهاز", "Run command on device"],
  "netadmin.execute": ["أمر إدارة جهاز شبكة", "Network-device command"],
  "ssh_host_key.forget": ["حذف مفتاح SSH محفوظ", "Forget saved SSH host key"],
  "fusion.export": ["تصدير جدول دمج", "Export fusion table"],
  "fusion.save_view": ["حفظ عرض دمج", "Save fusion view"],
  "fusion.delete_view": ["حذف عرض دمج", "Delete fusion view"],
  "topology.trace": ["اكتشاف مسارات الشبكة", "Discover network paths"],
  "maintenance.reset_inventory": ["مسح بيانات الجرد", "Reset inventory"],
};

export const TRIGGERS: Dict = {
  manual: ["يدوي", "Manual"],
  schedule: ["مجدول", "Scheduled"],
  resume: ["استكمال تلقائي", "Auto-resume"],
  rerun: ["إعادة", "Re-run"],
  asset: ["جهاز واحد", "Single device"],
};

export const label = (map: LabelMap, key: string | null | undefined): string => {
  if (key == null) return "—";
  const value = map[key];
  if (value == null) return key;
  if (typeof value === "string") return value;
  return getLang() === "en" ? value[1] : value[0];
};
