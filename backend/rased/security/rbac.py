"""Built-in roles and permissions (seeded idempotently at start-up)."""

from __future__ import annotations

PERMISSIONS: dict[str, str] = {
    "dashboard:read": "عرض لوحة التحكم",
    "scope:read": "عرض نطاقات الفحص",
    "scope:manage": "إنشاء وتعديل نطاقات الفحص",
    "scope:approve": "اعتماد نطاقات الفحص",
    "scan:read": "عرض مهام الفحص ونتائجها",
    "scan:run": "تشغيل وإيقاف مهام الفحص",
    "asset:read": "عرض الأجهزة والخدمات",
    "asset:write": "تعديل بيانات الأجهزة",
    "alert:read": "عرض التنبيهات وسجل التغييرات",
    "alert:manage": "الإقرار بالتنبيهات وإغلاقها",
    "audit:read": "عرض سجل التدقيق",
    "user:manage": "إدارة المستخدمين",
    "profile:manage": "إنشاء وتعديل ملفات الفحص",
    "credential:manage": "إدارة بيانات الدخول للأجهزة (الخزنة)",
    "remote:verify": "تشغيل أوامر التحقق (للقراءة فقط) على الأجهزة",
    "remote:change": "تشغيل أوامر الإغلاق والتأمين على الأجهزة",
    "data:manage": "حذف سجل الفحوصات ومسح بيانات الجرد",
    "report:read": "إنشاء وعرض التقارير الشاملة",
    "directory:read": "الاستعلام عن مستخدمي ومجموعات الدومين (قراءة فقط)",
}

ROLES: dict[str, tuple[str, str, set[str]]] = {
    "admin": ("مسؤول النظام", "صلاحيات كاملة بما فيها اعتماد النطاقات وإدارة المستخدمين", set(PERMISSIONS)),
    "operator": (
        "مشغل الفحص",
        "تشغيل الفحوص على النطاقات المعتمدة ومتابعة التنبيهات دون اعتماد نطاقات جديدة",
        {"dashboard:read", "scope:read", "scan:read", "scan:run", "asset:read", "asset:write", "alert:read",
         "alert:manage", "remote:verify", "report:read", "directory:read"},
    ),
    "auditor": (
        "مدقق",
        "اطلاع للقراءة فقط على كل البيانات وسجل التدقيق",
        {"dashboard:read", "scope:read", "scan:read", "asset:read", "alert:read", "audit:read", "report:read"},
    ),
}
