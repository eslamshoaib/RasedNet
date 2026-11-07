<div align="center">

# راصد · RasedNet

**منصّة اكتشاف الشبكات وجرد الأصول وتقييم التعرّض الأمني — تعمل دون اتصال بالكامل، وعربية الواجهة بالكامل.**

**Offline-first, Arabic-first network discovery, asset inventory & security-exposure platform — for networks you own and administer.**

![Offline](https://img.shields.io/badge/100%25-Offline-0B1B2D)
![Arabic First](https://img.shields.io/badge/واجهة-عربية%20RTL-38BDF8)
![Python](https://img.shields.io/badge/Python-3.12-3776AB)
![FastAPI](https://img.shields.io/badge/FastAPI-async-009688)
![React](https://img.shields.io/badge/React-19-61DAFB)
![License](https://img.shields.io/badge/License-Proprietary-1E293B)

</div>

---

## 🇪🇬 نظرة عامة

**راصد** مش مجرد ماسح للـ IP. ده نظام متكامل بيدّيك **صورة كاملة وحيّة** للشبكة اللي بتملكها وبتديرها: مين متصل، إيه الأجهزة، إيه الخدمات المفتوحة، فين نقاط الضعف، ومين خارج عن السياسة — وكل ده **من غير أي اتصال بالإنترنت**، وبواجهة **عربية من اليمين لليسار** مصمّمة إنها تبقى سهلة وواضحة.

الفكرة الأساسية اللي راصد مبني عليها: **ما بيشتغلش كأداة هجوم أبداً.** بيتحكم في الأجهزة ويقرأ منها **عبر القنوات الشرعية الموثّقة فقط** (SSH / WinRM / SNMP / LDAP بحسابات مُصرّح بها ومحفوظة في خزنة مُعمّاة). **مفيش استغلال لمنافذ، ولا تجاوز لمصادقة، ولا تخمين كلمات مرور، ولا حجب خدمة، ولا تخفّي.** أداة مدير شبكة محترفة — مش أداة اختراق.

> راصد اتبنى عشان يقف جنب أقوى الأدوات في مجاله، بس بميزة ما حدش بيوفّرها بالشكل ده: **عربي بالكامل، يعمل أوفلاين تماماً، وآمن بحكم التصميم.**

## 🌍 Overview

**RasedNet** is a complete, living picture of the LAN you own and operate: who is connected, what the devices are, which services are exposed, where the weaknesses are, and what drifts from policy — **fully offline**, behind a polished **Arabic RTL** interface (with a full English mode).

Its founding principle: **it never acts as an attack tool.** It controls and queries devices **only through legitimate, authenticated channels** (SSH / WinRM / SNMP / LDAP, using authorized accounts kept in an encrypted vault). **No port exploitation, no authentication bypass, no credential guessing, no denial-of-service, no stealth/evasion.** A professional network-administration platform — not an offensive tool.

---

## ✨ المميزات · Features

### 🔍 الاكتشاف والتعرّف · Discovery & Identification
- محرّك مسح أصلي على مرحلتين (ICMP/ARP عبر Windows IP Helper، اتصال TCP، DNS عكسي، NetBIOS، SSDP/UPnP، قراءة التوقيعات، بيانات شهادات TLS، traceroute).
- فحص **UDP** نشِط، وتصفّح مشاركات **SMB** العامة بلا مصادقة (بدون إرسال أي بيانات دخول).
- تعرّف قائم على الأدلّة: سجلّ **IEEE OUI** (أكثر من 40 ألف مُصنِّع)، بصمات الأجهزة، بصمة الويب (favicon hash)، و**SNMP sysObjectID**.
- جرد ذكي مع **كشف التغيّرات** وربط الهوية، وإضافة يدوية للأجهزة.

### 🗺️ الخرائط والتحليلات · Maps & Analytics
- خريطة شبكة منطقية تفاعلية (Cytoscape): تجميع، أوضاع ألوان، إبراز المسارات، الجيران، تخطيطات محفوظة.
- خريطة **فيزيائية** عبر SNMP/LLDP/CDP وجداول الجسور (FDB).
- جداول **Fusion** التحليلية + رسوم ECharts.

### 🛡️ الأمن والامتثال · Security & Compliance
- محرّك **ثغرات/CVE** أوفلاين مع ترتيب أولويات عبر **EPSS + CISA KEV**.
- **خرائط امتثال**: NCA ECC / ISO 27001 / PCI-DSS مع فحوص آلية ودرجات.
- **خطّ أساس للخدمات المعتمدة** وكشف الأجهزة/البوابات المارقة.
- استخبارات **Active Directory** (قراءة فقط عبر LDAP) وتحليل **مسارات الهجوم**.

### 🔧 التحكّم والتكامل · Control & Integration
- **خزنة بيانات اعتماد** (Fernet) وتنفيذ أوامر عن بُعد عبر **WinRM** و**SSH** (تثبيت مفتاح المضيف) — كل ده مُدقَّق.
- لوحة **تحكّم بأجهزة الشبكة/الراوترات** (RouterOS/Cisco/Linux) بتحقق صارم من المدخلات.
- **وكيل طرفي** و**مُجمِّعات موزّعة** لاكتشاف المقاطع المعزولة عبر HTTPS.
- **مستوردات**: Nmap / DHCP / CSV / Greenbone / Nessus / Wazuh / osquery.

### 📊 التقارير والتشغيل · Reporting & Operations
- تقارير عربية شاملة (**PDF / Excel / JSON**) بتكامل **SHA-256**.
- تحكّم كامل بالمسح: ملفات فحص، جدولة، استئناف تلقائي للمسح المتوقّف، إعادة فحص جهاز واحد.
- **نوافذ صيانة** + تنبيهات **بريد SMTP** مع تصعيد.
- تشخيص «**ليه الجهاز مش ظاهر؟**» بإجابة عملية قابلة للتنفيذ.

---

## 🔐 الأمان بحكم التصميم · Security by Design

| الطبقة | التفاصيل |
|---|---|
| كلمات المرور | **Argon2id**، وسياسة قوية، وأدمن افتراضي **يُجبَر على التغيير عند أول دخول** |
| الجلسات | من جهة الخادم، رموز عشوائية، **CSRF**، وانتهاء خمول/مُطلَق |
| الصلاحيات | **RBAC** (مدير / مشغّل / مدقّق) + **سجلّ تدقيق** لكل عملية |
| الحدود | اعتماد النطاقات قبل المسح، تحديد معدّل الطلبات، والربط على `127.0.0.1` افتراضياً |
| التقوية | **CSP**، `nosniff`، `X-Frame-Options: DENY`، **HSTS**، وتعطيل واجهات التوثيق الخارجية |
| الأسرار | خزنة مُعمّاة؛ ولا أسرار في الكود؛ و`.env` مُستبعد من المستودع |

**أخلاقيات الاستخدام:** راصد للشبكات اللي **تملكها وتُصرّح بإدارتها**. يعمل عبر قنوات الإدارة الشرعية فقط، ولا يُستخدَم لأي نشاط هجومي.

> **Authorized use only.** RasedNet is for networks you **own and are authorized to administer**. It works exclusively through legitimate administrative channels and must not be used for any offensive activity.

---

## 🧱 البنية التقنية · Tech Stack

| | |
|---|---|
| **Backend** | Python 3.12 · FastAPI · SQLAlchemy 2.0 · Alembic · PostgreSQL 17 |
| **Frontend** | React 19 · TypeScript · Vite · Tailwind CSS 4 · TanStack Query/Table · ECharts · Cytoscape.js · خط Cairo (مضمّن) |
| **Scanning** | محرّك أصلي: مسح على مرحلتين، ICMP/ARP عبر Windows IP Helper، TCP، DNS عكسي، NetBIOS، SSDP/UPnP، banners، TLS، traceroute، UDP |
| **i18n** | ثنائي اللغة بالكامل (عربي/إنجليزي) — الواجهة **ومحتوى الخادم** (الأخطاء، التقارير، الأدلّة) |

---

## 🚀 التشغيل السريع · Quick Start

```powershell
# 1) قاعدة بيانات PostgreSQL (أي نسخة يمكن الوصول إليها، مثلاً حاوية محلية)
docker run -d --name rasednet-db -e POSTGRES_USER=rasednet -e POSTGRES_PASSWORD=<pw> -e POSTGRES_DB=rasednet -p 127.0.0.1:5432:5432 postgres:17-alpine

# 2) الخادم
cd backend
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock
copy .env.example .env          # عدّل RASEDNET_DATABASE_URL ، واضبط RASEDNET_COOKIE_SECURE=false للتطوير على HTTP
.venv\Scripts\python -m rasednet init-db
#   init-db يُنشئ مسؤولاً قياسياً:  admin / RasedNet@2026  (يُجبَر على تغيير كلمة المرور عند أول دخول)

# 3) الواجهة
cd ..\frontend
npm ci && npm run build

# 4) التشغيل
cd ..\backend
.venv\Scripts\python -m rasednet serve --port 8765
```

للإنتاج: اضبط `RASEDNET_SECRET_KEY` قوياً (`python -m rasednet gen-secret-key`)، وقدّم الخدمة عبر **HTTPS**، واضبط `RASEDNET_COOKIE_SECURE=true`. التفاصيل الكاملة في [`docs/ar/`](docs/ar/).

---

## 🧭 أوامر الإدارة · CLI

```
python -m rasednet init-db            # تطبيق الهجرات + زرع البيانات المرجعية + المسؤول القياسي
python -m rasednet create-admin ...   # إنشاء مسؤول إضافي باسم محدّد
python -m rasednet gen-secret-key     # توليد مفتاح خزنة بيانات الاعتماد
python -m rasednet gen-cert ...       # شهادة TLS موقّعة ذاتياً
python -m rasednet serve ...          # تشغيل الخادم (عملية واحدة)
```

---

## 📂 البنية · Layout

```
backend/rasednet/     حزمة التطبيق (API, discovery, security, migrations, …)
frontend/             واجهة React (تُبنى وتُقدَّم من الخادم)
scripts/              PowerShell: إعداد، تشغيل، خدمة، نسخ احتياطي، ترقية، تراجع
docs/                 المعمارية، نموذج التهديد، ودليل المسؤول بالعربية
```

---

## 📜 الرخصة · License

برنامج احتكاري (Proprietary). جميع الحقوق محفوظة — **Eslam Shoaib**. انظر [`LICENSE`](LICENSE).

<div align="center">

**راصد · RasedNet** — شبكتك، تحت عينك، وبأمان. 🛡️

</div>
