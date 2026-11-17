# XopProtector جديد بالكامل تحت إدارة Cosmos

**الحالة:** ملفات البناء والخدمة جاهزة على GitHub. لا يوجد نشر فعلي على VPS حتى الآن.

## ما الذي بُني؟

- مصدر XopProtector الرسمي فقط، مثبت على commit `347f20717e32d9d93d081d00c27d91ce75bd84be`.
- مهمة GitHub Actions تبني Java Packer ومكتبات Android Native خارج VPS.
- خدمة Python مستقلة لمعالجة APK وواجهة API للمتابعة والتنزيل.
- إعداد Docker Compose لاستيراده بوصفه ServApp جديداً إلى Cosmos.
- لا تُستخدم ملفات XOP القديمة أو مفاتيح V4 أو قواعد بياناته أو إعدادات الأدمن.

## خطوات التنفيذ

1. ادخل GitHub ثم Actions ثم **Build official XopProtector for Cosmos**.
2. اختر **Run workflow** على الفرع main.
3. لا تنتقل إلى Cosmos إلا بعد نجاح جميع مراحل البناء ونشر صورة GHCR.
4. استخرج عنوان صورة Docker المطابق لنفس commit من GitHub Packages.
5. افتح Cosmos > ServApps > Import Docker Compose، واستورد ملف `compose.cosmos.yaml` بوصفه خدمة جديدة.
6. أدخل `XOP_IMAGE` وصلاحية سحب GHCR إذا لزم، وأنشئ قيمة خاصة لـ `XOP_API_TOKEN` بطول 32 حرفاً على الأقل. لا ترفعها إلى GitHub ولا تضعها في تطبيق Android.
7. تأكد من أن الخدمة Running وHealthy داخل Cosmos قبل تجربة أي تطبيق.

**مهم:** لا تعدّل أو تستبدل `lodinlas` أو MongoDB أو مستخدمي V4 أو الأدمن الرئيسي والفرعي. الخدمة القديمة لا تزال كما هي. لم يتم تنفيذ ربط Matrix الجديد بعد.

لا تعتبر نجاح بناء صورة Docker دليلاً على نجاح الحماية، ويجب إجراء اختبار APK فعلي وتوقيعه وتشغيله على هاتف Android.
