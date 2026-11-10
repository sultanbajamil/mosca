# Social threads — English and Arabic

## English X/Twitter thread

**1/**
Your adversaries are not waiting for the quantum computer.

They are recording your TLS and SSH traffic today and storing the ciphertext.

That attack is called harvest-now-decrypt-later.

We scanned 68 public endpoints to measure who is already exposed. 🧵

**2/**
The only question that matters is temporal:

If an adversary records this traffic today, when does it become readable?

MOSCA's inequality:

data shelf life + migration lead time > years until a CRQC

When the sum is larger, the recording is already a disclosure in progress.

**3/**
The benchmark result:

• Global QRI: 83.4/100 (A)
• Hybrid PQC adoption: 60.3%
• HNDL exposure at 2033: 41.2%
• 68 of 69 endpoints observed

Readiness is improving. Exposure is not disappearing.

**4/**
Sector spread:

Technology 94.4 (A+)
Cloud 94.3 (A+)
Aviation 92 (A+)
Retail 86.7 (A)
Telecom 86.7 (A)
Finance 80 (A)
Government 77.1 (B)
Healthcare 77.1 (B)
Education 76 (B)
Energy 66.7 (C)

**5/**
The most dangerous row is not the lowest score.

Healthcare and government score 77.1 — respectable until you add a 25-year data lifetime.

57.1% of their observed endpoints are inside the Mosca window at a 2033 CRQC.

A B grade can still be a breach.

**6/**
Most tools answer: "which algorithms do you use?"

The better question: "which recordings are already dangerous?"

New in MOSCA v3.1: `mosca pcap`.

It reads PCAP/PCAPNG, parses TLS and SSH handshakes, and anchors exposure to the CAPTURE date. No packets sent. No auth.

**7/**
Also new:

• `mosca benchmark` — sector readiness, A+–F
• Interactive 2027–2045 CRQC slider
• `--badge` — QRI and HNDL SVGs generated locally
• Zero runtime dependencies, still

npx mosca-pqc scan .
npx mosca-pqc pcap capture.pcap
npx mosca-pqc benchmark --snapshot benchmarks/snapshot.json

**8/**
The benchmark is reproducible: the raw handshake snapshot ships with the repo and CI replays it. The page changes when the evidence changes, not when a CDN rotates a key share.

Report: https://sultanbajamil.github.io/mosca/state-of-pqc.html
Code: https://github.com/sultanbajamil/mosca

**9/**
If you run it on a real estate, I want the false positives more than the nice demo. Open an issue with the file or capture shape.

The migration is measurable. Start measuring.

---

## English LinkedIn post

**41% of publicly reachable endpoints carry data that a 2033 quantum computer could read. Most organisations cannot tell which recordings are already exposed.**

That is the finding from *The State of Post-Quantum Readiness*, a benchmark of 68 endpoints across 10 sectors, published today with MOSCA v3.1.

The mistake most programmes make is treating PQC as an algorithm inventory. The right frame is temporal:

**data shelf life + migration lead time > years until a CRQC**

When that inequality holds, the data is already exposed — because the ciphertext was recorded last Tuesday.

What the benchmark shows:

• Only 60.3% negotiate a post-quantum hybrid key exchange.
• At a 2033 CRQC, 41.2% of observed endpoints are inside the Mosca window.
• Technology leads at 94.4/100 (A+); energy trails at 66.7 (C).
• Healthcare and government score 77.1 (B) — but 57.1% of their endpoints are exposed once you account for a 25-year data lifetime.

A B grade can still be a breach.

MOSCA v3.1 adds two things I think every CISO needs:

1. **Passive capture auditing.** `mosca pcap` reads a PCAP and tells you which recorded TLS/SSH sessions are already dangerous, anchored to the capture date. No packets sent, no authentication.
2. **A replayable sector benchmark.** Not a press-cycle dashboard: the raw snapshot ships with the repo and CI regenerates the page from it.

Still zero runtime dependencies. Still one self-contained HTML report. Still a CBOM, SARIF and a baseline gate that fails only on regressions.

Report: https://sultanbajamil.github.io/mosca/state-of-pqc.html
Code: https://github.com/sultanbajamil/mosca

If your board asks "are we quantum-ready?", the honest answer is a date and an evidence trail. Not a slide.

#PostQuantum #PQC #CyberSecurity #HNDL #CISO #Cryptography

---

## Arabic thread — سلسلة عربية

**1/**
خصومك لا ينتظرون الحاسوب الكمي.

هم يسجّلون حركة TLS وSSH اليوم ويحتفظون بالنص المشفّر.

هذا الهجوم يُسمّى: Harvest Now, Decrypt Later — سجّل الآن، وفكّ التشفير لاحقًا.

فحصنا 68 نقطة نهاية عامة لقياس من هو مكشوف بالفعل. 🧵

**2/**
السؤال الوحيد المهم هو سؤال زمني:

إذا سجّل خصم هذه الحركة اليوم، فمتى تصبح قابلة للقراءة؟

متباينة MOSCA:

عمر البيانات السرّي + زمن الهجرة > السنوات المتبقية حتى الحاسوب الكمي

عندما يكون المجموع أكبر، فالتسجيل أصبح كشفًا جاريًا.

**3/**
نتيجة المقياس:

• مؤشر الجاهزية العالمي: 83.4/100 (A)
• تبنّي التشفير الهجين: 60.3%
• التعرّض لـ HNDL بحلول 2033: 41.2%
• 68 من 69 نقطة نهاية تم رصدها

الجاهزية تتحسّن. لكن التعرّض لا يختفي.

**4/**
الفجوة بين القطاعات:

التقنية 94.4 (A+)
السحابة 94.3 (A+)
الطيران 92 (A+)
التجزئة 86.7 (A)
الاتصالات 86.7 (A)
المال 80 (A)
الحكومة 77.1 (B)
الصحة 77.1 (B)
التعليم 76 (B)
الطاقة 66.7 (C)

**5/**
أخطر صف ليس أدنى درجة.

الصحة والحكومة تحصلان على 77.1 — درجة محترمة حتى تضيف عمر بيانات 25 سنة.

57.1% من نقاط النهاية المرصودة داخل نافذة MOSCA بحلول 2033.

درجة B قد تعني اختراقًا.

**6/**
معظم الأدوات تسأل: "أي خوارزميات تستخدم؟"

السؤال الأفضل: "أي تسجيلات أصبحت خطرة بالفعل؟"

الجديد في MOSCA v3.1: الأمر `mosca pcap`.

يقرأ ملفات PCAP/PCAPNG، ويحلّل مصافحات TLS وSSH، ويربط التعرّض بتاريخ التسجيل نفسه. دون إرسال أي حزمة ودون مصادقة.

**7/**
جديد أيضًا:

• `mosca benchmark` — جاهزية القطاعات بدرجات A+ حتى F
• صفحة تفاعلية بشريط CRQC من 2027 إلى 2045
• `--badge` — شارات QRI وHNDL تُولَّد محليًا
• صفر اعتماديات وقت التشغيل، كما هو الحال دائمًا

npx mosca-pqc scan .
npx mosca-pqc pcap capture.pcap
npx mosca-pqc benchmark --snapshot benchmarks/snapshot.json

**8/**
المقياس قابل لإعادة الإنتاج: لقطة المصافحات الخام مرفقة بالمستودع، وCI يعيد توليد الصفحة منها. تتغيّر الأرقام عندما تتغيّر الأدلة، لا عندما يتغيّر مزوّد الخدمة.

التقرير: https://sultanbajamil.github.io/mosca/state-of-pqc.html
الكود: https://github.com/sultanbajamil/mosca

**9/**
إذا شغّلته على بيئة حقيقية، أريد الإيجابيات الكاذبة أكثر من العرض الجميل. افتح issue مع شكل الملف أو الحزمة.

الهجرة قابلة للقياس. ابدأ بالقياس.

#الأمن_السيبراني #التشفير #ما_بعد_الكم #PQC #HNDL
