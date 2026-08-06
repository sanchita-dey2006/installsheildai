# 📄 Member 4 Documentation — Local AI Decision Engine & PDF Report Generator

**Assigned Module**: Offline AI Intelligence Pipeline, Risk Scoring, Threat Classification & PDF Generation  
**Core Files**: [`ai/engine.py`](file:///home/lakshyniti/Desktop/installsheildai-main/ai/engine.py), [`ai/scoring.py`](file:///home/lakshyniti/Desktop/installsheildai-main/ai/scoring.py), [`ai/classification.py`](file:///home/lakshyniti/Desktop/installsheildai-main/ai/classification.py), [`ai/recommendation.py`](file:///home/lakshyniti/Desktop/installsheildai-main/ai/recommendation.py), [`ai/explanation.py`](file:///home/lakshyniti/Desktop/installsheildai-main/ai/explanation.py), [`ai/pdf_generator.py`](file:///home/lakshyniti/Desktop/installsheildai-main/ai/pdf_generator.py)

---

## 📌 ১. প্রাথমিক কাজ (Original Scope & Tasks)

Member 4 এর মূল কাজ ছিল স্ট্যাটিক এনালাইসিস থেকে প্রাপ্ত সমস্ত মেট্রিক্স (হ্যাশ, সিগনেচার স্ট্যাটাস, এন্ট্রপি, স্ট্রিং) ব্যবহার করে একটি AI রিস্ক স্কোরার তৈরি করা, ম্যালওয়্যার থ্রেট ক্লাসিফাই করা এবং এক্সপোর্ট করার উপযোগী PDF রিপোর্ট তৈরি করা।

* **Risk Scoring Algorithm (`ai/scoring.py`)**: 0–100 থ্রেট ইনডেক্স হিসাব করা।
* **Threat Classifier (`ai/classification.py`)**: ফাইলটিকে Ransomware, Backdoor, Dropper, Packed Executable, PUP, অথবা Trusted Software হিসেবে শ্রেণিবিভাগ করা।
* **Explainable AI (XAI) & Actionable Guidance (`ai/explanation.py` & `ai/recommendation.py`)**: মানব-পাঠযোগ্য নিরাপত্তা বিবরণী এবং অ্যাকশনেবল পরামর্শ তৈরি করা।
* **PDF Report Generator (`ai/pdf_generator.py`)**: স্ক্যান রেজাল্টকে প্রাতিষ্ঠানিক PDF রিপোর্টে রূপান্তর করা।

---

## 🔄 ২. পরবর্তীতে কি কি পরিবর্তন করা হয়েছে এবং কেন (Changes Made & Technical Rationale)

### 🔹 পরিবর্তন ১: 100% Offline Local AI Architecture Design
* **সমস্যা**: বহিঃস্থ কোনো থার্ড-পার্টি AI API (যেমন OpenAI/Gemini Cloud API) ব্যবহার করলে ফাইল স্ক্যান করতে ইন্টারনেট সংযোগ আবশ্যক হয়ে পড়ত এবং ইউজারের সংবেদনশীল ফাইলের ডাটা ক্লাউডে পাঠানোর সিকিউরিটি ও প্রাইভেসি ঝুঁকি থাকত।
* **সমাধান & কেন করা হয়েছে**: সম্পূর্ণ প্রজেক্টকে ১০০% অফলাইন ও স্থানীয় (Local Engine) ডিসিশন ফেসাদে রূপান্তর করা হয়েছে।
  * `ai/engine.py`: সকল AI মেথডকে একটি ইউনিফাইড ফেসাডে নিয়ে আসা হয়েছে।
  * `ai/scoring.py`: ওয়াটেড ড্যাশবোর্ড ইনডেক্স তৈরি করে (ডিজিটাল সিগনেচার ট্রাস্ট, এন্ট্রপি স্পাইক, মেমোরি ইনজেকশন এপিআই, সি২ ইউআরএল সমন্বয়ে)।
  * জিরো এক্সটার্নাল এপিআই কল — ইন্টারনেট ছাড়াও স্ক্যান শতভাগ সফল হয়।

### 🔹 পরিবর্তন ২: ReportLab 2-Pass Vector PDF Report Generator with Read-Only `/tmp` Fallback
* **সমস্যা**: প্রাথমিক অবস্থায় জেনারেট হওয়া PDF গুলোর পেজ নম্বর বা ডিজাইন লেআউট স্ট্যান্ডার্ড ছিল না। পাশাপাশি Vercel এর মতো সার্ভারলেস এনভায়রনমেন্টে ডিস্ক রিড-ওনলি থাকায় আউটপুট ফাইল পাথ তৈরি করতে গেলে `PermissionError` আসত।
* **সমাধান & কেন করা হয়েছে**: ReportLab 5.0 ব্যবহার করে ২-পাস `NumberedCanvas` চালিত প্রাতিষ্ঠানিক সিকিউরিটি রিপোর্ট তৈরি করা হয়েছে। যদি টার্গেট আউটপুট ডিরেক্টরি রিড-ওনলি হয়, `ai/pdf_generator.py` স্বয়ংক্রিয়ভাবে `/tmp/InstallShield_AI_Report_#.pdf` ডাউনলোডে ফলব্যাক করে।
  * **Executive Summary Box**: Scan ID, Timestamp, Risk Score Gauge ($0–100$), Threat Category, Threat Tier.
  * **Hash Signatures Table**: MD5, SHA-1, SHA-256.
  * **Authenticode & Entropy Metrics**: সিগনেচার পাবলিশার হোয়াইটলিস্ট স্ট্যাটাস এবং বাইনারি এন্ট্রপি অবফাসকেশন।
  * **Explainable AI & Recommendations Card**: মানব-পাঠযোগ্য রিস্ক ট্রিগার এবং অ্যাকশনেবল গাইডেন্স।

### 🔹 পরিবর্তন ৩: Direct Vector PDF Download Handler in UI (Fixing `window.print()`)
* **সমস্যা**: ফ্রন্টএন্ড UI তে "Download PDF Report" বাটনে ক্লিক করলে পূর্বে ব্রাউজারের `window.print()` কল হতো, যার ফলে ওয়েবসাইটের বাজে স্ক্রিনশট প্রিন্ট হতো, কোনো আসল PDF রিপোর্ট ডাউনলোড হতো না।
* **সমাধান & কেন করা হয়েছে**: `app.js` তে `setupPdfModal()` আপডেট করে সরাসরি ব্যাকএন্ড এন্ডপয়েন্ট `/api/scans/<id>/report` এবং `/api/scans/latest/report` এর সাথে কানেক্ট করা হয়েছে। এখন ইউজার বাটনে ক্লিক করা মাত্র ব্যাকএন্ড থেকে জেনারেট হওয়া আসল ভেক্টর `.pdf` ফাইল ডাউনলোডে প্রম্পট করে।

---

## 📊 ৩. ফাইনাল আউটপুট ও ইম্প্যাক্ট (Final Output & Metrics)

1. **100% Privacy & Offline Capability**: প্রজেক্ট সম্পূর্ণ অফলাইন, কোনো ডাটা লোকাল মেশিন ছাড়ে না।
2. **Accurate Risk Scoring**: ০-১০০ ইনডেক্স স্কেলে সঠিক থ্রেট ডিটেকশন ও ক্লাসিফিকেশন।
3. **High-Resolution Vector PDF Download**: সুন্দর লেআউটে ভেক্টর PDF ফাইল লোকাল এবং Vercel সার্ভারলেস এনভায়রনমেন্ট উভয় জায়গায় সরাসরি ডাউনলোড হয়।
