# 📄 Member 1 Documentation — Backend Engine & Server Infrastructure

**Assigned Module**: Backend Controller, File Upload Routing & Database Layer  
**Core Files**: [`analysis/app.py`](file:///home/lakshyniti/Desktop/installsheildai-main/analysis/app.py), [`analysis/db.py`](file:///home/lakshyniti/Desktop/installsheildai-main/analysis/db.py), [`analysis/operations.py`](file:///home/lakshyniti/Desktop/installsheildai-main/analysis/operations.py)

---

## 📌 ১. প্রাথমিক কাজ (Original Scope & Tasks)

Member 1 এর দায়িত্ব ছিল ব্যাকএন্ড ওয়েব সার্ভার তৈরি করা, ফাইল আপলোড রুট হ্যান্ডেল করা, SQLite ডাটাবেজ স্কিমা ডিজাইন করা এবং স্ক্যান হিস্ট্রি ডাটাবেজে পারসিস্ট করা।

* **Flask Controller Setup**: `analysis/app.py` তে Flask এপ্লিকেশন ইনিশিয়ালাইজ করা এবং static/templates রুট কানেক্ট করা।
* **File Upload Handling (`POST /upload`)**: ক্লায়েন্ট থেকে আসা ফাইল রিসিভ করা এবং ডিস্কে সংসংরক্ষণ করা (`uploads/` ডিরেক্টরি)।
* **Basic SQLite Operations**: `database/scanner.db` তে প্রাথমিক স্ক্যান হিস্ট্রি টেবিলে আইডি, ফাইলের নাম, পাথ এবং আপলোড টাইম সংরক্ষণ করা।

---

## 🔄 ২. পরবর্তীতে কি কি পরিবর্তন করা হয়েছে এবং কেন (Changes Made & Technical Rationale)

### 🔹 পরিবর্তন ১: Hard-Blocking Upload Gatekeeper অপসারণ ও Universal Upload Pipeline
* **সমস্যা**: পূর্বে `is_pe_executable()` ফাইল আপলোডের আগেই প্রথম ৮ বাইট চেক করত। যদি কোনো ইউজার শূন্য-বাইট ফাইল, ডামি `.exe` ফাইল, অথবা নন-স্ট্যান্ডার্ড বাইনারি আপলোড করার চেষ্টা করত, অ্যাপ সার্ভার upfront HTTP 400 / 415 error রিটার্ন করত এবং ব্রাউজারে বার বার `"Malformed upload error"` নোটিফিকেশন আসত।
* **সমাধান & কেন করা হয়েছে**: VirusTotal বা Enterprise Malware Analysis স্যুইটের মতো আপলোড প্রসেসকে নন-ব্লকিং করা হয়েছে। যেকোনো ফাইল সাবমিশন আপলোড হিসেবে গ্রহণ করা হয় এবং ফাইলটিতে হেডার অ্যানোমালি থাকলে AI Scoring Engine রিপোর্টে warning flag যোগ করে।
* **কোড পরিবর্তন**: `analysis/app.py` তে `is_pe_executable` এর ব্লকিং `return jsonify({"error": ...}), 400` লাইন অপসারণ করা হয়েছে।

### 🔹 পরিবর্তন ২: SQLite Database Schema Auto-Migration System
* **সমস্যা**: ডাটাবেজে কেবল আইডি, ফাইলের নাম, ফাইল পাথ ও আপলোড টাইম সংরক্ষিত হতো। ক্রিপ্টোগ্রাফিক হ্যাশ (MD5, SHA1, SHA256), এনট্রপি (Entropy), ডিজিটাল সিগনেচার স্ট্যাটাস, ট্রাস্টেড পাবলিশার এবং AI রিস্ক স্কোর রাখার কলাম ছিল না।
* **সমাধান & কেন করা হয়েছে**: `analysis/db.py` তে স্বয়ংক্রিয় কলাম মাইগ্রেশন স্ক্রিপ্ট যুক্ত করা হয়েছে। অ্যাপ্লিকেশন চালুর সাথে সাথে যদি কলামগুলো অনুপস্থিত থাকে, SQLite `ALTER TABLE` কমান্ডের মাধ্যমে ডাটাবেজ ক্র্যাশ করা ছাড়াই কলামগুলো যুক্ত করে নেয়।
* **কোড পরিবর্তন**:
  ```python
  required_columns = {
      "md5": "TEXT", "sha1": "TEXT", "sha256": "TEXT",
      "entropy": "REAL", "entropy_verdict": "TEXT",
      "signature_status": "TEXT", "publisher": "TEXT",
      "is_trusted": "INTEGER", "risk_score": "INTEGER", "threat_level": "TEXT"
  }
  ```

### 🔹 পরিবর্তন ৩: Complete REST API Endpoints Integration
* **সমস্যা**: ফ্রন্টএন্ড UI কেবল HTML পৃষ্ঠা রেন্ডার করত, যার ফলে হিস্ট্রি ডাটা রিয়েল-টাইমে আপডেট করা বা ডাটাবেজ রেকর্ড ডিলিট করার কোনো সুবিধা ছিল না।
* **সমাধান & কেন করা হয়েছে**: ব্যাকএন্ডে JSON REST API এন্ডপয়েন্ট যোগ করা হয়েছে:
  * `GET /api/scans`: ডাটাবেজ থেকে সমস্ত স্ক্যান হিস্ট্রি JSON ফরম্যাটে ব্যাকএন্ড থেকে রিটার্ন করে।
  * `GET /api/scans/<id>`: নির্দিষ্ট স্ক্যানের সম্পুর্ণ ডিটেইলস নিয়ে আসে।
  * `DELETE /api/scans`: ডাটাবেজের সমস্ত টেস্ট হিস্ট্রি ক্লিয়ার করার জন্য।
  * `DELETE /api/scans/<id>`: নির্দিষ্ট সিঙ্গেল রেকর্ড ডিলিট করার জন্য।
  * `GET /api/scans/<id>/report` & `/api/scans/latest/report`: ReportLab ভেক্টর PDF রিপোর্ট তৈরি ও ডাউনলোড করার জন্য।

---

## 📊 ৩. ফাইনাল আউটপুট ও ইম্প্যাক্ট (Final Output & Metrics)

1. **100% Upload Reliability**: যেকোনো ফাইল আপলোড সফলভাবে প্রসেস হয় এবং কোনো ব্লকিং Toast Error আসে না।
2. **Dynamic DB Auto-Migration**: ডাটাবেজ টেবিল আপডেট সম্পূর্ণ অটোমেটিক এবং নিরবচ্ছিন্ন।
3. **Full REST API Support**: ফ্রন্টএন্ড সিঙ্গেল পেজ অ্যাপ্লিকেশন (SPA) এর সাথে ব্যাকএন্ডের রিয়েল-টাইম সিঙ্ক নিশ্চিত করা হয়েছে।
4. **PDF Report Streaming**: সরাসরি ভেক্টর PDF ফাইল জেনারেট হয়ে ডাউনলোড হয়।
