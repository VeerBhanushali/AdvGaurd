# 🛡️ AdvGuard — Cloud DNS-over-HTTPS AdBlock Engine & Firewall

> **Created & Engineered by Veer Bhanushali**  
> *A 100% web-native, zero-root, serverless-ready DNS-over-HTTPS (DoH) engine with real-time ad-blocking, smart firewall, zero-PII privacy protection, and an authentic AdGuard Home-grade dashboard.*

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-14_App_Router-black)](https://nextjs.org/)
[![Database](https://img.shields.io/badge/Database-Supabase_PostgreSQL-green)](https://supabase.com)
[![Firebase](https://img.shields.io/badge/Firebase-Firestore_Supported-orange)](https://firebase.google.com/)
[![DoH](https://img.shields.io/badge/RFC_8484-Compliant-blue)](https://tools.ietf.org/html/rfc8484)
[![Author](https://img.shields.io/badge/Author-Veer_Bhanushali-green)](#author)

---

## 🌟 Key Features

* **Runs on Port 443 / HTTPS**: No root privileges or raw UDP port 53 required. Deployable on **Hostinger WebApp (Node.js)**, **Vercel**, or your local PC.
* **Public Service vs. Self-Hosted Security**:
  * **Public Cloud (`advgaurd.veerbhanushali.com`)**: Fortified with **Zero-PII IP Anonymization** (GDPR compliant), automated **30-day log purges**, and strict **anti-DDoS rate limiting** so users' browsing habits are completely private.
  * **Self-Hosted Edition**: Full local network controls (`192.168.1.xxx`), device tagging, and custom rule enforcement.
* **Dual Database Support**:
  * **Supabase (PostgreSQL)**: Instant SQL schema setup via [`supabase-schema.sql`](supabase-schema.sql), unlimited reads/writes, time-series query analytics.
  * **Google Firebase (Firestore)**: Zero SQL setup; collections auto-create dynamically.
  * **Built-in In-Memory LRU Cache**: 0.01ms response time, zero external calls for repeated queries.
* **Smart DNS Firewall (Killer Feature)**:
  * Blocks AI scrapers (OpenAI, Anthropic, Common Crawl, Perplexity).
  * Blocks Cryptominers (Coinhive, CryptoLoot, WebMinePool).
  * Automatically blocks malicious Spam TLDs (`.top`, `.work`, `.click`, `.buzz`, `.cfd`, `.loan`, `.gdn`, etc.).
* **Authentic AdGuard Home Dashboard**: 4-Card KPI metrics, 24-hour activity chart, 2x2 statistics grid, and 1-click **Blocked Services** (TikTok, Discord, YouTube, Facebook, WhatsApp, etc.).
* **Multi-Device / Client Routing**: Individual tokenized DoH endpoints (`https://yourdomain.com/dns-query/[clientId]`).
* **1-Click Apple iOS `.mobileconfig` Profile**: Direct download for iPhones and iPads.

---

## 🔒 Security & Privacy First

1. **Zero Raw IP Storage**: On public instances, all incoming client IPs are automatically masked (`103.21.244.78` &rarr; `103.21.244.xxx`).
2. **Automated 30-Day Purge**: DNS queries older than 30 days are automatically deleted by the database background worker.
3. **Strict Git Hygiene**: Secrets, tokens, and `.env.local` files are strictly ignored by `.gitignore`. Never push API keys or database credentials to GitHub. See [`SECURITY.md`](SECURITY.md) for details.

---

## 🚀 Quick Setup (Self-Hosted)

### 1. Database Setup (Choose Supabase or Firebase)

#### Option A: Supabase (Recommended)
1. Create a free project at [supabase.com](https://supabase.com).
2. Open **SQL Editor** in your Supabase dashboard.
3. Copy [`supabase-schema.sql`](supabase-schema.sql), paste it, and click **Run**.
4. Copy your **Project URL** and **Anon Key** from *Settings → API* into `.env.local`:
   ```env
   NEXT_PUBLIC_SUPABASE_URL="https://your-project.supabase.co"
   NEXT_PUBLIC_SUPABASE_ANON_KEY="your-anon-key"
   ANONYMIZE_IPS="true"
   LOG_RETENTION_DAYS="30"
   ```

#### Option B: Firebase (Zero-SQL Setup)
1. Create a project at [console.firebase.google.com](https://console.firebase.google.com).
2. Enable Firestore Database and copy your Web App credentials into `.env.local`.

---

### 2. Run the Application
```bash
npm install
npm run build
npm start
```
Open [http://localhost:3001](http://localhost:3001) in your browser.

---

## 📱 Connect Your Devices

| Device | Setup Method | Endpoint URL |
| :--- | :--- | :--- |
| **iPhone / iPad** | Download 1-Click Profile from Dashboard | `https://advgaurd.veerbhanushali.com/api/mobileconfig` |
| **Android** | Settings &rarr; Private DNS | `advgaurd.veerbhanushali.com` |
| **Chrome / Brave / Edge** | Settings &rarr; Privacy &amp; Security &rarr; Use Secure DNS | `https://advgaurd.veerbhanushali.com/dns-query` |
| **Firefox** | Settings &rarr; Network Settings &rarr; Enable DNS over HTTPS | `https://advgaurd.veerbhanushali.com/dns-query` |
| **Custom Device Tag** | Individual Token Route | `https://advgaurd.veerbhanushali.com/dns-query/[token]` |

---

## 📜 License & Copyright

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

```
Copyright (c) 2026 Veer Bhanushali
All rights reserved.
```
