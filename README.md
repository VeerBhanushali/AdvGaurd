# 🛡️ AdvGuard — Cloud DNS-over-HTTPS AdBlock Engine

> **Created & Engineered by Veer Bhanushali**  
> *A 100% web-native, zero-root, serverless-ready DNS-over-HTTPS (DoH) engine with real-time ad-blocking, multi-device routing, and an authentic AdGuard Home-grade dashboard.*

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-14_App_Router-black)](https://nextjs.org/)
[![Database](https://img.shields.io/badge/Database-Supabase_PostgreSQL-green)](https://supabase.com)
[![DoH](https://img.shields.io/badge/RFC_8484-Compliant-blue)](https://tools.ietf.org/html/rfc8484)
[![Author](https://img.shields.io/badge/Author-Veer_Bhanushali-green)](#author)

---

## 🌟 Features

* **Runs on Port 443 / HTTPS**: No root privileges or raw UDP port 53 required. Runs on **Hostinger WebApp (Node.js)**, **Vercel**, or your local PC.
* **Single Database (Supabase)**: Zero Redis needed! One free Supabase PostgreSQL database handles persistent query logging, custom rules, and authentication.
* **1-Click Database Setup**: Simply copy [`supabase-schema.sql`](supabase-schema.sql) and paste it into the Supabase SQL Editor.
* **Authentic AdGuard Home Dashboard**: 4-Card KPI metrics, 24-hour activity chart, 2x2 statistics grid, and 1-click **Blocked Services** (TikTok, Discord, YouTube, Facebook, WhatsApp, etc.).
* **Public & Multi-Device Subdomain Routing**: Connect any device with custom tags (`https://yourdomain.com/dns-query/veer-iphone`).
* **1-Click Apple iOS `.mobileconfig` Profile**: Direct download for iPhones and iPads.

---

## 🚀 Quick Setup

### 1. Database Setup (1 Minute)
1. Create a free project at [supabase.com](https://supabase.com).
2. Open **SQL Editor** in your Supabase dashboard.
3. Open [`supabase-schema.sql`](supabase-schema.sql), copy its entire contents, paste it, and click **Run**.
4. Copy your **Project URL** and **Anon Key** from *Settings → API* into `.env.local`:
   ```env
   NEXT_PUBLIC_SUPABASE_URL="https://your-project.supabase.co"
   NEXT_PUBLIC_SUPABASE_ANON_KEY="your-anon-key"
   ```

### 2. Local Development
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
| **iPhone / iPad** | Download 1-Click Profile from Dashboard | `https://yourdomain.com/api/mobileconfig` |
| **Android** | In **Intra** or **RethinkDNS** app | `https://yourdomain.com/dns-query/android` |
| **Chrome / Brave / Edge** | Settings → Privacy & Security → Use Secure DNS | `https://yourdomain.com/dns-query` |
| **Firefox** | Settings → Network Settings → Enable DNS over HTTPS | `https://yourdomain.com/dns-query` |

---

## 📜 License & Copyright

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

```
Copyright (c) 2026 Veer Bhanushali
All rights reserved.
```
