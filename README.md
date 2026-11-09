# 🛡️ AdGuard Web — Open-Source Cloud DNS-over-HTTPS AdBlock Engine

> **Created & Engineered by Veer Bhanushali**  
> *A 100% web-native, zero-root, serverless-ready DNS-over-HTTPS (DoH) engine with real-time ad-blocking, multi-device routing, and an official AdGuard Home-grade dashboard.*

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-14_App_Router-black)](https://nextjs.org/)
[![DoH](https://img.shields.io/badge/RFC_8484-Compliant-blue)](https://tools.ietf.org/html/rfc8484)
[![Author](https://img.shields.io/badge/Author-Veer_Bhanushali-green)](#author)

---

## 🌟 Why AdGuard Web?

Traditional DNS sinkholes like Pi-hole and AdGuard Home require **root access on Port 53 UDP** and cannot be hosted on serverless platforms or shared web hosting (like Hostinger WebApp plans or Vercel).

**AdGuard Web solves this completely:**
* **Runs on Port 443 / HTTPS**: Works on any web hosting plan, Vercel, Hostinger Node.js, Cloudflare, or local PC.
* **Public & Multi-Device Subdomain Routing**: Anyone can connect their phone, laptop, or smart TV using unique client endpoints (e.g. `https://yourdomain.com/dns-query/my-phone`).
* **100% Free Cloud Tier**: Supports **Upstash Redis** (caching) and **Supabase PostgreSQL** (query logging) with a zero-setup local RAM fallback.
* **Universal Rule Converter**: 1-click conversion between Hosts files, ABP syntax, plain domains, and AdGuard syntax (`||domain.com^`).
* **1-Click iOS & Android Profiles**: Native `.mobileconfig` downloads for iPhone and instant DoH links for Android.

---

## 🚀 Quick Start

### 1. Local Development
```bash
cd adguard-web
npm install
npm run dev
```
Open [http://localhost:3001](http://localhost:3001) to access the dashboard.

### 2. Connect Your Devices

| Device | Setup Method | Endpoint |
| :--- | :--- | :--- |
| **iPhone / iPad** | Download 1-Click Profile from Dashboard | `https://yourdomain.com/api/mobileconfig` |
| **Android** | In **Intra** or **RethinkDNS** app | `https://yourdomain.com/dns-query/android` |
| **Chrome / Brave / Edge** | Settings → Privacy → Use Secure DNS | `https://yourdomain.com/dns-query/browser` |
| **Firefox** | Settings → Network Settings → Enable DNS over HTTPS | `https://yourdomain.com/dns-query` |

---

## ☁️ 100% Free Cloud Integration (Optional)

Add these to your `.env.local` or host environment variables:

```env
# Upstash Redis (Free Caching Tier - 10,000 requests/day)
UPSTASH_REDIS_REST_URL="https://your-upstash-redis.upstash.io"
UPSTASH_REDIS_REST_TOKEN="your-token"

# Supabase (Free Database Tier - 500 MB Postgres)
NEXT_PUBLIC_SUPABASE_URL="https://your-supabase-project.supabase.co"
NEXT_PUBLIC_SUPABASE_ANON_KEY="your-anon-key"
```
*If left blank, AdGuard Web automatically runs with built-in high-speed in-memory RAM caching and local storage!*

---

## 📜 License & Copyright

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

```
Copyright (c) 2026 Veer Bhanushali
All rights reserved.
```

