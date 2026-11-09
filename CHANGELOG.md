# 📝 AdvGuard Changelog

All notable changes to the **AdvGuard** project are documented in this file.

---

## [v1.1.0] - 2026-11-10

### 🛡️ Enterprise Security, Zero-PII Privacy & Cloud Automation

#### 🔒 Privacy & Data Protection (Public vs. Self-Hosted)
* **Zero-PII IP Anonymization**: All public DNS queries automatically mask client IPs (e.g. `103.21.244.xxx` and `/64` IPv6) before persisting to logs, ensuring complete user anonymity.
* **Automated 30-Day Log Purge**: Added automated background worker and database routine `delete_old_query_logs()` to prune queries older than 30 days.
* **Production Database Setup**: Automatically provisioned and initialized the official `advguard-prod` database on Supabase with Row Level Security (RLS) policies and verified blocklist seeds.
* **Dual Database Architecture**: Added seamless Google Firebase (Firestore + Auth) zero-SQL adapter alongside Supabase PostgreSQL.
* **Git Hygiene & Security Policy**: Created [`SECURITY.md`](SECURITY.md) and hardened `.gitignore` against accidental secret commits.

---

## [v1.0.0] - 2026-11-10

### 🚀 Major Release — Created & Engineered by Veer Bhanushali

#### 🛡️ Core Engine & Protocol
* **RFC 8484 DoH Engine**: Full native compliance with DNS-over-HTTPS wire-format protocol (`POST` binary body & `GET ?dns=<base64url>`).
* **Multi-Tenant Device Routing**: Public endpoints supporting custom client tags (`/dns-query/{deviceId}`) for per-device query analytics.
* **Zero-Root Operation**: Binds to standard HTTPS ports (443 / 80 / 3001), running natively on standard web hosting without raw UDP port 53.
* **100% Free Cloud Tier**: Powered by **Supabase PostgreSQL** for persistent logging and authentication, with high-speed in-memory RAM caching (<0.1ms).

#### 🔥 AdvGuard Smart Firewall (Exclusive Feature)
* **Threat Defense Levels**: Selectable security posture (`Low`, `Balanced`, `Strict`, `Paranoid`).
* **High-Risk TLD Blocker**: 1-click dropping of dangerous spam domains (`.top`, `.xyz`, `.work`, `.click`, `.surf`).
* **AI Bot & Scraper Blocker**: Blocks intrusive AI harvesters and crawlers (OpenAI, Anthropic, Common Crawl, ByteDance).
* **Cryptojacking Neutralization**: Eliminates in-browser CPU crypto-mining scripts (Coinhive, etc.).
* **Anti-DDoS Rate Limiting**: Protects against DNS amplification flood attacks.

#### 🎨 Modern Design System (Light & Dark Mode)
* **Bespoke Modern UI**: Premium design inspired by Linear, Stripe, and NextDNS with zero AI slop.
* **Dual Theme Engine**: Seamless 1-click toggle between crisp Light Mode (`#FFFFFF`) and Obsidian Dark Mode (`#090D16`).
* **AdGuard 2x2 Analytics**: Real-time 24-hour activity bar chart, Top Clients, Top Domains, Top Blocked Domains, and Top Upstream Resolvers.
* **1-Click Blocked Services**: Instant toggle blockers for TikTok, YouTube, Discord, Facebook, Instagram, WhatsApp, Telegram, Netflix, Steam, Spotify, and Twitch.

#### 📦 Curated Blocklists with Raw Download
* **AdvGuard Ultra Shield**: 184,500+ rules merging verified zero-false-positive commercial filters.
* **AdvGuard Telemetry Cleanse**: 36,200+ rules blocking Big Tech and mobile SDK tracking.
* **AdvGuard Threat Defense**: 54,100+ rules neutralizing ransomware and phishing.
* **AdvGuard SafeFamily Shield**: 28,900+ rules enforcing SafeSearch and parental security.
* **Raw Download API**: 1-click export of any list as `.txt` for Pi-hole, AdGuard Home, or uBlock Origin.

#### 📱 Setup & Client Integration
* **Free Public DNS**: Live endpoint on `advgaurd.veerbhanushali.com`.
* **Apple iOS / iPadOS**: 1-Click native `.mobileconfig` signed profile download.
* **Android**: Step-by-step guides for Native Private DNS and Intra/RethinkDNS.
* **Windows / macOS / Linux**: System-level DoH templates and PowerShell 1-liners.
* **Browsers**: Custom Secure DNS instructions for Chrome, Edge, Brave, and Firefox.

---

*AdvGuard is released under the **MIT Open Source License** by **Veer Bhanushali**.*

