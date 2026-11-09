# AdvGuard

**Ad-blocking DNS that runs anywhere Node.js runs.**
A self-hostable DNS-over-HTTPS (RFC 8484) resolver with blocklists, a small DNS firewall and a web dashboard. You don't need a Raspberry Pi, root access or port 53, so it runs on cheap shared Node.js hosting, a VPS or Docker.

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![RFC 8484](https://img.shields.io/badge/RFC_8484-DoH-blue)](https://www.rfc-editor.org/rfc/rfc8484)
[![Next.js 14](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org/)

> Author: **Veer Bhanushali** · Public instance: `https://advgaurd.veerbhanushali.com/dns-query`
>
> AdvGuard is an independent project. It is not affiliated with or endorsed by AdGuard Software Ltd., Pi-hole LLC or NextDNS Inc.

---

## Why it exists

Pi-hole and AdGuard Home are excellent, but they need a machine you control that can bind UDP/TCP 53. Many people don't have one. What they do have is a $3/month shared hosting plan or a free-tier app platform that only speaks HTTPS.

AdvGuard serves DNS only over HTTPS on a normal web port. Point an iPhone, Windows 11, macOS or a browser at `https://your-domain/dns-query` and ads, trackers and malware domains get blocked on every network that device joins.

| | Pi-hole / AdGuard Home | NextDNS / AdGuard DNS | **AdvGuard** |
|---|---|---|---|
| Needs dedicated hardware / root | Yes | No | **No** |
| You own the data | Yes | No | **Yes** |
| Runs on shared web hosting | No | n/a | **Yes** |
| Plain DNS (port 53) / DoT | Yes | Yes | No (DoH only)* |

\*See [limitations](#honest-limitations).

## Features

- **RFC 8484 DoH**: `POST application/dns-message` and `GET ?dns=<base64url>` at `/dns-query`, plus per-device endpoints `/dns-query/<token>`.
- **JSON API**: `/api/resolve?name=example.com&type=A`.
- **Blocklists**:
  - A small built-in starter list that works offline.
  - [HaGeZi Multi PRO](https://github.com/hagezi/dns-blocklists) (~220k domains), downloaded at startup and refreshed daily. Bring your own lists with `BLOCKLIST_URLS`.
- **Custom rules**: `||domain^`, `@@||domain^` (allowlist), hosts-file and plain-domain syntax. Rewrites (A/AAAA/CNAME) and 1-click blocked services (TikTok, YouTube, Discord …).
- **SafeSearch**: enforced via CNAME for Google, Bing, DuckDuckGo and YouTube.
- **DNS firewall** with Low / Balanced / Strict / Paranoid presets:
  - cryptominer domains
  - high-abuse TLDs (`.top`, `.work`, `.click`, `.buzz`, `.cfd`, `.loan`, `.gdn` …)
  - optional AI-assistant-service policy for schools and workplaces
- **iOS / macOS profile**: 1-click `.mobileconfig` (also per device: `/api/mobileconfig?device=<token>`).
- **Dashboard**: live KPIs, a real 24-hour chart, top domains, clients and upstreams, and a query log. Dark and light themes.
- **Storage**: RAM-only by default. Optional Supabase (Postgres) or Firestore for persistent logs.

## Security & privacy

Details are in [`SECURITY.md`](SECURITY.md).

- **Fail-closed admin.** Without an `ADMIN_PASSWORD` of at least 12 characters, the admin API and dashboard are disabled in production.
- **Admin sessions.** Login returns a 12-hour HMAC-signed session token. The password is never stored in the browser, and logins are limited to 5 attempts per 15 minutes per IP.
- **Zero-PII logging.** Client IPs are cut to `/24` (IPv4) or `/64` (IPv6) *before* they reach the logs, stats or database. Raw IPs exist only inside the request, and rate-limiter keys are salted hashes.
- **Retention.** Logs are purged after `LOG_RETENTION_DAYS` (default 30) by a 12-hour worker plus `delete_old_query_logs()` in Postgres.
- **Abuse limits.**
  - Per-IP sliding-window rate limit that can't be bypassed by spoofing `X-Forwarded-For`.
  - 4 KB message cap; `ANY` queries refused (RFC 8482).
  - Bounded memory for counters, devices and the rate limiter.
- **Locked database.** The Supabase schema grants the public anon key *no* access. The server uses the service-role key, which is server-only.
- **Hardening.**
  - Strict security headers (CSP, HSTS, `frame-ancestors 'none'`).
  - Validated input on every endpoint and generic error messages.

## Quick start

```bash
git clone https://github.com/VeerBhanushali/AdvGaurd.git
cd AdvGaurd
cp .env.example .env.local      # set ADMIN_PASSWORD (12+ chars)
npm ci
npm run build
npm start                       # http://localhost:3001
```

Test it:

```bash
curl "http://localhost:3001/api/resolve?name=doubleclick.net"   # → 0.0.0.0 (blocked)
```

To deploy on Hostinger, a VPS + Caddy/Nginx, Vercel or Docker, see [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md).

## Connect a device

| Platform | How |
|---|---|
| iPhone / iPad / Mac | Open the dashboard in Safari → **Setup Guide** → download the profile → Settings → install |
| Windows 11 | Settings → Network → DNS → Manual → *Encrypted only (DNS over HTTPS)* → template `https://your-domain/dns-query` |
| Chrome / Edge / Brave / Firefox | Settings → Privacy → Secure DNS → Custom → `https://your-domain/dns-query` |
| Android (system-wide) | Install **Intra** or **RethinkDNS** → custom DoH URL. Android's built-in *Private DNS* only speaks DNS-over-TLS (see below). |

## Honest limitations

- **No DNS-over-TLS / port 53.** Android's native Private DNS, most routers and smart TVs need DoT (853) or plain DNS. On a VPS you can add a DoT front-end (e.g. `dnsdist` or Caddy L4) that forwards to `/dns-query`; shared hosting can't.
- **Settings live in memory.** Rules, devices and firewall settings reset on restart, and serverless platforms (Vercel) may run several isolated instances. Use a single long-running Node process for a real deployment. Persisting settings to Supabase is on the roadmap.
- **Unsigned iOS profile.** iOS shows the profile as "Unverified". Signing needs an Apple-trusted certificate.
- **DNS can't stop website scrapers.** The "AI services" toggle stops *your devices* from reaching AI assistants. It can't stop crawlers from scraping *your site*; use `robots.txt` or a WAF for that.
- **Running a public resolver is a commitment.** You become responsible for uptime, abuse handling and a privacy policy. Read `SECURITY.md` first.

## Roadmap

- [ ] Persist rules, devices and settings to Supabase
- [ ] Optional DoT listener for VPS deployments
- [ ] Per-device policies (e.g. kids' devices get SafeSearch)
- [ ] Docker image + one-click deploy buttons
- [ ] Automated test suite in CI

## License

MIT © 2026 Veer Bhanushali. Third-party blocklists keep their own licenses and are downloaded from their maintainers, not redistributed.
