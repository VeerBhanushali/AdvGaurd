# Security & Privacy

AdvGuard resolves other people's DNS queries, which reveal every site they visit. This document describes exactly what the code does to protect them, and what operators are responsible for.

## Threat model

| Threat | Mitigation | Where |
|---|---|---|
| Anyone becomes admin on a fresh deploy | Admin is **disabled** unless `ADMIN_PASSWORD` (≥12 chars) is set in production | `src/lib/security.ts` `adminAuthState()` |
| Password brute force | 5 attempts / 15 min / IP; constant-time comparison | `api/stats` `verify-admin` |
| Password theft from the browser | Browser holds only a 12 h HMAC session token in `sessionStorage`; rotating the password revokes all sessions | `issueAdminSession()` |
| Rate-limit bypass via spoofed `X-Forwarded-For` | Client IP is read from the right of XFF using `TRUSTED_PROXY_HOPS`; `server.js` injects the socket address | `getClientIp()` |
| Query floods / memory exhaustion | Sliding-window limiter with bounded keys, 4 KB DoH body cap, bounded stats maps, device cap (`MAX_DEVICES`), list size cap | `doh-handler.ts`, `dns-engine.ts` |
| Reflection / enumeration | `ANY` queries answered `NOTIMP` (RFC 8482). DoH runs over TCP+TLS, so it can't be used for spoofed-source amplification | `dns-engine.ts` |
| Database read by the public | Supabase RLS on with **no** anon/authenticated grants; server uses the service-role key (server-only env var). Firestore rules are write-only | `supabase-schema.sql`, `firestore.rules` |
| Host-header injection into the iOS profile | `PUBLIC_HOSTNAME` env, strict host regex, XML escaping | `api/mobileconfig` |
| Guessable device endpoints | Device tokens get a random 32-bit suffix | `user-manager.ts` |
| XSS / clickjacking | CSP, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, HSTS | `next.config.mjs` |
| Info leaks via errors | Generic error bodies; details go only to server logs | all routes |

## Privacy guarantees

- **IP anonymisation at ingestion.** With `ANONYMIZE_IPS` on (the default), IPs are truncated *before* they reach the in-memory log, dashboard stats or any database.
  - IPv4 is cut to `/24`: `103.21.244.78` → `103.21.244.xxx`
  - IPv6 is cut to `/64`: `2405:201:2004:abcd:…` → `2405:201:2004:abcd::/64`
- **Raw IPs stay in the request.** They are used only inside a single request, for rate limiting under a salted hash, and are never written anywhere.
- **Retention.** Query logs older than `LOG_RETENTION_DAYS` (default 30) are deleted:
  - every 12 hours by the server, with a lazy backstop for serverless platforms
  - optionally by `pg_cron` inside Postgres (see the schema)
- **Dashboard access.** Public visitors see only aggregate counters. Domains, clients, devices and logs need admin authentication.

Truncated IPs plus domain names can still be personal data in some jurisdictions (GDPR). If you run a public instance, publish a privacy policy and keep retention as short as you can.

## Operator checklist (public instance)

- [ ] `ADMIN_PASSWORD` set to a random 24+ character value
- [ ] `PUBLIC_HOSTNAME` set; `TRUSTED_PROXY_HOPS` matches your proxy chain
- [ ] `ANONYMIZE_IPS=true`, `LOG_RETENTION_DAYS` ≤ 30
- [ ] Re-run `supabase-schema.sql` (it drops the old "Anon Full Access" policies)
- [ ] Use `SUPABASE_SERVICE_ROLE_KEY`, **never** with a `NEXT_PUBLIC_` prefix
- [ ] Rotate any key that was ever committed or shared
- [ ] HTTPS only (the platform's TLS or Caddy/Nginx)
- [ ] Privacy policy page and an abuse contact

## Secrets

`.gitignore` blocks `.env*`, keys, tokens and service-account files. Only `.env.example` (placeholders) is committed. Put production secrets in your host's environment settings.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security → Advisories → Report a vulnerability) on [VeerBhanushali/AdvGaurd](https://github.com/VeerBhanushali/AdvGaurd), rather than opening a public issue.
