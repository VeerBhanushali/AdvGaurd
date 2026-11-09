# Deployment Guide

AdvGuard is a Next.js app with a custom `server.js`. It works best as **one long-running Node.js process**, because rules, devices and stats live in memory.

| Target | Good for | Notes |
|---|---|---|
| Hostinger Node.js web app | Cheapest public instance | Uses `server.js`, `PORT` injected by the host |
| VPS + Caddy / Nginx | Best overall; can add DoT | Full control, can add Android Private DNS support |
| Docker | Home lab / VPS | `node:20-alpine`, `npm ci && npm run build`, `CMD ["npm","start"]` |
| Vercel | Demo only | Multiple isolated instances: settings changed in the dashboard won't persist or be shared |

Before any deploy, set these environment variables (see `.env.example`):

```env
ADMIN_PASSWORD=<random, 12+ chars>
PUBLIC_HOSTNAME=advgaurd.example.com
TRUSTED_PROXY_HOPS=1
ANONYMIZE_IPS=true
LOG_RETENTION_DAYS=30
```

Generate a password:

```bash
node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))"
```

---

## 1. Hostinger (Node.js web app)

1. In hPanel, open **Websites → Node.js → Create application**.
   - Node.js 20.x, mode **Production**
   - Startup file **`server.js`**
   - Application URL: your subdomain
2. Deploy the repo via Git (or upload it, **without** `node_modules` and `.next`).
3. Add the environment variables above in the app's **Environment variables** panel.
4. Run `npm ci`, then `npm run build`, then **Restart**.
5. Check that it works:

   ```bash
   curl "https://your-domain/api/resolve?name=doubleclick.net"
   ```

   You should get a `0.0.0.0` answer.

On small plans (≤512 MB RAM), set `REMOTE_BLOCKLISTS=false`. The ~220k-domain HaGeZi list uses roughly 100 MB of extra RAM.

## 2. VPS (Ubuntu) + Caddy

```bash
git clone https://github.com/VeerBhanushali/AdvGaurd.git /opt/advguard
cd /opt/advguard
cp .env.example .env.local   # edit values
npm ci
npm run build
```

Run it with systemd or pm2 (`pm2 start server.js --name advguard`). Then add this `Caddyfile`, which gives automatic HTTPS:

```
advgaurd.example.com {
    reverse_proxy 127.0.0.1:3001
}
```

**Optional: Android Private DNS (DoT).** Android's native Private DNS needs DNS-over-TLS on port 853. On a VPS, run `dnsdist` with a DoT listener that uses your certificate and forwards to `https://127.0.0.1/dns-query` as a DoH backend. This isn't possible on shared hosting.

## 3. Vercel (demo)

1. Import the repo in Vercel and add the env vars.
2. `server.js` is not used; Vercel sets `X-Forwarded-For`, so keep `TRUSTED_PROXY_HOPS=1`.
3. Expect settings to reset between invocations (see the table above).

## 4. Database (optional)

**Supabase (recommended).**
1. Create a project, open the **SQL Editor**, paste [`supabase-schema.sql`](supabase-schema.sql) and click **Run**. It is safe to re-run, and it removes the insecure policies older versions created.
2. Set these on the **server**:

   ```env
   SUPABASE_URL=https://xxxx.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=<service role key>
   ```

   Never expose the service-role key with a `NEXT_PUBLIC_` prefix.

**Firestore.**
1. Deploy [`firestore.rules`](firestore.rules) first. The rules let the server create log documents and block all reads.
2. Set the `NEXT_PUBLIC_FIREBASE_*` variables.

With no database configured, AdvGuard runs RAM-only and nothing is persisted.

## 5. DNS for your domain

Point a subdomain (e.g. `advgaurd`) at your host with an `A` record (VPS / Hostinger) or a `CNAME` to `cname.vercel-dns.com` (Vercel). Wait for TLS to provision, then use `https://advgaurd.example.com/dns-query`.
