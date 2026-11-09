# 🚀 AdvGuard Deployment Guide

This guide explains how to deploy **AdvGuard** to **Hostinger WebApp (Node.js)**, **Vercel**, and configure your custom domain (`advgaurd.veerbhanushali.com`).

---

## 1. Deploying to Hostinger WebApp (Node.js)

Hostinger's Web Hosting and Cloud plans include a dedicated **Node.js Application** manager in hPanel.

### Step 1: Prepare the Node.js App in Hostinger hPanel
1. Log in to your Hostinger hPanel.
2. Under **Websites** or **Advanced**, click **Node.js**.
3. Click **Create Application**:
   * **Node.js version**: `v18.x` or `v20.x` (recommended)
   * **Application mode**: `Production`
   * **Application root**: `advguard`
   * **Application startup file**: `node_modules/next/dist/bin/next` with argument `start` (or `npm start`)
   * **Application URL**: Select `advgaurd.veerbhanushali.com` (or your subdomain)

### Step 2: Upload Files
1. In Hostinger File Manager or via Git / FTP, upload the contents of the `adguard-web` folder.
2. In the hPanel Node.js section, click **Run `npm install`**.
3. Click **Run `npm run build`**.
4. Click **Restart Application**.
5. Done! Your AdvGuard engine is live on Hostinger with automatic HTTPS SSL.

---

## 2. Deploying to Vercel (1-Click Global Deployment)

### Step 1: Push to GitHub
```bash
cd "E:\D_Drive\Alll Websites\AD GAURD\adguard-web"
git push -u origin main
```

### Step 2: Import into Vercel
1. Log in to [vercel.com](https://vercel.com).
2. Click **Add New...** &rarr; **Project**.
3. Import the `VeerBhanushali/AdvGaurd` repository.
4. Leave framework preset as **Next.js**.
5. *(Optional)* Add your Supabase environment variables in the **Environment Variables** section:
   ```env
   NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
   NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
   ```
6. Click **Deploy**.

### Step 3: Connect Your Domain (`advgaurd.veerbhanushali.com`)
1. In Vercel Project Settings, go to **Domains**.
2. Add `advgaurd.veerbhanushali.com`.
3. In your DNS manager (Cloudflare, GoDaddy, Hostinger, etc.), add the CNAME record:
   * **Type**: `CNAME`
   * **Name**: `advgaurd`
   * **Target**: `cname.vercel-dns.com`
4. Vercel automatically generates a free Let's Encrypt SSL certificate!

---

## 3. Database Setup (Supabase)

1. Go to [supabase.com](https://supabase.com) and create a free project.
2. Open **SQL Editor**.
3. Copy the entire contents of [`supabase-schema.sql`](supabase-schema.sql) and click **Run**.
4. All tables, security policies, and default blocklists are automatically configured.

---

## 4. Git Security & Ignore Policy

The following are strictly ignored by `.gitignore` to prevent secret leaks:
* `.env*.local` and `.env` (API keys & credentials)
* `node_modules/`
* `.next/` and build outputs
* OS cache files (`.DS_Store`, `Thumbs.db`)

---

*Authored by Veer Bhanushali • MIT Open Source License*
