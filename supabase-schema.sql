-- ========================================================
-- AdvGuard - Complete Database Schema & Authentication
-- Created & Engineered by Veer Bhanushali
-- ========================================================
-- Instructions:
-- 1. Create a free project at https://supabase.com
-- 2. Open "SQL Editor" in the left sidebar
-- 3. Paste this ENTIRE file and click "Run" (Ctrl+Enter)
-- ========================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. QUERY LOGS (Stores real-time DNS queries)
CREATE TABLE IF NOT EXISTS public.query_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    domain TEXT NOT NULL,
    query_type VARCHAR(10) NOT NULL DEFAULT 'A',
    client_ip VARCHAR(100) NOT NULL, -- already anonymised (/24 or /64) by the server
    status VARCHAR(20) NOT NULL, -- 'BLOCKED', 'RESOLVED'
    matched_rule TEXT,
    elapsed_ms INT NOT NULL DEFAULT 0,
    upstream VARCHAR(100)
);

-- Fast Indexes for Query Log Searching & Filtering
CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON public.query_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON public.query_logs(domain);
CREATE INDEX IF NOT EXISTS idx_query_logs_status ON public.query_logs(status);
CREATE INDEX IF NOT EXISTS idx_query_logs_client_ip ON public.query_logs(client_ip);

-- 2. CUSTOM USER RULES (Allowlists & Blocklists)
CREATE TABLE IF NOT EXISTS public.custom_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    pattern TEXT NOT NULL,
    rule_type VARCHAR(10) NOT NULL DEFAULT 'BLOCK', -- 'BLOCK', 'ALLOW'
    enabled BOOLEAN NOT NULL DEFAULT true
);

-- 3. SUBSCRIBED BLOCKLISTS (OISD, HaGeZi, AdGuard, etc.)
CREATE TABLE IF NOT EXISTS public.subscribed_blocklists (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    count INT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    category TEXT
);

-- Seed Default High-Efficiency Blocklists
INSERT INTO public.subscribed_blocklists (id, name, url, count, enabled, category)
VALUES
    ('adguard-base', 'AdGuard DNS Filter', 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt', 48200, true, 'General Ads'),
    ('oisd-big', 'OISD (Big)', 'https://big.oisd.nl', 145000, true, 'Zero False-Positive'),
    ('hagezi-pro', 'HaGeZi Multi PRO', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt', 98000, true, 'Malware & Trackers'),
    ('windows-spy', 'Windows Spy Blocker', 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt', 1200, true, 'OS Telemetry')
ON CONFLICT (id) DO NOTHING;

-- 4. DNS REWRITES (Domain -> IP mappings)
CREATE TABLE IF NOT EXISTS public.dns_rewrites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL UNIQUE,
    answer TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. BLOCKED SERVICES (TikTok, YouTube, Discord, etc.)
CREATE TABLE IF NOT EXISTS public.blocked_services (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT false
);

-- 6. GLOBAL ENGINE SETTINGS
CREATE TABLE IF NOT EXISTS public.settings (
    id TEXT PRIMARY KEY DEFAULT 'global',
    protection_enabled BOOLEAN NOT NULL DEFAULT true,
    safesearch_enabled BOOLEAN NOT NULL DEFAULT false,
    safebrowsing_enabled BOOLEAN NOT NULL DEFAULT true,
    upstreams JSONB NOT NULL DEFAULT '["https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"]',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO public.settings (id, protection_enabled, safesearch_enabled, safebrowsing_enabled)
VALUES ('global', true, false, true)
ON CONFLICT (id) DO NOTHING;

-- 7. REGISTERED CLIENT DEVICES
CREATE TABLE IF NOT EXISTS public.devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active TIMESTAMPTZ NOT NULL DEFAULT now(),
    total_queries INT NOT NULL DEFAULT 0,
    blocked_queries INT NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
);

-- 8. AUTOMATIC LOG PURGE FUNCTION (default 30 days)
DROP FUNCTION IF EXISTS public.delete_old_query_logs();
CREATE OR REPLACE FUNCTION public.delete_old_query_logs(retention_days INT DEFAULT 30)
RETURNS INT LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
    deleted_count INT;
BEGIN
    IF retention_days IS NULL OR retention_days < 1 THEN
        retention_days := 30;
    END IF;
    DELETE FROM public.query_logs
    WHERE timestamp < (NOW() - make_interval(days => retention_days));
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;

-- Only the server (service_role) may run the purge.
REVOKE ALL ON FUNCTION public.delete_old_query_logs(INT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.delete_old_query_logs(INT) TO service_role;

-- Optional: purge inside Postgres too (Database → Extensions → enable pg_cron first)
-- SELECT cron.schedule('advguard-purge', '0 */12 * * *', $$SELECT public.delete_old_query_logs(30)$$);

-- 9. ROW LEVEL SECURITY — LOCKED DOWN
-- The AdvGuard server connects with SUPABASE_SERVICE_ROLE_KEY, which bypasses RLS.
-- The public anon key (which ships to browsers) gets NO access to any table.
-- Previous versions created "Anon Full Access" policies; they are dropped here.
ALTER TABLE public.query_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.custom_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscribed_blocklists ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dns_rewrites ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blocked_services ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Anon Full Access Query Logs" ON public.query_logs;
DROP POLICY IF EXISTS "Anon Full Access Custom Rules" ON public.custom_rules;
DROP POLICY IF EXISTS "Anon Full Access Blocklists" ON public.subscribed_blocklists;
DROP POLICY IF EXISTS "Anon Full Access Rewrites" ON public.dns_rewrites;
DROP POLICY IF EXISTS "Anon Full Access Services" ON public.blocked_services;
DROP POLICY IF EXISTS "Anon Full Access Settings" ON public.settings;
DROP POLICY IF EXISTS "Anon Full Access Devices" ON public.devices;

REVOKE ALL ON public.query_logs, public.custom_rules, public.subscribed_blocklists,
    public.dns_rewrites, public.blocked_services, public.settings, public.devices
    FROM anon, authenticated;

-- Done! Safe to re-run on an existing database.
