import { NextRequest, NextResponse } from 'next/server';
import { dnsEngine } from '@/lib/dns-engine';
import { cloudStorage } from '@/lib/cloud-storage';
import { BLOCKED_SERVICES } from '@/lib/blocked-services';
import { firewallEngine } from '@/lib/firewall';
import { userManager } from '@/lib/user-manager';
import {
  adminAuthState,
  getClientIp,
  isAdminRequest,
  issueAdminSession,
  MIN_ADMIN_PASSWORD_LENGTH,
  SlidingWindowLimiter,
  verifyAdminPassword,
} from '@/lib/security';

export const dynamic = 'force-dynamic';

// 5 login attempts per IP per 15 minutes.
const loginLimiter = new SlidingWindowLimiter(5, 15 * 60_000);
// 10 public device registrations per IP per hour.
const registerLimiter = new SlidingWindowLimiter(10, 60 * 60_000);
// General API budget per IP.
const apiLimiter = new SlidingWindowLimiter(120, 60_000);

const MAX_BODY_BYTES = 16 * 1024;
const NO_STORE = { 'Cache-Control': 'no-store' };

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return NextResponse.json(body, { status, headers: { ...NO_STORE, ...headers } });
}

function authInfo() {
  const state = adminAuthState();
  return {
    hasAdminPassword: state === 'enabled',
    adminAuth: state,
    adminHint:
      state === 'not-configured'
        ? 'Admin is disabled: set ADMIN_PASSWORD in the server environment.'
        : state === 'too-weak'
        ? `Admin is disabled: ADMIN_PASSWORD must be at least ${MIN_ADMIN_PASSWORD_LENGTH} characters.`
        : state === 'dev-open'
        ? 'Development mode: admin is open because ADMIN_PASSWORD is not set.'
        : undefined,
  };
}

export async function GET(req: NextRequest) {
  const ip = getClientIp(req.headers);
  const retry = apiLimiter.hit(ip);
  if (retry) return json({ error: 'Too many requests' }, 429, { 'Retry-After': String(retry) });

  const isAdmin = isAdminRequest(req.headers);
  const stats = dnsEngine.getFullStats();
  const cloud = cloudStorage.getStatus();

  if (!isAdmin) {
    // Public view: aggregate counters only – no domains, clients, devices or logs.
    return json({
      success: true,
      isAdmin: false,
      ...authInfo(),
      stats: {
        totalQueries: stats.totalQueries,
        blockedQueries: stats.blockedQueries,
        blockedPercentage: stats.blockedPercentage,
        rulesCount: stats.rulesCount,
        avgLatencyMs: stats.avgLatencyMs,
        protectionEnabled: stats.protectionEnabled,
        chartData: stats.chartData,
        curatedLists: stats.curatedLists,
        // Policy settings are not sensitive and let visitors see what is filtered.
        firewall: { blocksCount: stats.firewall.blocksCount, config: stats.firewall.config },
        blockedServiceIds: stats.blockedServiceIds,
      },
      cloud: { privacyMode: cloud.privacyMode, retentionPolicy: cloud.retentionPolicy },
      availableServices: BLOCKED_SERVICES,
    });
  }

  return json({
    success: true,
    isAdmin: true,
    ...authInfo(),
    stats,
    logs: dnsEngine.getLogs().slice(0, 150),
    rules: dnsEngine.getRules(),
    blocklists: dnsEngine.getBlocklists(),
    cloud,
    availableServices: BLOCKED_SERVICES,
  });
}

const bool = (v: unknown): v is boolean => typeof v === 'boolean';
const str = (v: unknown, max = 300): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;

export async function POST(req: NextRequest) {
  const ip = getClientIp(req.headers);

  const ct = (req.headers.get('content-type') || '').toLowerCase();
  if (!ct.startsWith('application/json')) return json({ error: 'Content-Type must be application/json' }, 415);
  if (Number(req.headers.get('content-length') || 0) > MAX_BODY_BYTES) return json({ error: 'Body too large' }, 413);

  let body: Record<string, unknown>;
  try {
    const text = await req.text();
    if (text.length > MAX_BODY_BYTES) return json({ error: 'Body too large' }, 413);
    body = JSON.parse(text);
    if (!body || typeof body !== 'object') throw new Error();
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }
  const action = body.action;

  // 1. Login → short-lived signed session token (password is never stored client-side).
  if (action === 'verify-admin') {
    const retry = loginLimiter.hit(ip);
    if (retry) return json({ success: false, error: 'Too many attempts. Try again later.' }, 429, { 'Retry-After': String(retry) });
    const state = adminAuthState();
    if (state === 'dev-open') return json({ success: true, ...issueAdminSession(), ...authInfo() });
    if (verifyAdminPassword(body.password)) {
      loginLimiter.reset(ip);
      return json({ success: true, ...issueAdminSession(), ...authInfo() });
    }
    return json({ success: false, ...authInfo() }, 401);
  }

  const retry = apiLimiter.hit(ip);
  if (retry) return json({ error: 'Too many requests' }, 429, { 'Retry-After': String(retry) });

  // 2. Public device registration (rate-limited, capped, random token suffix).
  if (action === 'register-device') {
    const r = registerLimiter.hit(ip);
    if (r) return json({ error: 'Too many registrations' }, 429, { 'Retry-After': String(r) });
    const result = userManager.registerDevice(body.name, body.token);
    if (!result.ok) return json({ error: result.error }, result.status);
    return json({ success: true, device: { name: result.device.name, token: result.device.token } });
  }

  // 3. Everything below mutates server state → admin only (fail-closed).
  if (!isAdminRequest(req.headers)) {
    return json({ error: 'Unauthorized: admin authentication required' }, 401);
  }

  switch (action) {
    case 'set-protection':
      if (!bool(body.enabled)) break;
      dnsEngine.setProtection(body.enabled);
      return json({ success: true });
    case 'set-safesearch':
      if (!bool(body.enabled)) break;
      dnsEngine.setSafeSearch(body.enabled);
      return json({ success: true });
    case 'set-safebrowsing':
      if (!bool(body.enabled)) break;
      dnsEngine.setSafeBrowsing(body.enabled);
      return json({ success: true });
    case 'update-firewall':
      firewallEngine.updateConfig(body.config);
      return json({ success: true, config: firewallEngine.getConfig() });
    case 'set-device-status':
      if (!str(body.id, 64) || !['active', 'paused', 'revoked'].includes(body.status as string)) break;
      return json({ success: userManager.setDeviceStatus(body.id, body.status as 'active' | 'paused' | 'revoked') });
    case 'delete-device':
      if (!str(body.id, 64)) break;
      return json({ success: userManager.deleteDevice(body.id) });
    case 'clear-logs':
      dnsEngine.clearLogs();
      return json({ success: true });
    case 'toggle-service':
      if (!str(body.serviceId, 64) || !bool(body.enabled)) break;
      return json({ success: dnsEngine.toggleBlockedService(body.serviceId, body.enabled) });
    case 'add-rewrite':
      if (!str(body.domain, 253) || !str(body.answer, 253)) break;
      return json({ success: dnsEngine.addRewrite(body.domain, body.answer) });
    case 'delete-rewrite':
      if (!str(body.id, 64)) break;
      dnsEngine.deleteRewrite(body.id);
      return json({ success: true });
    case 'add-rule':
      if (!str(body.rule)) break;
      return json({ success: dnsEngine.addRule(body.rule) });
    case 'delete-rule':
      if (!str(body.id, 64)) break;
      return json({ success: dnsEngine.deleteRule(body.id) });
    case 'toggle-blocklist':
      if (!str(body.id, 64) || !bool(body.enabled)) break;
      return json({ success: dnsEngine.toggleBlocklist(body.id, body.enabled) });
    case 'check-domain':
      if (!str(body.domain, 253)) break;
      return json({ success: true, result: dnsEngine.isDomainBlocked(body.domain) });
    default:
      return json({ error: 'Unknown action' }, 400);
  }
  return json({ error: 'Invalid parameters' }, 400);
}
