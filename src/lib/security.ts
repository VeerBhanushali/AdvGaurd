import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { isIP } from 'net';

/* -------------------------------------------------------------------------- */
/*  Client IP resolution                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Number of reverse proxies in front of the app that append to X-Forwarded-For.
 *  - Hostinger / Vercel / Nginx / Cloudflare (single hop) → 1 (default)
 *  - Cloudflare → Nginx → app                             → 2
 *  - Directly exposed (server.js on a public port)        → 0
 *
 * The client controls everything to the LEFT of what our own proxies append,
 * so we read from the RIGHT. Reading the left-most entry (the old behaviour)
 * let anyone spoof their IP and bypass rate limits.
 */
function trustedProxyHops(): number {
  const raw = parseInt(process.env.TRUSTED_PROXY_HOPS ?? '1', 10);
  return Number.isFinite(raw) && raw >= 0 && raw <= 10 ? raw : 1;
}

function normalizeIp(ip: string): string {
  let v = ip.trim();
  if (v.startsWith('[') && v.includes(']')) v = v.slice(1, v.indexOf(']'));
  if (v.toLowerCase().startsWith('::ffff:') && isIP(v.slice(7)) === 4) v = v.slice(7);
  // Strip an IPv4 ":port" suffix if a proxy appended one.
  if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(v)) v = v.split(':')[0];
  return v;
}

export function getClientIp(headers: Headers): string {
  const hops = trustedProxyHops();
  if (hops > 0) {
    const xff = headers.get('x-forwarded-for');
    if (xff) {
      const list = xff.split(',').map((s) => s.trim()).filter(Boolean);
      const candidate = list[Math.max(0, list.length - hops)];
      if (candidate) {
        const ip = normalizeIp(candidate);
        if (isIP(ip)) return ip;
      }
    }
    const real = headers.get('x-real-ip');
    if (real && isIP(normalizeIp(real))) return normalizeIp(real);
  }
  // Set (and overwritten) by server.js from the TCP socket – cannot be spoofed
  // when the app is started through server.js.
  const socketAddr = headers.get('x-advguard-remote-addr');
  if (socketAddr && isIP(normalizeIp(socketAddr))) return normalizeIp(socketAddr);
  return 'unknown';
}

/* -------------------------------------------------------------------------- */
/*  Zero-PII anonymisation                                                    */
/* -------------------------------------------------------------------------- */

function expandIPv6(ip: string): string[] | null {
  const [head, tail, ...rest] = ip.split('::');
  if (rest.length) return null;
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  // Embedded IPv4 suffix (e.g. ::ffff:1.2.3.4) counts as two groups.
  const last = (tail !== undefined ? t : h).slice(-1)[0];
  const v4Groups = last && last.includes('.') ? 1 : 0;
  const missing = 8 - (h.length + t.length + v4Groups);
  if (tail === undefined && missing !== 0) return null;
  const groups = [...h, ...Array(Math.max(0, missing)).fill('0'), ...t];
  return groups.map((g) => (g.includes('.') ? g : g.padStart(4, '0').toLowerCase()));
}

/**
 * IPv4 → /24 (103.21.244.78 → 103.21.244.xxx)
 * IPv6 → /64 (2405:201:2004:abcd:1:2:3:4 → 2405:201:2004:abcd::/64)
 */
export function anonymizeIp(ip: string): string {
  const v = normalizeIp(ip || '');
  const family = isIP(v);
  if (family === 4) {
    const p = v.split('.');
    return `${p[0]}.${p[1]}.${p[2]}.xxx`;
  }
  if (family === 6) {
    const groups = expandIPv6(v);
    if (!groups) return 'ipv6-anonymized';
    return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
  }
  return 'unknown';
}

export function shouldAnonymize(): boolean {
  return process.env.ANONYMIZE_IPS !== 'false';
}

/** The identifier that is allowed to leave the request scope (logs, stats, DB). */
export function displayIp(ip: string): string {
  return shouldAnonymize() ? anonymizeIp(ip) : ip;
}

/* -------------------------------------------------------------------------- */
/*  Sliding-window rate limiter (bounded memory)                              */
/* -------------------------------------------------------------------------- */

// Per-process salt: raw IPs are never kept as map keys, even in RAM.
const KEY_SALT = randomBytes(16);
function hashKey(key: string): string {
  return createHash('sha256').update(KEY_SALT).update(key).digest('base64url').slice(0, 22);
}

interface Window {
  start: number;
  cur: number;
  prev: number;
}

export class SlidingWindowLimiter {
  private windows = new Map<string, Window>();

  constructor(
    private limit: number,
    private windowMs: number,
    private maxKeys = 50_000
  ) {}

  setLimit(limit: number) {
    this.limit = limit;
  }

  /** Returns 0 when allowed, otherwise seconds until the client may retry. */
  hit(rawKey: string): number {
    const key = hashKey(rawKey);
    const now = Date.now();
    let w = this.windows.get(key);
    if (!w) {
      if (this.windows.size >= this.maxKeys) this.evict(now);
      w = { start: now, cur: 0, prev: 0 };
      this.windows.set(key, w);
    }
    const elapsed = now - w.start;
    if (elapsed >= this.windowMs * 2) {
      w.start = now;
      w.prev = 0;
      w.cur = 0;
    } else if (elapsed >= this.windowMs) {
      w.start += this.windowMs;
      w.prev = w.cur;
      w.cur = 0;
    }
    const weight = 1 - (now - w.start) / this.windowMs;
    const estimated = w.prev * weight + w.cur;
    if (estimated >= this.limit) {
      return Math.max(1, Math.ceil((this.windowMs - (now - w.start)) / 1000));
    }
    w.cur++;
    return 0;
  }

  reset(rawKey: string) {
    this.windows.delete(hashKey(rawKey));
  }

  private evict(now: number) {
    for (const [k, w] of this.windows) {
      if (now - w.start >= this.windowMs * 2) this.windows.delete(k);
    }
    // Still full (flood of unique IPs): drop the oldest 10 %.
    if (this.windows.size >= this.maxKeys) {
      let n = Math.ceil(this.maxKeys / 10);
      for (const k of this.windows.keys()) {
        this.windows.delete(k);
        if (--n <= 0) break;
      }
    }
  }
}

/* -------------------------------------------------------------------------- */
/*  Admin authentication (fail-closed)                                        */
/* -------------------------------------------------------------------------- */

export const MIN_ADMIN_PASSWORD_LENGTH = 12;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

export type AdminAuthState = 'enabled' | 'not-configured' | 'too-weak' | 'dev-open';

export function adminAuthState(): AdminAuthState {
  const pw = process.env.ADMIN_PASSWORD;
  if (!pw) {
    // Only an explicit local development run is allowed to skip the password.
    return process.env.NODE_ENV === 'development' ? 'dev-open' : 'not-configured';
  }
  if (pw.length < MIN_ADMIN_PASSWORD_LENGTH) return 'too-weak';
  return 'enabled';
}

function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

function sessionKey(): Buffer {
  // Rotating ADMIN_PASSWORD invalidates every existing session.
  return createHash('sha256').update('advguard-session-v1:').update(process.env.ADMIN_PASSWORD || '').digest();
}

export function verifyAdminPassword(candidate: unknown): boolean {
  if (adminAuthState() !== 'enabled' || typeof candidate !== 'string') return false;
  return safeEqual(candidate, process.env.ADMIN_PASSWORD as string);
}

/** Short-lived signed session token – the password itself is never stored in the browser. */
export function issueAdminSession(): { token: string; expiresAt: number } {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const nonce = randomBytes(9).toString('base64url');
  const payload = `${expiresAt}.${nonce}`;
  const sig = createHmac('sha256', sessionKey()).update(payload).digest('base64url');
  return { token: `${payload}.${sig}`, expiresAt };
}

function verifyAdminSession(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [exp, nonce, sig] = parts;
  const expiresAt = Number(exp);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return false;
  const expected = createHmac('sha256', sessionKey()).update(`${exp}.${nonce}`).digest('base64url');
  return safeEqual(sig, expected);
}

/**
 * `x-admin-key` may carry either a session token from the login endpoint
 * (browser dashboard) or the raw ADMIN_PASSWORD (scripts / curl).
 */
export function isAdminRequest(headers: Headers): boolean {
  const state = adminAuthState();
  if (state === 'dev-open') return true;
  if (state !== 'enabled') return false;
  const key = headers.get('x-admin-key');
  if (!key || key.length > 512) return false;
  return verifyAdminSession(key) || verifyAdminPassword(key);
}

/* -------------------------------------------------------------------------- */
/*  Misc                                                                       */
/* -------------------------------------------------------------------------- */

export const CLIENT_ID_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function isValidClientId(id: string): boolean {
  return CLIENT_ID_RE.test(id);
}

/** Strict hostname check used for user-supplied domains (rules, rewrites, tests). */
export function isValidHostname(name: string): boolean {
  if (!name || name.length > 253) return false;
  return name
    .split('.')
    .every((label) => /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/i.test(label));
}
