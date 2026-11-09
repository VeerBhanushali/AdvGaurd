import { NextRequest, NextResponse } from 'next/server';
import { dnsEngine, DnsFormatError } from './dns-engine';
import { firewallEngine } from './firewall';
import { getClientIp, isValidClientId, SlidingWindowLimiter } from './security';

/** RFC 8484 messages are tiny; anything larger than this is abuse. */
const MAX_DNS_MESSAGE_BYTES = 4096;
const MAX_GET_PARAM_LEN = Math.ceil((MAX_DNS_MESSAGE_BYTES * 4) / 3) + 4;
const BASE64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;

export const dohLimiter = new SlidingWindowLimiter(300, 60_000);

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
  'Access-Control-Max-Age': '86400',
};

function plain(status: number, msg: string, extra: Record<string, string> = {}) {
  return new NextResponse(msg, { status, headers: { 'Content-Type': 'text/plain', ...CORS, ...extra } });
}

/** Returns a 429 response if the caller is over the limit, otherwise null. */
export function enforceRateLimit(ip: string): NextResponse | null {
  const cfg = firewallEngine.getConfig();
  if (!cfg.rateLimitEnabled) return null;
  dohLimiter.setLimit(cfg.maxQueriesPerMinute);
  const retry = dohLimiter.hit(ip);
  return retry ? plain(429, 'Too Many Requests', { 'Retry-After': String(retry) }) : null;
}

export async function handleDoh(req: NextRequest, clientIdRaw?: string): Promise<Response> {
  let clientId: string | undefined;
  if (clientIdRaw !== undefined) {
    clientId = clientIdRaw.toLowerCase();
    if (!isValidClientId(clientId)) return plain(400, 'Invalid client ID');
  }

  const ip = getClientIp(req.headers);
  const limited = enforceRateLimit(ip);
  if (limited) return limited;

  let query: Buffer;
  if (req.method === 'POST') {
    const ct = (req.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/dns-message') return plain(415, 'Content-Type must be application/dns-message');
    const declared = Number(req.headers.get('content-length') || 0);
    if (declared > MAX_DNS_MESSAGE_BYTES) return plain(413, 'DNS message too large');
    const ab = await req.arrayBuffer();
    if (ab.byteLength === 0) return plain(400, 'Empty DNS message');
    if (ab.byteLength > MAX_DNS_MESSAGE_BYTES) return plain(413, 'DNS message too large');
    query = Buffer.from(ab);
  } else {
    const dns = req.nextUrl.searchParams.get('dns');
    if (!dns) return plain(400, 'Missing dns parameter');
    if (dns.length > MAX_GET_PARAM_LEN) return plain(414, 'DNS message too large');
    if (!BASE64URL_RE.test(dns)) return plain(400, 'dns parameter must be base64url');
    query = Buffer.from(dns, 'base64url');
    if (query.length < 12) return plain(400, 'Malformed DNS message');
  }

  try {
    const { response, ttl } = await dnsEngine.handleDnsMessage(query, { ip, clientId });
    return new Response(new Uint8Array(response), {
      status: 200,
      headers: {
        'Content-Type': 'application/dns-message',
        // Per-device endpoints must never be stored by shared caches.
        'Cache-Control': ttl > 0 ? `${clientId ? 'private' : 'public'}, max-age=${ttl}` : 'no-store',
        ...CORS,
      },
    });
  } catch (err) {
    if (err instanceof DnsFormatError) return plain(400, 'Malformed DNS message');
    console.error('[advguard] DoH handler error:', err);
    return plain(500, 'Internal resolver error');
  }
}

export function dohOptions() {
  return new NextResponse(null, { status: 204, headers: CORS });
}
