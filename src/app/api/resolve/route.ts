import { NextRequest, NextResponse } from 'next/server';
import dnsPacket from 'dns-packet';
import { randomInt } from 'crypto';
import { dnsEngine } from '@/lib/dns-engine';
import { enforceRateLimit } from '@/lib/doh-handler';
import { getClientIp, isValidHostname } from '@/lib/security';
import { cleanDomain } from '@/lib/blocklists';

export const dynamic = 'force-dynamic';

const ALLOWED_TYPES = new Set(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'HTTPS', 'SVCB']);
const RCODES: Record<string, number> = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };

/** JSON DNS API (Google/Cloudflare-style): /api/resolve?name=example.com&type=A */
export async function GET(req: NextRequest) {
  const name = cleanDomain(req.nextUrl.searchParams.get('name') || '');
  const type = (req.nextUrl.searchParams.get('type') || 'A').toUpperCase();

  if (!name || !isValidHostname(name)) {
    return NextResponse.json({ Status: 1, Comment: 'Invalid or missing name' }, { status: 400 });
  }
  if (!ALLOWED_TYPES.has(type)) {
    return NextResponse.json({ Status: 4, Comment: 'Unsupported record type' }, { status: 400 });
  }

  const ip = getClientIp(req.headers);
  const limited = enforceRateLimit(ip);
  if (limited) return limited;

  try {
    const query = dnsPacket.encode({
      type: 'query',
      id: randomInt(0, 65535),
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: type as dnsPacket.RecordType, name }],
    });
    const { response, ttl } = await dnsEngine.handleDnsMessage(query, { ip });
    const decoded = dnsPacket.decode(response);

    const answers = (decoded.answers || []).map((a: any) => ({
      name: a.name,
      type: a.type,
      TTL: a.ttl ?? 0,
      data: typeof a.data === 'string' ? a.data : JSON.stringify(a.data),
    }));

    return NextResponse.json(
      {
        Status: RCODES[(decoded as any).rcode] ?? 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [{ name, type }],
        Answer: answers,
        Blocked: answers.some((a) => a.data === '0.0.0.0' || a.data === '::'),
      },
      { headers: { 'Cache-Control': ttl > 0 ? `public, max-age=${ttl}` : 'no-store' } }
    );
  } catch (err) {
    console.error('[advguard] resolve error:', err);
    return NextResponse.json({ Status: 2, Comment: 'Resolver error' }, { status: 500 });
  }
}
