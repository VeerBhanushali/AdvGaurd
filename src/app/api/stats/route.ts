import { NextRequest, NextResponse } from 'next/server';
import { dnsEngine } from '@/lib/dns-engine';
import { cloudStorage } from '@/lib/cloud-storage';

export const dynamic = 'force-dynamic';

export async function GET() {
  const stats = dnsEngine.getStats();
  const logs = dnsEngine.getLogs();
  const rules = dnsEngine.getRules();
  const blocklists = dnsEngine.getBlocklists();
  const cloud = cloudStorage.getStatus();

  return NextResponse.json({
    success: true,
    stats,
    logs: logs.slice(0, 100),
    rules,
    blocklists,
    cloud,
  });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    if (body.action === 'add-rule' && body.rule) {
      const ok = dnsEngine.addRule(body.rule);
      return NextResponse.json({ success: ok });
    }

    if (body.action === 'delete-rule' && body.id) {
      const ok = dnsEngine.deleteRule(body.id);
      return NextResponse.json({ success: ok });
    }

    if (body.action === 'toggle-blocklist' && body.id !== undefined && body.enabled !== undefined) {
      const ok = dnsEngine.toggleBlocklist(body.id, body.enabled);
      return NextResponse.json({ success: ok });
    }

    if (body.action === 'check-domain' && body.domain) {
      const result = dnsEngine.isDomainBlocked(body.domain);
      return NextResponse.json({ success: true, result });
    }

    return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
