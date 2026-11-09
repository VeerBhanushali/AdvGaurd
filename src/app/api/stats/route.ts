import { NextRequest, NextResponse } from 'next/server';
import { dnsEngine } from '@/lib/dns-engine';
import { cloudStorage } from '@/lib/cloud-storage';
import { BLOCKED_SERVICES } from '@/lib/blocked-services';
import { firewallEngine } from '@/lib/firewall';
import { userManager } from '@/lib/user-manager';

export const dynamic = 'force-dynamic';

export async function GET() {
  const stats = dnsEngine.getFullStats();
  const logs = dnsEngine.getLogs();
  const rules = dnsEngine.getRules();
  const blocklists = dnsEngine.getBlocklists();
  const cloud = cloudStorage.getStatus();

  return NextResponse.json({
    success: true,
    stats,
    logs: logs.slice(0, 150),
    rules,
    blocklists,
    cloud,
    availableServices: BLOCKED_SERVICES,
  });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    if (body.action === 'set-protection' && body.enabled !== undefined) {
      dnsEngine.setProtection(body.enabled);
      return NextResponse.json({ success: true });
    }

    if (body.action === 'set-safesearch' && body.enabled !== undefined) {
      dnsEngine.setSafeSearch(body.enabled);
      return NextResponse.json({ success: true });
    }

    if (body.action === 'set-safebrowsing' && body.enabled !== undefined) {
      dnsEngine.setSafeBrowsing(body.enabled);
      return NextResponse.json({ success: true });
    }

    if (body.action === 'update-firewall' && body.config) {
      firewallEngine.updateConfig(body.config);
      return NextResponse.json({ success: true });
    }

    if (body.action === 'register-device' && body.name && body.token) {
      const dev = userManager.registerDevice(body.name, body.token);
      return NextResponse.json({ success: true, device: dev });
    }

    if (body.action === 'delete-device' && body.id) {
      const ok = userManager.deleteDevice(body.id);
      return NextResponse.json({ success: ok });
    }

    if (body.action === 'clear-logs') {
      dnsEngine.clearLogs();
      return NextResponse.json({ success: true });
    }

    if (body.action === 'toggle-service' && body.serviceId && body.enabled !== undefined) {
      dnsEngine.toggleBlockedService(body.serviceId, body.enabled);
      return NextResponse.json({ success: true });
    }

    if (body.action === 'add-rewrite' && body.domain && body.answer) {
      dnsEngine.addRewrite(body.domain, body.answer);
      return NextResponse.json({ success: true });
    }

    if (body.action === 'delete-rewrite' && body.id) {
      dnsEngine.deleteRewrite(body.id);
      return NextResponse.json({ success: true });
    }

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
