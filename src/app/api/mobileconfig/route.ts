import { NextRequest, NextResponse } from 'next/server';
import { createHash } from 'crypto';
import { isValidClientId } from '@/lib/security';

export const dynamic = 'force-dynamic';

function xml(s: string): string {
  return s.replace(/[<>&'"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' })[c]!);
}

/** Deterministic UUID so re-installing the profile replaces it instead of duplicating it. */
function uuidFrom(seed: string): string {
  const h = createHash('sha256').update(seed).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`.toUpperCase();
}

/**
 * The host is taken from PUBLIC_HOSTNAME when set. Falling back to the Host
 * header is only safe because the value is validated and XML-escaped.
 */
function resolveHost(req: NextRequest): string | null {
  const configured = process.env.PUBLIC_HOSTNAME?.trim();
  const host = configured || req.headers.get('host') || '';
  return /^[a-z0-9.-]+(:\d{1,5})?$/i.test(host) ? host.toLowerCase() : null;
}

/**
 * Unsigned Apple configuration profile (iOS 14+ / macOS 11+).
 * iOS shows it as "Unverified" – that is expected for unsigned profiles.
 */
export async function GET(req: NextRequest) {
  const host = resolveHost(req);
  if (!host) return new NextResponse('Invalid host', { status: 400 });

  const device = (req.nextUrl.searchParams.get('device') || '').toLowerCase();
  if (device && !isValidClientId(device)) return new NextResponse('Invalid device token', { status: 400 });

  const dohUrl = `https://${host}/dns-query${device ? `/${device}` : ''}`;
  const id = `com.advguard.doh.${host.replace(/[^a-z0-9]/g, '-')}${device ? `.${device}` : ''}`;

  const payload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>${xml(dohUrl)}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Encrypted DNS-over-HTTPS with ad, tracker and malware blocking.</string>
            <key>PayloadDisplayName</key>
            <string>AdvGuard DNS</string>
            <key>PayloadIdentifier</key>
            <string>${xml(id)}.dns</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${uuidFrom(id + ':dns')}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Routes this device's DNS through ${xml(host)}. Remove any time in Settings › General › VPN &amp; Device Management.</string>
    <key>PayloadDisplayName</key>
    <string>AdvGuard Encrypted DNS</string>
    <key>PayloadIdentifier</key>
    <string>${xml(id)}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${uuidFrom(id)}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;

  return new NextResponse(payload, {
    headers: {
      'Content-Type': 'application/x-apple-aspen-config',
      'Content-Disposition': `attachment; filename="advguard${device ? '-' + device : ''}.mobileconfig"`,
      'Cache-Control': 'no-store',
    },
  });
}
