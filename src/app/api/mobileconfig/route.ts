import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const host = req.headers.get('host') || 'localhost:3001';
  const protocol = req.headers.get('x-forwarded-proto') || 'https';
  const dohUrl = `${protocol}://${host}/dns-query`;

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
                <string>${dohUrl}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures private encrypted DNS-over-HTTPS with ad-blocking</string>
            <key>PayloadDisplayName</key>
            <string>AdGuard Web DoH Profile</string>
            <key>PayloadIdentifier</key>
            <string>com.adguardweb.doh</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>B4E2B1F9-3B01-4F43-A7D9-715C13D1A5B8</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>AdGuard Web Encrypted DNS</string>
    <key>PayloadIdentifier</key>
    <string>com.adguardweb.profile</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>4DF32C9E-80A7-46BE-9897-4CFCE332D682</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;

  return new NextResponse(payload, {
    headers: {
      'Content-Type': 'application/x-apple-aspen-config',
      'Content-Disposition': 'attachment; filename="adguard-web.mobileconfig"',
    },
  });
}

