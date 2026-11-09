import { NextRequest, NextResponse } from 'next/server';
import dnsPacket from 'dns-packet';
import { dnsEngine } from '@/lib/dns-engine';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const name = searchParams.get('name');
  const type = (searchParams.get('type') || 'A').toUpperCase();

  if (!name) {
    return NextResponse.json({ Status: 2, Comment: 'Missing name parameter' }, { status: 400 });
  }

  try {
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || '127.0.0.1';

    // Encode DNS question into wire format
    const queryBuffer = dnsPacket.encode({
      type: 'query',
      id: Math.floor(Math.random() * 65535),
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [
        {
          type: type as any,
          name,
        },
      ],
    });

    const responseBuffer = await dnsEngine.handleDnsMessage(queryBuffer, clientIp);
    const decoded = dnsPacket.decode(responseBuffer);

    const answers = decoded.answers?.map((ans) => ({
      name: ans.name,
      type: ans.type,
      TTL: (ans as any).ttl ?? 300,
      data: (ans as any).data,
    })) || [];

    const isBlocked = answers.some((a) => a.data === '0.0.0.0' || a.data === '::');

    return NextResponse.json({
      Status: 0,
      TC: false,
      RD: true,
      RA: true,
      AD: false,
      CD: false,
      Question: [{ name, type }],
      Answer: answers,
      Blocked: isBlocked,
    });
  } catch (err: any) {
    return NextResponse.json({ Status: 2, Comment: err.message }, { status: 500 });
  }
}

