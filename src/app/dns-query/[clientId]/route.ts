import { NextRequest, NextResponse } from 'next/server';
import { dnsEngine } from '@/lib/dns-engine';

export const dynamic = 'force-dynamic';

export async function POST(
  req: NextRequest,
  { params }: { params: { clientId: string } }
) {
  try {
    const rawIp = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || '127.0.0.1';
    const clientIdentifier = `${params.clientId} [${rawIp}]`;

    const arrayBuffer = await req.arrayBuffer();
    const queryBuffer = Buffer.from(arrayBuffer);

    if (queryBuffer.length === 0) {
      return new NextResponse('Empty DNS query', { status: 400 });
    }

    const responseBuffer = await dnsEngine.handleDnsMessage(queryBuffer, clientIdentifier);

    return new Response(new Uint8Array(responseBuffer), {
      status: 200,
      headers: {
        'Content-Type': 'application/dns-message',
        'Cache-Control': 'max-age=300',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (err: any) {
    return new NextResponse(`DNS resolution error: ${err?.message}`, { status: 500 });
  }
}

export async function GET(
  req: NextRequest,
  { params }: { params: { clientId: string } }
) {
  try {
    const rawIp = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || '127.0.0.1';
    const clientIdentifier = `${params.clientId} [${rawIp}]`;

    const { searchParams } = new URL(req.url);
    const dnsBase64 = searchParams.get('dns');

    if (!dnsBase64) {
      return new NextResponse('Missing dns parameter', { status: 400 });
    }

    const base64 = dnsBase64.replace(/-/g, '+').replace(/_/g, '/');
    const queryBuffer = Buffer.from(base64, 'base64');

    const responseBuffer = await dnsEngine.handleDnsMessage(queryBuffer, clientIdentifier);

    return new Response(new Uint8Array(responseBuffer), {
      status: 200,
      headers: {
        'Content-Type': 'application/dns-message',
        'Cache-Control': 'max-age=300',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (err: any) {
    return new NextResponse(`DNS resolution error: ${err?.message}`, { status: 500 });
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Accept',
    },
  });
}
