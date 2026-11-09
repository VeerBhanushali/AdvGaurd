import { NextRequest } from 'next/server';
import { handleDoh, dohOptions } from '@/lib/doh-handler';

export const dynamic = 'force-dynamic';

/** RFC 8484 DNS-over-HTTPS endpoint (GET ?dns=<base64url> and POST application/dns-message). */
export async function GET(req: NextRequest) {
  return handleDoh(req);
}

export async function POST(req: NextRequest) {
  return handleDoh(req);
}

export async function OPTIONS() {
  return dohOptions();
}
