import { NextRequest } from 'next/server';
import { handleDoh, dohOptions } from '@/lib/doh-handler';

export const dynamic = 'force-dynamic';

type Ctx = { params: { clientId: string } };

/** Per-device DoH endpoint: /dns-query/<device-token> */
export async function GET(req: NextRequest, { params }: Ctx) {
  return handleDoh(req, params.clientId);
}

export async function POST(req: NextRequest, { params }: Ctx) {
  return handleDoh(req, params.clientId);
}

export async function OPTIONS() {
  return dohOptions();
}
