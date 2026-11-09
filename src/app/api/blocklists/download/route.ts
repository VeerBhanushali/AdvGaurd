import { NextRequest, NextResponse } from 'next/server';
import { generateRawBlocklist } from '@/lib/blocklists';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const listId = searchParams.get('id') || 'advguard-ultra';

  const content = generateRawBlocklist(listId);

  return new NextResponse(content, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${listId}.txt"`,
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

