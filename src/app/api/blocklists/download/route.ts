import { NextRequest, NextResponse } from 'next/server';
import { generateRawBlocklist } from '@/lib/blocklists';

export const dynamic = 'force-dynamic';

/** Raw AdGuard/uBlock-syntax export of AdvGuard's own built-in lists. */
export async function GET(req: NextRequest) {
  const listId = req.nextUrl.searchParams.get('id') || 'advguard-starter';
  const content = generateRawBlocklist(listId);
  if (!content) return new NextResponse('Unknown list', { status: 404 });

  return new NextResponse(content, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${listId}.txt"`,
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
