export const DEFAULT_BLOCKED_DOMAINS = new Set([
  // Google Ads & Tracking
  'doubleclick.net',
  'pagead2.googlesyndication.com',
  'google-analytics.com',
  'adservice.google.com',
  'adservice.google.co.in',
  'googletagmanager.com',
  'googletagservices.com',
  'analytics.google.com',
  'stats.g.doubleclick.net',
  'admob.com',
  'app-measurement.com',

  // Meta / Facebook Tracking
  'graph.facebook.com',
  'pixel.facebook.com',
  'an.facebook.com',
  'connect.facebook.net',
  'analytics.facebook.com',

  // Major Ad Networks
  'criteo.com',
  'criteo.net',
  'outbrain.com',
  'taboola.com',
  'adnxs.com',
  'rubiconproject.com',
  'pubmatic.com',
  'casale-media.com',
  'openx.net',
  'adroll.com',
  'smartadserver.com',
  'amazon-adsystem.com',
  'ads.tiktok.com',
  'analytics.tiktok.com',

  // Mobile App Telemetry & Trackers
  'appsflyer.com',
  'applovin.com',
  'adjust.com',
  'branch.io',
  'flurry.com',
  'kochava.com',
  'mixpanel.com',
  'segment.io',
  'amplitude.com',
  'telemetry.sdk.sensor-tower.com',

  // Device Telemetry (Xiaomi, Samsung, Microsoft)
  'tracking.miui.com',
  'data.mistat.xiaomi.com',
  'samsung-telemetry.com',
  'samsungcloudplatform.com',
  'v10.events.data.microsoft.com',
  'telemetry.microsoft.com',
  'vortex.data.microsoft.com',
  'browser.pipe.aria.microsoft.com',

  // Popups & Annoyances
  'popads.net',
  'propellerads.com',
  'adsterra.com',
  'exoclick.com',
  'mgid.com',
  'adkeeper.co.uk',
]);

export interface CuratedListDef {
  id: string;
  name: string;
  description: string;
  curator: string;
  count: number;
  updatedAt: string;
  category: string;
}

/**
 * Lists that ship inside this repository. Counts are computed from the real
 * data – no inflated marketing numbers. Large-scale coverage comes from the
 * third-party upstream lists in REMOTE_BLOCKLISTS below.
 */
export const CURATED_ADVGUARD_LISTS: CuratedListDef[] = [
  {
    id: 'advguard-starter',
    name: 'AdvGuard Starter List',
    description:
      'Hand-picked ad networks, trackers and OS/app telemetry endpoints. Small, fast and low on false positives – works offline with no list downloads.',
    curator: 'Veer Bhanushali',
    count: DEFAULT_BLOCKED_DOMAINS.size,
    updatedAt: 'Ships with release',
    category: 'Ads & Trackers',
  },
];

export interface RemoteListDef {
  id: string;
  name: string;
  url: string;
  category: string;
  license: string;
  homepage: string;
}

/**
 * Well-maintained community lists, fetched at startup and refreshed daily.
 * They are NOT redistributed by AdvGuard – each instance downloads them
 * directly from the maintainer. Override with BLOCKLIST_URLS (comma-separated)
 * or disable with REMOTE_BLOCKLISTS=false (e.g. on tiny shared-hosting plans).
 */
export const REMOTE_BLOCKLISTS: RemoteListDef[] = [
  {
    id: 'hagezi-pro',
    name: 'HaGeZi Multi PRO',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt',
    category: 'Ads, Trackers, Malware',
    license: 'GPL-3.0',
    homepage: 'https://github.com/hagezi/dns-blocklists',
  },
];

export function getRemoteListDefs(): RemoteListDef[] {
  if (process.env.REMOTE_BLOCKLISTS === 'false') return [];
  const custom = (process.env.BLOCKLIST_URLS || '')
    .split(',')
    .map((u) => u.trim())
    .filter((u) => /^https:\/\//.test(u));
  if (custom.length === 0) return REMOTE_BLOCKLISTS;
  return custom.map((url, i) => ({
    id: `custom-${i + 1}`,
    name: new URL(url).hostname + new URL(url).pathname,
    url,
    category: 'Custom',
    license: 'See source',
    homepage: url,
  }));
}

export function generateRawBlocklist(listId: string): string | null {
  const list = CURATED_ADVGUARD_LISTS.find((l) => l.id === listId);
  if (!list) return null;
  const header =
    `! Title: ${list.name}\n` +
    `! Description: ${list.description}\n` +
    `! Curator: ${list.curator}\n` +
    `! Homepage: https://github.com/VeerBhanushali/AdvGaurd\n` +
    `! License: MIT\n` +
    `! Entries: ${DEFAULT_BLOCKED_DOMAINS.size}\n` +
    `! --------------------------------------------------\n`;
  return header + Array.from(DEFAULT_BLOCKED_DOMAINS).map((d) => `||${d}^`).join('\n') + '\n';
}

export function cleanDomain(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '');
}

export function parseRule(rule: string): { domain: string; isAllow: boolean } | null {
  const trimmed = rule.trim();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) {
    return null;
  }

  // Allow rule: @@||domain.com^
  if (trimmed.startsWith('@@||')) {
    const d = cleanDomain(trimmed.slice(4).replace(/\^.*$/, ''));
    return /^[a-z0-9._-]+$/.test(d) && d.includes('.') ? { domain: d, isAllow: true } : null;
  }

  // AdGuard block rule: ||domain.com^
  if (trimmed.startsWith('||')) {
    const d = cleanDomain(trimmed.slice(2).replace(/\^.*$/, ''));
    return /^[a-z0-9._-]+$/.test(d) && d.includes('.') ? { domain: d, isAllow: false } : null;
  }

  // Hosts format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
  const hostsMatch = trimmed.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)/);
  if (hostsMatch) {
    return { domain: cleanDomain(hostsMatch[1]), isAllow: false };
  }

  // Plain domain (anything else – regex, cosmetic or modifier rules – is ignored)
  if (/^[a-z0-9.*_-]+$/i.test(trimmed) && !trimmed.includes('*')) {
    return { domain: cleanDomain(trimmed), isAllow: false };
  }
  return null;
}
