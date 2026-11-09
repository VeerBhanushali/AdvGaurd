// Built-in initial blocklist covering high-volume ads, telemetry, and tracking networks
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
    return { domain: d, isAllow: true };
  }

  // AdGuard block rule: ||domain.com^
  if (trimmed.startsWith('||')) {
    const d = cleanDomain(trimmed.slice(2).replace(/\^.*$/, ''));
    return { domain: d, isAllow: false };
  }

  // Hosts format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
  const hostsMatch = trimmed.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)/);
  if (hostsMatch) {
    return { domain: cleanDomain(hostsMatch[1]), isAllow: false };
  }

  // Plain domain
  return { domain: cleanDomain(trimmed), isAllow: false };
}

