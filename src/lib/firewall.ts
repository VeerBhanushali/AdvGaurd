export type ThreatLevel = 'low' | 'balanced' | 'strict' | 'paranoid';

export interface FirewallConfig {
  threatLevel: ThreatLevel;
  blockRiskyTlds: boolean;
  /**
   * Blocks devices using this resolver from reaching AI assistant services
   * (school / workplace / parental policy).
   *
   * NOTE: DNS filtering CANNOT stop AI crawlers from scraping *your website* –
   * crawlers use their own resolvers. Use robots.txt / a WAF for that.
   * The key name is kept for backwards compatibility with saved configs.
   */
  blockAiScrapers: boolean;
  blockCryptoMiners: boolean;
  /** Reserved – newly-registered-domain detection needs an RDAP/NRD feed and is not implemented yet. */
  blockNewDomains: boolean;
  rateLimitEnabled: boolean;
  maxQueriesPerMinute: number;
}

/**
 * TLDs with consistently high abuse rates in Spamhaus / Interisle reports.
 * Deliberately excludes general-purpose TLDs with large legitimate use
 * (.xyz hosts abc.xyz, .link, .win …) to avoid breaking real sites.
 */
export const RISKY_TLDS = new Set(['top', 'work', 'click', 'buzz', 'cfd', 'loan', 'gdn', 'surf', 'skin', 'tk', 'ml', 'ga', 'cf', 'gq']);

export const AI_SERVICE_DOMAINS = new Set([
  'openai.com',
  'chatgpt.com',
  'oaiusercontent.com',
  'anthropic.com',
  'claude.ai',
  'perplexity.ai',
  'gemini.google.com',
  'copilot.microsoft.com',
  'character.ai',
  'poe.com',
  'deepseek.com',
]);

export const CRYPTO_MINERS_DOMAINS = new Set([
  'coinhive.com',
  'coin-hive.com',
  'cryptoloot.pro',
  'crypto-loot.com',
  'minr.pw',
  'webminepool.com',
  'monerominer.rocks',
  'jsecoin.com',
  'coinhave.com',
  'coinimp.com',
  'authedmine.com',
]);

/** What each posture level switches on. Individual toggles can still be changed afterwards. */
export const THREAT_PRESETS: Record<ThreatLevel, Omit<FirewallConfig, 'threatLevel' | 'maxQueriesPerMinute'>> = {
  low: { blockCryptoMiners: true, blockRiskyTlds: false, blockAiScrapers: false, blockNewDomains: false, rateLimitEnabled: true },
  balanced: { blockCryptoMiners: true, blockRiskyTlds: true, blockAiScrapers: false, blockNewDomains: false, rateLimitEnabled: true },
  strict: { blockCryptoMiners: true, blockRiskyTlds: true, blockAiScrapers: true, blockNewDomains: false, rateLimitEnabled: true },
  // Paranoid additionally tightens the per-IP rate limit (see updateConfig).
  paranoid: { blockCryptoMiners: true, blockRiskyTlds: true, blockAiScrapers: true, blockNewDomains: false, rateLimitEnabled: true },
};

function matchesSuffix(domain: string, set: Set<string>): boolean {
  if (set.has(domain)) return true;
  let idx = domain.indexOf('.');
  while (idx !== -1) {
    if (set.has(domain.slice(idx + 1))) return true;
    idx = domain.indexOf('.', idx + 1);
  }
  return false;
}

class FirewallEngine {
  private static instance: FirewallEngine;
  private config: FirewallConfig = {
    threatLevel: 'balanced',
    ...THREAT_PRESETS.balanced,
    maxQueriesPerMinute: Math.min(10_000, Math.max(30, parseInt(process.env.RATE_LIMIT_PER_MINUTE || '300', 10) || 300)),
  };
  private firewallBlocksCount = 0;

  private constructor() {}

  public static getInstance(): FirewallEngine {
    if (!FirewallEngine.instance) FirewallEngine.instance = new FirewallEngine();
    return FirewallEngine.instance;
  }

  public getConfig(): FirewallConfig {
    return { ...this.config };
  }

  /** Validates untrusted input – unknown keys and wrong types are ignored. */
  public updateConfig(input: unknown) {
    if (!input || typeof input !== 'object') return;
    const c = input as Record<string, unknown>;
    const next = { ...this.config };

    if (typeof c.threatLevel === 'string' && c.threatLevel in THREAT_PRESETS && c.threatLevel !== this.config.threatLevel) {
      next.threatLevel = c.threatLevel as ThreatLevel;
      Object.assign(next, THREAT_PRESETS[next.threatLevel]);
      if (next.threatLevel === 'paranoid') next.maxQueriesPerMinute = Math.min(next.maxQueriesPerMinute, 120);
      this.config = next;
      return;
    }
    for (const key of ['blockRiskyTlds', 'blockAiScrapers', 'blockCryptoMiners', 'rateLimitEnabled'] as const) {
      if (typeof c[key] === 'boolean') next[key] = c[key] as boolean;
    }
    if (typeof c.maxQueriesPerMinute === 'number' && Number.isFinite(c.maxQueriesPerMinute)) {
      next.maxQueriesPerMinute = Math.min(10_000, Math.max(30, Math.round(c.maxQueriesPerMinute)));
    }
    this.config = next;
  }

  public getBlocksCount(): number {
    return this.firewallBlocksCount;
  }

  /** Domain-level policy. Rate limiting is enforced earlier, at the HTTP layer. */
  public inspectDomain(domain: string): { blocked: boolean; reason?: string } {
    const clean = domain.trim().toLowerCase().replace(/\.$/, '');

    if (this.config.blockCryptoMiners && matchesSuffix(clean, CRYPTO_MINERS_DOMAINS)) {
      this.firewallBlocksCount++;
      return { blocked: true, reason: 'Firewall: Cryptojacking / miner' };
    }

    if (this.config.blockAiScrapers && matchesSuffix(clean, AI_SERVICE_DOMAINS)) {
      this.firewallBlocksCount++;
      return { blocked: true, reason: 'Firewall: AI service (policy)' };
    }

    if (this.config.blockRiskyTlds) {
      const tld = clean.slice(clean.lastIndexOf('.') + 1);
      if (clean.includes('.') && RISKY_TLDS.has(tld)) {
        this.firewallBlocksCount++;
        return { blocked: true, reason: `Firewall: High-risk TLD (.${tld})` };
      }
    }

    return { blocked: false };
  }
}

export const firewallEngine = FirewallEngine.getInstance();
