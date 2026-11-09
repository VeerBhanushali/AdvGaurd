export interface FirewallConfig {
  threatLevel: 'low' | 'balanced' | 'strict' | 'paranoid';
  blockRiskyTlds: boolean;
  blockAiScrapers: boolean;
  blockCryptoMiners: boolean;
  blockNewDomains: boolean;
  rateLimitEnabled: boolean;
  maxQueriesPerMinute: number;
}

export const RISKY_TLDS = new Set([
  'top',
  'xyz',
  'work',
  'click',
  'link',
  'surf',
  'fit',
  'gq',
  'cf',
  'ml',
  'tk',
  'buzz',
  'rest',
  'country',
  'loan',
  'date',
  'racing',
  'win',
]);

export const AI_SCRAPERS_DOMAINS = new Set([
  'bytespider.com',
  'claudebot.com',
  'gptbot.com',
  'commoncrawl.org',
  'perplexity.ai',
  'anthropic.com',
  'semrush.com',
  'ahrefs.com',
  'dotbot.com',
  'mj12bot.com',
  'seekport.com',
  'petalbot.com',
]);

export const CRYPTO_MINERS_DOMAINS = new Set([
  'coinhive.com',
  'coin-hive.com',
  'cryptoloot.pro',
  'minr.pw',
  'webminepool.com',
  'monerominer.rocks',
  'crypto-loot.com',
  'miner.pr0gramm.com',
  'jsecoin.com',
  'coinhave.com',
]);

class FirewallEngine {
  private static instance: FirewallEngine;
  private config: FirewallConfig = {
    threatLevel: 'balanced',
    blockRiskyTlds: true,
    blockAiScrapers: true,
    blockCryptoMiners: true,
    blockNewDomains: false,
    rateLimitEnabled: true,
    maxQueriesPerMinute: 300,
  };

  private clientQueryBuckets: Map<string, { count: number; resetTime: number }> = new Map();
  private firewallBlocksCount = 42;

  private constructor() {}

  public static getInstance(): FirewallEngine {
    if (!FirewallEngine.instance) {
      FirewallEngine.instance = new FirewallEngine();
    }
    return FirewallEngine.instance;
  }

  public getConfig(): FirewallConfig {
    return { ...this.config };
  }

  public updateConfig(newConfig: Partial<FirewallConfig>) {
    this.config = { ...this.config, ...newConfig };
  }

  public getBlocksCount(): number {
    return this.firewallBlocksCount;
  }

  public inspectDomain(domain: string, clientIp: string): { blocked: boolean; reason?: string } {
    const clean = domain.trim().toLowerCase().replace(/\.$/, '');

    // 1. Rate Limiting Check
    if (this.config.rateLimitEnabled) {
      const now = Date.now();
      let bucket = this.clientQueryBuckets.get(clientIp);
      if (!bucket || now > bucket.resetTime) {
        bucket = { count: 1, resetTime: now + 60000 };
        this.clientQueryBuckets.set(clientIp, bucket);
      } else {
        bucket.count++;
        if (bucket.count > this.config.maxQueriesPerMinute) {
          this.firewallBlocksCount++;
          return { blocked: true, reason: 'Firewall: Rate Limit Exceeded (Anti-DDoS)' };
        }
      }
    }

    // 2. Cryptomining Script Check
    if (this.config.blockCryptoMiners) {
      for (const miner of CRYPTO_MINERS_DOMAINS) {
        if (clean === miner || clean.endsWith('.' + miner)) {
          this.firewallBlocksCount++;
          return { blocked: true, reason: 'Firewall: Cryptojacking / Miner Blocked' };
        }
      }
    }

    // 3. AI Scraper & Web Crawler Check
    if (this.config.blockAiScrapers) {
      for (const bot of AI_SCRAPERS_DOMAINS) {
        if (clean === bot || clean.endsWith('.' + bot)) {
          this.firewallBlocksCount++;
          return { blocked: true, reason: 'Firewall: AI Web Scraper / Bot Blocked' };
        }
      }
    }

    // 4. Risky / Spam TLD Check
    if (this.config.blockRiskyTlds) {
      const parts = clean.split('.');
      if (parts.length > 1) {
        const tld = parts[parts.length - 1];
        if (RISKY_TLDS.has(tld)) {
          this.firewallBlocksCount++;
          return { blocked: true, reason: `Firewall: High-Risk Spam TLD (.${tld}) Blocked` };
        }
      }
    }

    return { blocked: false };
  }
}

export const firewallEngine = FirewallEngine.getInstance();
