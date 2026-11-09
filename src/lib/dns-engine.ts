import dnsPacket from 'dns-packet';
import { cleanDomain, DEFAULT_BLOCKED_DOMAINS, parseRule } from './blocklists';
import { EngineStats, QueryLogEntry, CustomRule } from './types';
import { cloudStorage } from './cloud-storage';

export interface SubscribedList {
  id: string;
  name: string;
  url: string;
  count: number;
  enabled: boolean;
  category: string;
}

class DnsEngine {
  private static instance: DnsEngine;
  private blockedDomains = new Set<string>(DEFAULT_BLOCKED_DOMAINS);
  private allowedDomains = new Set<string>();
  private customRules: CustomRule[] = [];
  private logs: QueryLogEntry[] = [];
  private totalQueries = 0;
  private blockedQueries = 0;
  private startTime = Date.now();
  private domainCounts: Record<string, number> = {};
  private blockedDomainCounts: Record<string, number> = {};

  private blocklists: SubscribedList[] = [
    {
      id: 'adguard-base',
      name: 'AdGuard DNS Filter',
      url: 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt',
      count: 48200,
      enabled: true,
      category: 'General Ads',
    },
    {
      id: 'oisd-big',
      name: 'OISD (Big)',
      url: 'https://big.oisd.nl',
      count: 145000,
      enabled: true,
      category: 'Zero False-Positive',
    },
    {
      id: 'hagezi-pro',
      name: 'HaGeZi Multi PRO',
      url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt',
      count: 98000,
      enabled: true,
      category: 'Malware & Trackers',
    },
    {
      id: 'windows-spy',
      name: 'Windows Spy Blocker',
      url: 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',
      count: 1200,
      enabled: true,
      category: 'OS Telemetry',
    },
  ];

  private upstreams = [
    'https://dns.quad9.net/dns-query',
    'https://cloudflare-dns.com/dns-query',
  ];

  private constructor() {}

  public static getInstance(): DnsEngine {
    if (!DnsEngine.instance) {
      DnsEngine.instance = new DnsEngine();
    }
    return DnsEngine.instance;
  }

  public isDomainBlocked(domain: string): { blocked: boolean; matchedDomain?: string } {
    const clean = cleanDomain(domain);

    // Whitelist check first
    if (this.allowedDomains.has(clean)) {
      return { blocked: false };
    }

    // Exact check
    if (this.blockedDomains.has(clean)) {
      return { blocked: true, matchedDomain: clean };
    }

    // Subdomain walk: sub.ads.example.com -> ads.example.com -> example.com
    const parts = clean.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join('.');
      if (this.allowedDomains.has(parent)) {
        return { blocked: false };
      }
      if (this.blockedDomains.has(parent)) {
        return { blocked: true, matchedDomain: parent };
      }
    }

    return { blocked: false };
  }

  public async handleDnsMessage(queryBuffer: Buffer, clientIp = '127.0.0.1'): Promise<Buffer> {
    const start = Date.now();
    let decoded: dnsPacket.Packet;

    try {
      decoded = dnsPacket.decode(queryBuffer);
    } catch {
      return Buffer.alloc(0);
    }

    const question = decoded.questions?.[0];
    const qName = question?.name || '';
    const qType = question?.type || 'A';
    const domain = cleanDomain(qName);

    this.totalQueries++;
    this.domainCounts[domain] = (this.domainCounts[domain] || 0) + 1;

    // Check Blocklists
    const blockCheck = this.isDomainBlocked(domain);

    if (blockCheck.blocked) {
      this.blockedQueries++;
      this.blockedDomainCounts[domain] = (this.blockedDomainCounts[domain] || 0) + 1;

      const elapsed = Date.now() - start;
      const logEntry: QueryLogEntry = {
        id: Math.random().toString(36).substring(2, 9),
        timestamp: Date.now(),
        domain,
        type: qType,
        clientIp,
        blocked: true,
        ruleMatched: blockCheck.matchedDomain,
        elapsedMs: elapsed,
      };
      this.recordLog(logEntry);

      // Instant AdBlock Response: 0.0.0.0 for A, :: for AAAA
      const answers: dnsPacket.Answer[] = [];
      if (qType === 'A') {
        answers.push({
          type: 'A',
          name: qName,
          ttl: 300,
          data: '0.0.0.0',
        });
      } else if (qType === 'AAAA') {
        answers.push({
          type: 'AAAA',
          name: qName,
          ttl: 300,
          data: '::',
        });
      }

      return dnsPacket.encode({
        type: 'response',
        id: decoded.id,
        flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
        questions: decoded.questions,
        answers,
      });
    }

    // Check Cloud Redis / Memory Cache
    const cachedBase64 = await cloudStorage.getCachedDns(domain, qType);
    if (cachedBase64) {
      try {
        const cachedBuf = Buffer.from(cachedBase64, 'base64');
        const cachedDecoded = dnsPacket.decode(cachedBuf);
        cachedDecoded.id = decoded.id; // align packet ID
        const finalBuf = dnsPacket.encode(cachedDecoded);

        this.recordLog({
          id: Math.random().toString(36).substring(2, 9),
          timestamp: Date.now(),
          domain,
          type: qType,
          clientIp,
          blocked: false,
          elapsedMs: Date.now() - start,
          upstream: 'Upstash / In-Memory Cache',
        });

        return finalBuf;
      } catch {
        // proceed to upstream
      }
    }

    // Forward to Upstream DoH
    let upstreamRes: Response | null = null;
    let chosenUpstream = this.upstreams[0];

    for (const upstream of this.upstreams) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 2000);

        upstreamRes = await fetch(upstream, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/dns-message',
            Accept: 'application/dns-message',
          },
          body: new Uint8Array(queryBuffer),
          signal: controller.signal,
        });
        clearTimeout(timeout);

        if (upstreamRes.ok) {
          chosenUpstream = upstream;
          break;
        }
      } catch {
        continue;
      }
    }

    const elapsed = Date.now() - start;

    if (upstreamRes && upstreamRes.ok) {
      const arrayBuf = await upstreamRes.arrayBuffer();
      const resBuffer = Buffer.from(arrayBuf);

      // Async write to Cloud Cache
      cloudStorage.setCachedDns(domain, qType, resBuffer.toString('base64'), 300).catch(() => {});

      this.recordLog({
        id: Math.random().toString(36).substring(2, 9),
        timestamp: Date.now(),
        domain,
        type: qType,
        clientIp,
        blocked: false,
        elapsedMs: elapsed,
        upstream: chosenUpstream.replace('https://', '').split('/')[0],
      });

      return resBuffer;
    }

    // Fallback NXDOMAIN
    return dnsPacket.encode({
      type: 'response',
      id: decoded.id,
      flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
      questions: decoded.questions,
      answers: [],
    });
  }

  public addRule(ruleStr: string): boolean {
    const parsed = parseRule(ruleStr);
    if (!parsed) return false;

    if (parsed.isAllow) {
      this.allowedDomains.add(parsed.domain);
    } else {
      this.blockedDomains.add(parsed.domain);
    }

    this.customRules.push({
      id: Math.random().toString(36).substring(2, 9),
      pattern: ruleStr,
      type: parsed.isAllow ? 'allow' : 'block',
      enabled: true,
      createdAt: Date.now(),
    });

    return true;
  }

  public deleteRule(id: string): boolean {
    const ruleIndex = this.customRules.findIndex((r) => r.id === id);
    if (ruleIndex === -1) return false;

    const rule = this.customRules[ruleIndex];
    const parsed = parseRule(rule.pattern);
    if (parsed) {
      if (parsed.isAllow) {
        this.allowedDomains.delete(parsed.domain);
      } else {
        this.blockedDomains.delete(parsed.domain);
      }
    }

    this.customRules.splice(ruleIndex, 1);
    return true;
  }

  public toggleBlocklist(id: string, enabled: boolean): boolean {
    const list = this.blocklists.find((b) => b.id === id);
    if (!list) return false;
    list.enabled = enabled;
    return true;
  }

  public getBlocklists(): SubscribedList[] {
    return this.blocklists;
  }

  public getStats(): EngineStats {
    const uptime = Math.floor((Date.now() - this.startTime) / 1000);
    const pct = this.totalQueries > 0 ? (this.blockedQueries / this.totalQueries) * 100 : 0;

    const topDomains = Object.entries(this.domainCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([domain, count]) => ({ domain, count }));

    const topBlockedDomains = Object.entries(this.blockedDomainCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([domain, count]) => ({ domain, count }));

    const totalBlocklistRules = this.blocklists.reduce((acc, b) => acc + (b.enabled ? b.count : 0), 0);

    return {
      totalQueries: this.totalQueries,
      blockedQueries: this.blockedQueries,
      blockedPercentage: parseFloat(pct.toFixed(1)),
      uptimeSeconds: uptime,
      topDomains,
      topBlockedDomains,
      rulesCount: totalBlocklistRules + this.customRules.length,
    };
  }

  public getLogs(): QueryLogEntry[] {
    return this.logs;
  }

  public getRules(): CustomRule[] {
    return this.customRules;
  }

  private recordLog(entry: QueryLogEntry) {
    this.logs.unshift(entry);
    if (this.logs.length > 500) {
      this.logs.pop();
    }
    // Async non-blocking save to Supabase & Redis
    cloudStorage.saveQueryLog(entry).catch(() => {});
  }
}

export const dnsEngine = DnsEngine.getInstance();
