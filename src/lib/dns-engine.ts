import dnsPacket from 'dns-packet';
import {
  cleanDomain,
  DEFAULT_BLOCKED_DOMAINS,
  parseRule,
  CURATED_ADVGUARD_LISTS,
  CuratedListDef,
  getRemoteListDefs,
} from './blocklists';
import { EngineStats, QueryLogEntry, CustomRule } from './types';
import { cloudStorage } from './cloud-storage';
import { BLOCKED_SERVICES } from './blocked-services';
import { firewallEngine, FirewallConfig } from './firewall';
import { userManager, DeviceProfile, UserAccount } from './user-manager';
import { displayIp, isValidHostname } from './security';
import { isIP } from 'net';
import { randomBytes } from 'crypto';

export interface SubscribedList {
  id: string;
  name: string;
  url: string;
  count: number;
  enabled: boolean;
  category: string;
  lastUpdated?: number;
  error?: string;
}

export interface DnsRewrite {
  id: string;
  domain: string;
  answer: string;
}

export interface AdGuardFullStats extends EngineStats {
  protectionEnabled: boolean;
  safeSearchEnabled: boolean;
  safeBrowsingEnabled: boolean;
  malwareBlockedCount: number;
  adultBlockedCount: number;
  avgLatencyMs: number;
  topClients: { client: string; count: number }[];
  topUpstreams: { upstream: string; count: number; avgMs: number }[];
  chartData: { time: string; queries: number; blocked: number }[];
  rewrites: DnsRewrite[];
  blockedServiceIds: string[];
  firewall: {
    blocksCount: number;
    config: FirewallConfig;
  };
  curatedLists: CuratedListDef[];
  devices: DeviceProfile[];
  users: UserAccount[];
}

export interface DnsRequestContext {
  /** Raw client IP – used only in-request; never stored. */
  ip: string;
  /** Validated device token from /dns-query/[clientId]. */
  clientId?: string;
}

export interface DnsResult {
  response: Buffer;
  /** Seconds the response may be cached by HTTP caches (RFC 8484 §5.1). */
  ttl: number;
}

const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 } as const;
const BLOCK_TTL = 300;
const MIN_CACHE_TTL = 10;
const MAX_CACHE_TTL = 3600;
const MAX_UPSTREAM_BYTES = 65_535;
const MAX_COUNTER_KEYS = 5_000;
const LIST_REFRESH_MS = 24 * 60 * 60 * 1000;
const MAX_LIST_BYTES = 40 * 1024 * 1024;

/** SafeSearch enforcement via CNAME, as documented by each provider. */
const SAFE_SEARCH_CNAMES: Record<string, string> = {
  'www.google.com': 'forcesafesearch.google.com',
  'google.com': 'forcesafesearch.google.com',
  'www.bing.com': 'strict.bing.com',
  'bing.com': 'strict.bing.com',
  'duckduckgo.com': 'safe.duckduckgo.com',
  'www.duckduckgo.com': 'safe.duckduckgo.com',
  'www.youtube.com': 'restrict.youtube.com',
  'm.youtube.com': 'restrict.youtube.com',
  'youtube.com': 'restrict.youtube.com',
  'youtubei.googleapis.com': 'restrict.youtube.com',
  'youtube.googleapis.com': 'restrict.youtube.com',
  'www.youtube-nocookie.com': 'restrict.youtube.com',
};

function newId(): string {
  return randomBytes(6).toString('hex');
}

/** Increments a counter map while keeping it bounded (public instances see unbounded domain cardinality). */
function bump(map: Map<string, number>, key: string, by = 1) {
  map.set(key, (map.get(key) || 0) + by);
  if (map.size > MAX_COUNTER_KEYS) {
    const sorted = Array.from(map.entries()).sort((a, b) => a[1] - b[1]);
    for (let i = 0; i < sorted.length / 2; i++) map.delete(sorted[i][0]);
  }
}

function top<T extends string>(map: Map<string, number>, n: number, label: T) {
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k, count]) => ({ [label]: k, count }) as Record<T, string> & { count: number });
}

function minTtl(packet: dnsPacket.Packet): number {
  const ttls: number[] = [];
  for (const a of packet.answers || []) if (typeof (a as any).ttl === 'number') ttls.push((a as any).ttl);
  if (ttls.length === 0) {
    // Negative answer: RFC 2308 – use SOA minimum.
    for (const a of packet.authorities || []) {
      if (a.type === 'SOA') ttls.push(Math.min((a as any).ttl ?? 60, (a as any).data?.minimum ?? 60));
    }
  }
  const t = ttls.length ? Math.min(...ttls) : 60;
  return Math.max(MIN_CACHE_TTL, Math.min(MAX_CACHE_TTL, t));
}

class DnsEngine {
  private static instance: DnsEngine;

  /** Per-list domain sets; only enabled lists participate in matching. */
  private listDomains = new Map<string, Set<string>>([['advguard-starter', new Set(DEFAULT_BLOCKED_DOMAINS)]]);
  private customBlocked = new Set<string>();
  private allowedDomains = new Set<string>();
  private customRules: CustomRule[] = [];
  private logs: QueryLogEntry[] = [];

  private totalQueries = 0;
  private blockedQueries = 0;
  private malwareBlockedCount = 0;
  private adultBlockedCount = 0;
  private resolvedCount = 0;
  private totalLatencyMs = 0;
  private startTime = Date.now();
  private domainCounts = new Map<string, number>();
  private blockedDomainCounts = new Map<string, number>();
  private clientCounts = new Map<string, number>();
  private upstreamCounts: Record<string, { count: number; totalMs: number }> = {};
  /** hour bucket (epoch hours) → counts, last 24 h only */
  private hourly = new Map<number, { queries: number; blocked: number }>();

  private blockedServiceIds = new Set<string>();
  private dnsRewrites: DnsRewrite[] = [];

  private protectionEnabled = true;
  private safeSearchEnabled = false;
  private safeBrowsingEnabled = true;

  private blocklists: SubscribedList[] = [
    {
      id: 'advguard-starter',
      name: 'AdvGuard Starter List (built-in)',
      url: '/api/blocklists/download?id=advguard-starter',
      count: DEFAULT_BLOCKED_DOMAINS.size,
      enabled: true,
      category: 'Ads & Trackers',
      lastUpdated: Date.now(),
    },
    ...getRemoteListDefs().map((l) => ({
      id: l.id,
      name: l.name,
      url: l.url,
      count: 0,
      enabled: true,
      category: `${l.category} · ${l.license}`,
    })),
  ];

  private upstreams = (process.env.UPSTREAM_DOH || 'https://dns.quad9.net/dns-query,https://cloudflare-dns.com/dns-query')
    .split(',')
    .map((u) => u.trim())
    .filter((u) => /^https:\/\//.test(u));

  private constructor() {
    if (this.blocklists.length > 1) {
      // Fire-and-forget: the starter list protects immediately while big lists download.
      setTimeout(() => this.refreshRemoteLists().catch(() => {}), 0).unref?.();
      setInterval(() => this.refreshRemoteLists().catch(() => {}), LIST_REFRESH_MS).unref?.();
    }
  }

  public static getInstance(): DnsEngine {
    if (!DnsEngine.instance) DnsEngine.instance = new DnsEngine();
    return DnsEngine.instance;
  }

  /* ------------------------------ Lists ------------------------------ */

  private async refreshRemoteLists() {
    for (const list of this.blocklists) {
      if (!list.url.startsWith('https://')) continue;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 60_000);
        const res = await fetch(list.url, { signal: controller.signal, cache: 'no-store' });
        clearTimeout(timer);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const len = Number(res.headers.get('content-length') || 0);
        if (len > MAX_LIST_BYTES) throw new Error('List too large');
        const text = await res.text();
        if (text.length > MAX_LIST_BYTES) throw new Error('List too large');

        const set = new Set<string>();
        for (const line of text.split('\n')) {
          const parsed = parseRule(line);
          if (parsed && !parsed.isAllow) set.add(parsed.domain);
        }
        this.listDomains.set(list.id, set);
        list.count = set.size;
        list.lastUpdated = Date.now();
        list.error = undefined;
        console.log(`[advguard] loaded ${set.size.toLocaleString()} domains from ${list.name}`);
      } catch (e: any) {
        list.error = e?.name === 'AbortError' ? 'Timed out' : String(e?.message || 'Failed');
        console.warn(`[advguard] failed to load ${list.name}: ${list.error}`);
      }
    }
  }

  private matchInSets(candidate: string): string | null {
    if (this.customBlocked.has(candidate)) return 'Custom rule';
    for (const list of this.blocklists) {
      if (list.enabled && this.listDomains.get(list.id)?.has(candidate)) return list.name;
    }
    return null;
  }

  /* ----------------------------- Matching ---------------------------- */

  public isDomainBlocked(domain: string): { blocked: boolean; matchedDomain?: string } {
    if (!this.protectionEnabled) return { blocked: false };
    const clean = cleanDomain(domain);

    if (this.isAllowed(clean)) return { blocked: false };

    if (this.blockedServiceIds.size > 0) {
      for (const service of BLOCKED_SERVICES) {
        if (!this.blockedServiceIds.has(service.id)) continue;
        for (const sDomain of service.domains) {
          if (clean === sDomain || clean.endsWith('.' + sDomain)) {
            return { blocked: true, matchedDomain: `Blocked Service: ${service.name}` };
          }
        }
      }
    }

    // Walk from the full name up to the registrable parent: a.ads.example.com → ads.example.com → example.com
    const parts = clean.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const candidate = parts.slice(i).join('.');
      const hit = this.matchInSets(candidate);
      if (hit) return { blocked: true, matchedDomain: `${candidate} (${hit})` };
    }
    return { blocked: false };
  }

  private isAllowed(clean: string): boolean {
    if (this.allowedDomains.size === 0) return false;
    const parts = clean.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      if (this.allowedDomains.has(parts.slice(i).join('.'))) return true;
    }
    return false;
  }

  /* ----------------------------- Resolving --------------------------- */

  private reply(query: dnsPacket.Packet, rcode: number, answers: dnsPacket.Answer[] = []): Buffer {
    const rd = (query.flags || 0) & dnsPacket.RECURSION_DESIRED;
    return dnsPacket.encode({
      type: 'response',
      id: query.id,
      flags: rd | dnsPacket.RECURSION_AVAILABLE | rcode,
      questions: query.questions,
      answers,
    });
  }

  private blockedReply(query: dnsPacket.Packet, qName: string, qType: string): Buffer {
    // Null-IP for A/AAAA (fastest for clients), NODATA for everything else.
    const answers: dnsPacket.Answer[] = [];
    if (qType === 'A') answers.push({ type: 'A', name: qName, ttl: BLOCK_TTL, data: '0.0.0.0' });
    if (qType === 'AAAA') answers.push({ type: 'AAAA', name: qName, ttl: BLOCK_TTL, data: '::' });
    return this.reply(query, RCODE.NOERROR, answers);
  }

  private async forward(queryBuffer: Buffer): Promise<{ buf: Buffer; upstream: string } | null> {
    for (const upstream of this.upstreams) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2500);
      try {
        const res = await fetch(upstream, {
          method: 'POST',
          headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' },
          body: new Uint8Array(queryBuffer),
          signal: controller.signal,
          cache: 'no-store',
        });
        if (!res.ok) continue;
        const ab = await res.arrayBuffer();
        if (ab.byteLength === 0 || ab.byteLength > MAX_UPSTREAM_BYTES) continue;
        return { buf: Buffer.from(ab), upstream: new URL(upstream).host };
      } catch {
        continue;
      } finally {
        clearTimeout(timer);
      }
    }
    return null;
  }

  public async handleDnsMessage(queryBuffer: Buffer, ctx: DnsRequestContext): Promise<DnsResult> {
    const start = Date.now();
    let query: dnsPacket.Packet;
    try {
      query = dnsPacket.decode(queryBuffer);
    } catch {
      throw new DnsFormatError();
    }
    if (query.type !== 'query' || !query.questions || query.questions.length !== 1) {
      return { response: this.reply(query, RCODE.FORMERR), ttl: 0 };
    }

    const question = query.questions[0];
    const qName = question.name || '';
    const qType = String(question.type || 'A');
    const domain = cleanDomain(qName);
    const clientLabel = ctx.clientId ? `${ctx.clientId} (${displayIp(ctx.ip)})` : displayIp(ctx.ip);

    // RFC 8482: refuse ANY – it is only ever used for amplification and enumeration.
    if (qType === 'ANY') return { response: this.reply(query, RCODE.NOTIMP), ttl: 0 };

    const device = ctx.clientId ? userManager.getDeviceByToken(ctx.clientId) : undefined;
    if (device && device.status === 'revoked') return { response: this.reply(query, RCODE.REFUSED), ttl: 0 };

    this.totalQueries++;
    bump(this.domainCounts, domain);
    bump(this.clientCounts, clientLabel);

    const log = (blocked: boolean, extra: Partial<QueryLogEntry>) =>
      this.recordLog(
        {
          id: newId(),
          timestamp: Date.now(),
          domain,
          type: qType,
          clientIp: clientLabel,
          blocked,
          elapsedMs: Date.now() - start,
          ...extra,
        },
        ctx.clientId
      );

    const blocked = (reason: string, kind?: 'malware' | 'adult') => {
      this.blockedQueries++;
      if (kind === 'malware') this.malwareBlockedCount++;
      if (kind === 'adult') this.adultBlockedCount++;
      bump(this.blockedDomainCounts, domain);
      log(true, { ruleMatched: reason });
      return { response: this.blockedReply(query, qName, qType), ttl: BLOCK_TTL };
    };

    const paused = device?.status === 'paused';
    const filtering = this.protectionEnabled && !paused;
    const allowed = this.isAllowed(domain);

    // 1. Smart firewall (user allowlist always wins)
    if (filtering && !allowed && this.safeBrowsingEnabled) {
      const fw = firewallEngine.inspectDomain(domain);
      if (fw.blocked) return blocked(fw.reason || 'Firewall', 'malware');
    }

    // 2. DNS rewrites
    const rewrite = this.dnsRewrites.find((r) => r.domain === domain);
    if (rewrite) {
      const family = isIP(rewrite.answer);
      const answers: dnsPacket.Answer[] = [];
      if (family === 4 && qType === 'A') answers.push({ type: 'A', name: qName, ttl: 300, data: rewrite.answer });
      else if (family === 6 && qType === 'AAAA') answers.push({ type: 'AAAA', name: qName, ttl: 300, data: rewrite.answer });
      else if (family === 0 && (qType === 'A' || qType === 'AAAA' || qType === 'CNAME'))
        answers.push({ type: 'CNAME', name: qName, ttl: 300, data: rewrite.answer });
      log(false, { upstream: 'Rewrite', ruleMatched: `Rewrite → ${rewrite.answer}` });
      return { response: this.reply(query, RCODE.NOERROR, answers), ttl: 300 };
    }

    // 3. Blocklists, services, custom rules
    if (filtering) {
      const check = this.isDomainBlocked(domain);
      if (check.blocked) return blocked(check.matchedDomain || 'Blocklist');
    }

    // 4. SafeSearch (CNAME to the provider's enforced endpoint)
    if (filtering && this.safeSearchEnabled && (qType === 'A' || qType === 'AAAA')) {
      const target = SAFE_SEARCH_CNAMES[domain];
      if (target) {
        const sub = dnsPacket.encode({
          type: 'query',
          id: 0,
          flags: dnsPacket.RECURSION_DESIRED,
          questions: [{ type: qType as any, name: target }],
        });
        const res = await this.forward(sub);
        if (res) {
          const decoded = dnsPacket.decode(res.buf);
          const answers: dnsPacket.Answer[] = [
            { type: 'CNAME', name: qName, ttl: 300, data: target },
            ...(decoded.answers || []),
          ];
          this.adultBlockedCount++;
          log(false, { upstream: res.upstream, ruleMatched: `SafeSearch → ${target}` });
          return { response: this.reply(query, RCODE.NOERROR, answers), ttl: 300 };
        }
      }
    }

    // 5. In-memory cache
    const cached = await cloudStorage.getCachedDns(domain, qType);
    if (cached) {
      try {
        const packet = dnsPacket.decode(Buffer.from(cached, 'base64'));
        packet.id = query.id;
        log(false, { upstream: 'RAM cache' });
        return { response: dnsPacket.encode(packet), ttl: minTtl(packet) };
      } catch {
        /* fall through to upstream */
      }
    }

    // 6. Upstream DoH
    const res = await this.forward(queryBuffer);
    const elapsed = Date.now() - start;
    if (!res) {
      log(false, { upstream: 'none', ruleMatched: 'SERVFAIL: all upstreams failed' });
      return { response: this.reply(query, RCODE.SERVFAIL), ttl: 0 };
    }

    let ttl = 60;
    try {
      const decoded = dnsPacket.decode(res.buf);
      ttl = minTtl(decoded);
      const rcode = (decoded.flags || 0) & 0xf;
      if (decoded.id === query.id && (rcode === RCODE.NOERROR || rcode === RCODE.NXDOMAIN) && !(decoded.flags! & 0x200)) {
        cloudStorage.setCachedDns(domain, qType, res.buf.toString('base64'), ttl).catch(() => {});
      }
    } catch {
      return { response: this.reply(query, RCODE.SERVFAIL), ttl: 0 };
    }

    this.resolvedCount++;
    this.totalLatencyMs += elapsed;
    const u = (this.upstreamCounts[res.upstream] ||= { count: 0, totalMs: 0 });
    u.count++;
    u.totalMs += elapsed;
    log(false, { upstream: res.upstream });
    return { response: res.buf, ttl };
  }

  /* --------------------------- Admin actions -------------------------- */

  public setProtection(enabled: boolean) {
    this.protectionEnabled = enabled;
  }

  public setSafeSearch(enabled: boolean) {
    this.safeSearchEnabled = enabled;
  }

  public setSafeBrowsing(enabled: boolean) {
    this.safeBrowsingEnabled = enabled;
  }

  public toggleBlockedService(serviceId: string, enabled: boolean): boolean {
    if (!BLOCKED_SERVICES.some((s) => s.id === serviceId)) return false;
    if (enabled) this.blockedServiceIds.add(serviceId);
    else this.blockedServiceIds.delete(serviceId);
    return true;
  }

  public addRewrite(domainRaw: string, answerRaw: string): boolean {
    const domain = cleanDomain(domainRaw);
    const answer = answerRaw.trim().toLowerCase();
    if (!isValidHostname(domain)) return false;
    if (!isIP(answer) && !isValidHostname(answer)) return false;
    if (this.dnsRewrites.length >= 1000) return false;
    this.dnsRewrites = this.dnsRewrites.filter((r) => r.domain !== domain);
    this.dnsRewrites.push({ id: newId(), domain, answer });
    return true;
  }

  public deleteRewrite(id: string) {
    this.dnsRewrites = this.dnsRewrites.filter((r) => r.id !== id);
  }

  public addRule(ruleStr: string): boolean {
    if (ruleStr.length > 300 || this.customRules.length >= 10_000) return false;
    const parsed = parseRule(ruleStr);
    if (!parsed || !isValidHostname(parsed.domain)) return false;
    (parsed.isAllow ? this.allowedDomains : this.customBlocked).add(parsed.domain);
    this.customRules.push({
      id: newId(),
      pattern: ruleStr.trim(),
      type: parsed.isAllow ? 'allow' : 'block',
      enabled: true,
      createdAt: Date.now(),
    });
    return true;
  }

  public deleteRule(id: string): boolean {
    const idx = this.customRules.findIndex((r) => r.id === id);
    if (idx === -1) return false;
    const [rule] = this.customRules.splice(idx, 1);
    const parsed = parseRule(rule.pattern);
    if (parsed) {
      const stillUsed = this.customRules.some((r) => parseRule(r.pattern)?.domain === parsed.domain && r.type === rule.type);
      if (!stillUsed) (parsed.isAllow ? this.allowedDomains : this.customBlocked).delete(parsed.domain);
    }
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

  /* ------------------------------ Stats ------------------------------ */

  public getFullStats(): AdGuardFullStats {
    const uptime = Math.floor((Date.now() - this.startTime) / 1000);
    const pct = this.totalQueries > 0 ? (this.blockedQueries / this.totalQueries) * 100 : 0;

    const topUpstreams = Object.entries(this.upstreamCounts)
      .sort((a, b) => b[1].count - a[1].count)
      .map(([upstream, d]) => ({ upstream, count: d.count, avgMs: Math.round(d.totalMs / Math.max(1, d.count)) }));

    const totalBlocklistRules = this.blocklists.reduce((acc, b) => acc + (b.enabled ? b.count : 0), 0);

    const nowHour = Math.floor(Date.now() / 3_600_000);
    const chartData = Array.from({ length: 24 }, (_, i) => {
      const h = nowHour - 23 + i;
      const b = this.hourly.get(h) || { queries: 0, blocked: 0 };
      const label = new Date(h * 3_600_000).toISOString().slice(11, 16);
      return { time: `${label} UTC`, queries: b.queries, blocked: b.blocked };
    });

    return {
      totalQueries: this.totalQueries,
      blockedQueries: this.blockedQueries,
      blockedPercentage: parseFloat(pct.toFixed(1)),
      uptimeSeconds: uptime,
      topDomains: top(this.domainCounts, 6, 'domain'),
      topBlockedDomains: top(this.blockedDomainCounts, 6, 'domain'),
      topClients: top(this.clientCounts, 6, 'client'),
      topUpstreams,
      chartData,
      rulesCount: totalBlocklistRules + this.customRules.length,
      protectionEnabled: this.protectionEnabled,
      safeSearchEnabled: this.safeSearchEnabled,
      safeBrowsingEnabled: this.safeBrowsingEnabled,
      malwareBlockedCount: this.malwareBlockedCount,
      adultBlockedCount: this.adultBlockedCount,
      avgLatencyMs: this.resolvedCount ? Math.round(this.totalLatencyMs / this.resolvedCount) : 0,
      rewrites: this.dnsRewrites,
      blockedServiceIds: Array.from(this.blockedServiceIds),
      firewall: { blocksCount: firewallEngine.getBlocksCount(), config: firewallEngine.getConfig() },
      curatedLists: CURATED_ADVGUARD_LISTS,
      devices: userManager.getDevices(),
      users: userManager.getUsers(),
    };
  }

  public getLogs(): QueryLogEntry[] {
    return this.logs;
  }

  public getRules(): CustomRule[] {
    return this.customRules;
  }

  public clearLogs() {
    this.logs = [];
  }

  private recordLog(entry: QueryLogEntry, clientId?: string) {
    this.logs.unshift(entry);
    if (this.logs.length > 500) this.logs.pop();

    const hour = Math.floor(entry.timestamp / 3_600_000);
    const b = this.hourly.get(hour) || { queries: 0, blocked: 0 };
    b.queries++;
    if (entry.blocked) b.blocked++;
    this.hourly.set(hour, b);
    if (this.hourly.size > 25) {
      for (const h of this.hourly.keys()) if (h < hour - 23) this.hourly.delete(h);
    }

    userManager.recordDeviceActivity(clientId, entry.blocked);
    cloudStorage.saveQueryLog(entry).catch(() => {});
  }
}

export class DnsFormatError extends Error {
  constructor() {
    super('Malformed DNS message');
  }
}

export const dnsEngine = DnsEngine.getInstance();
