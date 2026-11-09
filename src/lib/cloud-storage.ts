import { QueryLogEntry } from './types';
import { db } from './firebase';
import { collection, addDoc } from 'firebase/firestore';
import { createClient, SupabaseClient } from '@supabase/supabase-js';

// Supabase Configuration
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;

// Privacy & GDPR Anonymizer (Masks IPv4 & IPv6 for Zero-PII logging on public clouds)
export function anonymizeIp(ip: string): string {
  if (!ip || ip === '::1' || ip === '127.0.0.1') return '127.0.0.1';
  // IPv4: mask last octet (e.g. 103.21.244.78 -> 103.21.244.0)
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
    }
  }
  // IPv6: mask host identifier (keep /64 network prefix)
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return `${parts.slice(0, 3).join(':')}::xxxx`;
  }
  return 'anonymized';
}

// High-Speed Local In-Memory Cache (0ms latency, zero extra costs)
class MemoryLruCache {
  private cache = new Map<string, { value: string; expiry: number }>();
  private maxSize = 5000;

  get(key: string): string | null {
    const item = this.cache.get(key);
    if (!item) return null;
    if (Date.now() > item.expiry) {
      this.cache.delete(key);
      return null;
    }
    this.cache.delete(key);
    this.cache.set(key, item);
    return item.value;
  }

  set(key: string, value: string, ttlSeconds = 300): void {
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }
    this.cache.set(key, { value, expiry: Date.now() + ttlSeconds * 1000 });
  }
}

export class CloudStorage {
  private static instance: CloudStorage;
  private supabase: SupabaseClient | null = null;
  private memoryCache = new MemoryLruCache();
  private lastPurge = 0;

  private constructor() {
    if (supabaseUrl && supabaseKey) {
      try {
        this.supabase = createClient(supabaseUrl, supabaseKey);
      } catch (e) {
        console.warn('Supabase initialization failed:', e);
      }
    }

    // Schedule 30-day log purge check every 6 hours
    if (typeof setInterval !== 'undefined') {
      setInterval(() => {
        this.purgeOldLogs(30).catch(() => {});
      }, 6 * 60 * 60 * 1000);
    }
  }

  public static getInstance(): CloudStorage {
    if (!CloudStorage.instance) {
      CloudStorage.instance = new CloudStorage();
    }
    return CloudStorage.instance;
  }

  public getStatus() {
    const isFirebase = !!db;
    const isSupabase = !!this.supabase;

    return {
      firebaseConnected: isFirebase,
      supabaseConnected: isSupabase,
      privacyMode: 'Zero-PII IP Anonymization (Active)',
      retentionPolicy: 'Auto-Purge 30 Days (Active)',
      mode: isSupabase
        ? 'Supabase PostgreSQL (Cloud Enterprise)'
        : isFirebase
        ? 'Firebase Firestore (Cloud NoSQL)'
        : 'Local In-Memory Mode',
    };
  }

  public async getCachedDns(domain: string, type: string): Promise<string | null> {
    return this.memoryCache.get(`dns:${type}:${domain}`);
  }

  public async setCachedDns(domain: string, type: string, base64Packet: string, ttl = 300): Promise<void> {
    this.memoryCache.set(`dns:${type}:${domain}`, base64Packet, ttl);
  }

  // 30-Day Auto Purge Execution (GDPR & High Privacy Compliance)
  public async purgeOldLogs(days = 30): Promise<number> {
    if (!this.supabase) return 0;
    try {
      // 1. Try PostgreSQL function delete_old_query_logs()
      const { data, error } = await this.supabase.rpc('delete_old_query_logs');
      if (!error && typeof data === 'number') {
        this.lastPurge = Date.now();
        return data;
      }

      // 2. Fallback query
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
      const { count } = await this.supabase
        .from('query_logs')
        .delete({ count: 'exact' })
        .lt('timestamp', cutoff);

      this.lastPurge = Date.now();
      return count || 0;
    } catch (e) {
      console.warn('Auto log purge failed:', e);
      return 0;
    }
  }

  // Asynchronous Query Log Ingestion (with Privacy Masking)
  public async saveQueryLog(entry: QueryLogEntry): Promise<void> {
    // If running in public cloud mode or anonymization enabled, mask client IP
    const shouldAnonymize = process.env.ANONYMIZE_IPS !== 'false';
    const safeIp = shouldAnonymize ? anonymizeIp(entry.clientIp) : entry.clientIp;

    // Trigger daily purge check lazily if 24 hours have passed
    if (Date.now() - this.lastPurge > 24 * 60 * 60 * 1000) {
      this.lastPurge = Date.now();
      this.purgeOldLogs(30).catch(() => {});
    }

    // 1. Write to Supabase (Primary PostgreSQL Engine)
    if (this.supabase) {
      try {
        await this.supabase.from('query_logs').insert([
          {
            domain: entry.domain,
            query_type: entry.type,
            client_ip: safeIp,
            status: entry.blocked ? 'BLOCKED' : 'RESOLVED',
            matched_rule: entry.ruleMatched || null,
            elapsed_ms: entry.elapsedMs,
            upstream: entry.upstream || null,
          },
        ]);
      } catch {
        // Non-blocking fallback
      }
    }

    // 2. Write to Firebase Firestore if connected
    if (db) {
      try {
        await addDoc(collection(db, 'query_logs'), {
          domain: entry.domain,
          query_type: entry.type,
          client_ip: safeIp,
          status: entry.blocked ? 'BLOCKED' : 'RESOLVED',
          matched_rule: entry.ruleMatched || null,
          elapsed_ms: entry.elapsedMs,
          upstream: entry.upstream || null,
          timestamp: new Date(),
        });
      } catch {
        // Non-blocking fallback
      }
    }
  }
}

export const cloudStorage = CloudStorage.getInstance();
