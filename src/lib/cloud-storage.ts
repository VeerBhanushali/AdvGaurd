import { QueryLogEntry } from './types';
import { db } from './firebase';
import { collection, addDoc } from 'firebase/firestore';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { shouldAnonymize } from './security';

// Supabase configuration – SERVER ONLY.
// The service-role key bypasses RLS and must never be exposed to the browser,
// so it is read from a non-NEXT_PUBLIC variable. The schema grants anon users
// nothing, so a leaked anon key cannot read query logs.
const supabaseUrl = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

export function retentionDays(): number {
  const d = parseInt(process.env.LOG_RETENTION_DAYS || '30', 10);
  return Number.isFinite(d) && d >= 1 && d <= 365 ? d : 30;
}

const PURGE_INTERVAL_MS = 12 * 60 * 60 * 1000;

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
        this.supabase = createClient(supabaseUrl, supabaseKey, {
          auth: { persistSession: false, autoRefreshToken: false },
        });
      } catch (e) {
        console.warn('Supabase initialization failed:', e);
      }
    }

    // Background retention worker: runs every 12 hours (and once shortly after boot).
    if (this.supabase) {
      const run = () => this.purgeOldLogs().catch(() => {});
      setTimeout(run, 60_000).unref?.();
      setInterval(run, PURGE_INTERVAL_MS).unref?.();
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
      privacyMode: shouldAnonymize() ? 'Zero-PII IP Anonymization (Active)' : 'IP Anonymization DISABLED',
      retentionPolicy: isSupabase ? `Auto-Purge ${retentionDays()} Days (Active)` : 'RAM only – last 500 entries, lost on restart',
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

  public async setCachedDns(domain: string, type: string, base64Packet: string, ttl: number): Promise<void> {
    this.memoryCache.set(`dns:${type}:${domain}`, base64Packet, ttl);
  }

  // 30-Day Auto Purge Execution (GDPR & High Privacy Compliance)
  public async purgeOldLogs(days = retentionDays()): Promise<number> {
    if (!this.supabase) return 0;
    try {
      // 1. Try PostgreSQL function delete_old_query_logs(retention_days)
      const { data, error } = await this.supabase.rpc('delete_old_query_logs', { retention_days: days });
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
    // entry.clientIp is already anonymised by the DNS engine before it reaches here.
    const safeIp = entry.clientIp;

    // Serverless platforms may never fire setInterval – purge lazily as a backstop.
    if (Date.now() - this.lastPurge > PURGE_INTERVAL_MS) {
      this.lastPurge = Date.now();
      this.purgeOldLogs().catch(() => {});
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
