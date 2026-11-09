import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { QueryLogEntry } from './types';

// Supabase Environment variables
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;

// High-Speed Local In-Memory Cache (replaces external Redis, 0ms latency, zero extra costs)
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
    // Refresh LRU position
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

  private constructor() {
    if (supabaseUrl && supabaseKey) {
      try {
        this.supabase = createClient(supabaseUrl, supabaseKey);
      } catch (e) {
        console.warn('Failed to initialize Supabase client:', e);
      }
    }
  }

  public static getInstance(): CloudStorage {
    if (!CloudStorage.instance) {
      CloudStorage.instance = new CloudStorage();
    }
    return CloudStorage.instance;
  }

  public getStatus() {
    return {
      supabaseConnected: !!this.supabase,
      mode: this.supabase ? 'Supabase Cloud (PostgreSQL)' : 'Local In-Memory Mode',
    };
  }

  // Sub-millisecond DNS In-Memory Cache (Zero external Redis dependency needed!)
  public async getCachedDns(domain: string, type: string): Promise<string | null> {
    return this.memoryCache.get(`dns:${type}:${domain}`);
  }

  public async setCachedDns(domain: string, type: string, base64Packet: string, ttl = 300): Promise<void> {
    this.memoryCache.set(`dns:${type}:${domain}`, base64Packet, ttl);
  }

  // Asynchronous Query Log Ingestion into Supabase
  public async saveQueryLog(entry: QueryLogEntry): Promise<void> {
    if (this.supabase) {
      try {
        await this.supabase.from('query_logs').insert([
          {
            domain: entry.domain,
            query_type: entry.type,
            client_ip: entry.clientIp,
            status: entry.blocked ? 'BLOCKED' : 'RESOLVED',
            matched_rule: entry.ruleMatched || null,
            elapsed_ms: entry.elapsedMs,
            upstream: entry.upstream || null,
          },
        ]);
      } catch {
        // Non-blocking fallback to protect DNS latency
      }
    }
  }
}

export const cloudStorage = CloudStorage.getInstance();
