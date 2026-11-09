import { Redis } from '@upstash/redis';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { QueryLogEntry, EngineStats, CustomRule } from './types';

// Detect environment variables
const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;

export class CloudStorage {
  private static instance: CloudStorage;
  private redis: Redis | null = null;
  private supabase: SupabaseClient | null = null;

  private constructor() {
    if (redisUrl && redisToken) {
      try {
        this.redis = new Redis({
          url: redisUrl,
          token: redisToken,
        });
      } catch (e) {
        console.warn('Failed to initialize Upstash Redis:', e);
      }
    }

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
      upstashConnected: !!this.redis,
      supabaseConnected: !!this.supabase,
      mode: this.redis && this.supabase ? 'Cloud Full Tier' : this.redis ? 'Upstash Edge' : this.supabase ? 'Supabase Hybrid' : 'Local In-Memory Fallback',
    };
  }

  // Fast DNS Cache (Upstash Redis)
  public async getCachedDns(domain: string, type: string): Promise<string | null> {
    if (!this.redis) return null;
    try {
      const val = await this.redis.get<string>(`dns:${type}:${domain}`);
      return val;
    } catch {
      return null;
    }
  }

  public async setCachedDns(domain: string, type: string, base64Packet: string, ttl = 300): Promise<void> {
    if (!this.redis) return;
    try {
      await this.redis.set(`dns:${type}:${domain}`, base64Packet, { ex: ttl });
    } catch {
      // ignore cache write error
    }
  }

  // Asynchronous Query Log Ingestion (Supabase)
  public async saveQueryLog(entry: QueryLogEntry): Promise<void> {
    // If Supabase is configured, write asynchronously without blocking
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
      } catch (e) {
        // non-blocking fallback
      }
    }

    // Also push to Redis recent stream if connected
    if (this.redis) {
      try {
        await this.redis.lpush('recent_queries', JSON.stringify(entry));
        await this.redis.ltrim('recent_queries', 0, 500);
        await this.redis.incr('total_queries');
        if (entry.blocked) {
          await this.redis.incr('blocked_queries');
        }
      } catch {
        // ignore
      }
    }
  }
}

export const cloudStorage = CloudStorage.getInstance();

