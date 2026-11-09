export interface QueryLogEntry {
  id: string;
  timestamp: number;
  domain: string;
  type: string;
  clientIp: string;
  blocked: boolean;
  ruleMatched?: string;
  elapsedMs: number;
  upstream?: string;
}

export interface EngineStats {
  totalQueries: number;
  blockedQueries: number;
  blockedPercentage: number;
  uptimeSeconds: number;
  topDomains: { domain: string; count: number }[];
  topBlockedDomains: { domain: string; count: number }[];
  rulesCount: number;
}

export interface CustomRule {
  id: string;
  pattern: string;
  type: 'block' | 'allow';
  enabled: boolean;
  createdAt: number;
}

