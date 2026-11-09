'use client';

import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Layers,
  Smartphone,
  Globe,
  Copy,
  Check,
  Download,
  Search,
  Plus,
  RefreshCw,
  Server,
  Zap,
  Trash2,
  ExternalLink,
  Sliders,
  Database,
  Lock,
  Cpu,
  UserCheck,
  Laptop,
} from 'lucide-react';

interface Stats {
  totalQueries: number;
  blockedQueries: number;
  blockedPercentage: number;
  uptimeSeconds: number;
  rulesCount: number;
  topDomains: { domain: string; count: number }[];
  topBlockedDomains: { domain: string; count: number }[];
}

interface LogEntry {
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

interface CustomRule {
  id: string;
  pattern: string;
  type: 'block' | 'allow';
  enabled: boolean;
  createdAt: number;
}

interface SubscribedList {
  id: string;
  name: string;
  url: string;
  count: number;
  enabled: boolean;
  category: string;
}

interface CloudStatus {
  upstashConnected: boolean;
  supabaseConnected: boolean;
  mode: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    totalQueries: 0,
    blockedQueries: 0,
    blockedPercentage: 0,
    uptimeSeconds: 0,
    rulesCount: 292400,
    topDomains: [],
    topBlockedDomains: [],
  });
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [blocklists, setBlocklists] = useState<SubscribedList[]>([]);
  const [cloud, setCloud] = useState<CloudStatus>({
    upstashConnected: false,
    supabaseConnected: false,
    mode: 'Local In-Memory Fallback',
  });

  const [activeTab, setActiveTab] = useState<'dashboard' | 'logs' | 'filters' | 'devices' | 'settings'>('dashboard');
  const [copied, setCopied] = useState(false);
  const [hostUrl, setHostUrl] = useState('');

  // Device Setup state
  const [deviceTag, setDeviceTag] = useState('my-phone');

  // Query log filter
  const [logFilter, setLogFilter] = useState<'all' | 'blocked' | 'processed'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Converter state
  const [rawRules, setRawRules] = useState('');
  const [convertedRules, setConvertedRules] = useState('');
  const [convertStatus, setConvertStatus] = useState('');

  // Quick Rule Add
  const [newRuleInput, setNewRuleInput] = useState('');

  // Tester state
  const [testDomain, setTestDomain] = useState('doubleclick.net');
  const [testResult, setTestResult] = useState<any>(null);
  const [isTesting, setIsTesting] = useState(false);

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data.stats);
        setLogs(data.logs || []);
        setRules(data.rules || []);
        setBlocklists(data.blocklists || []);
        if (data.cloud) setCloud(data.cloud);
      }
    } catch {
      // offline / starting
    }
  };

  useEffect(() => {
    setHostUrl(window.location.origin);
    fetchStats();
    const interval = setInterval(fetchStats, 3000);
    return () => clearInterval(interval);
  }, []);

  const copyDohUrl = (urlToCopy?: string) => {
    const target = urlToCopy || (hostUrl ? `${hostUrl}/dns-query` : '');
    navigator.clipboard.writeText(target);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleConvert = () => {
    const lines = rawRules.split('\n');
    const result: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) continue;

      const match = trimmed.match(/(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)/);
      const domain = match ? match[1].toLowerCase() : trimmed.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

      if (domain && domain.includes('.')) {
        result.push(`||${domain}^`);
      }
    }

    const unique = Array.from(new Set(result));
    setConvertedRules(unique.join('\n'));
    setConvertStatus(`Converted ${unique.length} rules to AdGuard syntax!`);
  };

  const applyConvertedRules = async () => {
    const lines = convertedRules.split('\n');
    let added = 0;
    for (const rule of lines) {
      if (rule.trim()) {
        const res = await fetch('/api/stats', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'add-rule', rule }),
        });
        if (res.ok) added++;
      }
    }
    setConvertStatus(`Applied ${added} rules into live engine!`);
    fetchStats();
  };

  const addCustomRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleInput.trim()) return;

    let formatted = newRuleInput.trim();
    if (!formatted.startsWith('||') && !formatted.startsWith('@@') && !formatted.includes(' ')) {
      formatted = `||${formatted}^`;
    }

    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'add-rule', rule: formatted }),
    });
    setNewRuleInput('');
    fetchStats();
  };

  const deleteRule = async (id: string) => {
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'delete-rule', id }),
    });
    fetchStats();
  };

  const toggleBlocklist = async (id: string, current: boolean) => {
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'toggle-blocklist', id, enabled: !current }),
    });
    fetchStats();
  };

  const runTester = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testDomain.trim()) return;
    setIsTesting(true);
    try {
      const res = await fetch(`/api/resolve?name=${encodeURIComponent(testDomain.trim())}`);
      const data = await res.json();
      setTestResult(data);
    } catch (err: any) {
      setTestResult({ error: err.message });
    } finally {
      setIsTesting(false);
      fetchStats();
    }
  };

  const quickBlock = async (domain: string) => {
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'add-rule', rule: `||${domain}^` }),
    });
    fetchStats();
  };

  // Filter query logs
  const filteredLogs = logs.filter((log) => {
    if (logFilter === 'blocked' && !log.blocked) return false;
    if (logFilter === 'processed' && log.blocked) return false;
    if (searchQuery && !log.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans">
      {/* Top Navigation Bar */}
      <nav className="border-b border-slate-800/80 bg-[#0c121e]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Author Badge */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-emerald-700 flex items-center justify-center shadow-lg shadow-emerald-500/20 text-white font-black">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold tracking-tight text-white text-lg">AdGuard Web</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  PUBLIC DoH
                </span>
              </div>
              <div className="text-[11px] text-slate-400 flex items-center gap-1">
                <span>By</span>
                <span className="text-emerald-400 font-semibold">Veer Bhanushali</span>
                <span className="text-slate-600">•</span>
                <span className="text-slate-500">MIT Open Source</span>
              </div>
            </div>
          </div>

          {/* DoH Quick Endpoint Copy Pill */}
          <div className="hidden lg:flex items-center gap-3 bg-slate-900/90 border border-slate-800 rounded-xl px-3 py-1.5 shadow-inner">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-mono text-slate-300 max-w-xs truncate">
              {hostUrl ? `${hostUrl}/dns-query` : 'Loading...'}
            </span>
            <button
              onClick={() => copyDohUrl()}
              className="flex items-center gap-1.5 px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>

        {/* Tab Links */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 sm:space-x-4 border-t border-slate-800/60 overflow-x-auto text-xs sm:text-sm font-medium">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`py-3 px-3 border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
              activeTab === 'dashboard'
                ? 'border-emerald-500 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-4 h-4" /> Dashboard
          </button>
          <button
            onClick={() => setActiveTab('logs')}
            className={`py-3 px-3 border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
              activeTab === 'logs'
                ? 'border-emerald-500 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-4 h-4" /> Query Log ({logs.length})
          </button>
          <button
            onClick={() => setActiveTab('filters')}
            className={`py-3 px-3 border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
              activeTab === 'filters'
                ? 'border-emerald-500 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" /> Filters & Rules
          </button>
          <button
            onClick={() => setActiveTab('devices')}
            className={`py-3 px-3 border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
              activeTab === 'devices'
                ? 'border-emerald-500 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Smartphone className="w-4 h-4" /> Connect Devices
          </button>
          <button
            onClick={() => setActiveTab('settings')}
            className={`py-3 px-3 border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
              activeTab === 'settings'
                ? 'border-emerald-500 text-emerald-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sliders className="w-4 h-4" /> Settings & Cloud
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 w-full space-y-8">
        {/* TAB 1: DASHBOARD */}
        {activeTab === 'dashboard' && (
          <div className="space-y-8">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-5 shadow-xl">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-semibold uppercase tracking-wider">DNS Queries</span>
                  <Activity className="w-4 h-4 text-sky-400" />
                </div>
                <div className="text-3xl font-extrabold text-white font-mono">{stats.totalQueries.toLocaleString()}</div>
                <div className="text-xs text-slate-500 mt-2 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" /> Upstream DoH active
                </div>
              </div>

              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-5 shadow-xl">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-semibold uppercase tracking-wider">Blocked Trackers</span>
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                </div>
                <div className="text-3xl font-extrabold text-rose-400 font-mono">{stats.blockedQueries.toLocaleString()}</div>
                <div className="text-xs text-slate-500 mt-2">Ads, telemetry & spyware blocked</div>
              </div>

              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-5 shadow-xl">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-semibold uppercase tracking-wider">Block Percentage</span>
                  <Zap className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="text-3xl font-extrabold text-emerald-400 font-mono">{stats.blockedPercentage}%</div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
                  <div
                    className="bg-emerald-500 h-full rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(stats.blockedPercentage, 100)}%` }}
                  />
                </div>
              </div>

              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-5 shadow-xl">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-semibold uppercase tracking-wider">Active Rules</span>
                  <Layers className="w-4 h-4 text-purple-400" />
                </div>
                <div className="text-3xl font-extrabold text-purple-400 font-mono">{stats.rulesCount.toLocaleString()}</div>
                <div className="text-xs text-slate-500 mt-2">OISD + HaGeZi + Custom Filters</div>
              </div>
            </div>

            {/* Quick DoH Domain Tester Bar */}
            <div className="bg-gradient-to-r from-emerald-950/30 to-slate-900 border border-emerald-500/20 rounded-2xl p-5">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Search className="w-4 h-4 text-emerald-400" /> Quick Domain Ad-Block Tester
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Query your live DoH resolver in real-time to check if any domain gets blocked.
                  </p>
                </div>
                <form onSubmit={runTester} className="flex items-center gap-2 w-full md:w-auto">
                  <input
                    type="text"
                    value={testDomain}
                    onChange={(e) => setTestDomain(e.target.value)}
                    placeholder="e.g. doubleclick.net, google.com"
                    className="bg-slate-950 border border-slate-800 rounded-xl px-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-full md:w-64"
                  />
                  <button
                    type="submit"
                    disabled={isTesting}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-semibold transition shrink-0"
                  >
                    {isTesting ? 'Testing...' : 'Test'}
                  </button>
                </form>
              </div>

              {testResult && (
                <div className="mt-4 p-3 bg-slate-950 rounded-xl border border-slate-800/80 text-xs font-mono flex items-center justify-between">
                  <span className="text-slate-300">Checked: <strong className="text-white">{testDomain}</strong></span>
                  {testResult.Blocked ? (
                    <span className="px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-400 font-bold border border-rose-500/30">
                      BLOCKED BY ADGUARD (0.0.0.0)
                    </span>
                  ) : (
                    <span className="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
                      RESOLVED VIA UPSTREAM DOH
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* Top Domains & Top Blocked Side-by-Side */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Top Queried Domains */}
              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Globe className="w-4 h-4 text-sky-400" /> Top Queried Domains
                  </h3>
                  <span className="text-xs text-slate-500">Live Traffic</span>
                </div>

                {stats.topDomains.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">
                    No domains queried yet. Connect your phone or test a domain!
                  </div>
                ) : (
                  <div className="space-y-3 text-xs">
                    {stats.topDomains.map((item, idx) => (
                      <div key={idx} className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-slate-200">{item.domain}</span>
                          <span className="text-slate-400 font-mono">{item.count} hits</span>
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div
                            className="bg-sky-500 h-full rounded-full"
                            style={{
                              width: `${Math.min((item.count / (stats.topDomains[0]?.count || 1)) * 100, 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Top Blocked Domains */}
              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" /> Top Blocked Trackers
                  </h3>
                  <span className="text-xs text-slate-500">Neutralized</span>
                </div>

                {stats.topBlockedDomains.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">
                    No blocked trackers logged yet. Ads will appear here when blocked.
                  </div>
                ) : (
                  <div className="space-y-3 text-xs">
                    {stats.topBlockedDomains.map((item, idx) => (
                      <div key={idx} className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-rose-300">{item.domain}</span>
                          <span className="text-rose-400 font-mono">{item.count} blocked</span>
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div
                            className="bg-rose-500 h-full rounded-full"
                            style={{
                              width: `${Math.min((item.count / (stats.topBlockedDomains[0]?.count || 1)) * 100, 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: QUERY LOG */}
        {activeTab === 'logs' && (
          <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl overflow-hidden shadow-2xl space-y-4 p-5">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Activity className="w-5 h-5 text-emerald-400" /> Real-Time Query Stream
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Inspect incoming DoH DNS queries, client devices, and latency in real-time.
                </p>
              </div>

              {/* Filter Pills */}
              <div className="flex items-center gap-2 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
                <button
                  onClick={() => setLogFilter('all')}
                  className={`px-3 py-1 rounded-lg font-medium transition ${
                    logFilter === 'all' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  All ({logs.length})
                </button>
                <button
                  onClick={() => setLogFilter('blocked')}
                  className={`px-3 py-1 rounded-lg font-medium transition ${
                    logFilter === 'blocked' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400 hover:text-rose-300'
                  }`}
                >
                  Blocked ({logs.filter((l) => l.blocked).length})
                </button>
                <button
                  onClick={() => setLogFilter('processed')}
                  className={`px-3 py-1 rounded-lg font-medium transition ${
                    logFilter === 'processed' ? 'bg-emerald-500/20 text-emerald-300' : 'text-slate-400 hover:text-emerald-300'
                  }`}
                >
                  Processed ({logs.filter((l) => !l.blocked).length})
                </button>
              </div>
            </div>

            {/* Search Input */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search domain name or client..."
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-xl border border-slate-800/80 max-h-[550px]">
              {filteredLogs.length === 0 ? (
                <div className="py-16 text-center text-slate-500 text-xs">
                  No matching queries found.
                </div>
              ) : (
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="p-3 pl-4">Time</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Domain</th>
                      <th className="p-3">Type</th>
                      <th className="p-3">Client / Subdomain</th>
                      <th className="p-3">Latency</th>
                      <th className="p-3 pr-4 text-right">Quick Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50 bg-[#0b101c]">
                    {filteredLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-slate-800/30 transition">
                        <td className="p-3 pl-4 text-slate-400">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="p-3">
                          {log.blocked ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                              BLOCKED
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              RESOLVED
                            </span>
                          )}
                        </td>
                        <td className="p-3 font-semibold text-slate-200">{log.domain}</td>
                        <td className="p-3 text-slate-400">{log.type}</td>
                        <td className="p-3 text-slate-300 font-sans">{log.clientIp}</td>
                        <td className="p-3 text-slate-400">{log.elapsedMs} ms</td>
                        <td className="p-3 pr-4 text-right">
                          {!log.blocked ? (
                            <button
                              onClick={() => quickBlock(log.domain)}
                              className="px-2.5 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded text-[11px] transition"
                            >
                              Block
                            </button>
                          ) : (
                            <span className="text-slate-600 text-[10px]">Filtered</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: FILTERS & RULES */}
        {activeTab === 'filters' && (
          <div className="space-y-8">
            {/* Subscribed Blocklists Cards */}
            <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <Layers className="w-5 h-5 text-purple-400" /> Subscribed Ad & Tracker Blocklists
                  </h3>
                  <p className="text-xs text-slate-400">
                    High-efficiency blocklists active in RAM for sub-millisecond matching.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {blocklists.map((list) => (
                  <div
                    key={list.id}
                    className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/60 flex items-center justify-between"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-sm text-white">{list.name}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-400">
                          {list.category}
                        </span>
                      </div>
                      <div className="text-xs text-slate-500 font-mono">
                        {list.count.toLocaleString()} rules • <span className="text-emerald-400">Synced</span>
                      </div>
                    </div>
                    <button
                      onClick={() => toggleBlocklist(list.id, list.enabled)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                        list.enabled
                          ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                          : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                      }`}
                    >
                      {list.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Custom User Rules Manager */}
            <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" /> Custom User Rules
                </h3>
                <p className="text-xs text-slate-400">
                  Add custom domain blocking (`||domain.com^`) or whitelisting (`@@||domain.com^`).
                </p>
              </div>

              <form onSubmit={addCustomRule} className="flex gap-2">
                <input
                  type="text"
                  value={newRuleInput}
                  onChange={(e) => setNewRuleInput(e.target.value)}
                  placeholder="e.g. ||tiktok.com^ or @@||safe-subdomain.com^"
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-emerald-500"
                />
                <button
                  type="submit"
                  className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-semibold transition flex items-center gap-1.5 shrink-0"
                >
                  <Plus className="w-4 h-4" /> Add Rule
                </button>
              </form>

              {rules.length > 0 && (
                <div className="divide-y divide-slate-800/60 rounded-xl border border-slate-800/80 bg-slate-950/60 max-h-60 overflow-y-auto">
                  {rules.map((rule) => (
                    <div key={rule.id} className="p-3 flex items-center justify-between text-xs font-mono">
                      <span className="text-emerald-300">{rule.pattern}</span>
                      <button
                        onClick={() => deleteRule(rule.id)}
                        className="text-slate-500 hover:text-rose-400 transition"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Universal Rule Converter Tool */}
            <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Zap className="w-5 h-5 text-sky-400" /> Universal Rule Converter
                </h3>
                <p className="text-xs text-slate-400">
                  Paste raw hosts files, ABP rules, or plain domains. Instantly convert and load them into the engine.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-[11px] font-semibold text-slate-400 uppercase">Input Raw Rules</label>
                  <textarea
                    value={rawRules}
                    onChange={(e) => setRawRules(e.target.value)}
                    placeholder={"0.0.0.0 trackingsite.com\n127.0.0.1 adnetwork.net\nspamdomain.org"}
                    rows={8}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[11px] font-semibold text-slate-400 uppercase">Converted AdGuard Syntax</label>
                  <textarea
                    value={convertedRules}
                    readOnly
                    placeholder={"||trackingsite.com^\n||adnetwork.net^\n||spamdomain.org^"}
                    rows={8}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-400 placeholder-slate-600 focus:outline-none"
                  />
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <div className="flex items-center gap-3">
                  <button
                    onClick={handleConvert}
                    className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-semibold transition"
                  >
                    Convert Rules
                  </button>
                  {convertedRules && (
                    <button
                      onClick={applyConvertedRules}
                      className="px-5 py-2.5 bg-sky-600 hover:bg-sky-500 text-white rounded-xl text-xs font-semibold transition flex items-center gap-1.5"
                    >
                      <Plus className="w-4 h-4" /> Apply to Live Engine
                    </button>
                  )}
                </div>
                {convertStatus && <span className="text-xs text-emerald-400 font-medium">{convertStatus}</span>}
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: CONNECT DEVICES & PUBLIC DNS GENERATOR */}
        {activeTab === 'devices' && (
          <div className="space-y-8">
            {/* Multi-Device / Public Subdomain Generator */}
            <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <UserCheck className="w-5 h-5 text-emerald-400" /> Public Device & Subdomain Router
                </h3>
                <p className="text-xs text-slate-400">
                  Anyone can connect any device to your AdGuard Web server. Create a custom device tag to isolate and identify your traffic in the Query Log.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                  <label className="text-xs text-slate-300 font-medium shrink-0">Device Tag / Name:</label>
                  <input
                    type="text"
                    value={deviceTag}
                    onChange={(e) => setDeviceTag(e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, ''))}
                    placeholder="e.g. veer-phone, living-room-tv"
                    className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div className="space-y-1 text-xs">
                  <span className="text-slate-400">Your Personalized DoH URL for this device:</span>
                  <div className="flex items-center gap-2 bg-slate-900 p-2 rounded-lg border border-slate-800">
                    <code className="text-emerald-400 font-mono flex-1 select-all truncate">
                      {hostUrl ? `${hostUrl}/dns-query/${deviceTag || 'default'}` : ''}
                    </code>
                    <button
                      onClick={() => copyDohUrl(`${hostUrl}/dns-query/${deviceTag || 'default'}`)}
                      className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-medium transition"
                    >
                      Copy
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Platform Setup Guides */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* iOS */}
              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-3">
                <div className="flex items-center gap-2.5 text-white font-bold text-sm">
                  <Smartphone className="w-5 h-5 text-sky-400" /> iPhone & iPad (iOS 14+)
                </div>
                <p className="text-xs text-slate-400">
                  Download our official Apple `.mobileconfig` encrypted DNS profile directly to your device via Safari.
                </p>
                <div className="pt-2">
                  <a
                    href="/api/mobileconfig"
                    download="adguard-web.mobileconfig"
                    className="inline-flex items-center gap-2 px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-xl text-xs font-semibold transition"
                  >
                    <Download className="w-4 h-4" /> Download 1-Click iOS Profile
                  </a>
                  <p className="text-[11px] text-slate-500 mt-2">
                    Open Settings &gt; Profile Downloaded &gt; Install. System-wide ad-blocking is immediately active.
                  </p>
                </div>
              </div>

              {/* Android */}
              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-3">
                <div className="flex items-center gap-2.5 text-white font-bold text-sm">
                  <Smartphone className="w-5 h-5 text-emerald-400" /> Android (5G & Wi-Fi)
                </div>
                <p className="text-xs text-slate-400">
                  Use open-source apps like <strong>Intra</strong> (by Google Jigsaw) or <strong>RethinkDNS</strong>.
                </p>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-xs space-y-1.5 text-slate-300">
                  <p>1. Open Intra or RethinkDNS.</p>
                  <p>2. Set Custom DNS-over-HTTPS URL to:</p>
                  <code className="block bg-slate-900 p-1.5 rounded text-emerald-300 font-mono select-all">
                    {hostUrl}/dns-query/{deviceTag}
                  </code>
                </div>
              </div>

              {/* Desktop Browsers */}
              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-3">
                <div className="flex items-center gap-2.5 text-white font-bold text-sm">
                  <Laptop className="w-5 h-5 text-purple-400" /> Chrome / Brave / Edge / Firefox
                </div>
                <p className="text-xs text-slate-400">
                  Configure Secure DNS directly inside your web browser.
                </p>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-xs space-y-1.5 text-slate-300">
                  <p>1. Go to <strong>Settings &gt; Privacy and Security &gt; Security</strong>.</p>
                  <p>2. Under <strong>Use Secure DNS</strong>, select <strong>Custom</strong>.</p>
                  <p>3. Enter your DoH URL:</p>
                  <code className="block bg-slate-900 p-1.5 rounded text-purple-300 font-mono select-all">
                    {hostUrl}/dns-query
                  </code>
                </div>
              </div>

              {/* Hostinger & Vercel */}
              <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-3">
                <div className="flex items-center gap-2.5 text-white font-bold text-sm">
                  <Globe className="w-5 h-5 text-emerald-400" /> Hostinger & Vercel Deployment
                </div>
                <p className="text-xs text-slate-400">
                  Host AdGuard Web on your own domain with free SSL.
                </p>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-xs space-y-1.5 text-slate-300">
                  <p>• <strong>Hostinger WebApp</strong>: Create Node.js app, upload folder, set command <code className="text-emerald-400 font-mono">npm start</code>.</p>
                  <p>• <strong>Vercel</strong>: Import repo into Vercel and click Deploy.</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: SETTINGS & CLOUD */}
        {activeTab === 'settings' && (
          <div className="space-y-8">
            {/* Cloud Storage & Persistence Status */}
            <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Database className="w-5 h-5 text-sky-400" /> 100% Free Cloud Tier Status
                </h3>
                <p className="text-xs text-slate-400">
                  AdGuard Web automatically detects Upstash Redis and Supabase Postgres credentials.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="font-bold text-sm text-white flex items-center gap-2">
                      <Zap className="w-4 h-4 text-emerald-400" /> Upstash Redis
                    </span>
                    <p className="text-xs text-slate-500">Sub-millisecond Edge DNS Cache</p>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold border ${
                      cloud.upstashConnected
                        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {cloud.upstashConnected ? 'Connected (Cloud)' : 'Local In-Memory'}
                  </span>
                </div>

                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="font-bold text-sm text-white flex items-center gap-2">
                      <Database className="w-4 h-4 text-purple-400" /> Supabase PostgreSQL
                    </span>
                    <p className="text-xs text-slate-500">Long-term Query Log & Rules Store</p>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold border ${
                      cloud.supabaseConnected
                        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {cloud.supabaseConnected ? 'Connected (Cloud)' : 'Local Storage'}
                  </span>
                </div>
              </div>
            </div>

            {/* Upstream Encrypted Resolvers */}
            <div className="bg-[#0f172a]/70 border border-slate-800/90 rounded-2xl p-6 shadow-xl space-y-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Lock className="w-5 h-5 text-emerald-400" /> Upstream Encrypted DoH Servers
                </h3>
                <p className="text-xs text-slate-400">
                  Clean queries are forwarded over encrypted HTTPS. Zero ISP snooping.
                </p>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-200">https://dns.quad9.net/dns-query</span>
                  <span className="text-emerald-400 font-bold">Primary (Swiss No-Log)</span>
                </div>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-200">https://cloudflare-dns.com/dns-query</span>
                  <span className="text-sky-400 font-bold">Secondary (1.1.1.1)</span>
                </div>
              </div>
            </div>

            {/* Open Source License & Author Credits */}
            <div className="bg-[#0f172a]/70 border border-emerald-500/30 rounded-2xl p-6 shadow-xl space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-sm font-bold text-white">Open Source License & Attribution</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400">MIT LICENSE</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                <strong>AdGuard Web</strong> is completely free and open-source software created and engineered by <strong>Veer Bhanushali</strong>.
                You are free to host it publicly, add custom subdomains for friends and family, and deploy it to any cloud or web hosting platform.
              </p>
              <div className="text-xs text-slate-500 font-mono pt-1">
                Copyright © 2026 Veer Bhanushali. All rights reserved.
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#070b12] py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>AdGuard Web • Cloud DNS-over-HTTPS AdBlock Engine</span>
          <span className="text-slate-400">
            Engineered with ❤️ by <strong className="text-emerald-400">Veer Bhanushali</strong>
          </span>
          <span>MIT Open Source License</span>
        </div>
      </footer>
    </div>
  );
}
