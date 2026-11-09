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
  CheckCircle2,
  XCircle,
  Clock,
  Settings,
  HelpCircle,
  FileText,
  BarChart2,
  ToggleLeft,
  ToggleRight,
  Code,
  AlertTriangle,
} from 'lucide-react';

interface Stats {
  totalQueries: number;
  blockedQueries: number;
  blockedPercentage: number;
  uptimeSeconds: number;
  rulesCount: number;
  topDomains: { domain: string; count: number }[];
  topBlockedDomains: { domain: string; count: number }[];
  topClients: { client: string; count: number }[];
  topUpstreams: { upstream: string; count: number; avgMs: number }[];
  chartData: { time: string; queries: number; blocked: number }[];
  protectionEnabled: boolean;
  safeSearchEnabled: boolean;
  safeBrowsingEnabled: boolean;
  malwareBlockedCount: number;
  adultBlockedCount: number;
  avgLatencyMs: number;
  rewrites: { id: string; domain: string; answer: string }[];
  blockedServiceIds: string[];
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

interface ServiceDef {
  id: string;
  name: string;
  category: string;
  domains: string[];
  icon: string;
}

interface CloudStatus {
  upstashConnected: boolean;
  supabaseConnected: boolean;
  mode: string;
}

export default function AdGuardHomeUI() {
  const [stats, setStats] = useState<Stats>({
    totalQueries: 0,
    blockedQueries: 0,
    blockedPercentage: 0,
    uptimeSeconds: 0,
    rulesCount: 292400,
    topDomains: [],
    topBlockedDomains: [],
    topClients: [],
    topUpstreams: [],
    chartData: [],
    protectionEnabled: true,
    safeSearchEnabled: false,
    safeBrowsingEnabled: true,
    malwareBlockedCount: 14,
    adultBlockedCount: 8,
    avgLatencyMs: 14,
    rewrites: [],
    blockedServiceIds: [],
  });

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [blocklists, setBlocklists] = useState<SubscribedList[]>([]);
  const [services, setServices] = useState<ServiceDef[]>([]);
  const [cloud, setCloud] = useState<CloudStatus>({
    upstashConnected: false,
    supabaseConnected: false,
    mode: 'Local In-Memory Fallback',
  });

  // Top Nav active section
  const [activeNav, setActiveNav] = useState<'dashboard' | 'settings' | 'filters' | 'logs' | 'guide'>('dashboard');
  const [filtersSubTab, setFiltersSubTab] = useState<'blocklists' | 'services' | 'custom' | 'rewrites'>('blocklists');
  const [settingsSubTab, setSettingsSubTab] = useState<'general' | 'dns' | 'cloud'>('general');

  const [copied, setCopied] = useState(false);
  const [hostUrl, setHostUrl] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Query log filters
  const [logStatusFilter, setLogStatusFilter] = useState<'all' | 'blocked' | 'processed'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Custom rule input
  const [customRulesText, setCustomRulesText] = useState('');
  const [ruleMessage, setRuleMessage] = useState('');

  // DNS Rewrite input
  const [rewriteDomain, setRewriteDomain] = useState('');
  const [rewriteIp, setRewriteIp] = useState('');

  // Device Tag state
  const [deviceTag, setDeviceTag] = useState('phone');

  // Quick live tester
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
        if (data.availableServices) setServices(data.availableServices);
        if (data.cloud) setCloud(data.cloud);
      }
    } catch {
      // offline or compiling
    }
  };

  useEffect(() => {
    setHostUrl(window.location.origin);
    fetchStats();
    if (!autoRefresh) return;
    const interval = setInterval(fetchStats, 3000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const copyUrl = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleProtection = async () => {
    const nextState = !stats.protectionEnabled;
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'set-protection', enabled: nextState }),
    });
    fetchStats();
  };

  const toggleSafeSearch = async () => {
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'set-safesearch', enabled: !stats.safeSearchEnabled }),
    });
    fetchStats();
  };

  const toggleSafeBrowsing = async () => {
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'set-safebrowsing', enabled: !stats.safeBrowsingEnabled }),
    });
    fetchStats();
  };

  const toggleBlockedService = async (serviceId: string, current: boolean) => {
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'toggle-service', serviceId, enabled: !current }),
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

  const addCustomRuleFromEditor = async () => {
    const lines = customRulesText.split('\n');
    let count = 0;
    for (const line of lines) {
      if (line.trim()) {
        await fetch('/api/stats', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'add-rule', rule: line.trim() }),
        });
        count++;
      }
    }
    setCustomRulesText('');
    setRuleMessage(`Saved ${count} rule(s) to AdGuard engine!`);
    setTimeout(() => setRuleMessage(''), 3000);
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

  const addRewrite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rewriteDomain.trim() || !rewriteIp.trim()) return;
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'add-rewrite', domain: rewriteDomain, answer: rewriteIp }),
    });
    setRewriteDomain('');
    setRewriteIp('');
    fetchStats();
  };

  const deleteRewrite = async (id: string) => {
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'delete-rewrite', id }),
    });
    fetchStats();
  };

  const quickBlock = async (domain: string) => {
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'add-rule', rule: `||${domain}^` }),
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

  // Filter query log
  const filteredLogs = logs.filter((log) => {
    if (logStatusFilter === 'blocked' && !log.blocked) return false;
    if (logStatusFilter === 'processed' && log.blocked) return false;
    if (searchQuery && !log.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="min-h-screen bg-[#111827] text-slate-100 flex flex-col font-sans selection:bg-[#2db365] selection:text-white">
      {/* Official AdGuard Home Header */}
      <header className="bg-[#1f2937] border-b border-slate-700/80 sticky top-0 z-50 shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14">
            {/* Logo: Authentic AdGuard Home */}
            <div className="flex items-center gap-6">
              <div
                onClick={() => setActiveNav('dashboard')}
                className="flex items-center gap-2.5 cursor-pointer group select-none"
              >
                <div className="w-8 h-8 rounded-lg bg-[#2db365] flex items-center justify-center text-white shadow-sm shadow-[#2db365]/30">
                  <Shield className="w-5 h-5 fill-white/20 stroke-[2.5]" />
                </div>
                <div className="flex items-baseline gap-1">
                  <span className="font-extrabold text-lg tracking-tight text-white">AdvGuard</span>
                  <span className="text-lg font-light text-[#2db365]">Home</span>
                  <span className="ml-1 text-[10px] font-mono font-medium px-1.5 py-0.2 bg-[#2db365]/20 text-[#2db365] rounded border border-[#2db365]/30">
                    Web Edition
                  </span>
                </div>
              </div>

              {/* Navigation Menu */}
              <nav className="hidden md:flex items-center space-x-1 text-sm font-medium">
                <button
                  onClick={() => setActiveNav('dashboard')}
                  className={`px-3.5 py-1.5 rounded-md transition ${
                    activeNav === 'dashboard'
                      ? 'bg-slate-800 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  Dashboard
                </button>

                <button
                  onClick={() => setActiveNav('settings')}
                  className={`px-3.5 py-1.5 rounded-md transition ${
                    activeNav === 'settings'
                      ? 'bg-slate-800 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  Settings
                </button>

                <button
                  onClick={() => setActiveNav('filters')}
                  className={`px-3.5 py-1.5 rounded-md transition ${
                    activeNav === 'filters'
                      ? 'bg-slate-800 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  Filters
                </button>

                <button
                  onClick={() => setActiveNav('logs')}
                  className={`px-3.5 py-1.5 rounded-md transition ${
                    activeNav === 'logs'
                      ? 'bg-slate-800 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  Query Log
                </button>

                <button
                  onClick={() => setActiveNav('guide')}
                  className={`px-3.5 py-1.5 rounded-md transition ${
                    activeNav === 'guide'
                      ? 'bg-slate-800 text-white font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  Setup Guide
                </button>
              </nav>
            </div>

            {/* Top Right: Protection Switch & Author attribution */}
            <div className="flex items-center gap-3">
              {/* Protection Toggle */}
              <button
                onClick={toggleProtection}
                className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold border transition ${
                  stats.protectionEnabled
                    ? 'bg-[#2db365]/10 text-[#2db365] border-[#2db365]/30 hover:bg-[#2db365]/20'
                    : 'bg-rose-500/10 text-rose-400 border-rose-500/30 hover:bg-rose-500/20'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    stats.protectionEnabled ? 'bg-[#2db365] animate-pulse' : 'bg-rose-500'
                  }`}
                />
                Protection: {stats.protectionEnabled ? 'ON' : 'OFF'}
              </button>

              {/* Author Badge */}
              <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-400 bg-slate-800/80 px-2.5 py-1 rounded-lg border border-slate-700">
                <span>By</span>
                <strong className="text-[#2db365]">Veer Bhanushali</strong>
              </div>
            </div>
          </div>
        </div>

        {/* Sub-navigation bar for Filters and Settings */}
        {activeNav === 'filters' && (
          <div className="bg-[#182230] border-t border-slate-700/60 px-4 sm:px-8 py-2 flex items-center space-x-4 text-xs font-medium">
            <button
              onClick={() => setFiltersSubTab('blocklists')}
              className={`px-2.5 py-1 rounded transition ${
                filtersSubTab === 'blocklists' ? 'bg-[#2db365] text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              DNS blocklists ({blocklists.length})
            </button>
            <button
              onClick={() => setFiltersSubTab('services')}
              className={`px-2.5 py-1 rounded transition ${
                filtersSubTab === 'services' ? 'bg-[#2db365] text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Blocked services ({services.length})
            </button>
            <button
              onClick={() => setFiltersSubTab('custom')}
              className={`px-2.5 py-1 rounded transition ${
                filtersSubTab === 'custom' ? 'bg-[#2db365] text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Custom filtering rules ({rules.length})
            </button>
            <button
              onClick={() => setFiltersSubTab('rewrites')}
              className={`px-2.5 py-1 rounded transition ${
                filtersSubTab === 'rewrites' ? 'bg-[#2db365] text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              DNS rewrites ({stats.rewrites.length})
            </button>
          </div>
        )}

        {activeNav === 'settings' && (
          <div className="bg-[#182230] border-t border-slate-700/60 px-4 sm:px-8 py-2 flex items-center space-x-4 text-xs font-medium">
            <button
              onClick={() => setSettingsSubTab('general')}
              className={`px-2.5 py-1 rounded transition ${
                settingsSubTab === 'general' ? 'bg-[#2db365] text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              General settings
            </button>
            <button
              onClick={() => setSettingsSubTab('dns')}
              className={`px-2.5 py-1 rounded transition ${
                settingsSubTab === 'dns' ? 'bg-[#2db365] text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              DNS settings
            </button>
            <button
              onClick={() => setSettingsSubTab('cloud')}
              className={`px-2.5 py-1 rounded transition ${
                settingsSubTab === 'cloud' ? 'bg-[#2db365] text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Upstash & Supabase Cloud
            </button>
          </div>
        )}
      </header>

      {/* Main App Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full space-y-6">
        {/* VIEW 1: DASHBOARD (Authentic AdGuard Home 4-Card + 2x2 Table Layout) */}
        {activeNav === 'dashboard' && (
          <div className="space-y-6">
            {/* Top Protection Banner */}
            <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-sm">
              <div className="flex items-center gap-3">
                <div
                  className={`w-3 h-3 rounded-full ${
                    stats.protectionEnabled ? 'bg-[#2db365]' : 'bg-rose-500'
                  }`}
                />
                <div>
                  <h3 className="text-sm font-bold text-white">
                    {stats.protectionEnabled
                      ? 'Protection is enabled'
                      : 'Protection is disabled — Ads and tracking are NOT blocked'}
                  </h3>
                  <p className="text-xs text-slate-400">
                    Running in DoH web mode over HTTPS. Upstream queries are encrypted.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <button
                  onClick={fetchStats}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg flex items-center gap-1.5 transition"
                >
                  <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
                <button
                  onClick={toggleProtection}
                  className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                    stats.protectionEnabled
                      ? 'bg-rose-600/20 text-rose-300 hover:bg-rose-600/30'
                      : 'bg-[#2db365] text-white hover:bg-[#259b56]'
                  }`}
                >
                  {stats.protectionEnabled ? 'Disable protection' : 'Enable protection'}
                </button>
              </div>
            </div>

            {/* Official 4-Card Metric Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Card 1: DNS Queries */}
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-2">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-semibold text-slate-300">DNS queries</span>
                  <BarChart2 className="w-4 h-4 text-sky-400" />
                </div>
                <div className="text-3xl font-extrabold text-white font-mono">{stats.totalQueries.toLocaleString()}</div>
                <div className="text-[11px] text-slate-400">Total queries in 24 hours</div>
                {/* Visual bar */}
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                  <div className="bg-sky-500 h-full w-full rounded-full" />
                </div>
              </div>

              {/* Card 2: Blocked by Filters */}
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-2">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-semibold text-slate-300">Blocked by filters</span>
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                </div>
                <div className="text-3xl font-extrabold text-rose-400 font-mono">{stats.blockedQueries.toLocaleString()}</div>
                <div className="text-[11px] text-slate-400">{stats.blockedPercentage}% of all queries blocked</div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                  <div
                    className="bg-rose-500 h-full rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(stats.blockedPercentage, 100)}%` }}
                  />
                </div>
              </div>

              {/* Card 3: Blocked malware/phishing */}
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-2">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-semibold text-slate-300">Blocked malware/phishing</span>
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                </div>
                <div className="text-3xl font-extrabold text-amber-400 font-mono">{stats.malwareBlockedCount}</div>
                <div className="text-[11px] text-slate-400">Safe Browsing active</div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                  <div className="bg-amber-500 h-full w-1/4 rounded-full" />
                </div>
              </div>

              {/* Card 4: Blocked adult websites */}
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-2">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-semibold text-slate-300">Blocked adult websites</span>
                  <Lock className="w-4 h-4 text-purple-400" />
                </div>
                <div className="text-3xl font-extrabold text-purple-400 font-mono">{stats.adultBlockedCount}</div>
                <div className="text-[11px] text-slate-400">Parental control active</div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                  <div className="bg-purple-500 h-full w-1/6 rounded-full" />
                </div>
              </div>
            </div>

            {/* Official 24-Hour Activity Chart */}
            <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white">DNS Queries Over Time (24h Activity)</h3>
                  <p className="text-xs text-slate-400">Real-time query distribution across hourly buckets</p>
                </div>
                <div className="flex items-center gap-4 text-xs">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 bg-[#2db365] rounded-sm" /> Clean Queries
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 bg-rose-500 rounded-sm" /> Blocked Requests
                  </div>
                </div>
              </div>

              {/* Visual Bar Graph */}
              <div className="h-32 flex items-end justify-between gap-2 pt-4 px-2 border-b border-slate-700">
                {stats.chartData.map((item, idx) => {
                  const maxVal = 300;
                  const queryH = Math.min((item.queries / maxVal) * 100, 100);
                  const blockedH = Math.min((item.blocked / maxVal) * 100, 100);

                  return (
                    <div key={idx} className="flex-1 flex flex-col items-center gap-1 h-full justify-end group">
                      <div className="w-full flex items-end justify-center gap-1 h-full">
                        {/* Clean queries bar */}
                        <div
                          className="w-1/2 bg-[#2db365] rounded-t transition-all group-hover:bg-[#34c772]"
                          style={{ height: `${queryH}%` }}
                          title={`Queries: ${item.queries}`}
                        />
                        {/* Blocked queries bar */}
                        <div
                          className="w-1/2 bg-rose-500 rounded-t transition-all group-hover:bg-rose-400"
                          style={{ height: `${blockedH}%` }}
                          title={`Blocked: ${item.blocked}`}
                        />
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono mt-1">{item.time}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Official AdGuard Home 2x2 Tables Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Box 1: Top Clients */}
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-700">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <Laptop className="w-4 h-4 text-sky-400" /> Top Clients
                  </h4>
                  <span className="text-xs text-slate-400">Total requests</span>
                </div>
                <div className="space-y-2.5 text-xs">
                  {stats.topClients.map((client, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-slate-200">{client.client}</span>
                        <span className="font-mono text-slate-400">{client.count.toLocaleString()}</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-sky-500 h-full rounded-full"
                          style={{ width: `${Math.min((client.count / (stats.topClients[0]?.count || 1)) * 100, 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Box 2: Top Queried Domains */}
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-700">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <Globe className="w-4 h-4 text-[#2db365]" /> Top Queried Domains
                  </h4>
                  <span className="text-xs text-slate-400">Requests</span>
                </div>
                <div className="space-y-2.5 text-xs">
                  {stats.topDomains.map((domain, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-slate-200">{domain.domain}</span>
                        <span className="font-mono text-slate-400">{domain.count.toLocaleString()}</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-[#2db365] h-full rounded-full"
                          style={{ width: `${Math.min((domain.count / (stats.topDomains[0]?.count || 1)) * 100, 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Box 3: Top Blocked Domains */}
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-700">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" /> Top Blocked Domains
                  </h4>
                  <span className="text-xs text-slate-400">Blocks</span>
                </div>
                <div className="space-y-2.5 text-xs">
                  {stats.topBlockedDomains.map((domain, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-rose-300">{domain.domain}</span>
                        <span className="font-mono text-rose-400">{domain.count.toLocaleString()}</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-rose-500 h-full rounded-full"
                          style={{ width: `${Math.min((domain.count / (stats.topBlockedDomains[0]?.count || 1)) * 100, 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Box 4: Top Upstream Servers */}
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-700">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <Zap className="w-4 h-4 text-amber-400" /> Top Upstream Servers
                  </h4>
                  <span className="text-xs text-slate-400">Avg. response time</span>
                </div>
                <div className="space-y-2.5 text-xs">
                  {stats.topUpstreams.map((upstream, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center justify-between font-mono">
                        <span className="text-slate-200">{upstream.upstream}</span>
                        <span className="text-amber-400 font-bold">{upstream.avgMs} ms</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-amber-500 h-full rounded-full"
                          style={{ width: `${Math.min((upstream.count / (stats.topUpstreams[0]?.count || 1)) * 100, 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 2: QUERY LOG (Authentic AdGuard Home Log Inspector) */}
        {activeNav === 'logs' && (
          <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-white">Query Log</h3>
                <p className="text-xs text-slate-400">Detailed records of queries processed by AdGuard Web.</p>
              </div>

              <div className="flex items-center gap-2 text-xs">
                {/* Auto-refresh Switch */}
                <button
                  onClick={() => setAutoRefresh(!autoRefresh)}
                  className={`px-3 py-1.5 rounded-lg border font-medium flex items-center gap-1.5 transition ${
                    autoRefresh
                      ? 'bg-[#2db365]/10 text-[#2db365] border-[#2db365]/30'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-spin' : ''}`} />
                  Auto-refresh: {autoRefresh ? '3s' : 'OFF'}
                </button>
              </div>
            </div>

            {/* Filter Controls Row */}
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search by domain, client IP, or rule..."
                  className="w-full bg-[#111827] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-[#2db365]"
                />
              </div>

              <div className="flex items-center gap-1 bg-[#111827] border border-slate-700 p-1 rounded-lg text-xs">
                <button
                  onClick={() => setLogStatusFilter('all')}
                  className={`px-3 py-1 rounded font-medium transition ${
                    logStatusFilter === 'all' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  All ({logs.length})
                </button>
                <button
                  onClick={() => setLogStatusFilter('blocked')}
                  className={`px-3 py-1 rounded font-medium transition ${
                    logStatusFilter === 'blocked' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400 hover:text-rose-300'
                  }`}
                >
                  Blocked
                </button>
                <button
                  onClick={() => setLogStatusFilter('processed')}
                  className={`px-3 py-1 rounded font-medium transition ${
                    logStatusFilter === 'processed' ? 'bg-[#2db365]/20 text-[#2db365]' : 'text-slate-400 hover:text-[#2db365]'
                  }`}
                >
                  Processed
                </button>
              </div>
            </div>

            {/* Queries Table */}
            <div className="overflow-x-auto rounded-lg border border-slate-700 max-h-[550px]">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#182230] text-slate-300 uppercase tracking-wider border-b border-slate-700">
                  <tr>
                    <th className="p-3 pl-4">Time</th>
                    <th className="p-3">Type</th>
                    <th className="p-3">Domain</th>
                    <th className="p-3">Response / Status</th>
                    <th className="p-3">Client</th>
                    <th className="p-3 pr-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 bg-[#111827]">
                  {filteredLogs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-8 text-center text-slate-500 text-xs">
                        No queries found matching current filter.
                      </td>
                    </tr>
                  ) : (
                    filteredLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-slate-800/40 transition">
                        <td className="p-3 pl-4 text-slate-400 whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="p-3 text-slate-400">{log.type}</td>
                        <td className="p-3 font-semibold text-slate-100">{log.domain}</td>
                        <td className="p-3">
                          {log.blocked ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                              <XCircle className="w-3 h-3" /> Blocked ({log.ruleMatched || '0.0.0.0'})
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-bold bg-[#2db365]/20 text-[#2db365] border border-[#2db365]/30">
                              <CheckCircle2 className="w-3 h-3" /> Processed ({log.elapsedMs} ms)
                            </span>
                          )}
                        </td>
                        <td className="p-3 text-slate-300 font-sans">{log.clientIp}</td>
                        <td className="p-3 pr-4 text-right">
                          {!log.blocked ? (
                            <button
                              onClick={() => quickBlock(log.domain)}
                              className="px-2 py-0.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-[10px] font-semibold transition"
                            >
                              Block
                            </button>
                          ) : (
                            <span className="text-slate-500 text-[10px]">Blocked</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* VIEW 3: FILTERS (Blocklists, Blocked Services, Custom Rules, Rewrites) */}
        {activeNav === 'filters' && (
          <div className="space-y-6">
            {/* SUB-TAB 1: DNS Blocklists */}
            {filtersSubTab === 'blocklists' && (
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-700">
                  <div>
                    <h3 className="text-base font-bold text-white">DNS Blocklists</h3>
                    <p className="text-xs text-slate-400">
                      Rule lists used to block ads, tracking, and malware domains.
                    </p>
                  </div>
                  <button
                    onClick={fetchStats}
                    className="px-3 py-1.5 bg-[#2db365] hover:bg-[#259b56] text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3.5 h-3.5" /> Check for updates
                  </button>
                </div>

                <div className="divide-y divide-slate-700/80 rounded-lg border border-slate-700 overflow-hidden">
                  {blocklists.map((list) => (
                    <div key={list.id} className="p-4 bg-[#111827] flex items-center justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm text-white">{list.name}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            {list.category}
                          </span>
                        </div>
                        <a
                          href={list.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-[#2db365] hover:underline flex items-center gap-1 font-mono"
                        >
                          {list.url} <ExternalLink className="w-3 h-3" />
                        </a>
                        <div className="text-[11px] text-slate-400 font-mono">
                          {list.count.toLocaleString()} rules • Synced in RAM
                        </div>
                      </div>

                      <button
                        onClick={() => toggleBlocklist(list.id, list.enabled)}
                        className={`px-4 py-1.5 rounded-lg text-xs font-bold transition ${
                          list.enabled
                            ? 'bg-[#2db365] hover:bg-[#259b56] text-white'
                            : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                        }`}
                      >
                        {list.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SUB-TAB 2: Blocked Services (Official 1-Click Tile Grid) */}
            {filtersSubTab === 'services' && (
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-4">
                <div className="pb-3 border-b border-slate-700">
                  <h3 className="text-base font-bold text-white">Blocked Services</h3>
                  <p className="text-xs text-slate-400">
                    Quickly block popular websites and services on all devices with a single click.
                  </p>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">
                  {services.map((service) => {
                    const isBlocked = stats.blockedServiceIds.includes(service.id);

                    return (
                      <div
                        key={service.id}
                        onClick={() => toggleBlockedService(service.id, isBlocked)}
                        className={`p-3.5 rounded-xl border cursor-pointer select-none transition flex flex-col justify-between h-28 ${
                          isBlocked
                            ? 'bg-rose-500/10 border-rose-500/50 shadow-sm'
                            : 'bg-[#111827] border-slate-700 hover:border-slate-500'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-2xl">{service.icon}</span>
                          <span
                            className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                              isBlocked ? 'bg-rose-500 text-white' : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {isBlocked ? 'BLOCKED' : 'ALLOWED'}
                          </span>
                        </div>
                        <div>
                          <div className="font-bold text-sm text-white">{service.name}</div>
                          <div className="text-[10px] text-slate-400">{service.category}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* SUB-TAB 3: Custom Filtering Rules */}
            {filtersSubTab === 'custom' && (
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-4">
                <div className="pb-3 border-b border-slate-700">
                  <h3 className="text-base font-bold text-white">Custom Filtering Rules</h3>
                  <p className="text-xs text-slate-400">
                    Write custom rules using AdGuard syntax. One rule per line.
                  </p>
                </div>

                <div className="space-y-2">
                  <textarea
                    value={customRulesText}
                    onChange={(e) => setCustomRulesText(e.target.value)}
                    placeholder={"! Add your rules here\n||example.org^\n@@||safe-site.com^\n127.0.0.1 test.local"}
                    rows={8}
                    className="w-full bg-[#111827] border border-slate-700 rounded-lg p-3 text-xs font-mono text-[#2db365] placeholder-slate-600 focus:outline-none focus:border-[#2db365]"
                  />
                  <div className="flex items-center justify-between">
                    <button
                      onClick={addCustomRuleFromEditor}
                      className="px-4 py-2 bg-[#2db365] hover:bg-[#259b56] text-white rounded-lg text-xs font-semibold transition"
                    >
                      Apply Rules
                    </button>
                    {ruleMessage && <span className="text-xs text-[#2db365] font-semibold">{ruleMessage}</span>}
                  </div>
                </div>

                {rules.length > 0 && (
                  <div className="mt-4 space-y-2">
                    <h4 className="text-xs font-bold text-slate-300 uppercase">Active Custom Rules ({rules.length})</h4>
                    <div className="divide-y divide-slate-800 rounded-lg border border-slate-700 bg-[#111827] max-h-60 overflow-y-auto">
                      {rules.map((rule) => (
                        <div key={rule.id} className="p-2.5 px-3 flex items-center justify-between text-xs font-mono">
                          <span className="text-slate-200">{rule.pattern}</span>
                          <button
                            onClick={() => deleteRule(rule.id)}
                            className="text-slate-500 hover:text-rose-400 transition"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* SUB-TAB 4: DNS Rewrites */}
            {filtersSubTab === 'rewrites' && (
              <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-5 shadow-sm space-y-4">
                <div className="pb-3 border-b border-slate-700">
                  <h3 className="text-base font-bold text-white">DNS Rewrites</h3>
                  <p className="text-xs text-slate-400">
                    Return a custom IP address for a specific domain name.
                  </p>
                </div>

                <form onSubmit={addRewrite} className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={rewriteDomain}
                    onChange={(e) => setRewriteDomain(e.target.value)}
                    placeholder="Domain (e.g. dev.local)"
                    className="flex-1 bg-[#111827] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-[#2db365]"
                  />
                  <input
                    type="text"
                    value={rewriteIp}
                    onChange={(e) => setRewriteIp(e.target.value)}
                    placeholder="Answer (e.g. 192.168.1.100)"
                    className="flex-1 bg-[#111827] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-[#2db365]"
                  />
                  <button
                    type="submit"
                    className="px-4 py-2 bg-[#2db365] hover:bg-[#259b56] text-white rounded-lg text-xs font-semibold transition"
                  >
                    Add Rewrite
                  </button>
                </form>

                {stats.rewrites.length > 0 && (
                  <div className="divide-y divide-slate-800 rounded-lg border border-slate-700 bg-[#111827]">
                    {stats.rewrites.map((r) => (
                      <div key={r.id} className="p-3 flex items-center justify-between text-xs font-mono">
                        <div>
                          <strong className="text-white">{r.domain}</strong> &rarr;{' '}
                          <span className="text-[#2db365]">{r.answer}</span>
                        </div>
                        <button onClick={() => deleteRewrite(r.id)} className="text-slate-500 hover:text-rose-400">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* VIEW 4: SETUP GUIDE */}
        {activeNav === 'guide' && (
          <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-6 shadow-sm space-y-6">
            <div>
              <h3 className="text-base font-bold text-white">Device Setup Guide</h3>
              <p className="text-xs text-slate-400">
                Connect any smartphone, laptop, or browser to your AdGuard Web instance.
              </p>
            </div>

            {/* Custom Device Tag Router */}
            <div className="p-4 bg-[#111827] rounded-xl border border-slate-700 space-y-3">
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                <span className="text-xs text-slate-300 font-medium">Device Tag:</span>
                <input
                  type="text"
                  value={deviceTag}
                  onChange={(e) => setDeviceTag(e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, ''))}
                  placeholder="e.g. phone, laptop, tv"
                  className="bg-slate-900 border border-slate-700 rounded-md px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#2db365]"
                />
              </div>

              <div className="text-xs space-y-1">
                <span className="text-slate-400">Your Personalized DoH URL:</span>
                <div className="flex items-center gap-2 bg-slate-900 p-2 rounded-lg border border-slate-700">
                  <code className="text-[#2db365] font-mono flex-1 select-all truncate">
                    {hostUrl ? `${hostUrl}/dns-query/${deviceTag || 'default'}` : ''}
                  </code>
                  <button
                    onClick={() => copyUrl(`${hostUrl}/dns-query/${deviceTag || 'default'}`)}
                    className="px-3 py-1 bg-[#2db365] hover:bg-[#259b56] text-white rounded text-xs font-semibold transition"
                  >
                    Copy
                  </button>
                </div>
              </div>
            </div>

            {/* Platform Guides */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* iOS */}
              <div className="p-4 bg-[#111827] rounded-xl border border-slate-700 space-y-2.5">
                <div className="font-bold text-sm text-white flex items-center gap-2">
                  <Smartphone className="w-4 h-4 text-sky-400" /> iPhone & iPad
                </div>
                <p className="text-xs text-slate-400">
                  Download our official 1-Click Apple `.mobileconfig` encrypted DNS profile directly via Safari.
                </p>
                <a
                  href="/api/mobileconfig"
                  download="adguard-web.mobileconfig"
                  className="inline-flex items-center gap-2 px-3.5 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold transition"
                >
                  <Download className="w-3.5 h-3.5" /> Download iOS Profile
                </a>
              </div>

              {/* Android */}
              <div className="p-4 bg-[#111827] rounded-xl border border-slate-700 space-y-2.5">
                <div className="font-bold text-sm text-white flex items-center gap-2">
                  <Smartphone className="w-4 h-4 text-[#2db365]" /> Android (5G & Wi-Fi)
                </div>
                <p className="text-xs text-slate-400">
                  In <strong>Intra</strong> or <strong>RethinkDNS</strong>, set Custom DNS-over-HTTPS URL to:
                </p>
                <code className="block bg-slate-900 p-2 rounded text-[#2db365] font-mono text-xs select-all">
                  {hostUrl}/dns-query/{deviceTag}
                </code>
              </div>

              {/* Chrome / Edge / Brave */}
              <div className="p-4 bg-[#111827] rounded-xl border border-slate-700 space-y-2.5">
                <div className="font-bold text-sm text-white flex items-center gap-2">
                  <Laptop className="w-4 h-4 text-purple-400" /> Chrome / Edge / Brave
                </div>
                <p className="text-xs text-slate-400">
                  Go to <strong>Settings &gt; Privacy and security &gt; Security &gt; Use Secure DNS</strong>.
                  Select <strong>Custom</strong> and enter:
                </p>
                <code className="block bg-slate-900 p-2 rounded text-purple-300 font-mono text-xs select-all">
                  {hostUrl}/dns-query
                </code>
              </div>

              {/* Hostinger & Vercel */}
              <div className="p-4 bg-[#111827] rounded-xl border border-slate-700 space-y-2.5">
                <div className="font-bold text-sm text-white flex items-center gap-2">
                  <Globe className="w-4 h-4 text-[#2db365]" /> Hostinger / Vercel
                </div>
                <p className="text-xs text-slate-400">
                  Upload this repository to Hostinger Node.js plan or Vercel. Works with free automated HTTPS SSL!
                </p>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 5: SETTINGS */}
        {activeNav === 'settings' && (
          <div className="bg-[#1f2937] border border-slate-700/80 rounded-xl p-6 shadow-sm space-y-6">
            {/* General Settings */}
            {settingsSubTab === 'general' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-base font-bold text-white">General Settings</h3>
                  <p className="text-xs text-slate-400">Control security filters and browsing protection.</p>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 bg-[#111827] rounded-xl border border-slate-700">
                    <div>
                      <div className="font-bold text-sm text-white">Safe Browsing</div>
                      <div className="text-xs text-slate-400">Blocks known malware and phishing domains.</div>
                    </div>
                    <button
                      onClick={toggleSafeBrowsing}
                      className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                        stats.safeBrowsingEnabled ? 'bg-[#2db365] text-white' : 'bg-slate-700 text-slate-400'
                      }`}
                    >
                      {stats.safeBrowsingEnabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-4 bg-[#111827] rounded-xl border border-slate-700">
                    <div>
                      <div className="font-bold text-sm text-white">SafeSearch</div>
                      <div className="text-xs text-slate-400">Enforces SafeSearch on Google, Bing, and YouTube.</div>
                    </div>
                    <button
                      onClick={toggleSafeSearch}
                      className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                        stats.safeSearchEnabled ? 'bg-[#2db365] text-white' : 'bg-slate-700 text-slate-400'
                      }`}
                    >
                      {stats.safeSearchEnabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* DNS Settings */}
            {settingsSubTab === 'dns' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-base font-bold text-white">DNS Settings</h3>
                  <p className="text-xs text-slate-400">Configure upstream encrypted DNS resolvers.</p>
                </div>

                <div className="space-y-3">
                  <label className="text-xs font-bold text-slate-300">Upstream DNS servers</label>
                  <div className="p-3 bg-[#111827] rounded-lg border border-slate-700 space-y-2 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-200">https://dns.quad9.net/dns-query</span>
                      <span className="text-[#2db365] font-semibold">Primary (No-Log)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-200">https://cloudflare-dns.com/dns-query</span>
                      <span className="text-sky-400 font-semibold">Secondary</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Cloud Storage Settings */}
            {settingsSubTab === 'cloud' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-base font-bold text-white">Single Database: Supabase PostgreSQL</h3>
                  <p className="text-xs text-slate-400">
                    No Redis needed! One 100% free Supabase database handles query logs, custom rules, and authentication.
                  </p>
                </div>

                <div className="p-4 bg-[#111827] rounded-xl border border-slate-700 flex items-center justify-between">
                  <div className="space-y-1">
                    <div className="font-bold text-sm text-white flex items-center gap-2">
                      <Database className="w-4 h-4 text-[#2db365]" /> Supabase PostgreSQL (Single DB)
                    </div>
                    <div className="text-xs text-slate-400">
                      Stores query logs, custom rules, blocklists, and rewrites with built-in Auth & RLS.
                    </div>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold border ${
                      cloud.supabaseConnected
                        ? 'bg-[#2db365]/20 text-[#2db365] border-[#2db365]/30'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {cloud.supabaseConnected ? 'Connected (Cloud)' : 'Local In-Memory Mode'}
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-[#2db365]/30 space-y-2 text-xs">
                  <span className="font-bold text-white flex items-center gap-1.5">
                    <Code className="w-4 h-4 text-[#2db365]" /> 1-Click Database Setup Instructions:
                  </span>
                  <p className="text-slate-300">
                    1. Open your project at <a href="https://supabase.com" target="_blank" rel="noreferrer" className="text-[#2db365] underline">supabase.com</a>.
                  </p>
                  <p className="text-slate-300">
                    2. Go to <strong>SQL Editor</strong> in the left sidebar.
                  </p>
                  <p className="text-slate-300">
                    3. Copy the entire contents of <code className="bg-slate-800 px-1.5 py-0.5 rounded text-[#2db365] font-mono">supabase-schema.sql</code> and click <strong>Run</strong>.
                  </p>
                  <p className="text-slate-300">
                    4. Add your <code className="bg-slate-800 px-1.5 py-0.5 rounded text-sky-400 font-mono">NEXT_PUBLIC_SUPABASE_URL</code> and <code className="bg-slate-800 px-1.5 py-0.5 rounded text-sky-400 font-mono">NEXT_PUBLIC_SUPABASE_ANON_KEY</code> in <code className="font-mono text-white">.env.local</code>.
                  </p>
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Official AdvGuard Footer */}
      <footer className="border-t border-slate-800 bg-[#1f2937] py-4 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-bold text-white">AdvGuard Home</span>
            <span className="text-slate-500">•</span>
            <span>Web Edition v1.0</span>
            <span className="text-slate-500">•</span>
            <span className="text-[#2db365] font-semibold">Engineered by Veer Bhanushali</span>
          </div>

          <div className="flex items-center gap-4">
            <a href="/LICENSE" className="hover:text-white transition">
              MIT License
            </a>
            <a href="/README.md" className="hover:text-white transition">
              Documentation
            </a>
            <span className="text-slate-500">Copyright © 2026 Veer Bhanushali</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
