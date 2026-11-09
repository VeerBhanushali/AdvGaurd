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
  AlertTriangle,
  Sun,
  Moon,
  Users,
  Flame,
  Radio,
  FileDown,
  ChevronRight,
  Filter,
  Eye,
  Key,
  Unlock,
  LogOut,
} from 'lucide-react';
import { CuratedListDef } from '@/lib/blocklists';

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
  firewall: {
    blocksCount: number;
    config: {
      threatLevel: 'low' | 'balanced' | 'strict' | 'paranoid';
      blockRiskyTlds: boolean;
      blockAiScrapers: boolean;
      blockCryptoMiners: boolean;
      blockNewDomains: boolean;
      rateLimitEnabled: boolean;
      maxQueriesPerMinute: number;
    };
  };
  curatedLists: CuratedListDef[];
  devices: {
    id: string;
    name: string;
    token: string;
    ownerEmail: string;
    createdAt: number;
    lastActive: number;
    totalQueries: number;
    blockedQueries: number;
    status: 'active' | 'paused' | 'revoked';
  }[];
  users: {
    id: string;
    email: string;
    role: 'admin' | 'user';
    name: string;
    createdAt: number;
  }[];
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
  firebaseConnected?: boolean;
  supabaseConnected: boolean;
  mode: string;
}

export default function AdvGuardApp() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
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
    firewall: {
      blocksCount: 42,
      config: {
        threatLevel: 'balanced',
        blockRiskyTlds: true,
        blockAiScrapers: true,
        blockCryptoMiners: true,
        blockNewDomains: false,
        rateLimitEnabled: true,
        maxQueriesPerMinute: 300,
      },
    },
    curatedLists: [],
    devices: [],
    users: [],
  });

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [blocklists, setBlocklists] = useState<SubscribedList[]>([]);
  const [services, setServices] = useState<ServiceDef[]>([]);
  const [cloud, setCloud] = useState<CloudStatus>({
    firebaseConnected: false,
    supabaseConnected: false,
    mode: 'Local In-Memory Mode',
  });

  // Navigation
  const [activeNav, setActiveNav] = useState<'dashboard' | 'logs' | 'firewall' | 'filters' | 'users' | 'guide' | 'settings'>('dashboard');
  const [filtersSubTab, setFiltersSubTab] = useState<'curated' | 'services' | 'blocklists' | 'custom' | 'rewrites'>('curated');
  const [guideSubTab, setGuideSubTab] = useState<'public' | 'ios' | 'android' | 'windows' | 'mac' | 'router' | 'browser'>('public');

  const [copied, setCopied] = useState(false);
  const [hostUrl, setHostUrl] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Filters
  const [logStatusFilter, setLogStatusFilter] = useState<'all' | 'blocked' | 'processed'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Device registration modal state
  const [newDevName, setNewDevName] = useState('');
  const [newDevToken, setNewDevToken] = useState('');
  const [showAddDeviceModal, setShowAddDeviceModal] = useState(false);

  // Custom rules text
  const [customRulesText, setCustomRulesText] = useState('');
  const [ruleMessage, setRuleMessage] = useState('');

  // DNS Rewrite input
  const [rewriteDomain, setRewriteDomain] = useState('');
  const [rewriteIp, setRewriteIp] = useState('');

  // Live Tester
  const [testDomain, setTestDomain] = useState('doubleclick.net');
  const [testResult, setTestResult] = useState<any>(null);
  const [isTesting, setIsTesting] = useState(false);

  // Admin & Public Access Control
  const [hasAdminPassword, setHasAdminPassword] = useState(false);
  const [isAdminUnlocked, setIsAdminUnlocked] = useState(false);
  const [adminKey, setAdminKey] = useState('');
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [loginPasswordInput, setLoginPasswordInput] = useState('');
  const [loginError, setLoginError] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [detectedOs, setDetectedOs] = useState('');

  const PUBLIC_DOMAIN = 'advgaurd.veerbhanushali.com';

  const fetchStats = async () => {
    try {
      const key = localStorage.getItem('advguard-admin-key') || adminKey || '';
      const res = await fetch('/api/stats', {
        headers: key ? { 'x-admin-key': key } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setStats(data.stats);
        setHasAdminPassword(!!data.hasAdminPassword);
        setIsAdminUnlocked(!!data.isAdmin);
        if (data.isAdmin) {
          setLogs(data.logs || []);
          setRules(data.rules || []);
          setBlocklists(data.blocklists || []);
        } else {
          setLogs([]);
          setRules([]);
          setBlocklists([]);
        }
        if (data.availableServices) setServices(data.availableServices);
        if (data.cloud) setCloud(data.cloud);
      }
    } catch {
      // offline / compiling
    }
  };

  useEffect(() => {
    setHostUrl(window.location.origin);
    const savedTheme = localStorage.getItem('advguard-theme') as 'dark' | 'light' | null;
    if (savedTheme) setTheme(savedTheme);

    const savedKey = localStorage.getItem('advguard-admin-key');
    if (savedKey) {
      setAdminKey(savedKey);
      setIsAdminUnlocked(true);
    } else {
      setActiveNav('guide');
    }

    if (typeof navigator !== 'undefined') {
      const ua = navigator.userAgent.toLowerCase();
      if (/iphone|ipad|ipod/.test(ua)) {
        setDetectedOs('Apple iOS');
        setGuideSubTab('ios');
      } else if (/android/.test(ua)) {
        setDetectedOs('Android');
        setGuideSubTab('android');
      } else if (/win/.test(ua)) {
        setDetectedOs('Windows');
        setGuideSubTab('windows');
      } else if (/mac/.test(ua)) {
        setDetectedOs('macOS');
        setGuideSubTab('browser');
      }
    }

    fetchStats();
    if (!autoRefresh) return;
    const interval = setInterval(fetchStats, 3000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('advguard-theme', next);
  };

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const authPost = async (action: string, payload: any = {}) => {
    const key = localStorage.getItem('advguard-admin-key') || adminKey || '';
    try {
      const res = await fetch('/api/stats', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(key ? { 'x-admin-key': key } : {}),
        },
        body: JSON.stringify({ action, ...payload }),
      });
      if (res.status === 401) {
        setShowLoginModal(true);
        return false;
      }
      return res.ok;
    } catch {
      return false;
    }
  };

  const handleAdminLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginPasswordInput) return;
    setIsVerifying(true);
    setLoginError('');
    try {
      const res = await fetch('/api/stats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'verify-admin', password: loginPasswordInput }),
      });
      const data = await res.json();
      if (data.success) {
        localStorage.setItem('advguard-admin-key', loginPasswordInput);
        setAdminKey(loginPasswordInput);
        setIsAdminUnlocked(true);
        setShowLoginModal(false);
        setLoginPasswordInput('');
        setActiveNav('dashboard');
        fetchStats();
      } else {
        setLoginError('Incorrect admin passcode. Access denied.');
      }
    } catch {
      setLoginError('Authentication failed. Server unreachable.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleAdminLogout = () => {
    localStorage.removeItem('advguard-admin-key');
    setAdminKey('');
    setIsAdminUnlocked(false);
    setActiveNav('guide');
    fetchStats();
  };

  const toggleProtection = async () => {
    const ok = await authPost('set-protection', { enabled: !stats.protectionEnabled });
    if (ok) fetchStats();
  };

  const updateFirewall = async (key: string, value: any) => {
    const updated = { ...stats.firewall.config, [key]: value };
    const ok = await authPost('update-firewall', { config: updated });
    if (ok) fetchStats();
  };

  const registerDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDevName.trim() || !newDevToken.trim()) return;
    await fetch('/api/stats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'register-device', name: newDevName, token: newDevToken }),
    });
    setNewDevName('');
    setNewDevToken('');
    setShowAddDeviceModal(false);
    fetchStats();
  };

  const deleteDevice = async (id: string) => {
    const ok = await authPost('delete-device', { id });
    if (ok) fetchStats();
  };

  const clearLogs = async () => {
    const ok = await authPost('clear-logs');
    if (ok) fetchStats();
  };

  const exportLogsToCsv = () => {
    const headers = 'Time,Type,Domain,Status,Client,Latency(ms),Upstream\n';
    const rows = logs
      .map(
        (l) =>
          `"${new Date(l.timestamp).toISOString()}","${l.type}","${l.domain}","${
            l.blocked ? 'BLOCKED' : 'RESOLVED'
          }","${l.clientIp}","${l.elapsedMs}","${l.upstream || ''}"`
      )
      .join('\n');

    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `advguard-logs-${Date.now()}.csv`;
    a.click();
  };

  const toggleBlockedService = async (serviceId: string, current: boolean) => {
    const ok = await authPost('toggle-service', { serviceId, enabled: !current });
    if (ok) fetchStats();
  };

  const toggleBlocklist = async (id: string, current: boolean) => {
    const ok = await authPost('toggle-blocklist', { id, enabled: !current });
    if (ok) fetchStats();
  };

  const addCustomRule = async () => {
    const lines = customRulesText.split('\n');
    let count = 0;
    for (const line of lines) {
      if (line.trim()) {
        const ok = await authPost('add-rule', { rule: line.trim() });
        if (ok) count++;
      }
    }
    setCustomRulesText('');
    setRuleMessage(`Applied ${count} custom rule(s)!`);
    setTimeout(() => setRuleMessage(''), 3000);
    fetchStats();
  };

  const deleteRule = async (id: string) => {
    const ok = await authPost('delete-rule', { id });
    if (ok) fetchStats();
  };

  const addRewrite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rewriteDomain.trim() || !rewriteIp.trim()) return;
    const ok = await authPost('add-rewrite', { domain: rewriteDomain, answer: rewriteIp });
    if (ok) {
      setRewriteDomain('');
      setRewriteIp('');
      fetchStats();
    }
  };

  const deleteRewrite = async (id: string) => {
    const ok = await authPost('delete-rewrite', { id });
    if (ok) fetchStats();
  };

  const quickBlock = async (domain: string) => {
    const ok = await authPost('add-rule', { rule: `||${domain}^` });
    if (ok) fetchStats();
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

  const filteredLogs = logs.filter((log) => {
    if (logStatusFilter === 'blocked' && !log.blocked) return false;
    if (logStatusFilter === 'processed' && log.blocked) return false;
    if (searchQuery && !log.domain.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const isDark = theme === 'dark';

  return (
    <div
      className={`min-h-screen flex flex-col font-sans transition-colors duration-200 ${
        isDark ? 'bg-[#090D16] text-slate-100' : 'bg-slate-50 text-slate-900'
      }`}
    >
      {/* Top Header Navbar */}
      <header
        className={`border-b sticky top-0 z-50 backdrop-blur-md transition-colors ${
          isDark ? 'bg-[#0E1524]/90 border-slate-800' : 'bg-white/95 border-slate-200 shadow-sm'
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <div className="flex items-center gap-8">
              <div
                onClick={() => setActiveNav('dashboard')}
                className="flex items-center gap-3 cursor-pointer group select-none"
              >
                <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-emerald-600 to-emerald-400 flex items-center justify-center text-white shadow-md shadow-emerald-500/20">
                  <Shield className="w-5 h-5 fill-white/20 stroke-[2.5]" />
                </div>
                <div className="flex items-baseline gap-1.5">
                  <span className="font-extrabold text-xl tracking-tight text-white dark:text-white">
                    Adv<span className="text-emerald-500">Guard</span>
                  </span>
                  <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                    Pro Engine
                  </span>
                </div>
              </div>

              {/* Navigation Links */}
              <nav className="hidden lg:flex items-center space-x-1 text-sm font-medium">
                {(isAdminUnlocked
                  ? [
                      { id: 'dashboard', label: 'Dashboard', icon: Activity },
                      { id: 'logs', label: 'Query Log', icon: ShieldAlert },
                      { id: 'firewall', label: 'Smart Firewall', icon: Flame },
                      { id: 'filters', label: 'Blocklists & Rules', icon: Layers },
                      { id: 'users', label: 'Devices & Users', icon: Users },
                      { id: 'guide', label: 'Setup Guide', icon: Smartphone },
                      { id: 'settings', label: 'Settings', icon: Sliders },
                    ]
                  : [
                      { id: 'guide', label: 'Connect & Setup Guide', icon: Smartphone },
                      { id: 'firewall', label: 'Firewall Protection', icon: Flame },
                    ]
                ).map((item) => {
                  const Icon = item.icon;
                  const active = activeNav === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => setActiveNav(item.id as any)}
                      className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition text-xs font-semibold ${
                        active
                          ? isDark
                            ? 'bg-slate-800 text-emerald-400 border border-slate-700'
                            : 'bg-slate-100 text-emerald-600 border border-slate-200'
                          : isDark
                          ? 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      {item.label}
                    </button>
                  );
                })}
              </nav>
            </div>

            {/* Right Header Actions */}
            <div className="flex items-center gap-3">
              {isAdminUnlocked ? (
                <>
                  {/* Protection Switch (Admin Only) */}
                  <button
                    onClick={toggleProtection}
                    className={`flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-bold transition border ${
                      stats.protectionEnabled
                        ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30 hover:bg-emerald-500/20'
                        : 'bg-rose-500/10 text-rose-500 border-rose-500/30 hover:bg-rose-500/20'
                    }`}
                  >
                    <span
                      className={`w-2 h-2 rounded-full ${
                        stats.protectionEnabled ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'
                      }`}
                    />
                    Protection: {stats.protectionEnabled ? 'ON' : 'PAUSED'}
                  </button>

                  {/* Sign Out Button */}
                  <button
                    onClick={handleAdminLogout}
                    title="Sign out of Admin Session"
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition"
                  >
                    <Unlock className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Admin Mode</span>
                    <LogOut className="w-3.5 h-3.5 ml-0.5 text-slate-400" />
                  </button>
                </>
              ) : (
                <>
                  {/* Public Shield Status Indicator */}
                  <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="hidden sm:inline">Public Cloud DNS:</span> Active
                  </div>

                  {/* Admin Sign In Trigger */}
                  <button
                    onClick={() => setShowLoginModal(true)}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 transition shadow-sm"
                  >
                    <Lock className="w-3.5 h-3.5 text-amber-400" />
                    <span>Admin Login</span>
                  </button>
                </>
              )}

              {/* Theme Toggle Button */}
              <button
                onClick={toggleTheme}
                title={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
                className={`p-2 rounded-xl border transition ${
                  isDark
                    ? 'bg-slate-800/80 text-amber-400 border-slate-700 hover:bg-slate-700'
                    : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-100 shadow-sm'
                }`}
              >
                {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              </button>

              {/* Creator Pill */}
              <div
                className={`hidden md:flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-xl border ${
                  isDark ? 'bg-slate-800/60 border-slate-700 text-slate-300' : 'bg-slate-100 border-slate-200 text-slate-700'
                }`}
              >
                <span className="text-slate-400">By</span>
                <strong className="text-emerald-500">Veer Bhanushali</strong>
              </div>
            </div>
          </div>
        </div>

        {/* Filters Sub-navigation */}
        {activeNav === 'filters' && (
          <div
            className={`border-t px-4 sm:px-8 py-2 flex items-center space-x-3 text-xs font-semibold ${
              isDark ? 'bg-[#0b101c] border-slate-800' : 'bg-slate-100 border-slate-200'
            }`}
          >
            {[
              { id: 'curated', label: 'Curated AdvGuard Lists' },
              { id: 'services', label: 'Blocked Services' },
              { id: 'blocklists', label: 'Subscribed Lists' },
              { id: 'custom', label: 'Custom User Rules' },
              { id: 'rewrites', label: 'DNS Rewrites' },
            ].map((sub) => (
              <button
                key={sub.id}
                onClick={() => setFiltersSubTab(sub.id as any)}
                className={`px-3 py-1 rounded-md transition ${
                  filtersSubTab === sub.id
                    ? 'bg-emerald-600 text-white'
                    : isDark
                    ? 'text-slate-400 hover:text-white'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {sub.label}
              </button>
            ))}
          </div>
        )}

        {/* Setup Guide Sub-navigation */}
        {activeNav === 'guide' && (
          <div
            className={`border-t px-4 sm:px-8 py-2 flex items-center space-x-3 text-xs font-semibold overflow-x-auto ${
              isDark ? 'bg-[#0b101c] border-slate-800' : 'bg-slate-100 border-slate-200'
            }`}
          >
            {[
              { id: 'public', label: 'Free Public DNS' },
              { id: 'ios', label: 'iOS & iPadOS' },
              { id: 'android', label: 'Android' },
              { id: 'windows', label: 'Windows 11 / 10' },
              { id: 'mac', label: 'macOS' },
              { id: 'router', label: 'Routers' },
              { id: 'browser', label: 'Chrome / Edge / Firefox' },
            ].map((g) => (
              <button
                key={g.id}
                onClick={() => setGuideSubTab(g.id as any)}
                className={`px-3 py-1 rounded-md transition whitespace-nowrap ${
                  guideSubTab === g.id
                    ? 'bg-emerald-600 text-white'
                    : isDark
                    ? 'text-slate-400 hover:text-white'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {g.label}
              </button>
            ))}
          </div>
        )}
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 w-full space-y-8">
        {/* PUBLIC ACCESS HERO BANNER (advgaurd.veerbhanushali.com) */}
        <div
          className={`rounded-2xl p-6 border relative overflow-hidden transition ${
            isDark
              ? 'bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-900 border-emerald-500/30'
              : 'bg-gradient-to-r from-emerald-50 via-white to-white border-emerald-200 shadow-sm'
          }`}
        >
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-xs font-bold">
                <Radio className="w-3.5 h-3.5 animate-pulse" /> FREE GLOBAL PUBLIC DNS SERVICE
              </div>
              <h2 className={`text-xl sm:text-2xl font-black tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Zero Setup? Connect to <span className="text-emerald-500">advgaurd.veerbhanushali.com</span>
              </h2>
              <p className={`text-xs sm:text-sm max-w-2xl ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                You don’t even need to host your own server. Paste our public DNS endpoint into your phone’s Private DNS or
                mobile VPN app, and all ads and trackers will be blocked automatically anywhere in the world!
              </p>
            </div>

            {/* Quick Copy Box */}
            <div
              className={`p-3 rounded-xl border flex items-center gap-3 w-full lg:w-auto font-mono text-xs ${
                isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-100 border-slate-300'
              }`}
            >
              <div className="space-y-0.5">
                <div className="text-[10px] text-slate-500 uppercase font-sans font-bold">Public DoH URL</div>
                <div className="text-emerald-500 font-bold select-all truncate max-w-xs sm:max-w-sm">
                  https://advgaurd.veerbhanushali.com/dns-query
                </div>
              </div>
              <button
                onClick={() => copyText('https://advgaurd.veerbhanushali.com/dns-query')}
                className="px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-sans font-bold text-xs flex items-center gap-1.5 transition shrink-0"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
        </div>

        {/* PUBLIC ACCESS RESTRICTION BANNER FOR ADMIN TABS */}
        {!isAdminUnlocked && activeNav !== 'guide' && activeNav !== 'firewall' ? (
          <div
            className={`p-8 max-w-xl mx-auto rounded-3xl border text-center space-y-4 shadow-xl my-12 ${
              isDark ? 'border-slate-800 bg-[#101726]' : 'border-slate-200 bg-white'
            }`}
          >
            <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-400 flex items-center justify-center mx-auto">
              <Lock className="w-6 h-6" />
            </div>
            <div className="space-y-1.5">
              <h3 className={`font-extrabold text-lg ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Admin Portal Protected
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed max-w-md mx-auto">
                You are connected to the official <strong>AdvGuard Public DNS</strong>. Real-time query logs, firewall configuration, and cloud database settings are restricted to system administrators to safeguard user privacy.
              </p>
            </div>
            <div className="pt-2 flex items-center justify-center gap-3">
              <button
                onClick={() => setActiveNav('guide')}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-xl"
              >
                View Public Setup Guide
              </button>
              <button
                onClick={() => setShowLoginModal(true)}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-xl shadow-md flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" /> Sign In as Admin
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* VIEW 1: DASHBOARD */}
        {activeNav === 'dashboard' && (
          <div className="space-y-8">
            {/* 4 Big KPI Metric Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Queries */}
              <div
                className={`p-5 rounded-2xl border transition shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider">DNS Queries</span>
                  <Activity className="w-4 h-4 text-sky-500" />
                </div>
                <div className={`text-3xl font-black font-mono ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  {stats.totalQueries.toLocaleString()}
                </div>
                <div className="text-xs text-slate-500 mt-2 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" /> Upstream DoH active
                </div>
              </div>

              {/* Blocked by Filters */}
              <div
                className={`p-5 rounded-2xl border transition shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider">Blocked by Filters</span>
                  <ShieldAlert className="w-4 h-4 text-rose-500" />
                </div>
                <div className="text-3xl font-black font-mono text-rose-500">
                  {stats.blockedQueries.toLocaleString()}
                </div>
                <div className="text-xs text-slate-500 mt-2">{stats.blockedPercentage}% of all traffic filtered</div>
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full mt-2.5 overflow-hidden">
                  <div
                    className="bg-rose-500 h-full rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(stats.blockedPercentage, 100)}%` }}
                  />
                </div>
              </div>

              {/* Firewall Blocks */}
              <div
                className={`p-5 rounded-2xl border transition shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider">Firewall Blocks</span>
                  <Flame className="w-4 h-4 text-amber-500" />
                </div>
                <div className="text-3xl font-black font-mono text-amber-500">
                  {stats.firewall.blocksCount.toLocaleString()}
                </div>
                <div className="text-xs text-slate-500 mt-2">Spam TLDs, AI Scrapers, Miners</div>
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full mt-2.5 overflow-hidden">
                  <div className="bg-amber-500 h-full w-2/5 rounded-full" />
                </div>
              </div>

              {/* Active Security Rules */}
              <div
                className={`p-5 rounded-2xl border transition shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider">Active Rules</span>
                  <Layers className="w-4 h-4 text-purple-500" />
                </div>
                <div className={`text-3xl font-black font-mono ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  {stats.rulesCount.toLocaleString()}
                </div>
                <div className="text-xs text-slate-500 mt-2">AdvGuard Ultra + Custom Filters</div>
              </div>
            </div>

            {/* Live DNS Domain Tester */}
            <div
              className={`p-5 rounded-2xl border transition ${
                isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200 shadow-sm'
              }`}
            >
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <h3 className={`text-sm font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    <Search className="w-4 h-4 text-emerald-500" /> Real-Time Domain Lookup & AdBlock Tester
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Query your AdvGuard DoH resolver live to verify if any domain is blocked or allowed.
                  </p>
                </div>

                <form onSubmit={runTester} className="flex items-center gap-2 w-full sm:w-auto">
                  <input
                    type="text"
                    value={testDomain}
                    onChange={(e) => setTestDomain(e.target.value)}
                    placeholder="e.g. doubleclick.net, google.com"
                    className={`px-3 py-2 rounded-xl text-xs font-mono border focus:outline-none focus:border-emerald-500 w-full sm:w-64 ${
                      isDark ? 'bg-slate-950 border-slate-800 text-white' : 'bg-slate-50 border-slate-300 text-slate-900'
                    }`}
                  />
                  <button
                    type="submit"
                    disabled={isTesting}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition shrink-0"
                  >
                    {isTesting ? 'Testing...' : 'Test DoH'}
                  </button>
                </form>
              </div>

              {testResult && (
                <div
                  className={`mt-4 p-3 rounded-xl border text-xs font-mono flex items-center justify-between ${
                    isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <span>
                    Domain: <strong className={isDark ? 'text-white' : 'text-slate-900'}>{testDomain}</strong>
                  </span>
                  {testResult.Blocked ? (
                    <span className="px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-500 font-bold border border-rose-500/30">
                      BLOCKED BY ADVGUARD (0.0.0.0)
                    </span>
                  ) : (
                    <span className="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-500 font-bold border border-emerald-500/30">
                      RESOLVED VIA ENCRYPTED UPSTREAM
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* 24-Hour Activity Chart */}
            <div
              className={`p-6 rounded-2xl border transition shadow-sm space-y-4 ${
                isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    DNS Queries Over Time (24h Activity)
                  </h3>
                  <p className="text-xs text-slate-500">Hourly query volume: Clean requests vs. blocked ads</p>
                </div>
                <div className="flex items-center gap-4 text-xs font-semibold">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 bg-emerald-500 rounded-sm" /> Clean Queries
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 bg-rose-500 rounded-sm" /> Blocked Traffic
                  </div>
                </div>
              </div>

              <div className="h-36 flex items-end justify-between gap-3 pt-6 border-b border-slate-200 dark:border-slate-800 px-2">
                {stats.chartData.map((item, idx) => {
                  const maxVal = 300;
                  const queryH = Math.min((item.queries / maxVal) * 100, 100);
                  const blockedH = Math.min((item.blocked / maxVal) * 100, 100);

                  return (
                    <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group">
                      <div className="w-full flex items-end justify-center gap-1 h-full">
                        <div
                          className="w-1/2 bg-emerald-500 rounded-t transition-all group-hover:bg-emerald-400"
                          style={{ height: `${queryH}%` }}
                        />
                        <div
                          className="w-1/2 bg-rose-500 rounded-t transition-all group-hover:bg-rose-400"
                          style={{ height: `${blockedH}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono mt-1">{item.time}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 2x2 Tables Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Top Queried Domains */}
              <div
                className={`p-5 rounded-2xl border space-y-4 shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
                  <h4 className={`text-sm font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    <Globe className="w-4 h-4 text-emerald-500" /> Top Queried Domains
                  </h4>
                  <span className="text-xs text-slate-500 font-mono">Requests</span>
                </div>
                <div className="space-y-3 text-xs">
                  {stats.topDomains.map((d, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center justify-between font-mono">
                        <span className={isDark ? 'text-slate-200' : 'text-slate-700'}>{d.domain}</span>
                        <span className="text-slate-400">{d.count.toLocaleString()}</span>
                      </div>
                      <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-emerald-500 h-full rounded-full"
                          style={{ width: `${Math.min((d.count / (stats.topDomains[0]?.count || 1)) * 100, 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Blocked Domains */}
              <div
                className={`p-5 rounded-2xl border space-y-4 shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
                  <h4 className={`text-sm font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    <ShieldAlert className="w-4 h-4 text-rose-500" /> Top Blocked Trackers
                  </h4>
                  <span className="text-xs text-slate-500 font-mono">Blocked</span>
                </div>
                <div className="space-y-3 text-xs">
                  {stats.topBlockedDomains.map((d, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center justify-between font-mono">
                        <span className="text-rose-400">{d.domain}</span>
                        <span className="text-rose-500 font-bold">{d.count.toLocaleString()}</span>
                      </div>
                      <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-rose-500 h-full rounded-full"
                          style={{ width: `${Math.min((d.count / (stats.topBlockedDomains[0]?.count || 1)) * 100, 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 2: QUERY LOG */}
        {activeNav === 'logs' && (
          <div
            className={`p-6 rounded-2xl border space-y-4 shadow-sm ${
              isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
            }`}
          >
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <h3 className={`text-lg font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>Real-Time Query Log</h3>
                <p className="text-xs text-slate-500">Live stream of DNS queries resolved by AdvGuard.</p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={exportLogsToCsv}
                  className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-xs font-bold rounded-xl flex items-center gap-1.5 transition"
                >
                  <FileDown className="w-3.5 h-3.5" /> Export CSV
                </button>
                <button
                  onClick={clearLogs}
                  className="px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 border border-rose-500/30 text-xs font-bold rounded-xl flex items-center gap-1.5 transition"
                >
                  <Trash2 className="w-3.5 h-3.5" /> Clear
                </button>
              </div>
            </div>

            {/* Filter Bar */}
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter by domain or client..."
                  className={`w-full border rounded-xl pl-9 pr-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500 ${
                    isDark ? 'bg-slate-950 border-slate-800 text-white' : 'bg-slate-50 border-slate-300 text-slate-900'
                  }`}
                />
              </div>

              <div className="flex items-center gap-1 p-1 rounded-xl border text-xs bg-slate-100 dark:bg-slate-950 border-slate-200 dark:border-slate-800">
                <button
                  onClick={() => setLogStatusFilter('all')}
                  className={`px-3 py-1 rounded-lg font-bold transition ${
                    logStatusFilter === 'all'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-sm'
                      : 'text-slate-500 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  All ({logs.length})
                </button>
                <button
                  onClick={() => setLogStatusFilter('blocked')}
                  className={`px-3 py-1 rounded-lg font-bold transition ${
                    logStatusFilter === 'blocked' ? 'bg-rose-500 text-white' : 'text-slate-500 hover:text-rose-500'
                  }`}
                >
                  Blocked
                </button>
                <button
                  onClick={() => setLogStatusFilter('processed')}
                  className={`px-3 py-1 rounded-lg font-bold transition ${
                    logStatusFilter === 'processed' ? 'bg-emerald-600 text-white' : 'text-slate-500 hover:text-emerald-500'
                  }`}
                >
                  Processed
                </button>
              </div>
            </div>

            {/* Log Table */}
            <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800 max-h-[550px]">
              <table className="w-full text-left text-xs font-mono">
                <thead
                  className={`uppercase tracking-wider border-b ${
                    isDark ? 'bg-slate-950 text-slate-400 border-slate-800' : 'bg-slate-100 text-slate-600 border-slate-200'
                  }`}
                >
                  <tr>
                    <th className="p-3 pl-4">Time</th>
                    <th className="p-3">Type</th>
                    <th className="p-3">Domain</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Client</th>
                    <th className="p-3 pr-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className={`divide-y ${isDark ? 'divide-slate-800 bg-[#0c121f]' : 'divide-slate-200 bg-white'}`}>
                  {filteredLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition">
                      <td className="p-3 pl-4 text-slate-400 whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="p-3 text-slate-400">{log.type}</td>
                      <td className="p-3 font-semibold">{log.domain}</td>
                      <td className="p-3">
                        {log.blocked ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/10 text-rose-500 border border-rose-500/20">
                            BLOCKED ({log.ruleMatched || '0.0.0.0'})
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                            RESOLVED ({log.elapsedMs} ms)
                          </span>
                        )}
                      </td>
                      <td className="p-3 font-sans text-slate-400">{log.clientIp}</td>
                      <td className="p-3 pr-4 text-right">
                        {!log.blocked ? (
                          <button
                            onClick={() => quickBlock(log.domain)}
                            className="px-2.5 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 border border-rose-500/30 rounded text-[10px] font-bold transition"
                          >
                            Block
                          </button>
                        ) : (
                          <span className="text-slate-400 text-[10px]">Blocked</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* VIEW 3: SMART FIREWALL (Killer feature AdGuard does NOT have) */}
        {activeNav === 'firewall' && (
          <div className="space-y-6">
            <div
              className={`p-6 rounded-2xl border space-y-4 shadow-sm ${
                isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
              }`}
            >
              <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
                <div>
                  <h3 className={`text-lg font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    <Flame className="w-5 h-5 text-amber-500" /> AdvGuard Smart DNS Firewall
                  </h3>
                  <p className="text-xs text-slate-500">
                    Next-generation behavioral heuristics, spam TLD blocking, anti-bot protection, and cryptojacking defense.
                  </p>
                </div>
                <div className="text-right">
                  <div className="text-xs font-bold text-slate-400">Total Threats Neutralized</div>
                  <div className="text-2xl font-black font-mono text-amber-500">
                    {stats.firewall.blocksCount.toLocaleString()}
                  </div>
                </div>
              </div>

              {/* Threat Defense Level */}
              <div className="space-y-2">
                <label className="text-xs font-bold uppercase text-slate-400">Threat Defense Level</label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { id: 'low', name: 'Low', desc: 'Permissive' },
                    { id: 'balanced', name: 'Balanced', desc: 'Recommended' },
                    { id: 'strict', name: 'Strict', desc: 'Aggressive' },
                    { id: 'paranoid', name: 'Paranoid', desc: 'Lockdown' },
                  ].map((level) => (
                    <button
                      key={level.id}
                      onClick={() => updateFirewall('threatLevel', level.id)}
                      className={`p-3 rounded-xl border text-left transition ${
                        stats.firewall.config.threatLevel === level.id
                          ? 'bg-amber-500/10 border-amber-500 text-amber-500'
                          : isDark
                          ? 'bg-slate-950 border-slate-800 text-slate-400'
                          : 'bg-slate-50 border-slate-200 text-slate-700'
                      }`}
                    >
                      <div className="font-bold text-xs">{level.name}</div>
                      <div className="text-[10px] text-slate-500">{level.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Firewall Security Toggles */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                {/* 1. Risky TLDs */}
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between ${
                    isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="space-y-0.5">
                    <div className="font-bold text-xs text-white dark:text-white">Block High-Risk Spam TLDs</div>
                    <div className="text-[11px] text-slate-500">
                      Drops queries to `.top`, `.xyz`, `.work`, `.click`, `.surf` known for malware.
                    </div>
                  </div>
                  <button
                    onClick={() => updateFirewall('blockRiskyTlds', !stats.firewall.config.blockRiskyTlds)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                      stats.firewall.config.blockRiskyTlds ? 'bg-emerald-600 text-white' : 'bg-slate-700 text-slate-400'
                    }`}
                  >
                    {stats.firewall.config.blockRiskyTlds ? 'Active' : 'Disabled'}
                  </button>
                </div>

                {/* 2. AI Scrapers & Crawlers */}
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between ${
                    isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="space-y-0.5">
                    <div className="font-bold text-xs text-white dark:text-white">Block AI Scrapers & Harvesters</div>
                    <div className="text-[11px] text-slate-500">
                      Blocks OpenAI, Anthropic, Common Crawl, and ByteDance web scrapers.
                    </div>
                  </div>
                  <button
                    onClick={() => updateFirewall('blockAiScrapers', !stats.firewall.config.blockAiScrapers)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                      stats.firewall.config.blockAiScrapers ? 'bg-emerald-600 text-white' : 'bg-slate-700 text-slate-400'
                    }`}
                  >
                    {stats.firewall.config.blockAiScrapers ? 'Active' : 'Disabled'}
                  </button>
                </div>

                {/* 3. Cryptojacking & In-Browser Mining */}
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between ${
                    isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="space-y-0.5">
                    <div className="font-bold text-xs text-white dark:text-white">Block In-Browser Cryptominers</div>
                    <div className="text-[11px] text-slate-500">
                      Stops websites from secretly hijacking your CPU to mine crypto (Coinhive, etc.).
                    </div>
                  </div>
                  <button
                    onClick={() => updateFirewall('blockCryptoMiners', !stats.firewall.config.blockCryptoMiners)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                      stats.firewall.config.blockCryptoMiners ? 'bg-emerald-600 text-white' : 'bg-slate-700 text-slate-400'
                    }`}
                  >
                    {stats.firewall.config.blockCryptoMiners ? 'Active' : 'Disabled'}
                  </button>
                </div>

                {/* 4. Anti-DDoS Rate Limiting */}
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between ${
                    isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="space-y-0.5">
                    <div className="font-bold text-xs text-white dark:text-white">Anti-DDoS DNS Rate Limiting</div>
                    <div className="text-[11px] text-slate-500">
                      Caps requests per IP to 300/min to mitigate DNS amplification flood attacks.
                    </div>
                  </div>
                  <button
                    onClick={() => updateFirewall('rateLimitEnabled', !stats.firewall.config.rateLimitEnabled)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                      stats.firewall.config.rateLimitEnabled ? 'bg-emerald-600 text-white' : 'bg-slate-700 text-slate-400'
                    }`}
                  >
                    {stats.firewall.config.rateLimitEnabled ? 'Active' : 'Disabled'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 4: BLOCKLISTS & RULES */}
        {activeNav === 'filters' && (
          <div className="space-y-6">
            {/* SUB-TAB 1: Curated AdvGuard Blocklists (by Veer Bhanushali) with Download */}
            {filtersSubTab === 'curated' && (
              <div
                className={`p-6 rounded-2xl border space-y-4 shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Curated AdvGuard Master Blocklists (by Veer Bhanushali)
                  </h3>
                  <p className="text-xs text-slate-500">
                    Hand-crafted, optimized blocklists. Download as raw text or load into any external adblocker.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {stats.curatedLists.map((list) => (
                    <div
                      key={list.id}
                      className={`p-5 rounded-xl border flex flex-col justify-between space-y-3 ${
                        isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                      }`}
                    >
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-sm text-emerald-500">{list.name}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-500">
                            {list.category}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400">{list.description}</p>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {list.count.toLocaleString()} rules • Curated by {list.curator} • {list.updatedAt}
                        </div>
                      </div>

                      <div className="flex items-center justify-between pt-2 border-t border-slate-800">
                        <span className="text-xs text-emerald-500 font-bold flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Built-in & Active
                        </span>
                        <a
                          href={`/api/blocklists/download?id=${list.id}`}
                          download={`${list.id}.txt`}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 transition"
                        >
                          <Download className="w-3.5 h-3.5" /> Download .txt
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SUB-TAB 2: Blocked Services */}
            {filtersSubTab === 'services' && (
              <div
                className={`p-6 rounded-2xl border space-y-4 shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    1-Click Blocked Services
                  </h3>
                  <p className="text-xs text-slate-500">
                    Instantly block social media, gaming, and streaming platforms across all connected devices.
                  </p>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">
                  {services.map((service) => {
                    const isBlocked = stats.blockedServiceIds.includes(service.id);
                    return (
                      <div
                        key={service.id}
                        onClick={() => toggleBlockedService(service.id, isBlocked)}
                        className={`p-4 rounded-xl border cursor-pointer select-none transition flex flex-col justify-between h-28 ${
                          isBlocked
                            ? 'bg-rose-500/10 border-rose-500/40 text-rose-400'
                            : isDark
                            ? 'bg-slate-950 border-slate-800 hover:border-slate-700'
                            : 'bg-slate-50 border-slate-200 hover:border-slate-300'
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
                          <div className="font-bold text-xs">{service.name}</div>
                          <div className="text-[10px] text-slate-500">{service.category}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* SUB-TAB 3: Subscribed Lists */}
            {filtersSubTab === 'blocklists' && (
              <div
                className={`p-6 rounded-2xl border space-y-4 shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <div>
                    <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                      DNS Blocklists
                    </h3>
                    <p className="text-xs text-slate-500">External blocklist subscriptions.</p>
                  </div>
                  <button
                    onClick={fetchStats}
                    className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-lg flex items-center gap-1.5 transition"
                  >
                    <RefreshCw className="w-3.5 h-3.5" /> Sync Lists
                  </button>
                </div>

                <div className="divide-y divide-slate-800 rounded-xl border border-slate-800 overflow-hidden">
                  {blocklists.map((list) => (
                    <div key={list.id} className="p-4 bg-slate-950 flex items-center justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm text-white">{list.name}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                            {list.category}
                          </span>
                        </div>
                        <div className="text-xs text-slate-500 font-mono">
                          {list.count.toLocaleString()} rules • Active in RAM
                        </div>
                      </div>

                      <button
                        onClick={() => toggleBlocklist(list.id, list.enabled)}
                        className={`px-4 py-1.5 rounded-lg text-xs font-bold transition ${
                          list.enabled
                            ? 'bg-emerald-600 text-white'
                            : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                        }`}
                      >
                        {list.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SUB-TAB 4: Custom Filtering Rules */}
            {filtersSubTab === 'custom' && (
              <div
                className={`p-6 rounded-2xl border space-y-4 shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Custom Filtering Rules
                  </h3>
                  <p className="text-xs text-slate-500">
                    Write custom rules using AdGuard syntax (`||domain.com^` to block, `@@||domain.com^` to allow).
                  </p>
                </div>

                <div className="space-y-2">
                  <textarea
                    value={customRulesText}
                    onChange={(e) => setCustomRulesText(e.target.value)}
                    placeholder={"||ads.example.com^\n@@||safe-subdomain.com^\n127.0.0.1 test.dev"}
                    rows={6}
                    className={`w-full border rounded-xl p-3 text-xs font-mono focus:outline-none focus:border-emerald-500 ${
                      isDark ? 'bg-slate-950 border-slate-800 text-emerald-400' : 'bg-slate-50 border-slate-300 text-emerald-600'
                    }`}
                  />
                  <div className="flex items-center justify-between">
                    <button
                      onClick={addCustomRule}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition"
                    >
                      Apply Rules
                    </button>
                    {ruleMessage && <span className="text-xs text-emerald-500 font-bold">{ruleMessage}</span>}
                  </div>
                </div>

                {rules.length > 0 && (
                  <div className="space-y-2 pt-2">
                    <h4 className="text-xs font-bold uppercase text-slate-400">Active Rules ({rules.length})</h4>
                    <div className="divide-y divide-slate-800 rounded-xl border border-slate-800 bg-slate-950 max-h-60 overflow-y-auto">
                      {rules.map((rule) => (
                        <div key={rule.id} className="p-3 flex items-center justify-between text-xs font-mono">
                          <span className="text-slate-200">{rule.pattern}</span>
                          <button onClick={() => deleteRule(rule.id)} className="text-slate-500 hover:text-rose-500">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* SUB-TAB 5: DNS Rewrites */}
            {filtersSubTab === 'rewrites' && (
              <div
                className={`p-6 rounded-2xl border space-y-4 shadow-sm ${
                  isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>DNS Rewrites</h3>
                  <p className="text-xs text-slate-500">Map internal domain names to specific IP addresses.</p>
                </div>

                <form onSubmit={addRewrite} className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={rewriteDomain}
                    onChange={(e) => setRewriteDomain(e.target.value)}
                    placeholder="Domain (e.g. dev.local)"
                    className={`flex-1 border rounded-xl px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500 ${
                      isDark ? 'bg-slate-950 border-slate-800 text-white' : 'bg-slate-50 border-slate-300 text-slate-900'
                    }`}
                  />
                  <input
                    type="text"
                    value={rewriteIp}
                    onChange={(e) => setRewriteIp(e.target.value)}
                    placeholder="Answer IP (e.g. 192.168.1.100)"
                    className={`flex-1 border rounded-xl px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500 ${
                      isDark ? 'bg-slate-950 border-slate-800 text-white' : 'bg-slate-50 border-slate-300 text-slate-900'
                    }`}
                  />
                  <button
                    type="submit"
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition"
                  >
                    Add Rewrite
                  </button>
                </form>

                {stats.rewrites.length > 0 && (
                  <div className="divide-y divide-slate-800 rounded-xl border border-slate-800 bg-slate-950">
                    {stats.rewrites.map((r) => (
                      <div key={r.id} className="p-3 flex items-center justify-between text-xs font-mono">
                        <div>
                          <strong className="text-white">{r.domain}</strong> &rarr;{' '}
                          <span className="text-emerald-500">{r.answer}</span>
                        </div>
                        <button onClick={() => deleteRewrite(r.id)} className="text-slate-500 hover:text-rose-500">
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

        {/* VIEW 5: DEVICES & USERS (Multi-Tenancy) */}
        {activeNav === 'users' && (
          <div className="space-y-6">
            <div
              className={`p-6 rounded-2xl border space-y-6 shadow-sm ${
                isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
              }`}
            >
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div>
                  <h3 className={`text-lg font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    <Users className="w-5 h-5 text-emerald-500" /> Authorized Devices & Multi-User Management
                  </h3>
                  <p className="text-xs text-slate-500">
                    Assign individual devices and client endpoints. Monitor per-device query traffic.
                  </p>
                </div>

                <button
                  onClick={() => setShowAddDeviceModal(true)}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 transition"
                >
                  <Plus className="w-4 h-4" /> Register New Device
                </button>
              </div>

              {/* Devices Table */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase text-slate-400">Connected Device Profiles ({stats.devices.length})</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {stats.devices.map((dev) => (
                    <div
                      key={dev.id}
                      className={`p-4 rounded-xl border flex flex-col justify-between space-y-3 ${
                        isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-sm">{dev.name}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                            {dev.status.toUpperCase()}
                          </span>
                        </div>
                        <div className="text-xs text-slate-400 font-mono">Token: {dev.token}</div>
                        <div className="text-[11px] text-slate-500">
                          {dev.totalQueries.toLocaleString()} queries • {dev.blockedQueries.toLocaleString()} blocked
                        </div>
                      </div>

                      <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
                        <button
                          onClick={() => copyText(`https://${PUBLIC_DOMAIN}/dns-query/${dev.token}`)}
                          className="text-emerald-500 font-bold hover:underline flex items-center gap-1"
                        >
                          <Copy className="w-3 h-3" /> Copy DoH URL
                        </button>
                        <button onClick={() => deleteDevice(dev.id)} className="text-slate-500 hover:text-rose-500">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Add Device Modal Form */}
              {showAddDeviceModal && (
                <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                  <div
                    className={`max-w-md w-full p-6 rounded-2xl border space-y-4 shadow-2xl ${
                      isDark ? 'bg-slate-900 border-slate-800 text-white' : 'bg-white border-slate-200 text-slate-900'
                    }`}
                  >
                    <h4 className="font-bold text-base">Register New Device Profile</h4>
                    <form onSubmit={registerDevice} className="space-y-3 text-xs">
                      <div className="space-y-1">
                        <label className="text-slate-400">Device Name</label>
                        <input
                          type="text"
                          value={newDevName}
                          onChange={(e) => setNewDevName(e.target.value)}
                          placeholder="e.g. Sister's iPhone, Work Laptop"
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-slate-400">Custom Device Tag / Token</label>
                        <input
                          type="text"
                          value={newDevToken}
                          onChange={(e) => setNewDevToken(e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, ''))}
                          placeholder="e.g. sister-phone"
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white font-mono"
                        />
                      </div>
                      <div className="flex items-center justify-end gap-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setShowAddDeviceModal(false)}
                          className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl"
                        >
                          Cancel
                        </button>
                        <button type="submit" className="px-4 py-2 bg-emerald-600 text-white font-bold rounded-xl">
                          Register Device
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* VIEW 6: SETUP GUIDE */}
        {activeNav === 'guide' && (
          <div
            className={`p-6 rounded-2xl border space-y-6 shadow-sm ${
              isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
            }`}
          >
            {/* Guide: Free Public DNS */}
            {guideSubTab === 'public' && (
              <div className="space-y-4">
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Use AdvGuard Free Public DNS (Zero Installation)
                  </h3>
                  <p className="text-xs text-slate-500">
                    Host it on your phone or computer right now using our official public server.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                    <span className="font-bold text-xs text-emerald-400">DNS-over-HTTPS (DoH) URL:</span>
                    <div className="flex items-center gap-2 bg-slate-900 p-2 rounded-lg border border-slate-800 font-mono text-xs">
                      <code className="text-emerald-400 flex-1 truncate select-all">
                        https://advgaurd.veerbhanushali.com/dns-query
                      </code>
                      <button
                        onClick={() => copyText('https://advgaurd.veerbhanushali.com/dns-query')}
                        className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[11px] font-bold"
                      >
                        Copy
                      </button>
                    </div>
                  </div>

                  <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                    <span className="font-bold text-xs text-sky-400">Android Private DNS Hostname:</span>
                    <div className="flex items-center gap-2 bg-slate-900 p-2 rounded-lg border border-slate-800 font-mono text-xs">
                      <code className="text-sky-400 flex-1 truncate select-all">advgaurd.veerbhanushali.com</code>
                      <button
                        onClick={() => copyText('advgaurd.veerbhanushali.com')}
                        className="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded text-[11px] font-bold"
                      >
                        Copy
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Guide: iOS */}
            {guideSubTab === 'ios' && (
              <div className="space-y-4">
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Apple iOS & iPadOS Setup (1-Click Profile)
                  </h3>
                  <p className="text-xs text-slate-500">
                    Installs an official encrypted DNS configuration directly into iOS Settings. Zero apps required.
                  </p>
                </div>

                <div className="p-5 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                  <p className="text-xs text-slate-300">
                    1. Open this website in Safari on your iPhone or iPad.
                  </p>
                  <p className="text-xs text-slate-300">
                    2. Click the button below to download the signed `.mobileconfig` profile:
                  </p>
                  <a
                    href="/api/mobileconfig"
                    download="advguard.mobileconfig"
                    className="inline-flex items-center gap-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl text-xs transition"
                  >
                    <Download className="w-4 h-4" /> Download 1-Click iOS Profile
                  </a>
                  <p className="text-xs text-slate-400 pt-2">
                    3. Open <strong>Settings &gt; Profile Downloaded &gt; Install</strong>.
                  </p>
                </div>
              </div>
            )}

            {/* Guide: Android */}
            {guideSubTab === 'android' && (
              <div className="space-y-4">
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Android Setup (5G & Wi-Fi)
                  </h3>
                  <p className="text-xs text-slate-500">
                    System-wide ad-blocking across all Android apps, browsers, and mobile games.
                  </p>
                </div>

                <div className="p-5 bg-slate-950 rounded-xl border border-slate-800 space-y-3 text-xs text-slate-300">
                  <div className="font-bold text-emerald-400">Method 1: Native Private DNS (Recommended)</div>
                  <p>1. Go to <strong>Settings &gt; Network &amp; internet &gt; Private DNS</strong>.</p>
                  <p>2. Select <strong>Private DNS provider hostname</strong>.</p>
                  <p>3. Enter:</p>
                  <code className="block bg-slate-900 p-2 rounded text-emerald-400 font-mono select-all">
                    advgaurd.veerbhanushali.com
                  </code>
                </div>
              </div>
            )}

            {/* Guide: Windows */}
            {guideSubTab === 'windows' && (
              <div className="space-y-4">
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Windows 11 / 10 DNS-over-HTTPS Setup
                  </h3>
                  <p className="text-xs text-slate-500">Native Windows encrypted DNS resolution.</p>
                </div>

                <div className="p-5 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs text-slate-300">
                  <p>1. Open <strong>Settings &gt; Network &amp; internet &gt; Wi-Fi (or Ethernet) &gt; Hardware properties</strong>.</p>
                  <p>2. Click <strong>Edit</strong> next to DNS server assignment.</p>
                  <p>3. Switch to <strong>Manual</strong>, enable <strong>IPv4</strong>, and enter DoH template:</p>
                  <code className="block bg-slate-900 p-2 rounded text-emerald-400 font-mono select-all">
                    https://advgaurd.veerbhanushali.com/dns-query
                  </code>
                </div>
              </div>
            )}

            {/* Guide: Browsers */}
            {guideSubTab === 'browser' && (
              <div className="space-y-4">
                <div>
                  <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Desktop Browser Secure DNS
                  </h3>
                  <p className="text-xs text-slate-500">Chrome, Edge, Brave, and Firefox.</p>
                </div>

                <div className="p-5 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs text-slate-300">
                  <p>1. Open browser <strong>Settings &gt; Privacy and security &gt; Security</strong>.</p>
                  <p>2. Scroll to <strong>Use secure DNS</strong> &rarr; Select <strong>Custom</strong>.</p>
                  <p>3. Paste:</p>
                  <code className="block bg-slate-900 p-2 rounded text-emerald-400 font-mono select-all">
                    https://advgaurd.veerbhanushali.com/dns-query
                  </code>
                </div>
              </div>
            )}
          </div>
        )}

        {/* VIEW 7: SETTINGS & CLOUD */}
        {activeNav === 'settings' && (
          <div
            className={`p-6 rounded-2xl border space-y-6 shadow-sm ${
              isDark ? 'bg-[#101726] border-slate-800' : 'bg-white border-slate-200'
            }`}
          >
            <div>
              <h3 className={`text-base font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Database &amp; Cloud Configuration
              </h3>
              <p className="text-xs text-slate-500">
                AdvGuard supports dual zero-friction cloud engines: Firebase (Zero-SQL NoSQL) or Supabase (PostgreSQL SQL).
              </p>
            </div>

            {/* Current Active Engine Status */}
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-bold text-sm text-white flex items-center gap-2">
                  <Database className="w-4 h-4 text-emerald-500" /> Active Database Engine
                </div>
                <div className="text-xs text-slate-400 font-mono mt-0.5">
                  Mode: {cloud.mode}
                </div>
              </div>
              <span
                className={`px-3 py-1 rounded-full text-xs font-bold border ${
                  cloud.firebaseConnected || cloud.supabaseConnected
                    ? 'bg-emerald-500/20 text-emerald-500 border-emerald-500/30'
                    : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                }`}
              >
                {cloud.firebaseConnected
                  ? '⚡ Firebase Connected'
                  : cloud.supabaseConnected
                  ? '⚡ Supabase Connected'
                  : '🚀 Ultra-Fast RAM Cache Active'}
              </span>
            </div>

            {/* Dual Engine Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Option A: Firebase */}
              <div
                className={`p-5 rounded-xl border space-y-3 ${
                  cloud.firebaseConnected
                    ? 'bg-emerald-950/20 border-emerald-500/40'
                    : isDark
                    ? 'bg-slate-950 border-slate-800'
                    : 'bg-slate-50 border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm text-white flex items-center gap-2">
                    🔥 Google Firebase
                  </span>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                      cloud.firebaseConnected
                        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {cloud.firebaseConnected ? 'CONNECTED' : 'ZERO SQL SETUP'}
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Zero SQL migrations needed. Collections like <code className="text-emerald-400">query_logs</code> auto-create dynamically on the first query.
                </p>
                <div className="p-3 bg-slate-900 rounded-lg text-xs space-y-1.5 text-slate-300 border border-slate-800">
                  <div className="font-semibold text-slate-200">How to connect Firebase:</div>
                  <p>1. Create project at <a href="https://console.firebase.google.com" target="_blank" rel="noreferrer" className="text-emerald-400 underline font-bold">firebase.google.com</a></p>
                  <p>2. Enable <strong>Firestore Database</strong> and <strong>Authentication</strong></p>
                  <p>3. Copy web app config to <code className="text-sky-400 font-mono">.env.local</code>:</p>
                  <pre className="bg-slate-950 p-2 rounded text-[11px] text-slate-400 font-mono overflow-x-auto">
NEXT_PUBLIC_FIREBASE_API_KEY="..."&#10;NEXT_PUBLIC_FIREBASE_PROJECT_ID="..."
                  </pre>
                </div>
              </div>

              {/* Option B: Supabase */}
              <div
                className={`p-5 rounded-xl border space-y-3 ${
                  cloud.supabaseConnected
                    ? 'bg-emerald-950/20 border-emerald-500/40'
                    : isDark
                    ? 'bg-slate-950 border-slate-800'
                    : 'bg-slate-50 border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm text-white flex items-center gap-2">
                    ⚡ Supabase (PostgreSQL)
                  </span>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                      cloud.supabaseConnected
                        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {cloud.supabaseConnected ? 'CONNECTED' : 'RELATIONAL SQL'}
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Ideal for large-scale time-series analytics, relational queries, and zero daily write-count quotas.
                </p>
                <div className="p-3 bg-slate-900 rounded-lg text-xs space-y-1.5 text-slate-300 border border-slate-800">
                  <div className="font-semibold text-slate-200">How to connect Supabase:</div>
                  <p>1. Create project at <a href="https://supabase.com" target="_blank" rel="noreferrer" className="text-emerald-400 underline font-bold">supabase.com</a></p>
                  <p>2. Open <strong>SQL Editor</strong> &amp; run <code className="text-emerald-400 font-mono">supabase-schema.sql</code></p>
                  <p>3. Copy Project URL &amp; Anon Key to <code className="text-sky-400 font-mono">.env.local</code>:</p>
                  <pre className="bg-slate-950 p-2 rounded text-[11px] text-slate-400 font-mono overflow-x-auto">
NEXT_PUBLIC_SUPABASE_URL="..."&#10;NEXT_PUBLIC_SUPABASE_ANON_KEY="..."
                  </pre>
                </div>
              </div>
            </div>

            {/* Built-in Memory RAM Cache Banner */}
            <div className="p-4 bg-slate-950 rounded-xl border border-emerald-500/20 text-xs text-slate-300 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center font-bold font-mono">
                  RAM
                </div>
                <div>
                  <div className="font-bold text-white">Built-in In-Memory LRU Shield (0.01ms Latency)</div>
                  <div className="text-[11px] text-slate-400">
                    AdvGuard caches all frequent DNS responses in RAM to eliminate redundant database reads and reduce API calls to zero.
                  </div>
                </div>
              </div>
              <span className="text-emerald-400 font-bold px-2 py-1 bg-emerald-500/10 rounded-md border border-emerald-500/20">
                Always Active
              </span>
            </div>
          </div>
        )}
      </>
    )}

    {/* ADMIN LOGIN MODAL */}
    {showLoginModal && (
      <div className="fixed inset-0 bg-black/70 backdrop-blur-md z-50 flex items-center justify-center p-4">
        <div
          className={`max-w-md w-full p-6 rounded-2xl border space-y-5 shadow-2xl transition-all ${
            isDark ? 'bg-[#0E1524] border-slate-800 text-white' : 'bg-white border-slate-200 text-slate-900'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center">
                <Lock className="w-4 h-4" />
              </div>
              <div>
                <h4 className="font-extrabold text-sm">AdvGuard Admin Login</h4>
                <p className="text-[11px] text-slate-400">Authenticate to manage cloud DNS &amp; telemetry</p>
              </div>
            </div>
            <button
              onClick={() => {
                setShowLoginModal(false);
                setLoginError('');
              }}
              className="text-slate-500 hover:text-slate-300 p-1 rounded-lg"
            >
              ✕
            </button>
          </div>

          <form onSubmit={handleAdminLogin} className="space-y-4 text-xs">
            {loginError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-xl text-xs font-semibold">
                {loginError}
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-slate-400 font-semibold">Master Admin Passcode</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={loginPasswordInput}
                  onChange={(e) => setLoginPasswordInput(e.target.value)}
                  placeholder="Enter admin passcode"
                  autoFocus
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500 pr-10 font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  <Eye className="w-4 h-4" />
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Default password: <code className="text-emerald-400">advguard2026</code> (configured via <code className="text-emerald-400">ADMIN_PASSWORD</code>).
              </p>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => {
                  setShowLoginModal(false);
                  setLoginError('');
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-semibold"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isVerifying || !loginPasswordInput}
                className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold rounded-xl shadow-md transition flex items-center gap-1.5"
              >
                {isVerifying ? 'Verifying...' : 'Unlock Admin Panel'}
              </button>
            </div>
          </form>
        </div>
      </div>
    )}
  </main>

      {/* Modern Footer */}
      <footer
        className={`border-t py-6 text-xs transition-colors ${
          isDark ? 'bg-[#0a0f1a] border-slate-800 text-slate-500' : 'bg-white border-slate-200 text-slate-600'
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className={`font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>AdvGuard Home</span>
            <span>•</span>
            <span>Web Edition v1.0</span>
            <span>•</span>
            <span className="text-emerald-500 font-bold">Engineered by Veer Bhanushali</span>
          </div>

          <div className="flex items-center gap-4">
            <a href="/LICENSE" className="hover:text-emerald-500 transition">
              MIT License
            </a>
            <a href="/README.md" className="hover:text-emerald-500 transition">
              Documentation
            </a>
            <span>Copyright © 2026 Veer Bhanushali</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
