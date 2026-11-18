import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  AppWindow,
  Building2,
  CheckCircle2,
  Globe,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { useNla } from '../context/NlaContext';
import { GlobalDataMap } from './GlobalDataMap';
import type { NavSectionId } from '../types/nla';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function OverviewDashboard({
  onNavigate,
}: {
  onNavigate: (tab: NavSectionId) => void;
}) {
  const {
    profile,
    acceptConsent,
    connections,
    applications,
    thirdParties,
    riskAlerts,
    auditLogs,
    scanWebAppAndSave,
    inspectDomainAndSave,
  } = useNla();

  const [quickTarget, setQuickTarget] = useState('');
  const [quickMode, setQuickMode] = useState<'web' | 'domain'>('web');
  const [running, setRunning] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const openAlerts = riskAlerts.filter((a) => a.status === 'open');
  const totalBytes = connections.reduce((acc, c) => acc + c.bytesTransferred, 0);

  const categoryCounts = connections.reduce<Record<string, number>>((acc, c) => {
    acc[c.serviceCategory] = (acc[c.serviceCategory] || 0) + 1;
    return acc;
  }, {});
  const sortedCategories = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]);

  const handleQuickInspect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickTarget.trim()) return;
    setRunning(true);
    setErrorMsg(null);
    setStatusMsg(null);
    try {
      if (quickMode === 'web') {
        await scanWebAppAndSave(quickTarget.trim());
        setStatusMsg(`Completed live web privacy inspection for ${quickTarget.trim()}.`);
      } else {
        await inspectDomainAndSave({
          domain: quickTarget.trim(),
          appName: quickTarget.trim(),
        });
        setStatusMsg(`Completed live DNS/TLS/GeoIP probe for ${quickTarget.trim()}.`);
      }
      setQuickTarget('');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Inspection failed.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {profile && !profile.consentAccepted && (
        <div className="bg-[#0B172B] border border-sky-500/40 rounded-xl p-5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-sky-400 text-sm font-semibold">
              <ShieldCheck className="w-4 h-4" />
              Explicit Monitoring &amp; Inspection Consent Required
            </div>
            <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
              NLA operates strictly under user-authorized inspection. Confirm that you authorize NLA to store your submitted DNS/TLS probes, imported network captures, and policy analyses in your isolated workspace with configurable retention.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void acceptConsent()}
            className="px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            Authorize Workspace Inspection
          </button>
        </div>
      )}

      {/* Quick Live Inspection Bar */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Live Privacy &amp; Destination Inspector
            </h2>
            <p className="text-xs text-slate-400">
              Run real DNS, TLS certificate, GeoIP, ASN, and third-party origin inspections on any public application or domain.
            </p>
          </div>
          <div className="flex items-center gap-1 p-1 bg-[#060C18] border border-slate-800 rounded-lg self-start">
            <button
              type="button"
              onClick={() => setQuickMode('web')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                quickMode === 'web'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Scan Website
            </button>
            <button
              type="button"
              onClick={() => setQuickMode('domain')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                quickMode === 'domain'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Probe Domain
            </button>
          </div>
        </div>

        <form onSubmit={handleQuickInspect} className="flex flex-col sm:flex-row gap-2.5">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={quickTarget}
              onChange={(e) => setQuickTarget(e.target.value)}
              placeholder={
                quickMode === 'web'
                  ? 'Enter website URL (e.g. https://wikipedia.org or https://nytimes.com)'
                  : 'Enter hostname (e.g. api.github.com or google-analytics.com)'
              }
              className="w-full pl-9 pr-3 py-2.5 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
          <button
            type="submit"
            disabled={running || !quickTarget.trim()}
            className="px-5 py-2.5 text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            {running ? 'Inspecting Live...' : quickMode === 'web' ? 'Run Web Scan' : 'Probe Destination'}
          </button>
        </form>

        {statusMsg && (
          <div className="flex items-center gap-2 text-xs text-emerald-400">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{statusMsg}</span>
          </div>
        )}
        {errorMsg && (
          <div className="text-xs text-rose-300 bg-rose-950/40 border border-rose-500/30 rounded-lg px-3 py-2">
            {errorMsg}
          </div>
        )}
      </div>

      {/* 4-Column KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <button
          type="button"
          onClick={() => onNavigate('map')}
          className="text-left bg-[#0B1426] border border-slate-800/90 hover:border-sky-500/40 rounded-xl p-4 transition-colors"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Observed Connections</span>
            <Globe className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-100 font-mono tabular-nums">
            {connections.length}
          </div>
          <div className="mt-1 text-xs text-slate-400 font-mono tabular-nums">
            {formatBytes(totalBytes)} measured payload metadata
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('apps')}
          className="text-left bg-[#0B1426] border border-slate-800/90 hover:border-sky-500/40 rounded-xl p-4 transition-colors"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Analyzed Applications</span>
            <AppWindow className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-100 font-mono tabular-nums">
            {applications.length}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            {applications.length > 0
              ? `Avg privacy score ${Math.round(
                  applications.reduce((s, a) => s + a.privacyScore, 0) / applications.length
                )}/100`
              : 'Scan web apps or manifests'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('third-parties')}
          className="text-left bg-[#0B1426] border border-slate-800/90 hover:border-sky-500/40 rounded-xl p-4 transition-colors"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Third-Party Services</span>
            <Building2 className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-100 font-mono tabular-nums">
            {thirdParties.length}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            Verified ASN &amp; hosting intelligence
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('risks')}
          className="text-left bg-[#0B1426] border border-slate-800/90 hover:border-amber-500/40 rounded-xl p-4 transition-colors"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Open Privacy Alerts</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-100 font-mono tabular-nums">
            {openAlerts.length}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            {riskAlerts.length} total findings logged
          </div>
        </button>
      </div>

      {/* Interactive Global Map Preview */}
      <GlobalDataMap compact />

      {/* Category Distribution & Recent Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-6 bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Destination Classification Breakdown
            </h3>
            <button
              type="button"
              onClick={() => onNavigate('third-parties')}
              className="text-xs text-sky-400 hover:text-sky-300"
            >
              View Registry
            </button>
          </div>
          {sortedCategories.length === 0 ? (
            <p className="text-xs text-slate-400 py-6">
              No destination telemetry recorded yet. Run a live domain probe or import a capture file to populate distribution charts.
            </p>
          ) : (
            <div className="space-y-2.5">
              {sortedCategories.map(([cat, count]) => {
                const pct = Math.round((count / connections.length) * 100);
                return (
                  <div key={cat} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-200 capitalize">{cat.replace('-', ' ')}</span>
                      <span className="text-slate-400 font-mono tabular-nums">
                        {count} ({pct}%)
                      </span>
                    </div>
                    <div className="h-2 bg-[#060C18] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-sky-500 rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="lg:col-span-6 bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              Recent Security &amp; Privacy Audit Activity
            </h3>
            <button
              type="button"
              onClick={() => onNavigate('settings')}
              className="text-xs text-sky-400 hover:text-sky-300"
            >
              Full Audit Log
            </button>
          </div>
          {auditLogs.length === 0 ? (
            <p className="text-xs text-slate-400 py-6">
              Audit trail events will appear here as you register devices, inspect domains, or analyze privacy policies.
            </p>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {auditLogs.slice(0, 6).map((log) => (
                <div key={log.id} className="py-2.5 flex items-start justify-between gap-3 text-xs">
                  <div className="min-w-0">
                    <div className="font-mono text-sky-300">{log.action}</div>
                    <p className="text-slate-400 truncate mt-0.5">{log.details}</p>
                  </div>
                  <span className="text-slate-500 font-mono shrink-0">{log.targetType}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
