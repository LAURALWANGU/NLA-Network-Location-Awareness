import React, { useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  Pause,
  Play,
  ShieldAlert,
  SlidersHorizontal,
  Square,
  Volume2,
} from 'lucide-react';
import { useNla } from '../context/NlaContext';
import type { AlertCategory, AlertSeverity, AlertStatus } from '../types/nla';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function LiveNetworkMonitor() {
  const {
    devices,
    connections,
    riskAlerts,
    liveEvents,
    monitoringPaused,
    setMonitoringPaused,
    toggleDeviceStatus,
  } = useNla();

  const activeDevices = devices.filter((d) => d.status === 'active');
  const uniqueApps = Array.from(new Set(connections.map((c) => c.appName)));
  const uniqueDomains = Array.from(new Set(connections.map((c) => c.destinationDomain)));
  const backgroundConns = connections.filter((c) => c.isBackground);
  const totalBytes = connections.reduce((sum, c) => sum + c.bytesTransferred, 0);

  return (
    <div className="space-y-6">
      {/* Control Bar */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <h2 className="text-base font-semibold text-slate-100">
              Real-Time Privacy &amp; Network Stream
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Authorized SSE telemetry stream powered by live DNS/TLS probes, capture imports, and registered endpoint agents.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {monitoringPaused ? (
            <button
              type="button"
              onClick={() => setMonitoringPaused(false)}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg transition-colors"
            >
              <Play className="w-3.5 h-3.5" />
              Resume Stream
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setMonitoringPaused(true)}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-amber-600 hover:bg-amber-500 text-white rounded-lg transition-colors"
            >
              <Pause className="w-3.5 h-3.5" />
              Pause Stream
            </button>
          )}
          {devices.map((dev) => (
            <button
              key={dev.id}
              type="button"
              onClick={() =>
                void toggleDeviceStatus(
                  dev.id,
                  dev.status === 'active' ? 'stopped' : 'active'
                )
              }
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 text-slate-200 rounded-lg transition-colors"
            >
              <Square className="w-3 h-3 text-rose-400" />
              {dev.name}: {dev.status}
            </button>
          ))}
        </div>
      </div>

      {/* Live Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 text-xs">
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4">
          <div className="text-slate-400">Active Endpoints</div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-100 mt-1">
            {activeDevices.length} / {devices.length}
          </div>
        </div>
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4">
          <div className="text-slate-400">Observed Apps</div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-100 mt-1">
            {uniqueApps.length}
          </div>
        </div>
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4">
          <div className="text-slate-400">Unique External Domains</div>
          <div className="text-xl font-bold font-mono tabular-nums text-sky-400 mt-1">
            {uniqueDomains.length}
          </div>
        </div>
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4">
          <div className="text-slate-400">Background Connections</div>
          <div className="text-xl font-bold font-mono tabular-nums text-amber-400 mt-1">
            {backgroundConns.length}
          </div>
        </div>
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4">
          <div className="text-slate-400">Measured Transfer</div>
          <div className="text-xl font-bold font-mono tabular-nums text-emerald-400 mt-1">
            {formatBytes(totalBytes)}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7 bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Authorized Stream Events ({liveEvents.length})
            </h3>
            <span className="text-xs font-mono text-slate-400">
              {monitoringPaused ? 'PAUSED BY USER' : 'SSE CONNECTED'}
            </span>
          </div>
          <div className="divide-y divide-slate-800/70 max-h-96 overflow-y-auto">
            {liveEvents.length === 0 ? (
              <div className="p-6 text-xs text-slate-400 text-center">
                Awaiting authorized probes, capture uploads, or endpoint agent heartbeats.
              </div>
            ) : (
              liveEvents.map((ev, idx) => (
                <div key={idx} className="p-3.5 text-xs space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-sky-400 uppercase">{ev.type}</span>
                    <span className="font-mono tabular-nums text-slate-500">
                      {ev.timestamp.slice(0, 19).replace('T', ' ')} UTC
                    </span>
                  </div>
                  <p className="text-slate-200">{ev.summary}</p>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="lg:col-span-5 bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">
              Recent Real-Time Privacy Alerts ({riskAlerts.length})
            </h3>
          </div>
          <div className="divide-y divide-slate-800/70 max-h-96 overflow-y-auto">
            {riskAlerts.length === 0 ? (
              <div className="p-6 text-xs text-slate-400 text-center">
                No suspicious patterns, threat feed matches, or unexpected third-party destinations flagged yet.
              </div>
            ) : (
              riskAlerts.slice(0, 10).map((alert) => (
                <div key={alert.id} className="p-3.5 text-xs space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-amber-300 uppercase">
                      {alert.severity}
                    </span>
                    <span className="text-slate-400 capitalize">{alert.status}</span>
                  </div>
                  <div className="font-medium text-slate-100">{alert.title}</div>
                  <div className="text-slate-400">
                    {alert.appName}
                    {alert.externalFeedSource ? ` · External Feed: ${alert.externalFeedSource}` : ''}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

const ALERT_CATEGORY_OPTIONS: Array<{ id: 'all' | AlertCategory; label: string }> = [
  { id: 'all', label: 'All Categories' },
  { id: 'threat-feed-match', label: 'Threat Feed Match' },
  { id: 'new-destination', label: 'New Destination' },
  { id: 'excessive-permissions', label: 'Sensitive Permissions' },
  { id: 'data-spike', label: 'Data Spike' },
  { id: 'policy-violation', label: 'Policy Risk' },
  { id: 'background-beacon', label: 'Background Beacon' },
  { id: 'unexpected-third-party', label: 'Third-Party Ad/Tracker' },
  { id: 'disclosure-mismatch', label: 'Disclosure Gap' },
];

export function AlertPreferencesPanel() {
  const { alertConfig, updateAlertPreferences, testAlertNotification } = useNla();
  const [saving, setSaving] = useState(false);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const [permThreshold, setPermThreshold] = useState<number>(
    alertConfig?.sensitivePermissionThreshold ?? 4
  );
  const [spikeKb, setSpikeKb] = useState<number>(alertConfig?.dataSpikeThresholdKb ?? 512);
  const [pushPermission, setPushPermission] = useState<string>(
    typeof Notification !== 'undefined' ? Notification.permission : 'unsupported'
  );

  React.useEffect(() => {
    if (alertConfig) {
      setPermThreshold(alertConfig.sensitivePermissionThreshold);
      setSpikeKb(alertConfig.dataSpikeThresholdKb);
    }
  }, [alertConfig]);

  if (!alertConfig) {
    return null;
  }

  const toggleSetting = async (
    key:
      | 'enableNewThirdPartyAlert'
      | 'enableSensitivePermissionAlert'
      | 'enableDataSpikeAlert'
      | 'enablePolicyViolationAlert'
      | 'enableThreatFeedAlert'
      | 'notifyInAppBanner'
      | 'notifyBrowserPush'
      | 'notifySoundChime',
    val: boolean
  ) => {
    setSaving(true);
    setSavedMsg(null);
    try {
      await updateAlertPreferences({ [key]: val });
      setSavedMsg('Alert preference updated and audit-logged.');
    } finally {
      setSaving(false);
    }
  };

  const handleSaveThresholds = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedMsg(null);
    try {
      await updateAlertPreferences({
        sensitivePermissionThreshold: permThreshold,
        dataSpikeThresholdKb: spikeKb,
      });
      setSavedMsg('Custom alert thresholds saved.');
    } finally {
      setSaving(false);
    }
  };

  const handleRequestBrowserPush = async () => {
    if (typeof Notification === 'undefined') return;
    const perm = await Notification.requestPermission();
    setPushPermission(perm);
    if (perm === 'granted') {
      await updateAlertPreferences({ notifyBrowserPush: true });
      setSavedMsg('Browser push notifications enabled.');
    }
  };

  return (
    <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <SlidersHorizontal className="w-4 h-4 text-sky-400" />
            Real-Time Alert Triggers, Thresholds &amp; Notification Preferences
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Customize when NLA raises real-time privacy alerts and how notifications are delivered.
          </p>
        </div>
        <button
          type="button"
          onClick={testAlertNotification}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 text-slate-200 rounded-lg transition-colors self-start"
        >
          <Bell className="w-3.5 h-3.5 text-sky-400" />
          Test Notification
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 text-xs">
        {/* Alert Rule Toggles */}
        <div className="space-y-2.5 bg-[#060C18] border border-slate-800 rounded-lg p-4">
          <div className="font-semibold text-slate-200 mb-2">Detection Triggers</div>
          {[
            {
              key: 'enableThreatFeedAlert' as const,
              label: 'External Threat Intelligence Feed Matches',
              desc: 'Alert when observed destinations match abuse.ch URLhaus, Disconnect.me, or Peter Lowe feeds.',
            },
            {
              key: 'enableNewThirdPartyAlert' as const,
              label: 'New / Unexpected Third-Party Domains',
              desc: 'Alert when an app contacts a previously unseen external host.',
            },
            {
              key: 'enableSensitivePermissionAlert' as const,
              label: 'Sensitive Permission Threshold Exceeded',
              desc: 'Alert when manifest or web scan declarations meet or exceed your sensitive permission count.',
            },
            {
              key: 'enableDataSpikeAlert' as const,
              label: 'Sudden Data Transmission Spikes',
              desc: 'Alert when observed destination or session payload exceeds your KB threshold.',
            },
            {
              key: 'enablePolicyViolationAlert' as const,
              label: 'Privacy Policy Violation / High-Risk Clauses',
              desc: 'Alert when analyzed agreements disclose data selling, indefinite retention, or missing deletion rights.',
            },
          ].map((rule) => (
            <label
              key={rule.key}
              className="flex items-start justify-between gap-3 py-2 border-b border-slate-800/70 last:border-b-0 cursor-pointer"
            >
              <div>
                <div className="text-slate-100 font-medium">{rule.label}</div>
                <div className="text-slate-400 text-[11px] mt-0.5">{rule.desc}</div>
              </div>
              <input
                type="checkbox"
                checked={alertConfig[rule.key]}
                disabled={saving}
                onChange={(e) => void toggleSetting(rule.key, e.target.checked)}
                className="mt-1 rounded border-slate-600 accent-sky-500"
              />
            </label>
          ))}
        </div>

        {/* Thresholds & Notification Delivery */}
        <div className="space-y-4">
          <form
            onSubmit={handleSaveThresholds}
            className="bg-[#060C18] border border-slate-800 rounded-lg p-4 space-y-3"
          >
            <div className="font-semibold text-slate-200">Custom Alert Thresholds</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-400 mb-1">
                  Sensitive Permissions Count (1–20)
                </label>
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={permThreshold}
                  onChange={(e) => setPermThreshold(Number(e.target.value))}
                  className="w-full px-3 py-2 font-mono text-sm bg-[#0B1426] border border-slate-700 rounded-lg text-slate-100"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">
                  Data Spike Threshold (KB: 10–100,000)
                </label>
                <input
                  type="number"
                  min={10}
                  max={100000}
                  value={spikeKb}
                  onChange={(e) => setSpikeKb(Number(e.target.value))}
                  className="w-full px-3 py-2 font-mono text-sm bg-[#0B1426] border border-slate-700 rounded-lg text-slate-100"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg"
            >
              Save Thresholds
            </button>
          </form>

          <div className="bg-[#060C18] border border-slate-800 rounded-lg p-4 space-y-2.5">
            <div className="font-semibold text-slate-200">Notification Delivery Channels</div>
            <label className="flex items-center justify-between gap-3 py-1 cursor-pointer">
              <span className="text-slate-300">In-App Real-Time Toast Banners</span>
              <input
                type="checkbox"
                checked={alertConfig.notifyInAppBanner}
                disabled={saving}
                onChange={(e) => void toggleSetting('notifyInAppBanner', e.target.checked)}
                className="rounded border-slate-600 accent-sky-500"
              />
            </label>
            <label className="flex items-center justify-between gap-3 py-1 cursor-pointer">
              <span className="inline-flex items-center gap-1.5 text-slate-300">
                <Volume2 className="w-3.5 h-3.5 text-slate-400" />
                Subtle Audio Chime on Alert
              </span>
              <input
                type="checkbox"
                checked={alertConfig.notifySoundChime}
                disabled={saving}
                onChange={(e) => void toggleSetting('notifySoundChime', e.target.checked)}
                className="rounded border-slate-600 accent-sky-500"
              />
            </label>
            <div className="flex items-center justify-between gap-3 pt-1">
              <div>
                <div className="text-slate-300">Desktop Browser Push Alerts</div>
                <div className="text-[11px] text-slate-500">
                  Browser permission: {pushPermission}
                </div>
              </div>
              {pushPermission === 'granted' ? (
                <input
                  type="checkbox"
                  checked={alertConfig.notifyBrowserPush}
                  disabled={saving}
                  onChange={(e) => void toggleSetting('notifyBrowserPush', e.target.checked)}
                  className="rounded border-slate-600 accent-sky-500"
                />
              ) : (
                <button
                  type="button"
                  onClick={() => void handleRequestBrowserPush()}
                  disabled={pushPermission === 'unsupported' || pushPermission === 'denied'}
                  className="px-3 py-1.5 text-[11px] font-medium bg-[#0B1426] border border-slate-700 hover:border-sky-500 disabled:opacity-50 text-sky-300 rounded-md"
                >
                  {pushPermission === 'denied' ? 'Blocked by Browser' : 'Enable Browser Push'}
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {savedMsg && (
        <div className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
          <CheckCircle2 className="w-3.5 h-3.5" />
          {savedMsg}
        </div>
      )}
    </div>
  );
}

export function PrivacyRiskAnalytics() {
  const { riskAlerts, setAlertStatus } = useNla();
  const [severityFilter, setSeverityFilter] = useState<'all' | AlertSeverity>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | AlertStatus>('all');
  const [categoryFilter, setCategoryFilter] = useState<'all' | AlertCategory>('all');
  const [showPrefs, setShowPrefs] = useState(true);

  const filtered = useMemo(() => {
    return riskAlerts.filter((a) => {
      if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
      if (statusFilter !== 'all' && a.status !== statusFilter) return false;
      if (categoryFilter !== 'all' && a.category !== categoryFilter) return false;
      return true;
    });
  }, [riskAlerts, severityFilter, statusFilter, categoryFilter]);

  const countsBySeverity = {
    critical: riskAlerts.filter((a) => a.severity === 'critical').length,
    high: riskAlerts.filter((a) => a.severity === 'high').length,
    medium: riskAlerts.filter((a) => a.severity === 'medium').length,
    low: riskAlerts.filter((a) => a.severity === 'low').length,
  };

  const feedMatchCount = riskAlerts.filter((a) => Boolean(a.externalFeedSource)).length;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
          <div key={sev} className="bg-[#0B1426] border border-slate-800 rounded-xl p-4">
            <div className="text-xs text-slate-400 capitalize">{sev} Severity</div>
            <div
              className={`text-2xl font-bold font-mono tabular-nums mt-1 ${
                sev === 'critical' || sev === 'high'
                  ? 'text-rose-400'
                  : sev === 'medium'
                    ? 'text-amber-400'
                    : 'text-sky-400'
              }`}
            >
              {countsBySeverity[sev]}
            </div>
          </div>
        ))}
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 col-span-2 md:col-span-1">
          <div className="text-xs text-slate-400">External Feed Alerts</div>
          <div className="text-2xl font-bold font-mono tabular-nums mt-1 text-cyan-400">
            {feedMatchCount}
          </div>
        </div>
      </div>

      {/* Collapsible Alert Rules & Preferences */}
      <div className="space-y-3">
        <div className="flex justify-end">
          <button
            type="button"
            onClick={() => setShowPrefs((v) => !v)}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-[#0B1426] border border-slate-800 hover:border-sky-500 text-slate-200 rounded-lg"
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-sky-400" />
            {showPrefs ? 'Hide Alert Rules & Preferences' : 'Configure Alert Rules & Preferences'}
          </button>
        </div>
        {showPrefs && <AlertPreferencesPanel />}
      </div>

      {/* Filters */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1 p-1 bg-[#060C18] border border-slate-800 rounded-lg">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSeverityFilter(s)}
                className={`px-3 py-1 text-xs font-medium rounded-md capitalize transition-colors ${
                  severityFilter === s ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 p-1 bg-[#060C18] border border-slate-800 rounded-lg">
            {(['all', 'open', 'acknowledged', 'mitigated'] as const).map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1 text-xs font-medium rounded-md capitalize transition-colors ${
                  statusFilter === st ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1 p-1 bg-[#060C18] border border-slate-800 rounded-lg">
          {ALERT_CATEGORY_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setCategoryFilter(opt.id)}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                categoryFilter === opt.id
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-8 text-center space-y-2">
            <ShieldAlert className="w-6 h-6 text-slate-500 mx-auto" />
            <p className="text-sm font-medium text-slate-200">No Matching Risk Findings</p>
            <p className="text-xs text-slate-400">
              Alerts fire automatically during live probes, web/manifest scans, capture imports, policy reviews, and external threat feed cross-referencing according to your configured thresholds.
            </p>
          </div>
        ) : (
          filtered.map((alert) => (
            <div
              key={alert.id}
              className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-3"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <AlertTriangle
                      className={`w-4 h-4 ${
                        alert.severity === 'critical' || alert.severity === 'high'
                          ? 'text-rose-400'
                          : 'text-amber-400'
                      }`}
                    />
                    <span className="font-semibold uppercase text-slate-200">
                      {alert.severity}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="text-slate-400 capitalize">
                      {alert.category.replace(/-/g, ' ')}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="text-sky-400">{alert.confidence} confidence</span>
                    {alert.externalFeedSource && (
                      <>
                        <span aria-hidden="true">·</span>
                        <span className="text-cyan-300 font-medium">
                          External Feed: {alert.externalFeedSource}
                        </span>
                      </>
                    )}
                  </div>
                  <h3 className="text-base font-semibold text-slate-100">{alert.title}</h3>
                  <p className="text-xs font-mono text-slate-400">
                    {alert.appName} {alert.domain ? `→ ${alert.domain}` : ''}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  {alert.status === 'open' && (
                    <button
                      type="button"
                      onClick={() => void setAlertStatus(alert.id, 'acknowledged')}
                      className="px-3 py-1.5 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 text-slate-200 rounded-lg"
                    >
                      Acknowledge
                    </button>
                  )}
                  {alert.status !== 'mitigated' ? (
                    <button
                      type="button"
                      onClick={() => void setAlertStatus(alert.id, 'mitigated')}
                      className="px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg"
                    >
                      Mark Mitigated
                    </button>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-xs text-emerald-400 font-medium">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Mitigated
                    </span>
                  )}
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">{alert.explanation}</p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                  <div className="text-slate-400 font-medium mb-1">
                    {alert.externalFeedSource
                      ? 'External Feed & Technical Evidence'
                      : 'Technical Evidence'}
                  </div>
                  <div className="text-slate-300">{alert.evidence}</div>
                </div>
                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                  <div className="text-slate-400 font-medium mb-1">Recommended Privacy Action</div>
                  <div className="text-slate-200">{alert.recommendedAction}</div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
