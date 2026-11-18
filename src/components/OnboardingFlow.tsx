import React, { useState } from 'react';
import {
  Activity,
  AppWindow,
  ArrowLeft,
  ArrowRight,
  Bell,
  Building2,
  CheckCircle2,
  Download,
  FileText,
  Globe,
  Lock,
  MonitorSmartphone,
  Network,
  Shield,
  ShieldCheck,
  X,
} from 'lucide-react';
import { useNla } from '../context/NlaContext';
import type { AgentMode, NavSectionId, PlatformType } from '../types/nla';

const STEPS = [
  { id: 1, title: 'Digital Privacy Foundations' },
  { id: 2, title: 'Consent & Data Governance' },
  { id: 3, title: 'Connect & Permissions' },
  { id: 4, title: 'Alerts & Threat Feeds' },
  { id: 5, title: 'Dashboard Tour & Launch' },
];

export function OnboardingFlow({
  onNavigate,
}: {
  onNavigate: (tab: NavSectionId) => void;
}) {
  const {
    profile,
    devices,
    alertConfig,
    feedStatuses,
    onboardingOpen,
    closeOnboarding,
    completeOnboarding,
    acceptConsent,
    updateRetention,
    registerDevice,
    updateAlertPreferences,
    refreshThreatFeeds,
    refreshingFeeds,
    inspectDomainAndSave,
  } = useNla();

  const [step, setStep] = useState(1);
  const [retentionDays, setRetentionDays] = useState(profile?.retentionDays || 90);

  // Step 3: quick device registration
  const [devName, setDevName] = useState('Primary Analyst Workstation');
  const [devPlatform, setDevPlatform] = useState<PlatformType>('web');
  const [devOs, setDevOs] = useState('Browser / Desktop');
  const [devCity, setDevCity] = useState('London');
  const [devCountry, setDevCountry] = useState('United Kingdom');
  const [devAgentMode, setDevAgentMode] = useState<AgentMode>('browser-inspector');
  const [devSaving, setDevSaving] = useState(false);
  const [devCreated, setDevCreated] = useState(false);

  // Step 5: optional first live probe
  const [probeHost, setProbeHost] = useState('');
  const [probing, setProbing] = useState(false);
  const [probeSuccess, setProbeSuccess] = useState<string | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  if (!onboardingOpen) return null;

  const handlePlatformSelect = (plat: PlatformType) => {
    setDevPlatform(plat);
    if (plat === 'windows' || plat === 'linux' || plat === 'macos') {
      setDevAgentMode('endpoint-agent');
      setDevOs(plat === 'windows' ? 'Windows 11' : plat === 'macos' ? 'macOS 15' : 'Linux');
    } else if (plat === 'android') {
      setDevAgentMode('vpn-metadata');
      setDevOs('Android 15');
    } else if (plat === 'ios') {
      setDevAgentMode('privacy-report');
      setDevOs('iOS 18');
    } else {
      setDevAgentMode('browser-inspector');
      setDevOs('Web Browser');
    }
  };

  const handleRegisterFirstDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!devName.trim()) return;
    setDevSaving(true);
    try {
      await registerDevice({
        name: devName.trim(),
        platform: devPlatform,
        osVersion: devOs.trim() || 'Unknown OS',
        hostname: window.location.hostname || 'nla-endpoint',
        agentMode: devAgentMode,
        city: devCity.trim() || 'London',
        country: devCountry.trim() || 'United Kingdom',
        latitude: 51.5074,
        longitude: -0.1278,
      });
      setDevCreated(true);
    } finally {
      setDevSaving(false);
    }
  };

  const handleRunFirstProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!probeHost.trim()) return;
    setProbing(true);
    setProbeError(null);
    setProbeSuccess(null);
    try {
      await inspectDomainAndSave({
        domain: probeHost.trim(),
        appName: probeHost.trim(),
      });
      setProbeSuccess(
        `Live DNS, TLS, GeoIP, and external threat feed inspection completed for ${probeHost.trim()}.`
      );
      setProbeHost('');
    } catch (err) {
      setProbeError(err instanceof Error ? err.message : 'Probe failed.');
    } finally {
      setProbing(false);
    }
  };

  const handleFinish = async (targetTab?: NavSectionId) => {
    await completeOnboarding();
    if (targetTab) onNavigate(targetTab);
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-label="NLA Platform Onboarding Guide"
    >
      <div className="w-full max-w-4xl bg-[#070E1C] border border-slate-700/90 rounded-2xl shadow-2xl overflow-hidden my-auto">
        {/* Header */}
        <div className="px-6 py-4 bg-[#0B1426] border-b border-slate-800 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-sky-500/15 border border-sky-500/40 flex items-center justify-center text-sky-400">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm sm:text-base font-bold text-slate-100">
                Welcome to NLA — Network &amp; Location Awareness
              </h2>
              <p className="text-xs text-slate-400">
                Step {step} of {STEPS.length}: {STEPS[step - 1].title}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={closeOnboarding}
            aria-label="Dismiss onboarding for now"
            className="p-2 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Step Progress Bar */}
        <div className="px-6 py-3 bg-[#050B16] border-b border-slate-800/80 grid grid-cols-5 gap-2">
          {STEPS.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => setStep(s.id)}
              className={`text-left px-2.5 py-2 rounded-lg border text-[11px] transition-colors ${
                step === s.id
                  ? 'bg-sky-600/20 border-sky-500/50 text-sky-300 font-semibold'
                  : step > s.id
                    ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
                    : 'bg-[#0B1426] border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <div className="font-mono">0{s.id}</div>
              <div className="truncate mt-0.5">{s.title}</div>
            </button>
          ))}
        </div>

        {/* Step Content */}
        <div className="p-6 max-h-[65vh] overflow-y-auto space-y-5 text-xs text-slate-300">
          {step === 1 && (
            <div className="space-y-4">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Why Digital Privacy Visibility Matters
                </h3>
                <p className="mt-1 text-slate-300 leading-relaxed">
                  Modern applications and websites routinely embed third-party analytics SDKs, advertising mediation networks, and attribution endpoints that transmit device metadata behind the scenes. NLA — built by Newtonix Tech House — illuminates where your data goes, who receives it, and what privacy agreements actually authorize.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-1.5">
                  <div className="font-semibold text-sky-400">
                    Evidence Integrity Without Fabrication
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    NLA strictly separates verified technical evidence (live DNS, TLS certificates, HTTP headers, user-imported captures), declared policy disclosures, inferred signals, and external threat intelligence feeds. Encrypted TLS payloads are never fabricated.
                  </p>
                </div>
                <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-1.5">
                  <div className="font-semibold text-emerald-400">
                    IP Geolocation vs. Data Storage
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    An IP address&apos;s city/country reflects approximate server-network routing — not legal proof of where personal records are stored. NLA clearly states this boundary across maps and forensic exports.
                  </p>
                </div>
                <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-1.5">
                  <div className="font-semibold text-amber-400">
                    Permission Declaration vs. Access
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    Requesting camera, microphone, or location permission in an app manifest shows capability, not proof that the app actively accessed that sensor.
                  </p>
                </div>
                <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-1.5">
                  <div className="font-semibold text-cyan-400">
                    External Threat Feeds Cross-Referenced
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    Every inspected destination is cross-referenced against reputable live feeds (abuse.ch URLhaus, Disconnect.me, Peter Lowe) with explicit external feed attribution.
                  </p>
                </div>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-4">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Explicit Authorization &amp; Data Retention Governance
                </h3>
                <p className="mt-1 text-slate-400 leading-relaxed">
                  NLA operates strictly under user-authorized inspection. Confirm your workspace consent and set how long inspection telemetry and forensic reports are retained in your private workspace.
                </p>
              </div>

              <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div className="space-y-1">
                  <div className="font-semibold text-slate-100 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-sky-400" />
                    Explicit Inspection Consent
                  </div>
                  <p className="text-slate-400">
                    Authorize NLA to store DNS/TLS metadata probes, uploaded network captures, and policy analyses in your isolated workspace.
                  </p>
                </div>
                {profile?.consentAccepted ? (
                  <span className="inline-flex items-center gap-1.5 text-emerald-400 font-semibold whitespace-nowrap shrink-0">
                    <CheckCircle2 className="w-4 h-4" />
                    Consent Accepted
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => void acceptConsent()}
                    className="px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white rounded-lg whitespace-nowrap shrink-0"
                  >
                    Authorize Workspace
                  </button>
                )}
              </div>

              <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="font-semibold text-slate-100 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  Telemetry Retention Window
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {[30, 90, 180, 365].map((days) => (
                    <button
                      key={days}
                      type="button"
                      onClick={() => {
                        setRetentionDays(days);
                        void updateRetention(days);
                      }}
                      className={`px-3.5 py-2 rounded-lg font-mono text-xs border transition-colors ${
                        retentionDays === days
                          ? 'bg-sky-600 text-white border-sky-500'
                          : 'bg-[#060C18] border-slate-700 text-slate-300 hover:border-slate-500'
                      }`}
                    >
                      {days} Days
                    </button>
                  ))}
                </div>
                <p className="text-[11px] text-slate-400">
                  Active retention window: <span className="text-sky-300 font-mono">{profile?.retentionDays || retentionDays} days</span>. All governance updates are recorded in the immutable audit log.
                </p>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-4">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Connect Your First Device &amp; OS Permission Boundaries
                </h3>
                <p className="mt-1 text-slate-400 leading-relaxed">
                  Register the device or browser environment you are auditing. On Windows, Linux, or macOS you can also run NLA&apos;s authorized local collector (<code className="text-sky-300">nla-agent.mjs</code>) to stream socket metadata; on mobile/web you can import HAR, Apple App Privacy Report (<code className="text-sky-300">.ndjson</code>), or manifest files.
                </p>
              </div>

              <form
                onSubmit={handleRegisterFirstDevice}
                className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-3"
              >
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-slate-400 mb-1">Device Name</label>
                    <input
                      type="text"
                      value={devName}
                      onChange={(e) => setDevName(e.target.value)}
                      required
                      className="w-full px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Platform</label>
                    <select
                      value={devPlatform}
                      onChange={(e) => handlePlatformSelect(e.target.value as PlatformType)}
                      className="w-full px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
                    >
                      <option value="web">Web Browser</option>
                      <option value="windows">Windows</option>
                      <option value="macos">macOS</option>
                      <option value="linux">Linux</option>
                      <option value="android">Android</option>
                      <option value="ios">iOS</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">OS Version</label>
                    <input
                      type="text"
                      value={devOs}
                      onChange={(e) => setDevOs(e.target.value)}
                      className="w-full px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 mb-1">Origin City</label>
                    <input
                      type="text"
                      value={devCity}
                      onChange={(e) => setDevCity(e.target.value)}
                      className="w-full px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Origin Country</label>
                    <input
                      type="text"
                      value={devCountry}
                      onChange={(e) => setDevCountry(e.target.value)}
                      className="w-full px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
                    />
                  </div>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                  <button
                    type="submit"
                    disabled={devSaving || !devName.trim()}
                    className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg"
                  >
                    <MonitorSmartphone className="w-3.5 h-3.5" />
                    {devSaving ? 'Registering...' : 'Register Device Endpoint'}
                  </button>
                  <a
                    href="/api/agent/script"
                    download="nla-agent.mjs"
                    className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 text-sky-300 rounded-lg"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download Desktop Collector (nla-agent.mjs)
                  </a>
                </div>
                {(devCreated || devices.length > 0) && (
                  <div className="text-emerald-400 flex items-center gap-1.5 pt-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {devices.length} endpoint(s) registered in your workspace.
                  </div>
                )}
              </form>
            </div>
          )}

          {step === 4 && (
            <div className="space-y-4">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Real-Time Alerting &amp; Live Threat Intelligence Feeds
                </h3>
                <p className="mt-1 text-slate-400 leading-relaxed">
                  NLA automatically cross-references observed domains against live external feeds and triggers real-time alerts based on your thresholds.
                </p>
              </div>

              <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-100">
                    Synced External Threat Intelligence Feeds
                  </span>
                  <button
                    type="button"
                    onClick={() => void refreshThreatFeeds()}
                    disabled={refreshingFeeds}
                    className="text-sky-400 hover:text-sky-300 font-medium"
                  >
                    {refreshingFeeds ? 'Syncing...' : 'Sync Now'}
                  </button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  {feedStatuses.map((f) => (
                    <div
                      key={f.id}
                      className="bg-[#060C18] border border-slate-800 rounded-lg p-3 space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-slate-100">{f.provider}</span>
                        <span
                          className={`font-mono text-[11px] uppercase ${
                            f.status === 'synced' ? 'text-emerald-400' : 'text-amber-400'
                          }`}
                        >
                          {f.status}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        {f.entryCount.toLocaleString()} domains
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {alertConfig && (
                <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-2.5">
                  <div className="font-semibold text-slate-100 flex items-center gap-2">
                    <Bell className="w-4 h-4 text-amber-400" />
                    Active Alert Rules &amp; Notification Channels
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    {[
                      {
                        key: 'enableThreatFeedAlert' as const,
                        label: 'External Threat Feed Matches',
                      },
                      {
                        key: 'enableNewThirdPartyAlert' as const,
                        label: 'New Third-Party Domains',
                      },
                      {
                        key: 'enableSensitivePermissionAlert' as const,
                        label: `Sensitive Permissions (>= ${alertConfig.sensitivePermissionThreshold})`,
                      },
                      {
                        key: 'enableDataSpikeAlert' as const,
                        label: `Data Transfer Spikes (>= ${alertConfig.dataSpikeThresholdKb} KB)`,
                      },
                      {
                        key: 'enablePolicyViolationAlert' as const,
                        label: 'Privacy Policy Violations',
                      },
                      {
                        key: 'notifyInAppBanner' as const,
                        label: 'In-App Real-Time Alert Banners',
                      },
                    ].map((item) => (
                      <label
                        key={item.key}
                        className="flex items-center justify-between gap-2 bg-[#060C18] border border-slate-800 rounded-lg px-3 py-2 cursor-pointer"
                      >
                        <span className="text-slate-200">{item.label}</span>
                        <input
                          type="checkbox"
                          checked={alertConfig[item.key]}
                          onChange={(e) =>
                            void updateAlertPreferences({ [item.key]: e.target.checked })
                          }
                          className="accent-sky-500"
                        />
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {step === 5 && (
            <div className="space-y-4">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Dashboard Modules Tour &amp; Optional First Live Probe
                </h3>
                <p className="mt-1 text-slate-400 leading-relaxed">
                  Explore NLA&apos;s intelligence workspace or run an immediate live DNS/TLS/Threat-Feed probe before entering the dashboard.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {[
                  {
                    icon: Globe,
                    title: 'Global Data Map',
                    desc: 'Interactive animated routes from your device to observed server cities & ASNs.',
                  },
                  {
                    icon: AppWindow,
                    title: 'Application Scanner',
                    desc: 'Inspect live websites, AndroidManifest, and iOS Info.plist with transparent privacy scores.',
                  },
                  {
                    icon: Network,
                    title: 'Data Collection Intel',
                    desc: 'Live DNS/TLS/HTTP probes and HAR / Apple Privacy Report (.ndjson) ingestion.',
                  },
                  {
                    icon: Building2,
                    title: 'Third-Party Trackers',
                    desc: 'Host classification cross-referenced with URLhaus, Disconnect.me, and Peter Lowe feeds.',
                  },
                  {
                    icon: FileText,
                    title: 'Privacy Policy Analyzer',
                    desc: 'AI plain-language breakdown, risky clause extraction, and old-vs-new policy diffs.',
                  },
                  {
                    icon: Activity,
                    title: 'Live Monitor & Forensics',
                    desc: 'SSE event stream, customizable real-time alerts, and SHA-256 PDF/CSV/JSON exports.',
                  },
                ].map((mod) => {
                  const Icon = mod.icon;
                  return (
                    <div
                      key={mod.title}
                      className="bg-[#0B1426] border border-slate-800 rounded-xl p-3.5 space-y-1"
                    >
                      <div className="flex items-center gap-2 font-semibold text-slate-100">
                        <Icon className="w-4 h-4 text-sky-400" />
                        {mod.title}
                      </div>
                      <p className="text-[11px] text-slate-400 leading-relaxed">{mod.desc}</p>
                    </div>
                  );
                })}
              </div>

              <form
                onSubmit={handleRunFirstProbe}
                className="bg-[#0B1426] border border-slate-800 rounded-xl p-4 space-y-2.5"
              >
                <div className="font-semibold text-slate-100">
                  Try Your First Live Destination Probe (Optional)
                </div>
                <div className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={probeHost}
                    onChange={(e) => setProbeHost(e.target.value)}
                    placeholder="Enter any public domain (e.g. wikipedia.org or doubleclick.net)"
                    className="flex-1 px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500"
                  />
                  <button
                    type="submit"
                    disabled={probing || !probeHost.trim()}
                    className="px-4 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg whitespace-nowrap"
                  >
                    {probing ? 'Probing Live...' : 'Run Live Probe'}
                  </button>
                </div>
                {probeSuccess && (
                  <div className="text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {probeSuccess}
                  </div>
                )}
                {probeError && <div className="text-rose-400">{probeError}</div>}
              </form>
            </div>
          )}
        </div>

        {/* Footer Controls */}
        <div className="px-6 py-4 bg-[#0B1426] border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <button
            type="button"
            onClick={() => void handleFinish()}
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Skip &amp; Don&apos;t Show Again
          </button>

          <div className="flex items-center gap-2.5">
            {step > 1 && (
              <button
                type="button"
                onClick={() => setStep((s) => Math.max(1, s - 1))}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-slate-500 text-slate-200 rounded-lg"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Back
              </button>
            )}
            {step < STEPS.length ? (
              <button
                type="button"
                onClick={() => setStep((s) => Math.min(STEPS.length, s + 1))}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white rounded-lg"
              >
                Next Step
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            ) : (
              <button
                type="button"
                onClick={() => void handleFinish('overview')}
                className="inline-flex items-center gap-1.5 px-5 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                Complete Setup &amp; Open Dashboard
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
