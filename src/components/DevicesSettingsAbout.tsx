import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Cpu,
  Download,
  Lock,
  MonitorSmartphone,
  ShieldCheck,
  Terminal,
  Trash2,
} from 'lucide-react';
import { useNla } from '../context/NlaContext';
import type { AgentMode, PlatformType } from '../types/nla';

const PLATFORM_CAPABILITIES: Array<{
  platform: string;
  mechanism: string;
  boundaries: string;
}> = [
  {
    platform: 'Windows & Linux',
    mechanism: 'Authorized NLA Endpoint Collector (ss / netstat socket & process metadata)',
    boundaries: 'Requires explicit OS user execution; observes socket destinations & process names without reading encrypted TLS payloads.',
  },
  {
    platform: 'macOS',
    mechanism: 'Authorized lsof socket metadata collector & network capture import',
    boundaries: 'Operates under user consent; respects macOS System Integrity Protection and App Sandbox boundaries.',
  },
  {
    platform: 'Android',
    mechanism: 'Supported VpnService local metadata tunnel & AndroidManifest permission scanner',
    boundaries: 'Cannot inspect private app storage or bypass certificate pinning on modern Android builds.',
  },
  {
    platform: 'iOS',
    mechanism: 'Apple App Privacy Report (.ndjson) ingestion & Info.plist inspection',
    boundaries: 'Respects iOS App Sandbox; does not promise background packet capture across third-party apps without Apple-approved NEPacketTunnelProvider.',
  },
  {
    platform: 'Web Applications',
    mechanism: 'Live HTML/header/CSP/script origin inspection & HAR v1.2 browser capture import',
    boundaries: 'Analyzes client-accessible markup, headers, DNS, TLS metadata, and user-exported HAR sessions.',
  },
];

export function DeviceManagement() {
  const { devices, registerDevice, toggleDeviceStatus, deleteRecord } = useNla();
  const [name, setName] = useState('');
  const [platform, setPlatform] = useState<PlatformType>('linux');
  const [osVersion, setOsVersion] = useState('Ubuntu 24.04');
  const [hostname, setHostname] = useState('');
  const [agentMode, setAgentMode] = useState<AgentMode>('endpoint-agent');
  const [city, setCity] = useState('London');
  const [country, setCountry] = useState('United Kingdom');
  const [latitude, setLatitude] = useState('51.5074');
  const [longitude, setLongitude] = useState('-0.1278');
  const [saving, setSaving] = useState(false);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSaving(true);
    try {
      await registerDevice({
        name: name.trim(),
        platform,
        osVersion: osVersion.trim() || 'Unknown OS',
        hostname: hostname.trim() || 'nla-endpoint',
        agentMode,
        city: city.trim() || 'London',
        country: country.trim() || 'United Kingdom',
        latitude: Number(latitude) || 51.5074,
        longitude: Number(longitude) || -0.1278,
      });
      setName('');
      setHostname('');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Cross-Platform Collector Download */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              NLA Cross-Platform Endpoint Metadata Agent (nla-agent.mjs)
            </h3>
          </div>
          <p className="text-xs text-slate-400 max-w-3xl">
            Run this authorized Node.js collector on Windows, Linux, or macOS to inspect active OS socket metadata (<code className="text-sky-300">ss</code> / <code className="text-sky-300">lsof</code> / <code className="text-sky-300">netstat</code>) with explicit user consent and post observations directly to <code className="text-sky-300">/api/agent/ingest</code>.
          </p>
        </div>
        <a
          href="/api/agent/script"
          download="nla-agent.mjs"
          className="inline-flex items-center gap-2 px-4 py-2.5 text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0"
        >
          <Download className="w-4 h-4" />
          Download nla-agent.mjs
        </a>
      </div>

      {/* Register Device Form */}
      <form
        onSubmit={handleRegister}
        className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-4"
      >
        <h3 className="text-sm font-semibold text-slate-100">Register Authorized Endpoint</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Device label (e.g. Analyst ThinkPad)"
            required
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500"
          />
          <select
            value={platform}
            onChange={(e) => setPlatform(e.target.value as PlatformType)}
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
          >
            <option value="windows">Windows</option>
            <option value="android">Android</option>
            <option value="linux">Linux</option>
            <option value="macos">macOS</option>
            <option value="ios">iOS</option>
            <option value="web">Web Browser</option>
          </select>
          <input
            type="text"
            value={osVersion}
            onChange={(e) => setOsVersion(e.target.value)}
            placeholder="OS Version"
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
          />
          <select
            value={agentMode}
            onChange={(e) => setAgentMode(e.target.value as AgentMode)}
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
          >
            <option value="endpoint-agent">Endpoint Agent (Windows/Linux/macOS)</option>
            <option value="vpn-metadata">VPN Metadata Tunnel (Android)</option>
            <option value="privacy-report">App Privacy Report Import (iOS)</option>
            <option value="browser-inspector">Web / HAR Inspector</option>
          </select>
          <input
            type="text"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            placeholder="Hostname / Device ID"
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
          />
          <input
            type="text"
            value={city}
            onChange={(e) => setCity(e.target.value)}
            placeholder="Origin City"
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
          />
          <input
            type="text"
            value={country}
            onChange={(e) => setCountry(e.target.value)}
            placeholder="Origin Country"
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
          />
          <div className="grid grid-cols-2 gap-2">
            <input
              type="text"
              value={latitude}
              onChange={(e) => setLatitude(e.target.value)}
              placeholder="Lat"
              className="px-3 py-2 text-sm font-mono bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
            />
            <input
              type="text"
              value={longitude}
              onChange={(e) => setLongitude(e.target.value)}
              placeholder="Lng"
              className="px-3 py-2 text-sm font-mono bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
            />
          </div>
        </div>
        <button
          type="submit"
          disabled={saving || !name.trim()}
          className="px-5 py-2 text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors"
        >
          {saving ? 'Registering...' : 'Register Device Endpoint'}
        </button>
      </form>

      {/* Registered Devices List */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2">
          <MonitorSmartphone className="w-4 h-4 text-sky-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            Authorized Devices ({devices.length})
          </h3>
        </div>
        <div className="divide-y divide-slate-800/70">
          {devices.length === 0 ? (
            <div className="p-6 text-xs text-slate-400 text-center">
              No devices registered yet. Register a Windows, Android, Linux, macOS, iOS, or Web endpoint above.
            </div>
          ) : (
            devices.map((dev) => (
              <div
                key={dev.id}
                className="p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-xs"
              >
                <div>
                  <div className="text-sm font-semibold text-slate-100">{dev.name}</div>
                  <div className="text-slate-400 mt-0.5">
                    <span className="uppercase font-mono text-sky-300">{dev.platform}</span>
                    {' · '}
                    <span>{dev.osVersion}</span>
                    {' · '}
                    <span>{dev.agentMode}</span>
                    {' · '}
                    <span>
                      {dev.city}, {dev.country}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {(['active', 'paused', 'stopped'] as const).map((st) => (
                    <button
                      key={st}
                      type="button"
                      onClick={() => void toggleDeviceStatus(dev.id, st)}
                      className={`px-2.5 py-1 rounded-md capitalize font-medium ${
                        dev.status === st
                          ? 'bg-sky-600 text-white'
                          : 'bg-[#060C18] border border-slate-700 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                  <button
                    type="button"
                    aria-label={`Remove ${dev.name}`}
                    onClick={() => void deleteRecord('devices', dev.id)}
                    className="p-1.5 text-slate-500 hover:text-rose-400"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Platform Architecture & OS Boundaries */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-slate-100">
          Modular OS Architecture &amp; Permission Boundaries
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
          {PLATFORM_CAPABILITIES.map((cap) => (
            <div
              key={cap.platform}
              className="bg-[#060C18] border border-slate-800 rounded-lg p-3.5 space-y-1.5"
            >
              <div className="font-semibold text-sky-400">{cap.platform}</div>
              <div className="text-slate-200 font-medium">{cap.mechanism}</div>
              <div className="text-slate-400 leading-relaxed">{cap.boundaries}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function SettingsView() {
  const { profile, auditLogs, updateRetention, acceptConsent, openOnboarding } = useNla();
  const [retention, setRetention] = useState(profile?.retentionDays || 90);
  const [savedNotice, setSavedNotice] = useState(false);
  const [apiDocs, setApiDocs] = useState<{
    endpoints?: Array<{ method: string; path: string; description: string }>;
  } | null>(null);

  useEffect(() => {
    fetch('/api/docs')
      .then((r) => r.json())
      .then((d) => setApiDocs(d))
      .catch(() => {});
  }, []);

  const handleSaveRetention = async (e: React.FormEvent) => {
    e.preventDefault();
    await updateRetention(retention);
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                Identity, RBAC &amp; Data Governance
              </h3>
            </div>
            <button
              type="button"
              onClick={openOnboarding}
              className="px-3 py-1.5 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 text-sky-300 rounded-lg"
            >
              Launch Setup Guide
            </button>
          </div>

          <dl className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
              <dt className="text-slate-400">Authenticated Identity</dt>
              <dd className="text-slate-100 font-medium mt-1 truncate">
                {profile?.email || 'Authenticated Analyst'}
              </dd>
            </div>
            <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
              <dt className="text-slate-400">Workspace Role</dt>
              <dd className="text-sky-400 font-mono uppercase mt-1">
                {profile?.role || 'analyst'}
              </dd>
            </div>
          </dl>

          <form onSubmit={handleSaveRetention} className="space-y-3">
            <label className="block text-xs font-medium text-slate-300">
              Telemetry &amp; Evidence Retention Window (Days: 7–365)
            </label>
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="number"
                min={7}
                max={365}
                value={retention}
                onChange={(e) => setRetention(Number(e.target.value))}
                className="w-32 px-3 py-2 text-sm font-mono bg-[#060C18] border border-slate-700 rounded-lg text-slate-100"
              />
              <button
                type="submit"
                className="px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white rounded-lg"
              >
                Save Retention Policy
              </button>
              {!profile?.consentAccepted && (
                <button
                  type="button"
                  onClick={() => void acceptConsent()}
                  className="px-4 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg"
                >
                  Confirm Consent
                </button>
              )}
            </div>
            {savedNotice && (
              <div className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Retention preference persisted and audit-logged.
              </div>
            )}
          </form>
        </div>

        {/* Live API Documentation */}
        <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Backend REST &amp; Streaming API Reference
            </h3>
            <a
              href="/api/docs"
              target="_blank"
              rel="noreferrer"
              className="text-xs text-sky-400 hover:underline font-mono"
            >
              /api/docs JSON
            </a>
          </div>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1 text-xs">
            {(apiDocs?.endpoints || []).map((ep) => (
              <div
                key={ep.path}
                className="bg-[#060C18] border border-slate-800 rounded-lg p-2.5"
              >
                <div className="font-mono text-sky-300">
                  {ep.method} {ep.path}
                </div>
                <div className="text-slate-400 mt-0.5">{ep.description}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Security Audit Logs */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            Immutable Security &amp; Governance Audit Log ({auditLogs.length})
          </h3>
        </div>
        <div className="overflow-x-auto max-h-80 overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#070E1C] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Action</th>
                <th className="py-2.5 px-4">Actor</th>
                <th className="py-2.5 px-4">Target</th>
                <th className="py-2.5 px-4">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-6 text-center text-slate-500">
                    No audit records logged yet.
                  </td>
                </tr>
              ) : (
                auditLogs.map((log) => (
                  <tr key={log.id}>
                    <td className="py-2 px-4 font-mono text-sky-300">{log.action}</td>
                    <td className="py-2 px-4 text-slate-300">{log.actorEmail}</td>
                    <td className="py-2 px-4 font-mono text-slate-400">
                      {log.targetType}:{log.targetId.slice(0, 18)}
                    </td>
                    <td className="py-2 px-4 text-slate-300">{log.details}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export function AboutNewtonixView() {
  return (
    <div className="space-y-6 max-w-5xl">
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">
              NLA — Network &amp; Location Awareness
            </h2>
            <p className="text-xs text-sky-400 font-medium">
              Developed &amp; Owned by Newtonix Tech House
            </p>
          </div>
        </div>

        <p className="text-sm font-semibold text-slate-100 tracking-wide">
          &ldquo;SEE YOUR DATA. KNOW ITS DESTINATION. CONTROL YOUR DIGITAL PRIVACY.&rdquo;
        </p>

        <p className="text-sm text-slate-300 leading-relaxed">
          NLA is an enterprise-grade digital privacy intelligence platform built by Newtonix Tech House to make invisible data collection understandable, expose observable third-party transmissions, decode complex privacy agreements, and empower individuals, organizations, educators, and security teams with verifiable evidence.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-5 space-y-2">
          <h3 className="text-sm font-semibold text-slate-100">Epistemic Integrity</h3>
          <p className="text-slate-400 leading-relaxed">
            Every finding distinguishes verified technical evidence (DNS, TLS certificates, HTTP headers, imported captures) from declared policy disclosures, inferred signals, and unknown data. Encrypted traffic payloads are never fabricated.
          </p>
        </div>
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-5 space-y-2">
          <h3 className="text-sm font-semibold text-slate-100">OS-Compliant Engineering</h3>
          <p className="text-slate-400 leading-relaxed">
            Respects Windows, Linux, macOS, Android, iOS, and Web security models. Uses authorized socket collectors, supported VPN metadata interfaces, Apple App Privacy Reports, and explicit user consent.
          </p>
        </div>
        <div className="bg-[#0B1426] border border-slate-800 rounded-xl p-5 space-y-2">
          <h3 className="text-sm font-semibold text-slate-100">Forensic Chain of Custody</h3>
          <p className="text-slate-400 leading-relaxed">
            Every monitoring session, capture import, and exported report (PDF, CSV, JSON, HTML) maintains UTC timestamps, source attribution, and SHA-256 cryptographic integrity hashes.
          </p>
        </div>
      </div>
    </div>
  );
}
