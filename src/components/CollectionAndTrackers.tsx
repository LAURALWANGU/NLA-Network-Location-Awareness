import React, { useMemo, useState } from 'react';
import {
  Building2,
  FileUp,
  Info,
  Lock,
  Network,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { useNla } from '../context/NlaContext';
import type { ServiceCategory } from '../types/nla';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function DataCollectionIntelligence() {
  const { connections, inspectDomainAndSave, importCaptureAndSave } = useNla();
  const [probeDomain, setProbeDomain] = useState('');
  const [probeApp, setProbeApp] = useState('');
  const [firstPartyHost, setFirstPartyHost] = useState('');
  const [probing, setProbing] = useState(false);

  const [captureFormat, setCaptureFormat] = useState<'har' | 'ios-ndjson' | 'nla-json' | 'csv'>('har');
  const [captureAppName, setCaptureAppName] = useState('');
  const [captureFirstParty, setCaptureFirstParty] = useState('');
  const [captureText, setCaptureText] = useState('');
  const [importing, setImporting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [bgOnly, setBgOnly] = useState(false);

  const filtered = useMemo(() => {
    const q = searchTerm.toLowerCase();
    return connections.filter((c) => {
      if (bgOnly && !c.isBackground) return false;
      if (!q) return true;
      return (
        c.destinationDomain.toLowerCase().includes(q) ||
        c.appName.toLowerCase().includes(q) ||
        c.destinationIp.toLowerCase().includes(q) ||
        c.companyName.toLowerCase().includes(q)
      );
    });
  }, [connections, searchTerm, bgOnly]);

  const handleDomainProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!probeDomain.trim()) return;
    setProbing(true);
    setError(null);
    setMessage(null);
    try {
      await inspectDomainAndSave({
        domain: probeDomain.trim(),
        appName: probeApp.trim() || probeDomain.trim(),
        firstPartyHost: firstPartyHost.trim() || undefined,
      });
      setMessage(`Verified DNS, TLS certificate metadata, and GeoIP for ${probeDomain.trim()}.`);
      setProbeDomain('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Probe failed.');
    } finally {
      setProbing(false);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setCaptureText(text);
    if (!captureAppName) {
      setCaptureAppName(file.name.replace(/\.(har|ndjson|json|csv)$/i, ''));
    }
  };

  const handleCaptureImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!captureText.trim()) return;
    setImporting(true);
    setError(null);
    setMessage(null);
    try {
      const count = await importCaptureAndSave({
        rawContent: captureText,
        format: captureFormat,
        defaultAppName: captureAppName.trim() || 'Imported Session',
        firstPartyHost: captureFirstParty.trim() || undefined,
      });
      setMessage(`Parsed and enriched ${count} unique destination routes from ${captureFormat.toUpperCase()} capture.`);
      setCaptureText('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Capture import failed.');
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#0B172B] border border-slate-800 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-300">
        <Lock className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-slate-100">Encrypted Traffic Transparency:</strong>{' '}
          Where connections use TLS/HTTPS, NLA inspects observable DNS resolutions, SNI/TLS certificate metadata, destination IPs, timing, and byte counts. It never claims to read encrypted payloads without authorized decryption captures (such as user-exported HAR files).
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Live DNS / TLS / HTTP Probe */}
        <form
          onSubmit={handleDomainProbe}
          className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-3"
        >
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Live DNS, TLS &amp; HTTP Header Metadata Probe
            </h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <input
              type="text"
              value={probeDomain}
              onChange={(e) => setProbeDomain(e.target.value)}
              placeholder="Target domain (e.g. telemetry.sdk.com)"
              required
              className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
            <input
              type="text"
              value={probeApp}
              onChange={(e) => setProbeApp(e.target.value)}
              placeholder="Associated app name"
              className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
          <input
            type="text"
            value={firstPartyHost}
            onChange={(e) => setFirstPartyHost(e.target.value)}
            placeholder="First-party root domain (optional, for party classification)"
            className="w-full px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={probing || !probeDomain.trim()}
            className="px-4 py-2 text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors"
          >
            {probing ? 'Inspecting DNS/TLS...' : 'Inspect Connection Metadata'}
          </button>
        </form>

        {/* Authorized Network Capture Importer */}
        <form
          onSubmit={handleCaptureImport}
          className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-3"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <FileUp className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                Import Network Capture / Privacy Report
              </h3>
            </div>
            <select
              value={captureFormat}
              onChange={(e) => setCaptureFormat(e.target.value as typeof captureFormat)}
              className="px-2.5 py-1 text-xs bg-[#060C18] border border-slate-700 rounded-md text-slate-200"
            >
              <option value="har">HAR v1.2 (.har)</option>
              <option value="ios-ndjson">Apple App Privacy Report (.ndjson)</option>
              <option value="nla-json">NLA Agent JSON</option>
              <option value="csv">CSV Flow Export</option>
            </select>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <input
              type="text"
              value={captureAppName}
              onChange={(e) => setCaptureAppName(e.target.value)}
              placeholder="Default app name"
              className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
            <input
              type="text"
              value={captureFirstParty}
              onChange={(e) => setCaptureFirstParty(e.target.value)}
              placeholder="First-party domain (optional)"
              className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
          <div className="flex items-center justify-between gap-3">
            <label className="px-3 py-2 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 rounded-lg text-slate-200 cursor-pointer">
              Select Capture File (.har, .ndjson, .json, .csv)
              <input
                type="file"
                accept=".har,.ndjson,.json,.csv,.txt"
                onChange={handleFileChange}
                className="hidden"
              />
            </label>
            <button
              type="submit"
              disabled={importing || !captureText.trim()}
              className="px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg transition-colors"
            >
              {importing ? 'Resolving & Enriching...' : 'Parse & Persist Capture'}
            </button>
          </div>
          {captureText && (
            <p className="text-xs font-mono text-emerald-400">
              Loaded {captureText.length.toLocaleString()} bytes ready for parsing.
            </p>
          )}
        </form>
      </div>

      {message && (
        <div className="px-4 py-2.5 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-xs text-emerald-300">
          {message}
        </div>
      )}
      {error && (
        <div className="px-4 py-2.5 bg-rose-950/40 border border-rose-500/40 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Connection Metadata Ledger */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <h3 className="text-sm font-semibold text-slate-100">
            Observed DNS, TLS &amp; Traffic Metadata ({filtered.length})
          </h3>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={bgOnly}
                onChange={(e) => setBgOnly(e.target.checked)}
                className="rounded border-slate-600"
              />
              Background activity only
            </label>
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Filter domain, IP, app..."
                className="pl-8 pr-3 py-1.5 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#070E1C] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4 font-medium">Timestamp</th>
                <th className="py-2.5 px-4 font-medium">Application</th>
                <th className="py-2.5 px-4 font-medium">Destination Domain</th>
                <th className="py-2.5 px-4 font-medium">IP / Protocol</th>
                <th className="py-2.5 px-4 font-medium">Category / Party</th>
                <th className="py-2.5 px-4 font-medium text-right">Hits / Volume</th>
                <th className="py-2.5 px-4 font-medium">TLS / DNS Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No matching connection metadata recorded.
                  </td>
                </tr>
              ) : (
                filtered.map((conn) => (
                  <tr key={conn.id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                      {conn.observedAt.slice(0, 19).replace('T', ' ')}
                    </td>
                    <td className="py-2.5 px-4 text-slate-200 font-medium">{conn.appName}</td>
                    <td className="py-2.5 px-4 font-mono text-sky-300">
                      {conn.destinationDomain}
                      {conn.isBackground && (
                        <span className="ml-2 text-[11px] text-amber-400">· background</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-slate-300">
                      {conn.destinationIp} · {conn.protocol}:{conn.destinationPort}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 capitalize">
                      {conn.serviceCategory} · {conn.partyType}
                    </td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-right text-slate-200">
                      {conn.requestCount}x · {formatBytes(conn.bytesTransferred)}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 max-w-xs truncate">
                      {conn.tlsSubject ? `TLS: ${conn.tlsSubject} · ` : ''}
                      {conn.evidenceSummary}
                    </td>
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

const CATEGORIES: Array<'all' | ServiceCategory> = [
  'all',
  'advertising',
  'analytics',
  'attribution',
  'cloud',
  'cdn',
  'social',
  'crash-reporting',
  'payment',
  'first-party',
  'unclassified',
];

export function ThirdPartyTrackerIntelligence() {
  const {
    thirdParties,
    feedStatuses,
    refreshingFeeds,
    crossReferencing,
    refreshThreatFeeds,
    crossReferenceAllThirdParties,
  } = useNla();
  const [catFilter, setCatFilter] = useState<'all' | ServiceCategory>('all');
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [xrefNotice, setXrefNotice] = useState<string | null>(null);
  const [xrefError, setXrefError] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return thirdParties.filter((tp) => {
      if (catFilter !== 'all' && tp.classification !== catFilter) return false;
      if (
        flaggedOnly &&
        (!tp.externalFeedVerdict ||
          tp.externalFeedVerdict === 'unlisted' ||
          tp.externalFeedVerdict === 'clean')
      ) {
        return false;
      }
      if (!q) return true;
      return (
        tp.companyName.toLowerCase().includes(q) ||
        tp.domain.toLowerCase().includes(q) ||
        tp.hostingOrg.toLowerCase().includes(q) ||
        tp.country.toLowerCase().includes(q) ||
        (tp.externalFeedSource || '').toLowerCase().includes(q)
      );
    });
  }, [thirdParties, catFilter, flaggedOnly, search]);

  const flaggedCount = thirdParties.filter(
    (tp) =>
      tp.externalFeedVerdict &&
      tp.externalFeedVerdict !== 'unlisted' &&
      tp.externalFeedVerdict !== 'clean'
  ).length;

  const handleCrossReference = async () => {
    setXrefError(null);
    setXrefNotice(null);
    try {
      const res = await crossReferenceAllThirdParties();
      setXrefNotice(
        `Cross-referenced ${res.checked} observed domains against live external feeds. ${res.flagged} domain(s) matched known threat or privacy-invasive lists.`
      );
    } catch (err) {
      setXrefError(err instanceof Error ? err.message : 'Cross-reference failed.');
    }
  };

  return (
    <div className="space-y-5">
      <div className="bg-[#0B172B] border border-slate-800 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-300">
        <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-slate-100">Classification &amp; Feed Attribution Discipline:</strong>{' '}
          Local technical evidence (DNS, TLS, hosting ASN) is kept strictly distinct from external threat intelligence feed findings. General CDNs and cloud hosts are never assumed to be trackers without supporting evidence, and any match from external lists is explicitly labeled with its feed provider.
        </div>
      </div>

      {/* Live External Threat Intelligence Feeds Panel */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Live External Threat &amp; Tracker Intelligence Feeds
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Real-time reputation and tracker lists cross-referenced against observed third-party domains.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => void refreshThreatFeeds()}
              disabled={refreshingFeeds}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 disabled:opacity-50 text-slate-200 rounded-lg transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshingFeeds ? 'animate-spin' : ''}`} />
              {refreshingFeeds ? 'Syncing Feeds...' : 'Refresh Feeds'}
            </button>
            <button
              type="button"
              onClick={() => void handleCrossReference()}
              disabled={crossReferencing || thirdParties.length === 0}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              {crossReferencing
                ? 'Cross-Referencing...'
                : `Cross-Reference Observed (${thirdParties.length})`}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          {feedStatuses.length === 0 ? (
            <div className="md:col-span-3 text-slate-400 py-2">
              Loading live threat feed telemetry...
            </div>
          ) : (
            feedStatuses.map((feed) => (
              <div
                key={feed.id}
                className="bg-[#060C18] border border-slate-800 rounded-lg p-3.5 space-y-1.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-slate-100 truncate">{feed.provider}</span>
                  <span
                    className={`font-mono uppercase text-[11px] ${
                      feed.status === 'synced'
                        ? 'text-emerald-400'
                        : feed.status === 'error'
                          ? 'text-rose-400'
                          : 'text-amber-400'
                    }`}
                  >
                    {feed.status}
                  </span>
                </div>
                <div className="text-slate-300 font-medium truncate">{feed.name}</div>
                <div className="text-slate-400 font-mono tabular-nums flex items-center justify-between gap-2 pt-1">
                  <span>{feed.entryCount.toLocaleString()} hosts</span>
                  <span>
                    {feed.lastSyncedAt
                      ? feed.lastSyncedAt.slice(11, 19) + ' UTC'
                      : 'Pending sync'}
                  </span>
                </div>
                {feed.errorMessage && (
                  <div className="text-[11px] text-rose-400 truncate">{feed.errorMessage}</div>
                )}
              </div>
            ))
          )}
        </div>

        {xrefNotice && (
          <div className="px-3.5 py-2 bg-emerald-950/40 border border-emerald-500/30 rounded-lg text-xs text-emerald-300">
            {xrefNotice}
          </div>
        )}
        {xrefError && (
          <div className="px-3.5 py-2 bg-rose-950/40 border border-rose-500/30 rounded-lg text-xs text-rose-300">
            {xrefError}
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex flex-wrap items-center gap-1 p-1 bg-[#060C18] border border-slate-800 rounded-lg">
            {CATEGORIES.map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setCatFilter(cat)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors capitalize whitespace-nowrap ${
                  catFilter === cat
                    ? 'bg-sky-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat.replace('-', ' ')}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => setFlaggedOnly((v) => !v)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap ${
              flaggedOnly
                ? 'bg-rose-600/20 border-rose-500/50 text-rose-300'
                : 'bg-[#060C18] border-slate-800 text-slate-300 hover:border-slate-600'
            }`}
          >
            Feed-Flagged Only ({flaggedCount})
          </button>
        </div>

        <div className="relative min-w-[220px]">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search company, domain, ASN, feed..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
          />
        </div>
      </div>

      {/* Registry Table */}
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Building2 className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Discovered External Services &amp; Infrastructure ({filtered.length})
            </h3>
          </div>
          <span className="text-xs font-mono tabular-nums text-slate-400">
            {flaggedCount} feed-flagged
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#070E1C] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4 font-medium">Company / Service</th>
                <th className="py-2.5 px-4 font-medium">Domain</th>
                <th className="py-2.5 px-4 font-medium">Observed IP &amp; Country</th>
                <th className="py-2.5 px-4 font-medium">Hosting / ASN</th>
                <th className="py-2.5 px-4 font-medium">Local Classification</th>
                <th className="py-2.5 px-4 font-medium">External Threat Feed Intel</th>
                <th className="py-2.5 px-4 font-medium">Associated Apps</th>
                <th className="py-2.5 px-4 font-medium">Evidence &amp; Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No matching third-party services discovered yet. Inspect live domains, scan websites, or import network captures to populate this database.
                  </td>
                </tr>
              ) : (
                filtered.map((tp) => {
                  const isFlagged =
                    tp.externalFeedVerdict &&
                    tp.externalFeedVerdict !== 'unlisted' &&
                    tp.externalFeedVerdict !== 'clean';
                  return (
                    <tr key={tp.id} className="hover:bg-slate-800/30 align-top">
                      <td className="py-2.5 px-4 font-semibold text-slate-100">{tp.companyName}</td>
                      <td className="py-2.5 px-4 font-mono text-sky-300">{tp.domain}</td>
                      <td className="py-2.5 px-4 font-mono tabular-nums text-slate-300 whitespace-nowrap">
                        {tp.observedIp} · {tp.country}
                      </td>
                      <td className="py-2.5 px-4 text-slate-300">
                        {tp.asn} · {tp.hostingOrg}
                      </td>
                      <td className="py-2.5 px-4 capitalize text-slate-200 whitespace-nowrap">
                        {tp.classification.replace('-', ' ')}
                      </td>
                      <td className="py-2.5 px-4 max-w-xs">
                        {tp.externalFeedVerdict ? (
                          <div className="space-y-0.5">
                            <div
                              className={`font-semibold capitalize ${
                                tp.externalFeedVerdict === 'malicious'
                                  ? 'text-rose-400'
                                  : tp.externalFeedVerdict === 'privacy-invasive'
                                    ? 'text-amber-400'
                                    : tp.externalFeedVerdict === 'ad-tracker'
                                      ? 'text-orange-300'
                                      : 'text-slate-400'
                              }`}
                            >
                              {isFlagged
                                ? `External Feed: ${tp.externalFeedVerdict.replace('-', ' ')}`
                                : 'Unlisted in external feeds'}
                            </div>
                            {tp.externalFeedSource && (
                              <div className="text-[11px] text-sky-300">
                                Source: {tp.externalFeedSource}
                              </div>
                            )}
                            {tp.externalFeedDetails && isFlagged && (
                              <div className="text-[11px] text-slate-400 line-clamp-2">
                                {tp.externalFeedDetails}
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-500">Not checked yet</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-slate-300">
                        {tp.associatedApps.join(', ')}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 max-w-xs">
                        <div className="text-slate-200 capitalize">{tp.confidence} confidence</div>
                        <div className="truncate">{tp.evidenceSummary}</div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
