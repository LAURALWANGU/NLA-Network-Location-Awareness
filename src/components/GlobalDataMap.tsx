import React, { useMemo, useState } from 'react';
import { geoInterpolate, geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import worldAtlas from 'world-atlas/countries-110m.json';
import { Globe, Info, Search, SlidersHorizontal, ArrowUpRight, ShieldCheck } from 'lucide-react';
import { useNla } from '../context/NlaContext';
import type { NetworkConnection, PartyType, ServiceCategory } from '../types/nla';

const MAP_WIDTH = 960;
const MAP_HEIGHT = 480;

const PARTY_COLORS: Record<PartyType, string> = {
  'first-party': '#10B981',
  'third-party': '#38BDF8',
  unknown: '#94A3B8',
};

const CATEGORY_COLORS: Partial<Record<ServiceCategory, string>> = {
  advertising: '#F59E0B',
  attribution: '#F43F5E',
  analytics: '#38BDF8',
  'first-party': '#10B981',
  cloud: '#60A5FA',
  cdn: '#22D3EE',
  social: '#A78BFA',
  'crash-reporting': '#FB923C',
  payment: '#34D399',
  unclassified: '#94A3B8',
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function GlobalDataMap({ compact = false }: { compact?: boolean }) {
  const { connections, devices, sessions, inspectDomainAndSave } = useNla();
  const [selectedConn, setSelectedConn] = useState<NetworkConnection | null>(null);
  const [partyFilter, setPartyFilter] = useState<'all' | PartyType>('all');
  const [sessionFilter, setSessionFilter] = useState<string>('all');
  const [appFilter, setAppFilter] = useState<string>('all');
  const [probeDomain, setProbeDomain] = useState('');
  const [probeAppName, setProbeAppName] = useState('');
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);

  const countries = useMemo(() => {
    const topo = worldAtlas as unknown as Parameters<typeof feature>[0];
    const obj = (worldAtlas as unknown as { objects: { countries: Parameters<typeof feature>[1] } })
      .objects.countries;
    return feature(topo, obj);
  }, []);

  const projection = useMemo(
    () =>
      geoNaturalEarth1()
        .scale(178)
        .translate([MAP_WIDTH / 2, MAP_HEIGHT / 2 + 12]),
    []
  );

  const pathGenerator = useMemo(() => geoPath(projection), [projection]);

  const uniqueApps = useMemo(
    () => Array.from(new Set(connections.map((c) => c.appName))),
    [connections]
  );

  const filteredConnections = useMemo(() => {
    return connections.filter((c) => {
      if (partyFilter !== 'all' && c.partyType !== partyFilter) return false;
      if (sessionFilter !== 'all' && c.sessionId !== sessionFilter) return false;
      if (appFilter !== 'all' && c.appName !== appFilter) return false;
      return c.latitude !== 0 || c.longitude !== 0;
    });
  }, [connections, partyFilter, sessionFilter, appFilter]);

  const activeSelection = selectedConn || filteredConnections[0] || null;

  const handleProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!probeDomain.trim()) return;
    setProbing(true);
    setProbeError(null);
    try {
      await inspectDomainAndSave({
        domain: probeDomain.trim(),
        appName: probeAppName.trim() || probeDomain.trim(),
      });
      setProbeDomain('');
      setProbeAppName('');
    } catch (err) {
      setProbeError(err instanceof Error ? err.message : 'Live probe failed.');
    } finally {
      setProbing(false);
    }
  };

  return (
    <div className="space-y-5">
      {!compact && (
        <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <form onSubmit={handleProbe} className="flex flex-wrap items-center gap-2.5 flex-1">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={probeDomain}
                onChange={(e) => setProbeDomain(e.target.value)}
                placeholder="Probe live domain (e.g. stripe.com)"
                className="w-full pl-9 pr-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>
            <input
              type="text"
              value={probeAppName}
              onChange={(e) => setProbeAppName(e.target.value)}
              placeholder="App label (optional)"
              className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 w-44"
            />
            <button
              type="submit"
              disabled={probing || !probeDomain.trim()}
              className="px-4 py-2 text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              {probing ? 'Resolving DNS/GeoIP...' : 'Probe & Plot Route'}
            </button>
          </form>

          <div className="flex flex-wrap items-center gap-2">
            <SlidersHorizontal className="w-4 h-4 text-slate-400" />
            <div className="flex items-center gap-1 p-1 bg-[#060C18] border border-slate-800 rounded-lg">
              {(['all', 'first-party', 'third-party', 'unknown'] as const).map((pt) => (
                <button
                  key={pt}
                  type="button"
                  onClick={() => setPartyFilter(pt)}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                    partyFilter === pt
                      ? 'bg-sky-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {pt === 'all' ? 'All Parties' : pt}
                </button>
              ))}
            </div>

            <select
              aria-label="Filter by application"
              value={appFilter}
              onChange={(e) => setAppFilter(e.target.value)}
              className="px-3 py-1.5 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="all">All Applications</option>
              {uniqueApps.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter by historical session"
              value={sessionFilter}
              onChange={(e) => setSessionFilter(e.target.value)}
              className="px-3 py-1.5 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-sky-500 max-w-[190px]"
            >
              <option value="all">All Sessions ({sessions.length})</option>
              {sessions.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.title}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {probeError && (
        <div className="px-4 py-2.5 bg-rose-950/50 border border-rose-500/40 rounded-lg text-xs text-rose-200">
          {probeError}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch">
        <div className="xl:col-span-8 bg-[#070E1C] border border-slate-800/90 rounded-xl overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                Observed Network Transmission Topology
              </h3>
            </div>
            <div className="flex items-center gap-4 text-xs text-slate-400">
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> First-Party
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-sky-400" /> Third-Party Infra
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> Ad / Attribution
              </span>
            </div>
          </div>

          <div className="relative flex-1 bg-[#040914] min-h-[340px]">
            <svg
              viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
              className="w-full h-full block"
              role="img"
              aria-label="Global live data transmission map showing device origins and observed server IP routes"
            >
              <defs>
                <radialGradient id="nla-origin-glow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.65" />
                  <stop offset="100%" stopColor="#38BDF8" stopOpacity="0" />
                </radialGradient>
              </defs>

              <rect width={MAP_WIDTH} height={MAP_HEIGHT} fill="#040914" />

              {Array.from(
                (countries as unknown as { features: GeoJSON.Feature[] }).features || []
              ).map((feat, idx) => (
                <path
                  key={feat.id ?? idx}
                  d={pathGenerator(feat) || ''}
                  fill="#0D192E"
                  stroke="#1B3052"
                  strokeWidth={0.6}
                />
              ))}

              {/* Geodesic transmission arcs */}
              {filteredConnections.map((conn) => {
                const start: [number, number] = [conn.sourceLng || -0.1278, conn.sourceLat || 51.5074];
                const end: [number, number] = [conn.longitude, conn.latitude];
                const interp = geoInterpolate(start, end);
                const points: Array<[number, number]> = [];
                for (let t = 0; t <= 1.001; t += 0.05) {
                  const pt = projection(interp(Math.min(1, t)));
                  if (pt) points.push(pt);
                }
                if (points.length < 2) return null;
                const dStr = `M ${points.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' L ')}`;
                const destProj = projection(end);
                const strokeColor =
                  CATEGORY_COLORS[conn.serviceCategory] || PARTY_COLORS[conn.partyType];
                const isSelected = activeSelection?.id === conn.id;

                return (
                  <g
                    key={conn.id}
                    onClick={() => setSelectedConn(conn)}
                    className="cursor-pointer"
                  >
                    <path
                      d={dStr}
                      fill="none"
                      stroke={strokeColor}
                      strokeOpacity={isSelected ? 0.95 : 0.45}
                      strokeWidth={isSelected ? 2.2 : 1.3}
                      className="nla-arc-flow"
                    />
                    {destProj && (
                      <g transform={`translate(${destProj[0]}, ${destProj[1]})`}>
                        <circle
                          r={isSelected ? 7 : 4.5}
                          fill={strokeColor}
                          fillOpacity={0.22}
                        />
                        <circle
                          r={isSelected ? 3.5 : 2.3}
                          fill={strokeColor}
                          stroke="#040914"
                          strokeWidth={1}
                        />
                      </g>
                    )}
                  </g>
                );
              })}

              {/* Monitored Device Origin Nodes */}
              {(devices.length > 0
                ? devices
                : [
                    {
                      id: 'origin-default',
                      name: 'Monitored Endpoint',
                      latitude: 51.5074,
                      longitude: -0.1278,
                      city: 'London',
                    },
                  ]
              ).map((dev) => {
                const proj = projection([dev.longitude, dev.latitude]);
                if (!proj) return null;
                return (
                  <g key={dev.id} transform={`translate(${proj[0]}, ${proj[1]})`}>
                    <circle r={13} fill="url(#nla-origin-glow)" />
                    <circle r={4.2} fill="#38BDF8" stroke="#E0F2FE" strokeWidth={1.4} />
                    <text
                      x={8}
                      y={3}
                      fill="#E2E8F0"
                      fontSize="10"
                      fontFamily="var(--font-mono)"
                    >
                      {dev.city}
                    </text>
                  </g>
                );
              })}
            </svg>

            {filteredConnections.length === 0 && (
              <div className="absolute inset-0 flex items-center justify-center p-6 pointer-events-none">
                <div className="bg-[#0B1426]/95 border border-slate-700/80 rounded-xl px-5 py-4 max-w-md text-center space-y-1.5">
                  <p className="text-sm font-semibold text-slate-100">
                    No Observed Geolocation Routes Yet
                  </p>
                  <p className="text-xs text-slate-400">
                    Probe a live domain above, scan a web application, or import a HAR / Apple App Privacy Report to plot verified server routes.
                  </p>
                </div>
              </div>
            )}
          </div>

          <div className="px-4 py-2.5 bg-[#081020] border-t border-slate-800/80 flex items-center gap-2 text-xs text-slate-400">
            <Info className="w-3.5 h-3.5 text-sky-400 shrink-0" />
            <span>
              Notice: An IP address&apos;s geographic location is an approximate server-network routing point, not proof of where personal data is stored or processed.
            </span>
          </div>
        </div>

        {/* Route Evidence Panel */}
        <div className="xl:col-span-4 bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 flex flex-col justify-between gap-4">
          {activeSelection ? (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <p className="text-xs text-slate-400 font-mono">
                    {activeSelection.observedAt.slice(0, 19).replace('T', ' ')} UTC
                  </p>
                  <h4 className="text-base font-semibold text-slate-100 mt-0.5 break-all">
                    {activeSelection.destinationDomain}
                  </h4>
                  <p className="text-xs text-sky-400 mt-0.5">{activeSelection.companyName}</p>
                </div>
                <span className="text-xs font-mono text-slate-300 px-2 py-1 bg-[#060C18] border border-slate-700 rounded">
                  {activeSelection.protocol}:{activeSelection.destinationPort}
                </span>
              </div>

              <dl className="grid grid-cols-2 gap-x-3 gap-y-2.5 text-xs">
                <div>
                  <dt className="text-slate-400">Responsible App</dt>
                  <dd className="text-slate-100 font-medium truncate">{activeSelection.appName}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Destination IP</dt>
                  <dd className="text-slate-100 font-mono tabular-nums">
                    {activeSelection.destinationIp}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Server Location</dt>
                  <dd className="text-slate-100">
                    {activeSelection.city}, {activeSelection.country}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">ASN / Hosting</dt>
                  <dd className="text-slate-100 truncate">
                    {activeSelection.asn} · {activeSelection.hostingOrg}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Classification</dt>
                  <dd className="text-slate-100 capitalize">
                    {activeSelection.partyType} / {activeSelection.serviceCategory}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Volume / Hits</dt>
                  <dd className="text-slate-100 font-mono tabular-nums">
                    {formatBytes(activeSelection.bytesTransferred)} · {activeSelection.requestCount}x
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Confidence</dt>
                  <dd className="text-slate-100 capitalize">{activeSelection.confidence}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Evidence Basis</dt>
                  <dd className="text-emerald-400 font-medium">{activeSelection.evidenceType}</dd>
                </div>
              </dl>

              <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3 space-y-1.5">
                <div className="flex items-center gap-1.5 text-xs font-medium text-slate-300">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  Supporting Evidence
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {activeSelection.evidenceSummary}
                </p>
                {activeSelection.tlsSubject && (
                  <p className="text-xs font-mono text-slate-500">
                    TLS Subject CN: {activeSelection.tlsSubject}
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-10 space-y-2">
              <ArrowUpRight className="w-6 h-6 text-slate-500" />
              <p className="text-sm font-medium text-slate-200">Select a Transmission Route</p>
              <p className="text-xs text-slate-400 max-w-xs">
                Click any destination node or geodesic arc on the map to inspect its ASN, IP, DNS/TLS metadata, and evidence confidence.
              </p>
            </div>
          )}

          {filteredConnections.length > 0 && (
            <div className="border-t border-slate-800 pt-3">
              <p className="text-xs text-slate-400 mb-2">
                Recent Observed Routes ({filteredConnections.length})
              </p>
              <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
                {filteredConnections.slice(0, 8).map((c) => (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setSelectedConn(c)}
                    className={`w-full text-left px-2.5 py-1.5 rounded-md text-xs flex items-center justify-between gap-2 transition-colors ${
                      activeSelection?.id === c.id
                        ? 'bg-sky-950/60 text-sky-200 border border-sky-500/40'
                        : 'hover:bg-slate-800/60 text-slate-300'
                    }`}
                  >
                    <span className="truncate font-mono">{c.destinationDomain}</span>
                    <span className="text-slate-400 shrink-0 tabular-nums">
                      {c.countryCode}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
