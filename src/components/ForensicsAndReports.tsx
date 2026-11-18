import React, { useState } from 'react';
import { Download, FileCheck2, Fingerprint, Search, Trash2 } from 'lucide-react';
import { useNla } from '../context/NlaContext';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function DigitalForensics() {
  const { sessions, devices, connections, riskAlerts, exportSessionReport } = useNla();
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');
  const [exporting, setExporting] = useState<string | null>(null);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  const activeSession =
    sessions.find((s) => s.id === selectedSessionId) || sessions[0] || null;
  const sessionConnections = activeSession
    ? connections.filter((c) => c.sessionId === activeSession.id)
    : [];
  const sessionAlerts = activeSession
    ? riskAlerts.filter((a) => a.sessionId === activeSession.id)
    : [];
  const sessionDevice = activeSession
    ? devices.find((d) => d.id === activeSession.deviceId)
    : null;

  const handleExport = async (format: 'pdf' | 'csv' | 'json' | 'html') => {
    if (!activeSession) return;
    setExporting(format);
    setExportNotice(null);
    try {
      const filename = await exportSessionReport(activeSession.id, format);
      setExportNotice(`Generated ${filename} with verified SHA-256 chain-of-custody hash.`);
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <div className="xl:col-span-4 bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">
              Investigation Sessions ({sessions.length})
            </h3>
          </div>
          {sessions.length === 0 ? (
            <div className="p-6 text-xs text-slate-400 text-center">
              No forensic sessions recorded yet. Inspect a domain, scan a web app, or import a capture to create an investigation session.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {sessions.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => setSelectedSessionId(s.id)}
                  className={`w-full text-left p-4 transition-colors ${
                    activeSession?.id === s.id ? 'bg-sky-950/30' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="text-sm font-semibold text-slate-100 truncate">{s.title}</div>
                  <div className="text-xs font-mono text-slate-400 mt-0.5 truncate">{s.id}</div>
                  <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
                    <span>{s.sourceType}</span>
                    <span className="capitalize text-sky-400">{s.status}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="xl:col-span-8 bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-5">
          {activeSession ? (
            <>
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                    <Fingerprint className="w-4 h-4 text-sky-400" />
                    <span>{activeSession.id}</span>
                  </div>
                  <h3 className="text-lg font-bold text-slate-100">{activeSession.title}</h3>
                  <p className="text-xs text-slate-400">
                    Endpoint: {sessionDevice?.name || activeSession.deviceId} ({sessionDevice?.platform || 'unknown'}) · Source: {activeSession.sourceType}
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  {(['pdf', 'csv', 'json', 'html'] as const).map((fmt) => (
                    <button
                      key={fmt}
                      type="button"
                      disabled={exporting !== null}
                      onClick={() => void handleExport(fmt)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-[#060C18] border border-slate-700 hover:border-sky-500 text-slate-200 rounded-lg uppercase transition-colors"
                    >
                      <Download className="w-3.5 h-3.5 text-sky-400" />
                      {exporting === fmt ? '...' : fmt}
                    </button>
                  ))}
                </div>
              </div>

              {exportNotice && (
                <div className="px-3.5 py-2.5 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-xs text-emerald-300">
                  {exportNotice}
                </div>
              )}

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                  <div className="text-slate-400">Observed Routes</div>
                  <div className="text-lg font-mono tabular-nums text-slate-100 mt-1">
                    {sessionConnections.length}
                  </div>
                </div>
                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                  <div className="text-slate-400">Measured Bytes</div>
                  <div className="text-lg font-mono tabular-nums text-slate-100 mt-1">
                    {formatBytes(
                      sessionConnections.reduce((acc, c) => acc + c.bytesTransferred, 0)
                    )}
                  </div>
                </div>
                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                  <div className="text-slate-400">Session Alerts</div>
                  <div className="text-lg font-mono tabular-nums text-amber-400 mt-1">
                    {sessionAlerts.length}
                  </div>
                </div>
                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3">
                  <div className="text-slate-400">Integrity Digest</div>
                  <div className="text-xs font-mono text-emerald-400 mt-2 truncate">
                    {activeSession.integrityHash}
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-slate-300">
                  Session DNS, IP &amp; Connection Artifacts ({sessionConnections.length})
                </h4>
                <div className="overflow-x-auto border border-slate-800 rounded-lg">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#060C18] text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="py-2 px-3">Timestamp</th>
                        <th className="py-2 px-3">App</th>
                        <th className="py-2 px-3">Domain</th>
                        <th className="py-2 px-3">IP / Port</th>
                        <th className="py-2 px-3">Geo / ASN</th>
                        <th className="py-2 px-3">Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {sessionConnections.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-6 text-center text-slate-500">
                            No artifacts attached to this session yet.
                          </td>
                        </tr>
                      ) : (
                        sessionConnections.map((c) => (
                          <tr key={c.id}>
                            <td className="py-2 px-3 font-mono tabular-nums text-slate-400">
                              {c.observedAt.slice(0, 19).replace('T', ' ')}
                            </td>
                            <td className="py-2 px-3 text-slate-200">{c.appName}</td>
                            <td className="py-2 px-3 font-mono text-sky-300">{c.destinationDomain}</td>
                            <td className="py-2 px-3 font-mono tabular-nums text-slate-300">
                              {c.destinationIp}:{c.destinationPort}
                            </td>
                            <td className="py-2 px-3 text-slate-300">
                              {c.city}, {c.countryCode} · {c.asn}
                            </td>
                            <td className="py-2 px-3 capitalize text-slate-300">{c.confidence}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            <div className="py-12 text-center space-y-2">
              <Search className="w-6 h-6 text-slate-500 mx-auto" />
              <p className="text-sm font-medium text-slate-200">No Investigation Session Selected</p>
              <p className="text-xs text-slate-400">
                Run a live scan or import a capture file to inspect forensic artifacts and export signed evidence reports.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function ReportsAndEvidence() {
  const { forensicReports, sessions, exportSessionReport, deleteRecord } = useNla();
  const [busy, setBusy] = useState(false);

  const handleQuickExport = async (format: 'pdf' | 'csv' | 'json' | 'html') => {
    if (sessions.length === 0) return;
    setBusy(true);
    try {
      await exportSessionReport(sessions[0].id, format);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Reports &amp; Chain-of-Custody Evidence Ledger
          </h2>
          <p className="text-xs text-slate-400">
            Every exported investigation bundle records a cryptographic SHA-256 integrity hash, source session ID, and timestamp.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {(['pdf', 'csv', 'json', 'html'] as const).map((fmt) => (
            <button
              key={fmt}
              type="button"
              disabled={busy || sessions.length === 0}
              onClick={() => void handleQuickExport(fmt)}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white rounded-lg uppercase transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export Latest {fmt}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2">
          <FileCheck2 className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            Exported Evidence Archive ({forensicReports.length})
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#070E1C] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4 font-medium">Report Title</th>
                <th className="py-2.5 px-4 font-medium">Format</th>
                <th className="py-2.5 px-4 font-medium">Session ID</th>
                <th className="py-2.5 px-4 font-medium text-right">Records</th>
                <th className="py-2.5 px-4 font-medium">SHA-256 Integrity Hash</th>
                <th className="py-2.5 px-4 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {forensicReports.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No forensic reports exported yet. Use the export controls above or in Digital Forensics.
                  </td>
                </tr>
              ) : (
                forensicReports.map((rep) => (
                  <tr key={rep.id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 font-medium text-slate-100">{rep.title}</td>
                    <td className="py-2.5 px-4 uppercase font-mono text-sky-400">{rep.format}</td>
                    <td className="py-2.5 px-4 font-mono text-slate-400">{rep.sessionId}</td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-right text-slate-200">
                      {rep.recordCount}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-emerald-400 max-w-xs truncate">
                      {rep.integritySha256}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        type="button"
                        aria-label={`Delete report ${rep.title}`}
                        onClick={() => void deleteRecord('forensicReports', rep.id)}
                        className="p-1 text-slate-500 hover:text-rose-400"
                      >
                        <Trash2 className="w-4 h-4 inline" />
                      </button>
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
