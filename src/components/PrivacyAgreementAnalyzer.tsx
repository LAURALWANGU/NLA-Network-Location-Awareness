import React, { useState } from 'react';
import { ExternalLink, FileText, GitCompare, Trash2, Upload } from 'lucide-react';
import { useNla } from '../context/NlaContext';
import type { PrivacyPolicyAnalysis } from '../types/nla';

export function PrivacyAgreementAnalyzer() {
  const { policies, analyzePolicyAndSave, deleteRecord } = useNla();
  const [appName, setAppName] = useState('');
  const [versionLabel, setVersionLabel] = useState('2026 Current');
  const [policyUrl, setPolicyUrl] = useState('');
  const [policyText, setPolicyText] = useState('');
  const [oldPolicyText, setOldPolicyText] = useState('');
  const [pdfBase64, setPdfBase64] = useState('');
  const [pdfName, setPdfName] = useState('');
  const [showCompare, setShowCompare] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState<PrivacyPolicyAnalysis | null>(null);

  const activePolicy = selectedPolicy || policies[0] || null;

  const handlePdfUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf')) {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      setPdfBase64(btoa(binary));
      setPdfName(file.name);
      if (!appName) setAppName(file.name.replace(/\.pdf$/i, ''));
    } else {
      const text = await file.text();
      setPolicyText(text.slice(0, 60000));
      setPdfBase64('');
      setPdfName('');
    }
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!appName.trim()) return;
    setAnalyzing(true);
    setError(null);
    try {
      const newId = await analyzePolicyAndSave({
        appName: appName.trim(),
        versionLabel: versionLabel.trim() || 'Current',
        policyUrl: policyUrl.trim() || undefined,
        policyText: policyText.trim() || undefined,
        pdfBase64: pdfBase64 || undefined,
        oldPolicyText: oldPolicyText.trim() || undefined,
      });
      setPolicyText('');
      setOldPolicyText('');
      setPdfBase64('');
      setPdfName('');
      const found = policies.find((p) => p.id === newId);
      if (found) setSelectedPolicy(found);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Policy analysis failed.');
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      <form
        onSubmit={handleAnalyze}
        className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Privacy Agreement &amp; Consent Intelligence
            </h2>
            <p className="text-xs text-slate-400">
              Submit a privacy policy URL, upload a PDF document, or paste agreement text to extract plain-language disclosures, supporting clauses, and version diffs.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowCompare((s) => !s)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 rounded-lg text-slate-200 self-start"
          >
            <GitCompare className="w-3.5 h-3.5 text-sky-400" />
            {showCompare ? 'Hide Old Version Diff' : 'Compare Old vs. New Policy'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            type="text"
            value={appName}
            onChange={(e) => setAppName(e.target.value)}
            placeholder="Application or website name"
            required
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
          />
          <input
            type="url"
            value={policyUrl}
            onChange={(e) => setPolicyUrl(e.target.value)}
            placeholder="Privacy policy URL (https://...)"
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
          />
          <input
            type="text"
            value={versionLabel}
            onChange={(e) => setVersionLabel(e.target.value)}
            placeholder="Version / Effective Date"
            className="px-3 py-2 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 rounded-lg text-slate-200 cursor-pointer">
            <Upload className="w-3.5 h-3.5 text-sky-400" />
            {pdfName ? `Loaded PDF: ${pdfName}` : 'Upload Privacy Policy PDF or TXT'}
            <input
              type="file"
              accept=".pdf,.txt,.md"
              onChange={handlePdfUpload}
              className="hidden"
            />
          </label>
          <span className="text-xs text-slate-500">
            Leave text empty if analyzing directly from the public URL or uploaded PDF.
          </span>
        </div>

        <textarea
          rows={4}
          value={policyText}
          onChange={(e) => setPolicyText(e.target.value)}
          placeholder="Or paste full privacy policy / terms text here..."
          className="w-full px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
        />

        {showCompare && (
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">
              Previous Policy Version Text (for side-by-side comparison)
            </label>
            <textarea
              rows={3}
              value={oldPolicyText}
              onChange={(e) => setOldPolicyText(e.target.value)}
              placeholder="Paste the older privacy policy version text to detect new sharing, retention, or tracking changes..."
              className="w-full px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
        )}

        <button
          type="submit"
          disabled={analyzing || !appName.trim()}
          className="px-5 py-2.5 text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors"
        >
          {analyzing ? 'Analyzing Agreement Clauses...' : 'Analyze Privacy Agreement'}
        </button>

        {error && (
          <div className="text-xs text-rose-300 bg-rose-950/40 border border-rose-500/30 rounded-lg px-3 py-2">
            {error}
          </div>
        )}
      </form>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <div className="xl:col-span-4 bg-[#0B1426] border border-slate-800/90 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">
              Analyzed Agreements ({policies.length})
            </h3>
          </div>
          {policies.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-400">
              No agreements analyzed yet. Submit a privacy policy URL, PDF, or text above.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {policies.map((pol) => (
                <div
                  key={pol.id}
                  onClick={() => setSelectedPolicy(pol)}
                  className={`p-4 cursor-pointer flex items-center justify-between gap-2 transition-colors ${
                    activePolicy?.id === pol.id ? 'bg-sky-950/30' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-slate-100 truncate">
                      {pol.appName}
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      {pol.versionLabel} · {pol.sourceType.toUpperCase()}
                    </div>
                  </div>
                  <button
                    type="button"
                    aria-label={`Delete ${pol.appName} analysis`}
                    onClick={(e) => {
                      e.stopPropagation();
                      void deleteRecord('policies', pol.id);
                    }}
                    className="p-1.5 text-slate-500 hover:text-rose-400"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="xl:col-span-8 bg-[#0B1426] border border-slate-800/90 rounded-xl p-5">
          {activePolicy ? (
            <div className="space-y-5">
              <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <h3 className="text-lg font-bold text-slate-100">{activePolicy.appName}</h3>
                  <div className="text-xs text-slate-400 mt-0.5">
                    Version {activePolicy.versionLabel} · Source: {activePolicy.sourceType.toUpperCase()}
                  </div>
                </div>
                {activePolicy.policyUrl && (
                  <a
                    href={activePolicy.policyUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-[#060C18] border border-slate-700 hover:border-sky-500 rounded-lg text-sky-400"
                  >
                    Original Agreement
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>

              <div className="bg-[#060C18] border border-slate-800 rounded-lg p-4 space-y-1">
                <div className="text-xs font-semibold text-sky-400">Plain-Language Summary</div>
                <p className="text-sm text-slate-200 leading-relaxed">{activePolicy.summary}</p>
              </div>

              {/* 8 Mandatory Highlights + Transfers + Deletion */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {[
                  { label: '01. What Information Is Collected', val: activePolicy.collectedInfo },
                  { label: '02. Why It Is Collected', val: activePolicy.purposeOfCollection },
                  { label: '03. Who May Receive It', val: activePolicy.recipients },
                  { label: '04. Whether Information May Be Sold or Shared', val: activePolicy.soldOrShared },
                  { label: '05. How Long Information May Be Retained', val: activePolicy.retentionPeriod },
                  { label: '06. What Choices Users Have', val: activePolicy.userChoices },
                  { label: '07. Impact of Withdrawing Consent', val: activePolicy.withdrawalImpact },
                  { label: '08. Risks & Unclear Clauses', val: activePolicy.unclearOrRiskyClauses },
                  { label: '09. International Data Transfers', val: activePolicy.internationalTransfers },
                  { label: '10. Account Deletion & Removal Rights', val: activePolicy.deletionRights },
                ].map((item) => (
                  <div
                    key={item.label}
                    className="bg-[#060C18] border border-slate-800 rounded-lg p-3.5 space-y-1"
                  >
                    <div className="font-semibold text-slate-200">{item.label}</div>
                    <p className="text-slate-300 leading-relaxed">{item.val}</p>
                  </div>
                ))}
              </div>

              {activePolicy.comparisonSummary && (
                <div className="bg-[#060C18] border border-slate-800 rounded-lg p-3.5 space-y-1 text-xs">
                  <div className="font-semibold text-amber-400">Version Comparison Findings</div>
                  <p className="text-slate-300 leading-relaxed">
                    {activePolicy.comparisonSummary}
                  </p>
                </div>
              )}

              {activePolicy.clauses.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-slate-300">
                    Supporting Clauses &amp; Excerpts ({activePolicy.clauses.length})
                  </h4>
                  <ul className="space-y-2 text-xs text-slate-300">
                    {activePolicy.clauses.map((clause, i) => (
                      <li
                        key={i}
                        className="bg-[#060C18] border border-slate-800 rounded-lg p-3 font-mono leading-relaxed"
                      >
                        {clause}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="py-12 text-center space-y-2">
              <FileText className="w-6 h-6 text-slate-500 mx-auto" />
              <p className="text-sm font-medium text-slate-200">No Policy Analysis Selected</p>
              <p className="text-xs text-slate-400">
                Analyze a privacy policy URL, PDF, or text above to review the 8-point plain-language breakdown and supporting clauses.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
