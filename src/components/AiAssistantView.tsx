import React, { useMemo, useState } from 'react';
import { Bot, ExternalLink, Globe, Send, ShieldCheck } from 'lucide-react';
import { useNla } from '../context/NlaContext';

interface ChatMessage {
  role: 'user' | 'model';
  text: string;
  sources?: Array<{ title: string; uri: string }>;
}

const PROMPT_SUGGESTIONS = [
  'What personal data do my analyzed applications collect or declare?',
  'Which third-party companies receive connections across my workspace?',
  'Where are my observed network connections routing geographically?',
  'What privacy risks or excessive permissions should I investigate first?',
  'Summarize key clauses and risks from my analyzed privacy agreements.',
];

export function AiAssistantView() {
  const { applications, connections, thirdParties, policies, riskAlerts } = useNla();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [useWebSearch, setUseWebSearch] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const telemetryContext = useMemo(() => {
    const summary = {
      analyzedApplications: applications.slice(0, 15).map((a) => ({
        name: a.name,
        packageId: a.packageId,
        platform: a.platform,
        privacyScore: a.privacyScore,
        requestedPermissions: a.requestedPermissions,
        detectedSdks: a.detectedSdks,
        externalDomains: a.externalDomains,
        policyUrl: a.policyUrl,
        evidenceType: a.evidenceType,
      })),
      observedConnections: connections.slice(0, 30).map((c) => ({
        appName: c.appName,
        domain: c.destinationDomain,
        ip: c.destinationIp,
        city: c.city,
        country: c.country,
        asn: c.asn,
        hostingOrg: c.hostingOrg,
        company: c.companyName,
        category: c.serviceCategory,
        partyType: c.partyType,
        isBackground: c.isBackground,
        confidence: c.confidence,
        evidenceSummary: c.evidenceSummary,
      })),
      thirdPartyServices: thirdParties.slice(0, 25).map((t) => ({
        company: t.companyName,
        domain: t.domain,
        classification: t.classification,
        country: t.country,
        associatedApps: t.associatedApps,
      })),
      analyzedPolicies: policies.slice(0, 10).map((p) => ({
        appName: p.appName,
        versionLabel: p.versionLabel,
        summary: p.summary,
        soldOrShared: p.soldOrShared,
        retentionPeriod: p.retentionPeriod,
        unclearOrRiskyClauses: p.unclearOrRiskyClauses,
        comparisonSummary: p.comparisonSummary,
      })),
      riskAlerts: riskAlerts.slice(0, 20).map((r) => ({
        title: r.title,
        appName: r.appName,
        severity: r.severity,
        status: r.status,
        evidence: r.evidence,
        recommendedAction: r.recommendedAction,
      })),
    };
    return JSON.stringify(summary);
  }, [applications, connections, thirdParties, policies, riskAlerts]);

  const sendQuestion = async (questionText: string) => {
    if (!questionText.trim() || loading) return;
    const trimmed = questionText.trim();
    const nextHistory = [...messages, { role: 'user' as const, text: trimmed }];
    setMessages(nextHistory);
    setInput('');
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: trimmed,
          history: messages.map((m) => ({ role: m.role, text: m.text })),
          telemetryContext,
          useWebSearch,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'NLA Intelligence request failed.');
      setMessages((prev) => [
        ...prev,
        {
          role: 'model',
          text: data.answer,
          sources: Array.isArray(data.sources) ? data.sources : [],
        },
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Assistant error.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Bot className="w-5 h-5 text-sky-400" />
            <h2 className="text-base font-semibold text-slate-100">
              NLA Intelligence Assistant
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Grounded strictly in your collected telemetry ({connections.length} connections, {applications.length} apps, {policies.length} policies, {riskAlerts.length} alerts). Never invents monitoring results.
          </p>
        </div>

        <label className="inline-flex items-center gap-2 px-3 py-2 text-xs bg-[#060C18] border border-slate-700 rounded-lg text-slate-200 cursor-pointer shrink-0">
          <input
            type="checkbox"
            checked={useWebSearch}
            onChange={(e) => setUseWebSearch(e.target.checked)}
            className="rounded border-slate-600"
          />
          <Globe className="w-3.5 h-3.5 text-sky-400" />
          External Web Disclosure Verification
        </label>
      </div>

      {/* Interactive Investigation Prompts */}
      <div className="flex flex-wrap gap-2">
        {PROMPT_SUGGESTIONS.map((prompt) => (
          <button
            key={prompt}
            type="button"
            onClick={() => void sendQuestion(prompt)}
            className="px-3 py-1.5 text-xs bg-[#0B1426] border border-slate-700 hover:border-sky-500 text-slate-300 hover:text-white rounded-lg transition-colors text-left"
          >
            {prompt}
          </button>
        ))}
      </div>

      <div className="bg-[#0B1426] border border-slate-800/90 rounded-xl flex flex-col min-h-[440px]">
        <div className="flex-1 p-5 space-y-4 overflow-y-auto max-h-[520px]">
          {messages.length === 0 ? (
            <div className="py-16 text-center space-y-2 max-w-md mx-auto">
              <ShieldCheck className="w-7 h-7 text-sky-400 mx-auto" />
              <h3 className="text-sm font-semibold text-slate-100">
                Ask NLA Intelligence About Your Evidence
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Ask why an app contacted a specific domain, whether requested permissions are necessary, what changed in a privacy policy, or which third-party destinations warrant attention.
              </p>
            </div>
          ) : (
            messages.map((msg, idx) => (
              <div
                key={idx}
                className={`p-4 rounded-xl text-sm leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-sky-950/40 border border-sky-500/30 text-slate-100 ml-auto max-w-2xl'
                    : 'bg-[#060C18] border border-slate-800 text-slate-200 max-w-4xl'
                }`}
              >
                <div className="text-[11px] font-mono text-slate-400 mb-1.5">
                  {msg.role === 'user' ? 'Analyst Query' : 'NLA Intelligence · Evidence-Grounded'}
                </div>
                <div className="whitespace-pre-wrap">{msg.text}</div>
                {msg.sources && msg.sources.length > 0 && (
                  <div className="mt-3 pt-2.5 border-t border-slate-800 space-y-1">
                    <div className="text-[11px] text-slate-400 font-medium">
                      External Verification Sources:
                    </div>
                    <div className="flex flex-wrap gap-3">
                      {msg.sources.map((src, sIdx) => (
                        <a
                          key={sIdx}
                          href={src.uri}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-sky-400 hover:underline"
                        >
                          {src.title}
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
          {loading && (
            <div className="p-4 rounded-xl bg-[#060C18] border border-slate-800 text-xs text-sky-300 max-w-md font-mono">
              Correlating workspace telemetry and disclosures...
            </div>
          )}
        </div>

        {error && (
          <div className="mx-5 mb-3 px-3 py-2 bg-rose-950/40 border border-rose-500/40 rounded-lg text-xs text-rose-300">
            {error}
          </div>
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void sendQuestion(input);
          }}
          className="p-4 border-t border-slate-800 flex gap-2.5"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about app data collection, third-party domains, permissions, or policy terms..."
            className="flex-1 px-4 py-2.5 text-sm bg-[#060C18] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition-colors shrink-0"
          >
            <Send className="w-4 h-4" />
            Ask
          </button>
        </form>
      </div>
    </div>
  );
}
