import { GoogleGenAI, Type } from '@google/genai';
import dns from 'node:dns/promises';
import { isPrivateOrReservedIp, sanitizeHostname } from './networkIntel.ts';

function getAiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not configured in the server environment.');
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

async function fetchPublicPolicyText(rawUrl: string): Promise<string> {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Only HTTP/HTTPS privacy policy URLs are supported.');
  }
  const host = sanitizeHostname(parsed.hostname);
  const ips = await dns.resolve4(host).catch(() => [] as string[]);
  if (ips.length === 0 || isPrivateOrReservedIp(ips[0])) {
    throw new Error(`Host ${host} is not publicly routable.`);
  }

  const res = await fetch(parsed.toString(), {
    headers: {
      'User-Agent': 'NLA-Policy-Analyzer/1.0 (+https://newtonix.tech)',
      Accept: 'text/html,text/plain,application/xhtml+xml',
    },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) {
    throw new Error(`Policy URL returned HTTP ${res.status}.`);
  }
  const rawHtml = await res.text();
  const stripped = rawHtml
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();

  if (stripped.length < 150) {
    throw new Error('Fetched document did not contain enough readable policy text.');
  }
  return stripped.slice(0, 65000);
}

export interface PolicyAnalysisOutput {
  summary: string;
  collectedInfo: string;
  purposeOfCollection: string;
  recipients: string;
  soldOrShared: string;
  retentionPeriod: string;
  userChoices: string;
  withdrawalImpact: string;
  unclearOrRiskyClauses: string;
  internationalTransfers: string;
  deletionRights: string;
  clauses: string[];
  comparisonSummary: string;
}

export async function analyzePrivacyPolicyWithGemini(params: {
  appName: string;
  policyUrl?: string;
  policyText?: string;
  pdfBase64?: string;
  oldPolicyText?: string;
  versionLabel: string;
}): Promise<{ analysis: PolicyAnalysisOutput; sourceType: 'url' | 'text' | 'pdf' }> {
  const ai = getAiClient();
  let sourceType: 'url' | 'text' | 'pdf' = 'text';
  let resolvedText = (params.policyText || '').trim();

  if (params.pdfBase64) {
    sourceType = 'pdf';
  } else if (params.policyUrl && !resolvedText) {
    sourceType = 'url';
    resolvedText = await fetchPublicPolicyText(params.policyUrl);
  }

  if (!params.pdfBase64 && resolvedText.length < 60) {
    throw new Error('Provide a privacy policy URL, upload a PDF, or paste the policy text.');
  }

  const comparisonPrompt = params.oldPolicyText?.trim()
    ? `\n\nPREVIOUS VERSION POLICY TEXT FOR COMPARISON:\n${params.oldPolicyText.slice(0, 25000)}`
    : '';

  const instructionPrompt = `You are NLA Privacy Agreement & Consent Intelligence by Newtonix Tech House.
Analyze the privacy policy for "${params.appName}" (Version: ${params.versionLabel}).
Be strictly factual and cite exact clauses or sections from the provided document. Never invent terms not present in the document; if a detail is not disclosed, explicitly write "Not disclosed in the provided agreement."
Provide concise, plain-language explanations for all fields and include up to 12 verbatim or tightly referenced supporting clause excerpts in "clauses".
If a previous version was provided, summarize material changes in data collection, third-party sharing, retention, or user rights in "comparisonSummary". Otherwise set "comparisonSummary" to "No baseline version provided for diff comparison."`;

  const contents = params.pdfBase64
    ? {
        parts: [
          {
            inlineData: {
              mimeType: 'application/pdf',
              data: params.pdfBase64,
            },
          },
          {
            text: `${instructionPrompt}${comparisonPrompt}`,
          },
        ],
      }
    : `${instructionPrompt}\n\nPOLICY DOCUMENT TEXT:\n${resolvedText}${comparisonPrompt}`;

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents,
    config: {
      systemInstruction:
        'You are a legal-technical privacy policy analyst. Return accurate structured JSON adhering strictly to the schema without fabricating unstated clauses.',
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          summary: { type: Type.STRING, description: 'Plain-language executive summary under 1500 chars.' },
          collectedInfo: { type: Type.STRING, description: '1. What information is collected.' },
          purposeOfCollection: { type: Type.STRING, description: '2. Why it is collected.' },
          recipients: { type: Type.STRING, description: '3. Who may receive it (advertisers, analytics, partners, authorities).' },
          soldOrShared: { type: Type.STRING, description: '4. Whether information may be sold or shared for targeted ads.' },
          retentionPeriod: { type: Type.STRING, description: '5. How long information may be retained.' },
          userChoices: { type: Type.STRING, description: '6. What choices and opt-out controls users have.' },
          withdrawalImpact: { type: Type.STRING, description: '7. What happens when users withdraw consent.' },
          unclearOrRiskyClauses: { type: Type.STRING, description: '8. What risks, broad discretion, or unclear clauses exist.' },
          internationalTransfers: { type: Type.STRING, description: 'Cross-border or international data transfer disclosures.' },
          deletionRights: { type: Type.STRING, description: 'Account deletion and data removal provisions.' },
          clauses: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: 'Supporting clause quotes or section references from the policy (max 12).',
          },
          comparisonSummary: { type: Type.STRING, description: 'Changes compared to previous policy version if supplied.' },
        },
        required: [
          'summary',
          'collectedInfo',
          'purposeOfCollection',
          'recipients',
          'soldOrShared',
          'retentionPeriod',
          'userChoices',
          'withdrawalImpact',
          'unclearOrRiskyClauses',
          'internationalTransfers',
          'deletionRights',
          'clauses',
          'comparisonSummary',
        ],
      },
    },
  });

  const jsonText = (response.text ?? '{}').trim();
  const parsed = JSON.parse(jsonText) as PolicyAnalysisOutput;
  return {
    sourceType,
    analysis: {
      summary: (parsed.summary || '').slice(0, 1950),
      collectedInfo: (parsed.collectedInfo || '').slice(0, 1450),
      purposeOfCollection: (parsed.purposeOfCollection || '').slice(0, 1450),
      recipients: (parsed.recipients || '').slice(0, 1450),
      soldOrShared: (parsed.soldOrShared || '').slice(0, 1450),
      retentionPeriod: (parsed.retentionPeriod || '').slice(0, 950),
      userChoices: (parsed.userChoices || '').slice(0, 1450),
      withdrawalImpact: (parsed.withdrawalImpact || '').slice(0, 950),
      unclearOrRiskyClauses: (parsed.unclearOrRiskyClauses || '').slice(0, 1950),
      internationalTransfers: (parsed.internationalTransfers || '').slice(0, 950),
      deletionRights: (parsed.deletionRights || '').slice(0, 950),
      clauses: Array.isArray(parsed.clauses)
        ? parsed.clauses.slice(0, 15).map((c) => String(c).slice(0, 450))
        : [],
      comparisonSummary: (parsed.comparisonSummary || 'No baseline version provided.').slice(0, 1950),
    },
  };
}

export async function askNlaIntelligence(params: {
  question: string;
  history: Array<{ role: 'user' | 'model'; text: string }>;
  telemetryContext: string;
  useWebSearch?: boolean;
}): Promise<{
  answer: string;
  sources: Array<{ title: string; uri: string }>;
}> {
  const ai = getAiClient();

  const systemInstruction = `You are NLA Intelligence, the digital privacy intelligence assistant built by Newtonix Tech House for the NLA (Network & Location Awareness) platform.
STRICT EPISTEMIC RULES:
1. Never invent, fabricate, or hallucinate monitoring results, IP addresses, domains, or app behavior.
2. Always distinguish clearly between:
   - [Verified Technical Evidence]: directly present in the user's collected NLA telemetry context below.
   - [Declared Disclosure]: stated in an analyzed privacy policy or app manifest.
   - [Inferred / External Context]: derived from public disclosures or external search (cite sources).
   - [Unknown / Unverified]: when evidence is missing or traffic is encrypted.
3. Remember: An IP geolocation is an approximate server-network location, NOT proof of where personal data is stored. Requesting an OS permission does NOT prove the app accessed that sensor.
4. Keep answers structured, concise, actionable, and grounded in the collected workspace telemetry below.

COLLECTED WORKSPACE TELEMETRY CONTEXT:
${params.telemetryContext.slice(0, 28000)}`;

  const contents = [
    ...params.history.slice(-8).map((msg) => ({
      role: msg.role,
      parts: [{ text: msg.text }],
    })),
    {
      role: 'user',
      parts: [{ text: params.question }],
    },
  ];

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents,
    config: {
      systemInstruction,
      ...(params.useWebSearch ? { tools: [{ googleSearch: {} }] } : {}),
    },
  });

  const rawChunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
  const sources: Array<{ title: string; uri: string }> = [];
  for (const ch of rawChunks) {
    const web = (ch as { web?: { uri?: string; title?: string } }).web;
    if (web?.uri) {
      sources.push({
        title: web.title || web.uri,
        uri: web.uri,
      });
    }
  }

  return {
    answer: response.text || 'No response generated by NLA Intelligence.',
    sources,
  };
}
