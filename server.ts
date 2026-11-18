import 'dotenv/config';
import express from 'express';
import type { Request, Response } from 'express';
import { EventEmitter } from 'node:events';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  analyzeLiveWebApplication,
  analyzeManifestText,
  parseAndEnrichCapture,
} from './server/appAnalyzer.ts';
import {
  analyzePrivacyPolicyWithGemini,
  askNlaIntelligence,
} from './server/geminiService.ts';
import { inspectLiveDomain } from './server/networkIntel.ts';
import {
  crossReferenceDomainWithFeeds,
  getThreatFeedStatuses,
  refreshAllThreatFeeds,
} from './server/threatIntel.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const monitorBus = new EventEmitter();
monitorBus.setMaxListeners(100);

interface MonitorEventPayload {
  type: 'probe' | 'capture' | 'agent-ingest' | 'web-scan';
  timestamp: string;
  summary: string;
  observations: unknown[];
}

function broadcastMonitorEvent(event: MonitorEventPayload) {
  monitorBus.emit('observation', event);
}

const ENDPOINT_AGENT_SCRIPT = `#!/usr/bin/env node
/**
 * NLA Endpoint Metadata Collector (Windows / Linux / macOS)
 * Developed by Newtonix Tech House
 *
 * Collects ONLY authorized socket & process metadata (no payload decryption).
 * Usage:
 *   node nla-agent.mjs --endpoint https://YOUR_NLA_URL/api/agent/ingest --device-id YOUR_DEVICE_ID
 */
import { execSync } from 'node:child_process';
import os from 'node:os';

const args = process.argv.slice(2);
const getArg = (flag, fallback = '') => {
  const idx = args.indexOf(flag);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
};

const endpoint = getArg('--endpoint', 'http://localhost:3000/api/agent/ingest');
const deviceId = getArg('--device-id', os.hostname());
const platform = os.platform();

function collectActiveSockets() {
  const observations = [];
  const now = new Date().toISOString();
  try {
    if (platform === 'linux') {
      const out = execSync('ss -tunp 2>/dev/null || netstat -tunp 2>/dev/null', { encoding: 'utf8' });
      for (const line of out.split('\\n').slice(1)) {
        const parts = line.trim().split(/\\s+/);
        if (parts.length < 5) continue;
        const remote = parts[4] || '';
        const match = remote.match(/^(\\[?[0-9a-fA-F.:]+\\]?):(\\d+)$/);
        if (!match) continue;
        const ip = match[1].replace(/[\\[\\]]/g, '');
        if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0' || ip === '*') continue;
        const procMatch = line.match(/users:\\(\\("([^"]+)"/);
        observations.push({
          appName: procMatch ? procMatch[1] : 'system-process',
          destinationDomain: ip,
          destinationIp: ip,
          destinationPort: Number(match[2]),
          protocol: parts[0].toUpperCase().startsWith('UDP') ? 'QUIC' : 'TLS',
          observedAt: now,
          bytes: 0,
        });
      }
    } else if (platform === 'darwin') {
      const out = execSync('lsof -i -n -P 2>/dev/null', { encoding: 'utf8' });
      for (const line of out.split('\\n').slice(1)) {
        if (!line.includes('ESTABLISHED')) continue;
        const parts = line.trim().split(/\\s+/);
        const appName = parts[0];
        const conn = parts[8] || '';
        const arrow = conn.split('->')[1] || '';
        const match = arrow.match(/^([^:]+):(\\d+)/);
        if (!match) continue;
        observations.push({
          appName,
          destinationDomain: match[1],
          destinationIp: match[1],
          destinationPort: Number(match[2]),
          protocol: Number(match[2]) === 443 ? 'HTTPS' : 'TLS',
          observedAt: now,
          bytes: 0,
        });
      }
    } else if (platform === 'win32') {
      const out = execSync('netstat -ano', { encoding: 'utf8' });
      for (const line of out.split('\\n')) {
        if (!line.includes('ESTABLISHED')) continue;
        const parts = line.trim().split(/\\s+/);
        if (parts.length < 4) continue;
        const match = parts[2].match(/^([^:]+):(\\d+)$/);
        if (!match) continue;
        if (match[1].startsWith('127.')) continue;
        observations.push({
          appName: 'PID-' + parts[4],
          destinationDomain: match[1],
          destinationIp: match[1],
          destinationPort: Number(match[2]),
          protocol: Number(match[2]) === 443 ? 'HTTPS' : 'TLS',
          observedAt: now,
          bytes: 0,
        });
      }
    }
  } catch (err) {
    console.error('Socket inspection failed:', err.message);
  }
  return observations.slice(0, 25);
}

async function main() {
  const observations = collectActiveSockets();
  console.log(\`[NLA Agent] Collected \${observations.length} active external socket endpoints on \${platform}.\`);
  if (observations.length === 0) return;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId, hostname: os.hostname(), platform, observations }),
  });
  const result = await res.json();
  console.log('[NLA Agent] Upload status:', res.status, result);
}

main();
`;

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '15mb' }));

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'NLA — Network & Location Awareness',
      developer: 'Newtonix Tech House',
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/docs', (_req: Request, res: Response) => {
    res.json({
      openapi: '3.1.0',
      info: {
        title: 'NLA — Network & Location Awareness API',
        version: '1.0.0',
        developer: 'Newtonix Tech House',
        description:
          'Digital Privacy Intelligence backend for live DNS/TLS/GeoIP inspection, application manifest & web scanning, capture parsing, Gemini privacy policy analysis, and authorized endpoint ingestion.',
      },
      endpoints: [
        { method: 'GET', path: '/api/health', description: 'Service availability & platform identity' },
        { method: 'POST', path: '/api/network/inspect', description: 'Live DNS, TLS certificate, HTTP header, GeoIP, and ASN probe for a target domain' },
        { method: 'POST', path: '/api/apps/analyze-web', description: 'Inspect live website HTML, third-party script origins, cookies, and privacy policy links' },
        { method: 'POST', path: '/api/apps/analyze-manifest', description: 'Parse AndroidManifest.xml, Info.plist, or permission lists with transparent score criteria' },
        { method: 'POST', path: '/api/captures/parse', description: 'Parse HAR v1.2, Apple App Privacy Report (.ndjson), NLA JSON, or CSV captures with GeoIP enrichment' },
        { method: 'POST', path: '/api/policies/analyze', description: 'Analyze privacy policy URL, text, or PDF via Gemini 4 Hydrogen with clause extraction & version comparison' },
        { method: 'POST', path: '/api/ai/chat', description: 'NLA Intelligence assistant grounded in collected workspace telemetry and optional search verification' },
        { method: 'POST', path: '/api/agent/ingest', description: 'Authorized endpoint collector telemetry ingestion' },
        { method: 'GET', path: '/api/agent/script', description: 'Download cross-platform NLA Node.js endpoint collector (nla-agent.mjs)' },
        { method: 'GET', path: '/api/monitor/stream', description: 'Server-Sent Events stream of verified network probes and capture observations' },
        { method: 'GET', path: '/api/threat-intel/status', description: 'Live sync status and entry counts for external threat & tracker feeds' },
        { method: 'POST', path: '/api/threat-intel/refresh', description: 'Force refresh of external threat intelligence feeds (URLhaus, Disconnect.me, Peter Lowe)' },
        { method: 'POST', path: '/api/threat-intel/cross-reference', description: 'Cross-reference a batch of domains against synced external threat & privacy feeds' },
      ],
    });
  });

  app.get('/api/agent/script', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="nla-agent.mjs"');
    res.send(ENDPOINT_AGENT_SCRIPT);
  });

  app.get('/api/monitor/stream', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    res.write(
      `data: ${JSON.stringify({
        type: 'connected',
        timestamp: new Date().toISOString(),
        summary: 'NLA authorized telemetry stream initialized.',
        observations: [],
      })}\n\n`
    );

    const onObservation = (payload: MonitorEventPayload) => {
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    };

    monitorBus.on('observation', onObservation);
    const keepalive = setInterval(() => {
      res.write(': keepalive\n\n');
    }, 25000);

    req.on('close', () => {
      clearInterval(keepalive);
      monitorBus.off('observation', onObservation);
    });
  });

  app.post('/api/network/inspect', async (req: Request, res: Response) => {
    try {
      const { domain, firstPartyHost, appName } = req.body as {
        domain?: string;
        firstPartyHost?: string;
        appName?: string;
      };
      if (!domain || typeof domain !== 'string') {
        res.status(400).json({ error: 'A domain or URL is required.' });
        return;
      }
      const inspection = await inspectLiveDomain(domain, firstPartyHost);
      broadcastMonitorEvent({
        type: 'probe',
        timestamp: inspection.observedAt,
        summary: `Verified live DNS/TLS probe for ${inspection.domain} (${inspection.geo.ip} · ${inspection.geo.city}, ${inspection.geo.country})`,
        observations: [
          {
            appName: appName || inspection.domain,
            ...inspection,
          },
        ],
      });
      res.json(inspection);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Domain inspection failed.';
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/apps/analyze-web', async (req: Request, res: Response) => {
    try {
      const { url } = req.body as { url?: string };
      if (!url || typeof url !== 'string') {
        res.status(400).json({ error: 'Target web URL is required.' });
        return;
      }
      const result = await analyzeLiveWebApplication(url);
      broadcastMonitorEvent({
        type: 'web-scan',
        timestamp: new Date().toISOString(),
        summary: `Scanned live web origin ${result.app.packageId}: ${result.inspectedConnections.length} external endpoints inspected.`,
        observations: result.inspectedConnections,
      });
      res.json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Web application analysis failed.';
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/apps/analyze-manifest', async (req: Request, res: Response) => {
    try {
      const { name, packageId, developer, version, platform, manifestContent, policyUrl } =
        req.body as {
          name?: string;
          packageId?: string;
          developer?: string;
          version?: string;
          platform?: 'windows' | 'android' | 'linux' | 'macos' | 'ios' | 'web';
          manifestContent?: string;
          policyUrl?: string;
        };
      if (!name || !packageId || !manifestContent) {
        res.status(400).json({ error: 'Application name, packageId, and manifest/permissions text are required.' });
        return;
      }
      const result = await analyzeManifestText({
        name,
        packageId,
        developer: developer || 'Disclosed Publisher',
        version: version || '1.0.0',
        platform: platform || 'android',
        manifestContent,
        policyUrl,
      });
      res.json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Manifest analysis failed.';
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/captures/parse', async (req: Request, res: Response) => {
    try {
      const { rawContent, format, defaultAppName, firstPartyHost } = req.body as {
        rawContent?: string;
        format?: 'har' | 'ios-ndjson' | 'nla-json' | 'csv';
        defaultAppName?: string;
        firstPartyHost?: string;
      };
      if (!rawContent || !format) {
        res.status(400).json({ error: 'Capture content and format are required.' });
        return;
      }
      const parsed = await parseAndEnrichCapture({
        rawContent,
        format,
        defaultAppName: defaultAppName || 'Imported Capture',
        firstPartyHost,
      });
      broadcastMonitorEvent({
        type: 'capture',
        timestamp: new Date().toISOString(),
        summary: `Parsed ${format.toUpperCase()} capture: ${parsed.observations.length} unique endpoint routes resolved.`,
        observations: parsed.observations,
      });
      res.json(parsed);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Capture parsing failed.';
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/agent/ingest', async (req: Request, res: Response) => {
    try {
      const { deviceId, observations } = req.body as {
        deviceId?: string;
        observations?: Array<{
          appName?: string;
          destinationDomain?: string;
          destinationIp?: string;
          destinationPort?: number;
          protocol?: string;
          bytes?: number;
          observedAt?: string;
        }>;
      };
      if (!deviceId || !Array.isArray(observations)) {
        res.status(400).json({ error: 'deviceId and observations array are required.' });
        return;
      }
      const enriched = await parseAndEnrichCapture({
        rawContent: JSON.stringify(observations),
        format: 'nla-json',
        defaultAppName: 'Endpoint Process',
      });
      broadcastMonitorEvent({
        type: 'agent-ingest',
        timestamp: new Date().toISOString(),
        summary: `Endpoint ${deviceId} submitted ${enriched.observations.length} authorized socket records.`,
        observations: enriched.observations,
      });
      res.json({ accepted: enriched.observations.length, integritySha256: enriched.integritySha256, observations: enriched.observations });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Agent ingestion failed.';
      res.status(400).json({ error: message });
    }
  });

  app.post('/api/policies/analyze', async (req: Request, res: Response) => {
    try {
      const { appName, policyUrl, policyText, pdfBase64, oldPolicyText, versionLabel } =
        req.body as {
          appName?: string;
          policyUrl?: string;
          policyText?: string;
          pdfBase64?: string;
          oldPolicyText?: string;
          versionLabel?: string;
        };
      if (!appName) {
        res.status(400).json({ error: 'Application or website name is required.' });
        return;
      }
      const result = await analyzePrivacyPolicyWithGemini({
        appName,
        policyUrl,
        policyText,
        pdfBase64,
        oldPolicyText,
        versionLabel: versionLabel || 'Current',
      });
      res.json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Privacy policy analysis failed.';
      res.status(500).json({ error: message });
    }
  });

  app.post('/api/ai/chat', async (req: Request, res: Response) => {
    try {
      const { question, history, telemetryContext, useWebSearch } = req.body as {
        question?: string;
        history?: Array<{ role: 'user' | 'model'; text: string }>;
        telemetryContext?: string;
        useWebSearch?: boolean;
      };
      if (!question || typeof question !== 'string') {
        res.status(400).json({ error: 'Question is required.' });
        return;
      }
      const result = await askNlaIntelligence({
        question,
        history: Array.isArray(history) ? history : [],
        telemetryContext: telemetryContext || 'No workspace telemetry collected yet.',
        useWebSearch: Boolean(useWebSearch),
      });
      res.json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'NLA Intelligence request failed.';
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/threat-intel/status', async (_req: Request, res: Response) => {
    try {
      const feeds = await refreshAllThreatFeeds(false);
      res.json({ feeds });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Feed status error', feeds: getThreatFeedStatuses() });
    }
  });

  app.post('/api/threat-intel/refresh', async (_req: Request, res: Response) => {
    try {
      const feeds = await refreshAllThreatFeeds(true);
      res.json({ feeds, refreshedAt: new Date().toISOString() });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Feed refresh failed.' });
    }
  });

  app.post('/api/threat-intel/cross-reference', async (req: Request, res: Response) => {
    try {
      const { domains } = req.body as { domains?: string[] };
      if (!Array.isArray(domains) || domains.length === 0) {
        res.status(400).json({ error: 'Provide a non-empty domains array.' });
        return;
      }
      const unique = Array.from(new Set(domains.map((d) => String(d).trim().toLowerCase()).filter(Boolean))).slice(0, 60);
      const results = await Promise.all(unique.map((d) => crossReferenceDomainWithFeeds(d)));
      res.json({ results, feeds: getThreatFeedStatuses() });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Cross-reference failed.' });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.join(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('/{*path}', (_req: Request, res: Response) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`NLA (Network & Location Awareness) server running on http://0.0.0.0:${PORT}`);
    void refreshAllThreatFeeds(false).catch(() => {});
  });
}

startServer().catch((err) => {
  console.error('Failed to start NLA server:', err);
  process.exit(1);
});
