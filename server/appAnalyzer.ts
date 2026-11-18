import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import {
  classifyDomain,
  inspectLiveDomain,
  isPrivateOrReservedIp,
  lookupGeoIp,
  sanitizeHostname,
} from './networkIntel.ts';
import { crossReferenceDomainWithFeeds, type ThreatFeedMatch } from './threatIntel.ts';

export interface TransparentScoreBreakdown {
  privacyScore: number;
  permissionsPenalty: number;
  thirdPartyPenalty: number;
  backgroundPenalty: number;
  disclosurePenalty: number;
}

const SENSITIVE_PERMISSIONS = [
  'CAMERA',
  'RECORD_AUDIO',
  'MICROPHONE',
  'ACCESS_FINE_LOCATION',
  'ACCESS_COARSE_LOCATION',
  'ACCESS_BACKGROUND_LOCATION',
  'LOCATION',
  'READ_CONTACTS',
  'WRITE_CONTACTS',
  'CONTACTS',
  'READ_EXTERNAL_STORAGE',
  'READ_MEDIA_IMAGES',
  'PHOTOS',
  'BLUETOOTH',
  'BLUETOOTH_SCAN',
  'BLUETOOTH_CONNECT',
  'RECEIVE_BOOT_COMPLETED',
  'FOREGROUND_SERVICE',
  'AD_ID',
];

const KNOWN_SDK_SIGNATURES: Array<{ pattern: RegExp; sdk: string; category: string }> = [
  { pattern: /google-analytics|googletagmanager|gtag|firebase/i, sdk: 'Google Analytics / Firebase Telemetry', category: 'analytics' },
  { pattern: /doubleclick|googlesyndication|admob|googleads/i, sdk: 'Google AdMob / DoubleClick Ads', category: 'advertising' },
  { pattern: /facebook\.net|fbcdn|graph\.facebook|fbsdk/i, sdk: 'Meta / Facebook SDK', category: 'social' },
  { pattern: /appsflyer/i, sdk: 'AppsFlyer Attribution SDK', category: 'attribution' },
  { pattern: /adjust\.com|adjust/i, sdk: 'Adjust Attribution SDK', category: 'attribution' },
  { pattern: /branch\.io|branchmetrics/i, sdk: 'Branch Deep-Link Attribution', category: 'attribution' },
  { pattern: /sentry\.io|sentry/i, sdk: 'Sentry Diagnostics SDK', category: 'crash-reporting' },
  { pattern: /crashlytics/i, sdk: 'Firebase Crashlytics', category: 'crash-reporting' },
  { pattern: /mixpanel/i, sdk: 'Mixpanel Product Analytics', category: 'analytics' },
  { pattern: /amplitude/i, sdk: 'Amplitude Analytics', category: 'analytics' },
  { pattern: /segment\.io|segment\.com/i, sdk: 'Segment CDP', category: 'analytics' },
  { pattern: /stripe\.com/i, sdk: 'Stripe Payments SDK', category: 'payment' },
  { pattern: /tiktok|byteoversea/i, sdk: 'TikTok Pixel / Analytics SDK', category: 'advertising' },
];

export function computePrivacyScore(params: {
  requestedPermissions: string[];
  grantedPermissions: string[];
  externalDomains: string[];
  detectedSdks: string[];
  hasBackgroundActivity: boolean;
  hasPolicyUrl: boolean;
  hasRetentionDisclosure: boolean;
  hasAdId: boolean;
}): TransparentScoreBreakdown {
  const highSensitivityCount = params.requestedPermissions.filter((perm) =>
    SENSITIVE_PERMISSIONS.some((s) => perm.toUpperCase().includes(s))
  ).length;
  const permissionsPenalty = Math.min(
    40,
    highSensitivityCount * 5 + (params.hasAdId ? 6 : 0)
  );

  const trackerSdks = params.detectedSdks.filter(
    (s) =>
      /ad|analytics|attribution|meta|tiktok|segment|mixpanel|amplitude/i.test(s)
  ).length;
  const thirdPartyPenalty = Math.min(
    30,
    Math.min(params.externalDomains.length, 10) * 2 + trackerSdks * 4
  );

  const backgroundPenalty = params.hasBackgroundActivity ? 12 : 0;
  const disclosurePenalty =
    (params.hasPolicyUrl ? 0 : 8) + (params.hasRetentionDisclosure ? 0 : 7);

  const totalPenalty =
    permissionsPenalty + thirdPartyPenalty + backgroundPenalty + disclosurePenalty;
  const privacyScore = Math.max(0, Math.min(100, 100 - totalPenalty));

  return {
    privacyScore,
    permissionsPenalty,
    thirdPartyPenalty,
    backgroundPenalty,
    disclosurePenalty,
  };
}

export async function analyzeLiveWebApplication(targetUrl: string) {
  const normalizedUrl =
    targetUrl.startsWith('http://') || targetUrl.startsWith('https://')
      ? targetUrl
      : `https://${targetUrl}`;
  const parsed = new URL(normalizedUrl);
  const host = sanitizeHostname(parsed.hostname);

  const ips = await dns.resolve4(host).catch(() => [] as string[]);
  if (ips.length === 0 || isPrivateOrReservedIp(ips[0])) {
    throw new Error(`Target host ${host} did not resolve to a public IPv4 address.`);
  }

  const res = await fetch(parsed.toString(), {
    method: 'GET',
    redirect: 'follow',
    headers: {
      'User-Agent': 'NLA-Privacy-Inspector/1.0 (+https://newtonix.tech)',
      Accept: 'text/html,application/xhtml+xml',
    },
    signal: AbortSignal.timeout(8000),
  });

  const html = await res.text();
  const titleMatch = html.match(/<title[^>]*>([^<]{1,120})<\/title>/i);
  const appName = titleMatch ? titleMatch[1].trim() : host;

  const urlMatches = Array.from(
    html.matchAll(/(?:src|href|action)=["'](https?:\/\/[^"'\s>]+)["']/gi)
  ).map((m) => m[1]);

  const externalDomainSet = new Set<string>();
  let discoveredPolicyUrl = '';

  for (const rawLink of urlMatches) {
    try {
      const linkUrl = new URL(rawLink);
      const linkHost = linkUrl.hostname.toLowerCase();
      if (/privacy/i.test(rawLink) && !discoveredPolicyUrl) {
        discoveredPolicyUrl = rawLink;
      }
      if (linkHost !== host && !linkHost.endsWith(`.${host}`)) {
        externalDomainSet.add(linkHost);
      }
    } catch {
      // Ignore malformed URIs
    }
  }

  const externalDomains = Array.from(externalDomainSet).slice(0, 16);
  const detectedSdksSet = new Set<string>();
  for (const dom of externalDomains) {
    for (const sig of KNOWN_SDK_SIGNATURES) {
      if (sig.pattern.test(dom)) {
        detectedSdksSet.add(sig.sdk);
      }
    }
  }
  for (const sig of KNOWN_SDK_SIGNATURES) {
    if (sig.pattern.test(html)) {
      detectedSdksSet.add(sig.sdk);
    }
  }

  const permPolicyHeader = res.headers.get('permissions-policy') || '';
  const requestedPermissions: string[] = [];
  if (permPolicyHeader.includes('camera')) requestedPermissions.push('Browser Camera Policy');
  if (permPolicyHeader.includes('microphone')) requestedPermissions.push('Browser Microphone Policy');
  if (permPolicyHeader.includes('geolocation')) requestedPermissions.push('Browser Geolocation Policy');
  if (/navigator\.geolocation/i.test(html)) requestedPermissions.push('LOCATION (navigator.geolocation script reference)');
  if (/getUserMedia/i.test(html)) requestedPermissions.push('CAMERA / MICROPHONE (getUserMedia script reference)');
  if (/serviceWorker\.register/i.test(html)) requestedPermissions.push('BACKGROUND_SYNC (Service Worker registration)');
  if (/document\.cookie/i.test(html) || res.headers.has('set-cookie')) {
    requestedPermissions.push('COOKIE_STORAGE (HTTP Set-Cookie / document.cookie)');
  }

  const domainsToInspect = [host, ...externalDomains.slice(0, 6)];
  const inspectedConnections = [];
  for (const dom of domainsToInspect) {
    try {
      const info = await inspectLiveDomain(dom, host);
      inspectedConnections.push(info);
    } catch {
      // Skip domains that fail DNS resolution
    }
  }

  const detectedSdks = Array.from(detectedSdksSet);
  const hasBackground = requestedPermissions.some((p) => p.includes('BACKGROUND'));
  const score = computePrivacyScore({
    requestedPermissions,
    grantedPermissions: [],
    externalDomains,
    detectedSdks,
    hasBackgroundActivity: hasBackground,
    hasPolicyUrl: Boolean(discoveredPolicyUrl),
    hasRetentionDisclosure: false,
    hasAdId: detectedSdks.some((s) => /ad/i.test(s)),
  });

  return {
    app: {
      name: appName,
      packageId: host,
      developer: host,
      version: 'Live Web Inspection',
      platform: 'web' as const,
      ...score,
      requestedPermissions,
      grantedPermissions: [] as string[],
      detectedSdks,
      externalDomains,
      advertisingIdAccess: detectedSdks.some((s) => /ad/i.test(s))
        ? ('inferred' as const)
        : ('not-detected' as const),
      policyUrl: discoveredPolicyUrl,
      retentionDisclosure: discoveredPolicyUrl
        ? 'Policy link discovered in page markup; analyze in Privacy Agreement Analyzer for retention terms.'
        : 'No privacy policy link discovered in initial HTML markup.',
      sharingPractices:
        externalDomains.length > 0
          ? `Observed ${externalDomains.length} external host references in initial HTML response.`
          : 'No external host references detected in initial HTML response.',
      evidenceType: 'verified-technical' as const,
    },
    inspectedConnections,
  };
}

export async function analyzeManifestText(params: {
  name: string;
  packageId: string;
  developer: string;
  version: string;
  platform: 'windows' | 'android' | 'linux' | 'macos' | 'ios' | 'web';
  manifestContent: string;
  policyUrl?: string;
}) {
  const text = params.manifestContent;
  const permMatches = new Set<string>();

  // Android uses-permission
  for (const m of text.matchAll(/android\.permission\.([A-Z0-9_]+)/g)) {
    permMatches.add(m[1]);
  }
  // iOS Info.plist NS*UsageDescription keys
  for (const m of text.matchAll(/NS([A-Za-z]+)UsageDescription/g)) {
    permMatches.add(m[1].toUpperCase());
  }
  // Comma/newline separated permissions if user pasted a list
  if (permMatches.size === 0 && text.trim().length > 0) {
    text
      .split(/[\n,;]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 2 && s.length < 80 && !s.startsWith('<'))
      .slice(0, 24)
      .forEach((p) => permMatches.add(p));
  }

  const domainMatches = new Set<string>();
  for (const m of text.matchAll(/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g)) {
    domainMatches.add(m[1].toLowerCase());
  }

  const sdkMatches = new Set<string>();
  for (const sig of KNOWN_SDK_SIGNATURES) {
    if (sig.pattern.test(text)) {
      sdkMatches.add(sig.sdk);
    }
  }

  const requestedPermissions = Array.from(permMatches).slice(0, 32);
  const externalDomains = Array.from(domainMatches).slice(0, 32);
  const detectedSdks = Array.from(sdkMatches).slice(0, 32);
  const hasAdId = requestedPermissions.some((p) => /AD_ID|IDFA|ADVERTISING/i.test(p));
  const hasBackground = requestedPermissions.some((p) =>
    /BACKGROUND|BOOT|FOREGROUND_SERVICE/i.test(p)
  );

  const score = computePrivacyScore({
    requestedPermissions,
    grantedPermissions: [],
    externalDomains,
    detectedSdks,
    hasBackgroundActivity: hasBackground,
    hasPolicyUrl: Boolean(params.policyUrl),
    hasRetentionDisclosure: false,
    hasAdId,
  });

  const inspectedConnections = [];
  for (const dom of externalDomains.slice(0, 5)) {
    try {
      const info = await inspectLiveDomain(dom, params.packageId);
      inspectedConnections.push(info);
    } catch {
      // Ignore unresolvable domains in static manifests
    }
  }

  return {
    app: {
      name: params.name,
      packageId: params.packageId,
      developer: params.developer,
      version: params.version || '1.0.0',
      platform: params.platform,
      ...score,
      requestedPermissions,
      grantedPermissions: [] as string[],
      detectedSdks,
      externalDomains,
      advertisingIdAccess: hasAdId ? ('declared' as const) : ('not-detected' as const),
      policyUrl: params.policyUrl || '',
      retentionDisclosure: params.policyUrl
        ? 'Referenced policy URL submitted; verify retention schedule in Agreement Analyzer.'
        : 'Not provided in manifest.',
      sharingPractices:
        'Requesting a permission in a manifest declares capability, not proof of active data access.',
      evidenceType: 'declared-disclosure' as const,
    },
    inspectedConnections,
  };
}

export interface ParsedCaptureObservation {
  appName: string;
  destinationDomain: string;
  destinationIp: string;
  destinationPort: number;
  protocol: 'HTTPS' | 'TLS' | 'DNS' | 'HTTP' | 'QUIC';
  bytesTransferred: number;
  requestCount: number;
  observedAt: string;
  isBackground: boolean;
  city: string;
  country: string;
  countryCode: string;
  latitude: number;
  longitude: number;
  asn: string;
  hostingOrg: string;
  companyName: string;
  serviceCategory:
    | 'first-party'
    | 'advertising'
    | 'analytics'
    | 'cloud'
    | 'cdn'
    | 'social'
    | 'crash-reporting'
    | 'payment'
    | 'attribution'
    | 'unclassified';
  partyType: 'first-party' | 'third-party' | 'unknown';
  confidence: 'high' | 'medium' | 'low';
  evidenceSummary: string;
  threatIntel: ThreatFeedMatch;
}

export async function parseAndEnrichCapture(params: {
  rawContent: string;
  format: 'har' | 'ios-ndjson' | 'nla-json' | 'csv';
  defaultAppName: string;
  firstPartyHost?: string;
}): Promise<{ observations: ParsedCaptureObservation[]; integritySha256: string }> {
  const integritySha256 = crypto
    .createHash('sha256')
    .update(params.rawContent)
    .digest('hex');

  const aggregated = new Map<
    string,
    {
      appName: string;
      domain: string;
      ip: string;
      port: number;
      protocol: 'HTTPS' | 'TLS' | 'DNS' | 'HTTP' | 'QUIC';
      bytes: number;
      count: number;
      observedAt: string;
      isBackground: boolean;
    }
  >();

  if (params.format === 'har') {
    const har = JSON.parse(params.rawContent) as {
      log?: {
        entries?: Array<{
          startedDateTime?: string;
          serverIPAddress?: string;
          request?: { url?: string };
          response?: { bodySize?: number; content?: { size?: number } };
        }>;
      };
    };
    const entries = har.log?.entries || [];
    for (const entry of entries) {
      const urlStr = entry.request?.url;
      if (!urlStr) continue;
      try {
        const u = new URL(urlStr);
        const dom = u.hostname.toLowerCase();
        const key = `${params.defaultAppName}::${dom}`;
        const bytes = Math.max(
          0,
          entry.response?.bodySize && entry.response.bodySize > 0
            ? entry.response.bodySize
            : entry.response?.content?.size || 0
        );
        const existing = aggregated.get(key);
        if (existing) {
          existing.bytes += bytes;
          existing.count += 1;
        } else {
          aggregated.set(key, {
            appName: params.defaultAppName,
            domain: dom,
            ip: entry.serverIPAddress || '',
            port: u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80,
            protocol: u.protocol === 'https:' ? 'HTTPS' : 'HTTP',
            bytes,
            count: 1,
            observedAt: entry.startedDateTime || new Date().toISOString(),
            isBackground: false,
          });
        }
      } catch {
        // Skip invalid entry URL
      }
    }
  } else if (params.format === 'ios-ndjson') {
    const lines = params.rawContent
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    for (const line of lines) {
      try {
        const item = JSON.parse(line) as {
          domain?: string;
          bundleID?: string;
          hits?: number;
          timeStamp?: string;
          domainType?: number;
        };
        if (!item.domain) continue;
        const appName = item.bundleID || params.defaultAppName;
        const dom = item.domain.toLowerCase();
        const key = `${appName}::${dom}`;
        const existing = aggregated.get(key);
        if (existing) {
          existing.count += item.hits || 1;
        } else {
          aggregated.set(key, {
            appName,
            domain: dom,
            ip: '',
            port: 443,
            protocol: 'TLS',
            bytes: 0,
            count: item.hits || 1,
            observedAt: item.timeStamp || new Date().toISOString(),
            isBackground: item.domainType === 2,
          });
        }
      } catch {
        // Ignore malformed NDJSON line
      }
    }
  } else if (params.format === 'nla-json') {
    const parsed = JSON.parse(params.rawContent) as Array<{
      appName?: string;
      domain?: string;
      destinationDomain?: string;
      ip?: string;
      destinationIp?: string;
      port?: number;
      protocol?: string;
      bytes?: number;
      observedAt?: string;
      isBackground?: boolean;
    }>;
    const rows = Array.isArray(parsed) ? parsed : [];
    for (const row of rows) {
      const dom = (row.destinationDomain || row.domain || '').toLowerCase();
      if (!dom) continue;
      const appName = row.appName || params.defaultAppName;
      const key = `${appName}::${dom}`;
      const proto =
        row.protocol === 'DNS' || row.protocol === 'HTTP' || row.protocol === 'TLS' || row.protocol === 'QUIC'
          ? row.protocol
          : 'HTTPS';
      const existing = aggregated.get(key);
      if (existing) {
        existing.bytes += row.bytes || 0;
        existing.count += 1;
      } else {
        aggregated.set(key, {
          appName,
          domain: dom,
          ip: row.destinationIp || row.ip || '',
          port: row.port || 443,
          protocol: proto,
          bytes: row.bytes || 0,
          count: 1,
          observedAt: row.observedAt || new Date().toISOString(),
          isBackground: Boolean(row.isBackground),
        });
      }
    }
  } else if (params.format === 'csv') {
    const lines = params.rawContent
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i].split(',').map((c) => c.trim().replace(/^"|"$/g, ''));
      if (cols.length < 2) continue;
      const [appNameRaw, domRaw, ipRaw, portRaw, protoRaw, bytesRaw, tsRaw] = cols;
      const dom = (domRaw || '').toLowerCase();
      if (!dom) continue;
      const appName = appNameRaw || params.defaultAppName;
      const key = `${appName}::${dom}`;
      const existing = aggregated.get(key);
      const bytes = Number(bytesRaw) || 0;
      if (existing) {
        existing.bytes += bytes;
        existing.count += 1;
      } else {
        aggregated.set(key, {
          appName,
          domain: dom,
          ip: ipRaw || '',
          port: Number(portRaw) || 443,
          protocol: protoRaw === 'DNS' || protoRaw === 'HTTP' || protoRaw === 'TLS' ? protoRaw : 'HTTPS',
          bytes,
          count: 1,
          observedAt: tsRaw || new Date().toISOString(),
          isBackground: false,
        });
      }
    }
  }

  const items = Array.from(aggregated.values()).slice(0, 30);
  const observations: ParsedCaptureObservation[] = [];

  for (const item of items) {
    let resolvedIp = item.ip;
    if (!resolvedIp) {
      try {
        const host = sanitizeHostname(item.domain);
        const ips = await dns.resolve4(host);
        resolvedIp = ips[0] || '';
      } catch {
        resolvedIp = '';
      }
    }

    const geo = await lookupGeoIp(resolvedIp);
    const classification = classifyDomain(
      item.domain,
      params.firstPartyHost,
      geo.hostingOrg
    );
    const partyType =
      classification.category === 'first-party'
        ? 'first-party'
        : classification.category === 'unclassified' && !params.firstPartyHost
          ? 'unknown'
          : 'third-party';

    const threatIntel = await crossReferenceDomainWithFeeds(item.domain);

    observations.push({
      appName: item.appName,
      destinationDomain: item.domain,
      destinationIp: geo.ip,
      destinationPort: item.port,
      protocol: item.protocol,
      bytesTransferred: item.bytes,
      requestCount: item.count,
      observedAt: item.observedAt,
      isBackground: item.isBackground,
      city: geo.city,
      country: geo.country,
      countryCode: geo.countryCode,
      latitude: geo.latitude,
      longitude: geo.longitude,
      asn: geo.asn,
      hostingOrg: geo.hostingOrg,
      companyName: classification.companyName,
      serviceCategory: classification.category,
      partyType,
      confidence: classification.confidence,
      evidenceSummary: `Imported ${params.format.toUpperCase()} capture (${item.count} requests). ${classification.reason}`,
      threatIntel,
    });
  }

  return { observations, integritySha256 };
}
