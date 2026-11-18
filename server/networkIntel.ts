import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import { crossReferenceDomainWithFeeds, type ThreatFeedMatch } from './threatIntel.ts';

export interface DomainClassification {
  companyName: string;
  category:
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
  confidence: 'high' | 'medium' | 'low';
  reason: string;
}

export interface GeoIpResult {
  ip: string;
  city: string;
  country: string;
  countryCode: string;
  latitude: number;
  longitude: number;
  asn: string;
  hostingOrg: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface TlsMetadataResult {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  alpnProtocol: string;
  authorized: boolean;
}

export interface DomainInspectionResult {
  domain: string;
  resolvedIps: string[];
  dnsRecords: {
    a: string[];
    aaaa: string[];
    cname: string[];
    txtCount: number;
  };
  tls: TlsMetadataResult | null;
  httpHeaders: {
    statusCode: number | null;
    server: string;
    via: string;
    setCookieCount: number;
    hsts: boolean;
    csp: boolean;
  };
  geo: GeoIpResult;
  classification: DomainClassification;
  threatIntel: ThreatFeedMatch;
  observedAt: string;
}

const KNOWN_SERVICE_PATTERNS: Array<{
  pattern: RegExp;
  companyName: string;
  category: DomainClassification['category'];
  reason: string;
}> = [
  { pattern: /(^|\.)doubleclick\.net$|(^|\.)googlesyndication\.com$|(^|\.)googleadservices\.com$|(^|\.)admob\.com$/i, companyName: 'Google Ads / DoubleClick', category: 'advertising', reason: 'Known advertising & ad-mediation domain signature.' },
  { pattern: /(^|\.)google-analytics\.com$|(^|\.)googletagmanager\.com$|(^|\.)app-measurement\.com$|(^|\.)firebase-settings\.crashlytics\.com$/i, companyName: 'Google Analytics / Measurement', category: 'analytics', reason: 'Known web/mobile analytics & telemetry collection endpoint.' },
  { pattern: /(^|\.)crashlytics\.com$|(^|\.)sentry\.io$|(^|\.)bugsnag\.com$|(^|\.)instabug\.com$/i, companyName: 'Crash & Diagnostics Telemetry', category: 'crash-reporting', reason: 'Known application crash reporting and diagnostics endpoint.' },
  { pattern: /(^|\.)appsflyer\.com$|(^|\.)adjust\.com$|(^|\.)branch\.io$|(^|\.)kochava\.com$/i, companyName: 'Mobile Attribution Network', category: 'attribution', reason: 'Known install attribution and deep-link tracking domain.' },
  { pattern: /(^|\.)graph\.facebook\.com$|(^|\.)connect\.facebook\.net$|(^|\.)facebook\.com$|(^|\.)fbcdn\.net$/i, companyName: 'Meta Platforms', category: 'social', reason: 'Meta Graph API, SDK, or social integration endpoint.' },
  { pattern: /(^|\.)ads\.tiktok\.com$|(^|\.)analytics\.tiktok\.com$|(^|\.)byteoversea\.com$/i, companyName: 'TikTok / ByteDance Analytics', category: 'advertising', reason: 'Known advertising and behavioral analytics endpoint.' },
  { pattern: /(^|\.)mixpanel\.com$|(^|\.)amplitude\.com$|(^|\.)segment\.io$|(^|\.)segment\.com$|(^|\.)heap\.io$|(^|\.)posthog\.com$/i, companyName: 'Product Analytics Provider', category: 'analytics', reason: 'Known product event analytics SDK endpoint.' },
  { pattern: /(^|\.)stripe\.com$|(^|\.)js\.stripe\.com$|(^|\.)paypal\.com$|(^|\.)braintreegateway\.com$|(^|\.)adyen\.com$/i, companyName: 'Payment Infrastructure', category: 'payment', reason: 'Payment tokenization and checkout processing domain.' },
  { pattern: /(^|\.)cloudflare\.com$|(^|\.)cloudflareinsights\.com$|(^|\.)fastly\.net$|(^|\.)akamaized\.net$|(^|\.)akamai\.net$|(^|\.)cloudfront\.net$/i, companyName: 'CDN & Edge Network', category: 'cdn', reason: 'Content delivery network and edge caching infrastructure.' },
  { pattern: /(^|\.)amazonaws\.com$|(^|\.)azure\.com$|(^|\.)microsoft\.com$|(^|\.)googleapis\.com$|(^|\.)googleusercontent\.com$/i, companyName: 'Cloud Infrastructure', category: 'cloud', reason: 'Hyperscale cloud hosting or API infrastructure.' },
];

export function isPrivateOrReservedIp(ip: string): boolean {
  if (!net.isIP(ip)) return true;
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
    const [a, b] = parts;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  return (
    lower === '::1' ||
    lower === '::' ||
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.startsWith('fe80')
  );
}

export function sanitizeHostname(input: string): string {
  const trimmed = input.trim().toLowerCase();
  let host = trimmed;
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    host = new URL(trimmed).hostname;
  }
  host = host.split('/')[0].split(':')[0].replace(/[^a-z0-9.-]/g, '');
  if (!host || host.length > 253 || host === 'localhost' || host.endsWith('.local')) {
    throw new Error('Invalid or local-only hostname.');
  }
  return host;
}

export function classifyDomain(
  domain: string,
  firstPartyHost?: string,
  hostingOrg?: string
): DomainClassification {
  const lower = domain.toLowerCase();
  if (firstPartyHost) {
    const rootFirst = firstPartyHost.toLowerCase().split('.').slice(-2).join('.');
    if (lower === firstPartyHost.toLowerCase() || lower.endsWith(`.${rootFirst}`)) {
      return {
        companyName: firstPartyHost,
        category: 'first-party',
        confidence: 'high',
        reason: `Matches primary application domain (${rootFirst}).`,
      };
    }
  }

  for (const entry of KNOWN_SERVICE_PATTERNS) {
    if (entry.pattern.test(lower)) {
      return {
        companyName: entry.companyName,
        category: entry.category,
        confidence: 'high',
        reason: entry.reason,
      };
    }
  }

  if (hostingOrg) {
    const orgLower = hostingOrg.toLowerCase();
    if (orgLower.includes('cloudflare') || orgLower.includes('fastly') || orgLower.includes('akamai')) {
      return {
        companyName: hostingOrg,
        category: 'cdn',
        confidence: 'medium',
        reason: `Hosted on CDN edge network (${hostingOrg}). Not assumed to be a tracker.`,
      };
    }
    if (orgLower.includes('amazon') || orgLower.includes('google') || orgLower.includes('microsoft') || orgLower.includes('digitalocean') || orgLower.includes('hetzner')) {
      return {
        companyName: hostingOrg,
        category: 'cloud',
        confidence: 'medium',
        reason: `Hosted on general cloud infrastructure (${hostingOrg}). Purpose requires payload or disclosure context.`,
      };
    }
  }

  return {
    companyName: domain,
    category: 'unclassified',
    confidence: 'low',
    reason: 'External endpoint without confirmed tracking signature. Not classified as a tracker without supporting evidence.',
  };
}

export async function lookupGeoIp(ip: string): Promise<GeoIpResult> {
  if (!ip || isPrivateOrReservedIp(ip)) {
    return {
      ip: ip || 'unresolved',
      city: 'Private / Unrouted',
      country: 'Local Network',
      countryCode: 'LOC',
      latitude: 0,
      longitude: 0,
      asn: 'RFC1918',
      hostingOrg: 'Private Network Space',
      confidence: 'low',
    };
  }

  try {
    const res = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,city,lat,lon,isp,org,as`,
      { signal: AbortSignal.timeout(4500) }
    );
    if (res.ok) {
      const data = (await res.json()) as {
        status?: string;
        country?: string;
        countryCode?: string;
        city?: string;
        lat?: number;
        lon?: number;
        isp?: string;
        org?: string;
        as?: string;
      };
      if (data.status === 'success' && typeof data.lat === 'number' && typeof data.lon === 'number') {
        const asnMatch = (data.as || '').match(/AS\d+/i);
        return {
          ip,
          city: data.city || 'Unknown City',
          country: data.country || 'Unknown Country',
          countryCode: data.countryCode || 'UN',
          latitude: data.lat,
          longitude: data.lon,
          asn: asnMatch ? asnMatch[0].toUpperCase() : data.as || 'Unknown ASN',
          hostingOrg: data.org || data.isp || 'Unknown Network Operator',
          confidence: 'medium',
        };
      }
    }
  } catch {
    // Fall through to secondary lookup
  }

  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(4500),
    });
    if (res.ok) {
      const data = (await res.json()) as {
        success?: boolean;
        city?: string;
        country?: string;
        country_code?: string;
        latitude?: number;
        longitude?: number;
        connection?: { asn?: number; org?: string; isp?: string };
      };
      if (data.success && typeof data.latitude === 'number' && typeof data.longitude === 'number') {
        return {
          ip,
          city: data.city || 'Unknown City',
          country: data.country || 'Unknown Country',
          countryCode: data.country_code || 'UN',
          latitude: data.latitude,
          longitude: data.longitude,
          asn: data.connection?.asn ? `AS${data.connection.asn}` : 'Unknown ASN',
          hostingOrg: data.connection?.org || data.connection?.isp || 'Unknown Network Operator',
          confidence: 'medium',
        };
      }
    }
  } catch {
    // Return unresolved metadata rather than fabricating coordinates
  }

  return {
    ip,
    city: 'Unresolved GeoIP',
    country: 'Unverified',
    countryCode: 'UN',
    latitude: 0,
    longitude: 0,
    asn: 'Unresolved',
    hostingOrg: 'Unresolved Operator',
    confidence: 'low',
  };
}

export async function inspectTlsCertificate(domain: string, ip: string): Promise<TlsMetadataResult | null> {
  if (isPrivateOrReservedIp(ip)) return null;
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: ip,
        port: 443,
        servername: domain,
        ALPNProtocols: ['h2', 'http/1.1'],
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const subjectCN =
            typeof cert?.subject?.CN === 'string' ? cert.subject.CN : domain;
          const issuerO =
            typeof cert?.issuer?.O === 'string'
              ? cert.issuer.O
              : typeof cert?.issuer?.CN === 'string'
                ? cert.issuer.CN
                : 'Unknown CA';
          resolve({
            subject: subjectCN,
            issuer: issuerO,
            validFrom: cert?.valid_from || '',
            validTo: cert?.valid_to || '',
            alpnProtocol: typeof socket.alpnProtocol === 'string' ? socket.alpnProtocol : 'tls',
            authorized: socket.authorized,
          });
        } catch {
          resolve(null);
        } finally {
          socket.end();
        }
      }
    );
    socket.setTimeout(3500, () => {
      socket.destroy();
      resolve(null);
    });
    socket.on('error', () => {
      resolve(null);
    });
  });
}

export async function inspectLiveDomain(
  rawDomain: string,
  firstPartyHost?: string
): Promise<DomainInspectionResult> {
  const domain = sanitizeHostname(rawDomain);
  const [a, aaaa, cname, txt] = await Promise.all([
    dns.resolve4(domain).catch(() => [] as string[]),
    dns.resolve6(domain).catch(() => [] as string[]),
    dns.resolveCname(domain).catch(() => [] as string[]),
    dns.resolveTxt(domain).catch(() => [] as string[][]),
  ]);

  const resolvedIps = [...a, ...aaaa];
  const primaryIp = a[0] || aaaa[0] || '';
  if (!primaryIp || isPrivateOrReservedIp(primaryIp)) {
    throw new Error(`Hostname ${domain} did not resolve to a public routable IP address.`);
  }

  const [geo, tlsMeta, httpHeaders] = await Promise.all([
    lookupGeoIp(primaryIp),
    inspectTlsCertificate(domain, primaryIp),
    (async () => {
      try {
        const res = await fetch(`https://${domain}`, {
          method: 'HEAD',
          redirect: 'manual',
          signal: AbortSignal.timeout(4000),
        });
        const setCookie = res.headers.get('set-cookie');
        return {
          statusCode: res.status,
          server: res.headers.get('server') || 'Undisclosed',
          via: res.headers.get('via') || '',
          setCookieCount: setCookie ? setCookie.split(',').length : 0,
          hsts: res.headers.has('strict-transport-security'),
          csp: res.headers.has('content-security-policy'),
        };
      } catch {
        return {
          statusCode: null,
          server: 'Unreachable over HTTPS HEAD',
          via: '',
          setCookieCount: 0,
          hsts: false,
          csp: false,
        };
      }
    })(),
  ]);

  const [classification, threatIntel] = await Promise.all([
    Promise.resolve(classifyDomain(domain, firstPartyHost, geo.hostingOrg)),
    crossReferenceDomainWithFeeds(domain),
  ]);

  return {
    domain,
    resolvedIps,
    dnsRecords: {
      a,
      aaaa,
      cname,
      txtCount: txt.length,
    },
    tls: tlsMeta,
    httpHeaders,
    geo,
    classification,
    threatIntel,
    observedAt: new Date().toISOString(),
  };
}
