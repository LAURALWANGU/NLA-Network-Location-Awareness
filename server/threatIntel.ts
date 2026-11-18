export type ExternalFeedVerdict =
  | 'malicious'
  | 'privacy-invasive'
  | 'ad-tracker'
  | 'clean'
  | 'unlisted';

export interface ThreatFeedMatch {
  domain: string;
  verdict: ExternalFeedVerdict;
  feedSource: string;
  categoryLabel: string;
  details: string;
  checkedAt: string;
}

export interface FeedStatusRecord {
  id: string;
  name: string;
  provider: string;
  url: string;
  status: 'synced' | 'error' | 'pending';
  entryCount: number;
  lastSyncedAt: string | null;
  errorMessage?: string;
}

const urlhausHosts = new Set<string>();
const disconnectDomains = new Map<string, { category: string; company: string }>();
const pglAdDomains = new Set<string>();

let lastSyncEpoch = 0;
let syncingPromise: Promise<void> | null = null;

const feedStatuses: Record<string, FeedStatusRecord> = {
  urlhaus: {
    id: 'urlhaus',
    name: 'URLhaus Online Malware & C2 Hostlist',
    provider: 'abuse.ch URLhaus',
    url: 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt',
    status: 'pending',
    entryCount: 0,
    lastSyncedAt: null,
  },
  disconnect: {
    id: 'disconnect',
    name: 'Disconnect Tracker Protection List',
    provider: 'Disconnect.me',
    url: 'https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json',
    status: 'pending',
    entryCount: 0,
    lastSyncedAt: null,
  },
  pgl: {
    id: 'pgl',
    name: "Peter Lowe's Ad & Tracking Server List",
    provider: 'pgl.yoyo.org',
    url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain&showintro=0&mimetype=plaintext',
    status: 'pending',
    entryCount: 0,
    lastSyncedAt: null,
  },
};

async function syncUrlhaus(): Promise<void> {
  try {
    const res = await fetch(feedStatuses.urlhaus.url, {
      headers: { 'User-Agent': 'NLA-ThreatIntel/1.0 (+https://newtonix.tech)' },
      signal: AbortSignal.timeout(7000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const nextSet = new Set<string>();
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const parts = trimmed.split(/\s+/);
      const host = (parts.length >= 2 ? parts[1] : parts[0]).toLowerCase();
      if (host && host.includes('.') && host !== 'localhost') {
        nextSet.add(host);
      }
    }
    urlhausHosts.clear();
    nextSet.forEach((h) => urlhausHosts.add(h));
    feedStatuses.urlhaus = {
      ...feedStatuses.urlhaus,
      status: 'synced',
      entryCount: urlhausHosts.size,
      lastSyncedAt: new Date().toISOString(),
      errorMessage: undefined,
    };
  } catch (err) {
    feedStatuses.urlhaus = {
      ...feedStatuses.urlhaus,
      status: 'error',
      errorMessage: err instanceof Error ? err.message : 'Fetch failed',
    };
  }
}

async function syncDisconnect(): Promise<void> {
  try {
    const res = await fetch(feedStatuses.disconnect.url, {
      headers: { 'User-Agent': 'NLA-ThreatIntel/1.0 (+https://newtonix.tech)' },
      signal: AbortSignal.timeout(7000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as {
      categories?: Record<
        string,
        Array<Record<string, Record<string, string[]>>>
      >;
    };
    const nextMap = new Map<string, { category: string; company: string }>();
    const categories = data.categories || {};
    for (const [catName, entries] of Object.entries(categories)) {
      if (!Array.isArray(entries)) continue;
      for (const entityObj of entries) {
        for (const [company, siteMap] of Object.entries(entityObj)) {
          for (const domains of Object.values(siteMap)) {
            if (!Array.isArray(domains)) continue;
            for (const d of domains) {
              const host = String(d).toLowerCase().trim();
              if (host && host.includes('.')) {
                nextMap.set(host, { category: catName, company });
              }
            }
          }
        }
      }
    }
    disconnectDomains.clear();
    nextMap.forEach((v, k) => disconnectDomains.set(k, v));
    feedStatuses.disconnect = {
      ...feedStatuses.disconnect,
      status: 'synced',
      entryCount: disconnectDomains.size,
      lastSyncedAt: new Date().toISOString(),
      errorMessage: undefined,
    };
  } catch (err) {
    feedStatuses.disconnect = {
      ...feedStatuses.disconnect,
      status: 'error',
      errorMessage: err instanceof Error ? err.message : 'Fetch failed',
    };
  }
}

async function syncPgl(): Promise<void> {
  try {
    const res = await fetch(feedStatuses.pgl.url, {
      headers: { 'User-Agent': 'NLA-ThreatIntel/1.0 (+https://newtonix.tech)' },
      signal: AbortSignal.timeout(7000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const nextSet = new Set<string>();
    for (const line of text.split(/\r?\n/)) {
      const host = line.trim().toLowerCase();
      if (host && !host.startsWith('#') && host.includes('.')) {
        nextSet.add(host);
      }
    }
    pglAdDomains.clear();
    nextSet.forEach((h) => pglAdDomains.add(h));
    feedStatuses.pgl = {
      ...feedStatuses.pgl,
      status: 'synced',
      entryCount: pglAdDomains.size,
      lastSyncedAt: new Date().toISOString(),
      errorMessage: undefined,
    };
  } catch (err) {
    feedStatuses.pgl = {
      ...feedStatuses.pgl,
      status: 'error',
      errorMessage: err instanceof Error ? err.message : 'Fetch failed',
    };
  }
}

export async function refreshAllThreatFeeds(force = false): Promise<FeedStatusRecord[]> {
  const now = Date.now();
  if (!force && now - lastSyncEpoch < 3600_000 && lastSyncEpoch > 0) {
    return Object.values(feedStatuses);
  }
  if (!syncingPromise) {
    syncingPromise = Promise.all([syncUrlhaus(), syncDisconnect(), syncPgl()])
      .then(() => {
        lastSyncEpoch = Date.now();
      })
      .finally(() => {
        syncingPromise = null;
      });
  }
  await syncingPromise;
  return Object.values(feedStatuses);
}

export function getThreatFeedStatuses(): FeedStatusRecord[] {
  return Object.values(feedStatuses);
}

function getCandidateDomains(domain: string): string[] {
  const parts = domain.toLowerCase().trim().split('.').filter(Boolean);
  const candidates: string[] = [];
  for (let i = 0; i <= Math.max(0, parts.length - 2); i++) {
    candidates.push(parts.slice(i).join('.'));
  }
  return candidates;
}

export async function crossReferenceDomainWithFeeds(
  rawDomain: string
): Promise<ThreatFeedMatch> {
  await refreshAllThreatFeeds(false);
  const domain = rawDomain.toLowerCase().trim();
  const candidates = getCandidateDomains(domain);
  const checkedAt = new Date().toISOString();

  for (const cand of candidates) {
    if (urlhausHosts.has(cand)) {
      return {
        domain,
        verdict: 'malicious',
        feedSource: 'abuse.ch URLhaus Feed',
        categoryLabel: 'Malware / C2 Infrastructure',
        details: `Matched active URLhaus hostlist entry (${cand}). External feed flags this host for malware distribution or command-and-control activity.`,
        checkedAt,
      };
    }
  }

  for (const cand of candidates) {
    const dcMatch = disconnectDomains.get(cand);
    if (dcMatch) {
      const catLower = dcMatch.category.toLowerCase();
      const isInvasive =
        catLower.includes('fingerprinting') ||
        catLower.includes('cryptomining') ||
        catLower.includes('analytics') ||
        catLower.includes('advertising');
      return {
        domain,
        verdict: isInvasive ? 'privacy-invasive' : 'ad-tracker',
        feedSource: 'Disconnect.me Tracker Protection Feed',
        categoryLabel: `${dcMatch.category} (${dcMatch.company})`,
        details: `Matched Disconnect.me entity "${dcMatch.company}" under category "${dcMatch.category}" via ${cand}.`,
        checkedAt,
      };
    }
  }

  for (const cand of candidates) {
    if (pglAdDomains.has(cand)) {
      return {
        domain,
        verdict: 'ad-tracker',
        feedSource: "Peter Lowe's Ad & Tracking List",
        categoryLabel: 'Advertising / Telemetry Server',
        details: `Matched Peter Lowe ad/tracking hostlist entry (${cand}).`,
        checkedAt,
      };
    }
  }

  const syncedCount = Object.values(feedStatuses).filter((f) => f.status === 'synced').length;
  return {
    domain,
    verdict: 'unlisted',
    feedSource:
      syncedCount > 0
        ? `Cross-referenced against ${syncedCount} live threat & tracker feeds`
        : 'External threat feeds unavailable',
    categoryLabel: 'No External Feed Match',
    details:
      syncedCount > 0
        ? 'Domain did not match URLhaus malware, Disconnect.me tracking, or Peter Lowe adserver lists at check time.'
        : 'External feeds have not synced yet; retry feed sync.',
    checkedAt,
  };
}
