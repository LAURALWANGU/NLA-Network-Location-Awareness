import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { onAuthStateChanged, signInWithPopup, signOut, type User } from 'firebase/auth';
import { auth, googleProvider } from '../lib/firebase';
import {
  DEFAULT_ALERT_CONFIG_VALUES,
  createDeviceRecord,
  createRiskAlert,
  createSessionRecord,
  deleteOwnedDocument,
  ensureAlertConfig,
  ensureUserProfile,
  saveApplicationRecord,
  saveConnectionBatch,
  saveForensicReportRecord,
  savePolicyAnalysis,
  subscribeAlertConfig,
  subscribeOwnerCollection,
  updateAlertConfig,
  updateDeviceStatus,
  updateRiskAlertStatus,
  updateSessionStats,
  updateThirdPartyThreatIntel,
  updateUserGovernance,
  upsertThirdPartyService,
  writeAuditLog,
} from '../lib/firestoreService';
import { computeSha256Hex, generateAndDownloadForensicExport } from '../lib/exportForensics';
import type {
  AgentMode,
  AlertCategory,
  AlertConfig,
  AlertSeverity,
  AlertStatus,
  AnalyzedApplication,
  AuditLogEntry,
  DeviceRecord,
  DeviceStatus,
  ExternalFeedMatch,
  FeedStatusRecord,
  ForensicReport,
  MonitoringSession,
  NetworkConnection,
  PlatformType,
  PrivacyPolicyAnalysis,
  RiskAlert,
  ServiceCategory,
  ThirdPartyService,
  UserProfile,
} from '../types/nla';

export interface LiveStreamEvent {
  type: string;
  timestamp: string;
  summary: string;
  observations: unknown[];
}

export interface LiveAlertBanner {
  id: string;
  title: string;
  appName: string;
  domain: string;
  severity: AlertSeverity;
  category: AlertCategory;
  externalFeedSource?: string;
  timestamp: string;
}

function playAlertChime(severity: AlertSeverity) {
  try {
    const AudioCtx =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    const baseFreq = severity === 'critical' ? 784 : severity === 'high' ? 659 : 523;
    osc.frequency.setValueAtTime(baseFreq, now);
    osc.frequency.setValueAtTime(baseFreq * 1.25, now + 0.09);
    gain.gain.setValueAtTime(0.06, now);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.24);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start(now);
    osc.stop(now + 0.25);
    setTimeout(() => {
      void ctx.close().catch(() => {});
    }, 350);
  } catch {
    // Ignore audio context autoplay restrictions
  }
}

function verdictToSeverity(verdict: ExternalFeedMatch['verdict']): AlertSeverity {
  if (verdict === 'malicious') return 'critical';
  if (verdict === 'privacy-invasive') return 'high';
  return 'medium';
}

const SENSITIVE_PERM_REGEX =
  /CAMERA|AUDIO|MICROPHONE|LOCATION|CONTACTS|STORAGE|MEDIA|PHOTOS|BLUETOOTH|BOOT|FOREGROUND|AD_ID|IDFA|COOKIE_STORAGE/i;

interface NlaContextValue {
  user: User | null;
  profile: UserProfile | null;
  authReady: boolean;
  signingIn: boolean;
  authError: string | null;
  devices: DeviceRecord[];
  sessions: MonitoringSession[];
  applications: AnalyzedApplication[];
  connections: NetworkConnection[];
  thirdParties: ThirdPartyService[];
  policies: PrivacyPolicyAnalysis[];
  riskAlerts: RiskAlert[];
  forensicReports: ForensicReport[];
  auditLogs: AuditLogEntry[];
  liveEvents: LiveStreamEvent[];
  monitoringPaused: boolean;
  setMonitoringPaused: (paused: boolean) => void;
  alertConfig: AlertConfig | null;
  feedStatuses: FeedStatusRecord[];
  refreshingFeeds: boolean;
  crossReferencing: boolean;
  liveAlertBanners: LiveAlertBanner[];
  dismissAlertBanner: (id: string) => void;
  onboardingOpen: boolean;
  openOnboarding: () => void;
  closeOnboarding: () => void;
  completeOnboarding: () => Promise<void>;
  signInWithGoogle: () => Promise<void>;
  logout: () => Promise<void>;
  acceptConsent: () => Promise<void>;
  updateRetention: (days: number) => Promise<void>;
  updateAlertPreferences: (
    updates: Partial<Omit<AlertConfig, 'id' | 'ownerId' | 'createdAt' | 'updatedAt'>>
  ) => Promise<void>;
  testAlertNotification: () => void;
  refreshThreatFeeds: () => Promise<void>;
  crossReferenceAllThirdParties: () => Promise<{ checked: number; flagged: number }>;
  registerDevice: (input: {
    name: string;
    platform: PlatformType;
    osVersion: string;
    hostname: string;
    agentMode: AgentMode;
    city: string;
    country: string;
    latitude: number;
    longitude: number;
  }) => Promise<string>;
  toggleDeviceStatus: (deviceId: string, status: DeviceStatus) => Promise<void>;
  inspectDomainAndSave: (params: {
    domain: string;
    appName: string;
    firstPartyHost?: string;
    deviceId?: string;
  }) => Promise<void>;
  scanWebAppAndSave: (url: string, deviceId?: string) => Promise<void>;
  scanManifestAndSave: (params: {
    name: string;
    packageId: string;
    developer: string;
    version: string;
    platform: PlatformType;
    manifestContent: string;
    policyUrl?: string;
    deviceId?: string;
  }) => Promise<void>;
  importCaptureAndSave: (params: {
    rawContent: string;
    format: 'har' | 'ios-ndjson' | 'nla-json' | 'csv';
    defaultAppName: string;
    firstPartyHost?: string;
    deviceId?: string;
    sessionTitle?: string;
  }) => Promise<number>;
  analyzePolicyAndSave: (params: {
    appName: string;
    policyUrl?: string;
    policyText?: string;
    pdfBase64?: string;
    oldPolicyText?: string;
    versionLabel: string;
  }) => Promise<string>;
  setAlertStatus: (alertId: string, status: AlertStatus) => Promise<void>;
  exportSessionReport: (sessionId: string, format: 'json' | 'csv' | 'html' | 'pdf') => Promise<string>;
  deleteRecord: (
    collectionName: 'devices' | 'applications' | 'connections' | 'thirdParties' | 'policies' | 'forensicReports' | 'riskAlerts',
    docId: string
  ) => Promise<void>;
}

const NlaContext = createContext<NlaContextValue | null>(null);

export function NlaProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [signingIn, setSigningIn] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [sessions, setSessions] = useState<MonitoringSession[]>([]);
  const [applications, setApplications] = useState<AnalyzedApplication[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [thirdParties, setThirdParties] = useState<ThirdPartyService[]>([]);
  const [policies, setPolicies] = useState<PrivacyPolicyAnalysis[]>([]);
  const [riskAlerts, setRiskAlerts] = useState<RiskAlert[]>([]);
  const [forensicReports, setForensicReports] = useState<ForensicReport[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [liveEvents, setLiveEvents] = useState<LiveStreamEvent[]>([]);
  const [monitoringPaused, setMonitoringPaused] = useState(false);

  const [alertConfig, setAlertConfig] = useState<AlertConfig | null>(null);
  const [feedStatuses, setFeedStatuses] = useState<FeedStatusRecord[]>([]);
  const [refreshingFeeds, setRefreshingFeeds] = useState(false);
  const [crossReferencing, setCrossReferencing] = useState(false);
  const [liveAlertBanners, setLiveAlertBanners] = useState<LiveAlertBanner[]>([]);
  const [onboardingOpen, setOnboardingOpen] = useState(false);

  const alertConfigRef = useRef<AlertConfig | null>(null);
  alertConfigRef.current = alertConfig;

  const dismissAlertBanner = useCallback((id: string) => {
    setLiveAlertBanners((prev) => prev.filter((b) => b.id !== id));
  }, []);

  const triggerNotification = useCallback((banner: LiveAlertBanner) => {
    const cfg = alertConfigRef.current ?? {
      id: 'default',
      ownerId: 'default',
      ...DEFAULT_ALERT_CONFIG_VALUES,
    };
    if (cfg.notifyInAppBanner) {
      setLiveAlertBanners((prev) => [banner, ...prev].slice(0, 4));
      setTimeout(() => {
        setLiveAlertBanners((prev) => prev.filter((b) => b.id !== banner.id));
      }, 12000);
    }
    if (cfg.notifySoundChime) {
      playAlertChime(banner.severity);
    }
    if (
      cfg.notifyBrowserPush &&
      typeof Notification !== 'undefined' &&
      Notification.permission === 'granted'
    ) {
      try {
        new Notification(`NLA ${banner.severity.toUpperCase()} Alert: ${banner.appName}`, {
          body: banner.externalFeedSource
            ? `${banner.title} [${banner.externalFeedSource}]`
            : banner.title,
        });
      } catch {
        // Ignore browser notification failure
      }
    }
  }, []);

  const emitRiskAlertAndNotify = useCallback(
    async (
      ownerId: string,
      deviceId: string,
      input: Omit<RiskAlert, 'id' | 'ownerId' | 'deviceId' | 'createdAt' | 'updatedAt'>
    ): Promise<string> => {
      const alertId = await createRiskAlert(ownerId, deviceId, input);
      triggerNotification({
        id: alertId,
        title: input.title,
        appName: input.appName,
        domain: input.domain,
        severity: input.severity,
        category: input.category,
        externalFeedSource: input.externalFeedSource,
        timestamp: new Date().toISOString(),
      });
      return alertId;
    },
    [triggerNotification]
  );

  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser);
      if (firebaseUser) {
        try {
          const [prof, cfg] = await Promise.all([
            ensureUserProfile({
              uid: firebaseUser.uid,
              email: firebaseUser.email,
              displayName: firebaseUser.displayName,
              photoURL: firebaseUser.photoURL,
            }),
            ensureAlertConfig(firebaseUser.uid),
          ]);
          setProfile(prof);
          setAlertConfig(cfg);
          if (!prof.onboardingCompleted) {
            setOnboardingOpen(true);
          }
        } catch (err) {
          console.error(err);
        }
      } else {
        setProfile(null);
        setAlertConfig(null);
        setOnboardingOpen(false);
        setDevices([]);
        setSessions([]);
        setApplications([]);
        setConnections([]);
        setThirdParties([]);
        setPolicies([]);
        setRiskAlerts([]);
        setForensicReports([]);
        setAuditLogs([]);
      }
      setAuthReady(true);
    });
    return () => unsub();
  }, []);

  useEffect(() => {
    if (!authReady || !user) return;
    const uid = user.uid;
    const unsubs = [
      subscribeOwnerCollection<DeviceRecord>('devices', uid, setDevices),
      subscribeOwnerCollection<MonitoringSession>('sessions', uid, setSessions),
      subscribeOwnerCollection<AnalyzedApplication>('applications', uid, setApplications),
      subscribeOwnerCollection<NetworkConnection>('connections', uid, setConnections),
      subscribeOwnerCollection<ThirdPartyService>('thirdParties', uid, setThirdParties),
      subscribeOwnerCollection<PrivacyPolicyAnalysis>('policies', uid, setPolicies),
      subscribeOwnerCollection<RiskAlert>('riskAlerts', uid, setRiskAlerts),
      subscribeOwnerCollection<ForensicReport>('forensicReports', uid, setForensicReports),
      subscribeOwnerCollection<AuditLogEntry>('auditLogs', uid, setAuditLogs),
      subscribeAlertConfig(uid, setAlertConfig),
    ];

    fetch('/api/threat-intel/status')
      .then((r) => r.json())
      .then((d) => {
        if (Array.isArray(d.feeds)) setFeedStatuses(d.feeds);
      })
      .catch(() => {});

    return () => {
      unsubs.forEach((u) => u());
    };
  }, [authReady, user]);

  useEffect(() => {
    if (!user || monitoringPaused) return;
    const ev = new EventSource('/api/monitor/stream');
    ev.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data) as LiveStreamEvent;
        setLiveEvents((prev) => [parsed, ...prev].slice(0, 60));
      } catch {
        // Ignore malformed SSE event
      }
    };
    return () => {
      ev.close();
    };
  }, [user, monitoringPaused]);

  const requireActiveDeviceAndSession = useCallback(
    async (
      preferredDeviceId?: string,
      sessionTitle?: string,
      sourceType: MonitoringSession['sourceType'] = 'live-probe'
    ): Promise<{ device: DeviceRecord; sessionId: string }> => {
      if (!user) throw new Error('Authentication required.');
      const actorEmail = user.email || 'analyst@newtonix.local';
      let targetDevice = devices.find((d) => d.id === preferredDeviceId) || devices[0];
      if (!targetDevice) {
        const devId = await createDeviceRecord(user.uid, actorEmail, {
          name: 'Primary Web Workstation',
          platform: 'web',
          osVersion: navigator.userAgent.slice(0, 56) || 'Browser Endpoint',
          hostname: window.location.hostname || 'browser-client',
          agentMode: 'browser-inspector',
          status: 'active',
          city: 'London',
          country: 'United Kingdom',
          latitude: 51.5074,
          longitude: -0.1278,
        });
        targetDevice = {
          id: devId,
          ownerId: user.uid,
          name: 'Primary Web Workstation',
          platform: 'web',
          osVersion: 'Browser Endpoint',
          hostname: window.location.hostname || 'browser-client',
          agentMode: 'browser-inspector',
          status: 'active',
          city: 'London',
          country: 'United Kingdom',
          latitude: 51.5074,
          longitude: -0.1278,
        };
      }

      const activeSess = sessions.find(
        (s) => s.deviceId === targetDevice.id && s.status === 'active'
      );
      if (activeSess && !sessionTitle) {
        return { device: targetDevice, sessionId: activeSess.id };
      }
      const hash = await computeSha256Hex(`${targetDevice.id}:${Date.now()}`);
      const sessionId = await createSessionRecord(
        user.uid,
        targetDevice.id,
        sessionTitle || `Inspection Session · ${targetDevice.name}`,
        sourceType,
        hash
      );
      return { device: targetDevice, sessionId };
    },
    [user, devices, sessions]
  );

  const value = useMemo<NlaContextValue>(() => {
    const activeCfg = alertConfig ?? {
      id: user?.uid || 'default',
      ownerId: user?.uid || 'default',
      ...DEFAULT_ALERT_CONFIG_VALUES,
    };

    return {
      user,
      profile,
      authReady,
      signingIn,
      authError,
      devices,
      sessions,
      applications,
      connections,
      thirdParties,
      policies,
      riskAlerts,
      forensicReports,
      auditLogs,
      liveEvents,
      monitoringPaused,
      setMonitoringPaused,
      alertConfig,
      feedStatuses,
      refreshingFeeds,
      crossReferencing,
      liveAlertBanners,
      dismissAlertBanner,
      onboardingOpen,
      openOnboarding: () => setOnboardingOpen(true),
      closeOnboarding: () => setOnboardingOpen(false),

      completeOnboarding: async () => {
        if (!user) return;
        await updateUserGovernance(user.uid, { onboardingCompleted: true });
        setProfile((prev) => (prev ? { ...prev, onboardingCompleted: true } : prev));
        setOnboardingOpen(false);
        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'ONBOARDING_COMPLETED',
          'user',
          user.uid,
          'Completed NLA guided privacy onboarding and initial workspace setup.'
        );
      },

      signInWithGoogle: async () => {
        setSigningIn(true);
        setAuthError(null);
        try {
          await signInWithPopup(auth, googleProvider);
        } catch (err) {
          setAuthError(err instanceof Error ? err.message : 'Sign-in failed.');
        } finally {
          setSigningIn(false);
        }
      },

      logout: async () => {
        await signOut(auth);
      },

      acceptConsent: async () => {
        if (!user) return;
        await updateUserGovernance(user.uid, { consentAccepted: true });
        setProfile((prev) => (prev ? { ...prev, consentAccepted: true } : prev));
        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'CONSENT_ACCEPTED',
          'user',
          user.uid,
          'User granted explicit authorization for NLA privacy & network metadata inspection.'
        );
      },

      updateRetention: async (days: number) => {
        if (!user) return;
        await updateUserGovernance(user.uid, { retentionDays: days });
        setProfile((prev) => (prev ? { ...prev, retentionDays: days } : prev));
        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'RETENTION_POLICY_UPDATED',
          'user',
          user.uid,
          `Configured data retention window to ${days} days.`
        );
      },

      updateAlertPreferences: async (updates) => {
        if (!user) return;
        await updateAlertConfig(user.uid, user.email || 'unknown', updates);
      },

      testAlertNotification: () => {
        triggerNotification({
          id: `test-${Date.now()}`,
          title: 'Real-Time Alert Notification Test',
          appName: 'NLA Alert Engine',
          domain: 'telemetry.check',
          severity: 'medium',
          category: 'new-destination',
          timestamp: new Date().toISOString(),
        });
      },

      refreshThreatFeeds: async () => {
        setRefreshingFeeds(true);
        try {
          const res = await fetch('/api/threat-intel/refresh', { method: 'POST' });
          const data = await res.json();
          if (Array.isArray(data.feeds)) {
            setFeedStatuses(data.feeds);
          }
          if (user) {
            await writeAuditLog(
              user.uid,
              user.email || 'unknown',
              'THREAT_FEEDS_REFRESHED',
              'threatFeed',
              'external-feeds',
              'Synchronized live external threat intelligence feeds (URLhaus, Disconnect.me, Peter Lowe).'
            );
          }
        } finally {
          setRefreshingFeeds(false);
        }
      },

      crossReferenceAllThirdParties: async () => {
        if (!user || thirdParties.length === 0) return { checked: 0, flagged: 0 };
        setCrossReferencing(true);
        try {
          const domains = thirdParties.map((tp) => tp.domain);
          const res = await fetch('/api/threat-intel/cross-reference', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domains }),
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Cross-reference failed.');
          if (Array.isArray(data.feeds)) setFeedStatuses(data.feeds);

          const results = (data.results || []) as ExternalFeedMatch[];
          const byDomain = new Map(results.map((r) => [r.domain.toLowerCase(), r]));
          let flaggedCount = 0;

          const activeDevice = devices[0];
          for (const tp of thirdParties) {
            const match = byDomain.get(tp.domain.toLowerCase());
            if (!match) continue;
            await updateThirdPartyThreatIntel(tp.id, match);

            if (
              match.verdict !== 'unlisted' &&
              match.verdict !== 'clean'
            ) {
              flaggedCount += 1;
              if (activeCfg.enableThreatFeedAlert && activeDevice) {
                const alreadyAlerted = riskAlerts.some(
                  (a) =>
                    a.category === 'threat-feed-match' &&
                    a.domain.toLowerCase() === tp.domain.toLowerCase() &&
                    a.status === 'open'
                );
                if (!alreadyAlerted) {
                  await emitRiskAlertAndNotify(user.uid, activeDevice.id, {
                    sessionId: sessions[0]?.id || '',
                    appName: tp.associatedApps[0] || tp.companyName,
                    domain: tp.domain,
                    severity: verdictToSeverity(match.verdict),
                    category: 'threat-feed-match',
                    title: `External feed flagged ${tp.domain} (${match.verdict.replace('-', ' ')})`,
                    explanation: `[External Threat Feed: ${match.feedSource}] ${match.details}`,
                    evidence: `Observed IP ${tp.observedIp} (${tp.country}). External feed attribution: ${match.feedSource} · ${match.categoryLabel}.`,
                    confidence: 'high',
                    recommendedAction:
                      match.verdict === 'malicious'
                        ? 'Isolate the associated application immediately and block this destination at DNS/firewall.'
                        : 'Block tracking domain via DNS/content filtering and verify privacy policy disclosure.',
                    status: 'open',
                    externalFeedSource: match.feedSource,
                  });
                }
              }
            }
          }

          await writeAuditLog(
            user.uid,
            user.email || 'unknown',
            'THREAT_INTEL_CROSS_REFERENCE',
            'thirdParty',
            'batch',
            `Cross-referenced ${thirdParties.length} observed domains against external threat feeds (${flaggedCount} flagged).`
          );

          return { checked: thirdParties.length, flagged: flaggedCount };
        } finally {
          setCrossReferencing(false);
        }
      },

      registerDevice: async (input) => {
        if (!user) throw new Error('Authentication required.');
        return createDeviceRecord(user.uid, user.email || 'unknown', {
          ...input,
          status: 'active',
        });
      },

      toggleDeviceStatus: async (deviceId, status) => {
        if (!user) return;
        await updateDeviceStatus(deviceId, status, user.uid, user.email || 'unknown');
      },

      inspectDomainAndSave: async ({ domain, appName, firstPartyHost, deviceId }) => {
        if (!user) throw new Error('Authentication required.');
        const res = await fetch('/api/network/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain, appName, firstPartyHost }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Live domain probe failed.');

        const knownDomains = new Set(thirdParties.map((t) => t.domain.toLowerCase()));
        const isNewDomain = !knownDomains.has(String(data.domain).toLowerCase());
        const threatIntel = data.threatIntel as ExternalFeedMatch | undefined;

        const { device, sessionId } = await requireActiveDeviceAndSession(deviceId);
        const category = data.classification.category as ServiceCategory;
        const partyType =
          category === 'first-party'
            ? 'first-party'
            : category === 'unclassified' && !firstPartyHost
              ? 'unknown'
              : 'third-party';

        const connPayload: Omit<
          NetworkConnection,
          'id' | 'ownerId' | 'sessionId' | 'deviceId' | 'createdAt'
        > = {
          appName: appName || data.domain,
          observedAt: data.observedAt,
          sourceOrigin: `${device.city}, ${device.country} (${device.name})`,
          sourceLat: device.latitude,
          sourceLng: device.longitude,
          destinationDomain: data.domain,
          destinationIp: data.geo.ip,
          destinationPort: 443,
          protocol: data.tls ? 'HTTPS' : 'DNS',
          city: data.geo.city,
          country: data.geo.country,
          countryCode: data.geo.countryCode,
          latitude: data.geo.latitude,
          longitude: data.geo.longitude,
          asn: data.geo.asn,
          hostingOrg: data.geo.hostingOrg,
          companyName: data.classification.companyName,
          serviceCategory: category,
          partyType,
          bytesTransferred: 2048,
          requestCount: 1,
          isBackground: false,
          confidence: data.classification.confidence,
          evidenceType: 'verified-technical',
          evidenceSummary: `Live DNS (${data.resolvedIps[0] || data.geo.ip}) + TLS (${data.tls?.issuer || 'unverified'}). ${data.classification.reason}`,
          tlsSubject: data.tls?.subject || '',
          dnsRecordType: data.dnsRecords.a.length > 0 ? 'A' : 'AAAA',
        };

        await saveConnectionBatch(user.uid, sessionId, device.id, [connPayload]);
        await upsertThirdPartyService(user.uid, {
          companyName: data.classification.companyName,
          domain: data.domain,
          observedIp: data.geo.ip,
          hostingOrg: data.geo.hostingOrg,
          country: data.geo.country,
          asn: data.geo.asn,
          classification: category,
          associatedApps: [appName || data.domain],
          firstObservedAt: data.observedAt,
          lastObservedAt: data.observedAt,
          evidenceSummary: connPayload.evidenceSummary,
          confidence: data.classification.confidence,
          externalFeedSource: threatIntel?.feedSource,
          externalFeedVerdict: threatIntel?.verdict,
          externalFeedDetails: threatIntel?.details,
          externalFeedCheckedAt: threatIntel?.checkedAt,
        });

        if (
          activeCfg.enableThreatFeedAlert &&
          threatIntel &&
          threatIntel.verdict !== 'unlisted' &&
          threatIntel.verdict !== 'clean'
        ) {
          await emitRiskAlertAndNotify(user.uid, device.id, {
            sessionId,
            appName: appName || data.domain,
            domain: data.domain,
            severity: verdictToSeverity(threatIntel.verdict),
            category: 'threat-feed-match',
            title: `External feed match (${threatIntel.verdict.replace('-', ' ')}): ${data.domain}`,
            explanation: `[External Threat Feed: ${threatIntel.feedSource}] ${threatIntel.details}`,
            evidence: `${connPayload.evidenceSummary} · External Feed: ${threatIntel.feedSource}`,
            confidence: 'high',
            recommendedAction:
              threatIntel.verdict === 'malicious'
                ? 'Block this host immediately and audit any application communicating with it.'
                : 'Review policy disclosure and block tracking endpoint if unconsented.',
            status: 'open',
            externalFeedSource: threatIntel.feedSource,
          });
        } else if (
          activeCfg.enableNewThirdPartyAlert &&
          isNewDomain &&
          partyType !== 'first-party'
        ) {
          await emitRiskAlertAndNotify(user.uid, device.id, {
            sessionId,
            appName: appName || data.domain,
            domain: data.domain,
            severity:
              category === 'advertising' || category === 'attribution' ? 'high' : 'medium',
            category: 'new-destination',
            title: `New external destination observed: ${data.domain}`,
            explanation: `${appName || data.domain} connected to a previously unseen external host ${data.classification.companyName} (${data.domain}) in ${data.geo.city}, ${data.geo.country}.`,
            evidence: connPayload.evidenceSummary,
            confidence: data.classification.confidence,
            recommendedAction:
              'Confirm this third-party endpoint is expected and documented in your privacy policy.',
            status: 'open',
          });
        } else if (category === 'advertising' || category === 'attribution') {
          await emitRiskAlertAndNotify(user.uid, device.id, {
            sessionId,
            appName: appName || data.domain,
            domain: data.domain,
            severity: 'high',
            category: 'unexpected-third-party',
            title: `${category === 'advertising' ? 'Advertising' : 'Attribution'} endpoint observed: ${data.domain}`,
            explanation: `${appName || data.domain} communicated with ${data.classification.companyName} (${data.domain}) hosted in ${data.geo.city}, ${data.geo.country}.`,
            evidence: connPayload.evidenceSummary,
            confidence: data.classification.confidence,
            recommendedAction:
              'Verify whether this third-party transfer is disclosed in the application privacy policy and consider DNS/content blocking.',
            status: 'open',
          });
        }

        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'LIVE_DOMAIN_INSPECTED',
          'connection',
          data.domain,
          `Inspected ${data.domain} (${data.geo.ip} · ${data.geo.city}, ${data.geo.country}).`
        );
      },

      scanWebAppAndSave: async (url, deviceId) => {
        if (!user) throw new Error('Authentication required.');
        const res = await fetch('/api/apps/analyze-web', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Web scan failed.');

        const knownDomains = new Set(thirdParties.map((t) => t.domain.toLowerCase()));
        const { device, sessionId } = await requireActiveDeviceAndSession(
          deviceId,
          `Web Scan · ${data.app.packageId}`,
          'live-probe'
        );

        await saveApplicationRecord(user.uid, device.id, data.app);

        const inspected = (data.inspectedConnections || []) as Array<{
          domain: string;
          observedAt: string;
          resolvedIps: string[];
          tls: { subject: string; issuer: string } | null;
          geo: {
            ip: string;
            city: string;
            country: string;
            countryCode: string;
            latitude: number;
            longitude: number;
            asn: string;
            hostingOrg: string;
          };
          classification: {
            companyName: string;
            category: ServiceCategory;
            confidence: 'high' | 'medium' | 'low';
            reason: string;
          };
          threatIntel?: ExternalFeedMatch;
        }>;

        if (inspected.length > 0) {
          const connBatch = inspected.map((item) => ({
            appName: data.app.name,
            observedAt: item.observedAt,
            sourceOrigin: `${device.city}, ${device.country}`,
            sourceLat: device.latitude,
            sourceLng: device.longitude,
            destinationDomain: item.domain,
            destinationIp: item.geo.ip,
            destinationPort: 443,
            protocol: (item.tls ? 'HTTPS' : 'DNS') as NetworkConnection['protocol'],
            city: item.geo.city,
            country: item.geo.country,
            countryCode: item.geo.countryCode,
            latitude: item.geo.latitude,
            longitude: item.geo.longitude,
            asn: item.geo.asn,
            hostingOrg: item.geo.hostingOrg,
            companyName: item.classification.companyName,
            serviceCategory: item.classification.category,
            partyType: (item.classification.category === 'first-party'
              ? 'first-party'
              : 'third-party') as NetworkConnection['partyType'],
            bytesTransferred: 4096,
            requestCount: 1,
            isBackground: false,
            confidence: item.classification.confidence,
            evidenceType: 'verified-technical' as const,
            evidenceSummary: `Discovered in ${data.app.packageId} HTML markup. ${item.classification.reason}`,
            tlsSubject: item.tls?.subject || '',
            dnsRecordType: 'A',
          }));
          await saveConnectionBatch(user.uid, sessionId, device.id, connBatch);

          const newlySeenDomains: string[] = [];
          let feedAlertsSent = 0;

          for (const item of inspected) {
            await upsertThirdPartyService(user.uid, {
              companyName: item.classification.companyName,
              domain: item.domain,
              observedIp: item.geo.ip,
              hostingOrg: item.geo.hostingOrg,
              country: item.geo.country,
              asn: item.geo.asn,
              classification: item.classification.category,
              associatedApps: [data.app.name],
              firstObservedAt: item.observedAt,
              lastObservedAt: item.observedAt,
              evidenceSummary: item.classification.reason,
              confidence: item.classification.confidence,
              externalFeedSource: item.threatIntel?.feedSource,
              externalFeedVerdict: item.threatIntel?.verdict,
              externalFeedDetails: item.threatIntel?.details,
              externalFeedCheckedAt: item.threatIntel?.checkedAt,
            });

            if (
              item.classification.category !== 'first-party' &&
              !knownDomains.has(item.domain.toLowerCase())
            ) {
              newlySeenDomains.push(item.domain);
            }

            if (
              activeCfg.enableThreatFeedAlert &&
              feedAlertsSent < 3 &&
              item.threatIntel &&
              item.threatIntel.verdict !== 'unlisted' &&
              item.threatIntel.verdict !== 'clean'
            ) {
              feedAlertsSent += 1;
              await emitRiskAlertAndNotify(user.uid, device.id, {
                sessionId,
                appName: data.app.name,
                domain: item.domain,
                severity: verdictToSeverity(item.threatIntel.verdict),
                category: 'threat-feed-match',
                title: `Web scan external feed match: ${item.domain}`,
                explanation: `[External Threat Feed: ${item.threatIntel.feedSource}] ${data.app.packageId} references ${item.domain}. ${item.threatIntel.details}`,
                evidence: `HTML markup reference · IP ${item.geo.ip} · ${item.threatIntel.feedSource}`,
                confidence: 'high',
                recommendedAction:
                  'Audit third-party script inclusions and enforce strict Content-Security-Policy rules.',
                status: 'open',
                externalFeedSource: item.threatIntel.feedSource,
              });
            }
          }

          if (activeCfg.enableNewThirdPartyAlert && newlySeenDomains.length > 0) {
            await emitRiskAlertAndNotify(user.uid, device.id, {
              sessionId,
              appName: data.app.name,
              domain: newlySeenDomains[0],
              severity: newlySeenDomains.length >= 3 ? 'high' : 'medium',
              category: 'new-destination',
              title: `${newlySeenDomains.length} new third-party domain(s) contacted by ${data.app.packageId}`,
              explanation: `Newly observed external domains in initial markup: ${newlySeenDomains.slice(0, 5).join(', ')}.`,
              evidence: `Verified HTML src/href references during live scan of ${data.app.packageId}.`,
              confidence: 'high',
              recommendedAction: 'Review whether each newly discovered third-party domain is necessary and disclosed.',
              status: 'open',
            });
          }
        }

        const sensitiveWebPerms = (data.app.requestedPermissions as string[]).filter((p) =>
          SENSITIVE_PERM_REGEX.test(p)
        );
        if (
          activeCfg.enableSensitivePermissionAlert &&
          sensitiveWebPerms.length >= activeCfg.sensitivePermissionThreshold
        ) {
          await emitRiskAlertAndNotify(user.uid, device.id, {
            sessionId,
            appName: data.app.name,
            domain: data.app.packageId,
            severity: 'high',
            category: 'excessive-permissions',
            title: `Sensitive browser capabilities requested on ${data.app.packageId}`,
            explanation: `Detected ${sensitiveWebPerms.length} sensitive capability/cookie signals (threshold: ${activeCfg.sensitivePermissionThreshold}): ${sensitiveWebPerms.join(', ')}.`,
            evidence: 'HTTP Permissions-Policy / client capability script signatures.',
            confidence: 'high',
            recommendedAction: 'Deny unnecessary browser sensor permissions and clear third-party cookies.',
            status: 'open',
          });
        }

        if (data.app.privacyScore < 70 || !data.app.policyUrl) {
          await emitRiskAlertAndNotify(user.uid, device.id, {
            sessionId,
            appName: data.app.name,
            domain: data.app.packageId,
            severity: data.app.privacyScore < 55 ? 'high' : 'medium',
            category: !data.app.policyUrl ? 'disclosure-mismatch' : 'unexpected-third-party',
            title: `Web privacy risk on ${data.app.packageId} (Score ${data.app.privacyScore}/100)`,
            explanation: `${data.app.externalDomains.length} external domains and ${data.app.detectedSdks.length} SDK signatures were identified in initial markup.`,
            evidence: data.app.sharingPractices,
            confidence: 'high',
            recommendedAction:
              'Review external script origins and inspect the site privacy policy in the Privacy Agreement Analyzer.',
            status: 'open',
          });
        }

        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'WEB_APP_SCANNED',
          'application',
          data.app.packageId,
          `Scanned web app ${data.app.packageId} (score ${data.app.privacyScore}/100, ${inspected.length} endpoints).`
        );
      },

      scanManifestAndSave: async (params) => {
        if (!user) throw new Error('Authentication required.');
        const res = await fetch('/api/apps/analyze-manifest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(params),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Manifest analysis failed.');

        const { device, sessionId } = await requireActiveDeviceAndSession(params.deviceId);
        await saveApplicationRecord(user.uid, device.id, data.app);

        const reqPerms = (data.app.requestedPermissions || []) as string[];
        const sensitiveCount = reqPerms.filter((p) => SENSITIVE_PERM_REGEX.test(p)).length;

        if (
          activeCfg.enableSensitivePermissionAlert &&
          (sensitiveCount >= activeCfg.sensitivePermissionThreshold ||
            data.app.permissionsPenalty >= 20)
        ) {
          await emitRiskAlertAndNotify(user.uid, device.id, {
            sessionId,
            appName: data.app.name,
            domain: data.app.packageId,
            severity: sensitiveCount >= activeCfg.sensitivePermissionThreshold + 2 ? 'critical' : 'high',
            category: 'excessive-permissions',
            title: `Sensitive permission threshold exceeded in ${data.app.name} (${sensitiveCount} sensitive)`,
            explanation: `${reqPerms.length} total permissions declared (${sensitiveCount} sensitive vs. configured threshold of ${activeCfg.sensitivePermissionThreshold}): ${reqPerms.slice(0, 5).join(', ')}. Note: requesting a permission does not prove active sensor access.`,
            evidence: `Permissions penalty: -${data.app.permissionsPenalty}/40 pts.`,
            confidence: 'high',
            recommendedAction: 'Grant sensitive permissions only while using the app or revoke unused OS permissions.',
            status: 'open',
          });
        }

        const inspected = (data.inspectedConnections || []) as Array<{
          domain: string;
          observedAt: string;
          geo: { ip: string; city: string; country: string; countryCode: string; latitude: number; longitude: number; asn: string; hostingOrg: string };
          classification: { companyName: string; category: ServiceCategory; confidence: 'high' | 'medium' | 'low'; reason: string };
          threatIntel?: ExternalFeedMatch;
        }>;
        for (const item of inspected) {
          await upsertThirdPartyService(user.uid, {
            companyName: item.classification.companyName,
            domain: item.domain,
            observedIp: item.geo.ip,
            hostingOrg: item.geo.hostingOrg,
            country: item.geo.country,
            asn: item.geo.asn,
            classification: item.classification.category,
            associatedApps: [data.app.name],
            firstObservedAt: item.observedAt,
            lastObservedAt: item.observedAt,
            evidenceSummary: item.classification.reason,
            confidence: item.classification.confidence,
            externalFeedSource: item.threatIntel?.feedSource,
            externalFeedVerdict: item.threatIntel?.verdict,
            externalFeedDetails: item.threatIntel?.details,
            externalFeedCheckedAt: item.threatIntel?.checkedAt,
          });
          if (
            activeCfg.enableThreatFeedAlert &&
            item.threatIntel &&
            item.threatIntel.verdict !== 'unlisted' &&
            item.threatIntel.verdict !== 'clean'
          ) {
            await emitRiskAlertAndNotify(user.uid, device.id, {
              sessionId,
              appName: data.app.name,
              domain: item.domain,
              severity: verdictToSeverity(item.threatIntel.verdict),
              category: 'threat-feed-match',
              title: `Manifest domain flagged by external feed: ${item.domain}`,
              explanation: `[External Threat Feed: ${item.threatIntel.feedSource}] ${item.threatIntel.details}`,
              evidence: `Declared URL in ${data.app.packageId} manifest · ${item.threatIntel.feedSource}`,
              confidence: 'high',
              recommendedAction: 'Inspect SDK integrations referencing this domain before trusting the build.',
              status: 'open',
              externalFeedSource: item.threatIntel.feedSource,
            });
          }
        }

        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'MANIFEST_ANALYZED',
          'application',
          data.app.packageId,
          `Analyzed ${params.platform} manifest for ${params.name}.`
        );
      },

      importCaptureAndSave: async (params) => {
        if (!user) throw new Error('Authentication required.');
        const res = await fetch('/api/captures/parse', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(params),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Capture import failed.');

        const observations = data.observations as Array<
          Omit<
            NetworkConnection,
            | 'id'
            | 'ownerId'
            | 'sessionId'
            | 'deviceId'
            | 'createdAt'
            | 'sourceOrigin'
            | 'sourceLat'
            | 'sourceLng'
            | 'evidenceType'
            | 'tlsSubject'
            | 'dnsRecordType'
          > & { threatIntel?: ExternalFeedMatch }
        >;

        const knownDomains = new Set(thirdParties.map((t) => t.domain.toLowerCase()));

        const sourceMap: Record<typeof params.format, MonitoringSession['sourceType']> = {
          har: 'har-import',
          'ios-ndjson': 'ios-privacy-report',
          'nla-json': 'endpoint-agent',
          csv: 'android-vpn-log',
        };

        const { device, sessionId } = await requireActiveDeviceAndSession(
          params.deviceId,
          params.sessionTitle || `${params.format.toUpperCase()} Import · ${params.defaultAppName}`,
          sourceMap[params.format]
        );

        const batchPayload = observations.map(({ threatIntel: _ti, ...o }) => ({
          ...o,
          sourceOrigin: `${device.city}, ${device.country} (${device.name})`,
          sourceLat: device.latitude,
          sourceLng: device.longitude,
          evidenceType: 'verified-technical' as const,
          tlsSubject: '',
          dnsRecordType: o.protocol === 'DNS' ? 'A' : 'HTTPS',
        }));

        if (batchPayload.length > 0) {
          await saveConnectionBatch(user.uid, sessionId, device.id, batchPayload);
          const totalBytes = batchPayload.reduce((sum, x) => sum + x.bytesTransferred, 0);
          await updateSessionStats(
            sessionId,
            'completed',
            batchPayload.length,
            totalBytes,
            data.integritySha256
          );

          const newlySeenDomains: string[] = [];
          let feedAlertCount = 0;

          for (const obs of observations.slice(0, 15)) {
            await upsertThirdPartyService(user.uid, {
              companyName: obs.companyName,
              domain: obs.destinationDomain,
              observedIp: obs.destinationIp,
              hostingOrg: obs.hostingOrg,
              country: obs.country,
              asn: obs.asn,
              classification: obs.serviceCategory,
              associatedApps: [obs.appName],
              firstObservedAt: obs.observedAt,
              lastObservedAt: obs.observedAt,
              evidenceSummary: obs.evidenceSummary,
              confidence: obs.confidence,
              externalFeedSource: obs.threatIntel?.feedSource,
              externalFeedVerdict: obs.threatIntel?.verdict,
              externalFeedDetails: obs.threatIntel?.details,
              externalFeedCheckedAt: obs.threatIntel?.checkedAt,
            });

            if (
              obs.partyType !== 'first-party' &&
              !knownDomains.has(obs.destinationDomain.toLowerCase())
            ) {
              newlySeenDomains.push(obs.destinationDomain);
            }

            if (
              activeCfg.enableThreatFeedAlert &&
              feedAlertCount < 4 &&
              obs.threatIntel &&
              obs.threatIntel.verdict !== 'unlisted' &&
              obs.threatIntel.verdict !== 'clean'
            ) {
              feedAlertCount += 1;
              await emitRiskAlertAndNotify(user.uid, device.id, {
                sessionId,
                appName: obs.appName,
                domain: obs.destinationDomain,
                severity: verdictToSeverity(obs.threatIntel.verdict),
                category: 'threat-feed-match',
                title: `Capture destination flagged by external feed: ${obs.destinationDomain}`,
                explanation: `[External Threat Feed: ${obs.threatIntel.feedSource}] ${obs.threatIntel.details}`,
                evidence: `${obs.evidenceSummary} · External Feed: ${obs.threatIntel.feedSource}`,
                confidence: 'high',
                recommendedAction:
                  obs.threatIntel.verdict === 'malicious'
                    ? 'Block destination at DNS/firewall and inspect the originating application.'
                    : 'Verify disclosure in privacy policy or block tracker host.',
                status: 'open',
                externalFeedSource: obs.threatIntel.feedSource,
              });
            }
          }

          if (activeCfg.enableNewThirdPartyAlert && newlySeenDomains.length > 0) {
            await emitRiskAlertAndNotify(user.uid, device.id, {
              sessionId,
              appName: params.defaultAppName,
              domain: newlySeenDomains[0],
              severity: newlySeenDomains.length >= 4 ? 'high' : 'medium',
              category: 'new-destination',
              title: `${newlySeenDomains.length} new third-party destination(s) in ${params.format.toUpperCase()} capture`,
              explanation: `New external hosts discovered: ${newlySeenDomains.slice(0, 6).join(', ')}.`,
              evidence: `Parsed capture SHA-256 ${String(data.integritySha256).slice(0, 16)}...`,
              confidence: 'high',
              recommendedAction: 'Audit new third-party endpoints in Third-Party Tracker Intelligence.',
              status: 'open',
            });
          }

          // Data Spike Detection
          const spikeThresholdBytes = activeCfg.dataSpikeThresholdKb * 1024;
          const spikedObs = batchPayload.reduce(
            (max, cur) => (cur.bytesTransferred > max.bytesTransferred ? cur : max),
            batchPayload[0]
          );
          if (
            activeCfg.enableDataSpikeAlert &&
            (spikedObs.bytesTransferred >= spikeThresholdBytes ||
              totalBytes >= spikeThresholdBytes * 2)
          ) {
            const kbObserved = Math.round(
              Math.max(spikedObs.bytesTransferred, totalBytes) / 1024
            );
            await emitRiskAlertAndNotify(user.uid, device.id, {
              sessionId,
              appName: spikedObs.appName,
              domain: spikedObs.destinationDomain,
              severity: 'high',
              category: 'data-spike',
              title: `Data transmission spike detected (${kbObserved.toLocaleString()} KB)`,
              explanation: `Observed transfer volume exceeded configured spike threshold of ${activeCfg.dataSpikeThresholdKb.toLocaleString()} KB. Largest destination: ${spikedObs.destinationDomain} (${Math.round(spikedObs.bytesTransferred / 1024)} KB).`,
              evidence: `${batchPayload.length} routes totaling ${Math.round(totalBytes / 1024)} KB in ${params.format.toUpperCase()} capture.`,
              confidence: 'high',
              recommendedAction:
                'Verify whether bulk media upload or telemetry exfiltration was expected.',
              status: 'open',
            });
          }

          const bgTrackers = batchPayload.filter(
            (o) =>
              o.isBackground &&
              (o.serviceCategory === 'advertising' || o.serviceCategory === 'attribution')
          );
          if (bgTrackers.length > 0) {
            await emitRiskAlertAndNotify(user.uid, device.id, {
              sessionId,
              appName: bgTrackers[0].appName,
              domain: bgTrackers[0].destinationDomain,
              severity: 'high',
              category: 'background-beacon',
              title: `Background advertising/attribution traffic detected (${bgTrackers.length} routes)`,
              explanation: `Imported capture recorded background activity to ${bgTrackers[0].companyName} (${bgTrackers[0].destinationDomain}).`,
              evidence: bgTrackers[0].evidenceSummary,
              confidence: bgTrackers[0].confidence,
              recommendedAction:
                'Restrict background network data for this application or block the attribution domain.',
              status: 'open',
            });
          }
        }

        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'CAPTURE_IMPORTED',
          'session',
          sessionId,
          `Imported ${observations.length} unique routes from ${params.format} capture (SHA-256 ${String(data.integritySha256).slice(0, 12)}...).`
        );

        return observations.length;
      },

      analyzePolicyAndSave: async (params) => {
        if (!user) throw new Error('Authentication required.');
        const res = await fetch('/api/policies/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(params),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Policy analysis failed.');

        const id = await savePolicyAnalysis(user.uid, {
          appName: params.appName,
          policyUrl: params.policyUrl || '',
          versionLabel: params.versionLabel || 'Current',
          sourceType: data.sourceType,
          ...data.analysis,
        });

        if (activeCfg.enablePolicyViolationAlert) {
          const soldText = String(data.analysis.soldOrShared || '').toLowerCase();
          const riskyText = String(data.analysis.unclearOrRiskyClauses || '').toLowerCase();
          const retentionText = String(data.analysis.retentionPeriod || '').toLowerCase();
          const deletionText = String(data.analysis.deletionRights || '').toLowerCase();

          const indicatesSelling =
            /(sell|sold|monetiz|data broker|targeted advertising|cross-context behavioral|share.*advertis)/.test(
              soldText
            ) && !/do not sell|does not sell|never sell/.test(soldText);
          const indicatesIndefiniteRetention =
            /(indefinite|as long as necessary|unspecified|not specified|no specific period)/.test(
              retentionText
            );
          const indicatesWeakDeletion =
            /(no deletion|cannot delete|not specified|unclear)/.test(deletionText);
          const indicatesRiskyClause =
            riskyText.length > 40 && !/none|no major|standard/.test(riskyText);

          if (
            indicatesSelling ||
            indicatesIndefiniteRetention ||
            indicatesWeakDeletion ||
            indicatesRiskyClause
          ) {
            const { device, sessionId } = await requireActiveDeviceAndSession();
            const reasons: string[] = [];
            if (indicatesSelling) reasons.push('third-party data sharing/advertising clauses');
            if (indicatesIndefiniteRetention) reasons.push('vague or indefinite retention window');
            if (indicatesWeakDeletion) reasons.push('limited or unspecified deletion rights');
            if (indicatesRiskyClause) reasons.push('broad/unclear consent or liability clauses');

            let policyDomain = '';
            if (params.policyUrl) {
              try {
                policyDomain = new URL(params.policyUrl).hostname;
              } catch {
                policyDomain = '';
              }
            }

            await emitRiskAlertAndNotify(user.uid, device.id, {
              sessionId,
              appName: params.appName,
              domain: policyDomain,
              severity: indicatesSelling ? 'high' : 'medium',
              category: 'policy-violation',
              title: `Privacy policy risk flagged for ${params.appName}`,
              explanation: `Policy analysis identified ${reasons.join(', ')}. ${String(data.analysis.unclearOrRiskyClauses || '').slice(0, 320)}`,
              evidence: `Declared Policy (${params.versionLabel || 'Current'}): ${String(data.analysis.soldOrShared || '').slice(0, 260)}`,
              confidence: 'medium',
              recommendedAction:
                'Opt out of third-party data sharing, review consent withdrawal impact, or restrict application permissions.',
              status: 'open',
            });
          }
        }

        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'POLICY_ANALYZED',
          'policy',
          id,
          `Analyzed privacy agreement for "${params.appName}" (${data.sourceType}).`
        );

        return id;
      },

      setAlertStatus: async (alertId, status) => {
        if (!user) return;
        await updateRiskAlertStatus(alertId, status, user.uid, user.email || 'unknown');
      },

      exportSessionReport: async (sessionId, format) => {
        if (!user) throw new Error('Authentication required.');
        const session = sessions.find((s) => s.id === sessionId);
        if (!session) throw new Error('Monitoring session not found.');
        const device = devices.find((d) => d.id === session.deviceId) || null;
        const sessionConns = connections.filter((c) => c.sessionId === sessionId);
        const sessionAlerts = riskAlerts.filter((a) => a.sessionId === sessionId);

        const { sha256, recordCount, filename } = await generateAndDownloadForensicExport(
          {
            generatedAt: new Date().toISOString(),
            platform: 'NLA — Network & Location Awareness',
            developer: 'Newtonix Tech House',
            session,
            device,
            applications,
            connections: sessionConns,
            thirdParties,
            policies,
            riskAlerts: sessionAlerts,
          },
          format
        );

        await saveForensicReportRecord(user.uid, {
          sessionId: session.id,
          deviceId: session.deviceId,
          title: `${session.title} (${format.toUpperCase()})`,
          format,
          integritySha256: sha256,
          recordCount,
          summary: `Exported ${sessionConns.length} connections, ${sessionAlerts.length} risk findings, and ${applications.length} app records.`,
        });

        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'FORENSIC_REPORT_EXPORTED',
          'forensicReport',
          session.id,
          `Exported ${format.toUpperCase()} report (${filename}) with SHA-256 ${sha256.slice(0, 16)}...`
        );

        return filename;
      },

      deleteRecord: async (collectionName, docId) => {
        if (!user) return;
        await deleteOwnedDocument(collectionName, docId);
        await writeAuditLog(
          user.uid,
          user.email || 'unknown',
          'RECORD_DELETED',
          collectionName,
          docId,
          `Securely deleted record ${docId} from ${collectionName}.`
        );
      },
    };
  }, [
    user,
    profile,
    authReady,
    signingIn,
    authError,
    devices,
    sessions,
    applications,
    connections,
    thirdParties,
    policies,
    riskAlerts,
    forensicReports,
    auditLogs,
    liveEvents,
    monitoringPaused,
    alertConfig,
    feedStatuses,
    refreshingFeeds,
    crossReferencing,
    liveAlertBanners,
    dismissAlertBanner,
    onboardingOpen,
    triggerNotification,
    emitRiskAlertAndNotify,
    requireActiveDeviceAndSession,
  ]);

  return <NlaContext.Provider value={value}>{children}</NlaContext.Provider>;
}

export function useNla() {
  const ctx = useContext(NlaContext);
  if (!ctx) throw new Error('useNla must be used inside NlaProvider');
  return ctx;
}
