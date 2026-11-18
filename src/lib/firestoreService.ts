import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
  writeBatch,
  type Unsubscribe,
} from 'firebase/firestore';
import type {
  AlertConfig,
  AlertStatus,
  AnalyzedApplication,
  AuditLogEntry,
  DeviceRecord,
  DeviceStatus,
  ExternalFeedMatch,
  ForensicReport,
  MonitoringSession,
  NetworkConnection,
  PrivacyPolicyAnalysis,
  RiskAlert,
  SessionStatus,
  ThirdPartyService,
  UserProfile,
} from '../types/nla';
import { db, handleFirestoreError, OperationType } from './firebase';

const ID_REGEX = /^[a-zA-Z0-9_-]+$/;

export function makeSafeId(prefix: string): string {
  const raw = `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 120);
  return ID_REGEX.test(cleaned) ? cleaned : `${prefix}-${Date.now()}`;
}

function clampStr(val: string | undefined | null, maxLen: number, fallback = ''): string {
  const s = (val ?? fallback).toString();
  return s.slice(0, maxLen);
}

function clampNum(val: number, min: number, max: number): number {
  if (Number.isNaN(val)) return min;
  return Math.max(min, Math.min(max, val));
}

export async function ensureUserProfile(user: {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
}): Promise<UserProfile> {
  const path = `users/${user.uid}`;
  const ref = doc(db, 'users', user.uid);
  try {
    const snap = await getDoc(ref);
    if (snap.exists()) {
      return snap.data() as UserProfile;
    }
    const profilePayload = {
      uid: user.uid,
      email: clampStr(user.email, 256, 'analyst@newtonix.local'),
      displayName: clampStr(user.displayName, 120, 'NLA Privacy Analyst'),
      photoURL: clampStr(user.photoURL, 512, ''),
      role: 'analyst' as const,
      retentionDays: 90,
      consentAccepted: false,
      onboardingCompleted: false,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    await setDoc(ref, profilePayload);
    return {
      ...profilePayload,
      role: user.email === 'blessednewton44@gmail.com' ? 'admin' : 'analyst',
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function updateUserGovernance(
  uid: string,
  updates: {
    retentionDays?: number;
    consentAccepted?: boolean;
    displayName?: string;
    onboardingCompleted?: boolean;
  }
): Promise<void> {
  const path = `users/${uid}`;
  try {
    const payload: Record<string, unknown> = {
      updatedAt: serverTimestamp(),
    };
    if (typeof updates.retentionDays === 'number') {
      payload.retentionDays = Math.round(clampNum(updates.retentionDays, 7, 365));
    }
    if (typeof updates.consentAccepted === 'boolean') {
      payload.consentAccepted = updates.consentAccepted;
      payload.consentUpdatedAt = serverTimestamp();
    }
    if (typeof updates.displayName === 'string' && updates.displayName.trim()) {
      payload.displayName = clampStr(updates.displayName.trim(), 120);
    }
    if (typeof updates.onboardingCompleted === 'boolean') {
      payload.onboardingCompleted = updates.onboardingCompleted;
    }
    await updateDoc(doc(db, 'users', uid), payload);
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function writeAuditLog(
  ownerId: string,
  actorEmail: string,
  action: string,
  targetType: string,
  targetId: string,
  details: string
): Promise<void> {
  const id = makeSafeId('audit');
  const path = `auditLogs/${id}`;
  try {
    await setDoc(doc(db, 'auditLogs', id), {
      id,
      ownerId,
      actorEmail: clampStr(actorEmail, 256, 'unknown'),
      action: clampStr(action, 120),
      targetType: clampStr(targetType, 64),
      targetId: clampStr(targetId, 128),
      details: clampStr(details, 600),
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function createDeviceRecord(
  ownerId: string,
  actorEmail: string,
  input: Omit<DeviceRecord, 'id' | 'ownerId' | 'createdAt' | 'updatedAt'>
): Promise<string> {
  const id = makeSafeId('dev');
  const path = `devices/${id}`;
  try {
    await setDoc(doc(db, 'devices', id), {
      id,
      ownerId,
      name: clampStr(input.name, 120, 'Authorized Endpoint'),
      platform: input.platform,
      osVersion: clampStr(input.osVersion, 64, 'Unknown OS'),
      hostname: clampStr(input.hostname, 128, 'nla-host'),
      agentMode: input.agentMode,
      status: input.status,
      city: clampStr(input.city, 80, 'London'),
      country: clampStr(input.country, 80, 'United Kingdom'),
      latitude: clampNum(input.latitude, -90, 90),
      longitude: clampNum(input.longitude, -180, 180),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    await writeAuditLog(
      ownerId,
      actorEmail,
      'REGISTER_DEVICE',
      'device',
      id,
      `Registered ${input.platform} endpoint "${input.name}" in ${input.agentMode} mode.`
    );
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function updateDeviceStatus(
  deviceId: string,
  status: DeviceStatus,
  ownerId: string,
  actorEmail: string
): Promise<void> {
  const path = `devices/${deviceId}`;
  try {
    await updateDoc(doc(db, 'devices', deviceId), {
      status,
      updatedAt: serverTimestamp(),
    });
    await writeAuditLog(
      ownerId,
      actorEmail,
      `DEVICE_MONITOR_${status.toUpperCase()}`,
      'device',
      deviceId,
      `Monitoring state changed to ${status}.`
    );
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function createSessionRecord(
  ownerId: string,
  deviceId: string,
  title: string,
  sourceType: MonitoringSession['sourceType'],
  integrityHash: string
): Promise<string> {
  const id = makeSafeId('sess');
  const path = `sessions/${id}`;
  try {
    await setDoc(doc(db, 'sessions', id), {
      id,
      ownerId,
      deviceId,
      title: clampStr(title, 160, 'Privacy Inspection Session'),
      status: 'active',
      sourceType,
      observationCount: 0,
      bytesObserved: 0,
      integrityHash: clampStr(integrityHash, 128, 'pending-sha256'),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function updateSessionStats(
  sessionId: string,
  status: SessionStatus,
  observationCount: number,
  bytesObserved: number,
  integrityHash: string
): Promise<void> {
  const path = `sessions/${sessionId}`;
  try {
    await updateDoc(doc(db, 'sessions', sessionId), {
      status,
      observationCount: Math.max(0, Math.round(observationCount)),
      bytesObserved: Math.max(0, Math.round(bytesObserved)),
      integrityHash: clampStr(integrityHash, 128),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function saveApplicationRecord(
  ownerId: string,
  deviceId: string,
  app: Omit<AnalyzedApplication, 'id' | 'ownerId' | 'deviceId' | 'createdAt' | 'updatedAt'>
): Promise<string> {
  const id = makeSafeId('app');
  const path = `applications/${id}`;
  try {
    await setDoc(doc(db, 'applications', id), {
      id,
      ownerId,
      deviceId,
      name: clampStr(app.name, 140, 'Application'),
      packageId: clampStr(app.packageId, 160, 'unknown.package'),
      developer: clampStr(app.developer, 140, 'Unknown Publisher'),
      version: clampStr(app.version, 48, '1.0'),
      platform: app.platform,
      privacyScore: Math.round(clampNum(app.privacyScore, 0, 100)),
      permissionsPenalty: Math.round(clampNum(app.permissionsPenalty, 0, 40)),
      thirdPartyPenalty: Math.round(clampNum(app.thirdPartyPenalty, 0, 30)),
      backgroundPenalty: Math.round(clampNum(app.backgroundPenalty, 0, 15)),
      disclosurePenalty: Math.round(clampNum(app.disclosurePenalty, 0, 15)),
      requestedPermissions: app.requestedPermissions.slice(0, 32).map((s) => clampStr(s, 120)),
      grantedPermissions: app.grantedPermissions.slice(0, 32).map((s) => clampStr(s, 120)),
      detectedSdks: app.detectedSdks.slice(0, 32).map((s) => clampStr(s, 120)),
      externalDomains: app.externalDomains.slice(0, 64).map((s) => clampStr(s, 253)),
      advertisingIdAccess: app.advertisingIdAccess,
      policyUrl: clampStr(app.policyUrl, 512),
      retentionDisclosure: clampStr(app.retentionDisclosure, 500),
      sharingPractices: clampStr(app.sharingPractices, 600),
      evidenceType: app.evidenceType,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function saveConnectionBatch(
  ownerId: string,
  sessionId: string,
  deviceId: string,
  items: Array<Omit<NetworkConnection, 'id' | 'ownerId' | 'sessionId' | 'deviceId' | 'createdAt'>>
): Promise<string[]> {
  const ids: string[] = [];
  const batch = writeBatch(db);
  for (const item of items.slice(0, 25)) {
    const id = makeSafeId('conn');
    ids.push(id);
    batch.set(doc(db, 'connections', id), {
      id,
      ownerId,
      sessionId,
      deviceId,
      appName: clampStr(item.appName, 140, 'Observed App'),
      observedAt: clampStr(item.observedAt, 64, new Date().toISOString()),
      sourceOrigin: clampStr(item.sourceOrigin, 120, 'Monitored Device'),
      sourceLat: clampNum(item.sourceLat, -90, 90),
      sourceLng: clampNum(item.sourceLng, -180, 180),
      destinationDomain: clampStr(item.destinationDomain, 253, 'unknown'),
      destinationIp: clampStr(item.destinationIp, 64, 'unresolved'),
      destinationPort: Math.round(clampNum(item.destinationPort, 0, 65535)),
      protocol: item.protocol,
      city: clampStr(item.city, 80, 'Unknown'),
      country: clampStr(item.country, 80, 'Unknown'),
      countryCode: clampStr(item.countryCode, 8, 'UN'),
      latitude: clampNum(item.latitude, -90, 90),
      longitude: clampNum(item.longitude, -180, 180),
      asn: clampStr(item.asn, 32, 'Unknown'),
      hostingOrg: clampStr(item.hostingOrg, 140, 'Unknown'),
      companyName: clampStr(item.companyName, 140, item.destinationDomain),
      serviceCategory: item.serviceCategory,
      partyType: item.partyType,
      bytesTransferred: Math.max(0, Math.round(item.bytesTransferred)),
      requestCount: Math.max(1, Math.round(item.requestCount)),
      isBackground: Boolean(item.isBackground),
      confidence: item.confidence,
      evidenceType: item.evidenceType,
      evidenceSummary: clampStr(item.evidenceSummary, 500, 'Network observation'),
      tlsSubject: clampStr(item.tlsSubject, 200, ''),
      dnsRecordType: clampStr(item.dnsRecordType, 24, 'A'),
      createdAt: serverTimestamp(),
    });
  }
  try {
    await batch.commit();
    return ids;
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, 'connections');
  }
}

export async function upsertThirdPartyService(
  ownerId: string,
  input: Omit<ThirdPartyService, 'id' | 'ownerId' | 'createdAt' | 'updatedAt'>
): Promise<string> {
  const safeDom = input.domain.toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 60);
  const id = `tp-${ownerId.slice(0, 10)}-${safeDom}`;
  const path = `thirdParties/${id}`;
  try {
    const ref = doc(db, 'thirdParties', id);
    const snap = await getDoc(ref);
    if (snap.exists()) {
      const existing = snap.data() as ThirdPartyService;
      const mergedApps = Array.from(
        new Set([...existing.associatedApps, ...input.associatedApps])
      ).slice(0, 32);
      const updatePayload: Record<string, unknown> = {
        observedIp: clampStr(input.observedIp, 64),
        hostingOrg: clampStr(input.hostingOrg, 140),
        country: clampStr(input.country, 80),
        asn: clampStr(input.asn, 32),
        classification: input.classification,
        associatedApps: mergedApps,
        lastObservedAt: clampStr(input.lastObservedAt, 64),
        evidenceSummary: clampStr(input.evidenceSummary, 500),
        confidence: input.confidence,
        updatedAt: serverTimestamp(),
      };
      if (input.externalFeedVerdict) {
        updatePayload.externalFeedSource = clampStr(input.externalFeedSource, 140);
        updatePayload.externalFeedVerdict = input.externalFeedVerdict;
        updatePayload.externalFeedDetails = clampStr(input.externalFeedDetails, 500);
        updatePayload.externalFeedCheckedAt = clampStr(input.externalFeedCheckedAt, 64);
      }
      await updateDoc(ref, updatePayload);
    } else {
      const createPayload: Record<string, unknown> = {
        id,
        ownerId,
        companyName: clampStr(input.companyName, 140),
        domain: clampStr(input.domain, 253),
        observedIp: clampStr(input.observedIp, 64),
        hostingOrg: clampStr(input.hostingOrg, 140),
        country: clampStr(input.country, 80),
        asn: clampStr(input.asn, 32),
        classification: input.classification,
        associatedApps: input.associatedApps.slice(0, 32).map((a) => clampStr(a, 120)),
        firstObservedAt: clampStr(input.firstObservedAt, 64),
        lastObservedAt: clampStr(input.lastObservedAt, 64),
        evidenceSummary: clampStr(input.evidenceSummary, 500),
        confidence: input.confidence,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      };
      if (input.externalFeedVerdict) {
        createPayload.externalFeedSource = clampStr(input.externalFeedSource, 140);
        createPayload.externalFeedVerdict = input.externalFeedVerdict;
        createPayload.externalFeedDetails = clampStr(input.externalFeedDetails, 500);
        createPayload.externalFeedCheckedAt = clampStr(input.externalFeedCheckedAt, 64);
      }
      await setDoc(ref, createPayload);
    }
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function updateThirdPartyThreatIntel(
  serviceId: string,
  match: ExternalFeedMatch
): Promise<void> {
  const path = `thirdParties/${serviceId}`;
  try {
    await updateDoc(doc(db, 'thirdParties', serviceId), {
      externalFeedSource: clampStr(match.feedSource, 140),
      externalFeedVerdict: match.verdict,
      externalFeedDetails: clampStr(match.details, 500),
      externalFeedCheckedAt: clampStr(match.checkedAt, 64),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function savePolicyAnalysis(
  ownerId: string,
  input: Omit<PrivacyPolicyAnalysis, 'id' | 'ownerId' | 'createdAt' | 'updatedAt'>
): Promise<string> {
  const id = makeSafeId('pol');
  const path = `policies/${id}`;
  try {
    await setDoc(doc(db, 'policies', id), {
      id,
      ownerId,
      appName: clampStr(input.appName, 140),
      policyUrl: clampStr(input.policyUrl, 512),
      versionLabel: clampStr(input.versionLabel, 64, 'Current'),
      sourceType: input.sourceType,
      summary: clampStr(input.summary, 2000),
      collectedInfo: clampStr(input.collectedInfo, 1500),
      purposeOfCollection: clampStr(input.purposeOfCollection, 1500),
      recipients: clampStr(input.recipients, 1500),
      soldOrShared: clampStr(input.soldOrShared, 1500),
      retentionPeriod: clampStr(input.retentionPeriod, 1000),
      userChoices: clampStr(input.userChoices, 1500),
      withdrawalImpact: clampStr(input.withdrawalImpact, 1000),
      unclearOrRiskyClauses: clampStr(input.unclearOrRiskyClauses, 2000),
      internationalTransfers: clampStr(input.internationalTransfers, 1000),
      deletionRights: clampStr(input.deletionRights, 1000),
      clauses: input.clauses.slice(0, 30).map((c) => clampStr(c, 500)),
      comparisonSummary: clampStr(input.comparisonSummary, 2000),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function createRiskAlert(
  ownerId: string,
  deviceId: string,
  input: Omit<RiskAlert, 'id' | 'ownerId' | 'deviceId' | 'createdAt' | 'updatedAt'>
): Promise<string> {
  const id = makeSafeId('risk');
  const path = `riskAlerts/${id}`;
  try {
    const payload: Record<string, unknown> = {
      id,
      ownerId,
      deviceId,
      sessionId: clampStr(input.sessionId, 128),
      appName: clampStr(input.appName, 140),
      domain: clampStr(input.domain, 253),
      severity: input.severity,
      category: input.category,
      title: clampStr(input.title, 180),
      explanation: clampStr(input.explanation, 1200),
      evidence: clampStr(input.evidence, 800),
      confidence: input.confidence,
      recommendedAction: clampStr(input.recommendedAction, 600),
      status: input.status,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    if (input.externalFeedSource) {
      payload.externalFeedSource = clampStr(input.externalFeedSource, 140);
    }
    await setDoc(doc(db, 'riskAlerts', id), payload);
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function updateRiskAlertStatus(
  alertId: string,
  status: AlertStatus,
  ownerId: string,
  actorEmail: string
): Promise<void> {
  const path = `riskAlerts/${alertId}`;
  try {
    await updateDoc(doc(db, 'riskAlerts', alertId), {
      status,
      updatedAt: serverTimestamp(),
    });
    await writeAuditLog(
      ownerId,
      actorEmail,
      `ALERT_${status.toUpperCase()}`,
      'riskAlert',
      alertId,
      `Updated risk alert status to ${status}.`
    );
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function saveForensicReportRecord(
  ownerId: string,
  input: Omit<ForensicReport, 'id' | 'ownerId' | 'createdAt'>
): Promise<string> {
  const id = makeSafeId('rep');
  const path = `forensicReports/${id}`;
  try {
    await setDoc(doc(db, 'forensicReports', id), {
      id,
      ownerId,
      sessionId: input.sessionId,
      deviceId: input.deviceId,
      title: clampStr(input.title, 180),
      format: input.format,
      integritySha256: input.integritySha256,
      recordCount: Math.max(0, Math.round(input.recordCount)),
      summary: clampStr(input.summary, 1000),
      createdAt: serverTimestamp(),
    });
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function deleteOwnedDocument(
  collectionName: 'devices' | 'applications' | 'connections' | 'thirdParties' | 'policies' | 'forensicReports' | 'riskAlerts',
  docId: string
): Promise<void> {
  const path = `${collectionName}/${docId}`;
  try {
    await deleteDoc(doc(db, collectionName, docId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export function subscribeOwnerCollection<T extends { createdAt?: unknown }>(
  collectionName: string,
  ownerId: string,
  onData: (rows: T[]) => void
): Unsubscribe {
  const q = query(
    collection(db, collectionName),
    where('ownerId', '==', ownerId)
  );
  return onSnapshot(
    q,
    (snap) => {
      const rows = snap.docs.map((d) => d.data() as T);
      rows.sort((a, b) => {
        const ta =
          a.createdAt && typeof (a.createdAt as { toMillis?: () => number }).toMillis === 'function'
            ? (a.createdAt as { toMillis: () => number }).toMillis()
            : 0;
        const tb =
          b.createdAt && typeof (b.createdAt as { toMillis?: () => number }).toMillis === 'function'
            ? (b.createdAt as { toMillis: () => number }).toMillis()
            : 0;
        return tb - ta;
      });
      onData(rows);
    },
    (error) => {
      handleFirestoreError(error, OperationType.LIST, collectionName);
    }
  );
}

export const DEFAULT_ALERT_CONFIG_VALUES: Omit<
  AlertConfig,
  'id' | 'ownerId' | 'createdAt' | 'updatedAt'
> = {
  enableNewThirdPartyAlert: true,
  enableSensitivePermissionAlert: true,
  sensitivePermissionThreshold: 4,
  enableDataSpikeAlert: true,
  dataSpikeThresholdKb: 512,
  enablePolicyViolationAlert: true,
  enableThreatFeedAlert: true,
  notifyInAppBanner: true,
  notifyBrowserPush: false,
  notifySoundChime: true,
};

export async function ensureAlertConfig(ownerId: string): Promise<AlertConfig> {
  const path = `alertConfigs/${ownerId}`;
  const ref = doc(db, 'alertConfigs', ownerId);
  try {
    const snap = await getDoc(ref);
    if (snap.exists()) {
      return snap.data() as AlertConfig;
    }
    const payload = {
      id: ownerId,
      ownerId,
      ...DEFAULT_ALERT_CONFIG_VALUES,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    await setDoc(ref, payload);
    return payload;
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export function subscribeAlertConfig(
  ownerId: string,
  onData: (config: AlertConfig) => void
): Unsubscribe {
  const path = `alertConfigs/${ownerId}`;
  return onSnapshot(
    doc(db, 'alertConfigs', ownerId),
    (snap) => {
      if (snap.exists()) {
        onData(snap.data() as AlertConfig);
      }
    },
    (error) => {
      handleFirestoreError(error, OperationType.GET, path);
    }
  );
}

export async function updateAlertConfig(
  ownerId: string,
  actorEmail: string,
  updates: Partial<Omit<AlertConfig, 'id' | 'ownerId' | 'createdAt' | 'updatedAt'>>
): Promise<void> {
  const path = `alertConfigs/${ownerId}`;
  try {
    const payload: Record<string, unknown> = {
      updatedAt: serverTimestamp(),
    };
    if (typeof updates.enableNewThirdPartyAlert === 'boolean') {
      payload.enableNewThirdPartyAlert = updates.enableNewThirdPartyAlert;
    }
    if (typeof updates.enableSensitivePermissionAlert === 'boolean') {
      payload.enableSensitivePermissionAlert = updates.enableSensitivePermissionAlert;
    }
    if (typeof updates.sensitivePermissionThreshold === 'number') {
      payload.sensitivePermissionThreshold = Math.round(
        clampNum(updates.sensitivePermissionThreshold, 1, 20)
      );
    }
    if (typeof updates.enableDataSpikeAlert === 'boolean') {
      payload.enableDataSpikeAlert = updates.enableDataSpikeAlert;
    }
    if (typeof updates.dataSpikeThresholdKb === 'number') {
      payload.dataSpikeThresholdKb = Math.round(
        clampNum(updates.dataSpikeThresholdKb, 10, 100000)
      );
    }
    if (typeof updates.enablePolicyViolationAlert === 'boolean') {
      payload.enablePolicyViolationAlert = updates.enablePolicyViolationAlert;
    }
    if (typeof updates.enableThreatFeedAlert === 'boolean') {
      payload.enableThreatFeedAlert = updates.enableThreatFeedAlert;
    }
    if (typeof updates.notifyInAppBanner === 'boolean') {
      payload.notifyInAppBanner = updates.notifyInAppBanner;
    }
    if (typeof updates.notifyBrowserPush === 'boolean') {
      payload.notifyBrowserPush = updates.notifyBrowserPush;
    }
    if (typeof updates.notifySoundChime === 'boolean') {
      payload.notifySoundChime = updates.notifySoundChime;
    }
    await updateDoc(doc(db, 'alertConfigs', ownerId), payload);
    await writeAuditLog(
      ownerId,
      actorEmail,
      'ALERT_CONFIG_UPDATED',
      'alertConfig',
      ownerId,
      'Updated real-time privacy alert thresholds and notification preferences.'
    );
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}
