export type PlatformType = 'windows' | 'android' | 'linux' | 'macos' | 'ios' | 'web';

export type AgentMode =
  | 'endpoint-agent'
  | 'vpn-metadata'
  | 'privacy-report'
  | 'browser-inspector';

export type DeviceStatus = 'active' | 'paused' | 'stopped';
export type SessionStatus = 'active' | 'paused' | 'completed';
export type SessionSourceType =
  | 'live-probe'
  | 'har-import'
  | 'ios-privacy-report'
  | 'android-vpn-log'
  | 'endpoint-agent';

export type ServiceCategory =
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

export type PartyType = 'first-party' | 'third-party' | 'unknown';
export type ConfidenceLevel = 'high' | 'medium' | 'low';
export type EvidenceType = 'verified-technical' | 'declared-disclosure' | 'inferred' | 'unknown';
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low';
export type AlertStatus = 'open' | 'acknowledged' | 'mitigated';

export type AlertCategory =
  | 'unexpected-third-party'
  | 'excessive-permissions'
  | 'background-beacon'
  | 'new-destination'
  | 'disclosure-mismatch'
  | 'suspicious-pattern'
  | 'data-spike'
  | 'policy-violation'
  | 'threat-feed-match';

export type ExternalFeedVerdict =
  | 'malicious'
  | 'privacy-invasive'
  | 'ad-tracker'
  | 'clean'
  | 'unlisted';

export interface ExternalFeedMatch {
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

export interface AlertConfig {
  id: string;
  ownerId: string;
  enableNewThirdPartyAlert: boolean;
  enableSensitivePermissionAlert: boolean;
  sensitivePermissionThreshold: number;
  enableDataSpikeAlert: boolean;
  dataSpikeThresholdKb: number;
  enablePolicyViolationAlert: boolean;
  enableThreatFeedAlert: boolean;
  notifyInAppBanner: boolean;
  notifyBrowserPush: boolean;
  notifySoundChime: boolean;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface UserProfile {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  role: 'analyst' | 'auditor' | 'admin';
  retentionDays: number;
  consentAccepted: boolean;
  consentUpdatedAt?: unknown;
  onboardingCompleted?: boolean;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface DeviceRecord {
  id: string;
  ownerId: string;
  name: string;
  platform: PlatformType;
  osVersion: string;
  hostname: string;
  agentMode: AgentMode;
  status: DeviceStatus;
  city: string;
  country: string;
  latitude: number;
  longitude: number;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface MonitoringSession {
  id: string;
  ownerId: string;
  deviceId: string;
  title: string;
  status: SessionStatus;
  sourceType: SessionSourceType;
  observationCount: number;
  bytesObserved: number;
  integrityHash: string;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface AnalyzedApplication {
  id: string;
  ownerId: string;
  deviceId: string;
  name: string;
  packageId: string;
  developer: string;
  version: string;
  platform: PlatformType;
  privacyScore: number;
  permissionsPenalty: number;
  thirdPartyPenalty: number;
  backgroundPenalty: number;
  disclosurePenalty: number;
  requestedPermissions: string[];
  grantedPermissions: string[];
  detectedSdks: string[];
  externalDomains: string[];
  advertisingIdAccess: 'observed' | 'declared' | 'not-detected' | 'unknown';
  policyUrl: string;
  retentionDisclosure: string;
  sharingPractices: string;
  evidenceType: EvidenceType;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface NetworkConnection {
  id: string;
  ownerId: string;
  sessionId: string;
  deviceId: string;
  appName: string;
  observedAt: string;
  sourceOrigin: string;
  sourceLat: number;
  sourceLng: number;
  destinationDomain: string;
  destinationIp: string;
  destinationPort: number;
  protocol: 'HTTPS' | 'TLS' | 'DNS' | 'HTTP' | 'QUIC';
  city: string;
  country: string;
  countryCode: string;
  latitude: number;
  longitude: number;
  asn: string;
  hostingOrg: string;
  companyName: string;
  serviceCategory: ServiceCategory;
  partyType: PartyType;
  bytesTransferred: number;
  requestCount: number;
  isBackground: boolean;
  confidence: ConfidenceLevel;
  evidenceType: EvidenceType;
  evidenceSummary: string;
  tlsSubject: string;
  dnsRecordType: string;
  createdAt?: unknown;
}

export interface ThirdPartyService {
  id: string;
  ownerId: string;
  companyName: string;
  domain: string;
  observedIp: string;
  hostingOrg: string;
  country: string;
  asn: string;
  classification: ServiceCategory;
  associatedApps: string[];
  firstObservedAt: string;
  lastObservedAt: string;
  evidenceSummary: string;
  confidence: ConfidenceLevel;
  externalFeedSource?: string;
  externalFeedVerdict?: ExternalFeedVerdict;
  externalFeedDetails?: string;
  externalFeedCheckedAt?: string;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface PrivacyPolicyAnalysis {
  id: string;
  ownerId: string;
  appName: string;
  policyUrl: string;
  versionLabel: string;
  sourceType: 'url' | 'text' | 'pdf';
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
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface RiskAlert {
  id: string;
  ownerId: string;
  deviceId: string;
  sessionId: string;
  appName: string;
  domain: string;
  severity: AlertSeverity;
  category: AlertCategory;
  title: string;
  explanation: string;
  evidence: string;
  confidence: ConfidenceLevel;
  recommendedAction: string;
  status: AlertStatus;
  externalFeedSource?: string;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface ForensicReport {
  id: string;
  ownerId: string;
  sessionId: string;
  deviceId: string;
  title: string;
  format: 'json' | 'csv' | 'html' | 'pdf';
  integritySha256: string;
  recordCount: number;
  summary: string;
  createdAt?: unknown;
}

export interface AuditLogEntry {
  id: string;
  ownerId: string;
  actorEmail: string;
  action: string;
  targetType: string;
  targetId: string;
  details: string;
  createdAt?: unknown;
}

export type NavSectionId =
  | 'overview'
  | 'map'
  | 'apps'
  | 'collection'
  | 'third-parties'
  | 'policies'
  | 'live-monitor'
  | 'risks'
  | 'forensics'
  | 'reports'
  | 'assistant'
  | 'devices'
  | 'settings'
  | 'about';
