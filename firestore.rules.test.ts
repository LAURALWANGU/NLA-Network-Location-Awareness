import assert from 'node:assert/strict';

/**
 * NLA Firestore Security Rules Adversarial Verification Suite ("Dirty Dozen")
 * Verifies rule invariants against security_spec.md.
 * Run against Firebase Emulator Suite or structural rule assertion suite.
 */
export const DIRTY_DOZEN_PAYLOADS = [
  {
    name: '01. Unauthenticated Read/Write',
    path: '/devices/dev-01',
    auth: null,
    operation: 'create',
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '02. Unverified Email Write',
    path: '/devices/dev-01',
    auth: { uid: 'user-1', token: { email: 'test@example.com', email_verified: false } },
    operation: 'create',
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '03. Self-Assigned Admin Privilege',
    path: '/users/user-1',
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'create',
    data: { uid: 'user-1', role: 'admin' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '04. Role Escalation Update',
    path: '/users/user-1',
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'update',
    data: { role: 'admin' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '05. Cross-Tenant Ownership Spoofing',
    path: '/devices/dev-spoof',
    auth: { uid: 'attacker-uid', token: { email: 'attacker@example.com', email_verified: true } },
    operation: 'create',
    data: { id: 'dev-spoof', ownerId: 'victim-uid' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '06. Shadow Field Injection',
    path: '/devices/dev-shadow',
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'create',
    data: { id: 'dev-shadow', ownerId: 'user-1', isTrusted: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '07. ID Poisoning (>128 chars)',
    path: `/devices/${'a'.repeat(1500)}`,
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'create',
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '08. Orphaned Session Creation',
    path: '/sessions/sess-orphan',
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'create',
    data: { id: 'sess-orphan', ownerId: 'user-1', deviceId: 'non-existent-device' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '09. Client Timestamp Forgery',
    path: '/devices/dev-time',
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'create',
    data: { id: 'dev-time', ownerId: 'user-1', createdAt: '2020-01-01T00:00:00Z' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '10. Terminal State Bypass on Mitigated Alert',
    path: '/riskAlerts/alert-1',
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'update',
    existing: { status: 'mitigated', ownerId: 'user-1' },
    data: { status: 'open' },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '11. Blanket List Query Scraping',
    path: '/devices',
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'list_unfiltered',
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '12. Audit Log Tampering',
    path: '/auditLogs/log-1',
    auth: { uid: 'user-1', token: { email: 'user1@example.com', email_verified: true } },
    operation: 'delete',
    expected: 'PERMISSION_DENIED',
  },
];

assert.equal(DIRTY_DOZEN_PAYLOADS.length, 12);
