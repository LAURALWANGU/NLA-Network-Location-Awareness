# NLA Security & Firestore Rules Specification

## 1. Data Invariants
1. **Strict Ownership**: Every operational document (`devices`, `sessions`, `applications`, `connections`, `thirdParties`, `policies`, `riskAlerts`, `forensicReports`, `auditLogs`) belongs to a single `ownerId` matching `request.auth.uid`, and cannot be read, listed, or modified by another non-admin user.
2. **Relational Integrity**: A `MonitoringSession` cannot be created without an existing `Device` owned by the caller. A `NetworkConnection` cannot be created without an existing `Device` and `MonitoringSession` owned by the caller.
3. **Privilege Escalation Prevention**: Users creating their own `/users/{userId}` document may only assign `role: 'analyst'` (never `'admin'`). Only an existing admin or verified bootstrapped admin (`blessednewton44@gmail.com` with `email_verified == true`) can create `/admins/{userId}` or elevate user roles.
4. **Immutable Audit Trail & Forensics**: `connections`, `forensicReports`, and `auditLogs` are append-only (no client updates allowed). `auditLogs` cannot be deleted by non-admins.
5. **Terminal State Locking**: Once a `MonitoringSession` transitions to `status: 'completed'`, or a `RiskAlert` transitions to `status: 'mitigated'`, non-admin users cannot mutate it back to an active/open state.
6. **Temporal Integrity**: All `createdAt` and `updatedAt` timestamps must equal `request.time` on creation/update; `createdAt` is immutable on update.
7. **Schema & Payload Bounds**: Every write enforces `keys().hasAll(...)` and `keys().hasOnly(...)` plus strict string `.size()` and array `.size()` limits to prevent shadow fields and resource exhaustion.

## 2. The "Dirty Dozen" Adversarial Payloads (Must Return PERMISSION_DENIED)
1. **Unauthenticated Read/Write**: Read `/devices/dev-1` or write `/devices/dev-1` with `auth == null`.
2. **Unverified Email Write**: Write `/devices/dev-1` with `email_verified: false`.
3. **Self-Assigned Admin Privilege**: Create `/users/{uid}` with `role: 'admin'`.
4. **Role Escalation Update**: Update `/users/{uid}` changing `role` from `'analyst'` to `'admin'`.
5. **Cross-Tenant Ownership Spoofing**: Create `/devices/dev-2` with `ownerId: 'victim-uid'` while authenticated as `'attacker-uid'`.
6. **Shadow Field Injection**: Create `/devices/dev-3` with all valid fields plus an extra undocumented field `isTrusted: true`.
7. **ID Poisoning (1.5KB Document ID)**: Create `/devices/${'a'.repeat(1500)}` exceeding `isValidId()` 128-char regex guard.
8. **Orphaned Session Creation**: Create `/sessions/sess-orphan` referencing a non-existent `deviceId: 'missing-dev'`.
9. **Client Timestamp Forgery**: Create `/devices/dev-4` with `createdAt: new Date('2020-01-01T00:00:00Z')` instead of `serverTimestamp()`.
10. **Terminal State Bypass**: Update `/riskAlerts/alert-1` from `status: 'mitigated'` back to `status: 'open'` as a non-admin.
11. **Blanket List Query Scraping**: Attempt `getDocs(collection(db, 'devices'))` without `where('ownerId', '==', uid)`.
12. **Audit Log Tampering**: Attempt `updateDoc` or `deleteDoc` on `/auditLogs/log-1` as a non-admin user.
