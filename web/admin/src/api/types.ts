// Shared DTOs for the Cloud API. Field names mirror the backend's
// camelCase serialization; ADMIN_READ_CONTRACT_VERSION must match the
// backend's `admin::ADMIN_READ_CONTRACT_VERSION`.
export const ADMIN_READ_CONTRACT_VERSION = 1

export interface Me {
  id: string
  email: string
  name: string
  roles: string[]
}

export interface Overview {
  contractVersion: number
  publishers: { pending: number; approved: number; suspended: number }
  releases: {
    awaitingVerification: number
    integrityPassed: number
    antivirusPassed: number
    reviewApproved: number
    reviewRejected: number
    rejected: number
  }
  pendingKeys: number
  auditEvents: number
}

export interface PublisherReviewItem {
  id: string
  namespace: string
  status: string
  createdAt: string
}

export interface PublisherReviewPage {
  contractVersion: number
  items: PublisherReviewItem[]
  nextCursor: string | null
}

export interface AuditEventView {
  id: string
  action: string
  actorUserId: string
  targetUserId: string | null
  publisherId: string | null
  subjectId: string | null
  oldRole: string | null
  newRole: string | null
  createdAt: string
}

export interface AuditPage {
  contractVersion: number
  events: AuditEventView[]
  nextCursor: string | null
}

export interface ModerationCandidate {
  id: string
  publisherId: string
  namespace: string
  pluginId: string
  version: string
  target: string
  sha256: string
  size: number
  keyId: string
  keyFingerprint: string
  yanked: boolean
  yankReason: string | null
  advisory: { severity: string; message: string; url: string | null } | null
}

export interface ModerationQueue {
  items: ModerationCandidate[]
  nextCursor: string | null
}

export interface Inspection {
  url: string
  expiresIn: number
}

export interface MyPublisher {
  id: string
  namespace: string
  status: string
  role: string
}

export type StepUpAction = 'publisher.key.enroll' | 'publisher.key.approve'

export interface StepUpGrant {
  grantId: string
  expiresIn: number
}

export interface StepUpStart {
  authorizationUrl: string
  expiresIn: number
}

export interface KeyChallenge {
  challengeId: string
  nonce: string
  expiresIn: number
}

export interface PublisherKey {
  id: string
  keyId: string
  publicKey: string
  fingerprint: string
  status: string
}

// NOTE: the members endpoint serializes snake_case (no camelCase rename on
// the backend struct); mirror it exactly rather than transforming.
export interface PublisherMember {
  user_id: string
  role: string
}

export interface PublisherTransfer {
  id: string
  offeredBy: string
  recipientUserId: string
}

export interface ReleaseAdvisory {
  severity: string
  message: string
  url: string | null
}

export interface ReleaseModeration {
  decision: string
  reasonCode: string
}

export interface ReleaseVerification {
  status: string
  resultClass: string | null
}

export interface PublisherRelease {
  id: string
  publisherId: string
  uploadId: string
  publisherKeyId: string
  pluginId: string
  version: string
  target: string
  status: string
  sha256: string
  size: number
  keyId: string
  keyFingerprint: string
  yanked: boolean
  yankReason: string | null
  advisory: ReleaseAdvisory | null
  moderation: ReleaseModeration | null
  verification: ReleaseVerification | null
}

export interface PublisherReleasePage {
  items: PublisherRelease[]
  nextCursor: string | null
}

export interface UploadReservation {
  id: string
  url: string
  headers: Record<string, string>
  expiresIn: number
}

export interface ReleaseReview {
  decision: string
  reasonCode: string
  yanked: boolean
  yankReason: string | null
  advisory: ReleaseAdvisory | null
}

export type PublisherRole = 'owner' | 'admin' | 'publisher' | 'viewer'

export function canPublish(role: string): boolean {
  return role === 'owner' || role === 'admin' || role === 'publisher'
}

export function canManageMembers(role: string): boolean {
  return role === 'owner'
}

export function canManageKeys(role: string): boolean {
  return role === 'owner' || role === 'admin'
}

export function isCloudAdmin(me: Me | null | undefined): boolean {
  return me?.roles.includes('admin') ?? false
}

export function isReviewer(me: Me | null | undefined): boolean {
  return me?.roles.some((r) => r === 'admin' || r === 'moderator') ?? false
}
