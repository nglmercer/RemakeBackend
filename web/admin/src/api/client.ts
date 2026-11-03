// Typed same-origin API client. Cookie sessions only: credentials are
// included on every request and no token is ever persisted anywhere
// (no localStorage, no sessionStorage).
import type {
  AuditPage,
  Inspection,
  KeyChallenge,
  Me,
  ModerationQueue,
  MyPublisher,
  Overview,
  PublisherKey,
  PublisherMember,
  PublisherRelease,
  PublisherReleasePage,
  PublisherTransfer,
  ReleaseReview,
  UploadReservation,
  PublisherReviewPage,
  StepUpAction,
  StepUpGrant,
  StepUpStart,
} from './types'

export class ApiError extends Error {
  status: number
  /** Machine-readable backend error code (`{error}` body), if any. */
  code?: string
  constructor(status: number, message: string, code?: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: 'include',
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  })
  if (!response.ok) {
    let code: string | undefined
    try {
      const data = (await response.json()) as { error?: unknown }
      if (data && typeof data.error === 'string') code = data.error
    } catch {
      // Non-JSON failures carry no code.
    }
    throw new ApiError(response.status, `${init?.method ?? 'GET'} ${path} -> ${response.status}`, code)
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

export const api = {
  me: () => request<Me>('/api/v1/me'),
  signOut: () =>
    request<unknown>('/api/auth/sign-out', { method: 'POST', body: JSON.stringify({}) }),
  signInEmail: (email: string, password: string) =>
    request<unknown>('/api/auth/sign-in/email', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
  overview: () => request<Overview>('/api/v1/admin/overview'),
  adminPublishers: (params: { status?: string; cursor?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params.status) q.set('status', params.status)
    if (params.cursor) q.set('cursor', params.cursor)
    if (params.limit) q.set('limit', String(params.limit))
    const s = q.toString()
    return request<PublisherReviewPage>(`/api/v1/admin/publishers${s ? `?${s}` : ''}`)
  },
  approvePublisher: (id: string) =>
    request<unknown>(`/api/v1/admin/publishers/${id}/approve`, { method: 'POST' }),
  audit: (params: { cursor?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params.cursor) q.set('cursor', params.cursor)
    if (params.limit) q.set('limit', String(params.limit))
    const s = q.toString()
    return request<AuditPage>(`/api/v1/admin/audit${s ? `?${s}` : ''}`)
  },
  moderationQueue: (after?: string) =>
    request<ModerationQueue>(
      `/api/v1/moderation/releases${after ? `?after=${encodeURIComponent(after)}` : ''}`,
    ),
  inspectRelease: (id: string) =>
    request<Inspection>(`/api/v1/moderation/releases/${id}/inspection`, { method: 'POST' }),
  decideRelease: (id: string, decision: 'approve' | 'reject', reasonCode: string) =>
    request<unknown>(`/api/v1/moderation/releases/${id}/decision`, {
      method: 'POST',
      body: JSON.stringify({ decision, reasonCode }),
    }),
  yankRelease: (id: string, reason: string) =>
    request<unknown>(`/api/v1/moderation/releases/${id}/yank`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  recordAdvisory: (id: string, severity: string, message: string, url?: string) =>
    request<unknown>(`/api/v1/moderation/releases/${id}/advisory`, {
      method: 'POST',
      body: JSON.stringify({ severity, message, url: url || null }),
    }),
  myPublishers: () => request<MyPublisher[]>('/api/v1/publishers'),
  createPublisher: (namespace: string) =>
    request<MyPublisher>('/api/v1/publishers', {
      method: 'POST',
      body: JSON.stringify({ namespace }),
    }),
  publisherMembers: (id: string) => request<PublisherMember[]>(`/api/v1/publishers/${id}/members`),
  setMemberRole: (id: string, userId: string, role: string) =>
    request<unknown>(`/api/v1/publishers/${id}/members/${encodeURIComponent(userId)}`, {
      method: 'PUT',
      body: JSON.stringify({ role }),
    }),
  removeMember: (id: string, userId: string) =>
    request<unknown>(`/api/v1/publishers/${id}/members/${encodeURIComponent(userId)}`, {
      method: 'DELETE',
    }),
  leavePublisher: (id: string) =>
    request<unknown>(`/api/v1/publishers/${id}/membership`, { method: 'DELETE' }),
  currentTransfer: (id: string) => request<PublisherTransfer>(`/api/v1/publishers/${id}/transfer`),
  offerTransfer: (id: string, recipientUserId: string) =>
    request<PublisherTransfer>(`/api/v1/publishers/${id}/transfer`, {
      method: 'POST',
      body: JSON.stringify({ recipientUserId }),
    }),
  cancelTransfer: (id: string) =>
    request<unknown>(`/api/v1/publishers/${id}/transfer`, { method: 'DELETE' }),
  acceptTransfer: (id: string, transferId: string) =>
    request<unknown>(`/api/v1/publishers/${id}/transfer/${transferId}/accept`, {
      method: 'POST',
    }),
  publisherKeys: (id: string) => request<PublisherKey[]>(`/api/v1/publishers/${id}/keys`),
  revokePublisherKey: (id: string, keyId: string) =>
    request<unknown>(`/api/v1/publishers/${id}/keys/${keyId}/revoke`, { method: 'POST' }),
  reserveUpload: (publisherId: string, size: number, sha256: string, idempotencyKey: string) =>
    request<UploadReservation>('/api/v1/plugins/uploads', {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ publisherId, size, sha256 }),
    }),
  completeUpload: (id: string) =>
    request<{ id: string; status: string }>(`/api/v1/plugins/uploads/${id}/complete`, {
      method: 'POST',
    }),
  submitRelease: (input: {
    uploadId: string
    publisherKeyId: string
    pluginId: string
    version: string
    target: string
  }) =>
    request<PublisherRelease>('/api/v1/plugins/releases', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  publisherReleases: (id: string, params: { cursor?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params.cursor) q.set('cursor', params.cursor)
    if (params.limit) q.set('limit', String(params.limit))
    const s = q.toString()
    return request<PublisherReleasePage>(`/api/v1/publishers/${id}/releases${s ? `?${s}` : ''}`)
  },
  releaseReview: (id: string) => request<ReleaseReview>(`/api/v1/plugins/releases/${id}/review`),
  stepUpPassword: (action: StepUpAction, publisherId: string, keyId: string | null, password: string) =>
    request<StepUpGrant>('/api/v1/step-up/password', {
      method: 'POST',
      body: JSON.stringify({ action, publisherId, keyId, password }),
    }),
  stepUpStart: (action: StepUpAction, publisherId: string, keyId: string | null, returnTo: string) =>
    request<StepUpStart>('/api/v1/step-up/oauth/start', {
      method: 'POST',
      body: JSON.stringify({ action, publisherId, keyId, returnTo }),
    }),
  publisherKeyChallenge: (publisherId: string, grantId: string) =>
    request<KeyChallenge>(`/api/v1/publishers/${publisherId}/keys/challenges`, {
      method: 'POST',
      body: JSON.stringify({ stepUpGrant: grantId }),
    }),
  requestPublisherKey: (
    publisherId: string,
    proof: { challengeId: string; keyId: string; publicKey: string; signature: string },
    grantId: string,
  ) =>
    request<PublisherKey>(`/api/v1/publishers/${publisherId}/keys`, {
      method: 'POST',
      body: JSON.stringify({ ...proof, stepUpGrant: grantId }),
    }),
  adminPublisherKeys: (publisherId: string) =>
    request<PublisherKey[]>(`/api/v1/admin/publishers/${publisherId}/keys`),
  approvePublisherKey: (publisherId: string, keyId: string, grantId: string) =>
    request<unknown>(`/api/v1/admin/publishers/${publisherId}/keys/${keyId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ stepUpGrant: grantId }),
    }),
}
