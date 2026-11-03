# Publisher self-service portal

The Vue publisher portal (`web/admin/src/views/Portal.vue` plus
`web/admin/src/components/portal/`) lets a signed-in publisher drive the whole
pre-publication lifecycle without Cloud-operator help:

1. Request a namespace (`POST /api/v1/publishers`); pending, approved, and
   suspended states render with the member's own role.
2. Manage members: owners change roles and remove non-owners; non-owners leave
   on their own (`DELETE /api/v1/publishers/{id}/membership`). Ownership moves
   through a 24-hour expiring offer that only the recipient member accepts.
3. Enroll signing keys with the existing session-bound step-up flow
   (KeyManager reuses the challenge dialog; nothing touches web storage), list
   keys with fingerprint and status, and revoke authorized keys with
   confirmation. Revocation only removes trust; it never deletes history.
4. Submit signed releases with the release wizard:
   select an approved publisher, select an approved key, pick a locally signed
   `.plugin` file, validate size/ZIP magic/SHA-256/identity/version locally,
   reserve an upload (`Idempotency-Key` required), PUT the bytes directly to
   private quarantine storage, complete the version-pinned upload, and submit
   the release metadata. Private keys never enter the browser; signing happens
   in the publisher's own CLI.
5. Monitor releases per publisher (`GET /api/v1/publishers/{id}/releases`,
   paginated): version, target, checksum, size, verification progress,
   moderation decision and reason, yank state and reason, and advisories.

All authorization is enforced in Axum handlers; Vue only hides or disables
actions. Quarantine object paths, credentials, and signed URLs never leave the
temporary upload responses. Failed PUTs keep the wizard retryable: the client
reserves a fresh URL instead of reusing an expired one, and duplicate
submissions of the same upload plus metadata return the existing release
instead of creating a second one.

The release stays private: no publication step exists yet (see
REGISTRY-OPERATIONS.md for the PR 4 promotion workflow). Verification and
moderation outcomes render from the same tables reviewers write, so the status
a publisher sees is the status the pipeline enforces.
