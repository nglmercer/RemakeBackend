-- Revocation cutoffs for native credentials. A row refuses every credential of its account issued
-- before the cutoff, in milliseconds since the Unix epoch. Written only by server-side revocation.
CREATE TABLE versioning_token_cutoffs (
    subject TEXT PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE,
    revoked_before_ms BIGINT NOT NULL CHECK (revoked_before_ms >= 0)
);
