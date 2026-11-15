-- Ownership of Lore repositories by backend accounts. A row says which account may hold
-- native credentials for a Lore repository. It is written only by server-side code that has
-- verified the repository exists and that the account owns it; no request body can create one.
CREATE TABLE versioning_workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    -- A Lore repository id, 32 lowercase hexadecimal characters.
    lore_repository_id TEXT NOT NULL UNIQUE CHECK (lore_repository_id ~ '^[0-9a-f]{32}$'),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX versioning_workspaces_owner_idx
    ON versioning_workspaces (owner_user_id)
    WHERE revoked_at IS NULL;
