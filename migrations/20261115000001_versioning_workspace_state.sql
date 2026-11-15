-- A workspace is recorded as pending before the engine creates its repository, and becomes
-- active once the engine confirms it. The pending row is the intent record: a repository the
-- engine created without an active row cannot exist, because the row was written first.
-- Credentials name only active workspaces.
ALTER TABLE versioning_workspaces
    ADD COLUMN state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('pending', 'active'));

CREATE INDEX versioning_workspaces_pending_idx
    ON versioning_workspaces (created_at)
    WHERE state = 'pending';
