-- Persistent public registry inventory. Generations are immutable full
-- snapshots: each new generation preserves the previous published releases
-- and adds newly prepared ones. The single active generation is the atomic
-- snapshot pointer the v1 protocol lacks. Nothing here deploys anything.
CREATE TABLE cloud_registry_generations (
    id UUID PRIMARY KEY,
    generation BIGINT NOT NULL UNIQUE CHECK (generation >= 1),
    candidate_id UUID NOT NULL REFERENCES cloud_snapshot_candidates(id),
    inventory_sha256 TEXT NOT NULL CHECK (inventory_sha256 ~ '^[0-9a-f]{64}$'),
    -- Empty while staged: the manifest hash is known only after the build.
    manifest_sha256 TEXT NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$' OR (status = 'staged' AND manifest_sha256 = '')),
    root_fingerprint TEXT NOT NULL CHECK (root_fingerprint ~ '^[0-9a-f]{64}$'),
    index_key_id TEXT NOT NULL CHECK (length(index_key_id) BETWEEN 1 AND 256),
    release_count INTEGER NOT NULL CHECK (release_count BETWEEN 1 AND 10000),
    -- Zero while staged: files are recorded after the build uploads them.
    file_count INTEGER NOT NULL CHECK (file_count BETWEEN 0 AND 41000),
    status TEXT NOT NULL CHECK (status IN ('staged','active','superseded','rolled_back')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    activated_by TEXT,
    superseded_by BIGINT,
    CHECK ((status = 'active' AND activated_at IS NOT NULL AND activated_by IS NOT NULL) OR status <> 'active')
);
-- Exactly one active generation: the atomic publication pointer.
CREATE UNIQUE INDEX cloud_registry_one_active ON cloud_registry_generations (status) WHERE status = 'active';

-- Published release inventory per generation. Advisory columns snapshot the
-- advisory state at publish time so rollback can refuse stale advisories.
CREATE TABLE cloud_registry_generation_releases (
    generation BIGINT NOT NULL REFERENCES cloud_registry_generations(generation),
    plugin_id TEXT NOT NULL CHECK (length(plugin_id) BETWEEN 1 AND 256),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 128),
    target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
    release_id UUID NOT NULL REFERENCES cloud_plugin_releases(id),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size BIGINT NOT NULL CHECK (size BETWEEN 1 AND 134217728),
    object_key TEXT NOT NULL,
    version_id TEXT NOT NULL CHECK (length(version_id) BETWEEN 1 AND 1024 AND version_id <> 'null'),
    advisory_severity TEXT CHECK (advisory_severity IN ('low','moderate','high','critical')),
    advisory_message TEXT,
    advisory_url TEXT,
    PRIMARY KEY (generation, plugin_id, version, target),
    CHECK ((advisory_severity IS NULL AND advisory_message IS NULL AND advisory_url IS NULL) OR (advisory_severity IS NOT NULL AND advisory_message IS NOT NULL))
);
CREATE INDEX cloud_registry_generation_releases_release_idx ON cloud_registry_generation_releases (release_id);

-- Immutable published files per generation. Rollback and clients read these
-- exact versions; GC must never delete files of active or retained generations.
CREATE TABLE cloud_registry_generation_files (
    generation BIGINT NOT NULL REFERENCES cloud_registry_generations(generation) ON DELETE CASCADE,
    path TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 2048),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size BIGINT NOT NULL CHECK (size BETWEEN 1 AND 134217728),
    object_key TEXT NOT NULL UNIQUE,
    version_id TEXT NOT NULL CHECK (length(version_id) BETWEEN 1 AND 1024 AND version_id <> 'null'),
    PRIMARY KEY (generation, path)
);

-- Consuming prepared jobs at promotion keeps future candidates to new work;
-- published jobs retain their staging pointer until bounded GC proves the
-- immutable public copies authoritative, then the pointer is nulled.
ALTER TABLE cloud_publication_jobs DROP CONSTRAINT cloud_publication_job_status;
ALTER TABLE cloud_publication_jobs ADD CONSTRAINT cloud_publication_job_status CHECK (status IN ('queued','running','prepared','published','blocked','rejected','failed'));
ALTER TABLE cloud_publication_jobs DROP CONSTRAINT cloud_publication_job_prepared;
ALTER TABLE cloud_publication_jobs ADD CONSTRAINT cloud_publication_job_prepared CHECK ((status IN ('prepared','published') AND prepared_key IS NOT NULL AND prepared_version_id IS NOT NULL AND prepared_version_id <> '' AND prepared_version_id <> 'null') OR (status NOT IN ('prepared','published') AND prepared_key IS NULL AND prepared_version_id IS NULL));

-- Promotion, rollback, failure, and recovery history with operator identity.
CREATE TABLE cloud_registry_promotions (
    id UUID PRIMARY KEY,
    generation BIGINT REFERENCES cloud_registry_generations(generation),
    candidate_id UUID REFERENCES cloud_snapshot_candidates(id),
    decision TEXT NOT NULL CHECK (decision IN ('promoted','rolled_back','blocked','failed')),
    operator TEXT NOT NULL CHECK (length(operator) BETWEEN 1 AND 80 AND operator ~ '^[A-Za-z0-9._@-]+$'),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
