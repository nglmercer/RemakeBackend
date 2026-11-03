//! Authenticated-operator promotion of verified candidates to immutable,
//! generation-based public snapshots, plus rollback and bounded GC.
//!
//! Promotion is fail-closed: a readiness record is evidence, never
//! authorization. Every promotion rechecks the exact manifest and inventory
//! hashes, current publisher/key authorization, moderation decisions,
//! yanks/advisories, signatures, object versions, digests, and the current
//! root/delegated signing policy under one advisory lock before any file is
//! staged, and rechecks inventory, manifest, readiness, and the active pointer
//! again before the atomic activation flip. Generations are complete snapshots
//! (previously published releases plus newly prepared ones), never rebuilt
//! empty registries. Publication is idempotent and restart-safe: re-running
//! promotion for the same candidate resumes the staged generation instead of
//! duplicating it, and interrupted runs leave enumerable staged rows for GC.
use crate::{snapshot_export, snapshot_verify, snapshot_worker};
use cloud_storage::{ObjectVersion, QuarantineStore};
use sqlx::{PgConnection, PgPool, Row};
use std::{
    collections::BTreeMap,
    error::Error,
    path::{Component, Path, PathBuf},
};
use tiktools_plugin_package::{Sha256Digest, TrustedKey};
use uuid::Uuid;

use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Serializes promoters, rollers-back, and collectors against each other.
/// The lock is held only inside short database transactions, never across
/// network or build work; inventory and manifest are rechecked after.
const REGISTRY_LOCK: i64 = 840170007;
/// Staged generations older than this are crash leftovers, eligible for GC.
const STALE_STAGED_SECS: i64 = 3600;
/// Upper bound for one GC run (files plus generations).
const GC_MAX: i64 = 1000;

fn valid_operator(operator: &str) -> bool {
    !operator.is_empty()
        && operator.len() <= 80
        && operator
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
}

async fn try_lock(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<()> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(REGISTRY_LOCK)
        .fetch_one(&mut **tx)
        .await?;
    if locked {
        Ok(())
    } else {
        Err("another registry promotion is running".into())
    }
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operator: &str,
    generation: Uuid,
    action: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO cloud_audit_events(id,actor_user_id,subject_id,action) VALUES($1,$2,$3,$4)",
    )
    .bind(Uuid::new_v4())
    .bind(format!("operator:{operator}"))
    .bind(generation)
    .bind(action)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Policy refusals (stale candidates, changed authorization, revoked trust)
/// are `blocked`; infrastructure failures are `failed`. Lock contention is
/// neither: the other promotion owns the outcome.
fn is_policy_refusal(message: &str) -> bool {
    [
        "candidate",
        "readiness",
        "stale",
        "authoriz",
        "nothing to publish",
        "duplicate",
        "invalid operator",
        "unknown generation",
        "previously live generation",
        "no active generation",
        "no releases",
        "no files",
        "advisory",
        "revoked",
        "fingerprint",
        "trust material",
        "registry policy",
        "snapshot",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

async fn record_outcome(
    pool: &PgPool,
    generation: Option<i64>,
    candidate: Option<Uuid>,
    decision: &str,
    operator: &str,
    reason: &str,
) {
    let mut reason = reason.to_owned();
    truncate_reason(&mut reason);
    let _ = sqlx::query("INSERT INTO cloud_registry_promotions (id, generation, candidate_id, decision, operator, reason) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(Uuid::new_v4()).bind(generation).bind(candidate).bind(decision).bind(operator).bind(&reason).execute(pool).await;
}

fn truncate_reason(reason: &mut String) {
    if reason.len() > 1024 {
        let mut end = 1024;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
}

/// Canonical digest of the exact release set: identity, artifact, key, and
/// advisory state. Compared before and after builds and across restarts.
fn inventory_digest(items: &[(SnapshotItem, Option<AdvisorySnapshot>)]) -> String {
    let mut canonical = items
        .iter()
        .map(|(item, advisory)| {
            serde_json::json!({
                "pluginId": item.plugin_id,
                "version": item.version,
                "target": item.target,
                "sha256": item.sha256,
                "size": item.size,
                "keyId": item.key_id,
                "advisory": advisory,
            })
        })
        .collect::<Vec<_>>();
    canonical.sort_by_key(|a| a.to_string());
    Sha256Digest::of_bytes(&serde_json::to_vec(&canonical).unwrap_or_default()).to_string()
}

fn manifest_digest(files: &BTreeMap<String, String>) -> String {
    Sha256Digest::of_bytes(&serde_json::to_vec(files).unwrap_or_default()).to_string()
}

/// The exact digest the readiness ledger records: the serialized export
/// manifest, byte for byte. Evidence comparison must use this, not a
/// projection, or every promotion fails closed on a phantom mismatch.
fn export_manifest_digest(manifest: &snapshot_export::Manifest) -> Result<String> {
    Ok(Sha256Digest::of_bytes(&serde_json::to_vec(manifest)?).to_string())
}

/// One release to publish: where its bytes live now and what authorizes it.
#[derive(Clone)]
struct SnapshotItem {
    release_id: Uuid,
    publisher: Uuid,
    namespace: String,
    plugin_id: String,
    version: String,
    target: String,
    sha256: String,
    size: i64,
    key_id: String,
    public_key: String,
    object_key: String,
    version_id: String,
    job: Option<Uuid>,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
struct AdvisorySnapshot {
    severity: String,
    message: String,
    url: Option<String>,
}

impl SnapshotItem {
    fn approved(&self) -> Result<TrustedKey> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use tiktools_plugin_package::{KeyId, KeyRole};
        let raw = STANDARD.decode(&self.public_key)?;
        if STANDARD.encode(&raw) != self.public_key {
            return Err("noncanonical publisher key".into());
        }
        let key = tiktools_plugin_package::PublicKey::new(KeyId::parse(&self.key_id)?, &raw)?;
        Ok(TrustedKey::new(key, KeyRole::Publisher).publisher(&self.namespace))
    }

    fn channel(&self) -> Result<&'static str> {
        let version = tiktools_plugin_api::manifest::parse_version(&self.version)
            .ok_or("invalid release version")?;
        Ok(if version.pre.is_empty() {
            "stable"
        } else {
            "beta"
        })
    }

    fn worker_item(
        &self,
        advisory: Option<snapshot_worker::AdvisoryRecord>,
    ) -> snapshot_worker::Item {
        snapshot_worker::Item {
            job: self.job.unwrap_or(self.release_id),
            publisher: self.publisher,
            namespace: self.namespace.clone(),
            plugin_id: self.plugin_id.clone(),
            version: self.version.clone(),
            target: self.target.clone(),
            sha256: self.sha256.clone(),
            size: self.size,
            prepared_key: self.object_key.clone(),
            prepared_version: self.version_id.clone(),
            key_id: self.key_id.clone(),
            public_key: self.public_key.clone(),
            requester: String::new(),
            revisions: Vec::new(),
            advisory,
        }
    }
}

fn advisory_record(advisory: &Option<AdvisorySnapshot>) -> Option<snapshot_worker::AdvisoryRecord> {
    advisory.as_ref().map(|a| snapshot_worker::AdvisoryRecord {
        severity: a.severity.clone(),
        message: a.message.clone(),
        url: a.url.clone(),
    })
}

/// Currently prepared jobs (authorization-checked by `capture`) that are not
/// yet published, plus previously published releases re-authorized against
/// current state. Yanked, revoked, suspended, or otherwise unauthorized base
/// releases are dropped and reported, never restored.
async fn merged_inventory(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    candidate_id: Uuid,
) -> Result<(
    Vec<(SnapshotItem, Option<AdvisorySnapshot>)>,
    Vec<String>,
    Uuid,
    String,
)> {
    let active: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, generation FROM cloud_registry_generations WHERE status='active' ORDER BY generation DESC LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await?;
    let mut base: BTreeMap<(String, String, String), (SnapshotItem, Option<AdvisorySnapshot>)> =
        BTreeMap::new();
    let mut dropped = Vec::new();
    if let Some((_, generation)) = active {
        let rows = sqlx::query(
            "SELECT r.id AS release_id, r.publisher_id, p.namespace, r.plugin_id, r.version, r.target, r.status AS release_status, r.requested_by, u.status AS upload_status, u.expected_sha256, u.expected_size, k.status AS key_status, k.key_id, k.public_key, k.fingerprint, v.status AS verification_status, v.result_class AS verification_result, m.decision AS moderation_decision, (y.release_id IS NOT NULL) AS yanked, a.severity AS advisory_severity, a.message AS advisory_message, a.url AS advisory_url, g.object_key, g.version_id FROM cloud_registry_generation_releases g JOIN cloud_plugin_releases r ON r.id = g.release_id JOIN cloud_publishers p ON p.id = r.publisher_id JOIN cloud_upload_sessions u ON u.id = r.upload_id AND u.publisher_id = r.publisher_id JOIN cloud_publisher_keys k ON k.id = r.publisher_key_id AND k.publisher_id = r.publisher_id LEFT JOIN cloud_verification_jobs v ON v.upload_id = u.id AND v.release_id = r.id LEFT JOIN cloud_moderation_events m ON m.release_id = r.id LEFT JOIN cloud_release_yanks y ON y.release_id = r.id LEFT JOIN cloud_release_advisories a ON a.release_id = r.id WHERE g.generation = $1",
        )
        .bind(generation)
        .fetch_all(&mut **tx)
        .await?;
        for row in rows {
            let plugin_id: String = row.get("plugin_id");
            let version: String = row.get("version");
            let target: String = row.get("target");
            let identity = format!("{plugin_id} {version} {target}");
            let item = SnapshotItem {
                release_id: row.get("release_id"),
                publisher: row.get("publisher_id"),
                namespace: row.get("namespace"),
                plugin_id: plugin_id.clone(),
                version: version.clone(),
                target: target.clone(),
                sha256: row.get("expected_sha256"),
                size: row.get("expected_size"),
                key_id: row.get("key_id"),
                public_key: row.get("public_key"),
                object_key: row.get("object_key"),
                version_id: row.get("version_id"),
                job: None,
            };
            // Current state decides: a release that changed since publication
            // is dropped from the new generation, never carried over.
            let authorized = row.get::<String, _>("release_status") == "review_approved"
                && row.get::<String, _>("upload_status") == "quarantined"
                && row
                    .get::<Option<String>, _>("verification_status")
                    .as_deref()
                    == Some("antivirus_passed")
                && row
                    .get::<Option<String>, _>("verification_result")
                    .as_deref()
                    == Some("antivirus_passed")
                && row
                    .get::<Option<String>, _>("moderation_decision")
                    .as_deref()
                    == Some("approve")
                && row.get::<Option<String>, _>("key_status").as_deref() == Some("approved")
                && !row.get::<bool, _>("yanked")
                && !row.get::<String, _>("namespace").is_empty();
            let fingerprint_ok = item
                .approved()
                .ok()
                .and_then(|key| key.key.fingerprint().ok())
                .is_some_and(|fingerprint| {
                    fingerprint.as_hex() == row.get::<String, _>("fingerprint")
                });
            let publisher_ok: bool = sqlx::query_scalar(
                "SELECT status = 'approved' FROM cloud_publishers WHERE id = $1",
            )
            .bind(item.publisher)
            .fetch_one(&mut **tx)
            .await?;
            if !authorized || !fingerprint_ok || !publisher_ok {
                let reason = if row.get::<bool, _>("yanked") {
                    "yanked"
                } else if row.get::<Option<String>, _>("key_status").as_deref() != Some("approved")
                {
                    "key_revoked"
                } else if !publisher_ok {
                    "publisher_suspended"
                } else {
                    "authorization_changed"
                };
                dropped.push(format!("{identity} ({reason})"));
                continue;
            }
            let advisory = row
                .get::<Option<String>, _>("advisory_severity")
                .map(|severity| AdvisorySnapshot {
                    severity,
                    message: row.get("advisory_message"),
                    url: row.get("advisory_url"),
                });
            if base
                .insert((plugin_id, version, target), (item, advisory))
                .is_some()
            {
                return Err("duplicate published release identity".into());
            }
        }
    }
    // Prepared jobs are authorization-checked by capture; anything invalid
    // fails the whole promotion instead of being silently skipped.
    let prepared = {
        let conn: &mut PgConnection = &mut *tx;
        snapshot_worker::capture(conn).await?
    };
    // The candidate pins exactly the prepared set promotion may publish: a
    // stale candidate (new jobs arrived, or jobs changed) fails closed here.
    let links = sqlx::query(
        "SELECT publication_job_id, prepared_key, prepared_version_id, sha256 FROM cloud_snapshot_candidate_releases WHERE candidate_id = $1 ORDER BY publication_job_id",
    )
    .bind(candidate_id)
    .fetch_all(&mut **tx)
    .await?;
    if links.len() != prepared.len()
        || links.iter().zip(&prepared).any(|(row, item)| {
            row.get::<Uuid, _>("publication_job_id") != item.job
                || row.get::<String, _>("prepared_key") != item.prepared_key
                || row.get::<String, _>("prepared_version_id") != item.prepared_version
                || row.get::<String, _>("sha256") != item.sha256
        })
    {
        return Err("candidate is stale: prepared inventory changed after verification".into());
    }
    let mut merged: BTreeMap<(String, String, String), (SnapshotItem, Option<AdvisorySnapshot>)> =
        base;
    for item in prepared {
        let key = (
            item.plugin_id.clone(),
            item.version.clone(),
            item.target.clone(),
        );
        // Link the prepared job back to its release for the published inventory.
        let release_id: Uuid =
            sqlx::query_scalar("SELECT release_id FROM cloud_publication_jobs WHERE id = $1")
                .bind(item.job)
                .fetch_one(&mut **tx)
                .await?;
        let snapshot = SnapshotItem {
            release_id,
            publisher: item.publisher,
            namespace: item.namespace.clone(),
            plugin_id: item.plugin_id.clone(),
            version: item.version.clone(),
            target: item.target.clone(),
            sha256: item.sha256.clone(),
            size: item.size,
            key_id: item.key_id.clone(),
            public_key: item.public_key.clone(),
            object_key: item.prepared_key.clone(),
            version_id: item.prepared_version.clone(),
            job: Some(item.job),
        };
        let advisory = item.advisory.as_ref().map(|a| AdvisorySnapshot {
            severity: a.severity.clone(),
            message: a.message.clone(),
            url: a.url.clone(),
        });
        if merged.contains_key(&key) {
            return Err(
                "duplicate release identity across published and prepared inventory".into(),
            );
        }
        // A prepared job for an already-published release can only exist for
        // the same bytes; anything else is a conflict.
        merged.insert(key, (snapshot, advisory));
    }
    let inventory: Vec<_> = merged.into_values().collect();
    if inventory.is_empty() {
        return Err("nothing to publish".into());
    }
    let digest = inventory_digest(&inventory);
    Ok((inventory, dropped, candidate_id, digest))
}

#[derive(Debug)]
pub struct Published {
    pub id: Uuid,
    pub generation: i64,
    pub manifest_sha256: String,
    pub release_count: usize,
    pub file_count: usize,
    pub dropped: Vec<String>,
}

/// The readiness record plus the exact hashes it attests to.
struct Readiness {
    id: Uuid,
    inventory_sha256: String,
    manifest_sha256: String,
}

async fn latest_verified(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    candidate_id: Uuid,
) -> Result<Readiness> {
    let row = sqlx::query(
        "SELECT id, inventory_sha256, manifest_sha256 FROM cloud_snapshot_promotion_checks WHERE candidate_id = $1 AND decision = 'verified' ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(candidate_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or("no verified promotion-readiness record for this candidate")?;
    Ok(Readiness {
        id: row.get("id"),
        inventory_sha256: row.get("inventory_sha256"),
        manifest_sha256: row
            .get::<Option<String>, _>("manifest_sha256")
            .ok_or("verified readiness record carries no manifest hash")?,
    })
}

/// Trust documents must match the current seed baseline byte for byte;
/// anything else means trust rotated after verification.
fn check_seed_policy(candidate_dir: &Path, seed: &Path) -> Result<()> {
    for name in ["root.json", "keys.json", "keys.json.sig"] {
        let expected = snapshot_worker::read_file(&seed.join(name), false, 8 * 1024 * 1024)?;
        let actual = std::fs::read(candidate_dir.join(name))?;
        if expected != actual {
            return Err("candidate trust material is stale".into());
        }
    }
    let current: tiktools_plugin_registry::RegistryConfigDocument = serde_json::from_slice(
        &snapshot_worker::read_file(&seed.join("config.json"), false, 8 * 1024 * 1024)?,
    )
    .map_err(|_| "invalid seed registry policy")?;
    let built: tiktools_plugin_registry::RegistryConfigDocument =
        serde_json::from_slice(&std::fs::read(candidate_dir.join("config.json"))?)
            .map_err(|_| "invalid candidate registry policy")?;
    if current.protocol != built.protocol
        || current.name != built.name
        || current.revoked_digests != built.revoked_digests
    {
        return Err("candidate registry policy is stale".into());
    }
    Ok(())
}

/// Download every inventory artifact by pinned version, digest-check it, and
/// rescan it. The sink directory holds untrusted bytes until verification.
async fn fetch_inventory(
    store: &QuarantineStore,
    scanner: &crate::scanner::ClamAv,
    inventory: &[(SnapshotItem, Option<AdvisorySnapshot>)],
    dir: &Path,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::with_capacity(inventory.len());
    for (item, _) in inventory {
        let path = dir.join(format!("{}.plugin", item.release_id));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;
        store
            .download_version(
                &item.object_key,
                &ObjectVersion {
                    version_id: item.version_id.clone(),
                    size: item.size,
                },
                &item.sha256,
                &mut file,
            )
            .await
            .map_err(|e| format!("published artifact unreadable: {e}"))?;
        drop(file);
        if scanner.scan(&path, item.size as u64, &item.sha256).await != crate::scanner::Scan::Clean
        {
            return Err("published artifact antivirus scan did not pass".into());
        }
        paths.push(path);
    }
    Ok(paths)
}

fn snapshot_inputs<'a>(
    inventory: &'a [(SnapshotItem, Option<AdvisorySnapshot>)],
    paths: &'a [PathBuf],
    approved: &'a [TrustedKey],
) -> Result<Vec<cloud_snapshot::ReleaseInput<'a>>> {
    inventory
        .iter()
        .zip(paths)
        .zip(approved)
        .map(|(((item, advisory), path), key)| {
            Ok(cloud_snapshot::ReleaseInput {
                source: path,
                expected: cloud_verifier::ExpectedRelease {
                    namespace: &item.namespace,
                    plugin_id: &item.plugin_id,
                    version: &item.version,
                    target: &item.target,
                    sha256: &item.sha256,
                },
                approved_key: key,
                channel: item.channel()?,
                yanked: false,
                advisory: advisory_record(advisory)
                    .map(|record| {
                        record
                            .registry()
                            .map_err(|e| format!("invalid advisory record: {e}"))
                    })
                    .transpose()?,
            })
        })
        .collect()
}

/// Promote a verified candidate to a new immutable generation and activate it.
///
/// The candidate must still match the currently prepared inventory exactly
/// (same check the verifier runs); previously published releases are
/// re-authorized and carried over. Re-running for the same candidate is
/// idempotent: an already-active generation is returned, and an interrupted
/// staged generation is resumed, never duplicated.
/// Wrapper that audits every promotion outcome. Lock contention is not
/// recorded: the promotion holding the lock owns the outcome.
pub async fn publish(
    pool: &PgPool,
    store: &QuarantineStore,
    scanner: &crate::scanner::ClamAv,
    inputs: &snapshot_worker::Inputs,
    candidate_id: Uuid,
    operator: &str,
) -> Result<Published> {
    if !valid_operator(operator) {
        return Err("invalid operator label".into());
    }
    let mut recorded_gen: Option<i64> = None;
    let result = publish_inner(
        pool,
        store,
        scanner,
        inputs,
        candidate_id,
        operator,
        &mut recorded_gen,
    )
    .await;
    if let Err(error) = &result {
        let message = error.to_string();
        if message != "another registry promotion is running" {
            record_outcome(
                pool,
                recorded_gen,
                Some(candidate_id),
                if is_policy_refusal(&message) {
                    "blocked"
                } else {
                    "failed"
                },
                operator,
                &message,
            )
            .await;
        }
    }
    result
}

async fn publish_inner(
    pool: &PgPool,
    store: &QuarantineStore,
    scanner: &crate::scanner::ClamAv,
    inputs: &snapshot_worker::Inputs,
    candidate_id: Uuid,
    operator: &str,
    recorded_gen: &mut Option<i64>,
) -> Result<Published> {
    // --- Pre-checks: lock, candidate, readiness evidence, merged inventory.
    let (inventory, dropped, pre_digest, pre_manifest, readiness_id, active_id) = {
        let mut tx = pool.begin().await?;
        try_lock(&mut tx).await?;
        let candidate: Option<String> =
            sqlx::query_scalar("SELECT status FROM cloud_snapshot_candidates WHERE id = $1")
                .bind(candidate_id)
                .fetch_optional(&mut *tx)
                .await?;
        if candidate.as_deref() != Some("candidate") {
            return Err("candidate unavailable".into());
        }
        let readiness = latest_verified(&mut tx, candidate_id).await?;
        let (inventory, dropped, _, digest) = merged_inventory(&mut tx, candidate_id).await?;
        let manifest = snapshot_export::manifest(&mut tx, candidate_id).await?;
        if manifest.inventory != readiness.inventory_sha256
            || export_manifest_digest(&manifest)? != readiness.manifest_sha256
        {
            return Err("promotion-readiness record does not match the current manifest".into());
        }
        let active: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM cloud_registry_generations WHERE status='active' ORDER BY generation DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        (inventory, dropped, digest, manifest, readiness.id, active)
    };
    // Idempotent: the candidate already produced the active generation.
    if let Some(active) = active_id {
        let row = sqlx::query(
            "SELECT id, generation, manifest_sha256, release_count, file_count FROM cloud_registry_generations WHERE id = $1 AND status='active' AND candidate_id = $2 AND inventory_sha256 = $3",
        )
        .bind(active)
        .bind(candidate_id)
        .bind(&pre_digest)
        .fetch_optional(pool)
        .await?;
        if let Some(row) = row {
            return Ok(Published {
                id: row.get("id"),
                generation: row.get("generation"),
                manifest_sha256: row.get("manifest_sha256"),
                release_count: row.get::<i32, _>("release_count") as usize,
                file_count: row.get::<i32, _>("file_count") as usize,
                dropped,
            });
        }
    }
    // --- Resume or create the staged generation row first so every staged
    // --- file is enumerable for restart recovery and GC.
    let generation_id: Uuid = {
        let mut tx = pool.begin().await?;
        try_lock(&mut tx).await?;
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM cloud_registry_generations WHERE status='staged' AND candidate_id=$1 AND inventory_sha256=$2",
        )
        .bind(candidate_id)
        .bind(&pre_digest)
        .fetch_optional(&mut *tx)
        .await?;
        let id = match existing {
            Some(id) => id,
            None => {
                let id = Uuid::new_v4();
                sqlx::query("INSERT INTO cloud_registry_generations (id, generation, candidate_id, inventory_sha256, manifest_sha256, root_fingerprint, index_key_id, release_count, file_count, status) VALUES ($1, COALESCE((SELECT max(generation) FROM cloud_registry_generations), 0) + 1, $2, $3, '', $4, $5, $6, 0, 'staged')")
                    .bind(id).bind(candidate_id).bind(&pre_digest).bind(inputs.root.key.fingerprint()?.as_hex()).bind(inputs.index.public_key().key_id.as_str()).bind(inventory.len() as i32).execute(&mut *tx).await?;
                id
            }
        };
        let number: i64 =
            sqlx::query_scalar("SELECT generation FROM cloud_registry_generations WHERE id = $1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        *recorded_gen = Some(number);
        id
    };
    // --- Network and build phase (no locks held): fetch, scan, build,
    // --- revalidate against current pins, upload immutable files.
    let approved = inventory
        .iter()
        .map(|(item, _)| item.approved())
        .collect::<Result<Vec<_>>>()?;
    let source_dir = tempfile::Builder::new()
        .prefix("cloud-publish-input-")
        .tempdir()?;
    let paths = fetch_inventory(store, scanner, &inventory, source_dir.path()).await?;
    let worker_items: Vec<snapshot_worker::Item> = inventory
        .iter()
        .map(|(item, advisory)| item.worker_item(advisory_record(advisory)))
        .collect();
    let index_pub = inputs.index.public_key();
    let build_inventory = inventory.clone();
    let build_approved = approved.clone();
    let build_paths = paths.clone();
    let seed = inputs.seed.clone();
    let root = inputs.root.clone();
    // `SigningKey` carries private material and is intentionally not `Clone`;
    // re-materialize it for the blocking build task.
    let index = tiktools_plugin_package::SigningKey::from_json(&inputs.index.to_json())
        .map_err(|_| "invalid index signing key")?;
    let snapshot: cloud_snapshot::CandidateSnapshot = tokio::task::spawn_blocking(move || {
        let release_inputs = snapshot_inputs(&build_inventory, &build_paths, &build_approved)
            .map_err(|e| e.to_string())?;
        cloud_snapshot::build(&seed, &root, index, &release_inputs)
            .map_err(|e| format!("snapshot build failed: {e}"))
    })
    .await
    .map_err(|_| -> Box<dyn Error> { "snapshot build task failed".into() })?
    .map_err(|e| -> Box<dyn Error> { e.into() })?;
    // Authoritative checks on the staged tree: current seed policy, current
    // pins and delegations, exact inventory contents, then a rescan of every
    // artifact the index references.
    check_seed_policy(snapshot.path(), &inputs.seed)?;
    let refs: Vec<(&TrustedKey, &str)> = approved
        .iter()
        .zip(inventory.iter())
        .map(|(key, (item, _))| (key, item.plugin_id.as_str()))
        .collect();
    snapshot
        .revalidate(&inputs.root, &index_pub, &refs)
        .map_err(|e| format!("snapshot revalidation failed: {e}"))?;
    let scan_files =
        snapshot_verify::check_contents(snapshot.path(), &snapshot.files, &worker_items, &approved)
            .map_err(|e| format!("snapshot contents do not match inventory: {e}"))?;
    for (name, size, digest) in &scan_files {
        if scanner
            .scan(&snapshot.path().join(name), *size, digest)
            .await
            != crate::scanner::Scan::Clean
        {
            return Err("published snapshot antivirus scan did not pass".into());
        }
    }
    snapshot
        .revalidate(&inputs.root, &index_pub, &refs)
        .map_err(|e| format!("snapshot changed during verification: {e}"))?;
    // --- Stage immutable files. Already-recorded rows (from an interrupted
    // --- run) are reused after digest comparison, never re-uploaded.
    let recorded: BTreeMap<String, (String, String)> = sqlx::query(
        "SELECT path, object_key, version_id FROM cloud_registry_generation_files WHERE generation = (SELECT generation FROM cloud_registry_generations WHERE id = $1)",
    )
    .bind(generation_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| {
        (
            row.get::<String, _>("path"),
            (
                row.get::<String, _>("object_key"),
                row.get::<String, _>("version_id"),
            ),
        )
    })
    .collect();
    let mut staged: Vec<(String, String, i64, String, String)> = Vec::new();
    for (path, digest) in &snapshot.files {
        if let Some((key, version)) = recorded.get(path) {
            let size = i64::try_from(std::fs::metadata(snapshot.path().join(path))?.len())?;
            staged.push((
                path.clone(),
                digest.clone(),
                size,
                key.clone(),
                version.clone(),
            ));
            continue;
        }
        let full = snapshot.path().join(path);
        let size = i64::try_from(std::fs::metadata(&full)?.len())?;
        let (key, version) = store
            .stage_public_file(generation_id, &full, size, digest)
            .await
            .map_err(|e| format!("published file staging failed: {e}"))?;
        staged.push((path.clone(), digest.clone(), size, key, version.version_id));
    }
    let manifest_sha = manifest_digest(&snapshot.files);
    {
        let mut tx = pool.begin().await?;
        for (path, digest, size, key, version) in &staged {
            sqlx::query("INSERT INTO cloud_registry_generation_files (generation, path, sha256, size, object_key, version_id) VALUES ((SELECT generation FROM cloud_registry_generations WHERE id = $1), $2, $3, $4, $5, $6) ON CONFLICT (generation, path) DO NOTHING")
                .bind(generation_id).bind(path).bind(digest).bind(size).bind(key).bind(version).execute(&mut *tx).await?;
        }
        tx.commit().await?;
    }
    // --- Activation: recheck everything that could have changed during the
    // --- network and build phase, then flip the active pointer atomically.
    let generation = {
        let mut tx = pool.begin().await?;
        try_lock(&mut tx).await?;
        let (current_inventory, _, _, current_digest) =
            merged_inventory(&mut tx, candidate_id).await?;
        if current_digest != pre_digest || current_inventory.len() != inventory.len() {
            return Err("inventory changed during promotion".into());
        }
        let manifest = snapshot_export::manifest(&mut tx, candidate_id).await?;
        if manifest.inventory != pre_manifest.inventory
            || export_manifest_digest(&manifest)? != export_manifest_digest(&pre_manifest)?
        {
            return Err("candidate manifest changed during promotion".into());
        }
        let readiness = latest_verified(&mut tx, candidate_id).await?;
        if readiness.id != readiness_id {
            return Err("promotion-readiness changed during promotion".into());
        }
        let still_active: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM cloud_registry_generations WHERE status='active' ORDER BY generation DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        if still_active != active_id {
            return Err("active generation changed during promotion".into());
        }
        let row = sqlx::query(
            "SELECT generation FROM cloud_registry_generations WHERE id = $1 AND status='staged' FOR UPDATE",
        )
        .bind(generation_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or("staged generation missing")?;
        let generation: i64 = row.get("generation");
        // Point published releases at the immutable public copies (never at
        // staging originals): future generations rebuild from these pinned
        // versions, and staging originals become bounded-GC orphans.
        let mut public_by_digest: std::collections::HashMap<&str, (&str, &str)> =
            std::collections::HashMap::new();
        for (_, digest, _, key, version) in staged
            .iter()
            .filter(|(path, _, _, _, _)| path.starts_with("packages/"))
            .chain(staged.iter())
        {
            public_by_digest.entry(digest).or_insert((key, version));
        }
        for (item, advisory) in &inventory {
            let (object_key, version_id) = public_by_digest
                .get(item.sha256.as_str())
                .ok_or("published artifact missing from snapshot")?;
            sqlx::query("INSERT INTO cloud_registry_generation_releases (generation, plugin_id, version, target, release_id, sha256, size, object_key, version_id, advisory_severity, advisory_message, advisory_url) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (generation, plugin_id, version, target) DO NOTHING")
                .bind(generation).bind(&item.plugin_id).bind(&item.version).bind(&item.target).bind(item.release_id).bind(&item.sha256).bind(item.size).bind(object_key).bind(version_id)
                .bind(advisory.as_ref().map(|a| a.severity.clone())).bind(advisory.as_ref().map(|a| a.message.clone())).bind(advisory.as_ref().and_then(|a| a.url.clone()))
                .execute(&mut *tx).await?;
        }
        // Consume the prepared jobs this generation publishes so future
        // candidates only see new work; the staging pointer stays until GC
        // proves the public copies authoritative.
        let consumed: Vec<Uuid> = inventory.iter().filter_map(|(item, _)| item.job).collect();
        if !consumed.is_empty() {
            sqlx::query("UPDATE cloud_publication_jobs SET status='published' WHERE id = ANY($1)")
                .bind(&consumed)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "UPDATE cloud_registry_generations SET manifest_sha256=$2, file_count=$3 WHERE id=$1",
        )
        .bind(generation_id)
        .bind(&manifest_sha)
        .bind(snapshot.files.len() as i32)
        .execute(&mut *tx)
        .await?;
        if let Some(previous) = still_active {
            sqlx::query("UPDATE cloud_registry_generations SET status='superseded', superseded_by=$2 WHERE id=$1")
                .bind(previous).bind(generation).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE cloud_registry_generations SET status='active', activated_at=now(), activated_by=$2, superseded_by=NULL WHERE id=$1")
            .bind(generation_id).bind(operator).execute(&mut *tx).await?;
        let mut reason = match still_active {
            Some(previous) => {
                let previous_generation: i64 = sqlx::query_scalar(
                    "SELECT generation FROM cloud_registry_generations WHERE id = $1",
                )
                .bind(previous)
                .fetch_one(&mut *tx)
                .await?;
                format!(
                    "promoted candidate {candidate_id} to generation {generation} (supersedes {previous_generation}; {} releases, {} files)",
                    inventory.len(),
                    snapshot.files.len()
                )
            }
            None => format!(
                "promoted candidate {candidate_id} to generation {generation} ({} releases, {} files)",
                inventory.len(),
                snapshot.files.len()
            ),
        };
        if !dropped.is_empty() {
            reason.push_str("; dropped across generations: ");
            reason.push_str(&dropped.join(", "));
        }
        truncate_reason(&mut reason);
        sqlx::query("INSERT INTO cloud_registry_promotions (id, generation, candidate_id, decision, operator, reason) VALUES ($1,$2,$3,'promoted',$4,$5)")
            .bind(Uuid::new_v4()).bind(generation).bind(candidate_id).bind(operator).bind(&reason).execute(&mut *tx).await?;
        audit(&mut tx, operator, generation_id, "registry.promoted").await?;
        tx.commit().await?;
        generation
    };
    Ok(Published {
        id: generation_id,
        generation,
        manifest_sha256: manifest_sha,
        release_count: inventory.len(),
        file_count: snapshot.files.len(),
        dropped,
    })
}

#[derive(Debug)]
pub struct RolledBack {
    pub id: Uuid,
    pub generation: i64,
    pub previous: i64,
}

/// Roll back to a previously live generation. The target is re-downloaded by
/// pinned version, digest-checked, signature-revalidated against the CURRENT
/// pins, contents-checked, and rescanned; current publisher/key authorization,
/// yanks, and advisories are rechecked. Anything stale or revoked refuses the
/// rollback instead of restoring it; rebuild and promote a corrected
/// generation in that case.
/// Wrapper that audits every rollback outcome except lock contention.
#[allow(clippy::too_many_arguments)]
pub async fn rollback(
    pool: &PgPool,
    store: &QuarantineStore,
    scanner: &crate::scanner::ClamAv,
    seed: &Path,
    root: &TrustedKey,
    index: &tiktools_plugin_package::PublicKey,
    generation: i64,
    operator: &str,
) -> Result<RolledBack> {
    if !valid_operator(operator) {
        return Err("invalid operator label".into());
    }
    if generation < 1 {
        return Err("unknown generation".into());
    }
    let result = rollback_inner(
        pool, store, scanner, seed, root, index, generation, operator,
    )
    .await;
    if let Err(error) = &result {
        let message = error.to_string();
        if message != "another registry promotion is running" {
            let candidate: Option<Uuid> = sqlx::query_scalar(
                "SELECT candidate_id FROM cloud_registry_generations WHERE generation = $1",
            )
            .bind(generation)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
            record_outcome(
                pool,
                Some(generation),
                candidate,
                if is_policy_refusal(&message) {
                    "blocked"
                } else {
                    "failed"
                },
                operator,
                &message,
            )
            .await;
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn rollback_inner(
    pool: &PgPool,
    store: &QuarantineStore,
    scanner: &crate::scanner::ClamAv,
    seed: &Path,
    root: &TrustedKey,
    index: &tiktools_plugin_package::PublicKey,
    generation: i64,
    operator: &str,
) -> Result<RolledBack> {
    // --- Lock and load the target plus current security state.
    let (target_id, candidate_id, files, items, approved) = {
        let mut tx = pool.begin().await?;
        try_lock(&mut tx).await?;
        let row = sqlx::query(
            "SELECT id, candidate_id, status FROM cloud_registry_generations WHERE generation = $1",
        )
        .bind(generation)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or("unknown generation")?;
        let status: String = row.get("status");
        if status == "active" {
            tx.commit().await?;
            let previous: i64 = generation;
            return Ok(RolledBack {
                id: row.get("id"),
                generation,
                previous,
            });
        }
        if status != "superseded" && status != "rolled_back" {
            return Err("only a previously live generation can be restored".into());
        }
        let target_id: Uuid = row.get("id");
        let candidate_id: Uuid = row.get("candidate_id");
        let release_rows = sqlx::query(
            "SELECT r.id AS release_id, r.publisher_id, p.namespace, r.plugin_id, r.version, r.target, r.status AS release_status, u.status AS upload_status, k.status AS key_status, k.key_id, k.public_key, k.fingerprint, v.status AS verification_status, v.result_class AS verification_result, m.decision AS moderation_decision, (y.release_id IS NOT NULL) AS yanked, a.severity AS advisory_severity, a.message AS advisory_message, a.url AS advisory_url, g.advisory_severity AS stored_severity, g.advisory_message AS stored_message, g.advisory_url AS stored_url, g.sha256, g.size FROM cloud_registry_generation_releases g JOIN cloud_plugin_releases r ON r.id = g.release_id JOIN cloud_publishers p ON p.id = r.publisher_id JOIN cloud_upload_sessions u ON u.id = r.upload_id AND u.publisher_id = r.publisher_id JOIN cloud_publisher_keys k ON k.id = r.publisher_key_id AND k.publisher_id = r.publisher_id LEFT JOIN cloud_verification_jobs v ON v.upload_id = u.id AND v.release_id = r.id LEFT JOIN cloud_moderation_events m ON m.release_id = r.id LEFT JOIN cloud_release_yanks y ON y.release_id = r.id LEFT JOIN cloud_release_advisories a ON a.release_id = r.id WHERE g.generation = $1",
        )
        .bind(generation)
        .fetch_all(&mut *tx)
        .await?;
        if release_rows.is_empty() {
            return Err("generation has no releases".into());
        }
        let mut items = Vec::with_capacity(release_rows.len());
        let mut approved_keys = Vec::with_capacity(release_rows.len());
        for row in release_rows {
            let namespace: String = row.get("namespace");
            let snapshot = SnapshotItem {
                release_id: row.get("release_id"),
                publisher: row.get("publisher_id"),
                namespace: namespace.clone(),
                plugin_id: row.get("plugin_id"),
                version: row.get("version"),
                target: row.get("target"),
                sha256: row.get("sha256"),
                size: row.get("size"),
                key_id: row.get("key_id"),
                public_key: row.get("public_key"),
                object_key: String::new(),
                version_id: String::new(),
                job: None,
            };
            let trusted = snapshot
                .approved()
                .map_err(|_| "stored publisher key invalid")?;
            if trusted
                .key
                .fingerprint()
                .map_err(|_| "stored key fingerprint invalid")?
                .as_hex()
                != row.get::<String, _>("fingerprint")
            {
                return Err("stored publisher key fingerprint mismatch".into());
            }
            // Current state must still authorize every release, and the
            // current advisory must equal the published one.
            let current = AdvisorySnapshot {
                severity: row
                    .get::<Option<String>, _>("advisory_severity")
                    .unwrap_or_default(),
                message: row
                    .get::<Option<String>, _>("advisory_message")
                    .unwrap_or_default(),
                url: row.get("advisory_url"),
            };
            let stored = AdvisorySnapshot {
                severity: row
                    .get::<Option<String>, _>("stored_severity")
                    .unwrap_or_default(),
                message: row
                    .get::<Option<String>, _>("stored_message")
                    .unwrap_or_default(),
                url: row.get("stored_url"),
            };
            let current_set = row.get::<Option<String>, _>("advisory_severity").is_some();
            let stored_set = row.get::<Option<String>, _>("stored_severity").is_some();
            if current_set != stored_set || (current_set && current != stored) {
                return Err("current advisory state differs from the published generation".into());
            }
            let authorized = row.get::<String, _>("release_status") == "review_approved"
                && row.get::<String, _>("upload_status") == "quarantined"
                && row
                    .get::<Option<String>, _>("verification_status")
                    .as_deref()
                    == Some("antivirus_passed")
                && row
                    .get::<Option<String>, _>("verification_result")
                    .as_deref()
                    == Some("antivirus_passed")
                && row
                    .get::<Option<String>, _>("moderation_decision")
                    .as_deref()
                    == Some("approve")
                && row.get::<Option<String>, _>("key_status").as_deref() == Some("approved")
                && !row.get::<bool, _>("yanked");
            let publisher_ok: bool = sqlx::query_scalar(
                "SELECT status = 'approved' FROM cloud_publishers WHERE id = $1",
            )
            .bind(snapshot.publisher)
            .fetch_one(&mut *tx)
            .await?;
            if !authorized || !publisher_ok {
                return Err("a published release is no longer authorized".into());
            }
            let advisory = if stored_set { Some(stored) } else { None };
            approved_keys.push(trusted);
            items.push((snapshot, advisory));
        }
        let file_rows = sqlx::query(
            "SELECT path, sha256, size, object_key, version_id FROM cloud_registry_generation_files WHERE generation = $1",
        )
        .bind(generation)
        .fetch_all(&mut *tx)
        .await?;
        if file_rows.is_empty() {
            return Err("generation has no files".into());
        }
        let files: Vec<(String, String, i64, String, String)> = file_rows
            .into_iter()
            .map(|row| {
                (
                    row.get("path"),
                    row.get("sha256"),
                    row.get("size"),
                    row.get("object_key"),
                    row.get("version_id"),
                )
            })
            .collect();
        tx.commit().await?;
        (target_id, candidate_id, files, items, approved_keys)
    };
    // --- Re-download every file by pinned version and recheck everything
    // --- against current trust and security state (no locks held).
    let dir = tempfile::Builder::new()
        .prefix("cloud-rollback-check-")
        .tempdir()?;
    let mut file_map = BTreeMap::new();
    for (path, digest, size, key, version) in &files {
        if path.contains('\\')
            || Path::new(path)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("invalid published path".into());
        }
        let dest = dir.path().join(path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
            .await?;
        store
            .download_version(
                key,
                &ObjectVersion {
                    version_id: version.clone(),
                    size: *size,
                },
                digest,
                &mut out,
            )
            .await
            .map_err(|e| format!("published file unreadable: {e}"))?;
        drop(out);
        if path.starts_with("packages/") {
            let stored_size: i64 = files
                .iter()
                .find(|(p, _, _, _, _)| p == path)
                .map(|(_, _, size, _, _)| *size)
                .unwrap_or(0);
            if scanner.scan(&dest, stored_size as u64, digest).await != crate::scanner::Scan::Clean
            {
                return Err("published artifact antivirus scan did not pass".into());
            }
        }
        file_map.insert(path.clone(), digest.clone());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock error")?
        .as_secs();
    if root.revoked || !root.is_valid_at(now) {
        return Err("current root pin is not valid".into());
    }
    check_seed_policy(dir.path(), seed)?;
    // Refuse to restore artifacts the current policy revokes.
    let seed_config: tiktools_plugin_registry::RegistryConfigDocument = serde_json::from_slice(
        &snapshot_worker::read_file(&seed.join("config.json"), false, 8 * 1024 * 1024)?,
    )
    .map_err(|_| "invalid seed registry policy")?;
    if items.iter().any(|(item, _)| {
        seed_config
            .revoked_digests
            .iter()
            .any(|digest| digest == &item.sha256)
    }) {
        return Err("a published artifact is revoked by current policy".into());
    }
    let refs: Vec<(&TrustedKey, &str)> = approved
        .iter()
        .zip(items.iter())
        .map(|(key, (item, _))| (key, item.plugin_id.as_str()))
        .collect();
    cloud_snapshot::revalidate_tree(dir.path(), &file_map, root, index, &refs)
        .map_err(|e| format!("rollback snapshot revalidation failed: {e}"))?;
    let worker_items: Vec<snapshot_worker::Item> = items
        .iter()
        .map(|(item, advisory)| {
            let mut worker = item.worker_item(advisory_record(advisory));
            worker.prepared_key = String::new();
            worker.prepared_version = String::new();
            worker
        })
        .collect();
    snapshot_verify::check_contents(dir.path(), &file_map, &worker_items, &approved)
        .map_err(|e| format!("rollback contents do not match inventory: {e}"))?;
    // --- Flip the active pointer atomically.
    let previous = {
        let mut tx = pool.begin().await?;
        try_lock(&mut tx).await?;
        let current: Option<(Uuid, i64)> = sqlx::query_as(
            "SELECT id, generation FROM cloud_registry_generations WHERE status='active' ORDER BY generation DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some((current_id, current_generation)) = current else {
            return Err("no active generation".into());
        };
        if current_generation == generation {
            tx.commit().await?;
            return Ok(RolledBack {
                id: target_id,
                generation,
                previous: generation,
            });
        }
        sqlx::query("SELECT id FROM cloud_registry_generations WHERE id=$1 AND status IN ('superseded','rolled_back') FOR UPDATE")
            .bind(target_id).fetch_optional(&mut *tx).await?.ok_or("rollback target changed")?;
        sqlx::query(
            "UPDATE cloud_registry_generations SET status='superseded', superseded_by=$2 WHERE id=$1",
        )
        .bind(current_id)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE cloud_registry_generations SET status='active', activated_at=now(), activated_by=$2, superseded_by=NULL WHERE id=$1")
            .bind(target_id).bind(operator).execute(&mut *tx).await?;
        let mut reason =
            format!("rolled back from generation {current_generation} to generation {generation}");
        truncate_reason(&mut reason);
        sqlx::query("INSERT INTO cloud_registry_promotions (id, generation, candidate_id, decision, operator, reason) VALUES ($1,$2,$3,'rolled_back',$4,$5)")
            .bind(Uuid::new_v4()).bind(generation).bind(candidate_id).bind(operator).bind(&reason).execute(&mut *tx).await?;
        audit(&mut tx, operator, target_id, "registry.rolled_back").await?;
        tx.commit().await?;
        current_generation
    };
    Ok(RolledBack {
        id: target_id,
        generation,
        previous,
    })
}

#[derive(Debug, Default)]
pub struct GcReport {
    pub deleted_files: usize,
    pub deleted_generations: usize,
    pub deleted_candidate_files: usize,
    pub deleted_prepared: usize,
}

/// Bounded collection of orphaned private artifacts: files of staged
/// generations that never activated and are older than one hour, plus staged
/// candidate files whose candidate already produced an active generation.
/// Files of live, superseded, or rolled-back generations are never touched:
/// superseded generations are the rollback targets.
pub async fn gc(
    pool: &PgPool,
    store: &QuarantineStore,
    limit: i64,
    operator: &str,
) -> Result<GcReport> {
    if !valid_operator(operator) {
        return Err("invalid operator label".into());
    }
    if !(1..=GC_MAX).contains(&limit) {
        return Err("gc limit must be between 1 and 1000".into());
    }
    let mut report = GcReport::default();
    let mut remaining = limit;
    let mut tx = pool.begin().await?;
    try_lock(&mut tx).await?;
    // Crash leftovers first: staged generations older than one hour. An
    // in-progress promotion holds no lock across its network phase, so a
    // staged row younger than that may still resume.
    let staged: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, generation FROM cloud_registry_generations WHERE status='staged' AND created_at < now() - make_interval(secs => $1) ORDER BY created_at LIMIT 100",
    )
    .bind(STALE_STAGED_SECS)
    .fetch_all(&mut *tx)
    .await?;
    let mut staged_files: Vec<(String, String, Uuid)> = Vec::new();
    for (id, generation) in &staged {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT object_key, version_id FROM cloud_registry_generation_files WHERE generation = $1",
        )
        .bind(generation)
        .fetch_all(&mut *tx)
        .await?;
        for (key, version) in rows {
            if remaining <= 0 {
                break;
            }
            remaining -= 1;
            staged_files.push((key, version, *id));
        }
    }
    tx.commit().await?;
    for (key, version, id) in staged_files {
        match store.delete_version(&key, &version).await {
            Ok(()) => report.deleted_files += 1,
            Err(_) => continue,
        }
        sqlx::query(
            "DELETE FROM cloud_registry_generation_files WHERE object_key = $1 AND version_id = $2",
        )
        .bind(&key)
        .bind(&version)
        .execute(pool)
        .await?;
        let _ = id;
    }
    // Drop staged generations whose files are all gone.
    let mut tx = pool.begin().await?;
    try_lock(&mut tx).await?;
    let orphans: Vec<Uuid> = sqlx::query_scalar(
        "SELECT g.id FROM cloud_registry_generations g LEFT JOIN cloud_registry_generation_files f ON f.generation = g.generation WHERE g.status='staged' AND g.created_at < now() - make_interval(secs => $1) AND f.generation IS NULL",
    )
    .bind(STALE_STAGED_SECS)
    .fetch_all(&mut *tx)
    .await?;
    for id in orphans {
        sqlx::query("DELETE FROM cloud_registry_generations WHERE id = $1 AND status='staged'")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        report.deleted_generations += 1;
    }
    // Candidate staging files are redundant once their candidate produced an
    // active generation: the immutable published copies are authoritative.
    let published: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT p.candidate_id FROM cloud_registry_promotions p JOIN cloud_registry_generations g ON g.generation = p.generation WHERE p.decision='promoted' AND p.candidate_id IS NOT NULL AND g.status IN ('active','superseded','rolled_back')",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut candidate_files: Vec<(String, String)> = Vec::new();
    for candidate in published {
        if remaining <= 0 {
            break;
        }
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT object_key, version_id FROM cloud_snapshot_candidate_files WHERE candidate_id = $1 LIMIT $2",
        )
        .bind(candidate)
        .bind(remaining)
        .fetch_all(&mut *tx)
        .await?;
        remaining -= rows.len() as i64;
        candidate_files.extend(rows);
    }
    tx.commit().await?;
    for (key, version) in candidate_files {
        match store.delete_version(&key, &version).await {
            Ok(()) => report.deleted_candidate_files += 1,
            Err(_) => continue,
        }
        sqlx::query(
            "DELETE FROM cloud_snapshot_candidate_files WHERE object_key = $1 AND version_id = $2",
        )
        .bind(&key)
        .bind(&version)
        .execute(pool)
        .await?;
    }
    // Prepared staging originals of consumed jobs: orphaned once their bytes
    // are published, since generations rebuild from the public copies.
    let mut tx = pool.begin().await?;
    try_lock(&mut tx).await?;
    let staged_jobs: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
        "SELECT id, prepared_key, prepared_version_id FROM cloud_publication_jobs WHERE status='published' AND prepared_key IS NOT NULL AND created_at < now() - make_interval(secs => $1) LIMIT $2",
    )
    .bind(STALE_STAGED_SECS)
    .bind(remaining.max(0))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    for (id, key, version) in staged_jobs {
        match store.delete_version(&key, &version).await {
            Ok(()) => report.deleted_prepared += 1,
            Err(_) => continue,
        }
        sqlx::query("UPDATE cloud_publication_jobs SET prepared_key=NULL, prepared_version_id=NULL WHERE id=$1 AND status='published'")
            .bind(id).execute(pool).await?;
    }
    let mut tx = pool.begin().await?;
    let mut reason = format!(
        "registry gc deleted {} staged files, {} staged generations, {} published candidate files, {} consumed staging originals",
        report.deleted_files,
        report.deleted_generations,
        report.deleted_candidate_files,
        report.deleted_prepared
    );
    truncate_reason(&mut reason);
    sqlx::query("INSERT INTO cloud_audit_events(id,actor_user_id,action) VALUES($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(format!("operator:{operator}"))
        .bind(format!("registry.gc: {reason}"))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(report)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationView {
    pub id: Uuid,
    pub generation: i64,
    pub candidate_id: Uuid,
    pub inventory_sha256: String,
    pub manifest_sha256: Option<String>,
    pub root_fingerprint: String,
    pub index_key_id: String,
    pub release_count: i32,
    pub file_count: i32,
    pub status: String,
    pub created_at: String,
    pub activated_at: Option<String>,
    pub activated_by: Option<String>,
    pub superseded_by: Option<i64>,
}

/// Newest generation first. Evidence for operators, not authorization.
pub async fn list(pool: &PgPool) -> Result<Vec<GenerationView>> {
    let rows = sqlx::query(
        "SELECT id, generation, candidate_id, inventory_sha256, manifest_sha256, root_fingerprint, index_key_id, release_count, file_count, status, to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at, to_char(activated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS activated_at, activated_by, superseded_by FROM cloud_registry_generations ORDER BY generation DESC LIMIT 100",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| GenerationView {
            id: row.get("id"),
            generation: row.get("generation"),
            candidate_id: row.get("candidate_id"),
            inventory_sha256: row.get("inventory_sha256"),
            manifest_sha256: row.get("manifest_sha256"),
            root_fingerprint: row.get("root_fingerprint"),
            index_key_id: row.get("index_key_id"),
            release_count: row.get("release_count"),
            file_count: row.get("file_count"),
            status: row.get("status"),
            created_at: row.get("created_at"),
            activated_at: row.get("activated_at"),
            activated_by: row.get("activated_by"),
            superseded_by: row.get("superseded_by"),
        })
        .collect())
}

fn public_db(_: sqlx::Error) -> StatusCode {
    tracing::error!("registry serving database operation failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// The atomic snapshot pointer the v1 protocol lacks: which immutable
/// generation clients must read. Never cached.
pub async fn current(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
) -> std::result::Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    let row = sqlx::query(
        "SELECT generation, inventory_sha256, manifest_sha256, root_fingerprint, index_key_id, release_count, file_count, activated_at FROM cloud_registry_generations WHERE status='active' ORDER BY generation DESC LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(public_db)?
    .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::json!({
        "generation": row.get::<i64, _>("generation"),
        "inventorySha256": row.get::<String, _>("inventory_sha256"),
        "manifestSha256": row.get::<String, _>("manifest_sha256"),
        "rootFingerprint": row.get::<String, _>("root_fingerprint"),
        "indexKeyId": row.get::<String, _>("index_key_id"),
        "releaseCount": row.get::<i32, _>("release_count"),
        "fileCount": row.get::<i32, _>("file_count"),
        "activatedAt": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("activated_at"),
    })))
}

/// Serve one immutable file from its pinned version. Generation-scoped and
/// content-addressed, safe to cache forever; clients that pin the generation
/// from `/current` first can never observe a mixed snapshot.
pub async fn file(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    axum::extract::Path((generation, path)): axum::extract::Path<(i64, String)>,
) -> std::result::Result<axum::response::Response, axum::http::StatusCode> {
    if generation < 1
        || path.len() > 2048
        || path.contains('\\')
        || Path::new(&path)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let store = state
        .object_storage
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let row = sqlx::query(
        "SELECT object_key, version_id, sha256, size FROM cloud_registry_generation_files WHERE generation = $1 AND path = $2",
    )
    .bind(generation)
    .bind(&path)
    .fetch_optional(&state.pool)
    .await
    .map_err(public_db)?
    .ok_or(StatusCode::NOT_FOUND)?;
    let size: i64 = row.get("size");
    if !(1..=cloud_storage::MAX_ARTIFACT_SIZE).contains(&size) {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let digest: String = row.get("sha256");
    let mut body: Vec<u8> = Vec::new();
    store
        .download_version(
            &row.get::<String, _>("object_key"),
            &ObjectVersion {
                version_id: row.get("version_id"),
                size,
            },
            &digest,
            &mut body,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let content_type = if path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    };
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::ETAG,
        header::HeaderValue::from_str(&format!("\"{digest}\""))
            .unwrap_or(header::HeaderValue::from_static("\"registry\"")),
    );
    Ok((headers, body).into_response())
}
