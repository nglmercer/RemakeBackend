//! Build and privately stage an initial candidate. No deployment or public pointer is changed.
use crate::scanner::{ClamAv, Scan};
use base64::{engine::general_purpose::STANDARD, Engine};
use cloud_snapshot::{CandidateSnapshot, ReleaseInput};
use cloud_storage::{ObjectVersion, QuarantineStore};
use cloud_verifier::ExpectedRelease;
use serde::Serialize;
use sqlx::{PgConnection, PgPool, Row};
use std::{
    error::Error,
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use tiktools_plugin_api::manifest::parse_version;
use tiktools_plugin_package::{KeyId, KeyRole, PublicKey, Sha256Digest, SigningKey, TrustedKey};
use tiktools_plugin_registry::{Advisory, AdvisorySeverity};
use uuid::Uuid;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

// Contains signing key material: no Debug or serialization.
pub struct Inputs {
    pub seed: PathBuf,
    pub root: TrustedKey,
    pub index: SigningKey,
}
pub(crate) fn read_file(path: &Path, secret: bool, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > limit {
        return Err("invalid snapshot input file".into());
    }
    let file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > limit {
        return Err("invalid snapshot input file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.dev() != opened.dev() || meta.ino() != opened.ino() {
            return Err("snapshot input changed during open".into());
        }
        if secret && opened.permissions().mode() & 0o077 != 0 {
            return Err("index key file must be private".into());
        }
    }
    #[cfg(not(unix))]
    if secret {
        return Err("index key permissions cannot be verified on this platform".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("invalid snapshot input file".into());
    }
    Ok(bytes)
}
pub fn inputs_from_env() -> Result<Inputs> {
    let seed = PathBuf::from(std::env::var("SNAPSHOT_SEED_DIR")?);
    let root_path = PathBuf::from(std::env::var("SNAPSHOT_ROOT_PIN_FILE")?);
    let index_path = PathBuf::from(std::env::var("SNAPSHOT_INDEX_KEY_FILE")?);
    let root: TrustedKey = serde_json::from_slice(&read_file(&root_path, false, 16384)?)
        .map_err(|_| "invalid root pin")?;
    let index = SigningKey::from_json(&read_file(&index_path, true, 16384)?)
        .map_err(|_| "invalid index signing key")?;
    Ok(Inputs { seed, root, index })
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Item {
    pub(crate) job: Uuid,
    pub(crate) publisher: Uuid,
    pub(crate) namespace: String,
    pub(crate) plugin_id: String,
    pub(crate) version: String,
    pub(crate) target: String,
    pub(crate) sha256: String,
    pub(crate) size: i64,
    pub(crate) prepared_key: String,
    pub(crate) prepared_version: String,
    pub(crate) key_id: String,
    pub(crate) public_key: String,
    pub(crate) requester: String,
    pub(crate) revisions: Vec<String>,
    pub(crate) advisory: Option<AdvisoryRecord>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct AdvisoryRecord {
    pub(crate) severity: String,
    pub(crate) message: String,
    pub(crate) url: Option<String>,
}
impl AdvisoryRecord {
    pub(crate) fn registry(&self) -> Result<Advisory> {
        let severity = match self.severity.as_str() {
            "low" => AdvisorySeverity::Low,
            "moderate" => AdvisorySeverity::Moderate,
            "high" => AdvisorySeverity::High,
            "critical" => AdvisorySeverity::Critical,
            _ => return Err("unknown advisory severity".into()),
        };
        Ok(Advisory {
            severity,
            message: self.message.clone(),
            url: self.url.clone(),
        })
    }
}
impl Item {
    pub(crate) fn approved(&self) -> Result<TrustedKey> {
        let raw = STANDARD.decode(&self.public_key)?;
        if STANDARD.encode(&raw) != self.public_key {
            return Err("noncanonical publisher key".into());
        }
        let key = PublicKey::new(KeyId::parse(&self.key_id)?, &raw)?;
        Ok(TrustedKey::new(key, KeyRole::Publisher).publisher(&self.namespace))
    }
}
// One SQL statement takes a point-in-time view and includes every prepared job.
// Never filter invalid prepared jobs away: any invalid row blocks the candidate.
pub(crate) async fn capture(conn: &mut PgConnection) -> Result<Vec<Item>> {
    let rows=sqlx::query("SELECT q.id AS job,q.prepared_key,q.prepared_version_id,q.requested_by AS requester,r.publisher_id,r.plugin_id,r.version,r.target,p.namespace,u.expected_sha256,u.expected_size,k.key_id,k.public_key,k.fingerprint,a.severity AS advisory_severity,a.message AS advisory_message,a.url AS advisory_url,q.xmin::text AS qrev,r.xmin::text AS rrev,p.xmin::text AS prev,u.xmin::text AS urev,k.xmin::text AS krev,v.xmin::text AS vrev,m.xmin::text AS mrev,COALESCE(a.xmin::text,'') AS arev,COALESCE((SELECT string_agg(a.role||':'||a.xmin::text,',' ORDER BY a.role) FROM cloud_account_roles a WHERE a.user_id=q.requested_by AND a.role IN ('admin','moderator')),'') AS roles,COALESCE(q.result_class='prepared' AND p.status='approved' AND k.status='approved' AND r.status='review_approved' AND u.status='quarantined' AND v.status='antivirus_passed' AND v.result_class='antivirus_passed' AND m.decision='approve' AND y.release_id IS NULL AND q.requested_by<>r.requested_by AND q.requested_by<>u.requested_by AND q.requested_by<>k.requested_by AND EXISTS(SELECT 1 FROM cloud_account_roles a WHERE a.user_id=q.requested_by AND a.role IN ('admin','moderator')) AND NOT EXISTS(SELECT 1 FROM cloud_publisher_memberships x WHERE x.publisher_id=r.publisher_id AND x.user_id=q.requested_by),false) AS authorized FROM cloud_publication_jobs q JOIN cloud_plugin_releases r ON r.id=q.release_id JOIN cloud_publishers p ON p.id=r.publisher_id JOIN cloud_upload_sessions u ON u.id=r.upload_id AND u.publisher_id=r.publisher_id JOIN cloud_publisher_keys k ON k.id=r.publisher_key_id AND k.publisher_id=r.publisher_id LEFT JOIN cloud_verification_jobs v ON v.upload_id=u.id AND v.release_id=r.id LEFT JOIN cloud_moderation_events m ON m.release_id=r.id LEFT JOIN cloud_release_yanks y ON y.release_id=r.id LEFT JOIN cloud_release_advisories a ON a.release_id=r.id WHERE q.status='prepared' ORDER BY q.id LIMIT 10001").fetch_all(&mut *conn).await?;
    if rows.len() > 10_000 {
        return Err("snapshot inventory exceeds limit".into());
    }
    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
        if !r.get::<bool, _>("authorized") {
            return Err("prepared release authorization changed".into());
        }
        let publisher: Uuid = r.get("publisher_id");
        let prepared_key: String = r.get("prepared_key");
        let prefix = format!("prepared/{publisher}/");
        let suffix = prepared_key
            .strip_prefix(&prefix)
            .ok_or("invalid prepared key")?;
        let attempt = Uuid::parse_str(suffix)?;
        if suffix != attempt.to_string() {
            return Err("invalid prepared key".into());
        }
        let version: String = r.get("prepared_version_id");
        if version.is_empty() || version == "null" || version.len() > 1024 {
            return Err("invalid prepared version".into());
        }
        let revisions = [
            "qrev", "rrev", "prev", "urev", "krev", "vrev", "mrev", "arev", "roles",
        ]
        .into_iter()
        .map(|n| r.try_get::<String, _>(n))
        .collect::<std::result::Result<Vec<_>, _>>()?;
        let advisory = match r.try_get::<Option<String>, _>("advisory_severity")? {
            Some(severity) => Some(AdvisoryRecord {
                severity,
                message: r
                    .try_get::<Option<String>, _>("advisory_message")?
                    .ok_or("advisory without message")?,
                url: r.try_get::<Option<String>, _>("advisory_url")?,
            }),
            None => None,
        };
        let item = Item {
            job: r.get("job"),
            publisher,
            namespace: r.get("namespace"),
            plugin_id: r.get("plugin_id"),
            version: r.get("version"),
            target: r.get("target"),
            sha256: r.get("expected_sha256"),
            size: r.get("expected_size"),
            prepared_key,
            prepared_version: version,
            key_id: r.get("key_id"),
            public_key: r.get("public_key"),
            requester: r.get("requester"),
            revisions,
            advisory,
        };
        if item.approved()?.key.fingerprint()?.as_hex() != r.get::<String, _>("fingerprint") {
            return Err("publisher fingerprint mismatch".into());
        }
        items.push(item);
    }
    Ok(items)
}
pub(crate) async fn current(pool: &PgPool) -> Result<Vec<Item>> {
    let mut connection = pool.acquire().await?;
    capture(&mut connection).await
}
struct StagedFile {
    path: String,
    sha256: String,
    size: i64,
    key: String,
    version: String,
}

pub async fn build(
    pool: &PgPool,
    store: &QuarantineStore,
    scanner: &ClamAv,
    inputs: Inputs,
) -> Result<Option<Uuid>> {
    // No previous public inventory, yanks, or advisories are modeled in Cloud yet.
    // Accept only a genuinely empty seed; this command is not a registry updater.
    for name in ["index", "packages", "catalog"] {
        match fs::symlink_metadata(inputs.seed.join(name)) {
            Ok(_) => return Err("initial snapshot requires an empty seed".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let config: serde_json::Value = serde_json::from_slice(&read_file(
        &inputs.seed.join("config.json"),
        false,
        8 * 1024 * 1024,
    )?)?;
    if config
        .get("catalogPages")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        != 0
    {
        return Err("initial snapshot requires an empty seed".into());
    }
    let inventory = current(pool).await?;
    if inventory.is_empty() {
        return Ok(None);
    }
    let source_dir = tempfile::Builder::new()
        .prefix("cloud-snapshot-input-")
        .tempdir()?;
    let mut paths = Vec::with_capacity(inventory.len());
    for item in &inventory {
        let path = source_dir.path().join(format!("{}.plugin", item.job));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;
        store
            .download_version(
                &item.prepared_key,
                &ObjectVersion {
                    version_id: item.prepared_version.clone(),
                    size: item.size,
                },
                &item.sha256,
                &mut file,
            )
            .await?;
        drop(file);
        if scanner.scan(&path, item.size as u64, &item.sha256).await != Scan::Clean {
            return Err("snapshot antivirus scan did not pass".into());
        }
        paths.push(path);
    }
    let approved = inventory
        .iter()
        .map(Item::approved)
        .collect::<Result<Vec<_>>>()?;
    let index_public = inputs.index.public_key();
    let root = inputs.root.clone();
    let build_inventory = inventory.clone();
    let build_approved = approved.clone();
    let seed = inputs.seed;
    let candidate: CandidateSnapshot = tokio::task::spawn_blocking(move || {
        let mut releases = Vec::with_capacity(build_inventory.len());
        for ((item, path), key) in build_inventory.iter().zip(&paths).zip(&build_approved) {
            let version = parse_version(&item.version).ok_or("invalid release version")?;
            releases.push(ReleaseInput {
                source: path,
                expected: ExpectedRelease {
                    namespace: &item.namespace,
                    plugin_id: &item.plugin_id,
                    version: &item.version,
                    target: &item.target,
                    sha256: &item.sha256,
                },
                approved_key: key,
                channel: if version.pre.is_empty() {
                    "stable"
                } else {
                    "beta"
                },
                yanked: false,
                advisory: item
                    .advisory
                    .as_ref()
                    .map(AdvisoryRecord::registry)
                    .transpose()
                    .map_err(|_| "invalid advisory record")?,
            });
        }
        cloud_snapshot::build(&seed, &root, inputs.index, &releases)
            .map_err(|_| "candidate build failed")
    })
    .await
    .map_err(|_| "candidate build task failed")??;
    // No prior published inventory is modeled yet; this is an initial private
    // candidate only. Yanked releases block the candidate; recorded advisories
    // are carried into the registry documents. Deployment must not consume
    // the candidate as-is.
    if current(pool).await? != inventory {
        return Err("snapshot inventory changed during build".into());
    }
    let candidate_id = Uuid::new_v4();
    let mut staged = Vec::with_capacity(candidate.files.len());
    for (path, digest) in &candidate.files {
        let full = candidate.path().join(path);
        let size = i64::try_from(fs::metadata(&full)?.len())?;
        let (key, version) = store
            .stage_verified(candidate_id, Uuid::new_v4(), &full, size, digest)
            .await?;
        staged.push(StagedFile {
            path: path.clone(),
            sha256: digest.clone(),
            size,
            key,
            version: version.version_id,
        });
    }
    let references: Vec<_> = approved
        .iter()
        .zip(&inventory)
        .map(|(key, item)| (key, item.plugin_id.as_str()))
        .collect();
    candidate
        .revalidate(&inputs.root, &index_public, &references)
        .map_err(|_| "candidate revalidation failed")?;
    let inventory_sha = Sha256Digest::of_bytes(&serde_json::to_vec(&inventory)?).to_string();
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    if capture(&mut tx).await? != inventory {
        return Err("snapshot inventory changed during staging".into());
    }
    sqlx::query("INSERT INTO cloud_snapshot_candidates (id,status,root_fingerprint,inventory_sha256,release_count,file_count) VALUES ($1,'candidate',$2,$3,$4,$5)")
        .bind(candidate_id).bind(inputs.root.key.fingerprint()?.to_string()).bind(inventory_sha).bind(inventory.len() as i32).bind(staged.len() as i32).execute(&mut *tx).await?;
    for item in &inventory {
        sqlx::query("INSERT INTO cloud_snapshot_candidate_releases (candidate_id,publication_job_id,prepared_key,prepared_version_id,sha256) VALUES ($1,$2,$3,$4,$5)")
        .bind(candidate_id).bind(item.job).bind(&item.prepared_key).bind(&item.prepared_version).bind(&item.sha256).execute(&mut *tx).await?;
    }
    for file in staged {
        sqlx::query("INSERT INTO cloud_snapshot_candidate_files (candidate_id,path,sha256,size,object_key,version_id) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(candidate_id).bind(file.path).bind(file.sha256).bind(file.size).bind(file.key).bind(file.version).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO cloud_audit_events (id,actor_user_id,subject_id,action) VALUES ($1,'system:snapshot-builder',$2,'snapshot.candidate_created')").bind(Uuid::new_v4()).bind(candidate_id).execute(&mut *tx).await?;
    candidate
        .revalidate(&inputs.root, &index_public, &references)
        .map_err(|_| "candidate revalidation failed")?;
    tx.commit().await?;
    Ok(Some(candidate_id))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn signing_inputs_require_private_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.json");
        fs::write(&key, b"secret").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_file(&key, true, 32).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_file(&key, true, 32).unwrap(), b"secret");
        assert!(read_file(&key, true, 3).is_err());
        let link = dir.path().join("link");
        symlink(&key, &link).unwrap();
        assert!(read_file(&link, true, 32).is_err());
    }
    #[test]
    fn advisory_records_map_to_registry_advisories() {
        use tiktools_plugin_registry::AdvisorySeverity;
        for (severity, expected) in [
            ("low", AdvisorySeverity::Low),
            ("moderate", AdvisorySeverity::Moderate),
            ("high", AdvisorySeverity::High),
            ("critical", AdvisorySeverity::Critical),
        ] {
            let record = AdvisoryRecord {
                severity: severity.into(),
                message: "upgrade now".into(),
                url: Some("https://example.test/a".into()),
            };
            let advisory = record.registry().unwrap();
            assert_eq!(advisory.severity, expected);
            assert_eq!(advisory.message, "upgrade now");
            assert_eq!(advisory.url.as_deref(), Some("https://example.test/a"));
        }
        let unknown = AdvisoryRecord {
            severity: "unknown".into(),
            message: "x".into(),
            url: None,
        };
        assert!(unknown.registry().is_err());
    }
}
