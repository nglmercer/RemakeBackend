//! Registry publication integration: initial and incremental publication,
//! promotion concurrency, authorization changes after readiness, revoked keys,
//! yanked releases and advisories, corrupt and forged artifacts, interrupted
//! uploads, atomic switching and caches, restart recovery, safe and unsafe
//! rollback, bounded GC, and real TikTools registry-client compatibility
//! (discover, download, signature verification, install, update).
//!
//! Run explicitly with CLOUD_TEST_DATABASE_URL; the tests apply upstream
//! migrations and drive a fake versioned S3 endpoint plus a fake ClamAV
//! INSTREAM server. Nothing here touches real storage, real scanners, or
//! production trust material.
use super::*;
use axum::{
    body::Body,
    extract::State,
    http::{header, Method, StatusCode, Uri},
    response::IntoResponse,
    Router,
};
use better_auth::email_password::{EmailPasswordService, SignUpInput};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tiktools_plugin_package::{KeyId, KeyRole, SigningKey, TrustedKey};
use tokio::sync::Mutex;
use tower::ServiceExt;

const ORIGIN: &str = "https://cloud.example.test";

async fn context(database_url: &str) -> (AuthContext, PgPool) {
    use better_auth::database::{SqlxDbAdapter, SqlxSecondaryStorage};
    use better_auth_core::{
        migration::SqlDialect,
        options::{AuthOptions, BaseUrl},
    };
    let adapter = Arc::new(SqlxDbAdapter::postgres(database_url).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(database_url).await.unwrap());
    let ctx = AuthContext::new(
        AuthOptions {
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            ..Default::default()
        },
        adapter.clone(),
        Some(secondary.clone()),
        vec![Arc::new(better_auth::UsernamePlugin)],
    )
    .unwrap();
    let mut attempts = 0;
    loop {
        attempts += 1;
        let auth_result = adapter
            .apply_migrations(&ctx.migration_plan(), SqlDialect::Postgres)
            .await;
        let secondary_result = match &auth_result {
            Ok(()) => secondary.migrate().await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        if secondary_result.is_ok() {
            break;
        }
        assert!(
            attempts < 20,
            "auth migrations did not converge: {}",
            secondary_result.unwrap_err()
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .unwrap();
    let mut attempts = 0;
    loop {
        attempts += 1;
        match readiness::MIGRATOR.run(&pool).await {
            Ok(()) => break,
            Err(e) if attempts < 20 => {
                let _ = e;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => panic!("cloud migrations did not converge: {e}"),
        }
    }
    (ctx, pool)
}

async fn user(ctx: &AuthContext) -> (String, String) {
    let result = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Registry Test".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    (
        result.user.id,
        format!("{}={}", result.cookie.name, result.cookie.value),
    )
}

/// Fake versioned object storage: versioning probes, versioned PUT/GET with
/// read-back digests, versioned DELETE, plus fault flags for tamper and
/// single-failure injection. Paths are matched by substring so bucket
/// prefixes do not matter, mirroring the existing fake-S3 tests.
type VersionedObjects = HashMap<String, Vec<(String, Vec<u8>)>>;

#[derive(Clone)]
struct FakeS3 {
    objects: Arc<Mutex<VersionedObjects>>,
    counter: Arc<AtomicU64>,
    tamper_read: Arc<AtomicBool>,
    fail_put_once: Arc<AtomicBool>,
    put_count: Arc<AtomicU64>,
}

impl FakeS3 {
    fn new() -> Self {
        Self {
            objects: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(AtomicU64::new(1)),
            tamper_read: Arc::new(AtomicBool::new(false)),
            fail_put_once: Arc::new(AtomicBool::new(false)),
            put_count: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn handler(
        State(state): State<FakeS3>,
        method: Method,
        uri: Uri,
        body: Body,
    ) -> axum::response::Response {
        let path = uri.path().to_owned();
        let query = uri.query().unwrap_or("").to_owned();
        if method == Method::GET && query.contains("versioning") {
            return ([(header::CONTENT_TYPE, "application/xml")], "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>").into_response();
        }
        let version = query
            .split('&')
            .find_map(|part| part.strip_prefix("versionId="))
            .unwrap_or("")
            .to_owned();
        if method == Method::PUT && (path.contains("/prepared/") || path.contains("/public/")) {
            // A hard 403 like an expired credential: the SDK does not retry
            // it, so the promotion fails exactly once and can resume.
            if state.fail_put_once.swap(false, Ordering::SeqCst) {
                return StatusCode::FORBIDDEN.into_response();
            }
            let bytes = axum::body::to_bytes(body, 200 * 1024 * 1024)
                .await
                .unwrap()
                .to_vec();
            let version = format!("v{}", state.counter.fetch_add(1, Ordering::SeqCst));
            state
                .objects
                .lock()
                .await
                .entry(path)
                .or_default()
                .push((version.clone(), bytes));
            state.put_count.fetch_add(1, Ordering::SeqCst);
            return (
                [(header::HeaderName::from_static("x-amz-version-id"), version)],
                "",
            )
                .into_response();
        }
        if method == Method::GET && !version.is_empty() {
            let objects = state.objects.lock().await;
            if let Some(versions) = objects.get(&path) {
                if let Some((_, bytes)) = versions.iter().find(|(v, _)| v == &version) {
                    let mut bytes = bytes.clone();
                    if state.tamper_read.load(Ordering::SeqCst)
                        && (path.contains("/prepared/") || path.contains("/public/"))
                        && !bytes.is_empty()
                    {
                        bytes[0] ^= 0xff;
                    }
                    return (
                        [(header::HeaderName::from_static("x-amz-version-id"), version)],
                        bytes,
                    )
                        .into_response();
                }
            }
            return StatusCode::NOT_FOUND.into_response();
        }
        if method == Method::DELETE && !version.is_empty() {
            let mut objects = state.objects.lock().await;
            if let Some(versions) = objects.get_mut(&path) {
                let before = versions.len();
                versions.retain(|(v, _)| v != &version);
                if versions.len() != before {
                    return StatusCode::NO_CONTENT.into_response();
                }
            }
            return StatusCode::NOT_FOUND.into_response();
        }
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn fake_s3() -> (FakeS3, String, tokio::task::JoinHandle<()>) {
    let state = FakeS3::new();
    let handle = state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(FakeS3::handler).with_state(state),
        )
        .await
        .unwrap();
    });
    (handle, endpoint, server)
}

/// Fake ClamAV INSTREAM server. Mirrors the existing test fake: reads chunked
/// input, then answers `stream: OK` (or an alert when infected is set).
#[derive(Clone)]
struct FakeClam {
    infected: Arc<AtomicBool>,
}

async fn fake_clam() -> (FakeClam, String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let state = FakeClam {
        infected: Arc::new(AtomicBool::new(false)),
    };
    let handle = state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let infected = state.infected.clone();
            tokio::spawn(async move {
                let mut command = [0u8; 10];
                if socket.read_exact(&mut command).await.is_err() {
                    return;
                }
                assert_eq!(&command, b"zINSTREAM\0");
                loop {
                    let mut size = [0u8; 4];
                    if socket.read_exact(&mut size).await.is_err() {
                        return;
                    }
                    let size = u32::from_be_bytes(size) as usize;
                    if size == 0 {
                        break;
                    }
                    let mut chunk = vec![0u8; size];
                    if socket.read_exact(&mut chunk).await.is_err() {
                        return;
                    }
                }
                let verdict = if infected.load(Ordering::SeqCst) {
                    "stream: Test FOUND\0"
                } else {
                    "stream: OK\0"
                };
                let _ = socket.write_all(verdict.as_bytes()).await;
            });
        }
    });
    (handle, addr, server)
}

fn scanner(addr: &str) -> crate::scanner::ClamAv {
    crate::scanner::ClamAv::new(addr.parse().unwrap())
}

/// Disposable staging trust: a root pin, a staged index key, and a seed
/// directory. Never production material; every test mints fresh keys.
struct Trust {
    seed: std::path::PathBuf,
    root: TrustedKey,
    index_json: Vec<u8>,
    index_pub: tiktools_plugin_package::PublicKey,
    #[allow(dead_code)]
    dir: tempfile::TempDir,
}

fn trust(namespace: &str, publisher: &SigningKey, standby: &[&SigningKey]) -> Trust {
    let dir = tempfile::Builder::new()
        .prefix("cloud-registry-test-")
        .tempdir()
        .unwrap();
    let seed = dir.path().join("seed");
    std::fs::create_dir(&seed).unwrap();
    let root = SigningKey::generate(KeyId::parse("root-one").unwrap(), None).unwrap();
    let index = SigningKey::generate(KeyId::parse("index-one").unwrap(), None).unwrap();
    let index_json = index.to_json();
    let index_pub = index.public_key();
    // The registry trust delegates the publisher namespace to every known
    // key; Cloud-side key revocation is the independent authorization layer
    // promotion rechecks. This mirrors rotated deployments.
    let mut delegations = vec![
        TrustedKey::new(index_pub.clone(), KeyRole::Index),
        TrustedKey::new(publisher.public_key(), KeyRole::Publisher).publisher(namespace),
    ];
    for key in standby {
        delegations
            .push(TrustedKey::new(key.public_key(), KeyRole::Publisher).publisher(namespace));
    }
    IndexWriter::open(&seed, "fixture", Some(index))
        .init(&root, delegations, None, None)
        .unwrap();
    Trust {
        seed,
        root: TrustedKey::new(root.public_key(), KeyRole::Root),
        index_json,
        index_pub,
        dir,
    }
}

fn inputs(t: &Trust) -> snapshot_worker::Inputs {
    snapshot_worker::Inputs {
        seed: t.seed.clone(),
        root: t.root.clone(),
        index: SigningKey::from_json(&t.index_json).unwrap(),
    }
}

fn publisher_key(namespace: &str) -> SigningKey {
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    SigningKey::generate(
        KeyId::parse(&format!("key-{suffix}")).unwrap(),
        Some(namespace.into()),
    )
    .unwrap()
}

/// Build and sign a real `.plugin` package with the TikTools devkit.
fn package(
    dir: &std::path::Path,
    signing: &SigningKey,
    namespace: &str,
    plugin_id: &str,
    version: &str,
) -> (std::path::PathBuf, String, i64) {
    use tiktools_plugin_package::{pack, sign_archive, PackRequest};
    let plugin_dir = dir.join(format!("{plugin_id}-{version}"));
    std::fs::create_dir_all(&plugin_dir).unwrap();
    let manifest_path = plugin_dir.join("tiktools.plugin.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"id":plugin_id,"name":plugin_id,"version":version,"runtime":"process","entry":"index.js","protocolVersion":1,"publisher":namespace,"description":"Registry publication integration fixture.","license":"MIT","engines":{"tiktools":">=0.4.0"},"categories":["audio"]})).unwrap(),
    )
    .unwrap();
    let entry_path = plugin_dir.join("index.js");
    std::fs::write(&entry_path, b"module.exports = {};").unwrap();
    let package_path = dir.join(format!("{plugin_id}-{version}.plugin"));
    pack(&PackRequest {
        manifest: manifest_path,
        entry: Some(entry_path),
        output: package_path.clone(),
        target: None,
    })
    .unwrap();
    sign_archive(&package_path, signing).unwrap();
    let digest = tiktools_plugin_package::Sha256Digest::of_file(&package_path).unwrap();
    let size = i64::try_from(std::fs::metadata(&package_path).unwrap().len()).unwrap();
    (package_path, digest.to_string(), size)
}

async fn setup_publisher(pool: &PgPool, owner: &str, status: &str) -> (uuid::Uuid, String) {
    let id = uuid::Uuid::new_v4();
    let namespace = format!("p{}", uuid::Uuid::new_v4().simple());
    sqlx::query("INSERT INTO cloud_publishers (id, namespace, status) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&namespace)
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(id).bind(owner).execute(pool).await.unwrap();
    (id, namespace)
}

async fn setup_key(
    pool: &PgPool,
    publisher: uuid::Uuid,
    signing: &SigningKey,
    requester: &str,
    status: &str,
) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys (id, publisher_id, key_id, public_key, fingerprint, status, requested_by) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(id)
        .bind(publisher)
        .bind(signing.public_key().key_id.as_str())
        .bind(&signing.public_key().public_key)
        .bind(signing.public_key().fingerprint().unwrap().to_string())
        .bind(status)
        .bind(requester)
        .execute(pool)
        .await
        .unwrap();
    id
}

/// A fully verified, moderated release row set plus its prepared storage
/// bytes served by the fake S3. Like production, the publisher owns the
/// upload and release while an independent moderator owns the publication
/// job. Returns the publication job id.
#[allow(clippy::too_many_arguments)]
async fn verified_release(
    pool: &PgPool,
    store: &cloud_storage::QuarantineStore,
    publisher: uuid::Uuid,
    key_row: uuid::Uuid,
    owner: &str,
    moderator: &str,
    plugin_id: &str,
    version: &str,
    package: &std::path::Path,
    digest: &str,
    size: i64,
) -> uuid::Uuid {
    let upload = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions (id, publisher_id, requested_by, idempotency_key, expected_size, expected_sha256, object_key, status, expires_at, version_id) VALUES ($1,$2,$3,$4,$5,$6,$7,'quarantined', now() + interval '5 minutes','v1')")
        .bind(upload).bind(publisher).bind(owner).bind(format!("key{}", upload.simple())).bind(size).bind(digest).bind(format!("quarantine/{publisher}/{upload}"))
        .execute(pool).await.unwrap();
    let prepared = store
        .stage_verified(publisher, uuid::Uuid::new_v4(), package, size, digest)
        .await
        .unwrap();
    let release = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_plugin_releases (id, publisher_id, upload_id, publisher_key_id, plugin_id, version, target, status, requested_by) VALUES ($1,$2,$3,$4,$5,$6,'any','review_approved',$7)")
        .bind(release).bind(publisher).bind(upload).bind(key_row).bind(plugin_id).bind(version).bind(owner)
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_verification_jobs (upload_id, release_id, status, result_class) VALUES ($1,$2,'antivirus_passed','antivirus_passed')")
        .bind(upload).bind(release).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_moderation_events (id, release_id, actor_user_id, decision, reason_code) VALUES ($1,$2,$3,'approve','policy_reviewed')")
        .bind(uuid::Uuid::new_v4()).bind(release).bind(moderator).execute(pool).await.unwrap();
    let job = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publication_jobs (id, release_id, requested_by, status, result_class, prepared_key, prepared_version_id) VALUES ($1,$2,$3,'prepared','prepared',$4,$5)")
        .bind(job).bind(release).bind(moderator).bind(&prepared.0).bind(&prepared.1.version_id).execute(pool).await.unwrap();
    job
}

/// Build, verify, and mark-ready a candidate for the currently prepared set.
async fn ready_candidate(
    pool: &PgPool,
    store: &cloud_storage::QuarantineStore,
    clam: &crate::scanner::ClamAv,
    t: &Trust,
    operator: &str,
) -> uuid::Uuid {
    let id = snapshot_worker::build(pool, store, clam, inputs(t))
        .await
        .unwrap()
        .expect("prepared jobs must yield a candidate");
    let manifest = snapshot_verify::verify(pool, store, clam, &t.seed, id, &t.root, &t.index_pub)
        .await
        .unwrap();
    snapshot_promotion::record_verified(pool, id, &manifest, operator, "registry integration test")
        .await
        .unwrap();
    id
}

/// Serve the full Cloud API (with versioned storage) over loopback HTTP.
async fn serve_app(
    ctx: AuthContext,
    pool: PgPool,
    store: cloud_storage::QuarantineStore,
) -> (String, tokio::task::JoinHandle<()>) {
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app_with_storage(ctx, pool, auth, Some(store));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, server)
}

// The prepared-job inventory is global, so registry tests serialize on this
// lock and clean up leftover prepared jobs at start: a panicked test must not
// poison the next candidate.
static REGISTRY_TEST_LOCK: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

async fn lock(pool: &PgPool) -> tokio::sync::OwnedMutexGuard<()> {
    let guard = REGISTRY_TEST_LOCK.clone().lock_owned().await;
    // Previous runs leave active generations whose artifacts are gone with
    // their fake storage: reset the registry inventory so each test starts
    // from an empty published set. Prepared jobs are blocked (nulling their
    // staging pointers per the job lifecycle); consumed jobs stay linked.
    for table in [
        "cloud_registry_promotions",
        "cloud_registry_generation_files",
        "cloud_registry_generation_releases",
        "cloud_registry_generations",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE cloud_publication_jobs SET status='blocked', result_class='temporary_failure', prepared_key=NULL, prepared_version_id=NULL WHERE status='prepared'")
        .execute(pool)
        .await
        .unwrap();
    guard
}

use std::sync::RwLock;
use tiktools_plugin_package::{PackageArchive, TrustStore};
use tiktools_plugin_registry::{
    join_url, DownloadRequest, Downloader, IndexWriter, RegistryClient, RegistrySource,
};

fn tiktools_client(
    base: &str,
    generation: i64,
    root_pub: &tiktools_plugin_package::PublicKey,
    dir: &tempfile::TempDir,
) -> (RegistryClient, Arc<RwLock<TrustStore>>, RegistrySource) {
    let mut source = RegistrySource::new(
        "fixture",
        format!("{base}/api/v1/registry/generations/{generation}/files"),
    )
    .unwrap();
    source.root_keys = vec![root_pub.clone()];
    let trust = Arc::new(RwLock::new(TrustStore::new()));
    let client = RegistryClient::new(
        dir.path().join("cache"),
        dir.path().join("state.json"),
        vec![source.clone()],
        trust.clone(),
    )
    .unwrap();
    (client, trust, source)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn initial_publication_serves_signed_registry_to_tiktools_client() {
    let database_url = std::env::var("CLOUD_TEST_DATABASE_URL").unwrap();
    let (ctx, pool) = context(&database_url).await;
    let _guard = lock(&pool).await;
    let owner = user(&ctx).await;
    let moderator = user(&ctx).await;
    sqlx::query("INSERT INTO cloud_account_roles (user_id, role) VALUES ($1, 'moderator')")
        .bind(&moderator.0)
        .execute(&pool)
        .await
        .unwrap();
    let (publisher, namespace) = setup_publisher(&pool, &owner.0, "approved").await;
    let signing = publisher_key(&namespace);
    let key_row = setup_key(&pool, publisher, &signing, &owner.0, "approved").await;
    let t = trust(&namespace, &signing, &[]);
    let work = tempfile::tempdir().unwrap();
    let plugin_id = format!("{namespace}.plugin");
    let (package_path, digest, size) =
        package(work.path(), &signing, &namespace, &plugin_id, "1.0.0");
    let (_s3, endpoint, s3server) = fake_s3().await;
    let store = cloud_storage::QuarantineStore::new(cloud_storage::Config {
        endpoint: endpoint.clone(),
        region: "us-east-1".into(),
        bucket: "cloud-test".into(),
        access_key: "test".into(),
        secret_key: "test-secret".into(),
    })
    .unwrap();
    let (_clam, clam_addr, clamserver) = fake_clam().await;
    let clam = scanner(&clam_addr);
    verified_release(
        &pool,
        &store,
        publisher,
        key_row,
        &owner.0,
        &moderator.0,
        &plugin_id,
        "1.0.0",
        &package_path,
        &digest,
        size,
    )
    .await;
    let candidate = ready_candidate(&pool, &store, &clam, &t, "test-operator").await;
    let published = snapshot_publish::publish(
        &pool,
        &store,
        &clam,
        &inputs(&t),
        candidate,
        "test-operator",
    )
    .await
    .unwrap();
    let generation = published.generation;
    assert!(generation >= 1);
    assert_eq!(published.release_count, 1);
    assert!(published.file_count > 0);

    // The published row set carries this release with its verified digest.
    let row_digest: String = sqlx::query_scalar(
        "SELECT sha256 FROM cloud_registry_generation_releases WHERE generation = $1 AND plugin_id = $2",
    )
    .bind(generation)
    .bind(&plugin_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row_digest, digest);
    // The prepared job was consumed so future candidates start clean.
    let job_status: String = sqlx::query_scalar(
        "SELECT status FROM cloud_publication_jobs WHERE release_id = (SELECT release_id FROM cloud_registry_generation_releases WHERE generation = $1 AND plugin_id = $2)",
    )
    .bind(generation)
    .bind(&plugin_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(job_status, "published");

    // Serve the API and drive the real pinned TikTools registry client.
    let (base, server) = serve_app(ctx.clone(), pool.clone(), store).await;
    let client_dir = tempfile::tempdir().unwrap();
    let (client, trust_store, source) =
        tiktools_client(&base, generation, &t.root.key, &client_dir);
    let status = client.refresh("fixture").await.unwrap();
    assert!(status.verified);
    let page = client.catalog_page("fixture", 1).await.unwrap();
    assert!(page.entries.iter().any(|entry| entry.id == plugin_id));
    let (doc_source, document) = client.package(&plugin_id, Some("fixture")).await.unwrap();
    assert_eq!(doc_source.url, source.url);
    let release = document
        .releases
        .iter()
        .find(|r| r.version == "1.0.0")
        .expect("published release visible to clients");
    let artifact = release
        .artifacts
        .iter()
        .find(|artifact| artifact.target == "any")
        .or(release.artifacts.first())
        .expect("release artifact");
    let download_dir = tempfile::tempdir().unwrap();
    let downloaded = Downloader::new(download_dir.path())
        .unwrap()
        .fetch(
            DownloadRequest {
                url: &join_url(&source.url, &artifact.url).unwrap(),
                expected_digest: Some(&artifact.sha256),
                expected_size: Some(artifact.size),
            },
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
    let archive = PackageArchive::open(&downloaded.path).unwrap();
    let inspection = archive.inspect().unwrap();
    assert_eq!(inspection.manifest.id, plugin_id);
    let verified = trust_store
        .read()
        .unwrap()
        .verify_package(
            inspection.signature.as_ref().unwrap(),
            inspection.checksums.as_ref().unwrap(),
            &plugin_id,
            now_secs(),
        )
        .unwrap();
    assert_eq!(verified.key_id, signing.public_key().key_id);
    // Installation is the extraction plus the installer commit; offline
    // signature verification already passed above without Cloud credentials.
    let staging = tempfile::tempdir().unwrap();
    let extracted = archive.extract(staging.path()).unwrap();
    assert_eq!(extracted.manifest.id, plugin_id);
    use tiktools_plugin_api::HostCompat;
    use tiktools_plugin_installer::{
        CommitOptions, Consent, Installer, InstallerConfig, NoopHooks, NoopReporter, PackageOrigin,
        SignaturePolicy,
    };
    let plugins_dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let installer = Installer::new(
        InstallerConfig {
            plugins_dir: plugins_dir.path().to_owned(),
            store_dir: store_dir.path().to_owned(),
            host: HostCompat::new(semver::Version::new(0, 4, 0)),
            retain_versions: 1,
            provider_endpoints: None,
        },
        trust_store.clone(),
    );
    let prepared = installer
        .prepare(
            &downloaded.path,
            PackageOrigin::Registry {
                registry: "fixture".into(),
                url: source.url.clone(),
            },
            SignaturePolicy::Require,
        )
        .unwrap();
    let preview = installer.preview(&prepared);
    let outcome = installer
        .commit(
            &prepared,
            &CommitOptions {
                consent: Consent::Token(preview.consent_token),
                policy: None,
            },
            &NoopHooks,
            &NoopReporter,
        )
        .unwrap();
    assert_eq!(outcome.receipt.id, plugin_id);

    // Forged trust is rejected: a wrong root pin fails the refresh.
    let wrong_root = SigningKey::generate(KeyId::parse("root-evil").unwrap(), None).unwrap();
    let (evil_client, _, _) = tiktools_client(
        &base,
        generation,
        &wrong_root.public_key(),
        &tempfile::tempdir().unwrap(),
    );
    assert!(evil_client.refresh("fixture").await.is_err());
    // Tampered downloads are rejected by digest comparison.
    let bad = tiktools_plugin_package::Sha256Digest::parse(&"0".repeat(64)).unwrap();
    assert!(Downloader::new(download_dir.path())
        .unwrap()
        .fetch(
            DownloadRequest {
                url: &join_url(&source.url, &artifact.url).unwrap(),
                expected_digest: Some(&bad),
                expected_size: Some(artifact.size),
            },
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .await
        .is_err());

    // Serving headers: the pointer is never cached, files are immutable.
    let app = {
        let auth = AuthRouter::new(ctx.clone()).unwrap();
        app_with_storage(
            ctx,
            pool.clone(),
            auth,
            Some(
                cloud_storage::QuarantineStore::new(cloud_storage::Config {
                    endpoint,
                    region: "us-east-1".into(),
                    bucket: "cloud-test".into(),
                    access_key: "test".into(),
                    secret_key: "test-secret".into(),
                })
                .unwrap(),
            ),
        )
    };
    let current = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/registry/current")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(current.status(), StatusCode::OK);
    assert!(current
        .headers()
        .get(header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("no-store"));
    let body = axum::body::to_bytes(current.into_body(), 64 * 1024)
        .await
        .unwrap();
    let current_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(current_json["generation"], generation);
    let file = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(format!(
                    "/api/v1/registry/generations/{generation}/files/root.json"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(file.status(), StatusCode::OK);
    let cache = file
        .headers()
        .get(header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cache.contains("immutable"));
    assert!(file.headers().contains_key(header::ETAG));
    let missing = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/registry/generations/999999/files/root.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let traversal = app
        .oneshot(
            axum::http::Request::builder()
                .uri(format!(
                    "/api/v1/registry/generations/{generation}/files/../root.json"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(traversal.status(), StatusCode::NOT_FOUND);

    server.abort();
    s3server.abort();
    clamserver.abort();
}

/// Shared per-test rig: fresh publisher, key, trust, storage, and scanner.
/// Each test holds the registry lock for its whole body, so prepared sets and
/// generations never interleave between tests.
struct Fixture {
    ctx: AuthContext,
    pool: PgPool,
    store: cloud_storage::QuarantineStore,
    clam: crate::scanner::ClamAv,
    s3: FakeS3,
    owner: (String, String),
    moderator: (String, String),
    publisher: uuid::Uuid,
    namespace: String,
    signing: SigningKey,
    standby: SigningKey,
    key_row: uuid::Uuid,
    trust: Trust,
    work: tempfile::TempDir,
    _servers: Vec<tokio::task::JoinHandle<()>>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Fixture {
    async fn setup() -> Self {
        let database_url = std::env::var("CLOUD_TEST_DATABASE_URL").unwrap();
        let (ctx, pool) = context(&database_url).await;
        let guard = lock(&pool).await;
        let owner = user(&ctx).await;
        let moderator = user(&ctx).await;
        sqlx::query("INSERT INTO cloud_account_roles (user_id, role) VALUES ($1, 'moderator')")
            .bind(&moderator.0)
            .execute(&pool)
            .await
            .unwrap();
        let (publisher, namespace) = setup_publisher(&pool, &owner.0, "approved").await;
        let signing = publisher_key(&namespace);
        let standby = publisher_key(&namespace);
        let key_row = setup_key(&pool, publisher, &signing, &owner.0, "approved").await;
        let trust = trust(&namespace, &signing, &[&standby]);
        let work = tempfile::tempdir().unwrap();
        let (s3, endpoint, s3server) = fake_s3().await;
        let store = cloud_storage::QuarantineStore::new(cloud_storage::Config {
            endpoint: endpoint.clone(),
            region: "us-east-1".into(),
            bucket: "cloud-test".into(),
            access_key: "test".into(),
            secret_key: "test-secret".into(),
        })
        .unwrap();
        let (_clam, clam_addr, clamserver) = fake_clam().await;
        let clam = scanner(&clam_addr);
        Fixture {
            ctx,
            pool,
            store,
            clam,
            s3,
            owner,
            moderator,
            publisher,
            namespace,
            signing,
            standby,
            key_row,
            trust,
            work,
            _servers: vec![s3server, clamserver],
            _guard: guard,
        }
    }

    fn plugin_id(&self, name: &str) -> String {
        format!("{}.{name}", self.namespace)
    }

    /// Build, sign, verify, moderate, and prepare one release. Returns the
    /// plugin id; the prepared job is ready for the next candidate.
    async fn release(&self, name: &str, version: &str) -> String {
        let plugin_id = self.plugin_id(name);
        let (path, digest, size) = package(
            self.work.path(),
            &self.signing,
            &self.namespace,
            &plugin_id,
            version,
        );
        verified_release(
            &self.pool,
            &self.store,
            self.publisher,
            self.key_row,
            &self.owner.0,
            &self.moderator.0,
            &plugin_id,
            version,
            &path,
            &digest,
            size,
        )
        .await;
        plugin_id
    }

    /// Build a candidate for the current prepared set, verify it, record
    /// readiness, and promote it to a new active generation.
    async fn publish(&self, operator: &str) -> (uuid::Uuid, snapshot_publish::Published) {
        let candidate =
            ready_candidate(&self.pool, &self.store, &self.clam, &self.trust, operator).await;
        let published = snapshot_publish::publish(
            &self.pool,
            &self.store,
            &self.clam,
            &inputs(&self.trust),
            candidate,
            operator,
        )
        .await
        .unwrap();
        (candidate, published)
    }

    async fn active_generation(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT generation FROM cloud_registry_generations WHERE status='active' ORDER BY generation DESC LIMIT 1",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn generation_plugins(&self, generation: i64) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT plugin_id, version FROM cloud_registry_generation_releases WHERE generation = $1 ORDER BY plugin_id, version",
        )
        .bind(generation)
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn incremental_publication_preserves_versions_and_applies_yanks() {
    let fx = Fixture::setup().await;
    let a = fx.release("alpha", "1.0.0").await;
    let (_, first) = fx.publish("op-one").await;
    assert_eq!(fx.active_generation().await, first.generation);
    assert!(fx
        .generation_plugins(first.generation)
        .await
        .contains(&(a.clone(), "1.0.0".into())));

    let b = fx.release("beta", "1.0.0").await;
    let (_, second) = fx.publish("op-one").await;
    assert!(second.generation > first.generation);
    let plugins = fx.generation_plugins(second.generation).await;
    // Previously published versions are preserved in the new generation.
    assert!(plugins.contains(&(a.clone(), "1.0.0".into())));
    assert!(plugins.contains(&(b.clone(), "1.0.0".into())));

    // Yank beta, publish gamma: the yank is applied, not restored.
    sqlx::query("INSERT INTO cloud_release_yanks (release_id, yanked_by, reason) VALUES ((SELECT release_id FROM cloud_registry_generation_releases WHERE generation=$1 AND plugin_id=$2), $3, 'upstream compromise')")
        .bind(second.generation).bind(&b).bind(&fx.moderator.0).execute(&fx.pool).await.unwrap();
    let c = fx.release("gamma", "1.0.0").await;
    let (_, third) = fx.publish("op-one").await;
    assert!(third
        .dropped
        .iter()
        .any(|d| d.contains(&b) && d.contains("yanked")));
    let plugins = fx.generation_plugins(third.generation).await;
    assert!(plugins.contains(&(a.clone(), "1.0.0".into())));
    assert!(plugins.contains(&(c.clone(), "1.0.0".into())));
    assert!(!plugins.iter().any(|(id, _)| id == &b));
    // The promotion history records the operator and the drop.
    let (operator, reason): (String, String) = sqlx::query_as(
        "SELECT operator, reason FROM cloud_registry_promotions WHERE generation=$1 AND decision='promoted'",
    )
    .bind(third.generation)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(operator, "op-one");
    assert!(reason.contains(b.as_str()));
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn revoked_signing_key_drops_base_release() {
    let fx = Fixture::setup().await;
    let a = fx.release("solo", "1.0.0").await;
    let (_, first) = fx.publish("op-one").await;
    assert!(fx
        .generation_plugins(first.generation)
        .await
        .contains(&(a.clone(), "1.0.0".into())));

    // Compromise the only key, enroll the standby (already delegated in the
    // registry trust, as in a rotated deployment), publish again.
    sqlx::query("UPDATE cloud_publisher_keys SET status='revoked' WHERE id=$1")
        .bind(fx.key_row)
        .execute(&fx.pool)
        .await
        .unwrap();
    let fresh_row = setup_key(&fx.pool, fx.publisher, &fx.standby, &fx.owner.0, "approved").await;
    let plugin_b = fx.plugin_id("next");
    let (path, digest, size) = package(
        fx.work.path(),
        &fx.standby,
        &fx.namespace,
        &plugin_b,
        "1.0.0",
    );
    verified_release(
        &fx.pool,
        &fx.store,
        fx.publisher,
        fresh_row,
        &fx.owner.0,
        &fx.moderator.0,
        &plugin_b,
        "1.0.0",
        &path,
        &digest,
        size,
    )
    .await;
    let (_, second) = fx.publish("op-one").await;
    assert!(second
        .dropped
        .iter()
        .any(|d| d.contains(&a) && d.contains("key_revoked")));
    let plugins = fx.generation_plugins(second.generation).await;
    assert!(!plugins.iter().any(|(id, _)| id == &a));
    assert!(plugins.contains(&(plugin_b, "1.0.0".into())));
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn changed_authorization_after_readiness_blocks_promotion() {
    let fx = Fixture::setup().await;
    let a = fx.release("blocked", "1.0.0").await;
    let candidate = ready_candidate(&fx.pool, &fx.store, &fx.clam, &fx.trust, "op-one").await;
    // A yank lands after the readiness record: promotion must fail closed.
    sqlx::query("INSERT INTO cloud_release_yanks (release_id, yanked_by, reason) VALUES ((SELECT id FROM cloud_plugin_releases WHERE plugin_id=$1), $2, 'late report')")
        .bind(&a).bind(&fx.moderator.0).execute(&fx.pool).await.unwrap();
    let error = snapshot_publish::publish(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &inputs(&fx.trust),
        candidate,
        "op-one",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("authorization"), "unexpected error: {error}");
    let decision: String = sqlx::query_scalar(
        "SELECT decision FROM cloud_registry_promotions WHERE candidate_id=$1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(candidate)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(decision, "blocked");
    // The prepared job survives for triage; the next test's cleanup blocks it.
    let status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM cloud_publication_jobs WHERE release_id=(SELECT id FROM cloud_plugin_releases WHERE plugin_id=$1)",
    )
    .bind(&a)
    .fetch_optional(&fx.pool)
    .await
    .unwrap();
    assert!(matches!(
        status.as_deref(),
        Some("prepared") | Some("blocked")
    ));
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn concurrent_promotions_fail_closed_and_stay_atomic() {
    let fx = Fixture::setup().await;
    // A held advisory lock makes a second promotion fail immediately.
    let mut held = fx.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(840170007)")
        .execute(&mut *held)
        .await
        .unwrap();
    fx.release("raced", "1.0.0").await;
    let candidate = ready_candidate(&fx.pool, &fx.store, &fx.clam, &fx.trust, "op-one").await;
    let error = snapshot_publish::publish(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &inputs(&fx.trust),
        candidate,
        "op-one",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("another registry promotion is running"),
        "unexpected: {error}"
    );
    // Lock contention is not recorded: the holder owns the outcome.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cloud_registry_promotions WHERE candidate_id=$1")
            .bind(candidate)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    held.commit().await.unwrap();

    // Two genuinely concurrent promotions: one wins, the registry stays atomic.
    let concurrent_one = inputs(&fx.trust);
    let concurrent_two = inputs(&fx.trust);
    let (first, second) = tokio::join!(
        snapshot_publish::publish(
            &fx.pool,
            &fx.store,
            &fx.clam,
            &concurrent_one,
            candidate,
            "op-one"
        ),
        snapshot_publish::publish(
            &fx.pool,
            &fx.store,
            &fx.clam,
            &concurrent_two,
            candidate,
            "op-two"
        ),
    );
    let generations: Vec<i64> = [first, second]
        .into_iter()
        .filter_map(|result| result.ok().map(|p| p.generation))
        .collect();
    assert!(!generations.is_empty(), "at least one promotion succeeds");
    assert!(
        generations.windows(2).all(|w| w[0] == w[1]),
        "winners agree on one generation"
    );
    let active: Vec<i64> = sqlx::query_scalar(
        "SELECT generation FROM cloud_registry_generations WHERE status='active'",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0], generations[0]);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn corrupt_and_forged_artifacts_fail_closed() {
    let fx = Fixture::setup().await;
    // Corrupted bytes: the pinned version no longer matches its digest.
    let a = fx.release("honest", "1.0.0").await;
    let candidate = ready_candidate(&fx.pool, &fx.store, &fx.clam, &fx.trust, "op-one").await;
    fx.s3.tamper_read.store(true, Ordering::SeqCst);
    let error = snapshot_publish::publish(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &inputs(&fx.trust),
        candidate,
        "op-one",
    )
    .await
    .unwrap_err()
    .to_string();
    fx.s3.tamper_read.store(false, Ordering::SeqCst);
    assert!(
        error.contains("digest") || error.contains("unreadable"),
        "unexpected error: {error}"
    );
    let decision: String = sqlx::query_scalar(
        "SELECT decision FROM cloud_registry_promotions WHERE candidate_id=$1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(candidate)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(decision, "failed");

    // Forged bytes: an attacker's signature under the victim's metadata never
    // becomes a candidate — the build gate verifies every package signature.
    let attacker = publisher_key(&fx.namespace);
    let forged_id = fx.plugin_id("forged");
    let (path, digest, size) = package(
        fx.work.path(),
        &attacker,
        &fx.namespace,
        &forged_id,
        "1.0.0",
    );
    verified_release(
        &fx.pool,
        &fx.store,
        fx.publisher,
        fx.key_row,
        &fx.owner.0,
        &fx.moderator.0,
        &forged_id,
        "1.0.0",
        &path,
        &digest,
        size,
    )
    .await;
    // The honest release's job stays prepared, so block it explicitly (nulling
    // its staging pointer per the job lifecycle); the build must still refuse
    // the forged remainder.
    sqlx::query("UPDATE cloud_publication_jobs SET status='blocked', result_class='temporary_failure', prepared_key=NULL, prepared_version_id=NULL WHERE release_id=(SELECT id FROM cloud_plugin_releases WHERE plugin_id=$1)")
        .bind(&a).execute(&fx.pool).await.unwrap();
    let error = snapshot_worker::build(&fx.pool, &fx.store, &fx.clam, inputs(&fx.trust))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("candidate build failed") || error.contains("verify"),
        "unexpected error: {error}"
    );
    // Nothing activated from either attempt.
    let plugin_gens: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM cloud_registry_generation_releases WHERE plugin_id=$1 OR plugin_id=$2",
    )
    .bind(&a)
    .bind(&forged_id)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(plugin_gens, 0);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn interrupted_upload_resumes_same_generation() {
    let fx = Fixture::setup().await;
    let a = fx.release("resumed", "1.0.0").await;
    let candidate = ready_candidate(&fx.pool, &fx.store, &fx.clam, &fx.trust, "op-one").await;
    // Crash the first published-file upload; the staged row stays behind.
    fx.s3.fail_put_once.store(true, Ordering::SeqCst);
    let error = snapshot_publish::publish(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &inputs(&fx.trust),
        candidate,
        "op-one",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!error.is_empty());
    let staged: (uuid::Uuid, i64) = sqlx::query_as(
        "SELECT id, generation FROM cloud_registry_generations WHERE status='staged' AND candidate_id=$1",
    )
    .bind(candidate)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    // The retry resumes the same staged generation instead of duplicating it.
    let published = snapshot_publish::publish(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &inputs(&fx.trust),
        candidate,
        "op-one",
    )
    .await
    .unwrap();
    assert_eq!(published.id, staged.0);
    assert_eq!(published.generation, staged.1);
    assert_eq!(fx.active_generation().await, staged.1);
    assert!(fx
        .generation_plugins(staged.1)
        .await
        .contains(&(a, "1.0.0".into())));
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn rollback_restores_safe_generation_and_refuses_unsafe() {
    let fx = Fixture::setup().await;
    let a = fx.release("steady", "1.0.0").await;
    let (_, first) = fx.publish("op-one").await;
    let b = fx.release("shiny", "1.0.0").await;
    let (_, second) = fx.publish("op-one").await;
    assert_eq!(fx.active_generation().await, second.generation);

    // Safe rollback: the target re-verifies against current trust and policy.
    let rolled = snapshot_publish::rollback(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &fx.trust.seed,
        &fx.trust.root,
        &fx.trust.index_pub,
        first.generation,
        "op-two",
    )
    .await
    .unwrap();
    assert_eq!(rolled.generation, first.generation);
    assert_eq!(rolled.previous, second.generation);
    assert_eq!(fx.active_generation().await, first.generation);
    // Rolling back to the active generation is an idempotent no-op.
    let same = snapshot_publish::rollback(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &fx.trust.seed,
        &fx.trust.root,
        &fx.trust.index_pub,
        first.generation,
        "op-two",
    )
    .await
    .unwrap();
    assert_eq!(same.generation, first.generation);

    // A new advisory on a release of generation two makes restoring it unsafe.
    sqlx::query("INSERT INTO cloud_release_advisories (release_id, severity, message, created_by) VALUES ((SELECT id FROM cloud_plugin_releases WHERE plugin_id=$1), 'high', 'upgrade now', $2)")
        .bind(&a).bind(&fx.moderator.0).execute(&fx.pool).await.unwrap();
    let error = snapshot_publish::rollback(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &fx.trust.seed,
        &fx.trust.root,
        &fx.trust.index_pub,
        second.generation,
        "op-two",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("advisory"), "unexpected error: {error}");
    assert_eq!(fx.active_generation().await, first.generation);
    // A yank is equally unsafe to restore.
    sqlx::query("INSERT INTO cloud_release_yanks (release_id, yanked_by, reason) VALUES ((SELECT id FROM cloud_plugin_releases WHERE plugin_id=$1), $2, 'bad')")
        .bind(&b).bind(&fx.moderator.0).execute(&fx.pool).await.unwrap();
    let error = snapshot_publish::rollback(
        &fx.pool,
        &fx.store,
        &fx.clam,
        &fx.trust.seed,
        &fx.trust.root,
        &fx.trust.index_pub,
        second.generation,
        "op-two",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("authorized") || error.contains("yank"),
        "unexpected error: {error}"
    );
    assert_eq!(fx.active_generation().await, first.generation);
    let decisions: Vec<String> = sqlx::query_scalar(
        "SELECT decision FROM cloud_registry_promotions WHERE generation=$1 ORDER BY created_at",
    )
    .bind(second.generation)
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert!(decisions.contains(&"blocked".to_string()));
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn gc_collects_staged_and_published_candidate_files() {
    let fx = Fixture::setup().await;
    let a = fx.release("collected", "1.0.0").await;
    let (candidate, published) = fx.publish("op-one").await;

    // A crashed promotion leaves a staged generation with staged files.
    let stale_id = uuid::Uuid::new_v4();
    let stale_gen = 999991;
    let zeroes = "0".repeat(64);
    sqlx::query("INSERT INTO cloud_registry_generations (id, generation, candidate_id, inventory_sha256, manifest_sha256, root_fingerprint, index_key_id, release_count, file_count, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,'stale-key',1,1,'staged', now() - interval '2 hours')")
        .bind(stale_id).bind(stale_gen).bind(candidate).bind(&zeroes).bind(&zeroes).bind(&zeroes).execute(&fx.pool).await.unwrap();
    let scratch = fx.work.path().join("scratch.bin");
    std::fs::write(&scratch, b"orphaned").unwrap();
    let digest = tiktools_plugin_package::Sha256Digest::of_bytes(b"orphaned").to_string();
    let (key, version) = fx
        .store
        .stage_public_file(stale_id, &scratch, 8, &digest)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_registry_generation_files (generation, path, sha256, size, object_key, version_id) VALUES ($1,'stale.json',$2,8,$3,$4)")
        .bind(stale_gen).bind(&digest).bind(&key).bind(&version.version_id).execute(&fx.pool).await.unwrap();

    let report = snapshot_publish::gc(&fx.pool, &fx.store, 100, "op-gc")
        .await
        .unwrap();
    assert!(
        report.deleted_files >= 1,
        "staged files collected: {report:?}"
    );
    assert!(
        report.deleted_generations >= 1,
        "staged generations collected: {report:?}"
    );
    assert!(
        report.deleted_candidate_files >= 1,
        "published candidate files collected: {report:?}"
    );
    let stale_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cloud_registry_generations WHERE id=$1")
            .bind(stale_id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(stale_rows, 0);
    // Live generations keep their files: the rollback target survives GC.
    let live_files: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM cloud_registry_generation_files WHERE generation=$1",
    )
    .bind(published.generation)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert!(live_files > 0);
    assert!(fx
        .generation_plugins(published.generation)
        .await
        .contains(&(a, "1.0.0".into())));
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn client_discovers_update_and_yank_removal() {
    let fx = Fixture::setup().await;
    let plugin = fx.release("evolving", "1.0.0").await;
    let (_, first) = fx.publish("op-one").await;
    let (base, server) = serve_app(fx.ctx.clone(), fx.pool.clone(), fx.store.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let (client, _, _) = tiktools_client(&base, first.generation, &fx.trust.root.key, &dir);
    let (_, document) = client.package(&plugin, Some("fixture")).await.unwrap();
    assert_eq!(document.releases.len(), 1);

    // Publish a newer version and yank the old one: clients see the update,
    // and the yanked version disappears from the snapshot.
    let (path, digest, size) =
        package(fx.work.path(), &fx.signing, &fx.namespace, &plugin, "2.0.0");
    verified_release(
        &fx.pool,
        &fx.store,
        fx.publisher,
        fx.key_row,
        &fx.owner.0,
        &fx.moderator.0,
        &plugin,
        "2.0.0",
        &path,
        &digest,
        size,
    )
    .await;
    sqlx::query("INSERT INTO cloud_release_yanks (release_id, yanked_by, reason) VALUES ((SELECT id FROM cloud_plugin_releases WHERE plugin_id=$1 AND version='1.0.0'), $2, 'superseded')")
        .bind(&plugin).bind(&fx.moderator.0).execute(&fx.pool).await.unwrap();
    let (_, second) = fx.publish("op-one").await;
    // Generation one is superseded but still serves pinned clients.
    let old_status: String =
        sqlx::query_scalar("SELECT status FROM cloud_registry_generations WHERE generation=$1")
            .bind(first.generation)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(old_status, "superseded");
    let (client2, trust2, source2) = tiktools_client(
        &base,
        second.generation,
        &fx.trust.root.key,
        &tempfile::tempdir().unwrap(),
    );
    client2.refresh("fixture").await.unwrap();
    let (_, document) = client2.package(&plugin, Some("fixture")).await.unwrap();
    let versions: Vec<&str> = document
        .releases
        .iter()
        .map(|r| r.version.as_str())
        .collect();
    assert!(versions.contains(&"2.0.0"));
    assert!(!versions.contains(&"1.0.0"));
    // The update installs end to end with offline signature verification.
    let release = document
        .releases
        .iter()
        .find(|r| r.version == "2.0.0")
        .unwrap();
    let artifact = release
        .artifacts
        .iter()
        .find(|artifact| artifact.target == "any")
        .or(release.artifacts.first())
        .expect("release artifact");
    let downloads = tempfile::tempdir().unwrap();
    let downloaded = tiktools_plugin_registry::Downloader::new(downloads.path())
        .unwrap()
        .fetch(
            tiktools_plugin_registry::DownloadRequest {
                url: &tiktools_plugin_registry::join_url(&source2.url, &artifact.url).unwrap(),
                expected_digest: Some(&artifact.sha256),
                expected_size: Some(artifact.size),
            },
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
    use tiktools_plugin_api::HostCompat;
    use tiktools_plugin_installer::{
        CommitOptions, Consent, Installer, InstallerConfig, NoopHooks, NoopReporter, PackageOrigin,
        SignaturePolicy,
    };
    let plugins_keep = tempfile::tempdir().unwrap();
    let store_keep = tempfile::tempdir().unwrap();
    let installer = Installer::new(
        InstallerConfig {
            plugins_dir: plugins_keep.path().to_owned(),
            store_dir: store_keep.path().to_owned(),
            host: HostCompat::new(semver::Version::new(0, 4, 0)),
            retain_versions: 1,
            provider_endpoints: None,
        },
        trust2,
    );
    let prepared = installer
        .prepare(
            &downloaded.path,
            PackageOrigin::Registry {
                registry: "fixture".into(),
                url: source2.url.clone(),
            },
            SignaturePolicy::Require,
        )
        .unwrap();
    let preview = installer.preview(&prepared);
    let outcome = installer
        .commit(
            &prepared,
            &CommitOptions {
                consent: Consent::Token(preview.consent_token),
                policy: None,
            },
            &NoopHooks,
            &NoopReporter,
        )
        .unwrap();
    assert_eq!(outcome.receipt.version, "2.0.0");
    server.abort();
}
