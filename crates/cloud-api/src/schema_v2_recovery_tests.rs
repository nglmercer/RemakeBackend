//! Opt-in PostgreSQL-only upgrade and actual archive restore proof. Every
//! schema/database removed here was randomly named and created by this fixture.
use super::*;
use better_auth::email_password::{EmailPasswordService, SignUpInput};
use futures_util::FutureExt;
use serde_json::{json, Value};
use std::{borrow::Cow, collections::BTreeMap, panic::AssertUnwindSafe, process::Stdio};
use url::{Host, Url};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
const PRE_V2: i64 = 20261102000024;
const FIRST_V2: i64 = 20261108000001;
const DIGEST_REPAIR: i64 = 20261108000002;
const ORIGIN: &str = "https://schema-recovery.example.test";

fn validate_fixture_url(raw: &str) -> TestResult<Url> {
    // Validate libpq's accepted settings before SQLx can interpret connection
    // overrides differently. Constructing this command never starts a process.
    let mut command = tokio::process::Command::new("pg_dump");
    let database = local_backup::configure_pg_command(&mut command, raw)?;
    let url = Url::parse(raw)?;
    let local = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        // postgres is a non-special URL scheme, so Url can represent a literal
        // IPv4 authority as Domain. Parse it as an IP without DNS resolution.
        Some(Host::Domain(host)) => host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    };
    if !local
        || !(database.starts_with("cloud_test") || database.starts_with("test_"))
        || database.contains('/')
        || database.len() > 63
        || database.chars().any(char::is_control)
        || url.query_pairs().any(|(key, _)| key == "options")
    {
        return Err("recovery drill requires an explicit loopback PostgreSQL test database without connection options".into());
    }
    Ok(url)
}

struct Fixture {
    url: Url,
    schema: String,
    restore_database: String,
    control: PgPool,
    source: Option<PgPool>,
    restored: Option<PgPool>,
    created_schema: bool,
    created_database: bool,
}
impl Fixture {
    async fn new() -> TestResult<Self> {
        // An empty private database: this drill migrates it itself, from the pre-v2 schema.
        let raw = crate::test_support::empty_url();
        let url = validate_fixture_url(&raw)?;
        let control = PgPoolOptions::new()
            .max_connections(1)
            .connect(&raw)
            .await?;
        Ok(Self {
            url,
            schema: format!("v2_upgrade_{}", uuid::Uuid::new_v4().simple()),
            restore_database: format!("cloud_v2_restore_{}", uuid::Uuid::new_v4().simple()),
            control,
            source: None,
            restored: None,
            created_schema: false,
            created_database: false,
        })
    }
    fn schema_url(&self, database: Option<&str>) -> String {
        let mut url = self.url.clone();
        if let Some(database) = database {
            url.set_path(&format!("/{database}"));
        }
        let pairs: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "options")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        url.set_query(None);
        url.query_pairs_mut().extend_pairs(pairs).append_pair(
            "options",
            &format!("-csearch_path={} -ctimezone=UTC", self.schema),
        );
        url.to_string()
    }
    async fn cleanup(&mut self) {
        if let Some(pool) = self.restored.take() {
            pool.close().await;
        }
        if let Some(pool) = self.source.take() {
            pool.close().await;
        }
        // Never derive DROP targets from environment or archive contents.
        for (created, sql) in [
            (
                self.created_database,
                format!("DROP DATABASE {} WITH (FORCE)", self.restore_database),
            ),
            (
                self.created_schema,
                format!("DROP SCHEMA {} CASCADE", self.schema),
            ),
        ] {
            if created
                && !matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(15),
                        sqlx::query(&sql).execute(&self.control)
                    )
                    .await,
                    Ok(Ok(_))
                )
            {
                eprintln!("best-effort cleanup of a recovery-fixture object failed");
            }
        }
        self.control.close().await;
    }
}
fn migrations_through(last: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            readiness::MIGRATOR
                .iter()
                .filter(|migration| migration.version <= last)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: false,
        no_tx: false,
    }
}
fn identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
async fn table_snapshot(pool: &PgPool) -> TestResult<BTreeMap<String, Value>> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename",
    )
    .fetch_all(pool)
    .await?;
    let mut snapshot = BTreeMap::new();
    for name in names {
        let rows: Value = sqlx::query_scalar(&format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {} t", identifier(&name))).fetch_one(pool).await?;
        snapshot.insert(name, rows);
    }
    Ok(snapshot)
}
/// True when every row in `before` still exists in `after` with all of its
/// fields unchanged. Extra fields on the new rows are allowed, because a
/// migration may add columns; the row count must stay the same.
fn rows_keep_values(before: &Value, after: &Value) -> bool {
    let (Some(before), Some(after)) = (before.as_array(), after.as_array()) else {
        return before == after;
    };
    before.len() == after.len()
        && before.iter().all(|old| {
            after
                .iter()
                .any(|new| match (old.as_object(), new.as_object()) {
                    (Some(old), Some(new)) => {
                        old.iter().all(|(key, value)| new.get(key) == Some(value))
                    }
                    _ => old == new,
                })
        })
}
fn retained_migrations(before: &BTreeMap<String, Value>, after: &BTreeMap<String, Value>) {
    for old in before["_sqlx_migrations"].as_array().unwrap() {
        let retained = after["_sqlx_migrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["version"] == old["version"]);
        assert_eq!(
            retained,
            Some(old),
            "upgrade changed an existing migration checksum/result"
        );
    }
}
fn service_state(auth: &AuthContext, pool: &PgPool) -> AppState {
    AppState {
        versioning: versioning::bridge().expect("the versioning credential key"),
        peer: remote::peers::PeerConfig::default(),
        auth: auth.clone(),
        pool: pool.clone(),
        object_storage: None,
        step_up_oauth: None,
        temporary_log_approvals: false,
        remote: std::sync::Arc::new(crate::remote::relay::Hub::new("schema-test")),
    }
}
async fn ready(auth: &AuthContext, pool: &PgPool) -> StatusCode {
    readiness::ready(State(service_state(auth, pool))).await
}
fn selection(id: &str, enabled: bool) -> Value {
    json!({"schemaVersion":1,"pluginId":id,"version":"1.0.0","enabled":enabled})
}
fn document(message: &str) -> Value {
    json!({"templateVersion":1,"id":"drill-rule","title":"Recovery fixture","actions":[{"name":"Log","typeId":"core.log","enabled":false,"config":{"message":message,"coefficient":1.0}}],"event":{"name":"Event","trigger":"tiktok.chat","enabled":false}})
}

async fn seed_pre_v2(pool: &PgPool, owner: &str, reviewer: &str) -> TestResult<()> {
    let publisher = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cloud_publishers(id,namespace,status) VALUES($1,'v2-drill','approved')",
    )
    .bind(publisher)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(publisher)
    .bind(owner)
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO cloud_account_roles(user_id,role) VALUES($1,'moderator')")
        .bind(reviewer)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO cloud_audit_events(id,actor_user_id,publisher_id,target_user_id,action) VALUES($1,$2,$3,$4,'fixture.pre_v2')").bind(uuid::Uuid::new_v4()).bind(reviewer).bind(publisher).bind(owner).execute(pool).await?;
    let key = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys(id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES($1,$2,'drill-signing-key','cGtleQ',$3,'approved',$4)").bind(key).bind(publisher).bind("f".repeat(64)).bind(owner).execute(pool).await?;
    let upload = uuid::Uuid::new_v4();
    let release = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions(id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES($1,$2,$3,$4,5,$5,$6,'quarantined',now()+interval '1 hour','fixture-version')").bind(upload).bind(publisher).bind(owner).bind(format!("drill-{}", upload.simple())).bind("a".repeat(64)).bind(format!("quarantine/{upload}")).execute(pool).await?;
    sqlx::query("INSERT INTO cloud_plugin_releases(id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES($1,$2,$3,$4,'drill.plugin','1.0.0','any','awaiting_verification',$5)").bind(release).bind(publisher).bind(upload).bind(key).bind(owner).execute(pool).await?;
    sqlx::query("INSERT INTO cloud_verification_jobs(upload_id,release_id,status,lease_id,lease_expires_at,attempts) VALUES($1,$2,'running',$3,now()+interval '1 hour',1)").bind(upload).bind(release).bind(uuid::Uuid::new_v4()).execute(pool).await?;
    let candidate = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_snapshot_candidates(id,status,root_fingerprint,inventory_sha256,release_count,file_count) VALUES($1,'candidate',$2,$3,1,1)").bind(candidate).bind("b".repeat(64)).bind("c".repeat(64)).execute(pool).await?;
    sqlx::query("INSERT INTO cloud_snapshot_candidate_files(candidate_id,path,sha256,size,object_key,version_id) VALUES($1,'root.json',$2,1,'drill-root','fixture-version')").bind(candidate).bind("d".repeat(64)).execute(pool).await?;
    sqlx::query("INSERT INTO cloud_snapshot_promotion_checks(id,candidate_id,decision,operator,reason,inventory_sha256) VALUES($1,$2,'blocked','v2-drill','Synthetic fixture has no external trust material',$3)").bind(uuid::Uuid::new_v4()).bind(candidate).bind("c".repeat(64)).execute(pool).await?;
    sqlx::query("INSERT INTO cloud_sync_cursors(user_id,cursor) VALUES($1,2)")
        .bind(owner)
        .execute(pool)
        .await?;
    for (id, revision, value) in [
        ("drill.plugin", 1i64, Some(selection("drill.plugin", true))),
        ("drill.removed", 2, None),
    ] {
        sqlx::query("INSERT INTO cloud_sync_records(user_id,collection,key,revision,value,deleted) VALUES($1,'plugin-selections',$2,$3,$4,$5)").bind(owner).bind(id).bind(revision).bind(&value).bind(value.is_none()).execute(pool).await?;
        sqlx::query("INSERT INTO cloud_sync_changes(user_id,cursor,collection,key,value,deleted) VALUES($1,$2,'plugin-selections',$3,$4,$5)").bind(owner).bind(revision).bind(id).bind(&value).bind(value.is_none()).execute(pool).await?;
    }
    Ok(())
}
async fn seed_v2(pool: &PgPool, owner: &str, reviewer: &str) -> TestResult<uuid::Uuid> {
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_library_documents(id,owner_user_id,kind,slug,revision) VALUES($1,$2,'template','drill-rule',2)").bind(id).bind(owner).execute(pool).await?;
    for (revision, status, source) in [
        (1i64, "published", document("published-source")),
        (2, "draft", document("newer-private-source")),
    ] {
        // Revision one models a retained pre-fix JSONB identity mismatch.
        let sha = if revision == 1 {
            "0".repeat(64)
        } else {
            let normalized: Value = sqlx::query_scalar("SELECT $1::jsonb")
                .bind(&source)
                .fetch_one(pool)
                .await?;
            library::digest(&normalized)
        };
        sqlx::query("INSERT INTO cloud_library_versions(document_id,revision,title,document,sha256,status,reviewed_by,reason) VALUES($1,$2,'Recovery fixture',$3,$4,$5,$6,$7)").bind(id).bind(revision).bind(source).bind(sha).bind(status).bind(if revision == 1 {Some(reviewer)} else {None}).bind(if revision == 1 {Some("Original independent review")} else {None}).execute(pool).await?;
    }
    sqlx::query("UPDATE cloud_library_documents SET published_revision=1 WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO cloud_audit_events(id,actor_user_id,subject_id,action) VALUES($1,$2,$3,'library.approved')").bind(uuid::Uuid::new_v4()).bind(reviewer).bind(id).execute(pool).await?;
    sqlx::query("INSERT INTO cloud_workspace_cursors(user_id,cursor) VALUES($1,3)")
        .bind(owner)
        .execute(pool)
        .await?;
    for (collection, key, revision, value) in [
        (
            "plugin-selections",
            "drill.plugin",
            1i64,
            Some(selection("drill.plugin", false)),
        ),
        (
            "rule-templates",
            "drill-rule",
            2,
            Some(document("workspace-source")),
        ),
        ("profiles", "removed-profile", 3, None),
    ] {
        sqlx::query("INSERT INTO cloud_workspace_records(user_id,collection,key,revision,value,deleted) VALUES($1,$2,$3,$4,$5,$6)").bind(owner).bind(collection).bind(key).bind(revision).bind(&value).bind(value.is_none()).execute(pool).await?;
        sqlx::query("INSERT INTO cloud_workspace_changes(user_id,cursor,collection,key,value,deleted) VALUES($1,$2,$3,$4,$5,$6)").bind(owner).bind(revision).bind(collection).bind(key).bind(&value).bind(value.is_none()).execute(pool).await?;
    }
    Ok(id)
}
async fn prove_restored_guards(pool: &PgPool, owner: &str, document: uuid::Uuid) -> TestResult<()> {
    let mut first = pool.begin().await?;
    sqlx::query("SELECT cursor FROM cloud_workspace_cursors WHERE user_id=$1 FOR UPDATE")
        .bind(owner)
        .fetch_one(&mut *first)
        .await?;
    let mut second = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='100ms'")
        .execute(&mut *second)
        .await?;
    let blocked =
        sqlx::query("UPDATE cloud_workspace_cursors SET cursor=cursor+1 WHERE user_id=$1")
            .bind(owner)
            .execute(&mut *second)
            .await;
    let blocked = blocked.unwrap_err();
    let code = blocked
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code.into_owned());
    assert_eq!(
        code.as_deref(),
        Some("55P03"),
        "restored account cursor must still serialize writers"
    );
    second.rollback().await?;
    first.rollback().await?;
    assert!(
        sqlx::query("DELETE FROM \"user\" WHERE id=$1")
            .bind(owner)
            .execute(pool)
            .await
            .is_err(),
        "restored publisher Owner protection must still reject deletion"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE cloud_library_documents SET published_revision=999 WHERE id=$1")
        .bind(document)
        .execute(&mut *tx)
        .await?;
    assert!(
        tx.commit().await.is_err(),
        "restored deferred publication pointer must still reference a real immutable revision"
    );
    Ok(())
}

async fn run_drill(fixture: &mut Fixture) -> TestResult<()> {
    sqlx::query(&format!("CREATE SCHEMA {}", fixture.schema))
        .execute(&fixture.control)
        .await?;
    fixture.created_schema = true;
    let source_url = fixture.schema_url(None);
    let adapter = Arc::new(SqlxDbAdapter::postgres(&source_url).await?);
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(&source_url).await?);
    let auth = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-recovery-secret-32-bytes".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            ..Default::default()
        },
        adapter.clone(),
        Some(secondary.clone()),
        vec![Arc::new(better_auth::UsernamePlugin)],
    )?;
    adapter
        .apply_migrations(&auth.migration_plan(), SqlDialect::Postgres)
        .await?;
    secondary.migrate().await?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&source_url)
        .await?;
    fixture.source = Some(pool.clone());
    migrations_through(PRE_V2).run(&pool).await?;
    let service = EmailPasswordService::new(auth.clone())?;
    let mut users = Vec::new();
    for label in ["owner", "reviewer"] {
        users.push(
            service
                .sign_up(
                    SignUpInput {
                        email: format!("{label}-{}@example.test", uuid::Uuid::new_v4()),
                        name: format!("V2 recovery {label}"),
                        password: "test password with enough characters".into(),
                    },
                    true,
                )
                .await?
                .user
                .id,
        );
    }
    seed_pre_v2(&pool, &users[0], &users[1]).await?;
    let before = table_snapshot(&pool).await?;
    assert_eq!(
        before["user"].as_array().unwrap().len(),
        2,
        "Better Auth accounts must live in the isolated fixture schema"
    );
    assert_eq!(before["cloud_sync_records"].as_array().unwrap().len(), 2);
    assert_eq!(ready(&auth, &pool).await, StatusCode::SERVICE_UNAVAILABLE);
    migrations_through(FIRST_V2).run(&pool).await?;
    let upgraded = table_snapshot(&pool).await?;
    retained_migrations(&before, &upgraded);
    for (table, rows) in before
        .iter()
        .filter(|(table, _)| table.as_str() != "_sqlx_migrations")
    {
        assert_eq!(
            upgraded.get(table),
            Some(rows),
            "pre-v2 rows changed in {table}"
        );
    }
    for table in [
        "cloud_workspace_cursors",
        "cloud_workspace_records",
        "cloud_workspace_changes",
        "cloud_library_documents",
        "cloud_library_versions",
    ] {
        assert_eq!(
            upgraded[table],
            json!([]),
            "v1 must not implicitly migrate into {table}"
        );
    }
    let document = seed_v2(&pool, &users[0], &users[1]).await?;
    let before_repair_migration = table_snapshot(&pool).await?;
    // The digest repair migration alone must not rewrite a single row.
    migrations_through(DIGEST_REPAIR).run(&pool).await?;
    let after_digest_migration = table_snapshot(&pool).await?;
    retained_migrations(&before_repair_migration, &after_digest_migration);
    for (table, rows) in before_repair_migration
        .iter()
        .filter(|(table, _)| table.as_str() != "_sqlx_migrations")
    {
        assert_eq!(
            after_digest_migration.get(table),
            Some(rows),
            "digest repair migration must not rewrite {table}"
        );
    }
    assert_eq!(
        after_digest_migration["cloud_library_digest_repairs"],
        json!([])
    );
    // Later migrations may add columns or tables on purpose, for example the
    // plugin presentation columns, but must keep every value that already existed.
    readiness::MIGRATOR.run(&pool).await?;
    let after_repair_migration = table_snapshot(&pool).await?;
    retained_migrations(&after_digest_migration, &after_repair_migration);
    for (table, rows) in after_digest_migration
        .iter()
        .filter(|(table, _)| table.as_str() != "_sqlx_migrations")
    {
        assert!(
            rows_keep_values(rows, &after_repair_migration[table]),
            "a later migration changed existing values in {table}"
        );
    }
    assert_eq!(
        after_repair_migration["cloud_library_digest_repairs"],
        json!([])
    );
    assert_eq!(ready(&auth, &pool).await, StatusCode::OK);
    assert!(
        migrations_through(PRE_V2).run(&pool).await.is_err(),
        "older migrator must reject the newer schema"
    );
    let future = readiness::MIGRATOR.iter().map(|m| m.version).max().unwrap() + 1000;
    sqlx::query("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES($1,'fixture incompatible future',true,$2,0)").bind(future).bind(vec![0u8;48]).execute(&pool).await?;
    assert_eq!(ready(&auth, &pool).await, StatusCode::SERVICE_UNAVAILABLE);
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=$1")
        .bind(future)
        .execute(&pool)
        .await?;
    assert_eq!(ready(&auth, &pool).await, StatusCode::OK);
    let audit = library_digest_repair::audit(&pool, None, 100).await?;
    assert_eq!(audit.items.len(), 1);
    let mismatch = &audit.items[0];
    assert_eq!(mismatch.document_id, document);
    assert_eq!(mismatch.revision, 1);
    library_digest_repair::repair(
        &pool,
        document,
        1,
        &mismatch.stored_sha256,
        &mismatch.normalized_sha256,
        "v2-recovery-drill",
    )
    .await?;
    let repaired = table_snapshot(&pool).await?;
    assert_eq!(
        repaired["cloud_library_documents"],
        after_repair_migration["cloud_library_documents"]
    );
    assert_eq!(
        repaired["cloud_library_digest_repairs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    for old in after_repair_migration["cloud_library_versions"]
        .as_array()
        .unwrap()
    {
        let new = repaired["cloud_library_versions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["document_id"] == old["document_id"] && row["revision"] == old["revision"]
            })
            .expect("repair must retain every immutable revision");
        let mut old = old.clone();
        if old["revision"] == 1 {
            old["sha256"] = mismatch.normalized_sha256.clone().into();
        }
        assert_eq!(
            &old, new,
            "explicit repair changed source, review or history metadata"
        );
    }
    let dump = tempfile::NamedTempFile::new()?;
    let mut command = tokio::process::Command::new("pg_dump");
    let database = local_backup::configure_pg_command(&mut command, &source_url)?;
    let dumped = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        command
            .args([
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--strict-names",
                "--schema",
            ])
            .arg(&fixture.schema)
            .arg("--file")
            .arg(dump.path())
            .arg("--dbname")
            .arg(database)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    assert!(
        dumped.success(),
        "fixture pg_dump failed; check matching PostgreSQL client tools"
    );
    sqlx::query(&format!("CREATE DATABASE {}", fixture.restore_database))
        .execute(&fixture.control)
        .await?;
    fixture.created_database = true;
    let restore_url = fixture.schema_url(Some(&fixture.restore_database));
    let mut command = tokio::process::Command::new("pg_restore");
    let database = local_backup::configure_pg_command(&mut command, &restore_url)?;
    let restored = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        command
            .args([
                "--no-owner",
                "--no-acl",
                "--exit-on-error",
                "--single-transaction",
                "--dbname",
            ])
            .arg(database)
            .arg(dump.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    assert!(
        restored.success(),
        "fixture pg_restore failed; no configured application database is a restore target"
    );
    let target = PgPoolOptions::new()
        .max_connections(4)
        .connect(&restore_url)
        .await?;
    fixture.restored = Some(target.clone());
    assert_eq!(
        table_snapshot(&target).await?,
        repaired,
        "actual archive restore lost schema rows/history/checksums"
    );
    assert_eq!(ready(&auth, &target).await, StatusCode::OK);
    assert!(library_digest_repair::audit(&target, None, 100)
        .await?
        .items
        .is_empty());
    prove_restored_guards(&target, &users[0], document).await?;
    assert_eq!(
        table_snapshot(&target).await?,
        repaired,
        "negative constraint/lock checks must leave restored state unchanged"
    );
    Ok(())
}

#[test]
fn fixture_urls_reject_overrides_and_nonlocal_or_ambiguous_targets() {
    for raw in [
        "postgres://127.0.0.1/cloud_test_v2?host=external.example.test",
        "postgres://127.0.0.1/cloud_test_v2?hostaddr=192.0.2.10",
        "postgres://127.0.0.1/cloud_test_v2?dbname=production",
        "postgres://127.0.0.1/cloud_test_v2?port=5433",
        "postgres://127.0.0.1/cloud_test_v2?options=-csearch_path%3Dpublic",
        "postgres://127.0.0.1/cloud_test_v2?options%5Bsearch_path%5D=public",
        "postgres://127.0.0.1/cloud_test_v2?sslmode=disable&sslmode=require",
        "postgres://127.0.0.1/cloud_test_v2?unknown=setting",
        "postgres://127.0.0.1/cloud_test%2Fproduction",
        "postgres://127.0.0.1/cloud_test%00v2",
        "postgres://127.0.0.1/production",
        "postgres://192.0.2.10/cloud_test_v2",
        "postgres://[2001:db8::1]/cloud_test_v2",
        "postgres://localhost/cloud_test_v2",
        "postgres://127.1/cloud_test_v2",
        "https://127.0.0.1/cloud_test_v2",
    ] {
        assert!(validate_fixture_url(raw).is_err(), "accepted {raw}");
    }
    // PostgreSQL's identifier limit applies to decoded bytes, not URL spelling
    // or Unicode scalar count.
    for database in [
        format!("test_{}", "a".repeat(59)),
        format!("test_{}", "é".repeat(30)),
    ] {
        assert!(validate_fixture_url(&format!("postgres://127.0.0.1/{database}")).is_err());
    }
}

#[test]
fn fixture_urls_accept_literal_loopback_test_databases_without_connecting() {
    for raw in [
        "postgres://127.0.0.1:50401/cloud_test_v2",
        "postgresql://fixture:synthetic%40password@127.0.0.1/test_v2?sslmode=disable",
        "postgres://[::1]:50401/cloud_test_v2?application_name=recovery-drill",
        "postgres://127.0.0.1/test_%31",
    ] {
        assert!(validate_fixture_url(raw).is_ok(), "rejected {raw}");
    }
    let max_name = format!("test_{}", "a".repeat(58));
    assert!(validate_fixture_url(&format!("postgres://127.0.0.1/{max_name}")).is_ok());
}

#[tokio::test]
#[ignore = "requires local disposable CLOUD_TEST_DATABASE_URL, CREATEDB and matching pg_dump/pg_restore; run serialized"]
async fn populated_pre_v2_upgrade_and_real_archive_restore_preserve_all_domains() {
    let mut fixture = Fixture::new()
        .await
        .expect("use only a dedicated loopback PostgreSQL test database");
    let result = AssertUnwindSafe(run_drill(&mut fixture))
        .catch_unwind()
        .await;
    fixture.cleanup().await;
    match result {
        Ok(Ok(())) => (),
        Ok(Err(error)) => panic!("v2 recovery fixture failed: {error}"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
