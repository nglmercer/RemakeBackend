//! Read-only readiness checks. They never apply migrations or expose schema details.
use crate::AppState;
use axum::{extract::State, http::StatusCode};
use sqlx::{migrate::Migrator, Row};
use std::time::Duration;

pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

pub async fn ready(State(state): State<AppState>) -> StatusCode {
    match tokio::time::timeout(Duration::from_secs(3), check(&state)).await {
        Ok(true) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn check(state: &AppState) -> bool {
    let Ok(rows) =
        sqlx::query("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&state.pool)
            .await
    else {
        return false;
    };
    let expected: Vec<_> = MIGRATOR
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .collect();
    if rows.len() != expected.len() {
        return false;
    }
    for (row, migration) in rows.iter().zip(expected) {
        let (Ok(version), Ok(checksum), Ok(success)) = (
            row.try_get::<i64, _>("version"),
            row.try_get::<Vec<u8>, _>("checksum"),
            row.try_get::<bool, _>("success"),
        ) else {
            return false;
        };
        if version != migration.version || checksum != migration.checksum.as_ref() || !success {
            return false;
        }
    }
    // Auth's schema is supplied by the pinned library, including any enabled plugins.
    // This checks column presence and basic privileges, not type/index correctness.
    let mut tables = Vec::new();
    let mut columns = Vec::new();
    for (table, schema) in &state.auth.schema.tables {
        for column in schema.fields.keys() {
            tables.push(table.clone());
            columns.push(column.clone());
        }
    }
    for (table, fields) in [
        (
            "_better_auth_kv",
            &["storage_key", "value_json", "expires_at"][..],
        ),
        ("cloud_account_roles", &["user_id", "role"][..]),
        (
            "cloud_publishers",
            &["id", "namespace", "status", "created_at"],
        ),
        (
            "cloud_publisher_memberships",
            &["publisher_id", "user_id", "role"],
        ),
        (
            "cloud_audit_events",
            &[
                "id",
                "actor_user_id",
                "publisher_id",
                "action",
                "created_at",
                "target_user_id",
                "old_role",
                "new_role",
                "subject_id",
            ],
        ),
        (
            "cloud_publisher_key_challenges",
            &[
                "id",
                "publisher_id",
                "actor_user_id",
                "nonce",
                "expires_at",
                "consumed_at",
            ][..],
        ),
        (
            "cloud_publisher_keys",
            &[
                "id",
                "publisher_id",
                "key_id",
                "public_key",
                "fingerprint",
                "status",
                "requested_by",
                "created_at",
            ][..],
        ),
        (
            "cloud_upload_sessions",
            &[
                "id",
                "publisher_id",
                "requested_by",
                "idempotency_key",
                "expected_size",
                "expected_sha256",
                "object_key",
                "status",
                "expires_at",
                "version_id",
            ][..],
        ),
        (
            "cloud_verification_jobs",
            &[
                "upload_id",
                "release_id",
                "status",
                "created_at",
                "lease_id",
                "lease_expires_at",
                "attempts",
                "result_class",
            ][..],
        ),
        (
            "cloud_plugin_releases",
            &[
                "id",
                "publisher_id",
                "upload_id",
                "publisher_key_id",
                "plugin_id",
                "version",
                "target",
                "status",
                "requested_by",
                "created_at",
            ][..],
        ),
        (
            "cloud_publisher_transfers",
            &[
                "id",
                "publisher_id",
                "offered_by",
                "recipient",
                "created_at",
                "expires_at",
            ][..],
        ),
        (
            "cloud_snapshot_candidates",
            &[
                "id",
                "status",
                "root_fingerprint",
                "inventory_sha256",
                "release_count",
                "file_count",
                "created_at",
            ][..],
        ),
        (
            "cloud_snapshot_candidate_releases",
            &[
                "candidate_id",
                "publication_job_id",
                "prepared_key",
                "prepared_version_id",
                "sha256",
            ][..],
        ),
        (
            "cloud_release_yanks",
            &["release_id", "yanked_by", "reason", "created_at"][..],
        ),
        (
            "cloud_release_advisories",
            &[
                "release_id",
                "severity",
                "message",
                "url",
                "created_by",
                "created_at",
            ][..],
        ),
        (
            "cloud_snapshot_candidate_files",
            &[
                "candidate_id",
                "path",
                "sha256",
                "size",
                "object_key",
                "version_id",
            ][..],
        ),
        (
            "cloud_snapshot_promotion_checks",
            &[
                "id",
                "candidate_id",
                "inventory_sha256",
                "manifest_sha256",
                "decision",
                "operator",
                "reason",
                "created_at",
            ][..],
        ),
        (
            "cloud_publication_jobs",
            &[
                "id",
                "release_id",
                "requested_by",
                "status",
                "created_at",
                "lease_id",
                "lease_expires_at",
                "attempts",
                "result_class",
                "prepared_key",
                "prepared_version_id",
            ][..],
        ),
        (
            "cloud_registry_generations",
            &[
                "id",
                "generation",
                "candidate_id",
                "inventory_sha256",
                "manifest_sha256",
                "root_fingerprint",
                "index_key_id",
                "release_count",
                "file_count",
                "status",
                "created_at",
                "activated_at",
                "activated_by",
                "superseded_by",
            ][..],
        ),
        (
            "cloud_registry_generation_releases",
            &[
                "generation",
                "plugin_id",
                "version",
                "target",
                "release_id",
                "sha256",
                "size",
                "object_key",
                "version_id",
                "advisory_severity",
                "advisory_message",
                "advisory_url",
            ][..],
        ),
        (
            "cloud_registry_generation_files",
            &[
                "generation",
                "path",
                "sha256",
                "size",
                "object_key",
                "version_id",
            ][..],
        ),
        (
            "cloud_registry_promotions",
            &[
                "id",
                "generation",
                "candidate_id",
                "decision",
                "operator",
                "reason",
                "created_at",
            ][..],
        ),
        (
            "cloud_moderation_events",
            &[
                "id",
                "release_id",
                "actor_user_id",
                "decision",
                "reason_code",
                "created_at",
            ][..],
        ),
        ("cloud_sync_cursors", &["user_id", "cursor"]),
        (
            "cloud_sync_records",
            &[
                "user_id",
                "collection",
                "key",
                "revision",
                "value",
                "deleted",
            ],
        ),
        (
            "cloud_sync_changes",
            &["user_id", "cursor", "collection", "key", "value", "deleted"],
        ),
    ] {
        for field in fields {
            tables.push(table.to_owned());
            columns.push((*field).to_owned());
        }
    }
    let result: Result<bool, _> = sqlx::query_scalar(r#"
        SELECT COALESCE(bool_and(a.attnum IS NOT NULL
            AND has_table_privilege(c.oid, 'SELECT')
            AND has_table_privilege(c.oid, 'INSERT')
            AND has_table_privilege(c.oid, 'UPDATE')
            AND has_table_privilege(c.oid, 'DELETE')), false)
        FROM unnest($1::text[], $2::text[]) AS expected(table_name, column_name)
        LEFT JOIN pg_class c ON c.oid = to_regclass(quote_ident(expected.table_name))
        LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = expected.column_name AND a.attnum > 0 AND NOT a.attisdropped
    "#).bind(&tables).bind(&columns).fetch_one(&state.pool).await;
    result.unwrap_or(false)
}
