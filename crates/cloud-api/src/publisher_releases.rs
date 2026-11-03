//! Publisher-scoped release listing. Members see their own publisher's releases
//! with verification progress, moderation decisions, and yank/advisory state.
//! This is a read projection over existing tables; it creates no releases.
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use better_auth::axum_integration::AuthUser;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

fn db(_: sqlx::Error) -> StatusCode {
    tracing::error!("publisher release listing failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

const PAGE_DEFAULT: i64 = 50;
const PAGE_MAX: i64 = 100;

fn page_limit(limit: Option<i64>) -> Result<i64, StatusCode> {
    match limit {
        None => Ok(PAGE_DEFAULT),
        Some(n) if (1..=PAGE_MAX).contains(&n) => Ok(n),
        Some(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryView {
    severity: String,
    message: String,
    url: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModerationView {
    decision: String,
    reason_code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationView {
    status: String,
    result_class: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseItem {
    id: Uuid,
    publisher_id: Uuid,
    upload_id: Uuid,
    publisher_key_id: Uuid,
    plugin_id: String,
    version: String,
    target: String,
    status: String,
    sha256: String,
    size: i64,
    key_id: String,
    key_fingerprint: String,
    yanked: bool,
    yank_reason: Option<String>,
    advisory: Option<AdvisoryView>,
    moderation: Option<ModerationView>,
    verification: Option<VerificationView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleasePage {
    items: Vec<ReleaseItem>,
    next_cursor: Option<Uuid>,
}

/// Any membership grants read access; non-members get NOT_FOUND so publisher
/// release history is not enumerable by outsiders.
async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    publisher: Uuid,
    user: &str,
) -> Result<(), StatusCode> {
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM cloud_publishers WHERE id = $1 FOR UPDATE")
            .bind(publisher)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?;
    if exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cloud_publisher_memberships WHERE publisher_id = $1 AND user_id = $2)",
    )
    .bind(publisher)
    .bind(user)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if !member {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(())
}

pub async fn list(
    AuthUser(user): AuthUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReleasePageQuery>,
) -> Result<Json<ReleasePage>, StatusCode> {
    let limit = page_limit(query.limit)?;
    let mut tx = state.pool.begin().await.map_err(db)?;
    authorize(&mut tx, id, &user.user.id).await?;
    // Resolve the cursor to a stable (created_at, id) position. An unknown
    // cursor is a broken or forged page reference, not an empty page.
    let cursor: Option<(chrono::DateTime<chrono::Utc>, Uuid)> = match query.cursor {
        None => None,
        Some(cursor_id) => {
            let row = sqlx::query(
                "SELECT created_at, id FROM cloud_plugin_releases WHERE id = $1 AND publisher_id = $2",
            )
            .bind(cursor_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(StatusCode::BAD_REQUEST)?;
            Some((row.get("created_at"), row.get("id")))
        }
    };
    let (cursor_at, cursor_id) = match cursor {
        Some((at, cursor_id)) => (Some(at), Some(cursor_id)),
        None => (None, None),
    };
    let rows = sqlx::query(
        "SELECT r.id, r.publisher_id, r.upload_id, r.publisher_key_id, r.plugin_id, r.version, r.target, r.status, r.created_at, u.expected_sha256, u.expected_size, k.key_id, k.fingerprint, y.reason AS yank_reason, a.severity AS advisory_severity, a.message AS advisory_message, a.url AS advisory_url, m.decision AS moderation_decision, m.reason_code AS moderation_reason, v.status AS verification_status, v.result_class AS verification_result FROM cloud_plugin_releases r JOIN cloud_upload_sessions u ON u.id = r.upload_id AND u.publisher_id = r.publisher_id JOIN cloud_publisher_keys k ON k.id = r.publisher_key_id AND k.publisher_id = r.publisher_id LEFT JOIN cloud_release_yanks y ON y.release_id = r.id LEFT JOIN cloud_release_advisories a ON a.release_id = r.id LEFT JOIN cloud_moderation_events m ON m.release_id = r.id LEFT JOIN cloud_verification_jobs v ON v.upload_id = u.id AND v.release_id = r.id WHERE r.publisher_id = $1 AND (($2::timestamptz IS NULL AND $3::uuid IS NULL) OR (r.created_at, r.id) < ($2, $3)) ORDER BY r.created_at DESC, r.id DESC LIMIT $4",
    )
    .bind(id)
    .bind(cursor_at)
    .bind(cursor_id)
    .bind(limit + 1)
    .fetch_all(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    let more = rows.len() as i64 > limit;
    let items: Vec<ReleaseItem> = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| {
            let yank_reason: Option<String> = row.get("yank_reason");
            ReleaseItem {
                id: row.get("id"),
                publisher_id: row.get("publisher_id"),
                upload_id: row.get("upload_id"),
                publisher_key_id: row.get("publisher_key_id"),
                plugin_id: row.get("plugin_id"),
                version: row.get("version"),
                target: row.get("target"),
                status: row.get("status"),
                sha256: row.get("expected_sha256"),
                size: row.get("expected_size"),
                key_id: row.get("key_id"),
                key_fingerprint: row.get("fingerprint"),
                yanked: yank_reason.is_some(),
                yank_reason,
                advisory: row
                    .get::<Option<String>, _>("advisory_severity")
                    .map(|severity| AdvisoryView {
                        severity,
                        message: row.get("advisory_message"),
                        url: row.get("advisory_url"),
                    }),
                moderation: row
                    .get::<Option<String>, _>("moderation_decision")
                    .map(|decision| ModerationView {
                        decision,
                        reason_code: row.get("moderation_reason"),
                    }),
                verification: row
                    .get::<Option<String>, _>("verification_status")
                    .map(|status| VerificationView {
                        status,
                        result_class: row.get("verification_result"),
                    }),
            }
        })
        .collect();
    let next_cursor = if more {
        items.last().map(|item| item.id)
    } else {
        None
    };
    Ok(Json(ReleasePage { items, next_cursor }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_page_limits_accept_only_bounded_values() {
        assert_eq!(page_limit(None).unwrap(), 50);
        assert_eq!(page_limit(Some(1)).unwrap(), 1);
        assert_eq!(page_limit(Some(100)).unwrap(), 100);
        assert!(page_limit(Some(0)).is_err());
        assert!(page_limit(Some(101)).is_err());
    }
}
