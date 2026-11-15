//! Revocation of native credentials.
//!
//! A host revokes an account's credentials by recording a cutoff: every token of that account
//! issued before the cutoff is refused from then on. The engine consults the cutoffs on every
//! repository access through [`RevocableAuthorizer`], which wraps the grants authorizer the
//! engine would otherwise use.
//!
//! Limits, stated where they bind: the cutoffs live in one process. A deployment with several
//! engines must propagate them, and until it does a revocation takes effect at most at the
//! credential's lifetime. A session already open keeps the grants it started with until it ends,
//! because the engine checks each command against the grants recorded at session start.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use lore_base::types::RepositoryId;
use lore_server::authnz::repository_authorizer::{
    Action, Grants, RepositoryAuthorizer, VerifiedToken,
};
use lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer;

use crate::tonic::Status;

/// Revocation cutoffs by account, in milliseconds since the Unix epoch.
#[derive(Default)]
pub struct RevocationList {
    cutoffs: RwLock<HashMap<String, u64>>,
}

impl RevocationList {
    /// An empty list: nothing is revoked.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Refuses every credential of `subject` issued before `at_ms`. A later cutoff replaces an
    /// earlier one; an earlier one never weakens a later one.
    pub fn revoke_before(&self, subject: &str, at_ms: u64) {
        let mut cutoffs = self
            .cutoffs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = cutoffs.entry(subject.to_string()).or_insert(0);
        if at_ms > *entry {
            *entry = at_ms;
        }
    }

    /// Whether a credential of `subject`, issued at `issued_ms`, is refused. A credential with no
    /// issue time is refused whenever the account has a cutoff, so an unknown token fails closed.
    #[must_use]
    pub fn is_revoked(&self, subject: &str, issued_ms: Option<u64>) -> bool {
        let cutoffs = self
            .cutoffs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match cutoffs.get(subject) {
            None => false,
            Some(cutoff) => issued_ms.is_none_or(|issued| issued < *cutoff),
        }
    }
}

/// The current time in milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// The repository authorizer the engine runs with: refuses revoked credentials, and otherwise
/// answers from the grants each token carries, as the engine's own grants authorizer does.
pub struct RevocableAuthorizer {
    inner: ResourceGrantsAuthorizer,
    revocations: Arc<RevocationList>,
}

impl RevocableAuthorizer {
    /// The authorizer for tokens that carry their grants in the `resources` claim, named by
    /// `urc-{id}` and `urc-*`, which is what the backend mints.
    #[must_use]
    pub fn new(revocations: Arc<RevocationList>) -> Self {
        Self {
            inner: ResourceGrantsAuthorizer::new(
                "resources".to_string(),
                "resource_id".to_string(),
                None,
                "urc-{id}".to_string(),
                "urc-*".to_string(),
            ),
            revocations,
        }
    }

    fn revoked(&self, token: &VerifiedToken<'_>) -> bool {
        let issued_ms = token
            .claims
            .extra
            .get("iat_ms")
            .and_then(serde_json::Value::as_u64);
        self.revocations
            .is_revoked(&token.claims.user_id, issued_ms)
    }
}

#[async_trait]
impl RepositoryAuthorizer for RevocableAuthorizer {
    async fn check_repository_access(
        &self,
        token: Option<&VerifiedToken<'_>>,
        repository_id: RepositoryId,
        action: Action,
    ) -> Result<(), Status> {
        if token.is_some_and(|token| self.revoked(token)) {
            return Err(Status::unauthenticated("the credential was revoked"));
        }
        self.inner
            .check_repository_access(token, repository_id, action)
            .await
    }

    async fn granted_actions(
        &self,
        token: Option<&VerifiedToken<'_>>,
        repository_id: RepositoryId,
    ) -> Result<Option<Grants>, Status> {
        if token.is_some_and(|token| self.revoked(token)) {
            return Ok(Some(Grants::Denied));
        }
        self.inner.granted_actions(token, repository_id).await
    }

    fn check_repository_access_sync(
        &self,
        token: Option<&VerifiedToken<'_>>,
        repository_id: RepositoryId,
        action: Action,
    ) -> Option<Result<(), Status>> {
        if token.is_some_and(|token| self.revoked(token)) {
            return Some(Err(Status::unauthenticated("the credential was revoked")));
        }
        self.inner
            .check_repository_access_sync(token, repository_id, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cutoff_refuses_only_older_credentials() {
        let list = RevocationList::new();
        assert!(
            !list.is_revoked("alice", Some(10)),
            "no cutoff, nothing refused"
        );
        list.revoke_before("alice", 100);
        assert!(list.is_revoked("alice", Some(99)));
        assert!(
            !list.is_revoked("alice", Some(100)),
            "issued at the cutoff is valid"
        );
        assert!(
            !list.is_revoked("bob", Some(1)),
            "other accounts are unaffected"
        );
    }

    #[test]
    fn a_credential_without_an_issue_time_is_refused_once_revoked() {
        let list = RevocationList::new();
        list.revoke_before("alice", 100);
        assert!(list.is_revoked("alice", None));
    }

    #[test]
    fn a_later_cutoff_replaces_an_earlier_one_and_never_the_reverse() {
        let list = RevocationList::new();
        list.revoke_before("alice", 200);
        list.revoke_before("alice", 100);
        assert!(
            list.is_revoked("alice", Some(150)),
            "the earlier call did not weaken it"
        );
    }

    /// The engine's own authorizer refuses a revoked token before it looks at any grant, and does
    /// not refuse a current one on account of the revocation.
    #[test]
    fn the_authorizer_refuses_a_revoked_token_before_its_grants() {
        use lore_server::auth::jwt::AuthorizationToken;
        let list = Arc::new(RevocationList::new());
        let authorizer = RevocableAuthorizer::new(list.clone());
        let token = |issued_ms: u64| {
            serde_json::from_value::<AuthorizationToken>(serde_json::json!({
                "sub": "alice",
                "iss": "remake-backend",
                "iat": issued_ms / 1000,
                "exp": issued_ms / 1000 + 300,
                "aud": ["remake-native"],
                "iat_ms": issued_ms,
            }))
            .expect("a token claim set")
        };
        let old = token(1_000);
        let current = token(5_000);
        list.revoke_before("alice", 3_000);

        let check = |claims: &AuthorizationToken| {
            let verified = VerifiedToken { raw: "", claims };
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(authorizer.check_repository_access(
                    Some(&verified),
                    RepositoryId::from([7u8; 16]),
                    Action::Read,
                ))
        };
        let refused = check(&old).expect_err("a credential from before the cutoff is refused");
        assert_eq!(refused.code(), crate::tonic::Code::Unauthenticated);
        // A credential from after the cutoff is not refused for the revocation; it is refused
        // only if the grants do not reach the repository, which is a different answer.
        let current_answer = check(&current);
        assert!(
            current_answer
                .as_ref()
                .err()
                .is_none_or(|status| status.code() != crate::tonic::Code::Unauthenticated),
            "a current credential is not refused as revoked"
        );
    }
}
