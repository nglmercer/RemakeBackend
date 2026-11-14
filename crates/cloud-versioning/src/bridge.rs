//! The credential bridge: turns an identity the backend has already verified into a short-lived
//! protocol credential for Lore's native endpoints (clone, fetch and push by the Lore CLI).
//!
//! The in-process path never uses it. A browser or SDK request is authenticated by Better Auth
//! and authorized by the backend's own policy. The native endpoints authenticate independently,
//! so they accept a signed JWT whose claims carry the repositories the holder may use and the
//! actions on each. Lore verifies the signature against the key set the backend publishes, checks
//! issuer, audience and expiry, and answers every repository access from the grants in the token.
//!
//! What this is not: an OpenID Connect provider. It publishes a key set and nothing else, and
//! refuses to mint without a verified subject. Authorization is bounded by the token lifetime: a
//! grant revoked in the backend stays usable until the token expires, so keep the lifetime short.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

/// What a token holder may do on one repository. Lore's actions are `read`, `write`, `owner`,
/// `admin`, `migrate`, `push-protected`, `obliterate` and `presign`; `read` is implied by any
/// grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryGrant {
    /// The repository id as Lore prints it (32 hexadecimal characters), or `None` for every
    /// repository. A wildcard grant is for service identities, never for a user's workspace.
    pub repository_id: Option<String>,
    /// The granted actions.
    pub actions: Vec<String>,
}

#[derive(Serialize)]
struct Resource {
    resource_id: String,
    permission: Vec<String>,
}

#[derive(Serialize)]
struct Claims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
    resources: Vec<Resource>,
}

/// Signs protocol credentials and publishes the key that verifies them.
pub struct CredentialBridge {
    issuer: String,
    audience: String,
    key_id: String,
    encoding_key: EncodingKey,
    public_x: String,
}

impl CredentialBridge {
    /// Creates a bridge with a fresh in-memory signing key.
    ///
    /// The key is not persisted: a restart invalidates every outstanding token, which is the
    /// right default for a credential that lives for minutes. A deployment with several
    /// processes must share one key and rotate it by publishing both keys in the key set.
    ///
    /// # Errors
    ///
    /// Fails when the key cannot be encoded for signing.
    pub fn generate(issuer: &str, audience: &str) -> Result<Self> {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let der = signing_key
            .to_pkcs8_der()
            .context("encoding the signing key")?;
        let public = signing_key.verifying_key();
        let public_x = URL_SAFE_NO_PAD.encode(public.as_bytes());
        // The key id is derived from the public key, so it changes with the key.
        let key_id = URL_SAFE_NO_PAD.encode(&public.as_bytes()[..12]);
        Ok(Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            key_id,
            encoding_key: EncodingKey::from_ed_der(der.as_bytes()),
            public_x,
        })
    }

    /// The issuer claim of every token, which Lore is configured to require.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The audience claim of every token, which Lore is configured to require.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The public key set (JWKS) that Lore fetches to verify signatures. Contains no secret.
    #[must_use]
    pub fn jwks_json(&self) -> String {
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": self.key_id,
                "x": self.public_x,
            }]
        })
        .to_string()
    }

    /// Mints a token for `subject` valid for `lifetime_seconds`, carrying `grants`.
    ///
    /// `subject` must be the stable identity of an account the caller has already verified
    /// (issuer plus subject of the Better Auth user). This function trusts it: authorize before
    /// calling, and derive `grants` from trusted server state, never from request data.
    ///
    /// # Errors
    ///
    /// Fails when `subject` is empty, `lifetime_seconds` is zero, or signing fails.
    pub fn mint(
        &self,
        subject: &str,
        grants: &[RepositoryGrant],
        lifetime_seconds: u64,
    ) -> Result<String> {
        anyhow::ensure!(!subject.is_empty(), "a token needs a verified subject");
        anyhow::ensure!(lifetime_seconds > 0, "a token needs a lifetime");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("reading the clock")?
            .as_secs();
        let resources = grants
            .iter()
            .map(|grant| Resource {
                // `urc-{id}` is Lore's default resource name template, and `urc-*` its
                // wildcard.
                resource_id: match &grant.repository_id {
                    Some(id) => format!("urc-{id}"),
                    None => "urc-*".to_string(),
                },
                permission: grant.actions.clone(),
            })
            .collect();
        let claims = Claims {
            sub: subject,
            iss: &self.issuer,
            aud: &self.audience,
            iat: now,
            exp: now + lifetime_seconds,
            resources,
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());
        jsonwebtoken::encode(&header, &claims, &self.encoding_key).context("signing the token")
    }
}

/// How the embedded server verifies the tokens the bridge mints.
#[derive(Debug, Clone)]
pub struct NativeAuth {
    /// Must equal [`CredentialBridge::issuer`].
    pub issuer: String,
    /// Must equal [`CredentialBridge::audience`].
    pub audience: String,
    /// Where the server fetches the key set, serving [`CredentialBridge::jwks_json`]. The
    /// server refuses plain `http` for an `https` issuer, so use a loopback `http` issuer only
    /// for local evaluation.
    pub jwks_url: String,
}
