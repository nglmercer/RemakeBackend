//! S3 quarantine primitives. They do not authorize publishers or publish artifacts.
#![forbid(unsafe_code)]
use aws_sdk_s3::{
    config::{Credentials, Region},
    presigning::PresigningConfig,
    primitives::ByteStream,
    types::BucketVersioningStatus,
    Client,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, time::Duration};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;
use uuid::Uuid;

pub const MAX_ARTIFACT_SIZE: i64 = 128 * 1024 * 1024;
pub const MAX_URL_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid storage configuration or upload metadata")]
    Invalid,
    #[error("object storage is unavailable")]
    Unavailable,
    #[error("object storage must have versioning enabled")]
    VersioningRequired,
    #[error("object is missing a valid immutable version or has an unexpected size")]
    InvalidObject,
    #[error("required upload headers are not signed")]
    UnsafePresign,
}

// Do not derive Debug: this contains credentials.
pub struct Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}
#[derive(Clone)]
pub struct QuarantineStore {
    client: Client,
    bucket: String,
}
// This is a bearer capability: avoid Debug and logging it.
pub struct PresignedUpload {
    pub url: String,
    pub headers: BTreeMap<String, String>,
}
// The URL is a bearer capability and must never be logged.
pub struct PresignedDownload {
    pub url: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectVersion {
    pub version_id: String,
    pub size: i64,
}

impl QuarantineStore {
    pub fn new(config: Config) -> Result<Self, StorageError> {
        let endpoint = Url::parse(&config.endpoint).map_err(|_| StorageError::Invalid)?;
        let loopback = matches!(endpoint.host_str(), Some("127.0.0.1" | "[::1]"));
        if !(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback)
            || endpoint.host().is_none()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || config.region.is_empty()
            || config.region.len() > 64
            || !config
                .region
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || !valid_bucket(&config.bucket)
            || config.access_key.is_empty()
            || config.secret_key.is_empty()
        {
            return Err(StorageError::Invalid);
        }
        let credentials = Credentials::new(
            config.access_key,
            config.secret_key,
            None,
            None,
            "cloud-explicit",
        );
        let settings = aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new(config.region))
            .credentials_provider(credentials)
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(3))
                    .operation_attempt_timeout(Duration::from_secs(5))
                    .operation_timeout(Duration::from_secs(10))
                    .build(),
            )
            .endpoint_url(endpoint.as_str())
            .force_path_style(true)
            .build();
        Ok(Self {
            client: Client::from_conf(settings),
            bucket: config.bucket,
        })
    }
    async fn require_versioning(&self) -> Result<(), StorageError> {
        let response = self
            .client
            .get_bucket_versioning()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|_| StorageError::Unavailable)?;
        if response.status() != Some(&BucketVersioningStatus::Enabled) {
            return Err(StorageError::VersioningRequired);
        }
        Ok(())
    }
    /// Signed headers bind the declared size, checksum and conditional write.
    /// The caller must authorize and allocate the opaque quarantine key first.
    pub async fn presign_upload(
        &self,
        key: &str,
        size: i64,
        sha256: &str,
        ttl: Duration,
    ) -> Result<PresignedUpload, StorageError> {
        if !valid_key(key)
            || !(1..=MAX_ARTIFACT_SIZE).contains(&size)
            || ttl.as_secs() == 0
            || ttl.subsec_nanos() != 0
            || ttl > MAX_URL_TTL
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(StorageError::Invalid);
        }
        let digest = hex::decode(sha256).map_err(|_| StorageError::Invalid)?;
        let checksum = STANDARD.encode(digest);
        self.require_versioning().await?;
        let presign = PresigningConfig::expires_in(ttl).map_err(|_| StorageError::Invalid)?;
        let signed = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_length(size)
            .checksum_sha256(&checksum)
            .if_none_match("*")
            .presigned(presign)
            .await
            .map_err(|_| StorageError::Unavailable)?;
        let headers: BTreeMap<String, String> = signed
            .headers()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
            .collect();
        let url = Url::parse(signed.uri()).map_err(|_| StorageError::UnsafePresign)?;
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        if headers.get("content-length").map(String::as_str) != Some(size.to_string().as_str())
            || headers.get("if-none-match").map(String::as_str) != Some("*")
            || headers.get("x-amz-checksum-sha256").map(String::as_str) != Some(checksum.as_str())
            || query.get("X-Amz-Expires").map(String::as_str)
                != Some(ttl.as_secs().to_string().as_str())
        {
            return Err(StorageError::UnsafePresign);
        }
        let signed_headers = query
            .get("X-Amz-SignedHeaders")
            .ok_or(StorageError::UnsafePresign)?;
        for name in ["content-length", "if-none-match", "x-amz-checksum-sha256"] {
            if !headers.contains_key(name) || !signed_headers.split(';').any(|v| v == name) {
                return Err(StorageError::UnsafePresign);
            }
        }
        Ok(PresignedUpload {
            url: signed.uri().to_owned(),
            headers,
        })
    }
    /// Generate an attachment download capability for one immutable quarantine version.
    pub async fn presign_inspection(
        &self,
        key: &str,
        version_id: &str,
        ttl: Duration,
    ) -> Result<PresignedDownload, StorageError> {
        if !valid_key(key)
            || version_id.is_empty()
            || version_id == "null"
            || version_id.len() > 1024
            || ttl.subsec_nanos() != 0
            || !(1..=60).contains(&ttl.as_secs())
        {
            return Err(StorageError::Invalid);
        }
        self.require_versioning().await?;
        let config = PresigningConfig::expires_in(ttl).map_err(|_| StorageError::Invalid)?;
        let signed = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .version_id(version_id)
            .response_content_type("application/octet-stream")
            .response_content_disposition("attachment")
            .response_cache_control("no-store")
            .presigned(config)
            .await
            .map_err(|_| StorageError::Unavailable)?;
        let url = Url::parse(signed.uri()).map_err(|_| StorageError::UnsafePresign)?;
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        if query.get("versionId").map(String::as_str) != Some(version_id)
            || query.get("response-content-type").map(String::as_str)
                != Some("application/octet-stream")
            || query
                .get("response-content-disposition")
                .map(String::as_str)
                != Some("attachment")
            || query.get("response-cache-control").map(String::as_str) != Some("no-store")
            || query.get("X-Amz-Expires").map(String::as_str)
                != Some(ttl.as_secs().to_string().as_str())
        {
            return Err(StorageError::UnsafePresign);
        }
        Ok(PresignedDownload {
            url: signed.uri().to_owned(),
        })
    }

    /// Store an independently verified private file under a fresh server-generated key,
    /// then read the exact returned version back and verify size and digest.
    /// An error may leave an unreferenced object version for later cleanup.
    pub async fn stage_verified(
        &self,
        publisher: Uuid,
        attempt: Uuid,
        path: &Path,
        size: i64,
        sha256: &str,
    ) -> Result<(String, ObjectVersion), StorageError> {
        self.stage_under(
            &format!("prepared/{publisher}/{attempt}"),
            path,
            size,
            sha256,
        )
        .await
    }

    /// Store an independently verified public registry file under a fresh
    /// server-generated key inside one immutable generation, then read the
    /// exact returned version back and verify size and digest. Published files
    /// are immutable: the generation directory is never modified in place.
    pub async fn stage_public_file(
        &self,
        generation: Uuid,
        path: &Path,
        size: i64,
        sha256: &str,
    ) -> Result<(String, ObjectVersion), StorageError> {
        self.stage_under(
            &format!("public/{generation}/{}", Uuid::new_v4()),
            path,
            size,
            sha256,
        )
        .await
    }

    async fn stage_under(
        &self,
        key: &str,
        path: &Path,
        size: i64,
        sha256: &str,
    ) -> Result<(String, ObjectVersion), StorageError> {
        if !(valid_prepared_key(key) || valid_public_key(key))
            || !(1..=MAX_ARTIFACT_SIZE).contains(&size)
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(StorageError::Invalid);
        }
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|_| StorageError::Unavailable)?;
        if !metadata.is_file() || metadata.len() != size as u64 {
            return Err(StorageError::InvalidObject);
        }
        self.require_versioning().await?;
        let checksum = STANDARD.encode(hex::decode(sha256).map_err(|_| StorageError::Invalid)?);
        let body = ByteStream::from_path(path)
            .await
            .map_err(|_| StorageError::Unavailable)?;
        let response = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_length(size)
            .checksum_sha256(checksum)
            .if_none_match("*")
            .body(body)
            .send()
            .await
            .map_err(|_| StorageError::Unavailable)?;
        let version_id = response
            .version_id()
            .filter(|v| !v.is_empty() && *v != "null" && v.len() <= 1024)
            .ok_or(StorageError::InvalidObject)?
            .to_owned();
        let version = ObjectVersion { version_id, size };
        self.download_version(key, &version, sha256, tokio::io::sink())
            .await?;
        Ok((key.to_owned(), version))
    }

    /// Delete one exact version. Used only by bounded registry garbage
    /// collection for versions no generation or promotable candidate needs.
    pub async fn delete_version(&self, key: &str, version_id: &str) -> Result<(), StorageError> {
        if !(valid_key(key) || valid_prepared_key(key) || valid_public_key(key))
            || version_id.is_empty()
            || version_id == "null"
            || version_id.len() > 1024
        {
            return Err(StorageError::Invalid);
        }
        self.require_versioning().await?;
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .version_id(version_id)
            .send()
            .await
            .map_err(|_| StorageError::Unavailable)?;
        Ok(())
    }

    /// Stream a captured version to a private temporary sink and verify its digest.
    /// On error the sink may contain partial/untrusted bytes and must be discarded.
    pub async fn download_version<W: AsyncWrite + Unpin>(
        &self,
        key: &str,
        version: &ObjectVersion,
        expected_sha256: &str,
        mut output: W,
    ) -> Result<(), StorageError> {
        if !(valid_key(key) || valid_prepared_key(key) || valid_public_key(key))
            || !(1..=MAX_ARTIFACT_SIZE).contains(&version.size)
            || version.version_id.is_empty()
            || version.version_id == "null"
            || version.version_id.len() > 1024
            || expected_sha256.len() != 64
            || !expected_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(StorageError::Invalid);
        }
        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .version_id(&version.version_id)
            .send()
            .await
            .map_err(|_| StorageError::Unavailable)?;
        if result.version_id() != Some(version.version_id.as_str())
            || result.content_length() != Some(version.size)
        {
            return Err(StorageError::InvalidObject);
        }
        let mut stream = result.body.into_async_read();
        let mut hash = Sha256::new();
        let mut total = 0_i64;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let n = stream
                .read(&mut buffer)
                .await
                .map_err(|_| StorageError::Unavailable)?;
            if n == 0 {
                break;
            }
            total = total
                .checked_add(n as i64)
                .ok_or(StorageError::InvalidObject)?;
            if total > version.size {
                return Err(StorageError::InvalidObject);
            }
            hash.update(&buffer[..n]);
            output
                .write_all(&buffer[..n])
                .await
                .map_err(|_| StorageError::Unavailable)?;
        }
        output
            .flush()
            .await
            .map_err(|_| StorageError::Unavailable)?;
        if total != version.size || hex::encode(hash.finalize()) != expected_sha256 {
            return Err(StorageError::InvalidObject);
        }
        Ok(())
    }

    /// Capture an immutable version for later verification; never verify a mutable key.
    pub async fn capture(
        &self,
        key: &str,
        expected_size: i64,
    ) -> Result<ObjectVersion, StorageError> {
        if !valid_key(key) || !(1..=MAX_ARTIFACT_SIZE).contains(&expected_size) {
            return Err(StorageError::Invalid);
        }
        self.require_versioning().await?;
        let head = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|_| StorageError::Unavailable)?;
        let version = head
            .version_id()
            .filter(|v| !v.is_empty() && *v != "null" && v.len() <= 1024)
            .ok_or(StorageError::InvalidObject)?;
        if head.content_length() != Some(expected_size) {
            return Err(StorageError::InvalidObject);
        }
        Ok(ObjectVersion {
            version_id: version.to_owned(),
            size: expected_size,
        })
    }
}
fn valid_key(key: &str) -> bool {
    let mut parts = key.split('/');
    matches!((parts.next(), parts.next(), parts.next(), parts.next()), (Some("quarantine"), Some(a), Some(b), None) if Uuid::parse_str(a).is_ok() && Uuid::parse_str(b).is_ok())
}
fn valid_prepared_key(key: &str) -> bool {
    let mut parts = key.split('/');
    matches!((parts.next(),parts.next(),parts.next(),parts.next()),(Some("prepared"),Some(a),Some(b),None) if Uuid::parse_str(a).is_ok() && Uuid::parse_str(b).is_ok())
}
fn valid_public_key(key: &str) -> bool {
    let mut parts = key.split('/');
    matches!((parts.next(),parts.next(),parts.next(),parts.next()),(Some("public"),Some(a),Some(b),None) if Uuid::parse_str(a).is_ok() && Uuid::parse_str(b).is_ok())
}
fn valid_bucket(bucket: &str) -> bool {
    (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && bucket
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn validates_quarantine_paths_and_endpoints() {
        let key = format!("quarantine/{}/{}", Uuid::new_v4(), Uuid::new_v4());
        assert!(valid_key(&key));
        assert!(!valid_key("quarantine/../public"));
        let make = |endpoint: &str| Config {
            endpoint: endpoint.into(),
            region: "test".into(),
            bucket: "cloud-test".into(),
            access_key: "test".into(),
            secret_key: "secret".into(),
        };
        assert!(QuarantineStore::new(make("http://example.com")).is_err());
        assert!(QuarantineStore::new(make("https://example.com/path")).is_err());
        let store = QuarantineStore::new(make("http://127.0.0.1:9000")).unwrap();
        assert!(matches!(
            store
                .presign_upload(&key, 0, &"a".repeat(64), Duration::from_secs(60))
                .await,
            Err(StorageError::Invalid)
        ));
        assert!(matches!(
            store
                .presign_upload(&key, 10, &"A".repeat(64), Duration::from_secs(60))
                .await,
            Err(StorageError::Invalid)
        ));
        assert!(matches!(
            store
                .presign_upload(&key, 10, &"a".repeat(64), Duration::from_secs(301))
                .await,
            Err(StorageError::Invalid)
        ));
        assert!(matches!(
            store
                .presign_upload(
                    "quarantine/../escape",
                    10,
                    &"a".repeat(64),
                    Duration::from_secs(60)
                )
                .await,
            Err(StorageError::Invalid)
        ));
    }
    #[tokio::test]
    async fn presigned_upload_binds_required_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0 && request.len() + n <= 8192);
                request.extend_from_slice(&chunk[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(String::from_utf8_lossy(&request).contains("versioning"));
            let body = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let store = QuarantineStore::new(Config {
            endpoint,
            region: "us-east-1".into(),
            bucket: "cloud-test".into(),
            access_key: "test".into(),
            secret_key: "test-secret".into(),
        })
        .unwrap();
        let key = format!("quarantine/{}/{}", Uuid::new_v4(), Uuid::new_v4());
        let signed = store
            .presign_upload(&key, 10, &"a".repeat(64), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(signed.headers.get("content-length").unwrap(), "10");
        assert_eq!(signed.headers.get("if-none-match").unwrap(), "*");
        assert!(signed.headers.contains_key("x-amz-checksum-sha256"));
        let url = Url::parse(&signed.url).unwrap();
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("X-Amz-Expires").map(String::as_str), Some("60"));
        let names = query.get("X-Amz-SignedHeaders").unwrap();
        for name in ["content-length", "if-none-match", "x-amz-checksum-sha256"] {
            assert!(names.split(';').any(|v| v == name));
        }
        server.await.unwrap();
    }
    #[tokio::test]
    async fn inspection_capability_is_bound_to_object_version_and_attachment() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0 && request.len() + n <= 8192);
                request.extend_from_slice(&chunk[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(String::from_utf8_lossy(&request).contains("versioning"));
            let body="<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        });
        let store = QuarantineStore::new(Config {
            endpoint,
            region: "us-east-1".into(),
            bucket: "cloud-test".into(),
            access_key: "test".into(),
            secret_key: "test-secret".into(),
        })
        .unwrap();
        let key = format!("quarantine/{}/{}", Uuid::new_v4(), Uuid::new_v4());
        assert!(matches!(
            store
                .presign_inspection(&key, "null", Duration::from_secs(60))
                .await,
            Err(StorageError::Invalid)
        ));
        let signed = store
            .presign_inspection(&key, "version+/=", Duration::from_secs(60))
            .await
            .unwrap();
        let url = Url::parse(&signed.url).unwrap();
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("versionId").map(String::as_str),
            Some("version+/=")
        );
        assert_eq!(
            query.get("response-content-type").map(String::as_str),
            Some("application/octet-stream")
        );
        assert_eq!(
            query
                .get("response-content-disposition")
                .map(String::as_str),
            Some("attachment")
        );
        assert_eq!(query.get("X-Amz-Expires").map(String::as_str), Some("60"));
        assert_eq!(
            query.get("response-cache-control").map(String::as_str),
            Some("no-store")
        );
        assert!(query.contains_key("X-Amz-Signature"));
        server.await.unwrap();
    }
}
