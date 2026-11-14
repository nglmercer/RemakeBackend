//! The Lore versioning engine, embedded in RemakeBackend.
//!
//! [`VersioningHost`] owns one embedded Lore server for the life of the backend process. The
//! backend owns the process: its tracing subscriber, its signals and its HTTP server. This
//! crate only starts and stops the engine, reports its health, and hands out the authoritative
//! stores. Native Lore listeners are off unless the configuration enables them.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use lore_server::server::{EmbeddedServer, ServerStores};
use lore_server::server_config::ServerConfig;
use lore_server::settings::Settings;

/// Where the engine keeps its authoritative stores.
///
/// Both stores are local, durable directories under [`data_dir`](Self::data_dir). They are the
/// source of truth for versioned content and branch heads: back them up together. Only one
/// [`VersioningHost`] may use a directory at a time, in this process or any other: the host
/// takes an exclusive lock on `host.lock` there and a second start fails. Lore's own claim on
/// its stores coordinates processes that share them rather than excluding them, so this lock is
/// what makes the deployment single-instance until multi-instance correctness is verified.
#[derive(Debug, Clone)]
pub struct VersioningConfig {
    /// A persistent directory. It is created when missing.
    pub data_dir: PathBuf,
}

impl VersioningConfig {
    /// The Lore settings, as TOML overrides over Lore's built-in defaults.
    ///
    /// Every native listener is disabled: the backend's own routes are the public surface, and
    /// a native listener may be enabled only once its authentication and authorization are
    /// configured and tested.
    fn lore_overrides(&self) -> String {
        let immutable = toml_string(&self.data_dir.join("immutable"));
        let mutable = toml_string(&self.data_dir.join("mutable"));
        format!(
            "[server.quic]\nenabled = false\n\
             [server.http]\nenabled = false\n\
             [server.grpc]\nenabled = false\n\
             [immutable_store.local]\npath = {immutable}\n\
             [mutable_store.local]\npath = {mutable}\n"
        )
    }
}

/// Quotes `path` as a TOML basic string.
fn toml_string(path: &Path) -> String {
    let text = path.to_string_lossy();
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for character in text.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            character if character.is_control() => {
                quoted.push_str(&format!("\\u{:04x}", u32::from(character)));
            }
            character => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

/// Takes the exclusive lock that keeps a second host off `data_dir`.
fn lock_directory(data_dir: &Path) -> Result<File> {
    let path = data_dir.join("host.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => anyhow::bail!(
            "another versioning host already uses {}; only one backend instance may run \
             against a data directory",
            data_dir.display()
        ),
        Err(TryLockError::Error(error)) => {
            Err(error).with_context(|| format!("locking {}", path.display()))
        }
    }
}

/// A snapshot of whether the engine can serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostHealth {
    /// Whether the embedded server is still running.
    pub running: bool,
}

/// The embedded Lore engine of this backend process.
pub struct VersioningHost {
    server: EmbeddedServer,
    /// Holds the exclusive lock on the data directory for as long as the host lives. Declared
    /// after `server` so that it is released after the server has stopped.
    _directory_lock: File,
}

impl VersioningHost {
    /// Starts the engine over the stores in `config.data_dir`.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be created, the settings are invalid, or the stores
    /// cannot be opened, for example because another process holds them.
    pub async fn start(config: VersioningConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("creating {}", config.data_dir.display()))?;
        let directory_lock = lock_directory(&config.data_dir)?;
        let (settings, settings_hash) = Settings::from_overrides(&config.lore_overrides())
            .context("building the Lore settings")?;
        let server = EmbeddedServer::start(settings, settings_hash, ServerConfig::default())
            .await
            .context("starting the embedded Lore server")?;
        tracing::info!(data_dir = %config.data_dir.display(), "Versioning engine started");
        Ok(Self {
            server,
            _directory_lock: directory_lock,
        })
    }

    /// The authoritative stores. Valid while the host is running.
    #[must_use]
    pub fn stores(&self) -> &ServerStores {
        self.server.stores()
    }

    /// Whether the engine can serve right now.
    #[must_use]
    pub fn health(&self) -> HostHealth {
        HostHealth {
            running: self.server.is_running(),
        }
    }

    /// Stops admitting work, drains, flushes the stores and releases them.
    ///
    /// # Errors
    ///
    /// Returns the error that ended the engine, when one did.
    pub async fn stop(self) -> Result<()> {
        self.server.stop().await?;
        tracing::info!("Versioning engine stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_with_special_characters_is_quoted_as_toml() {
        let quoted = toml_string(Path::new("C:\\data\\\"x\"\n"));
        assert_eq!(quoted, "\"C:\\\\data\\\\\\\"x\\\"\\u000a\"");
    }

    /// The engine serves over durable directories, stops, and starts again on them in the same
    /// process, the way the backend restarts it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_engine_starts_stops_and_restarts_on_the_same_directory() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for round in 0..2 {
            let host = VersioningHost::start(VersioningConfig {
                data_dir: directory.path().to_path_buf(),
            })
            .await
            .unwrap_or_else(|error| panic!("round {round}: starts: {error:#}"));
            assert!(host.health().running, "round {round}: running");
            host.stop()
                .await
                .unwrap_or_else(|error| panic!("round {round}: stops: {error:#}"));
        }
        assert!(directory.path().join("immutable").is_dir());
        assert!(directory.path().join("mutable").is_dir());
    }

    /// A second host on directories the first still holds must not start, so two backend
    /// instances cannot both write one set of stores.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_host_on_held_directories_does_not_start() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let config = VersioningConfig {
            data_dir: directory.path().to_path_buf(),
        };
        let first = VersioningHost::start(config.clone()).await.expect("first");

        let second = VersioningHost::start(config).await;

        let second_started = second.is_ok();
        first.stop().await.expect("stop first");
        if let Ok(second) = second {
            second.stop().await.expect("stop second");
        }
        assert!(!second_started, "two hosts on one directory");
    }
}
