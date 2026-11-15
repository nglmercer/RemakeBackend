//! Native development tooling for RemakeBackend.
//!
//! One library behind the `remake-dev` CLI, usable from tests and other tools:
//!
//! ```no_run
//! use devtools_core::DevEnvironment;
//! # async fn example() -> anyhow::Result<()> {
//! let tools = DevEnvironment::load()?;
//! tools.database().up().await?;                 // reuses pgrust; never compiles it
//! let run = tools.tests().run_integration().await?;
//! let report = tools.reports().generate().await?;
//! # Ok(())
//! # }
//! ```
//!
//! Rules every module follows:
//! * pgrust is compiled only by `db install` / `db upgrade` with a source checkout;
//! * `RUSTFLAGS`, `RUSTC_WRAPPER`, `CARGO_TARGET_DIR` and linker settings belong to the user
//!   and are inherited, never set or cleared;
//! * nothing here is a dependency of the production `cloud-api` binary.

pub mod binary;
pub mod build;
pub mod clean;
pub mod config;
pub mod database;
pub mod dev;
pub mod env;
pub mod health;
pub mod process;
pub mod report;
pub mod tests;
pub mod util;

pub use config::{Connection, DevConfig, DevEnvironment};
pub use database::{DatabaseController, DatabaseManager};
pub use report::{doctor, ReportGenerator};
pub use tests::{TestRun, TestRunner};

impl DevEnvironment {
    pub fn database(&self) -> DatabaseManager {
        DatabaseManager::new(self.clone())
    }
    pub fn tests(&self) -> TestRunner {
        TestRunner::new(self.clone())
    }
    pub fn reports(&self) -> ReportGenerator {
        ReportGenerator::new(self.clone())
    }
}

impl DatabaseManager {
    /// Plan-level name for `up`: make sure a healthy pgrust is running, building nothing.
    pub async fn ensure_running(&self) -> anyhow::Result<database::UpOutcome> {
        self.up().await
    }
}
