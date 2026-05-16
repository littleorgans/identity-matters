pub mod config;
pub mod schema;
pub mod sqlite;

use std::path::Path;

use im_core::AuditRow;

pub use config::default_audit_db_path;
pub use sqlite::{AuditTableColumn, SqliteAuditSink, StoreError};

pub async fn query_audit(path: impl AsRef<Path>) -> Result<Vec<AuditRow>, StoreError> {
    SqliteAuditSink::connect(path).await?.query_audit().await
}

pub async fn query_default_audit() -> Result<Vec<AuditRow>, StoreError> {
    query_audit(default_audit_db_path()).await
}
