use std::path::Path;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use im_core::{Action, AuditDecision, AuditError, AuditRow, AuditSink, Principal, ResourceSpec};
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use thiserror::Error;
use uuid::Uuid;

use crate::config::{audit_db_parent, default_audit_db_path};
use crate::schema::MIGRATOR;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("sqlite migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("timestamp parse error: {0}")]
    Timestamp(#[from] chrono::ParseError),
    #[error("uuid parse error: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTableColumn {
    pub name: String,
    pub data_type: String,
    pub not_null: bool,
    pub primary_key: bool,
}

#[derive(Debug, Clone)]
pub struct SqliteAuditSink {
    pool: SqlitePool,
}

impl SqliteAuditSink {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if let Some(parent) = audit_db_parent(path) {
            std::fs::create_dir_all(parent)?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;

        Ok(Self { pool })
    }

    pub async fn connect_default() -> Result<Self, StoreError> {
        Self::connect(default_audit_db_path()).await
    }

    pub async fn run_migrations(&self) -> Result<(), StoreError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub async fn query_audit(&self) -> Result<Vec<AuditRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, timestamp, principal, action, resource, decision, session_ref, notes, \
             policy_id, evaluation_trace, denial_reason FROM audit ORDER BY rowid ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(AuditRecord::from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    pub async fn audit_table_columns(&self) -> Result<Vec<AuditTableColumn>, StoreError> {
        let rows = sqlx::query("PRAGMA table_info(audit)")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(AuditTableColumn::from_row)
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn insert_audit_row(&self, row: &AuditRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO audit (
                id, timestamp, principal, action, resource, decision, session_ref, notes,
                policy_id, evaluation_trace, denial_reason
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(row.id.to_string())
        .bind(row.timestamp.to_rfc3339())
        .bind(serialize_json(&row.principal)?)
        .bind(serialize_json(&row.action)?)
        .bind(serialize_json(&row.resource)?)
        .bind(serialize_json(&row.decision)?)
        .bind(row.session_ref.map(|id| id.to_string()))
        .bind(row.notes.as_deref())
        .bind(row.policy_id.as_deref())
        .bind(row.evaluation_trace.as_deref())
        .bind(row.denial_reason.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl AuditSink for SqliteAuditSink {
    async fn record(&self, row: AuditRow) -> Result<(), AuditError> {
        self.insert_audit_row(&row)
            .await
            .map_err(|error| AuditError::sink(error.to_string()))
    }
}

#[derive(Debug)]
struct AuditRecord {
    id: String,
    timestamp: String,
    principal: String,
    action: String,
    resource: String,
    decision: String,
    session_ref: Option<String>,
    notes: Option<String>,
    policy_id: Option<String>,
    evaluation_trace: Option<String>,
    denial_reason: Option<String>,
}

impl AuditRecord {
    fn from_row(row: SqliteRow) -> Result<AuditRow, StoreError> {
        Self {
            id: row.try_get("id")?,
            timestamp: row.try_get("timestamp")?,
            principal: row.try_get("principal")?,
            action: row.try_get("action")?,
            resource: row.try_get("resource")?,
            decision: row.try_get("decision")?,
            session_ref: row.try_get("session_ref")?,
            notes: row.try_get("notes")?,
            policy_id: row.try_get("policy_id")?,
            evaluation_trace: row.try_get("evaluation_trace")?,
            denial_reason: row.try_get("denial_reason")?,
        }
        .try_into_audit_row()
    }

    fn try_into_audit_row(self) -> Result<AuditRow, StoreError> {
        Ok(AuditRow {
            id: Uuid::parse_str(&self.id)?,
            timestamp: DateTime::parse_from_rfc3339(&self.timestamp)?.with_timezone(&Utc),
            principal: serde_json::from_str::<Principal>(&self.principal)?,
            action: serde_json::from_str::<Action>(&self.action)?,
            resource: serde_json::from_str::<ResourceSpec>(&self.resource)?,
            decision: serde_json::from_str::<AuditDecision>(&self.decision)?,
            session_ref: parse_optional_uuid(self.session_ref)?,
            notes: self.notes,
            policy_id: self.policy_id,
            evaluation_trace: self.evaluation_trace,
            denial_reason: self.denial_reason,
        })
    }
}

impl AuditTableColumn {
    fn from_row(row: SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            name: row.try_get("name")?,
            data_type: row.try_get("type")?,
            not_null: row.try_get::<i64, _>("notnull")? != 0,
            primary_key: row.try_get::<i64, _>("pk")? != 0,
        })
    }
}

fn serialize_json<T: Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(Into::into)
}

fn parse_optional_uuid(value: Option<String>) -> Result<Option<Uuid>, StoreError> {
    value
        .map(|id| Uuid::parse_str(&id))
        .transpose()
        .map_err(Into::into)
}
