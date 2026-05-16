use sqlx::migrate::Migrator;

pub const AUDIT_TABLE: &str = "audit";
pub const RESERVED_AUDIT_COLUMNS: [&str; 3] = ["policy_id", "evaluation_trace", "denial_reason"];

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
