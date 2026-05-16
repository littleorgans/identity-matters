use std::collections::HashMap;

use chrono::Utc;
use im_core::{
    Action, AuditDecision, Authorizer, AuthzError, Principal, ResourceSpec, RuntimeKind,
};
use im_store::schema::RESERVED_AUDIT_COLUMNS;
use im_store::{AuditTableColumn, SqliteAuditSink, query_audit};
use im_stub::StubAuthorizer;
use uuid::Uuid;

#[tokio::test]
async fn sqlite_sink_persists_authorizer_audit_rows() {
    let temp_dir = tempfile::tempdir().expect("create audit sqlite temp dir");
    let db_path = temp_dir.path().join("audit.sqlite");
    let sink = SqliteAuditSink::connect(&db_path)
        .await
        .expect("connect audit sqlite sink");

    sink.run_migrations().await.expect("run audit migrations");
    let columns = sink
        .audit_table_columns()
        .await
        .expect("read audit table info");
    sink.run_migrations().await.expect("rerun audit migrations");
    assert_eq!(
        sink.audit_table_columns()
            .await
            .expect("read rerun table info"),
        columns
    );
    assert_reserved_columns_are_nullable(&columns);
    assert_primary_key_is_uuid_column(&columns);

    let process_uid = nix::unistd::getuid().as_raw();
    let authorizer = StubAuthorizer::new(&sink, process_uid);
    let resource = resource();
    let started_at = Utc::now();

    for action in Action::ALL {
        let authorized = authorizer
            .authorize(&Principal::Local(process_uid), action, &resource)
            .await
            .expect("local uid should authorize");

        assert_eq!(authorized.principal, Principal::Local(process_uid));
        assert_eq!(authorized.role, "admin");
        assert!(authorized.capabilities.is_empty());
    }

    let rows = query_audit(&db_path).await.expect("read audit rows");
    assert_eq!(rows.len(), Action::ALL.len());

    for (row, expected_action) in rows.iter().zip(Action::ALL) {
        assert_eq!(row.principal, Principal::Local(process_uid));
        assert_eq!(row.action, expected_action);
        assert_eq!(row.resource, resource);
        assert_eq!(row.decision, AuditDecision::Allow);
        assert_eq!(row.session_ref, resource.session_id);
        assert!(row.timestamp >= started_at);
        assert!(row.timestamp <= Utc::now());
        assert_uuid_v7(row.id);
    }

    let denial = authorizer
        .authorize(
            &Principal::Local(different_uid(process_uid)),
            Action::Spawn,
            &resource,
        )
        .await;

    assert_eq!(denial, Err(AuthzError::UnknownPrincipal));
    let rows = query_audit(&db_path)
        .await
        .expect("read audit rows after denial");
    let denied = &rows[Action::ALL.len()];
    assert_eq!(
        denied.decision,
        AuditDecision::Deny {
            reason: "non-local uid".to_owned(),
        }
    );
    assert_eq!(denied.denial_reason.as_deref(), Some("non-local uid"));
    assert_uuid_v7(denied.id);
}

fn resource() -> ResourceSpec {
    ResourceSpec {
        workspace: Some("identity-matters".to_owned()),
        role: Some("worker".to_owned()),
        runtime: Some(RuntimeKind::Codex),
        session_id: Some(Uuid::now_v7()),
        labels: HashMap::from([("issue".to_owned(), "ALP-2457".to_owned())]),
    }
}

fn assert_reserved_columns_are_nullable(columns: &[AuditTableColumn]) {
    for name in RESERVED_AUDIT_COLUMNS {
        let column = audit_column(columns, name);
        assert!(!column.not_null, "{name} should be nullable");
    }
}

fn assert_primary_key_is_uuid_column(columns: &[AuditTableColumn]) {
    let id = audit_column(columns, "id");
    assert!(id.primary_key);
    assert_eq!(id.data_type, "TEXT");
}

fn audit_column<'a>(columns: &'a [AuditTableColumn], name: &str) -> &'a AuditTableColumn {
    columns
        .iter()
        .find(|column| column.name == name)
        .unwrap_or_else(|| panic!("missing audit column {name}"))
}

fn assert_uuid_v7(id: Uuid) {
    assert_eq!(id.to_string().chars().nth(14), Some('7'));
}

fn different_uid(uid: u32) -> u32 {
    uid.checked_add(1).unwrap_or(uid - 1)
}
