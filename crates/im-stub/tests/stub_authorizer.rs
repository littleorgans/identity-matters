use std::sync::Mutex;

use async_trait::async_trait;
use im_core::{
    Action, AuditDecision, AuditError, AuditRow, AuditSink, Authorized, Authorizer, AuthzError,
    Principal, ResourceSpec,
};
use im_store::{SqliteAuditSink, query_audit};
use im_stub::StubAuthorizer;

#[derive(Default)]
struct MockAuditSink {
    rows: Mutex<Vec<AuditRow>>,
}

impl MockAuditSink {
    fn rows(&self) -> Vec<AuditRow> {
        self.rows.lock().expect("audit rows lock poisoned").clone()
    }
}

#[async_trait]
impl AuditSink for MockAuditSink {
    async fn record(&self, row: AuditRow) -> Result<(), AuditError> {
        self.rows
            .lock()
            .expect("audit rows lock poisoned")
            .push(row);
        Ok(())
    }
}

#[tokio::test]
async fn authorizes_local_uid_and_audits_both_decisions_with_mock_sink() {
    let mock = MockAuditSink::default();
    let process_uid = nix::unistd::getuid().as_raw();
    authorize_both_decisions(&mock, process_uid).await;

    assert_audited_both_decisions(mock.rows(), process_uid);
}

#[tokio::test]
async fn authorizes_local_uid_and_audits_both_decisions_with_sqlite_sink() {
    let temp_dir = tempfile::tempdir().expect("create audit sqlite temp dir");
    let db_path = temp_dir.path().join("audit.sqlite");
    let sink = SqliteAuditSink::connect(&db_path)
        .await
        .expect("connect audit sqlite sink");
    sink.run_migrations().await.expect("run audit migrations");

    let process_uid = nix::unistd::getuid().as_raw();
    authorize_both_decisions(&sink, process_uid).await;
    let rows = query_audit(&db_path).await.expect("read audit rows");

    assert_audited_both_decisions(rows, process_uid);
}

async fn authorize_both_decisions<S>(audit_sink: &S, process_uid: u32)
where
    S: AuditSink + ?Sized,
{
    let authorizer = StubAuthorizer::new(audit_sink, process_uid);
    let resource = ResourceSpec::default();

    let allowed = authorizer
        .authorize(&Principal::Local(process_uid), Action::Spawn, &resource)
        .await;

    assert_eq!(
        allowed,
        Ok(Authorized {
            principal: Principal::Local(process_uid),
            role: "admin".to_owned(),
            capabilities: Vec::new(),
        })
    );

    let denied = authorizer
        .authorize(&Principal::Local(process_uid + 1), Action::Spawn, &resource)
        .await;

    assert_eq!(denied, Err(AuthzError::UnknownPrincipal));
}

fn assert_audited_both_decisions(rows: Vec<AuditRow>, process_uid: u32) {
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].decision, AuditDecision::Allow);
    assert_eq!(rows[0].action, Action::Spawn);
    assert_eq!(rows[0].principal, Principal::Local(process_uid));
    assert_eq!(
        rows[1].decision,
        AuditDecision::Deny {
            reason: "non-local uid".to_owned(),
        }
    );
    assert_eq!(rows[1].denial_reason.as_deref(), Some("non-local uid"));
}
