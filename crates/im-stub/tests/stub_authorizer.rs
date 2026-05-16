use std::sync::Mutex;

use async_trait::async_trait;
use im_core::{
    Action, AuditDecision, AuditError, AuditRow, AuditSink, Authorized, Authorizer, AuthzError,
    Principal, ResourceSpec,
};
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
async fn authorizes_local_uid_and_audits_both_decisions() {
    let mock = MockAuditSink::default();
    let process_uid = nix::unistd::getuid().as_raw();
    let authorizer = StubAuthorizer {
        audit_sink: &mock,
        local_uid: process_uid,
    };
    let resource = ResourceSpec::default();

    let result = authorizer
        .authorize(&Principal::Local(process_uid), Action::Spawn, &resource)
        .await;

    assert_eq!(
        result,
        Ok(Authorized {
            principal: Principal::Local(process_uid),
            role: "admin".to_owned(),
            capabilities: Vec::new(),
        })
    );
    let rows = mock.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].decision, AuditDecision::Allow);
    assert_eq!(rows[0].action, Action::Spawn);
    assert_eq!(rows[0].principal, Principal::Local(process_uid));

    let result = authorizer
        .authorize(&Principal::Local(process_uid + 1), Action::Spawn, &resource)
        .await;

    assert_eq!(result, Err(AuthzError::UnknownPrincipal));
    let rows = mock.rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[1].decision,
        AuditDecision::Deny {
            reason: "non-local uid".to_owned(),
        }
    );
    assert_eq!(rows[1].denial_reason.as_deref(), Some("non-local uid"));
}
