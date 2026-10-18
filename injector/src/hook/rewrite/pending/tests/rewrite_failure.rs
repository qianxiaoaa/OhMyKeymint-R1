use super::*;

#[test]
fn service_rewrite_failure_preserves_only_system_route() {
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let pending = |route| {
        PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            route,
        })
    };

    assert!(!pending_preserves_system_on_rewrite_failure(&pending(
        RouteTarget::Omk
    )));
    assert!(pending_preserves_system_on_rewrite_failure(&pending(
        RouteTarget::System
    )));
}

#[test]
fn security_level_rewrite_failure_preserves_only_system_route() {
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let pending = |route| {
        PendingCall::SecurityLevel(PendingSecurityLevelCall {
            request: ParsedSecurityLevelRequest::CreateOperation {
                key: sample_key_descriptor(),
                operation_parameters: vec![],
                forced: false,
            },
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            route,
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
        })
    };

    assert!(!pending_preserves_system_on_rewrite_failure(&pending(
        RouteTarget::Omk
    )));
    assert!(pending_preserves_system_on_rewrite_failure(&pending(
        RouteTarget::System
    )));
}

#[test]
fn operation_rewrite_failure_preserves_only_system_route() {
    let _guard = route_state_test_guard();
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let omk_target = LocalBinderTarget {
        ptr: 0x1111,
        cookie: 0x2222,
    };
    remember_operation_target(
        omk_target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: true,
            backend: None,
            finalized: false,
            call_gate: Arc::new(Mutex::new(())),
        },
    );
    let system_target = LocalBinderTarget {
        ptr: 0x3333,
        cookie: 0x4444,
    };
    remember_operation_target(
        system_target,
        OperationTargetInfo {
            route: RouteTarget::System,
            aad_allowed: true,
            backend: None,
            finalized: false,
            call_gate: Arc::new(Mutex::new(())),
        },
    );

    let pending = |target| {
        PendingCall::Operation(PendingOperationCall {
            request: ParsedOperationRequest::Update { input: vec![1] },
            caller: caller.clone(),
            target,
        })
    };
    assert!(!pending_preserves_system_on_rewrite_failure(&pending(
        omk_target
    )));
    assert!(pending_preserves_system_on_rewrite_failure(&pending(
        system_target
    )));
}

#[test]
fn authorization_and_ordinary_maintenance_rewrite_failures_preserve_system() {
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let authorization = PendingCall::Authorization(PendingAuthorizationCall {
        request: ParsedAuthorizationRequest::AddAuthToken {
            auth_token: Default::default(),
        },
        method: AuthorizationMethod::AddAuthToken,
        caller: caller.clone(),
        mirror_update: None,
    });
    let maintenance = PendingCall::Maintenance(PendingMaintenanceCall {
        request: ParsedMaintenanceRequest::OnUserAdded { user_id: 10 },
        caller,
        route: RouteTarget::System,
        mirror_update: None,
    });

    assert!(pending_preserves_system_on_rewrite_failure(&authorization));
    assert!(pending_preserves_system_on_rewrite_failure(&maintenance));
}

#[test]
fn migration_rewrite_failure_preserves_only_system_route() {
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let request = ParsedMaintenanceRequest::MigrateKeyNamespace {
        source: sample_key_descriptor(),
        destination: sample_key_descriptor(),
    };
    let pending = |route| {
        PendingCall::Maintenance(PendingMaintenanceCall {
            request: request.clone(),
            caller: caller.clone(),
            route,
            mirror_update: None,
        })
    };

    assert!(pending_preserves_system_on_rewrite_failure(&pending(
        RouteTarget::System
    )));
    assert!(!pending_preserves_system_on_rewrite_failure(&pending(
        RouteTarget::Omk
    )));
}
