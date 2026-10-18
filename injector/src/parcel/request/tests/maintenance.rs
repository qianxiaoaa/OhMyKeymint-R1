use super::*;

#[test]
fn maintenance_non_null_password_rejects_null() {
    assert_status_code(
        parse_maintenance_request_as_method(MaintenanceMethod::InitUserSuperKeys, |parcel| {
            parcel.write(&0i32).unwrap();
            parcel.write(&-1i32).unwrap();
            parcel.write(&false).unwrap();
        }),
        StatusCode::UnexpectedNull,
    );
}

#[test]
fn maintenance_preserves_empty_optional_password() {
    let parsed =
        parse_maintenance_request_as_method(MaintenanceMethod::OnUserPasswordChanged, |parcel| {
            parcel.write(&0i32).unwrap();
            parcel.write(&Some(Vec::<u8>::new())).unwrap();
        })
        .expect("empty onUserPasswordChanged password should parse");
    let ParsedMaintenanceRequest::OnUserPasswordChanged { password, .. } = parsed else {
        panic!("onUserPasswordChanged request should parse");
    };
    assert_eq!(password, Some(Vec::new()));
}

#[test]
fn maintenance_accepts_empty_super_key_password() {
    let parsed =
        parse_maintenance_request_as_method(MaintenanceMethod::InitUserSuperKeys, |parcel| {
            parcel.write(&0i32).unwrap();
            parcel.write(&Vec::<u8>::new()).unwrap();
            parcel.write(&false).unwrap();
        })
        .expect("empty initUserSuperKeys password should parse");
    let ParsedMaintenanceRequest::InitUserSuperKeys { password, .. } = parsed else {
        panic!("initUserSuperKeys request should parse");
    };
    assert!(password.is_empty());
}

#[test]
fn maintenance_request_accepts_trailing_payload() {
    let parsed = parse_maintenance_request_as_method(MaintenanceMethod::DeleteAllKeys, |parcel| {
        parcel.write(&0x4f4d4bi32).unwrap();
    })
    .expect("maintenance mirror request with trailing payload should parse");
    assert!(matches!(parsed, ParsedMaintenanceRequest::DeleteAllKeys));
}

#[test]
fn android_12_maintenance_password_change_parses_optional_password() {
    let parsed = parse_maintenance_request_for_android(Some(12), tx(2), |parcel| {
        parcel.write(&10i32).unwrap();
        parcel.write(&Some(vec![1u8, 2, 3])).unwrap();
    })
    .expect("legacy password change should parse");
    let ParsedMaintenanceRequest::OnUserPasswordChanged { user_id, password } = parsed else {
        panic!("legacy password change should stay OnUserPasswordChanged");
    };
    assert_eq!(user_id, 10);
    assert_eq!(password.as_deref(), Some(&[1, 2, 3][..]));

    let parsed = parse_maintenance_request_for_android(Some(12), tx(2), |parcel| {
        parcel.write(&12i32).unwrap();
        parcel.write(&Some(Vec::<u8>::new())).unwrap();
    })
    .expect("legacy empty password change should parse");
    let ParsedMaintenanceRequest::OnUserPasswordChanged { user_id, password } = parsed else {
        panic!("legacy empty password change should stay OnUserPasswordChanged");
    };
    assert_eq!(user_id, 12);
    assert_eq!(password, Some(Vec::new()));

    let parsed = parse_maintenance_request_for_android(Some(12), tx(2), |parcel| {
        parcel.write(&11i32).unwrap();
        parcel.write(&None::<Vec<u8>>).unwrap();
    })
    .expect("legacy password removal should parse");
    let ParsedMaintenanceRequest::OnUserPasswordChanged { user_id, password } = parsed else {
        panic!("legacy password removal should stay OnUserPasswordChanged");
    };
    assert_eq!(user_id, 11);
    assert_eq!(password, None);
}
