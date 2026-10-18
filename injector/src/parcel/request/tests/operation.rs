use super::*;

#[test]
fn operation_non_null_inputs_reject_null() {
    for code in [
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#updateAad,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
    ] {
        assert_status_code(
            parse_operation_request_with_payload(code, |parcel| parcel.write(&-1i32).unwrap()),
            StatusCode::UnexpectedNull,
        );
    }
}

#[test]
fn operation_inputs_preserve_empty() {
    let empty = Vec::<u8>::new();
    let parsed = parse_operation_request_with_payload(
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#updateAad,
        |parcel| parcel.write(&empty).unwrap(),
    )
    .expect("empty updateAad input should parse");
    let ParsedOperationRequest::UpdateAad { aad_input } = parsed else {
        panic!("updateAad request should parse");
    };
    assert!(aad_input.is_empty());

    let parsed = parse_operation_request_with_payload(
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
        |parcel| parcel.write(&empty).unwrap(),
    )
    .expect("empty update input should parse");
    let ParsedOperationRequest::Update { input } = parsed else {
        panic!("update request should parse");
    };
    assert!(input.is_empty());
}

#[test]
fn operation_request_accepts_trailing_payload() {
    let parsed = parse_operation_request_with_payload(
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
        |parcel| parcel.write(&0x4f4d4bi32).unwrap(),
    )
    .expect("operation request with trailing payload should parse");
    assert!(matches!(parsed, ParsedOperationRequest::Abort));
}
