use super::*;

#[test]
fn create_operation_params_reject_null() {
    let key = blob_key_descriptor(None);
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#createOperation,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&-1i32).unwrap();
                parcel.write(&false).unwrap();
            },
        ),
        StatusCode::UnexpectedNull,
    );
}

#[test]
fn generate_key_params_and_entropy_reject_null() {
    let key = blob_key_descriptor(None);
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&Option::<KeyDescriptor>::None).unwrap();
                parcel.write(&-1i32).unwrap();
            },
        ),
        StatusCode::UnexpectedNull,
    );
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&Option::<KeyDescriptor>::None).unwrap();
                parcel.write(&Vec::<KeyParameter>::new()).unwrap();
                parcel.write(&0i32).unwrap();
                parcel.write(&-1i32).unwrap();
            },
        ),
        StatusCode::UnexpectedNull,
    );
}

#[test]
fn import_key_params_and_data_reject_null() {
    let key = blob_key_descriptor(None);
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importKey,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&Option::<KeyDescriptor>::None).unwrap();
                parcel.write(&-1i32).unwrap();
            },
        ),
        StatusCode::UnexpectedNull,
    );
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importKey,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&Option::<KeyDescriptor>::None).unwrap();
                parcel.write(&Vec::<KeyParameter>::new()).unwrap();
                parcel.write(&0i32).unwrap();
                parcel.write(&-1i32).unwrap();
            },
        ),
        StatusCode::UnexpectedNull,
    );
}

#[test]
fn import_wrapped_key_params_and_authenticators_reject_null() {
    let key = blob_key_descriptor(None);
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importWrappedKey,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&key).unwrap();
                parcel.write(&Option::<Vec<u8>>::None).unwrap();
                parcel.write(&-1i32).unwrap();
            },
        ),
        StatusCode::UnexpectedNull,
    );
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importWrappedKey,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&key).unwrap();
                parcel.write(&Option::<Vec<u8>>::None).unwrap();
                parcel.write(&Vec::<KeyParameter>::new()).unwrap();
                parcel.write(&-1i32).unwrap();
            },
        ),
        StatusCode::UnexpectedNull,
    );
}

#[test]
fn key_parameter_blob_rejects_null() {
    let key = blob_key_descriptor(None);
    for tag in [Tag::APPLICATION_ID, Tag::APPLICATION_DATA] {
        assert_status_code(
            parse_security_level_request_with_payload(
                crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey,
                |parcel| {
                    parcel.write(&key).unwrap();
                    parcel.write(&Option::<KeyDescriptor>::None).unwrap();
                    write_single_blob_key_parameter_array(parcel, tag, -1);
                    parcel.write(&0i32).unwrap();
                    parcel.write(&Vec::<u8>::new()).unwrap();
                },
            ),
            StatusCode::UnexpectedNull,
        );
    }
}
