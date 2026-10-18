use super::*;

#[test]
fn owned_outbound_reply_clears_tf_status_code() {
    let fd = 31;
    clear_outbound_reply_buffers(fd);
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.flags = crate::hook::binder::TF_STATUS_CODE;
    let reply = parcel::build_void_reply().expect("void reply should build");
    let data_size = reply.data_size();
    let offsets_size = reply.offsets_size();
    let data = reply.data_ptr() as libc::c_ulong;
    let offsets = reply.offsets.as_ptr() as libc::c_ulong;

    unsafe { install_outbound_reply(fd, &mut tr, reply) };

    assert_eq!(tr.flags & crate::hook::binder::TF_STATUS_CODE, 0);
    assert_eq!(tr.data_size, data_size);
    assert_eq!(tr.offsets_size, offsets_size);
    assert_eq!(unsafe { tr.data.ptr.buffer }, data);
    assert_eq!(
        unsafe { tr.data.ptr.offsets },
        if offsets_size == 0 { 0 } else { offsets }
    );
    clear_outbound_reply_buffers(fd);
}

#[test]
fn outbound_reply_cleanup_is_isolated_by_binder_fd() {
    let first_fd = 32;
    let second_fd = 33;
    clear_outbound_reply_buffers(first_fd);
    clear_outbound_reply_buffers(second_fd);

    let mut first_tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    unsafe {
        install_outbound_reply(
            first_fd,
            &mut first_tr,
            parcel::build_void_reply().expect("first reply should build"),
        )
    };

    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let retirement = NativeBinderRetirement {
        target,
        generation: 1,
    };
    let mut second_reply = parcel::build_void_reply().expect("second reply should build");
    second_reply.native_operation = Some(retirement);
    let mut second_tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    unsafe { install_outbound_reply(second_fd, &mut second_tr, second_reply) };
    let second_data = unsafe { second_tr.data.ptr.buffer as usize };

    clear_outbound_reply_buffers(first_fd);
    assert_eq!(
        commit_bc_reply(second_fd, None, second_data),
        Some(retirement)
    );
    clear_outbound_reply_buffers(second_fd);
}

#[test]
fn pending_reply_queue_consumes_nested_requests_from_the_top() {
    let _guard = route_state_test_guard();
    let fd = 38;
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    assert!(take_top_pending(fd).is_none());

    push_pending_frame(fd);
    assert!(matches!(take_top_pending(fd), Some(None)));

    push_pending_frame(fd);
    replace_top_pending(
        fd,
        PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetSecurityLevel {
                security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            },
            caller: CallerInfo {
                uid: 1000,
                sid: String::new(),
                pid: 2000,
            },
            packages: vec!["com.example".to_string()],
            route: RouteTarget::Omk,
        }),
    );

    push_pending_frame(fd);
    replace_top_pending(
        fd,
        PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            caller: CallerInfo {
                uid: 1000,
                sid: String::new(),
                pid: 2000,
            },
            packages: vec!["com.example".to_string()],
            route: RouteTarget::Omk,
        }),
    );

    let Some(Some(PendingCall::Service(first))) = take_top_pending(fd) else {
        panic!("top call should be a service request");
    };
    assert_eq!(first.request.method(), ServiceMethod::GetKeyEntry);

    let Some(Some(PendingCall::Service(second))) = take_top_pending(fd) else {
        panic!("outer call should be a service request");
    };
    assert_eq!(second.request.method(), ServiceMethod::GetSecurityLevel);
    assert!(take_top_pending(fd).is_none());

    let legacy = PendingCall::Authorization(PendingAuthorizationCall {
        request: ParsedAuthorizationRequest::OnDeviceUnlocked {
            user_id: 10,
            password: None,
        },
        method: AuthorizationMethod::LegacyOnLockScreenEvent,
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        mirror_update: None,
    });
    assert_eq!(legacy.reply_log_context().1, "LegacyOnLockScreenEvent");
}

#[test]
fn pending_reply_queue_claims_only_the_matching_binder_fd() {
    let _guard = route_state_test_guard();
    let first_fd = 39;
    let second_fd = 40;
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    push_pending_frame(first_fd);
    push_pending_frame(second_fd);

    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let first_frame = unsafe { handle_bc_reply(first_fd, &mut tr) };
    assert!(first_frame.is_some());
    assert_eq!(pending_reply_frame_claims_for_test(first_fd), vec![true]);
    assert_eq!(pending_reply_frame_claims_for_test(second_fd), vec![false]);

    abort_bc_reply(first_fd, first_frame, 0);
    let second_frame = unsafe { handle_bc_reply(second_fd, &mut tr) };
    assert!(second_frame.is_some());
    abort_bc_reply(second_fd, second_frame, 0);
    assert!(PENDING_REPLY_QUEUE.with(|slot| slot.borrow().is_empty()));
}

#[test]
fn native_reply_sentinel_preserves_the_outer_pending_frame() {
    let _guard = route_state_test_guard();
    let fd = 41;
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    push_pending_frame(fd);
    push_pending_frame(fd);

    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let native_frame = unsafe { handle_bc_reply(fd, &mut tr) };
    assert!(native_frame.is_some());
    assert_eq!(pending_reply_frame_claims_for_test(fd), vec![false, true]);

    abort_bc_reply(fd, native_frame, 0);
    assert_eq!(pending_reply_frame_claims_for_test(fd), vec![false]);
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
}
