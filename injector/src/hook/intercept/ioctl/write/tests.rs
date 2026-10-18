use super::super::super::SYNTHETIC_REPLY_TEST_LOCK;
use super::super::test_support::push_unaligned;
use super::*;
use crate::hook::rewrite::reset_pending_reply_frames_for_test;

#[test]
fn write_parser_tracks_transaction_and_reply_completions() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _route_guard = crate::tracker::state_test_guard();
    reset_pending_reply_frames_for_test(0, 0);
    let tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let mut write = Vec::new();
    let bc_transaction_cmd = BC_REPLY_CMD - BC_REPLY_NR + BC_TRANSACTION_NR;
    push_unaligned(&mut write, &bc_transaction_cmd);
    push_unaligned(&mut write, &tr);
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    push_unaligned(&mut write, &BC_ACQUIRE_DONE_CMD);
    let acquire_target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let acquire_retirement = register_operation_publication_for_test(acquire_target);
    let connection = binder_state_key(20);
    bind_operation_publication_connection(acquire_retirement, connection);
    assert_eq!(
        mark_operation_publication_acquire_pending(acquire_target, connection),
        Some(acquire_retirement)
    );
    push_unaligned(
        &mut write,
        &binder_ptr_cookie {
            ptr: acquire_target.ptr,
            cookie: acquire_target.cookie,
        },
    );

    let completions = unsafe { parse_write_buffer(20, &mut write) };
    assert_eq!(completions.len(), 3);
    assert_eq!(completions[0].1, None);
    assert!(completions[0].2);
    assert_eq!(completions[0].3, None);
    assert_eq!(completions[1].1, Some(0));
    assert!(!completions[1].2);
    assert_eq!(completions[1].3, None);
    assert_eq!(completions[2].3, Some(acquire_retirement));
    abort_prepared_bc_replies(20);
    cancel_operation_publication_acquire_pending(acquire_retirement);
    finish_local_operation_publication(acquire_retirement);
}

#[test]
fn inbound_shadow_free_is_translated_and_released_only_after_consumption() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let connection = binder_state_key(20);
    clear_inbound_transaction_shadows(connection);
    let original = [1u8, 2, 3, 4];
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = original.len();
    tr.data.ptr.buffer = original.as_ptr() as libc::c_ulong;
    let shadow = unsafe { TransactionPayloadShadow::read(&tr) }
        .expect("readable transaction should create a shadow");
    let shadow_buffer = retain_inbound_transaction_shadow(connection, shadow);
    publish_inbound_transaction_shadows(connection, &[shadow_buffer]);

    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    push_unaligned(&mut write, &shadow_buffer);
    push_unaligned(&mut write, &BC_REPLY_CMD);
    assert!(!unsafe { write_buffer_is_safe_to_intercept(&write) });

    let rewritten = unsafe { rewrite_inbound_free_buffers(connection, &mut write) };
    let command_end = size_of::<u32>() + size_of::<libc::c_ulong>();
    assert_eq!(rewritten, vec![(command_end, shadow_buffer)]);
    assert_eq!(
        unsafe { std::ptr::read_unaligned(write.as_ptr().add(size_of::<u32>()) as *const usize) },
        original.as_ptr() as usize
    );

    complete_inbound_free_buffers(connection, &rewritten, command_end - 1);
    assert_eq!(
        inbound_transaction_original_buffer(connection, shadow_buffer),
        Some(original.as_ptr() as libc::c_ulong)
    );
    mark_inbound_free_buffers_consumed(connection, &rewritten, command_end);
    complete_inbound_free_buffers(connection, &rewritten, command_end);
    assert_eq!(
        inbound_transaction_original_buffer(connection, shadow_buffer),
        None
    );
}
