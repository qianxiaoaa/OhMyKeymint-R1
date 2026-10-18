use super::*;

pub(super) fn drain_transaction_completions(fd: c_int) {
    while complete_transaction_submission(fd).is_some() {}
    abort_prepared_bc_replies(fd);
    let connection = binder_state_key(fd);
    clear_outbound_reply_buffers(connection);
    SYNC_TRANSACTIONS.with(|transactions| {
        transactions.borrow_mut().remove(&connection);
    });
}

pub(super) fn push_unaligned<T: Copy>(out: &mut Vec<u8>, value: &T) {
    let start = out.len();
    out.resize(start + size_of::<T>(), 0);
    unsafe {
        std::ptr::write_unaligned(out.as_mut_ptr().add(start) as *mut T, *value);
    }
}
