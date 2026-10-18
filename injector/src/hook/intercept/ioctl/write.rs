use super::super::*;

fn prepared_bc_reply(fd: c_int, reply_index: usize) -> Option<PreparedBcReply> {
    let connection = binder_state_key(fd);
    PREPARED_BC_REPLIES.with(|prepared| {
        prepared
            .borrow()
            .get(&connection)
            .and_then(|replies| replies.get(reply_index))
            .copied()
    })
}

fn remember_prepared_bc_reply(fd: c_int, prepared_reply: PreparedBcReply) {
    let connection = binder_state_key(fd);
    PREPARED_BC_REPLIES.with(|prepared| {
        prepared
            .borrow_mut()
            .entry(connection)
            .or_default()
            .push_back(prepared_reply);
    });
}

fn take_prepared_bc_reply(fd: c_int) -> Option<PreparedBcReply> {
    let connection = binder_state_key(fd);
    PREPARED_BC_REPLIES.with(|prepared| {
        let mut prepared = prepared.borrow_mut();
        let replies = prepared.get_mut(&connection)?;
        let reply = replies.pop_front();
        if replies.is_empty() {
            prepared.remove(&connection);
        }
        reply
    })
}

pub(super) fn complete_prepared_bc_reply(
    fd: c_int,
    observed_data_ptr: usize,
) -> Option<NativeBinderRetirement> {
    let connection = binder_state_key(fd);
    let Some(prepared) = take_prepared_bc_reply(fd) else {
        return commit_bc_reply(connection, None, observed_data_ptr);
    };
    let data_ptr = prepared.data_ptr;
    if data_ptr != observed_data_ptr {
        warn!(
            "event=reply consumed prepared BC_REPLY with changed data pointer fd={} prepared=0x{:x} observed=0x{:x}",
            fd, data_ptr, observed_data_ptr
        );
    }
    commit_bc_reply(connection, prepared.frame_id, data_ptr)
}

pub(super) fn abort_prepared_bc_replies(fd: c_int) {
    abort_prepared_bc_replies_for_connection(binder_state_key(fd));
}

pub(in crate::hook::intercept) fn abort_prepared_bc_replies_for_connection(
    connection: BinderStateKey,
) {
    let prepared = PREPARED_BC_REPLIES.with(|prepared| prepared.borrow_mut().remove(&connection));
    if let Some(prepared) = prepared {
        for reply in prepared {
            abort_bc_reply(connection, reply.frame_id, reply.data_ptr);
        }
    }
}

pub(super) unsafe fn write_buffer_is_safe_to_intercept(write: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < write.len() {
        if write.len() - offset < size_of::<u32>() {
            return false;
        }
        let cmd = std::ptr::read_unaligned(write.as_ptr().add(offset) as *const u32);
        offset += size_of::<u32>();
        let cmd_size = _ioc_size(cmd);
        if cmd_size > write.len() - offset {
            return false;
        }
        let command_end = offset + cmd_size;
        let cmd_nr = _ioc_nr(cmd);
        if _ioc_dir(cmd) == 1 && matches!(cmd_nr, BC_REPLY_NR | BC_REPLY_SG_NR) {
            let expected_size = if cmd_nr == BC_REPLY_SG_NR {
                size_of::<binder_transaction_data_sg>()
            } else {
                size_of::<binder_transaction_data>()
            };
            if cmd_size != expected_size {
                return false;
            }
            let tr = std::ptr::read_unaligned(
                write.as_ptr().add(offset) as *const binder_transaction_data
            );
            if TransactionPayloadShadow::read(&tr).is_none() {
                return false;
            }
        }
        offset = command_end;
    }
    true
}

pub(super) unsafe fn rewrite_inbound_free_buffers(
    connection: BinderStateKey,
    write: &mut [u8],
) -> Vec<(usize, usize)> {
    let mut offset = 0usize;
    let mut rewritten = Vec::new();
    while write.len().saturating_sub(offset) >= size_of::<u32>() {
        let cmd = std::ptr::read_unaligned(write.as_ptr().add(offset) as *const u32);
        offset += size_of::<u32>();
        let cmd_size = _ioc_size(cmd);
        if cmd_size > write.len().saturating_sub(offset) {
            break;
        }
        let command_end = offset + cmd_size;
        if _ioc_dir(cmd) == 1
            && _ioc_nr(cmd) == BC_FREE_BUFFER_NR
            && cmd_size == size_of::<libc::c_ulong>()
        {
            let payload = write.as_mut_ptr().add(offset) as *mut libc::c_ulong;
            let shadow_buffer = std::ptr::read_unaligned(payload) as usize;
            if let Some(original_buffer) =
                inbound_transaction_original_buffer(connection, shadow_buffer)
            {
                std::ptr::write_unaligned(payload, original_buffer);
                rewritten.push((command_end, shadow_buffer));
            }
        }
        offset = command_end;
    }
    rewritten
}

pub(super) fn mark_inbound_free_buffers_consumed(
    connection: BinderStateKey,
    rewritten: &[(usize, usize)],
    write_consumed: usize,
) {
    let mut entries = INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned");
    for &(_, shadow_buffer) in rewritten
        .iter()
        .take_while(|(end, _)| *end <= write_consumed)
    {
        if let Some(shadow) = entries.get_mut(&(connection, shadow_buffer)) {
            if shadow.state == InboundTransactionShadowState::Live {
                shadow.state = InboundTransactionShadowState::KernelFreedPendingAck;
            }
        }
    }
}

pub(in crate::hook::intercept) fn complete_inbound_free_buffers(
    connection: BinderStateKey,
    rewritten: &[(usize, usize)],
    write_consumed: usize,
) {
    let mut entries = INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned");
    for &(_, shadow_buffer) in rewritten
        .iter()
        .take_while(|(end, _)| *end <= write_consumed)
    {
        if entries
            .get(&(connection, shadow_buffer))
            .is_some_and(|shadow| {
                shadow.state == InboundTransactionShadowState::KernelFreedPendingAck
            })
        {
            entries.remove(&(connection, shadow_buffer));
        }
    }
}

pub(super) unsafe fn parse_write_buffer(
    fd: c_int,
    write: &mut [u8],
) -> Vec<(usize, Option<usize>, bool, Option<NativeBinderRetirement>)> {
    let base = write.as_mut_ptr();
    let total_size = write.len();
    let mut offset = 0usize;
    let mut completion_commands = Vec::new();
    let mut reply_count = 0;
    while offset < total_size {
        let command_start = base.add(offset);
        if total_size.saturating_sub(offset) < size_of::<u32>() {
            warn!(
                "truncated binder write command header: remaining={}",
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd = std::ptr::read_unaligned(command_start as *const u32);
        offset += size_of::<u32>();
        let payload = base.add(offset);

        let cmd_size = _ioc_size(cmd);
        if cmd_size > total_size.saturating_sub(offset) {
            warn!(
                "truncated binder write command payload: nr={} size={} remaining={}",
                _ioc_nr(cmd),
                cmd_size,
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd_nr = _ioc_nr(cmd);
        let is_write = _ioc_dir(cmd) == 1;

        if is_write {
            match cmd_nr {
                BC_TRANSACTION_NR | BC_REPLY_NR | BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR => {
                    let is_sg = matches!(cmd_nr, BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR);
                    let is_reply = matches!(cmd_nr, BC_REPLY_NR | BC_REPLY_SG_NR);
                    let expected_size = if is_sg {
                        size_of::<binder_transaction_data_sg>()
                    } else {
                        size_of::<binder_transaction_data>()
                    };
                    if cmd_size == expected_size {
                        let tr_ptr = payload as *mut binder_transaction_data;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);
                        let prepared = is_reply
                            .then(|| prepared_bc_reply(fd, reply_count))
                            .flatten();
                        if let Some(prepared) = prepared {
                            tr = prepared.transaction;
                        }
                        let mut shadow = None;
                        let inspectable = if let Some(mut payload) =
                            TransactionPayloadShadow::read(&tr)
                        {
                            payload.install(&mut tr);
                            shadow = Some(payload);
                            true
                        } else {
                            warn!(
                                "event=binder skipped unsafe {} parcel fd={} data_size={} offsets_size={}",
                                if is_reply { "reply" } else { "transaction" },
                                fd,
                                tr.data_size,
                                tr.offsets_size
                            );
                            false
                        };
                        let label = match cmd_nr {
                            BC_TRANSACTION_NR => "BC_TRANSACTION",
                            BC_REPLY_NR => "BC_REPLY",
                            BC_TRANSACTION_SG_NR => "BC_TRANSACTION_SG",
                            BC_REPLY_SG_NR => "BC_REPLY_SG",
                            _ => unreachable!(),
                        };
                        let frame_id = if is_reply && prepared.is_none() && inspectable {
                            Some(handle_bc_reply(binder_state_key(fd), &mut tr))
                        } else {
                            None
                        };
                        if inspectable {
                            log_write_transaction(label, &tr);
                        }
                        if let Some(shadow) = shadow.as_ref() {
                            shadow.restore(&mut tr);
                        }
                        if let Some(frame_id) = frame_id {
                            remember_prepared_bc_reply(
                                fd,
                                PreparedBcReply {
                                    frame_id,
                                    data_ptr: tr.data.ptr.buffer as usize,
                                    transaction: tr,
                                },
                            );
                        }
                        std::ptr::write_unaligned(tr_ptr, tr);
                        completion_commands.push((
                            offset + cmd_size,
                            is_reply.then_some(tr.data.ptr.buffer as usize),
                            !is_reply && (tr.flags & TF_ONE_WAY) == 0,
                            None,
                        ));
                    } else if !is_sg {
                        warn!(
                            "unexpected binder write command payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    } else {
                        warn!(
                            "unexpected binder write SG payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    }
                    if cmd_size != expected_size {
                        completion_commands.push((
                            offset + cmd_size,
                            is_reply.then_some(0),
                            false,
                            None,
                        ));
                    }
                    if is_reply {
                        reply_count += 1;
                    }
                }
                _ => {}
            }
            if cmd == BC_ACQUIRE_DONE_CMD && cmd_size == size_of::<binder_ptr_cookie>() {
                let ptr_cookie = std::ptr::read_unaligned(payload as *const binder_ptr_cookie);
                let target = LocalBinderTarget {
                    ptr: ptr_cookie.ptr,
                    cookie: ptr_cookie.cookie,
                };
                completion_commands.push((
                    offset + cmd_size,
                    None,
                    false,
                    operation_publication_pending_acquire(target, binder_state_key(fd)),
                ));
            }
        }

        offset += cmd_size;
    }

    completion_commands
}

#[cfg(test)]
mod tests;
