use std::sync::{Barrier, LazyLock};
use std::time::Duration;

use super::super::{reset_binder_fd_for_test, SYNTHETIC_REPLY_TEST_LOCK};
use super::*;

mod pinning;
mod registry;

static PINNED_IOCTL_ENTERED: LazyLock<Barrier> = LazyLock::new(|| Barrier::new(2));
static PINNED_IOCTL_RELEASE: LazyLock<Barrier> = LazyLock::new(|| Barrier::new(2));

unsafe extern "C" fn blocking_ioctl(_fd: c_int, _request: c_int, _arg: *mut c_void) -> c_int {
    PINNED_IOCTL_ENTERED.wait();
    PINNED_IOCTL_RELEASE.wait();
    0
}

#[test]
fn publication_deadline_wait_does_not_need_an_ioctl_wakeup() {
    let _ioctl_guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _route_guard = route_state_test_guard();
    let target = LocalBinderTarget {
        ptr: 0x6d00,
        cookie: 0x7d00,
    };
    let retirement = register_operation_publication_for_test(target);
    mark_operation_publication_completed(
        retirement,
        BinderFdToken {
            fd: 91,
            generation: 0,
            connection: 91,
        },
    );

    std::thread::spawn(wait_for_operation_publication_deadline)
        .join()
        .expect("deadline wait thread should not panic");
    let probe = take_operation_publication_probe(Instant::now())
        .expect("publication probe should be ready after its deadline");
    assert_eq!(probe.target, target);
    finish_local_operation_publication(retirement);
}
