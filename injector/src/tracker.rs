use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::hook::binder::LocalBinderTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityLevelTargetInfo {
    pub security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
}

static SECURITY_LEVEL_TARGETS: LazyLock<
    Mutex<HashMap<LocalBinderTarget, SecurityLevelTargetInfo>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));
#[cfg(test)]
static STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn remember_security_level_target(
    target: LocalBinderTarget,
    info: SecurityLevelTargetInfo,
) {
    SECURITY_LEVEL_TARGETS
        .lock()
        .expect("security level target map poisoned")
        .insert(target, info);
}

pub(crate) fn lookup_security_level_target(
    target: LocalBinderTarget,
) -> Option<SecurityLevelTargetInfo> {
    SECURITY_LEVEL_TARGETS
        .lock()
        .expect("security level target map poisoned")
        .get(&target)
        .copied()
}

#[cfg(test)]
pub fn clear_state_for_tests() {
    SECURITY_LEVEL_TARGETS
        .lock()
        .expect("security level target map poisoned")
        .clear();
}

#[cfg(test)]
pub fn state_test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = STATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_state_for_tests();
    guard
}
