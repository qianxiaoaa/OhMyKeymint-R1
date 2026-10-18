use super::*;

mod publication;

use publication::register_operation_publication;

#[cfg(test)]
pub(in crate::hook) use publication::register_operation_publication_for_test;
pub(in crate::hook) use publication::{
    bind_operation_publication_connection, cancel_operation_publication_acquire_pending,
    finish_local_operation_publication, finish_operation_publication_probe,
    mark_operation_publication_acquire_committed, mark_operation_publication_acquire_pending,
    mark_operation_publication_completed, next_operation_publication_probe_deadline,
    operation_publication_acquire_is_pending, operation_publication_pending_acquire,
    retire_binder_connection_publications, take_operation_publication_probe,
};

#[derive(Clone)]
pub(super) struct OperationTargetInfo {
    pub(super) route: RouteTarget,
    pub(super) aad_allowed: bool,
    pub(super) backend: Option<AospOperationBinder>,
    pub(super) finalized: bool,
    pub(super) call_gate: Arc<Mutex<()>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OperationPublication {
    generation: u64,
    acquire_pending: bool,
    acquire_owned: bool,
    connection: Option<BinderStateKey>,
    binder: Option<BinderFdToken>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::hook) struct OperationPublicationProbe {
    pub(in crate::hook) target: LocalBinderTarget,
    pub(in crate::hook) binder: BinderFdToken,
    pub(in crate::hook) generation: u64,
    pub(in crate::hook) not_before: Instant,
    pub(in crate::hook) query_failures: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::hook) enum SyntheticTargetKind {
    SecurityLevel,
    Operation,
}

pub(in crate::hook) enum SyntheticReply {
    Parcel(Box<parcel::OwnedReply>),
    Status(i32),
    NoReply,
}

#[derive(Clone, Debug)]
pub(super) struct SyntheticTargetInfo {
    pub(super) kind: SyntheticTargetKind,
    pub(super) caller: Option<CallerInfo>,
    pub(super) native_generation: Option<u64>,
}

static OPERATION_TARGETS: LazyLock<Mutex<HashMap<LocalBinderTarget, OperationTargetInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SYNTHETIC_SECURITY_LEVEL_TARGETS: LazyLock<
    Mutex<
        HashMap<
            crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
            LocalBinderTarget,
        >,
    >,
> = LazyLock::new(|| Mutex::new(HashMap::new()));
static SYNTHETIC_TARGETS: LazyLock<Mutex<HashMap<LocalBinderTarget, SyntheticTargetInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NATIVE_BINDERS: LazyLock<Mutex<HashMap<LocalBinderTarget, Arc<NativeBinder>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static OPERATION_PUBLICATIONS: LazyLock<Mutex<HashMap<LocalBinderTarget, OperationPublication>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static OPERATION_PUBLICATION_PROBES: LazyLock<Mutex<VecDeque<OperationPublicationProbe>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

#[cfg(test)]
pub(super) fn reset_state_for_tests() {
    OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .clear();
    OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .clear();
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .clear();
    SYNTHETIC_SECURITY_LEVEL_TARGETS
        .lock()
        .expect("synthetic security-level target map poisoned")
        .clear();
    SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .clear();
    let natives = NATIVE_BINDERS
        .lock()
        .expect("native binder map poisoned")
        .drain()
        .map(|(_, native)| native)
        .collect::<Vec<_>>();
    for native in &natives {
        native.disarm_retirement();
    }
}

static NEXT_OPERATION_PUBLICATION_GENERATION: AtomicU64 = AtomicU64::new(1);

const OPERATION_PUBLICATION_PROBE_GRACE: Duration = Duration::from_millis(250);
const OPERATION_PUBLICATION_REPROBE_DELAY: Duration = Duration::from_secs(1);
const OPERATION_PUBLICATION_MAX_QUERY_BACKOFF_SHIFT: u8 = 5;
const MAX_PENDING_OPERATION_PUBLICATIONS: usize = 64;

pub(in crate::hook) fn lookup_synthetic_target(
    target: LocalBinderTarget,
) -> Option<SyntheticTargetKind> {
    lookup_synthetic_target_info(target).map(|info| info.kind)
}

pub(in crate::hook::rewrite) fn lookup_synthetic_target_info(
    target: LocalBinderTarget,
) -> Option<SyntheticTargetInfo> {
    SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .get(&target)
        .cloned()
}

pub(in crate::hook::rewrite) fn remember_operation_target(
    target: LocalBinderTarget,
    info: OperationTargetInfo,
) {
    let previous = OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .insert(target, info);
    if let Some(previous) = previous {
        if let Some(backend) = previous.backend {
            let _guard = BypassGuard::enter();
            if let Err(status) = backend.r#abort() {
                debug!(
                    "event=route previous OMK operation for carrier ptr=0x{:x} cookie=0x{:x} could not be aborted while replacing mapping: {}",
                    target.ptr, target.cookie, status
                );
            }
        }
    }
}

pub(in crate::hook::rewrite) fn lookup_operation_target(
    target: LocalBinderTarget,
) -> Option<OperationTargetInfo> {
    OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .get(&target)
        .cloned()
}

pub(in crate::hook::rewrite) fn forget_operation_target(target: LocalBinderTarget) {
    OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .remove(&target);
}

#[cfg(test)]
fn current_operation_retirement(target: LocalBinderTarget) -> Option<NativeBinderRetirement> {
    let generation = SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .get(&target)
        .filter(|info| info.kind == SyntheticTargetKind::Operation)
        .and_then(|info| info.native_generation)?;
    Some(NativeBinderRetirement { target, generation })
}

pub(crate) fn drop_synthetic_operation_retirement(retirement: NativeBinderRetirement) {
    let (info, native) = {
        let mut binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
        let mut operations = OPERATION_TARGETS
            .lock()
            .expect("operation target map poisoned");
        let mut synthetic = SYNTHETIC_TARGETS
            .lock()
            .expect("synthetic target map poisoned");
        let matches_generation = binders
            .get(&retirement.target)
            .is_some_and(|native| native.retirement_generation() == retirement.generation)
            || synthetic.get(&retirement.target).is_some_and(|info| {
                info.kind == SyntheticTargetKind::Operation
                    && info.native_generation == Some(retirement.generation)
            });
        if !matches_generation {
            return;
        }
        let info = operations.remove(&retirement.target);
        synthetic.remove(&retirement.target);
        let native = binders.remove(&retirement.target);
        (info, native)
    };

    {
        let mut publications = OPERATION_PUBLICATIONS
            .lock()
            .expect("operation publication map poisoned");
        if publications
            .get(&retirement.target)
            .is_some_and(|publication| publication.generation == retirement.generation)
        {
            publications.remove(&retirement.target);
        }
    }
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .retain(|probe| {
            probe.target != retirement.target || probe.generation != retirement.generation
        });
    if let Some(native) = native.as_ref() {
        native.disarm_retirement();
    }
    abort_operation_target_info(retirement.target, info);
    drop(native);
}

#[cfg(test)]
fn drop_synthetic_operation_target(target: LocalBinderTarget) {
    if let Some(retirement) = current_operation_retirement(target) {
        drop_synthetic_operation_retirement(retirement);
        return;
    }
    OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .remove(&target);
    let native = NATIVE_BINDERS
        .lock()
        .expect("native binder map poisoned")
        .remove(&target);
    if let Some(native) = native.as_ref() {
        native.disarm_retirement();
    }
    drop(native);

    retire_synthetic_operation_target(target);
}

fn release_native_operation_initial_strong(retirement: NativeBinderRetirement) {
    let native = {
        let mut binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
        binders
            .get(&retirement.target)
            .is_some_and(|native| native.retirement_generation() == retirement.generation)
            .then(|| binders.remove(&retirement.target))
            .flatten()
    };
    drop(native);
}

fn abort_operation_target_info(target: LocalBinderTarget, info: Option<OperationTargetInfo>) {
    let Some(info) = info else {
        debug!(
            "event=synthetic release for stale operation target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
        return;
    };
    if info.finalized {
        debug!(
            "event=synthetic release for finalized operation target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
        return;
    }
    let Some(backend) = info.backend else {
        return;
    };
    let _guard = BypassGuard::enter();
    if let Err(status) = backend.r#abort() {
        debug!(
            "event=synthetic drop abort for operation target ptr=0x{:x} cookie=0x{:x} failed: {}",
            target.ptr, target.cookie, status
        );
    }
}

#[cfg(test)]
fn retire_synthetic_operation_target(target: LocalBinderTarget) {
    let info = OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .remove(&target);
    SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .remove(&target);
    if OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target)
    {
        let now = Instant::now();
        for probe in OPERATION_PUBLICATION_PROBES
            .lock()
            .expect("operation publication probe queue poisoned")
            .iter_mut()
            .filter(|probe| probe.target == target)
        {
            probe.not_before = now;
        }
        super::super::intercept::wake_operation_publication_worker();
    }

    abort_operation_target_info(target, info);
}

pub(in crate::hook) fn retire_synthetic_operation_retirement(retirement: NativeBinderRetirement) {
    let info = {
        let mut operations = OPERATION_TARGETS
            .lock()
            .expect("operation target map poisoned");
        let mut synthetic = SYNTHETIC_TARGETS
            .lock()
            .expect("synthetic target map poisoned");
        let matches_generation = synthetic.get(&retirement.target).is_some_and(|info| {
            info.kind == SyntheticTargetKind::Operation
                && info.native_generation == Some(retirement.generation)
        });
        if !matches_generation {
            return;
        }
        synthetic.remove(&retirement.target);
        operations.remove(&retirement.target)
    };
    if OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .get(&retirement.target)
        .is_some_and(|publication| publication.generation == retirement.generation)
    {
        let now = Instant::now();
        for probe in OPERATION_PUBLICATION_PROBES
            .lock()
            .expect("operation publication probe queue poisoned")
            .iter_mut()
            .filter(|probe| {
                probe.target == retirement.target && probe.generation == retirement.generation
            })
        {
            probe.not_before = now;
        }
        super::super::intercept::wake_operation_publication_worker();
    }
    abort_operation_target_info(retirement.target, info);
}

pub(crate) fn retire_native_operation_target(retirement: NativeBinderRetirement) {
    let info = {
        let mut operations = OPERATION_TARGETS
            .lock()
            .expect("operation target map poisoned");
        let mut synthetic = SYNTHETIC_TARGETS
            .lock()
            .expect("synthetic target map poisoned");
        let matches_generation = synthetic.get(&retirement.target).is_some_and(|info| {
            info.kind == SyntheticTargetKind::Operation
                && info.native_generation == Some(retirement.generation)
        });
        if !matches_generation {
            debug!(
                "event=synthetic ignored stale native operation retirement ptr=0x{:x} cookie=0x{:x} generation={}",
                retirement.target.ptr, retirement.target.cookie, retirement.generation
            );
            return;
        }
        synthetic.remove(&retirement.target);
        operations.remove(&retirement.target)
    };

    {
        let mut publications = OPERATION_PUBLICATIONS
            .lock()
            .expect("operation publication map poisoned");
        if publications
            .get(&retirement.target)
            .is_some_and(|publication| publication.generation == retirement.generation)
        {
            publications.remove(&retirement.target);
        }
    }
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .retain(|probe| {
            probe.target != retirement.target || probe.generation != retirement.generation
        });

    drop(info);
}

#[cfg(test)]
fn observe_synthetic_operation_release(target: LocalBinderTarget) {
    if lookup_synthetic_target(target) == Some(SyntheticTargetKind::Operation) {
        drop_synthetic_operation_target(target);
    }
}

pub(in crate::hook::rewrite) fn mark_operation_target_finalized(target: LocalBinderTarget) {
    if let Some(info) = OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .get_mut(&target)
    {
        info.backend = None;
        info.finalized = true;
    }
}

fn native_binder_carrier(native: &NativeBinder) -> parcel::ReplyBinderCarrier {
    parcel::ReplyBinderCarrier {
        bytes: native.carrier().to_vec(),
        is_object: true,
    }
}

pub(in crate::hook) fn lookup_native_binder(
    target: LocalBinderTarget,
) -> Option<Arc<NativeBinder>> {
    NATIVE_BINDERS
        .lock()
        .expect("native binder map poisoned")
        .get(&target)
        .cloned()
}

pub(in crate::hook) fn lookup_native_binder_for(
    retirement: NativeBinderRetirement,
) -> Option<Arc<NativeBinder>> {
    let binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
    binders
        .get(&retirement.target)
        .filter(|native| native.retirement_generation() == retirement.generation)
        .cloned()
}

pub(in crate::hook::rewrite) fn register_synthetic_operation_carrier(
    backend: AospOperationBinder,
    aad_allowed: bool,
    caller: &CallerInfo,
) -> anyhow::Result<(parcel::ReplyBinderCarrier, NativeBinderRetirement)> {
    let native = Arc::new(create_native_operation_binder()?);
    let target = native.target();
    let carrier = native_binder_carrier(&native);
    let generation = register_operation_publication(target)?;
    let mut binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
    let mut operations = OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned");
    let mut synthetic = SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned");
    let replaced_stale_system = if !synthetic.contains_key(&target)
        && !binders.contains_key(&target)
        && operations
            .get(&target)
            .is_some_and(|info| info.route == RouteTarget::System)
    {
        operations.remove(&target);
        true
    } else {
        false
    };
    if operations.contains_key(&target)
        || synthetic.contains_key(&target)
        || binders.contains_key(&target)
    {
        drop(synthetic);
        drop(operations);
        drop(binders);
        OPERATION_PUBLICATIONS
            .lock()
            .expect("operation publication map poisoned")
            .remove(&target);
        anyhow::bail!(
            "native operation target collision for ptr=0x{:x} cookie=0x{:x}",
            target.ptr,
            target.cookie
        );
    }
    operations.insert(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed,
            backend: Some(backend),
            finalized: false,
            call_gate: Arc::new(Mutex::new(())),
        },
    );
    synthetic.insert(
        target,
        SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(caller.clone()),
            native_generation: Some(generation),
        },
    );
    binders.insert(target, native.clone());
    native.arm_retirement(generation);
    drop(binders);
    drop(synthetic);
    drop(operations);
    if replaced_stale_system {
        debug!(
            "event=synthetic replaced stale system operation mapping for reused target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
    }
    info!(
        "event=synthetic registered operation target ptr=0x{:x} cookie=0x{:x} aad_allowed={} uid={} pid={} sid='{}'",
        target.ptr, target.cookie, aad_allowed, caller.uid, caller.pid, caller.sid
    );
    Ok((carrier, NativeBinderRetirement { target, generation }))
}

pub(in crate::hook::rewrite) fn register_synthetic_security_level_carrier(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    source_method: ServiceMethod,
    caller: &CallerInfo,
) -> anyhow::Result<parcel::ReplyBinderCarrier> {
    let (target, carrier) = {
        let mut targets = SYNTHETIC_SECURITY_LEVEL_TARGETS
            .lock()
            .expect("synthetic security-level target map poisoned");
        if let Some(target) = targets.get(&security_level) {
            let native = NATIVE_BINDERS
                .lock()
                .expect("native binder map poisoned")
                .get(target)
                .cloned();
            let carrier = if let Some(native) = native {
                native_binder_carrier(&native)
            } else {
                return Err(anyhow::anyhow!(
                    "missing cached security-level binder for ptr=0x{:x} cookie=0x{:x}",
                    target.ptr,
                    target.cookie
                ));
            };
            (*target, carrier)
        } else {
            let native = Arc::new(create_native_security_level_binder()?);
            let target = native.target();
            let carrier = native_binder_carrier(&native);
            let mut binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
            let mut synthetic = SYNTHETIC_TARGETS
                .lock()
                .expect("synthetic target map poisoned");
            if binders.contains_key(&target) || synthetic.contains_key(&target) {
                anyhow::bail!(
                    "native security-level binder collision for ptr=0x{:x} cookie=0x{:x}",
                    target.ptr,
                    target.cookie
                );
            }
            binders.insert(target, native);
            synthetic.insert(
                target,
                SyntheticTargetInfo {
                    kind: SyntheticTargetKind::SecurityLevel,
                    caller: None,
                    native_generation: None,
                },
            );
            targets.insert(security_level, target);
            (target, carrier)
        }
    };
    tracker::remember_security_level_target(target, SecurityLevelTargetInfo { security_level });
    info!(
        "event=synthetic registered/reused security-level target ptr=0x{:x} cookie=0x{:x} security_level={:?} source_method={:?} uid={} pid={} sid='{}'",
        target.ptr, target.cookie, security_level, source_method, caller.uid, caller.pid, caller.sid
    );
    Ok(carrier)
}

#[cfg(test)]
mod tests;
