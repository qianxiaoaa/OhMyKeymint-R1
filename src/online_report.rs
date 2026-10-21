//! R1 online heartbeat reporter.
//!
//! The R1 server keeps a live device count from real active heartbeats
//! (`server/api/omk/lib/online.php`). This module posts a heartbeat every
//! `online_interval` seconds to the fixed report endpoint, carrying:
//!
//!   - `module_id` — a per-install identifier (`omk-` + 32 lowercase hex),
//!     generated once and persisted under the keystore data directory so the
//!     device keeps a stable identity across reboots and module updates. The
//!     server only stores the SHA-256 of this id as a dedup key, never the id.
//!   - `keybox_sha256` — the SHA-256 of the currently installed keybox, or an
//!     empty string when none is installed yet.
//!
//! Like the mirror sources, the endpoint is fixed at compile time: there is no
//! client-side configuration for where to report. All traffic is https to a
//! single allowlisted host, with a response-size cap and timeouts. Failures are
//! logged as warnings and retried on the next tick; there is no retry storm.

use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    sync::{Condvar, Mutex, OnceLock},
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use serde::{Deserialize, Serialize};
use ureq::http::Uri;

use crate::{global, mirror_keybox, root_path, webui_activity};

/// Report endpoint: `<base>/index.php?action=report` where the base matches
/// `server/api/omk/config.php` `base_url` (https://omk.5ijxa.com/api/omk).
const REPORT_URL: &str = "https://omk.5ijxa.com/api/omk/index.php?action=report";
const ALLOWED_HOST: &str = "omk.5ijxa.com";

/// Default heartbeat cadence; the server echoes its own `online_interval`
/// (1800 s today), and a sane server-provided value is honored if present.
const DEFAULT_INTERVAL_SECONDS: u64 = 1800;
const MIN_INTERVAL_SECONDS: u64 = 300;
const MAX_INTERVAL_SECONDS: u64 = 86_400;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_LABEL: &str = "8 KiB";

/// State file: the stable module id plus the last report outcome.
const STATE_PATH: &str = root_path!("data/online_report.toml");
const STATE_VERSION: u32 = 1;

static WORKER_STARTED: OnceLock<()> = OnceLock::new();
static WORKER_WAKE: OnceLock<(Condvar, Mutex<bool>)> = OnceLock::new();

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OnlineState {
    pub version: u32,
    pub module_id: String,
    pub last_report_unix: i64,
    pub last_status: String,
    pub last_error: String,
    /// Heartbeat cadence echoed by the server, clamped to the accepted range.
    pub interval_seconds: u64,
}

impl Default for OnlineState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            module_id: String::new(),
            last_report_unix: 0,
            last_status: String::new(),
            last_error: String::new(),
            interval_seconds: DEFAULT_INTERVAL_SECONDS,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportReply {
    ok: bool,
    devices: u64,
    peak: u64,
    interval: u64,
    checked_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportOutcome {
    pub ok: bool,
    pub devices: u64,
    pub peak: u64,
    pub interval: u64,
    pub checked_at: String,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

fn random_module_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .context("failed to open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("failed to read random bytes for the module id")?;
    Ok(format!("omk-{}", hex::encode(bytes)))
}

fn is_valid_module_id(id: &str) -> bool {
    if let Some(rest) = id.strip_prefix("omk-") {
        rest.len() == 32 && rest.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else {
        false
    }
}

/// Returns the stable module id, generating and persisting it on first use.
fn ensure_module_id(state: &OnlineState) -> Result<String> {
    if is_valid_module_id(&state.module_id) {
        return Ok(state.module_id.clone());
    }
    let module_id = random_module_id()?;
    let mut next = state.clone();
    next.module_id = module_id.clone();
    write_state(&next);
    Ok(module_id)
}

fn is_allowed_uri(uri: &Uri) -> bool {
    if uri.scheme_str() != Some("https") {
        return false;
    }
    let Some(authority) = uri.authority() else {
        return false;
    };
    let authority = authority.as_str();
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_suffix(":443") {
        Some(host) if !host.contains(':') => host,
        Some(_) => return false,
        None if authority.contains(':') => return false,
        None => authority,
    };
    host.eq_ignore_ascii_case(ALLOWED_HOST)
}

fn clamp_interval(seconds: u64) -> u64 {
    seconds.clamp(MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS)
}

fn read_state() -> OnlineState {
    let Ok(contents) = fs::read_to_string(STATE_PATH) else {
        return OnlineState::default();
    };
    toml::from_str(&contents).unwrap_or_default()
}

fn write_state(state: &OnlineState) {
    let contents = match toml::to_string_pretty(state) {
        Ok(contents) => contents,
        Err(error) => {
            log::warn!("failed to serialize the online report state: {error:#}");
            return;
        }
    };
    if let Err(error) = atomic_replace_preserving_metadata(
        Path::new(STATE_PATH),
        contents.as_bytes(),
        0o600,
        KEYSTORE_UID,
        KEYSTORE_GID,
    ) {
        log::warn!("failed to persist the online report state: {error:#}");
    }
}

fn persist_outcome(
    state: &OnlineState,
    status: &str,
    error: Option<&str>,
    reply: Option<&ReportReply>,
) {
    let mut next = state.clone();
    next.last_report_unix = now_unix();
    next.last_status = status.to_string();
    next.last_error = error.unwrap_or_default().to_string();
    if let Some(reply) = reply {
        next.interval_seconds = clamp_interval(reply.interval);
    }
    write_state(&next);
}

/// Posts one heartbeat and returns the server reply. On a transport, status or
/// JSON failure the state is still updated (status `failed`) so the worker
/// keeps the cadence instead of hammering the endpoint.
fn report_once() -> Result<ReportOutcome> {
    let state = read_state();
    let module_id = ensure_module_id(&state)?;
    let keybox_sha256 = mirror_keybox::installed_keybox_digest().unwrap_or_default();

    let uri: Uri = REPORT_URL
        .parse()
        .context("the report URL is not a valid URI")?;
    if !is_allowed_uri(&uri) {
        bail!("the report URL is outside the fixed server host");
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .into();

    let response = agent
        .post(uri)
        .config()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .header(
            "User-Agent",
            concat!("OhMyKeymint/", env!("CARGO_PKG_VERSION")),
        )
        .send_form([
            ("module_id", module_id.as_str()),
            ("keybox_sha256", keybox_sha256.as_str()),
        ]);

    let mut response = match response {
        Ok(response) => response,
        Err(error) => {
            persist_outcome(&state, "failed", Some(&format!("{error:#}")), None);
            return Err(anyhow!("failed to report the online heartbeat: {error:#}"));
        }
    };

    if !response.status().is_success() {
        let message = format!(
            "the online report endpoint returned HTTP status {}",
            response.status()
        );
        persist_outcome(&state, "failed", Some(&message), None);
        return Err(anyhow!(message));
    }

    let bytes = match response
        .body_mut()
        .with_config()
        .limit((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_vec()
    {
        Ok(bytes) if bytes.len() <= MAX_RESPONSE_BYTES => bytes,
        Ok(_) => {
            let message = format!(
                "the online report response exceeds the {} limit",
                MAX_RESPONSE_LABEL
            );
            persist_outcome(&state, "failed", Some(&message), None);
            return Err(anyhow!(message));
        }
        Err(error) => {
            let message = format!("failed to read the online report response: {error:#}");
            persist_outcome(&state, "failed", Some(&message), None);
            return Err(anyhow!(message));
        }
    };

    let reply: ReportReply = match serde_json::from_slice(&bytes) {
        Ok(reply) => reply,
        Err(error) => {
            let message = format!("the online report response is not valid JSON: {error:#}");
            persist_outcome(&state, "failed", Some(&message), None);
            return Err(anyhow!(message));
        }
    };

    if !reply.ok {
        let message = "the online report endpoint rejected the heartbeat".to_string();
        persist_outcome(&state, "failed", Some(&message), Some(&reply));
        return Err(anyhow!(message));
    }

    persist_outcome(&state, "ok", None, Some(&reply));
    let _ = webui_activity::record(
        "online_reported",
        &format!("devices={} peak={}", reply.devices, reply.peak),
    );
    log::debug!(
        "online heartbeat reported: devices={} peak={} interval={} checked_at={}",
        reply.devices,
        reply.peak,
        reply.interval,
        reply.checked_at
    );
    Ok(ReportOutcome {
        ok: true,
        devices: reply.devices,
        peak: reply.peak,
        interval: clamp_interval(reply.interval),
        checked_at: reply.checked_at,
    })
}

/// Status JSON for the WebUI. Only reads the persisted state, no network.
pub fn status_json() -> Result<String> {
    let state = read_state();
    serde_json::to_string(&OnlineStatus {
        module_id: state.module_id.clone(),
        last_report_unix: state.last_report_unix,
        last_status: state.last_status.clone(),
        last_error: state.last_error.clone(),
        interval_seconds: state.interval_seconds,
    })
    .context("failed to serialize the online report status")
}

#[derive(Debug, Clone, Serialize)]
struct OnlineStatus {
    module_id: String,
    last_report_unix: i64,
    last_status: String,
    last_error: String,
    interval_seconds: u64,
}

/// Verdict for the boot self-check: the feed is "connected" only after at
/// least one successful heartbeat.
pub fn boot_verdict() -> (bool, String) {
    let state = read_state();
    match state.last_status.as_str() {
        "ok" => (true, "online reporting ready".to_string()),
        _ if !state.module_id.is_empty() => (
            false,
            format!("online reporting pending: {}", state.last_status),
        ),
        _ => (false, "online reporting not initialized".to_string()),
    }
}

fn wake_slot() -> &'static (Condvar, Mutex<bool>) {
    WORKER_WAKE.get_or_init(|| (Condvar::new(), Mutex::new(false)))
}

/// Low frequency heartbeat worker: reports every `online_interval` seconds
/// after boot. It performs no network work until `sys.boot_completed`.
pub fn spawn_worker() {
    WORKER_STARTED.get_or_init(|| {
        if let Err(error) = std::thread::Builder::new()
            .name("omk-online-report".to_string())
            .spawn(run_worker)
        {
            log::warn!("failed to start the online report worker: {error}");
        }
    });
}

fn run_worker() {
    let (wake, pending) = wake_slot();
    loop {
        let now = now_unix();
        let state = read_state();
        let last = state.last_report_unix;
        let interval = clamp_interval(state.interval_seconds);
        if global::boot_completed() && (last == 0 || now.saturating_sub(last) >= interval as i64) {
            match report_once() {
                Ok(outcome) => log::debug!("automatic online heartbeat: {outcome:?}"),
                Err(error) => log::warn!("automatic online heartbeat failed: {error:#}"),
            }
        }
        let state = read_state();
        let interval = clamp_interval(state.interval_seconds);
        let sleep = now_unix().saturating_sub(state.last_report_unix).max(0);
        let sleep = if sleep >= interval as i64 {
            60
        } else {
            (interval as i64 - sleep) as u64
        };
        let mut guard = pending.lock().unwrap_or_else(|error| error.into_inner());
        if !*guard {
            let (locked, _) = wake
                .wait_timeout(guard, Duration::from_secs(sleep))
                .unwrap_or_else(|error| error.into_inner());
            guard = locked;
        }
        *guard = false;
        drop(guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_ids_match_the_server_contract() {
        for _ in 0..4 {
            let id = random_module_id().unwrap();
            assert!(id.starts_with("omk-"), "{id}");
            assert_eq!(id.len(), 4 + 32, "{id}");
            assert!(is_valid_module_id(&id), "{id}");
        }
    }

    #[test]
    fn module_ids_are_effectively_distinct() {
        let a = random_module_id().unwrap();
        let b = random_module_id().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn module_id_validation_rejects_bad_shapes() {
        assert!(!is_valid_module_id(""));
        assert!(!is_valid_module_id("omk-"));
        assert!(!is_valid_module_id("omk"));
        assert!(!is_valid_module_id(
            "omk-zz0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_valid_module_id("omk-0123456789abcdef0123456789abcde")); // 31 hex
        assert!(!is_valid_module_id("omk-0123456789abcdef0123456789abcdef0")); // 33 hex
        assert!(is_valid_module_id("omk-0123456789abcdef0123456789abcdef"));
        assert!(is_valid_module_id(&format!("omk-{}", "a".repeat(32))));
    }

    #[test]
    fn allowlist_accepts_only_the_fixed_host() {
        for url in [
            "https://omk.5ijxa.com/api/omk/index.php?action=report",
            "https://omk.5ijxa.com:443/api/omk/index.php?action=stats",
        ] {
            assert!(is_allowed_uri(&url.parse().unwrap()), "{url}");
        }
        for url in [
            "http://omk.5ijxa.com/api/omk/index.php?action=report",
            "https://evil.example/api/omk/index.php?action=report",
            "https://omk.5ijxa.com.evil.com/api/omk/index.php?action=report",
            "https://omk.5ijxa.com:8443/api/omk/index.php?action=report",
            "https://omk.5ijxa.com@evil.example/api/omk",
        ] {
            assert!(!is_allowed_uri(&url.parse().unwrap()), "{url}");
        }
    }

    #[test]
    fn report_url_is_static_and_allowed() {
        assert!(REPORT_URL.starts_with("https://omk.5ijxa.com/api/omk"));
        assert!(is_allowed_uri(&REPORT_URL.parse().unwrap()));
    }

    #[test]
    fn interval_clamp_keeps_sane_cadence() {
        assert_eq!(clamp_interval(0), MIN_INTERVAL_SECONDS);
        assert_eq!(clamp_interval(1800), 1800);
        assert_eq!(clamp_interval(1_000_000), MAX_INTERVAL_SECONDS);
    }

    #[test]
    fn state_defaults_to_never_reported() {
        let state = OnlineState::default();
        assert_eq!(state.version, STATE_VERSION);
        assert_eq!(state.module_id, "");
        assert_eq!(state.last_report_unix, 0);
        assert_eq!(state.last_status, "");
        assert_eq!(state.interval_seconds, DEFAULT_INTERVAL_SECONDS);
    }

    #[test]
    fn reply_parses_the_server_contract() {
        let json = br#"{"ok":true,"devices":42,"peak":100,"interval":1800,"checked_at":"2026-10-20T12:00:00+00:00"}"#;
        let reply: ReportReply = serde_json::from_slice(json).unwrap();
        assert!(reply.ok);
        assert_eq!(reply.devices, 42);
        assert_eq!(reply.peak, 100);
        assert_eq!(reply.interval, 1800);
    }
}
