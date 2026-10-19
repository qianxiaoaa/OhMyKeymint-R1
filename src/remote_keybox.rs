//! R1: cloud keybox client.
//!
//! The server publishes a rotation pool and signs every member with an Ed25519 key.
//! `action=manifest` describes the member that the next `action=keybox` request will
//! deliver, so the manifest is fetched first and the delivered bytes are verified
//! against it before anything is installed.
//!
//! The trust anchor is the built-in public key, optionally overridden by
//! `server.trusted_keybox_pubkey`. A `sign_public` value inside the manifest is never
//! used as an anchor by itself; that would let a compromised server sign its own
//! keyboxes.

use std::{
    fs,
    path::Path,
    sync::{Condvar, Mutex, OnceLock},
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use serde::{Deserialize, Serialize};
use ureq::http::Uri;

use crate::{
    config::{self, ServerConfig},
    global, keybox, root_path, webui_activity, webui_http,
};

pub const DEFAULT_BASE_URL: &str = "https://omk.5ijxa.com/api/omk";
/// Ed25519 anchor of the default distribution site (`keys/ed25519.pub`).
pub const TRUSTED_PUBKEY_B64: &str = "KJSC4WN6GpiHemdQ4N/DYGBZnWM/uPJkbHFFoCGAd8Q=";

const STATE_PATH: &str = root_path!("data/cloud_keybox.toml");
const STATE_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_KEYBOX_DOWNLOAD_BYTES: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound the refresh worker sleeps between due checks. A setting change wakes it
/// immediately, so this only bounds how late a changed interval or switch is noticed.
const WORKER_MAX_SLEEP: Duration = Duration::from_secs(3600);
const WORKER_MIN_SLEEP: Duration = Duration::from_secs(60);

static WORKER_STARTED: OnceLock<()> = OnceLock::new();
static WORKER_WAKE: OnceLock<(Condvar, Mutex<bool>)> = OnceLock::new();

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Manifest {
    pub version: String,
    pub version_code: i64,
    pub base_url: String,
    pub keybox: ManifestKeybox,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ManifestKeybox {
    pub url: String,
    pub sha256: String,
    pub size: i64,
    pub source: String,
    pub signature: String,
    pub sign_public: String,
    pub validity: KeyboxValidity,
    pub rotation: KeyboxRotation,
    /// Cloud-delivered notices shown by the client every time it fetches a keybox.
    /// Free-form text from the server, forwarded verbatim and never interpreted.
    pub notice: Vec<String>,
    /// Revocation blocklist summary published by the server. Informational:
    /// the client keeps using its own Google attestation cache for the local
    /// revocation decision and never acts on these numbers.
    pub revocation: ManifestRevocation,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ManifestRevocation {
    pub version: i64,
    pub permanent_count: i64,
    pub permanent_updated_at: String,
    pub report_count: i64,
    pub pending_count: i64,
    pub report_threshold: i64,
    pub report_unverified_threshold: i64,
    pub report_url: String,
    pub checked: i64,
    pub fresh: bool,
    pub fetched_at: i64,
    pub count: i64,
    pub source: String,
    pub tried: Vec<String>,
    pub sources: Vec<RevocationSource>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RevocationSource {
    pub source: String,
    pub ok: bool,
    pub count: i64,
    pub why: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KeyboxValidity {
    pub level: String,
    pub ok: bool,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
    pub days_remaining: Option<i64>,
    pub min_not_after: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KeyboxRotation {
    pub enabled: bool,
    pub pool_size: i64,
    pub current_index: i64,
    /// The filtered rotation pool, in rotation order starting from the current
    /// member. `pool[0]` equals the member this manifest describes; `pool[N]`
    /// matches `action=keybox&offset=N`. Revoked members never appear here.
    pub pool: Vec<RotationPoolMember>,
}

/// One rotation pool member as published inside the manifest. Every member is
/// signed with the same anchor, so the digests and signatures here can be used
/// to verify a member fetched with an `offset` request.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RotationPoolMember {
    pub source: String,
    pub sha256: String,
    pub size: i64,
    pub signature: String,
    pub validity: KeyboxValidity,
}

/// Decides whether a cloud refresh may skip the keybox download. Passive checks
/// (the auto-fetch worker, the WebUI "check for update" click) only download the
/// payload when the manifest no longer matches the installed keybox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshPolicy {
    AlwaysFetch,
    SkipIfInstalled,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub ok: bool,
    pub applied: bool,
    pub source: String,
    pub sha256: String,
    pub size: usize,
    pub days_remaining: Option<i64>,
    pub min_not_after: Option<String>,
    pub rotation: Option<String>,
    pub note: String,
    /// Cloud-delivered notices from the manifest, forwarded verbatim for the WebUI
    /// to display alongside the fetch result.
    pub notice: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudState {
    version: u32,
    last_fetch_unix: i64,
    last_sha256: String,
    last_source: String,
    last_status: String,
    last_error: String,
}

impl Default for CloudState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            last_fetch_unix: 0,
            last_sha256: String::new(),
            last_source: String::new(),
            last_status: String::new(),
            last_error: String::new(),
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

fn policy(
    resource: &'static str,
    max_bytes: usize,
    max_size_label: &'static str,
) -> webui_http::DownloadPolicy {
    webui_http::DownloadPolicy {
        resource,
        redirect_allowlist: "the configured cloud keybox host",
        max_bytes,
        max_size_label,
        max_redirects: 2,
        timeout: REQUEST_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
    }
}

fn host_of(raw: &str) -> Option<String> {
    let uri: Uri = raw.parse().ok()?;
    uri.host().map(|host| host.to_ascii_lowercase())
}

/// Anchors every request to the configured host so a redirect cannot move the download
/// to an unrelated origin. An unusable base URL yields an empty anchor and denies all
/// requests rather than allowing them.
fn make_allowlist(server: &ServerConfig) -> impl Fn(&Uri) -> bool + '_ {
    let allowed = host_of(server.base_url.trim()).unwrap_or_default();
    move |uri: &Uri| {
        uri.scheme_str() == Some("https")
            && uri.host().map(|host| host.to_ascii_lowercase()).as_deref() == Some(allowed.as_str())
    }
}

fn join_url(base: &str, suffix: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), suffix)
}

/// Accepts the base64 form published by the server and the 64 hex character form.
pub fn parse_public_key(raw: &str) -> Result<[u8; 32]> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("public key must not be empty");
    }
    let decoded = if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        hex::decode(value).context("public key hex is invalid")?
    } else {
        BASE64_STANDARD
            .decode(value)
            .context("public key is neither base64 nor 64 hex characters")?
    };
    let Ok(bytes): Result<[u8; 32], _> = decoded.as_slice().try_into() else {
        bail!("public key must be 32 bytes, got {}", decoded.len());
    };
    Ok(bytes)
}

fn anchor_key(server: &ServerConfig) -> Result<[u8; 32]> {
    let override_key = server.trusted_keybox_pubkey.trim();
    if !override_key.is_empty() {
        return parse_public_key(override_key);
    }
    parse_public_key(TRUSTED_PUBKEY_B64)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes))
}

fn short_digest(digest: &str) -> String {
    digest.chars().take(12).collect()
}

pub fn fetch_manifest(server: &ServerConfig) -> Result<Manifest> {
    let uri: Uri = join_url(server.base_url.trim(), "/index.php?action=manifest")
        .parse()
        .context("cloud keybox manifest URL is invalid")?;
    let body = webui_http::download_https_utf8(
        uri,
        &policy("cloud keybox manifest", MAX_MANIFEST_BYTES, "256 KiB"),
        make_allowlist(server),
    )
    .context("failed to fetch the cloud keybox manifest")?;
    serde_json::from_str(&body).context("failed to parse the cloud keybox manifest")
}

fn keybox_url(server: &ServerConfig, manifest: &Manifest) -> Result<Uri> {
    let published = manifest.keybox.url.trim();
    let candidate = if published.is_empty() {
        join_url(server.base_url.trim(), "/index.php?action=keybox")
    } else {
        published.to_string()
    };
    let uri: Uri = candidate
        .parse()
        .context("cloud keybox download URL is invalid")?;
    if !make_allowlist(server)(&uri) {
        bail!("cloud keybox download URL points outside the configured host");
    }
    Ok(uri)
}

pub fn fetch_keybox(server: &ServerConfig, manifest: &Manifest) -> Result<Vec<u8>> {
    let uri = keybox_url(server, manifest)?;
    webui_http::download_https(
        uri,
        &policy("cloud keybox", MAX_KEYBOX_DOWNLOAD_BYTES, "256 KiB"),
        make_allowlist(server),
    )
    .context("failed to fetch the cloud keybox")
}

/// Fetches a specific rotation member with `action=keybox&offset=N` (offset=0 is
/// the member the manifest describes, offset=1 is the second keybox). Totally
/// non-destructive: the server never advances `rotation.json` for an offset
/// request. The URL is built from the configured base so the host-anchored
/// allowlist still applies.
fn fetch_keybox_at_offset(server: &ServerConfig, offset: u32) -> Result<Vec<u8>> {
    let url = join_url(
        server.base_url.trim(),
        &format!("/index.php?action=keybox&offset={offset}"),
    );
    let uri: Uri = url
        .parse()
        .context("cloud keybox download URL is invalid")?;
    if !make_allowlist(server)(&uri) {
        bail!("cloud keybox download URL points outside the configured host");
    }
    webui_http::download_https(
        uri,
        &policy("cloud keybox", MAX_KEYBOX_DOWNLOAD_BYTES, "256 KiB"),
        make_allowlist(server),
    )
    .context("failed to fetch the cloud keybox")
}

/// Verifies digest, signature and validity report before anything is installed.
pub fn verify_bundle(server: &ServerConfig, manifest: &Manifest, contents: &[u8]) -> Result<()> {
    if contents.is_empty() {
        bail!("cloud keybox response is empty");
    }
    if contents.len() > keybox::MAX_KEYBOX_XML_BYTES {
        bail!(
            "cloud keybox is larger than the {} KiB install limit",
            keybox::MAX_KEYBOX_XML_BYTES / 1024
        );
    }

    let digest = sha256_hex(contents);
    let expected = manifest.keybox.sha256.trim().to_ascii_lowercase();
    if expected.is_empty() {
        if server.verify_signature {
            bail!("manifest published no keybox digest");
        }
    } else if expected != digest {
        bail!("cloud keybox digest mismatch: manifest={expected} actual={digest}");
    }
    if manifest.keybox.size > 0 && manifest.keybox.size as usize != contents.len() {
        bail!(
            "cloud keybox size mismatch: manifest={} actual={}",
            manifest.keybox.size,
            contents.len()
        );
    }

    if server.verify_signature {
        let anchor = anchor_key(server)?;
        let published = manifest.keybox.sign_public.trim();
        if !published.is_empty() && parse_public_key(published)? != anchor {
            bail!("manifest public key does not match the configured trust anchor");
        }
        let signature = BASE64_STANDARD
            .decode(manifest.keybox.signature.trim())
            .context("cloud keybox signature is not valid base64")?;
        let verifier = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, anchor);
        verifier
            .verify(contents, &signature)
            .map_err(|_| anyhow!("cloud keybox Ed25519 signature verification failed"))?;
    }

    let validity = &manifest.keybox.validity;
    if server.require_valid && (!validity.ok || validity.level == "invalid") {
        let reasons = if validity.reasons.is_empty() {
            "no reason reported".to_string()
        } else {
            validity.reasons.join("; ")
        };
        bail!("cloud keybox is not valid on the server: {reasons}");
    }
    if let Some(days) = validity.days_remaining {
        if days < server.min_days_remaining {
            bail!(
                "cloud keybox expires in {days} days, below the required {} days",
                server.min_days_remaining
            );
        }
    }
    keybox::validate_keybox_xml(contents).context("cloud keybox is not an installable keybox")
}

fn installed_keybox_digest() -> Option<String> {
    let contents = fs::read(keybox::KEYBOX_PATH).ok()?;
    Some(sha256_hex(&contents))
}

fn read_state() -> CloudState {
    let Ok(contents) = fs::read_to_string(STATE_PATH) else {
        return CloudState::default();
    };
    toml::from_str(&contents).unwrap_or_default()
}

fn write_state(status: &str, report: Option<&ApplyReport>, error: Option<&str>) {
    let state = CloudState {
        version: STATE_VERSION,
        last_fetch_unix: now_unix(),
        last_sha256: report
            .map(|report| report.sha256.clone())
            .unwrap_or_default(),
        last_source: report
            .map(|report| report.source.clone())
            .unwrap_or_default(),
        last_status: status.to_string(),
        last_error: error.unwrap_or_default().to_string(),
    };
    let contents = match toml::to_string_pretty(&state) {
        Ok(contents) => contents,
        Err(error) => {
            log::warn!("failed to serialize the cloud keybox state: {error:#}");
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
        log::warn!("failed to persist the cloud keybox state: {error:#}");
    }
}

/// The on-disk config is the source of truth here: WebUI bridge commands run as short
/// lived helper processes that never install the runtime config copy.
fn server_config() -> Result<ServerConfig> {
    Ok(config::load_config_file()?.server)
}

/// One-shot cloud probe used by the boot self-check. It reads only the manifest, so it
/// proves reachability and the signing anchor without touching the installed keybox.
pub fn probe() -> Result<Manifest> {
    let server = server_config()?;
    if !server.enabled {
        bail!("the cloud keybox is disabled (server.enabled=false)");
    }
    fetch_manifest(&server)
}

/// Fetches, verifies and installs one cloud keybox. This is the explicit
/// "change keybox" action: it always downloads the member the server delivers
/// (advancing the shared rotation), even if it is the one already installed.
pub fn apply_from_cloud() -> Result<ApplyReport> {
    let server = server_config()?;
    if !server.enabled {
        bail!("the cloud keybox is disabled (server.enabled=false)");
    }
    let report = apply_with_config(&server, RefreshPolicy::AlwaysFetch)?;
    if report.applied {
        record_cloud_applied(&report);
    }
    Ok(report)
}

/// Manifest-first check: when the member the server is delivering already
/// matches the installed keybox it reports "unchanged" without downloading
/// anything; otherwise it fetches, verifies and installs the new one. Backs the
/// WebUI "check for update" click and the automatic refresh worker.
pub fn update_from_cloud() -> Result<ApplyReport> {
    let server = server_config()?;
    if !server.enabled {
        bail!("the cloud keybox is disabled (server.enabled=false)");
    }
    let report = apply_with_config(&server, RefreshPolicy::SkipIfInstalled)?;
    if report.applied {
        record_cloud_applied(&report);
    }
    Ok(report)
}

/// Installs the second keybox of the cloud rotation pool (the member right after
/// the one the manifest describes, `offset=1`). The manifest carries the
/// member-level digest and signature, so the download is verified before install
/// and skipped when it already matches the installed keybox. The request never
/// moves the shared rotation pointer.
pub fn second_from_cloud() -> Result<ApplyReport> {
    let server = server_config()?;
    if !server.enabled {
        bail!("the cloud keybox is disabled (server.enabled=false)");
    }
    let report = (|| -> Result<ApplyReport> {
        let manifest = fetch_manifest(&server)?;
        if !manifest.keybox.rotation.enabled || manifest.keybox.rotation.pool.is_empty() {
            bail!("the server has no rotation pool to draw a second keybox from");
        }
        if manifest.keybox.rotation.pool.len() < 2 {
            bail!("the cloud rotation pool has only one keybox, there is no second one yet");
        }
        let member = &manifest.keybox.rotation.pool[1];
        let expected = member.sha256.trim().to_ascii_lowercase();
        if expected.is_empty() {
            bail!("the server published no digest for the second keybox");
        }
        if installed_keybox_digest().as_deref() == Some(expected.as_str()) {
            return Ok(report_skipped(
                &member.source,
                &expected,
                member.size,
                &member.validity,
                rotation_label(&manifest.keybox.rotation),
                manifest.keybox.notice.clone(),
            ));
        }
        let contents = fetch_keybox_at_offset(&server, 1)?;
        verify_pool_bundle(&server, &manifest, member, &contents)?;
        build_member_report(&manifest, member, &contents)
    })();
    persist_state(&report);
    if let Ok(report) = &report {
        if report.applied {
            record_cloud_applied(report);
        }
    }
    report
}

fn record_cloud_applied(report: &ApplyReport) {
    let _ = webui_activity::record(
        "cloud_keybox_applied",
        &format!("{} {}", report.source, short_digest(&report.sha256)),
    );
}

fn persist_state(result: &Result<ApplyReport>) {
    match result {
        Ok(report) if report.applied => write_state("applied", Some(report), None),
        Ok(report) => write_state("unchanged", Some(report), None),
        Err(error) => write_state("failed", None, Some(&format!("{error:#}"))),
    }
}

fn apply_with_config(server: &ServerConfig, policy: RefreshPolicy) -> Result<ApplyReport> {
    let result = (|| -> Result<ApplyReport> {
        let manifest = fetch_manifest(server)?;
        if manifest.keybox.url.trim().is_empty() && manifest.keybox.sha256.trim().is_empty() {
            bail!("the server published no keybox yet");
        }
        let expected = manifest.keybox.sha256.trim().to_ascii_lowercase();
        if policy == RefreshPolicy::SkipIfInstalled
            && !expected.is_empty()
            && installed_keybox_digest().as_deref() == Some(expected.as_str())
        {
            return Ok(report_skipped(
                &manifest.keybox.source,
                &expected,
                manifest.keybox.size,
                &manifest.keybox.validity,
                rotation_label(&manifest.keybox.rotation),
                manifest.keybox.notice.clone(),
            ));
        }
        let contents = fetch_keybox(server, &manifest)?;
        verify_bundle(server, &manifest, &contents)?;
        build_report(&manifest, &contents)
    })();
    persist_state(&result);
    result
}

fn rotation_label(rotation: &KeyboxRotation) -> Option<String> {
    if rotation.enabled {
        Some(format!(
            "{}/{}",
            rotation.current_index + 1,
            rotation.pool_size
        ))
    } else {
        None
    }
}

/// Report for a skip path: the installed keybox already matches what the cloud
/// would deliver, so no download and no install happened.
fn report_skipped(
    source: &str,
    digest: &str,
    size: i64,
    validity: &KeyboxValidity,
    rotation: Option<String>,
    notice: Vec<String>,
) -> ApplyReport {
    ApplyReport {
        ok: true,
        applied: false,
        source: source.to_string(),
        sha256: digest.to_string(),
        size: size.max(0) as usize,
        days_remaining: validity.days_remaining,
        min_not_after: validity.min_not_after.clone(),
        rotation,
        note: "the installed keybox is already the newest one".to_string(),
        notice,
    }
}

fn build_report(manifest: &Manifest, contents: &[u8]) -> Result<ApplyReport> {
    apply_install(
        &manifest.keybox.source,
        &sha256_hex(contents),
        contents,
        rotation_label(&manifest.keybox.rotation),
        manifest.keybox.validity.days_remaining,
        manifest.keybox.validity.min_not_after.clone(),
        manifest.keybox.notice.clone(),
    )
}

fn build_member_report(
    manifest: &Manifest,
    member: &RotationPoolMember,
    contents: &[u8],
) -> Result<ApplyReport> {
    apply_install(
        &member.source,
        &sha256_hex(contents),
        contents,
        rotation_label(&manifest.keybox.rotation),
        member.validity.days_remaining,
        member.validity.min_not_after.clone(),
        manifest.keybox.notice.clone(),
    )
}

/// Verifies a keybox fetched with an `offset` request against the member entry
/// the same manifest published. Reuses the exact digest / signature / validity
/// checks of `verify_bundle` through a synthetic manifest view.
fn verify_pool_bundle(
    server: &ServerConfig,
    manifest: &Manifest,
    member: &RotationPoolMember,
    contents: &[u8],
) -> Result<()> {
    let view = Manifest {
        version: manifest.version.clone(),
        version_code: manifest.version_code,
        base_url: manifest.base_url.clone(),
        keybox: ManifestKeybox {
            url: manifest.keybox.url.clone(),
            sha256: member.sha256.clone(),
            size: member.size,
            source: member.source.clone(),
            signature: member.signature.clone(),
            sign_public: manifest.keybox.sign_public.clone(),
            validity: member.validity.clone(),
            rotation: manifest.keybox.rotation.clone(),
            notice: manifest.keybox.notice.clone(),
            revocation: manifest.keybox.revocation.clone(),
        },
    };
    verify_bundle(server, &view, contents)
}

fn apply_install(
    source: &str,
    digest: &str,
    contents: &[u8],
    rotation: Option<String>,
    days_remaining: Option<i64>,
    min_not_after: Option<String>,
    notice: Vec<String>,
) -> Result<ApplyReport> {
    let applied = if installed_keybox_digest().as_deref() == Some(digest) {
        false
    } else {
        keybox::install_keybox_xml(contents).context("failed to install the cloud keybox")?;
        // The running keymint process owns the keybox identity, the root of trust
        // re-pin and the stale blob cleanup, and its file watcher reacts to this write.
        // Reloading here would open a second database connection inside a short lived
        // WebUI helper process.
        true
    };

    let note = if applied {
        "cloud keybox installed".to_string()
    } else {
        "the installed keybox is already the one the server is delivering".to_string()
    };
    Ok(ApplyReport {
        ok: true,
        applied,
        source: source.to_string(),
        sha256: digest.to_string(),
        size: contents.len(),
        days_remaining,
        min_not_after,
        rotation,
        note,
        notice,
    })
}

/// Fixed key shape so the WebUI can validate the reply strictly. Unknown or missing
/// values are empty, `false`, or `-1` rather than absent keys.
#[derive(Serialize)]
pub struct CloudStatus {
    pub enabled: bool,
    pub base_url: String,
    pub auto_fetch: bool,
    pub fetch_interval_hours: u32,
    pub verify_signature: bool,
    pub require_valid: bool,
    pub min_days_remaining: i64,
    pub trusted_pubkey: &'static str,
    pub last_fetch_unix: i64,
    pub last_sha256: String,
    pub last_source: String,
    pub last_status: String,
    pub last_error: String,
    pub installed_sha256: String,
    pub cloud: &'static str,
    pub cloud_error: String,
    pub server_version: String,
    pub next_source: String,
    pub next_sha256: String,
    pub next_size: i64,
    pub next_level: String,
    pub next_ok: bool,
    pub next_days_remaining: i64,
    pub next_min_not_after: String,
    pub rotation_enabled: bool,
    pub rotation_pool_size: i64,
    pub rotation_current_index: i64,
    pub is_current: bool,
    /// Cloud-delivered notices from the manifest, forwarded verbatim for the WebUI
    /// to display in the dialog.
    pub notice: Vec<String>,
    /// Revocation blocklist summary published by the server manifest. Purely
    /// informational for the WebUI; the client revocation decision is unchanged.
    pub revocation: CloudRevocation,
}

/// Fixed key shape so the WebUI can validate the reply strictly. Unknown or missing
/// values are empty, `false`, or `-1` rather than absent keys.
#[derive(Serialize)]
pub struct CloudRevocation {
    pub present: bool,
    pub permanent_count: i64,
    pub pending_count: i64,
    pub report_threshold: i64,
    pub report_unverified_threshold: i64,
    pub checked: i64,
    pub fresh: bool,
    pub source: String,
    pub fetched_at: i64,
}

impl CloudStatus {
    fn base(server: &ServerConfig) -> Self {
        Self {
            enabled: server.enabled,
            base_url: server.base_url.clone(),
            auto_fetch: server.auto_fetch,
            fetch_interval_hours: server.fetch_interval_hours,
            verify_signature: server.verify_signature,
            require_valid: server.require_valid,
            min_days_remaining: server.min_days_remaining,
            trusted_pubkey: if server.trusted_keybox_pubkey.trim().is_empty() {
                "builtin"
            } else {
                "configured"
            },
            last_fetch_unix: 0,
            last_sha256: String::new(),
            last_source: String::new(),
            last_status: String::new(),
            last_error: String::new(),
            installed_sha256: String::new(),
            cloud: "disabled",
            cloud_error: String::new(),
            server_version: String::new(),
            next_source: String::new(),
            next_sha256: String::new(),
            next_size: 0,
            next_level: String::new(),
            next_ok: false,
            next_days_remaining: -1,
            next_min_not_after: String::new(),
            rotation_enabled: false,
            rotation_pool_size: 0,
            rotation_current_index: 0,
            is_current: false,
            notice: Vec::new(),
            revocation: CloudRevocation {
                present: false,
                permanent_count: 0,
                pending_count: 0,
                report_threshold: 0,
                report_unverified_threshold: 0,
                checked: 0,
                fresh: false,
                source: String::new(),
                fetched_at: 0,
            },
        }
    }
}

pub fn status_report() -> Result<CloudStatus> {
    let server = server_config()?;
    let state = read_state();
    let installed = installed_keybox_digest().unwrap_or_default();
    let mut status = CloudStatus::base(&server);
    status.last_fetch_unix = state.last_fetch_unix;
    status.last_sha256 = state.last_sha256;
    status.last_source = state.last_source;
    status.last_status = state.last_status;
    status.last_error = state.last_error;
    status.installed_sha256 = installed.clone();
    if !server.enabled {
        return Ok(status);
    }

    match fetch_manifest(&server) {
        Ok(manifest) => {
            let next = manifest.keybox.sha256.to_ascii_lowercase();
            status.cloud = "connected";
            status.server_version = manifest.version.clone();
            status.next_source = manifest.keybox.source.clone();
            status.next_sha256 = next.clone();
            status.next_size = manifest.keybox.size;
            status.next_level = manifest.keybox.validity.level.clone();
            status.next_ok = manifest.keybox.validity.ok;
            status.next_days_remaining = manifest.keybox.validity.days_remaining.unwrap_or(-1);
            status.next_min_not_after = manifest
                .keybox
                .validity
                .min_not_after
                .clone()
                .unwrap_or_default();
            status.rotation_enabled = manifest.keybox.rotation.enabled;
            status.rotation_pool_size = manifest.keybox.rotation.pool_size;
            status.rotation_current_index = manifest.keybox.rotation.current_index;
            status.is_current = !next.is_empty() && installed == next;
            status.notice = manifest.keybox.notice.clone();
            let revocation = &manifest.keybox.revocation;
            status.revocation = CloudRevocation {
                present: true,
                permanent_count: revocation.permanent_count,
                pending_count: revocation.pending_count,
                report_threshold: revocation.report_threshold,
                report_unverified_threshold: revocation.report_unverified_threshold,
                checked: revocation.checked,
                fresh: revocation.fresh,
                source: revocation.source.clone(),
                fetched_at: revocation.fetched_at,
            };
        }
        Err(error) => {
            status.cloud = "unreachable";
            status.cloud_error = format!("{error:#}");
        }
    }
    Ok(status)
}

/// Reads the cloud settings from `config.toml`, changes one field and writes them back.
/// Unknown keys survive because the writer merges into the existing table.
fn update_server_config<F>(change: F) -> Result<()>
where
    F: FnOnce(&mut ServerConfig),
{
    let mut config_file = config::load_config_file().context("failed to read config.toml")?;
    change(&mut config_file.server);
    config::persist_config_file(&config_file).context("failed to write config.toml")?;
    wake_worker();
    Ok(())
}

pub fn set_enabled(enabled: bool) -> Result<()> {
    update_server_config(|server| server.enabled = enabled)
}

pub fn set_auto_fetch(enabled: bool) -> Result<()> {
    update_server_config(|server| server.auto_fetch = enabled)
}

pub fn set_verify_signature(verify: bool) -> Result<()> {
    update_server_config(|server| server.verify_signature = verify)
}

pub fn set_base_url(raw: &str) -> Result<()> {
    let base = raw.trim().trim_end_matches('/').to_string();
    if !base.starts_with("https://") || host_of(&base).is_none() {
        bail!("cloud keybox base URL must be a valid https URL without a trailing slash");
    }
    update_server_config(|server| server.base_url = base)
}

pub fn set_trusted_pubkey(raw: &str) -> Result<()> {
    let value = raw.trim().to_string();
    if !value.is_empty() {
        parse_public_key(&value).context("trusted public key is invalid")?;
    }
    update_server_config(|server| server.trusted_keybox_pubkey = value)
}

fn wake_slot() -> &'static (Condvar, Mutex<bool>) {
    WORKER_WAKE.get_or_init(|| (Condvar::new(), Mutex::new(false)))
}

fn wake_worker() {
    let (wake, pending) = wake_slot();
    if let Ok(mut guard) = pending.lock() {
        *guard = true;
    }
    wake.notify_all();
}

fn interval_seconds(server: &ServerConfig) -> i64 {
    i64::from(
        server
            .fetch_interval_hours
            .clamp(1, 744)
            .saturating_mul(3600),
    )
}

fn seconds_since_fetch() -> i64 {
    now_unix().saturating_sub(read_state().last_fetch_unix)
}

fn seconds_to_next_check(server: &ServerConfig) -> u64 {
    let remaining = interval_seconds(server)
        .saturating_sub(seconds_since_fetch())
        .max(0);
    remaining.clamp(
        WORKER_MIN_SLEEP.as_secs() as i64,
        WORKER_MAX_SLEEP.as_secs() as i64,
    ) as u64
}

fn due_now(server: &ServerConfig) -> bool {
    seconds_since_fetch() >= interval_seconds(server)
}

/// Low frequency refresh worker. It sleeps until the next due point instead of polling,
/// wakes immediately when a setting changes and performs no network work while
/// automatic fetch is off.
pub fn spawn_worker() {
    WORKER_STARTED.get_or_init(|| {
        if let Err(error) = std::thread::Builder::new()
            .name("omk-cloud-keybox".to_string())
            .spawn(run_worker)
        {
            log::warn!("failed to start the cloud keybox worker: {error}");
        }
    });
}

fn run_worker() {
    let (wake, pending) = wake_slot();
    loop {
        // A broken or unreadable config must never fall back to the defaults, because
        // the defaults have the cloud feature enabled.
        let server = match server_config() {
            Ok(server) => server,
            Err(error) => {
                log::warn!("cloud keybox worker cannot read the config: {error:#}");
                ServerConfig {
                    enabled: false,
                    ..ServerConfig::default()
                }
            }
        };
        if server.enabled && server.auto_fetch && global::boot_completed() && due_now(&server) {
            match apply_with_config(&server, RefreshPolicy::SkipIfInstalled) {
                Ok(report) if report.applied => log::info!(
                    "automatic cloud keybox applied: source={} sha256={}",
                    report.source,
                    report.sha256
                ),
                Ok(_) => log::debug!("automatic cloud keybox check found the installed keybox"),
                Err(error) => log::warn!("automatic cloud keybox update failed: {error:#}"),
            }
        }
        let sleep = if server.enabled && server.auto_fetch {
            seconds_to_next_check(&server)
        } else {
            WORKER_MAX_SLEEP.as_secs()
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
    fn public_key_accepts_base64_and_hex() {
        let from_base64 = parse_public_key(TRUSTED_PUBKEY_B64).unwrap();
        assert_eq!(from_base64.len(), 32);
        let from_hex = parse_public_key(&hex::encode(from_base64)).unwrap();
        assert_eq!(from_base64, from_hex);
        assert!(parse_public_key("").is_err());
        assert!(parse_public_key("not-a-key").is_err());
        assert!(parse_public_key(&hex::encode([7u8; 31])).is_err());
    }

    #[test]
    fn builtin_anchor_is_the_documented_server_key() {
        assert!(parse_public_key(TRUSTED_PUBKEY_B64).is_ok());
    }

    #[test]
    fn allowlist_is_https_and_host_bound() {
        let server = ServerConfig {
            base_url: "https://omk.5ijxa.com/api/omk".to_string(),
            ..ServerConfig::default()
        };
        let allowed = make_allowlist(&server);
        assert!(allowed(
            &"https://omk.5ijxa.com/api/omk/index.php?action=keybox"
                .parse()
                .unwrap()
        ));
        assert!(!allowed(
            &"http://omk.5ijxa.com/api/omk/index.php".parse().unwrap()
        ));
        assert!(!allowed(&"https://evil.example/index.php".parse().unwrap()));

        let unusable = ServerConfig {
            base_url: "not a url".to_string(),
            ..ServerConfig::default()
        };
        assert!(!make_allowlist(&unusable)(
            &"https://omk.5ijxa.com/index.php".parse().unwrap()
        ));
    }

    #[test]
    fn keybox_url_falls_back_to_the_documented_action() {
        let server = ServerConfig::default();
        let manifest = Manifest::default();
        let uri = keybox_url(&server, &manifest).unwrap();
        assert_eq!(uri.path(), "/api/omk/index.php");
        assert_eq!(uri.query(), Some("action=keybox"));

        let outside = Manifest {
            keybox: ManifestKeybox {
                url: "https://evil.example/k.xml".to_string(),
                ..ManifestKeybox::default()
            },
            ..Manifest::default()
        };
        assert!(keybox_url(&server, &outside).is_err());
    }

    #[test]
    fn digest_mismatch_is_rejected() {
        let server = ServerConfig {
            verify_signature: false,
            require_valid: false,
            min_days_remaining: 0,
            ..ServerConfig::default()
        };
        let manifest = Manifest {
            keybox: ManifestKeybox {
                sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                ..ManifestKeybox::default()
            },
            ..Manifest::default()
        };
        assert!(verify_bundle(&server, &manifest, b"<keybox/>").is_err());
        assert!(verify_bundle(&server, &manifest, b"").is_err());
    }

    #[test]
    fn invalid_server_validity_is_rejected() {
        let server = ServerConfig {
            verify_signature: false,
            ..ServerConfig::default()
        };
        let manifest = Manifest {
            keybox: ManifestKeybox {
                validity: KeyboxValidity {
                    level: "invalid".to_string(),
                    ok: false,
                    reasons: vec!["expired".to_string()],
                    ..KeyboxValidity::default()
                },
                ..ManifestKeybox::default()
            },
            ..Manifest::default()
        };
        let error = verify_bundle(&server, &manifest, b"<keybox/>").unwrap_err();
        assert!(format!("{error:#}").contains("expired"));
    }
}
