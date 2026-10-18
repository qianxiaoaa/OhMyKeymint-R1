//! R1: automatic Root of Trust pinning and stale key blob recovery.
//!
//! OMK binds every KeyBlob KEK to the verified boot key, the lock state and the
//! verified boot state. When any of those inputs changes between boots, existing
//! blobs cannot be decrypted any more and callers see `InvalidKeyBlob` (-33)
//! forever. This module keeps the effective values in `config.toml` as explicit
//! hex, records the values the stored blobs were created with, and clears the
//! blobs that can no longer be decrypted.

use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::{self, ConfigFile, RotPinMode, TrustValueSource, TrustValueSpec},
    global, root_path,
};

const STAMP_PATH: &str = root_path!("data/rot_stamp.toml");
const STAMP_VERSION: u32 = 1;
const MAX_STAMP_BYTES: u64 = 4096;
/// `restart.keymint` lives in OMK's own data directory because the keymint process runs
/// as the keystore user and `/data/adb` is not traversable for it. The root side
/// `daemon` script watches this path together with its legacy `/data/adb/omk` file.
const RESTART_KEYMINT_FLAG: &str = root_path!("data/restart.keymint");

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotStamp {
    version: u32,
    vb_key: String,
    vb_hash: String,
    device_locked: bool,
    verified_boot_state: bool,
}

#[derive(Serialize)]
pub struct RotReport {
    pub mode: &'static str,
    pub vb_key: String,
    pub vb_hash: String,
    pub vb_key_source: String,
    pub vb_hash_source: String,
    pub pinned_in_config: bool,
    pub drift: bool,
    pub stamp_present: bool,
    pub purged_keys: Option<usize>,
    pub restart_required: bool,
    pub note: String,
}

fn is_pinnable_key_source(source: &TrustValueSource) -> bool {
    matches!(
        source,
        TrustValueSource::Property
            | TrustValueSource::Computed
            | TrustValueSource::ExplicitHex
            | TrustValueSource::Persisted
    )
}

fn is_pinnable_hash_source(source: &TrustValueSource) -> bool {
    matches!(
        source,
        TrustValueSource::Property | TrustValueSource::Original | TrustValueSource::ExplicitHex
    )
}

fn hex32(value: &[u8; 32]) -> String {
    hex::encode(value)
}

fn load_stamp() -> Result<Option<RotStamp>> {
    let path = Path::new(STAMP_PATH);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() > MAX_STAMP_BYTES {
                return Err(anyhow!(
                    "root of trust stamp must be a regular file of at most {MAX_STAMP_BYTES} bytes"
                ));
            }
            let mut contents = String::new();
            File::open(path)?
                .take(MAX_STAMP_BYTES + 1)
                .read_to_string(&mut contents)
                .context("failed to read root of trust stamp")?;
            if contents.len() as u64 > MAX_STAMP_BYTES {
                return Err(anyhow!("root of trust stamp is too large"));
            }
            let stamp: RotStamp = toml::from_str(&contents)
                .context("failed to parse root of trust stamp; skipping blob recovery")?;
            if stamp.version != STAMP_VERSION {
                return Err(anyhow!(
                    "unsupported root of trust stamp version {}",
                    stamp.version
                ));
            }
            Ok(Some(stamp))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to inspect root of trust stamp"),
    }
}

fn save_stamp(vb_key: &[u8; 32], vb_hash: &[u8; 32], device_locked: bool, boot_state: bool) {
    let stamp = RotStamp {
        version: STAMP_VERSION,
        vb_key: hex32(vb_key),
        vb_hash: hex32(vb_hash),
        device_locked,
        verified_boot_state: boot_state,
    };
    let contents = match toml::to_string_pretty(&stamp) {
        Ok(contents) => contents,
        Err(error) => {
            log::warn!("failed to serialize root of trust stamp: {error:#}");
            return;
        }
    };
    if let Err(error) = atomic_replace_preserving_metadata(
        Path::new(STAMP_PATH),
        contents.as_bytes(),
        0o600,
        KEYSTORE_UID,
        KEYSTORE_GID,
    ) {
        log::warn!("failed to persist root of trust stamp: {error:#}");
    }
}

struct CurrentRot {
    vb_key: String,
    vb_hash: String,
    device_locked: bool,
    verified_boot_state: bool,
}

impl CurrentRot {
    fn new(vb_key: &[u8; 32], vb_hash: &[u8; 32], device_locked: bool, boot: bool) -> Self {
        Self {
            vb_key: hex32(vb_key),
            vb_hash: hex32(vb_hash),
            device_locked,
            verified_boot_state: boot,
        }
    }
}

fn stamp_matches(stamp: &RotStamp, current: &CurrentRot) -> bool {
    stamp.vb_key == current.vb_key
        && stamp.vb_hash == current.vb_hash
        && stamp.device_locked == current.device_locked
        && stamp.verified_boot_state == current.verified_boot_state
}

/// Deletes every key entry: their blobs cannot be decrypted with the root of
/// trust inputs that are now in use.
fn purge_key_blobs() -> Result<usize> {
    let purged = global::DB
        .with(|db| db.borrow_mut().purge_all_keys())
        .context("failed to purge undecryptable key blobs")?;
    log::warn!("cleared {purged} key entries bound to a stale root of trust");
    Ok(purged)
}

fn request_keymint_restart() {
    let flag = Path::new(RESTART_KEYMINT_FLAG);
    if let Some(parent) = flag.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            log::warn!("failed to create the state directory: {error:#}");
            return;
        }
    }
    match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(flag)
    {
        Ok(_) => log::info!("requested a keymint restart to apply the pinned trust values"),
        Err(error) => log::warn!("failed to request a keymint restart: {error:#}"),
    }
}

/// Runs once at daemon startup, before any key is served. The values in use are
/// written to `config.toml` and compared with the values the stored blobs were
/// created with; a mismatch means those blobs are undecryptable, so they are cleared
/// instead of failing with `InvalidKeyBlob` on every use.
pub fn apply_at_boot() -> Result<()> {
    let (r1, trust) = {
        let guard = config::config()
            .read()
            .map_err(|_| anyhow!("config lock poisoned during the root of trust pin"))?;
        (guard.r1.clone(), guard.trust.clone())
    };
    let current = CurrentRot::new(
        &trust.vb_key,
        &trust.vb_hash,
        trust.device_locked,
        trust.verified_boot_state,
    );
    let pinnable = is_pinnable_key_source(&trust.vb_key_source)
        && is_pinnable_hash_source(&trust.vb_hash_source);

    if matches!(r1.rot_pin, RotPinMode::Pinned) && pinnable {
        match config::sync_vbmeta_pin(&current.vb_key, &current.vb_hash) {
            Ok(true) => log::info!(
                "pinned the root of trust into config.toml: vb_key={} vb_hash={}",
                current.vb_key,
                current.vb_hash
            ),
            Ok(false) => {}
            Err(error) => log::warn!("failed to pin the root of trust: {error:#}"),
        }
    } else if !pinnable {
        log::warn!(
            "live vbmeta values are not pinnable (vb_key source={}, vb_hash source={}); the pin is unchanged",
            trust.vb_key_source,
            trust.vb_hash_source
        );
    }

    let stamp = match load_stamp() {
        Ok(stamp) => stamp,
        Err(error) => {
            log::warn!("root of trust stamp unavailable: {error:#}; recording it without purging");
            save_stamp_from(&current);
            return Ok(());
        }
    };

    match stamp {
        None => {
            save_stamp_from(&current);
            Ok(())
        }
        Some(stamp) if stamp_matches(&stamp, &current) => Ok(()),
        Some(_) => {
            log::warn!(
                "root of trust changed since the stored key blobs were created (vb_key={} vb_hash={})",
                current.vb_key,
                current.vb_hash
            );
            if r1.rot_auto_heal {
                if let Err(error) = purge_key_blobs() {
                    log::error!("automatic key blob recovery failed: {error:#}");
                }
            } else {
                log::warn!(
                    "r1.rot_auto_heal is disabled; existing keys may keep reporting InvalidKeyBlob"
                );
            }
            save_stamp_from(&current);
            Ok(())
        }
    }
}

fn save_stamp_from(current: &CurrentRot) {
    let vb_key = parse_hex32(&current.vb_key);
    let vb_hash = parse_hex32(&current.vb_hash);
    let (Some(vb_key), Some(vb_hash)) = (vb_key, vb_hash) else {
        log::warn!("refusing to record a malformed root of trust stamp");
        return;
    };
    save_stamp(
        &vb_key,
        &vb_hash,
        current.device_locked,
        current.verified_boot_state,
    );
}

fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    let decoded = hex::decode(value).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Some(bytes)
}

/// The inputs the KeyBlob KEK is derived from, resolved without needing the daemon's
/// runtime config copy so a short lived WebUI helper can report the same values.
struct EffectiveRot {
    vb_key: [u8; 32],
    vb_hash: [u8; 32],
    vb_key_source: String,
    vb_hash_source: String,
    device_locked: bool,
    verified_boot_state: bool,
}

impl EffectiveRot {
    fn from_trust(trust: &crate::config::ResolvedTrust) -> Self {
        Self {
            vb_key: trust.vb_key,
            vb_hash: trust.vb_hash,
            vb_key_source: trust.vb_key_source.to_string(),
            vb_hash_source: trust.vb_hash_source.to_string(),
            device_locked: trust.device_locked,
            verified_boot_state: trust.verified_boot_state,
        }
    }

    fn current(&self) -> CurrentRot {
        CurrentRot::new(
            &self.vb_key,
            &self.vb_hash,
            self.device_locked,
            self.verified_boot_state,
        )
    }
}

fn runtime_trust() -> Result<crate::config::ResolvedTrust> {
    let guard = config::config()
        .read()
        .map_err(|_| anyhow!("config lock poisoned while reading trust state"))?;
    Ok(guard.trust.clone())
}

/// Pinned values win, then the running daemon's resolved values, then what the device
/// reports right now. `None` means no trustworthy value is available at all.
fn effective_rot() -> Result<Option<EffectiveRot>> {
    let config_file = config::load_config_file().context("failed to read config.toml")?;
    let device_locked = config_file.trust.device_locked;
    let verified_boot_state = config_file.trust.verified_boot_state;
    if let (TrustValueSpec::Hex(vb_key), TrustValueSpec::Hex(vb_hash)) =
        (&config_file.trust.vb_key, &config_file.trust.vb_hash)
    {
        return Ok(Some(EffectiveRot {
            vb_key: *vb_key,
            vb_hash: *vb_hash,
            vb_key_source: TrustValueSource::ExplicitHex.to_string(),
            vb_hash_source: TrustValueSource::ExplicitHex.to_string(),
            device_locked,
            verified_boot_state,
        }));
    }
    if let Some(runtime) = config::CONFIG.get() {
        let trust = runtime
            .read()
            .map_err(|_| anyhow!("config lock poisoned while reading trust state"))?
            .trust
            .clone();
        return Ok(Some(EffectiveRot::from_trust(&trust)));
    }
    Ok(
        crate::plat::vbmeta::live_vbmeta_values(device_locked).map(|(vb_key, vb_hash)| {
            EffectiveRot {
                vb_key,
                vb_hash,
                vb_key_source: "live".to_string(),
                vb_hash_source: "live".to_string(),
                device_locked,
                verified_boot_state,
            }
        }),
    )
}

fn runtime_r1() -> Result<crate::config::R1Config> {
    let guard = config::config()
        .read()
        .map_err(|_| anyhow!("config lock poisoned while reading the R1 settings"))?;
    Ok(guard.r1.clone())
}

/// Runs on the keybox identity change path. A keybox swap changes the attestation
/// identity on purpose, so the effective trust values are re-pinned to what the
/// device reports now and blobs that no longer match are cleared.
pub fn on_keybox_identity_change() -> Result<()> {
    let trust = runtime_trust()?;
    let r1 = runtime_r1()?;
    let live = crate::plat::vbmeta::live_vbmeta_values(trust.device_locked);

    let (vb_key, vb_hash) = match live {
        Some(values) => values,
        None => {
            log::warn!("live vbmeta values unavailable during the keybox re-pin; pin unchanged");
            save_stamp(
                &trust.vb_key,
                &trust.vb_hash,
                trust.device_locked,
                trust.verified_boot_state,
            );
            return Ok(());
        }
    };

    let vb_key_hex = hex32(&vb_key);
    let vb_hash_hex = hex32(&vb_hash);
    let rot_changed = vb_key != trust.vb_key || vb_hash != trust.vb_hash;

    if matches!(r1.rot_pin, RotPinMode::Pinned) {
        config::sync_vbmeta_pin(&vb_key_hex, &vb_hash_hex)
            .context("failed to re-pin the root of trust after a keybox change")?;
        log::info!(
            "re-pinned the root of trust after a keybox change: vb_key={vb_key_hex} vb_hash={vb_hash_hex}"
        );
    }

    // Keybox-bound keys are retired by the caller. Only a root of trust change also
    // makes every remaining blob undecryptable.
    if rot_changed {
        if r1.rot_auto_heal {
            purge_key_blobs()?;
        }
        request_keymint_restart();
    }

    save_stamp(
        &vb_key,
        &vb_hash,
        trust.device_locked,
        trust.verified_boot_state,
    );
    Ok(())
}

fn pinned_in_config(config_file: &ConfigFile) -> bool {
    matches!(
        (&config_file.trust.vb_key, &config_file.trust.vb_hash),
        (TrustValueSpec::Hex(_), TrustValueSpec::Hex(_))
    )
}

pub fn status_report() -> Result<RotReport> {
    let config_file = config::load_config_file().context("failed to read config.toml")?;
    let stamp = load_stamp()?;
    let stamp_present = stamp.is_some();
    let pinned = pinned_in_config(&config_file);
    let mode = config_file.r1.rot_pin.as_str();

    let Some(rot) = effective_rot()? else {
        return Ok(RotReport {
            mode,
            vb_key: String::new(),
            vb_hash: String::new(),
            vb_key_source: String::new(),
            vb_hash_source: String::new(),
            pinned_in_config: pinned,
            drift: false,
            stamp_present,
            purged_keys: None,
            restart_required: false,
            note: "no root of trust value is available on this device".to_string(),
        });
    };

    let current = rot.current();
    let drift = stamp
        .as_ref()
        .map(|stamp| !stamp_matches(stamp, &current))
        .unwrap_or(false);

    let note = if drift {
        "the stored root of trust differs from the values in use".to_string()
    } else if stamp_present {
        "the root of trust is pinned and consistent".to_string()
    } else {
        "no root of trust stamp yet; the next keymint start records one".to_string()
    };

    Ok(RotReport {
        mode,
        vb_key: current.vb_key,
        vb_hash: current.vb_hash,
        vb_key_source: rot.vb_key_source,
        vb_hash_source: rot.vb_hash_source,
        pinned_in_config: pinned,
        drift,
        stamp_present,
        purged_keys: None,
        restart_required: false,
        note,
    })
}

/// Force path used by the WebUI: adopt the values the device reports now and restart
/// keymint so the new pin is in use.
///
/// `purge` cannot delete key blobs from a short lived helper process, because the
/// running keymint owns the database connection. Leaving the stamp at the previous
/// values makes the restarted daemon detect the drift in [`apply_at_boot`] and clear
/// the undecryptable blobs there instead.
pub fn force_repin(purge: bool) -> Result<RotReport> {
    let config_file = config::load_config_file().context("failed to read config.toml")?;
    let mut report = status_report()?;
    let live = crate::plat::vbmeta::live_vbmeta_values(config_file.trust.device_locked);

    let (vb_key, vb_hash) = match live {
        Some(values) => values,
        None => {
            report.note = "live vbmeta values unavailable; nothing was changed".to_string();
            return Ok(report);
        }
    };

    config::sync_vbmeta_pin(&hex32(&vb_key), &hex32(&vb_hash))
        .context("failed to pin the root of trust on request")?;

    let in_daemon = config::CONFIG.get().is_some();
    if purge && in_daemon {
        report.purged_keys = Some(purge_key_blobs()?);
        save_stamp(
            &vb_key,
            &vb_hash,
            config_file.trust.device_locked,
            config_file.trust.verified_boot_state,
        );
    } else if !purge {
        save_stamp(
            &vb_key,
            &vb_hash,
            config_file.trust.device_locked,
            config_file.trust.verified_boot_state,
        );
    }

    report.vb_key = hex32(&vb_key);
    report.vb_hash = hex32(&vb_hash);
    report.vb_key_source = TrustValueSource::ExplicitHex.to_string();
    report.vb_hash_source = TrustValueSource::ExplicitHex.to_string();
    report.pinned_in_config = true;
    report.drift = purge && !in_daemon;
    report.restart_required = true;
    report.note = if purge && !in_daemon {
        "re-pinned; the running keymint clears the stale key blobs after its restart".to_string()
    } else {
        "the root of trust was re-pinned on request".to_string()
    };
    request_keymint_restart();
    let _ = crate::webui_activity::record(
        "rot_repinned",
        &format!(
            "vb_hash={}",
            hex32(&vb_hash).chars().take(12).collect::<String>()
        ),
    );
    Ok(report)
}

pub fn status_json() -> Result<String> {
    let report = status_report()?;
    serde_json::to_string(&report).context("failed to serialize the root of trust status")
}
