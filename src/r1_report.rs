//! R1 boot self-check.
//!
//! The module is only useful when the software KeyMint daemon is actually serving and the
//! cloud keybox feed answers, so this fork publishes that verdict through the manager's module
//! description instead of asking the user to read logs. The texts below are product display
//! strings for the Chinese-speaking audience this fork targets, which is why they are the one
//! place in the Rust source that is not ASCII.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use kmr_common::runtime::fs::atomic_replace_preserving_metadata;
use log::{info, warn};
use serde::Serialize;

use crate::{
    config::{self, DeviceProperty},
    pidfile_process,
    plat::resetprop,
    process_pid, remote_keybox, trust_pin,
};

/// Packaged module directory, used when the binary runs from a hot-updated location.
const MODULE_DIR: &str = "/data/adb/modules/oh_my_keymint";
const LOGS_PATH: &str = "/data/misc/keystore/omk/logs/";
const INJECTOR_PIDFILE: &str = "/data/adb/omk/injector-daemon.pid";

/// OMK answers attestation with the identity in `config.toml`, while the system properties the
/// Play Store reads are whatever PIF last published. A pair that disagrees is the signature of the
/// two spoofing layers fighting each other, so the boot check compares them field by field.
const IDENTITY_PROPERTIES: [(&str, &str); 5] = [
    ("brand", "ro.product.brand"),
    ("device", "ro.product.device"),
    ("product", "ro.product.name"),
    ("manufacturer", "ro.product.manufacturer"),
    ("model", "ro.product.model"),
];

#[derive(Serialize)]
pub struct BootReport {
    pub ok: bool,
    pub label: String,
    pub keymint_pid: Option<u32>,
    pub keystore_pid: Option<u32>,
    pub injector_pid: Option<u32>,
    pub rot_mode: String,
    pub rot_pinned: bool,
    pub rot_drift: bool,
    pub identity: IdentityCheck,
    pub cloud: String,
    pub description: String,
    pub description_written: bool,
}

#[derive(Serialize)]
pub struct IdentityCheck {
    pub matches: bool,
    pub mismatched: Vec<String>,
    pub unreadable: Vec<String>,
}

fn identity_check_with<F>(device: &DeviceProperty, read: F) -> IdentityCheck
where
    F: Fn(&str) -> Option<String>,
{
    let mut mismatched = Vec::new();
    let mut unreadable = Vec::new();

    for (field, property) in IDENTITY_PROPERTIES {
        let value = match field {
            "brand" => &device.brand,
            "device" => &device.device,
            "product" => &device.product,
            "manufacturer" => &device.manufacturer,
            "model" => &device.model,
            other => unreachable!("unknown identity field {other}"),
        };

        match read(property) {
            Some(live) if live.trim() == value.trim() => {}
            Some(live) => mismatched.push(format!("{field}: config={value:?} live={live:?}")),
            None => unreadable.push(format!("{field} ({property})")),
        }
    }

    IdentityCheck {
        matches: mismatched.is_empty(),
        mismatched,
        unreadable,
    }
}

fn identity_check() -> IdentityCheck {
    let device = match config::load_config_file() {
        Ok(config_file) => config_file.device,
        Err(error) => {
            warn!("device identity self-check skipped: {error:#}");
            return IdentityCheck {
                matches: false,
                mismatched: Vec::new(),
                unreadable: IDENTITY_PROPERTIES
                    .iter()
                    .map(|(field, property)| format!("{field} ({property})"))
                    .collect(),
            };
        }
    };
    identity_check_with(&device, resetprop::read_string_property)
}

/// `Oh My Keymint-R1-1.3.6-d6f65a3` becomes `OMK-R1-1.3.6-d6f65a3`, so the description carries
/// the same release identity that build.py baked into the `name` line. Hot updates replace only
/// the binaries, so the space-free name of an older build is shortened the same way.
fn release_label(module_prop: &str) -> String {
    let name = module_prop
        .lines()
        .find_map(|line| line.strip_prefix("name="))
        .unwrap_or_default()
        .trim();
    match name
        .strip_prefix("Oh My Keymint")
        .or_else(|| name.strip_prefix("OhMyKeymint"))
    {
        Some(rest) => format!("OMK{rest}"),
        None if !name.is_empty() => name.to_string(),
        None => format!("OMK-R1-{}", env!("CARGO_PKG_VERSION")),
    }
}

fn success_description(label: &str) -> String {
    format!("✅ {label}已成功运行。已成功连接云端。就等着被我格你机机吧😄 【本模块由【浅笑呐】二改自用】")
}

fn failure_description() -> String {
    format!("❌ OMK-R1 运行失败请把{LOGS_PATH}目录下日志给【浅笑呐】")
}

fn module_prop_path() -> Option<PathBuf> {
    let from_binary = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("module.prop")));
    if from_binary.as_deref().is_some_and(Path::is_file) {
        return from_binary;
    }
    let packaged = Path::new(MODULE_DIR).join("module.prop");
    packaged.is_file().then_some(packaged)
}

/// Rewrites only the `description` line so a hand-edited module.prop keeps the rest intact.
fn replace_description(raw: &str, description: &str) -> String {
    let replacement = format!("description={description}");
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in raw.lines() {
        if line.starts_with("description=") && !replaced {
            lines.push(replacement.clone());
            replaced = true;
        } else if line.starts_with("description=") {
            continue;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        lines.push(replacement);
    }
    let mut joined = lines.join("\n");
    joined.push('\n');
    joined
}

fn current_description(raw: &str) -> &str {
    raw.lines()
        .find_map(|line| line.strip_prefix("description="))
        .unwrap_or_default()
}

fn write_description(path: &Path, raw: &str, description: &str) -> Result<bool> {
    if current_description(raw).trim() == description {
        return Ok(false);
    }
    let contents = replace_description(raw, description);
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o644, 0, 0)
        .with_context(|| format!("failed to rewrite the module description at {path:?}"))?;
    Ok(true)
}

fn cloud_note(sha256: &str) -> String {
    // Keeps the log line short without splitting a hex digest in the middle.
    if sha256.len() > 32 {
        format!("{}...", &sha256[..32])
    } else {
        sha256.to_string()
    }
}

pub fn boot_report() -> Result<BootReport> {
    let path = module_prop_path();
    let raw = match path.as_deref() {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read module.prop at {path:?}"))?,
        None => String::new(),
    };
    let label = release_label(&raw);

    let executable = std::env::current_exe().ok();
    let keymint_pid = executable
        .as_deref()
        .and_then(|path| process_pid(&["keymint"], Some(path)))
        .or_else(|| process_pid(&["keymint"], None));
    let keystore_pid = process_pid(&["keystore2"], None);
    let injector_pid = pidfile_process(INJECTOR_PIDFILE, "daemon-injector")
        .or_else(|| process_pid(&["inject"], None));

    let rot = match trust_pin::status_report() {
        Ok(report) => (
            report.mode.to_string(),
            report.pinned_in_config,
            report.drift,
        ),
        Err(error) => {
            warn!("root of trust self-check failed: {error:#}");
            ("unknown".to_string(), false, false)
        }
    };

    let identity = identity_check();
    if !identity.matches {
        for entry in &identity.mismatched {
            warn!("device identity conflict with the live properties: {entry}");
        }
    }
    for entry in &identity.unreadable {
        warn!("device identity could not be cross-checked: {entry}");
    }

    let (cloud_ok, cloud) = match remote_keybox::probe() {
        Ok(manifest) => {
            info!(
                "cloud keybox feed reachable: source={} sha256={} pool={}",
                manifest.keybox.source,
                cloud_note(&manifest.keybox.sha256),
                manifest.keybox.rotation.pool_size
            );
            (true, format!("connected: {}", manifest.keybox.source))
        }
        Err(error) => {
            warn!("cloud keybox self-check failed: {error:#}");
            (false, format!("unreachable: {error:#}"))
        }
    };

    let ok = keymint_pid.is_some() && cloud_ok;
    let description = if ok {
        success_description(&label)
    } else {
        failure_description()
    };
    info!("R1 boot self-check: keymint={keymint_pid:?} cloud={cloud} verdict={ok}");

    let description_written = match path.as_deref() {
        None => {
            warn!("module.prop is not reachable; the boot verdict is reported only");
            false
        }
        Some(path) => match write_description(path, &raw, &description) {
            Ok(written) => written,
            Err(error) => {
                warn!("failed to update the module description: {error:#}");
                false
            }
        },
    };

    Ok(BootReport {
        ok,
        label,
        keymint_pid,
        keystore_pid,
        injector_pid,
        rot_mode: rot.0,
        rot_pinned: rot.1,
        rot_drift: rot.2,
        identity,
        cloud,
        description,
        description_written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "id=oh_my_keymint\nname=Oh My Keymint-R1-1.3.6-d6f65a3\nversion=1.3.6 (100-d6f65a3-release)\nversionCode=100\ndescription=Oh My Keymint-R1-1.3.6-d6f65a3 等待开机自检\n";

    #[test]
    fn label_shortens_the_prefix_and_keeps_identity() {
        assert_eq!(release_label(SAMPLE), "OMK-R1-1.3.6-d6f65a3");
    }

    #[test]
    fn label_shortens_a_space_free_name_from_an_older_build() {
        assert_eq!(
            release_label("id=oh_my_keymint\nname=OhMyKeymint-R1-1.3.6-d6f65a3\n"),
            "OMK-R1-1.3.6-d6f65a3"
        );
    }

    #[test]
    fn label_falls_back_to_the_package_version() {
        assert_eq!(
            release_label("id=oh_my_keymint\n"),
            format!("OMK-R1-{}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn only_the_description_line_changes() {
        let rewritten = replace_description(SAMPLE, "second");
        let lines: Vec<&str> = rewritten.lines().collect();
        assert_eq!(
            lines.first(),
            Some(&"id=oh_my_keymint"),
            "other keys must survive"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("description="))
                .count(),
            1
        );
        assert_eq!(current_description(&rewritten), "second");
        assert!(rewritten.ends_with('\n'));
    }

    #[test]
    fn missing_description_is_appended() {
        let rewritten = replace_description("id=oh_my_keymint\nname=x\n", "added");
        assert_eq!(current_description(&rewritten), "added");
    }

    #[test]
    fn digest_note_stays_on_a_boundary() {
        assert_eq!(
            cloud_note("a".repeat(64).as_str()),
            format!("{}...", "a".repeat(32))
        );
        assert_eq!(cloud_note("short"), "short");
    }

    fn device() -> DeviceProperty {
        DeviceProperty {
            brand: "google".to_string(),
            device: "caiman".to_string(),
            product: "caiman".to_string(),
            manufacturer: "google".to_string(),
            model: "Pixel 8".to_string(),
            serial: "serial".to_string(),
            override_telephony_properties: false,
            meid: String::new(),
            imei: String::new(),
            imei2: String::new(),
        }
    }

    #[test]
    fn identity_matches_when_the_live_properties_agree() {
        let check = identity_check_with(&device(), |property| match property {
            "ro.product.brand" => Some("google".to_string()),
            "ro.product.device" => Some("caiman".to_string()),
            "ro.product.name" => Some("caiman".to_string()),
            "ro.product.manufacturer" => Some("google".to_string()),
            "ro.product.model" => Some("Pixel 8".to_string()),
            _ => None,
        });
        assert!(check.matches, "mismatched={:?}", check.mismatched);
        assert!(check.unreadable.is_empty());
    }

    #[test]
    fn identity_reports_the_field_that_pif_changed() {
        let check = identity_check_with(&device(), |property| match property {
            "ro.product.model" => Some("Pixel 9".to_string()),
            "ro.product.name" => Some("shiba".to_string()),
            _ => Some("google".to_string()),
        });
        assert!(!check.matches);
        assert_eq!(check.mismatched.len(), 2);
        assert!(check
            .mismatched
            .iter()
            .any(|entry| entry.starts_with("model:")));
        assert!(check
            .mismatched
            .iter()
            .any(|entry| entry.contains("config=\"caiman\" live=\"shiba\"")));
    }

    #[test]
    fn unreadable_properties_are_not_reported_as_conflicts() {
        let check = identity_check_with(&device(), |property| {
            (property == "ro.product.brand").then(|| "google".to_string())
        });
        assert!(check.matches, "a missing property is not a conflict");
        assert!(check.mismatched.is_empty());
        assert_eq!(check.unreadable.len(), 4);
        assert!(check
            .unreadable
            .iter()
            .any(|entry| entry == "model (ro.product.model)"));
    }
}
