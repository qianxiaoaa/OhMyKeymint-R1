//! Configuration for the Qualcomm Soter HAL relay.
//!
//! The native Soter service reads the same file from its own TA process; the
//! WebUI only uses this module to validate and atomically publish the
//! configuration.

use std::{
    collections::HashSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use serde::{Deserialize, Serialize};
use ureq::http::Uri;

use crate::root_path;

/// Shared with the software Soter TA and its native HAL watchdog.
pub const CONFIG_PATH: &str = root_path!("data/soterta/remote.conf");
const CONFIG_DIR: &str = root_path!("data/soterta");
/// Persistent switch for taking over the vendor Soter service. It is kept as
/// a separate on-disk marker for watchdog coordination, independently of
/// remote forwarding configured in `remote.conf`.
pub const SOFTWARE_FLAG_PATH: &str = root_path!("data/soterta/enabled");
const MAX_URL_BYTES: usize = 2048;
const MAX_TOKEN_BYTES: usize = 1024;
const MAX_DEVICE_ID_BYTES: usize = 512;
const MAX_UID_MAP_BYTES: usize = 4096;
// Includes JSON escaping and field names; keep the WebUI transport cap in sync.
const MAX_JSON_BYTES: usize = 16 * 1024;

/// The field order is part of the WebUI/native bridge contract.  Keep this in
/// sync with `webui/src/cli.ts` so responses remain canonical JSON.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Whether the software Soter TA owns the native HAL service.
    pub enabled: bool,
    /// Whether the software TA forwards supported operations to the relay.
    pub remote_enabled: bool,
    pub url: String,
    pub token: String,
    pub device_id: String,
    pub tls_insecure: bool,
    pub uid_map: String,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        validate_text("url", &self.url, MAX_URL_BYTES, true)?;
        validate_text("token", &self.token, MAX_TOKEN_BYTES, true)?;
        validate_text("device_id", &self.device_id, MAX_DEVICE_ID_BYTES, true)?;
        validate_text("uid_map", &self.uid_map, MAX_UID_MAP_BYTES, true)?;

        if !self.url.is_empty() {
            validate_url(&self.url)?;
        }
        if !self.uid_map.is_empty() {
            validate_uid_map(&self.uid_map)?;
        }
        if self.remote_enabled {
            if self.url.is_empty() {
                bail!("Soter server URL is required when the relay is enabled");
            }
            if self.token.is_empty() {
                bail!("Soter token is required when the relay is enabled");
            }
            if self.device_id.is_empty() {
                bail!("Soter B device ID is required when the relay is enabled");
            }
        }
        Ok(())
    }

    /// Parse the canonical JSON payload sent by the WebUI bridge.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > MAX_JSON_BYTES {
            bail!("Soter HAL configuration exceeds the byte limit");
        }
        let config: Self = serde_json::from_str(raw).context("invalid Soter HAL JSON")?;
        let canonical = serde_json::to_string(&config).context("failed to serialize Soter HAL")?;
        if raw != canonical {
            bail!("Soter HAL JSON is not canonical");
        }
        config.validate()?;
        Ok(config)
    }

    /// Decode the shell-safe WebUI payload without changing the raw JSON CLI.
    pub fn parse_base64(encoded: &str) -> Result<Self> {
        if encoded.is_empty() || encoded.len() > MAX_JSON_BYTES.div_ceil(3) * 4 {
            bail!("invalid Soter HAL payload size");
        }
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .context("invalid Soter HAL payload encoding")?;
        let raw = std::str::from_utf8(&bytes).context("Soter HAL payload is not UTF-8")?;
        Self::parse(raw)
    }

    /// Parse the line-oriented file consumed by the native software TA.
    pub fn parse_file(raw: &str) -> Result<Self> {
        let mut config = Self::default();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid Soter HAL configuration line"))?;
            let value = value.trim();
            match key.trim() {
                // `enabled` was the only switch in older OMK builds.  Keep
                // accepting it as the relay switch so existing files remain
                // readable; new files use the unambiguous `remote_enabled`
                // spelling and store the takeover marker separately.
                "enabled" | "remote_enabled" => {
                    config.remote_enabled = match value {
                        "1" | "true" | "yes" | "on" => true,
                        "0" | "false" | "no" | "off" => false,
                        _ => bail!("invalid Soter HAL enabled value"),
                    }
                }
                "url" => config.url = value.to_string(),
                "token" => config.token = value.to_string(),
                "device_id" => config.device_id = value.to_string(),
                "tls_insecure" => {
                    config.tls_insecure = match value {
                        "1" | "true" | "yes" | "on" => true,
                        "0" | "false" | "no" | "off" => false,
                        _ => bail!("invalid Soter HAL tls_insecure value"),
                    }
                }
                "uid_map" => config.uid_map = value.to_string(),
                _ => bail!("unknown Soter HAL configuration key"),
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn load() -> Result<Self> {
        Self::load_from_paths(Path::new(CONFIG_PATH), Path::new(SOFTWARE_FLAG_PATH))
    }

    fn load_from_paths(config_path: &Path, software_flag_path: &Path) -> Result<Self> {
        let mut config = match fs::read_to_string(config_path) {
            Ok(raw) => {
                let legacy = !raw.lines().any(|line| {
                    line.split_once('=')
                        .is_some_and(|(key, _)| key.trim() == "remote_enabled")
                });
                let mut config = Self::parse_file(&raw)?;
                // Before the split, `enabled` controlled both the watchdog
                // and remote forwarding. Preserve that behavior for legacy
                // files; new files keep forwarding independent of takeover.
                if legacy && config.remote_enabled {
                    config.enabled = true;
                }
                config
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => Err(error).context("failed to read Soter HAL configuration")?,
        };
        // A local software TA can run without remote forwarding, and relay
        // settings can be prepared while the stock HAL remains active.
        config.enabled = config.enabled || software_flag_path.is_file();
        Ok(config)
    }
}

fn validate_text(name: &str, value: &str, max_bytes: usize, allow_empty: bool) -> Result<()> {
    if !allow_empty && value.is_empty() {
        bail!("Soter {name} cannot be empty");
    }
    if value.len() > max_bytes {
        bail!("Soter {name} exceeds the {max_bytes} byte limit");
    }
    if value.trim() != value || value.chars().any(|ch| ch.is_control()) {
        bail!("Soter {name} contains whitespace or control characters");
    }
    Ok(())
}

fn validate_url(value: &str) -> Result<()> {
    let uri: Uri = value
        .parse()
        .map_err(|_| anyhow!("invalid Soter server URL"))?;
    let scheme = uri
        .scheme()
        .map(|scheme| scheme.as_str())
        .ok_or_else(|| anyhow!("Soter server URL must include a scheme"))?;
    if scheme != "http" && scheme != "https" {
        bail!("Soter server URL must use HTTP or HTTPS");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("Soter server URL must include a host"))?;
    if authority.as_str().is_empty() || authority.as_str().contains('@') {
        bail!("Soter server URL must not contain embedded credentials");
    }
    if uri.path().contains(['\r', '\n']) {
        bail!("Soter server URL contains a newline");
    }
    Ok(())
}

fn validate_uid_map(value: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for mapping in value.split([',', ';', ' ']) {
        if mapping.is_empty() {
            bail!("Soter UID mapping contains an empty entry");
        }
        let (from, to) = mapping
            .split_once('=')
            .or_else(|| mapping.split_once(':'))
            .ok_or_else(|| anyhow!("Soter UID mapping must use A=B entries"))?;
        if from.is_empty()
            || to.is_empty()
            || from.parse::<u32>().is_err()
            || to.parse::<u32>().is_err()
        {
            bail!("Soter UID mapping contains an invalid UID");
        }
        if !seen.insert(from) {
            bail!("Soter UID mapping contains a duplicate source UID");
        }
    }
    Ok(())
}

fn file_contents(config: &Config) -> String {
    format!(
        "remote_enabled={}\nurl={}\ntoken={}\ndevice_id={}\ntls_insecure={}\nuid_map={}\n",
        if config.remote_enabled {
            "true"
        } else {
            "false"
        },
        config.url,
        config.token,
        config.device_id,
        if config.tls_insecure { "true" } else { "false" },
        config.uid_map,
    )
}

pub fn state_json() -> Result<String> {
    let config = Config::load()?;
    serde_json::to_string(&config).context("failed to serialize Soter HAL state")
}

pub fn is_enabled() -> Result<bool> {
    // Exclusivity follows HAL takeover, including local software-TA mode.
    // Prepared relay settings alone do not enable the Qualcomm service.
    Ok(Config::load()?.enabled)
}

fn ensure_config_dir() -> Result<()> {
    fs::create_dir_all(CONFIG_DIR).context("failed to create Soter HAL configuration directory")?;
    fs::set_permissions(CONFIG_DIR, fs::Permissions::from_mode(0o770))
        .context("failed to set Soter HAL configuration directory permissions")?;
    let c_path = std::ffi::CString::new(CONFIG_DIR).expect("constant path has no NUL");
    if unsafe { libc::chown(c_path.as_ptr(), KEYSTORE_UID, KEYSTORE_GID) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set Soter HAL configuration directory ownership");
    }
    Ok(())
}

fn write_software_flag(enabled: bool) -> Result<()> {
    if enabled {
        atomic_replace_preserving_metadata(
            Path::new(SOFTWARE_FLAG_PATH),
            b"1\n",
            0o600,
            KEYSTORE_UID,
            KEYSTORE_GID,
        )
        .context("failed to enable the Soter HAL watchdog")?;
        fs::set_permissions(SOFTWARE_FLAG_PATH, fs::Permissions::from_mode(0o600))?;
    } else {
        match fs::remove_file(SOFTWARE_FLAG_PATH) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("failed to disable the Soter HAL watchdog"),
        }
    }
    Ok(())
}

fn refresh_watchdog(config_enabled: bool) -> Result<()> {
    // The watchdog is intentionally optional here: older installations may
    // not contain the relay daemon yet, but saving a valid disabled config is
    // still useful and must not fail solely because the module is being
    // upgraded. The explicit enable/disable command also updates the
    // watchdog's takeover flag, while the watchdog reads remote.conf on boot.
    let candidates = [
        "/data/adb/modules/oh_my_keymint/soterta.sh",
        "/data/adb/modules/oh_my_keymint/soterta/soterta.sh",
    ];
    let Some(script) = candidates.iter().find(|path| Path::new(path).is_file()) else {
        return Ok(());
    };
    let status = Command::new(script)
        .arg(if config_enabled { "enable" } else { "disable" })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to refresh Soter HAL watchdog {script}"))?;
    if !status.success() {
        bail!("Soter HAL watchdog refresh failed with {status}");
    }
    Ok(())
}

pub fn save(config: Config) -> Result<()> {
    config.validate()?;
    ensure_config_dir()?;
    let contents = file_contents(&config);
    atomic_replace_preserving_metadata(
        Path::new(CONFIG_PATH),
        contents.as_bytes(),
        0o600,
        KEYSTORE_UID,
        KEYSTORE_GID,
    )
    .context("failed to atomically write Soter HAL configuration")?;
    // Preserve neither an unexpectedly broad mode nor an owner inherited from
    // an old module installation: this file contains the relay token.
    fs::set_permissions(CONFIG_PATH, fs::Permissions::from_mode(0o600))
        .context("failed to set Soter HAL configuration permissions")?;
    let c_path = std::ffi::CString::new(CONFIG_PATH).expect("constant path has no NUL");
    if unsafe { libc::chown(c_path.as_ptr(), KEYSTORE_UID, KEYSTORE_GID) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set Soter HAL configuration ownership");
    }
    write_software_flag(config.enabled)?;
    refresh_watchdog(config.enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        Config::default().validate().unwrap();
        assert_eq!(
            Config::parse(&serde_json::to_string(&Config::default()).unwrap()).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn default_config_is_disabled_and_takeover_needs_no_relay_identity() {
        let mut config = Config::default();
        assert!(!config.enabled);
        assert!(!config.remote_enabled);
        assert!(!config.tls_insecure);
        assert!(config.uid_map.is_empty());
        assert!(config.url.is_empty());
        assert!(config.device_id.is_empty());
        assert!(config.token.is_empty());
        config.enabled = true;
        config.validate().unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert!(Config::parse_base64(&BASE64_STANDARD.encode(json)).unwrap() == config);
    }

    #[test]
    fn webui_transport_preserves_every_supplied_relay_identity() {
        // Relay identity comes only from explicit configuration; the save
        // transport never invents or rewrites user-supplied values.
        for fields in 1..=7 {
            let config = Config {
                url: if fields & 1 != 0 {
                    "https://relay.example.test".into()
                } else {
                    String::new()
                },
                device_id: if fields & 2 != 0 {
                    "custom-device".into()
                } else {
                    String::new()
                },
                token: if fields & 4 != 0 {
                    "custom-token".into()
                } else {
                    String::new()
                },
                ..Config::default()
            };
            let payload = BASE64_STANDARD.encode(serde_json::to_string(&config).unwrap());
            assert_eq!(Config::parse_base64(&payload).unwrap(), config);
        }
    }

    #[test]
    fn relay_identity_is_required_only_when_forwarding_is_enabled() {
        for fields in 0..=7 {
            let partial = Config {
                remote_enabled: true,
                url: if fields & 1 != 0 {
                    "https://relay.example.test".into()
                } else {
                    String::new()
                },
                device_id: if fields & 2 != 0 {
                    "custom-device".into()
                } else {
                    String::new()
                },
                token: if fields & 4 != 0 {
                    "custom-token".into()
                } else {
                    String::new()
                },
                ..Config::default()
            };
            let contents = file_contents(&partial);
            if fields == 7 {
                let resolved = Config::parse_file(&contents).unwrap();
                assert!(resolved == partial);
                let payload = BASE64_STANDARD.encode(serde_json::to_string(&resolved).unwrap());
                let saved = Config::parse_base64(&payload).unwrap();
                assert!(Config::parse_file(&file_contents(&saved)).unwrap() == resolved);
            } else {
                assert!(Config::parse_file(&contents).is_err());
            }
        }
        let resolved = Config::parse_file(&file_contents(&Config::default())).unwrap();
        assert!(!resolved.enabled);
        assert!(!resolved.remote_enabled);
        assert!(resolved.url.is_empty());
        assert!(resolved.device_id.is_empty());
        assert!(resolved.token.is_empty());
    }

    #[test]
    fn webui_transport_preserves_advanced_settings() {
        let config = Config {
            tls_insecure: true,
            uid_map: "10001=10002".into(),
            ..Config::default()
        };
        let payload = BASE64_STANDARD.encode(serde_json::to_string(&config).unwrap());
        let transported = Config::parse_base64(&payload).unwrap();
        assert!(!transported.enabled);
        assert!(transported.tls_insecure);
        assert_eq!(transported.uid_map, "10001=10002");
    }

    #[test]
    fn enabled_config_requires_relay_identity() {
        let config = Config {
            remote_enabled: true,
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_credentials_and_bad_uid_mappings() {
        let mut config = Config {
            url: "https://user:pass@example.test".into(),
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.url = "https://example.test".into();
        config.uid_map = "1000=1001 1000=1002".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn file_format_matches_software_ta_parser() {
        let config = Config {
            enabled: false,
            remote_enabled: true,
            url: "https://relay.example.test/base".into(),
            token: "relay-token".into(),
            device_id: "soter-b".into(),
            tls_insecure: true,
            uid_map: "10001=10002".into(),
        };
        let file = file_contents(&config);
        assert_eq!(Config::parse_file(&file).unwrap(), config);
    }

    #[test]
    fn file_parser_accepts_legacy_and_split_switches() {
        let identity = "url=https://relay.example.test\ntoken=relay-token\ndevice_id=soter-b\n";
        let legacy = Config::parse_file(&format!("enabled=true\n{identity}")).unwrap();
        assert!(legacy.remote_enabled);
        assert!(!legacy.enabled);

        let split = Config::parse_file(&format!("remote_enabled=true\n{identity}")).unwrap();
        assert!(split.remote_enabled);
        assert!(!split.enabled);

        // Forwarding switches without an explicit relay identity no longer
        // resolve to baked-in defaults and must fail closed.
        assert!(Config::parse_file("enabled=true\n").is_err());
        assert!(Config::parse_file("remote_enabled=true\n").is_err());
    }

    #[test]
    fn independent_switches_round_trip_through_transport_and_split_storage() {
        let directory = tempfile::TempDir::new().unwrap();
        let config_path = directory.path().join("remote.conf");
        let flag_path = directory.path().join("enabled");
        for enabled in [false, true] {
            for remote_enabled in [false, true] {
                let config = Config {
                    enabled,
                    remote_enabled,
                    url: "https://relay.example.test/base".into(),
                    token: "custom-token".into(),
                    device_id: "custom-device".into(),
                    tls_insecure: true,
                    uid_map: "10001=10002".into(),
                };
                let payload = BASE64_STANDARD.encode(serde_json::to_string(&config).unwrap());
                let transported = Config::parse_base64(&payload).unwrap();
                assert_eq!(transported, config);
                fs::write(&config_path, file_contents(&transported)).unwrap();
                if transported.enabled {
                    fs::write(&flag_path, b"1\n").unwrap();
                } else if flag_path.exists() {
                    fs::remove_file(&flag_path).unwrap();
                }
                assert_eq!(
                    Config::load_from_paths(&config_path, &flag_path).unwrap(),
                    config
                );
            }
        }
    }

    #[test]
    fn independent_takeover_flag_preserves_legacy_and_local_only_state() {
        let directory = tempfile::TempDir::new().unwrap();
        let config_path = directory.path().join("remote.conf");
        let flag_path = directory.path().join("enabled");
        assert_eq!(
            Config::load_from_paths(&config_path, &flag_path).unwrap(),
            Config::default()
        );
        fs::write(&flag_path, b"1\n").unwrap();
        let local = Config::load_from_paths(&config_path, &flag_path).unwrap();
        assert!(local.enabled);
        assert!(!local.remote_enabled);
        fs::remove_file(&flag_path).unwrap();

        fs::write(
            &config_path,
            "enabled=true\nurl=https://relay.example.test\ntoken=relay-token\ndevice_id=soter-b\n",
        )
        .unwrap();
        let legacy = Config::load_from_paths(&config_path, &flag_path).unwrap();
        assert!(legacy.enabled);
        assert!(legacy.remote_enabled);

        fs::write(
            &config_path,
            "remote_enabled=true\nurl=https://relay.example.test\ntoken=relay-token\ndevice_id=soter-b\n",
        )
        .unwrap();
        let prepared = Config::load_from_paths(&config_path, &flag_path).unwrap();
        assert!(!prepared.enabled);
        assert!(prepared.remote_enabled);

        fs::write(&config_path, "remote_enabled=true\n").unwrap();
        assert!(Config::load_from_paths(&config_path, &flag_path).is_err());

        fs::write(&flag_path, b"1\n").unwrap();
        fs::write(&config_path, "remote_enabled=false\n").unwrap();
        let local = Config::load_from_paths(&config_path, &flag_path).unwrap();
        assert!(local.enabled);
        assert!(!local.remote_enabled);
    }

    #[test]
    fn webui_base64_preserves_shell_characters_and_empty_fields() {
        let configs = [
            Config::default(),
            Config {
                enabled: true,
                remote_enabled: true,
                url: "https://relay.example.test/base?a=1&b=2".into(),
                token: "quotes'\" $HOME `id` $(id);{}*\\+=".into(),
                device_id: "device b".into(),
                tls_insecure: false,
                uid_map: "10001=10002 10003=10004".into(),
            },
        ];
        for config in configs {
            let json = serde_json::to_string(&config).unwrap();
            let encoded = BASE64_STANDARD.encode(json);
            assert_eq!(Config::parse_base64(&encoded).unwrap(), config);
        }
    }

    #[test]
    fn webui_base64_rejects_invalid_payloads() {
        let json = serde_json::to_string(&Config::default()).unwrap();
        for encoded in [
            String::new(),
            "not-base64".into(),
            BASE64_STANDARD.encode([0xff]),
            BASE64_STANDARD.encode("{}"),
            BASE64_STANDARD.encode(format!("{json}\n")),
            BASE64_STANDARD.encode(json.replacen('{', "{\"extra\":0,", 1)),
            "A".repeat(MAX_JSON_BYTES.div_ceil(3) * 4 + 1),
            BASE64_STANDARD.encode(" ".repeat(MAX_JSON_BYTES + 1)),
        ] {
            assert!(Config::parse_base64(&encoded).is_err());
        }
    }

    #[test]
    fn webui_base64_accepts_valid_config_over_four_kib() {
        let config = Config {
            enabled: false,
            remote_enabled: true,
            url: format!("https://relay.example.test/{}", "a".repeat(1800)),
            token: "a".repeat(MAX_TOKEN_BYTES),
            device_id: "b".repeat(MAX_DEVICE_ID_BYTES),
            tls_insecure: false,
            uid_map: (10000..10200)
                .map(|uid| format!("{uid}={uid}"))
                .collect::<Vec<_>>()
                .join(","),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.len() > 4096);
        assert_eq!(
            Config::parse_base64(&BASE64_STANDARD.encode(json)).unwrap(),
            config
        );
    }
}
