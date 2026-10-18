//! WebUI wallpaper storage.
//!
//! The page background is a module asset, so a user picture has to live inside the webroot that
//! the manager serves. Two copies are kept: a durable one under the module state directory, which
//! survives a module update, and the served one under `webroot/assets/wallpaper`. The served copy
//! always uses a name this module picks, never a name that comes from the request.

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use kmr_common::runtime::fs::atomic_replace_preserving_metadata;
use log::info;
use serde::Serialize;

use crate::root_path;

const MODULE_DIR: &str = "/data/adb/modules/oh_my_keymint";
const STATE_DIR: &str = root_path!("data");
const STAGE_DIR: &str = root_path!("data/wallpaper-stage");
const SERVED_SUBDIR: &str = "assets/wallpaper";
const DEFAULT_ASSET: &str = "assets/wallpaper/default.jpg";
const CUSTOM_PREFIX: &str = "custom.";
const MAX_WALLPAPER_BYTES: u64 = 10 * 1024 * 1024;
// One command argument has to stay under the kernel's per-argument limit, so an upload travels as
// small base64 chunks instead of as a single multi-megabyte argv entry.
const MAX_APPEND_BYTES: usize = 64 * 1024;
const STAGE_TTL_SECONDS: u64 = 30 * 60;
const STORAGE_ROOT: &str = "/storage/emulated/0";

#[derive(Serialize)]
pub struct WallpaperState {
    pub custom: bool,
    pub url: String,
    pub bytes: u64,
    pub updated_at: u64,
    pub max_bytes: u64,
}

#[derive(Clone, Copy)]
struct ImageFormat {
    extension: &'static str,
}

fn webroot_dir() -> Result<PathBuf> {
    let packaged = Path::new(MODULE_DIR).join("webroot");
    if packaged.is_dir() {
        return Ok(packaged);
    }
    // A hot-updated helper still has to reach the installed webroot, so walk up from the binary
    // until a module.prop is visible and take the webroot beside it.
    let executable = std::env::current_exe().context("failed to resolve the helper path")?;
    for ancestor in executable.ancestors().skip(1) {
        if ancestor.join("module.prop").is_file() {
            return Ok(ancestor.join("webroot"));
        }
    }
    bail!("the module webroot directory was not found")
}

fn served_dir() -> Result<PathBuf> {
    Ok(webroot_dir()?.join(SERVED_SUBDIR))
}

fn durable_path() -> PathBuf {
    Path::new(STATE_DIR).join("wallpaper.bin")
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to protect {}", path.display()))?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 {
        bail!("{} is not a root-owned directory", path.display());
    }
    Ok(())
}

fn detect_image(header: &[u8]) -> Option<ImageFormat> {
    let format = |extension| Some(ImageFormat { extension });
    if header.starts_with(&[0xff, 0xd8, 0xff]) {
        return format("jpg");
    }
    if header.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return format("png");
    }
    if header.len() >= 12 && header.starts_with(b"RIFF") && header[8..12] == *b"WEBP" {
        return format("webp");
    }
    None
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .context("failed to open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("failed to read random bytes")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn is_stage_token(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn stage_path(token: &str) -> Result<PathBuf> {
    if !is_stage_token(token) {
        bail!("the wallpaper upload token is not valid")
    }
    Ok(Path::new(STAGE_DIR).join(format!("{token}.bin")))
}

fn remove_stale_stages() {
    let Ok(entries) = fs::read_dir(STAGE_DIR) else {
        return;
    };
    let Some(now) = unix_now() else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|since| since.as_secs())
            .unwrap_or(now);
        if now.saturating_sub(modified) > STAGE_TTL_SECONDS {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|since| since.as_secs())
}

/// Lists the served custom wallpapers. Only this module's own names are considered, so a foreign
/// file that appears in the directory can never be selected or deleted by name guessing.
fn custom_assets(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut assets: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(CUSTOM_PREFIX))
        })
        .filter(|path| {
            path.symlink_metadata()
                .is_ok_and(|metadata| metadata.is_file())
        })
        .collect();
    assets.sort();
    assets
}

fn install_bytes(bytes: &[u8], source: &str) -> Result<WallpaperState> {
    if bytes.is_empty() {
        bail!("the wallpaper is empty");
    }
    if bytes.len() as u64 > MAX_WALLPAPER_BYTES {
        bail!(
            "the wallpaper exceeds the {} byte limit",
            MAX_WALLPAPER_BYTES
        );
    }
    let Some(format) = detect_image(&bytes[..bytes.len().min(16)]) else {
        bail!("the wallpaper is not a JPEG, PNG or WebP image");
    };

    let dir = served_dir()?;
    fs::create_dir_all(&dir).context("failed to create the wallpaper directory")?;
    let target = dir.join(format!("{CUSTOM_PREFIX}{}", format.extension));

    ensure_private_dir(Path::new(STATE_DIR))?;
    let durable = durable_path();
    fs::write(&durable, bytes).with_context(|| format!("failed to write {}", durable.display()))?;
    fs::set_permissions(&durable, fs::Permissions::from_mode(0o600))?;

    atomic_replace_preserving_metadata(&target, bytes, 0o644, 0, 0)
        .with_context(|| format!("failed to publish {}", target.display()))?;
    for stale in custom_assets(&dir) {
        if stale != target {
            let _ = fs::remove_file(&stale);
        }
    }

    info!(
        "wallpaper installed from {source}: {} bytes as {}",
        bytes.len(),
        target.display()
    );
    Ok(state(Some(&target)))
}

fn state(custom: Option<&Path>) -> WallpaperState {
    let usable = custom.filter(|path| path.is_file());
    let (url, bytes, updated_at) = match usable {
        Some(path) => {
            let metadata = fs::metadata(path).ok();
            let bytes = metadata.as_ref().map(fs::Metadata::len).unwrap_or_default();
            let updated_at = metadata
                .as_ref()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|since| since.as_secs())
                .unwrap_or_default();
            (
                format!(
                    "{SERVED_SUBDIR}/{}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                bytes,
                updated_at,
            )
        }
        None => (DEFAULT_ASSET.to_string(), 0, 0),
    };
    WallpaperState {
        custom: usable.is_some(),
        url,
        bytes,
        updated_at,
        max_bytes: MAX_WALLPAPER_BYTES,
    }
}

pub fn get_state() -> Result<String> {
    let dir = served_dir()?;
    let payload = state(custom_assets(&dir).first().map(PathBuf::as_path));
    serde_json::to_string(&payload).context("failed to serialize the wallpaper state")
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if metadata.len() > limit {
        bail!("the wallpaper exceeds the {limit} byte limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(bytes)
}

/// Validates a shared-storage path chosen by the file browser and copies it without routing the
/// bytes through the command channel.
pub fn install_from_storage(path: &str) -> Result<String> {
    let source = validate_storage_path(path)?;
    let bytes = read_bounded(&source, MAX_WALLPAPER_BYTES)?;
    let payload = install_bytes(&bytes, "storage")?;
    serde_json::to_string(&payload).context("failed to serialize the wallpaper state")
}

fn validate_storage_path(raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 || trimmed.contains('\0') {
        bail!("the wallpaper path is not valid");
    }
    let Some(relative) = trimmed.strip_prefix(&format!("{STORAGE_ROOT}/")) else {
        bail!("the wallpaper must come from shared storage");
    };
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("the wallpaper path is not valid");
    }
    Ok(PathBuf::from(trimmed))
}

pub fn begin_stage() -> Result<String> {
    ensure_private_dir(Path::new(STATE_DIR))?;
    ensure_private_dir(Path::new(STAGE_DIR))?;
    remove_stale_stages();
    let token = random_token()?;
    let path = stage_path(&token)?;
    File::create(&path)
        .with_context(|| format!("failed to create {}", path.display()))?
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(token)
}

pub fn append_stage(token: &str, payload: &str) -> Result<()> {
    let path = stage_path(token)?;
    let decoded = BASE64_STANDARD
        .decode(payload)
        .context("the wallpaper chunk is not valid base64")?;
    if decoded.len() > MAX_APPEND_BYTES {
        bail!("the wallpaper chunk is too large");
    }

    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.uid() != 0 {
        bail!("the wallpaper upload session is not usable");
    }
    if metadata.len() as usize + decoded.len() > MAX_WALLPAPER_BYTES as usize {
        let _ = fs::remove_file(&path);
        bail!(
            "the wallpaper exceeds the {} byte limit",
            MAX_WALLPAPER_BYTES
        );
    }

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(&decoded)?;
    file.flush()?;
    Ok(())
}

pub fn install_staged(token: &str) -> Result<String> {
    let path = stage_path(token)?;
    let result = (|| -> Result<String> {
        let bytes = read_bounded(&path, MAX_WALLPAPER_BYTES)?;
        let payload = install_bytes(&bytes, "upload")?;
        serde_json::to_string(&payload).context("failed to serialize the wallpaper state")
    })();
    let _ = fs::remove_file(&path);
    result
}

pub fn reset() -> Result<String> {
    let dir = served_dir()?;
    for stale in custom_assets(&dir) {
        fs::remove_file(&stale).with_context(|| format!("failed to remove {}", stale.display()))?;
    }
    let durable = durable_path();
    if durable.is_file() {
        fs::remove_file(&durable)
            .with_context(|| format!("failed to remove {}", durable.display()))?;
    }
    info!("wallpaper reset to the packaged default");
    serde_json::to_string(&state(None)).context("failed to serialize the wallpaper state")
}

/// Copies the durable wallpaper back into the webroot, used after a module update replaces the
/// served assets. Returns Ok(false) when there is nothing to restore.
pub fn restore_from_durable() -> Result<bool> {
    let durable = durable_path();
    if !durable.is_file() {
        return Ok(false);
    }
    let bytes = read_bounded(&durable, MAX_WALLPAPER_BYTES)?;
    install_bytes(&bytes, "restore")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JPEG: &[u8] = &[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];
    const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00];
    const WEBP: &[u8] = b"RIFF\x00\x00\x00\x00WEBPVP8 ";

    #[test]
    fn image_detection_uses_the_header_not_the_name() {
        assert_eq!(
            detect_image(JPEG).map(|format| format.extension),
            Some("jpg")
        );
        assert_eq!(
            detect_image(PNG).map(|format| format.extension),
            Some("png")
        );
        assert_eq!(
            detect_image(WEBP).map(|format| format.extension),
            Some("webp")
        );
        assert!(detect_image(b"GIF89a").is_none());
        assert!(detect_image(b"<?xml ").is_none());
        assert!(detect_image(b"RIFF").is_none());
        assert!(detect_image(b"").is_none());
    }

    #[test]
    fn storage_paths_stay_inside_shared_storage() {
        assert_eq!(
            validate_storage_path("/storage/emulated/0/Download/photo.jpg").unwrap(),
            PathBuf::from("/storage/emulated/0/Download/photo.jpg")
        );
        for rejected in [
            "",
            "   ",
            "/storage/emulated/0",
            "/data/local/tmp/photo.jpg",
            "/storage/emulated/0/../adb/photo.jpg",
            "/storage/emulated/0//photo.jpg",
            "/storage/emulated/0/./photo.jpg",
            "/storage/emulated/0x/photo.jpg",
            "/storage/emulated/0/photo.jpg\0.png",
        ] {
            assert!(
                validate_storage_path(rejected).is_err(),
                "must reject {rejected:?}"
            );
        }
    }

    #[test]
    fn stage_tokens_are_fixed_length_hex() {
        assert!(is_stage_token(&"a1b2".repeat(8)));
        for rejected in [
            "",
            "deadbeef",
            &"z".repeat(32),
            &"a".repeat(31),
            &"a".repeat(33),
        ] {
            assert!(!is_stage_token(rejected), "must reject {rejected:?}");
        }
        assert!(stage_path("../escape").is_err());
        assert!(stage_path(&"f".repeat(32)).is_ok());
    }

    #[test]
    fn state_urls_are_relative_to_the_webroot() {
        let default = state(None);
        assert!(!default.custom);
        assert_eq!(default.url, DEFAULT_ASSET);
        assert_eq!(default.max_bytes, MAX_WALLPAPER_BYTES);

        let directory = tempfile::tempdir().unwrap();
        let served = directory.path().join("custom.jpg");
        fs::write(&served, JPEG).unwrap();
        let custom = state(Some(&served));
        assert!(custom.custom);
        assert_eq!(custom.url, "assets/wallpaper/custom.jpg");
        assert_eq!(custom.bytes, JPEG.len() as u64);

        let removed = state(Some(&directory.path().join("custom.png")));
        assert!(!removed.custom);
        assert_eq!(removed.url, DEFAULT_ASSET);
    }

    #[test]
    fn custom_assets_ignores_foreign_names() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("default.jpg"), JPEG).unwrap();
        fs::write(directory.path().join("custom.png"), PNG).unwrap();
        fs::write(directory.path().join("custom.jpg"), JPEG).unwrap();
        fs::create_dir(directory.path().join("custom.d")).unwrap();

        let assets = custom_assets(directory.path());
        let names: Vec<String> = assets
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["custom.jpg".to_string(), "custom.png".to_string()]
        );
    }
}
