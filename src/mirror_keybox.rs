//! R1: fixed GitHub mirror keybox fetcher.
//!
//! The client no longer configures a cloud keybox service. Instead it fetches
//! keyboxes from three fixed community mirror sources, in priority order, and
//! installs the first one that passes the standard `keybox::validate_keybox_xml`
//! checks. The sources are:
//!
//!   1. `raw.githubusercontent.com/Yurii0307/yurikey/main/key` — a single
//!      base64-encoded keybox file.
//!   2. `codeload.github.com/rahmatsobrian/keybox-collection/tar.gz/refs/heads/main`
//!      — a tarball of `.xml` keybox files.
//!   3. `codeload.github.com/shall0e/KeyboxHub/tar.gz/refs/heads/main`
//!      — a tarball of UTF-16LE-encoded `.xml` keybox files.
//!
//! Every download goes through `webui_http::download_https` with a host-anchored
//! allowlist and a redirect budget, exactly like the PIF feed. Tarballs are
//! decompressed with `flate2` and walked in memory; only the files named
//! `*.xml` inside the archive are considered candidates. A candidate is decoded
//! (base64 for the raw source, UTF-16LE for KeyboxHub, plain UTF-8 otherwise),
//! validated, and installed through `keybox::install_keybox_xml`, which keeps
//! the file permission and identity semantics identical to every other install
//! path.

use std::{
    fs,
    io::{BufReader, Read},
    path::Path,
    sync::OnceLock,
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use flate2::bufread::GzDecoder;
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use serde::{Deserialize, Serialize};
use ureq::http::Uri;

use crate::{global, keybox, root_path, webui_activity, webui_http};

/// Raw single-file source (base64-encoded XML).
const YURIKEY_URL: &str = "https://raw.githubusercontent.com/Yurii0307/yurikey/main/key";
/// Tarball source, plain UTF-8 `.xml` members.
const KEYBOX_COLLECTION_URL: &str =
    "https://codeload.github.com/rahmatsobrian/keybox-collection/tar.gz/refs/heads/main";
/// Tarball source, UTF-16LE `.xml` members.
const KEYBOX_HUB_URL: &str = "https://codeload.github.com/shall0e/KeyboxHub/tar.gz/refs/heads/main";

const ALLOWED_HOSTS: [&str; 3] = [
    "raw.githubusercontent.com",
    "codeload.github.com",
    "github.com",
];

/// Upper bound on one tarball download. The two directory sources are small
/// (< 1 MiB and ~4 MiB today); this cap keeps a hostile mirror from feeding the
/// decompressor an unbounded stream.
const MAX_TARBALL_BYTES: usize = 8 * 1024 * 1024;
const MAX_TARBALL_LABEL: &str = "8 MiB";
const MAX_KEYBOX_BYTES: usize = keybox::MAX_KEYBOX_XML_BYTES;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 3;
/// How many `*.xml` members are tried before giving up on a tarball.
const MAX_CANDIDATES_PER_TARBALL: usize = 64;
/// Total entries scanned before giving up (tarballs can carry banners and
/// unrelated files, so this bounds the walk without trusting the layout).
const MAX_TARBALL_ENTRIES: usize = 4096;

/// State file written after an applied (or skipped) install so the WebUI can
/// show the last outcome without re-fetching anything.
const STATE_PATH: &str = root_path!("data/mirror_keybox.toml");
const STATE_VERSION: u32 = 1;

const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 3600);

static WORKER_STARTED: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MirrorState {
    pub version: u32,
    pub last_fetch_unix: i64,
    pub last_sha256: String,
    pub last_source: String,
    pub last_status: String,
    pub last_error: String,
}

impl Default for MirrorState {
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes))
}

/// One candidate source for a keybox payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MirrorSource {
    Yurikey,
    KeyboxCollection,
    KeyboxHub,
}

impl MirrorSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Yurikey => "yurikey",
            Self::KeyboxCollection => "keybox-collection",
            Self::KeyboxHub => "keyboxhub",
        }
    }

    fn url(self) -> &'static str {
        match self {
            Self::Yurikey => YURIKEY_URL,
            Self::KeyboxCollection => KEYBOX_COLLECTION_URL,
            Self::KeyboxHub => KEYBOX_HUB_URL,
        }
    }
}

const SOURCES: [MirrorSource; 3] = [
    MirrorSource::Yurikey,
    MirrorSource::KeyboxCollection,
    MirrorSource::KeyboxHub,
];

fn source_policy(source: MirrorSource) -> webui_http::DownloadPolicy {
    webui_http::DownloadPolicy {
        resource: match source {
            MirrorSource::Yurikey => "mirror keybox (yurikey)",
            MirrorSource::KeyboxCollection => "mirror keybox collection tarball",
            MirrorSource::KeyboxHub => "mirror KeyboxHub tarball",
        },
        redirect_allowlist: "the fixed GitHub mirror hosts",
        max_bytes: match source {
            MirrorSource::Yurikey => MAX_KEYBOX_BYTES,
            MirrorSource::KeyboxCollection | MirrorSource::KeyboxHub => MAX_TARBALL_BYTES,
        },
        max_size_label: match source {
            MirrorSource::Yurikey => "64 KiB",
            MirrorSource::KeyboxCollection | MirrorSource::KeyboxHub => MAX_TARBALL_LABEL,
        },
        max_redirects: MAX_REDIRECTS,
        timeout: REQUEST_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
    }
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
    ALLOWED_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn fetch_bytes(source: MirrorSource) -> Result<Vec<u8>> {
    let url = source.url();
    let uri: Uri = url
        .parse()
        .with_context(|| format!("mirror {} URL is invalid", source.as_str()))?;
    if !is_allowed_uri(&uri) {
        bail!(
            "mirror {} URL is outside the fixed GitHub hosts",
            source.as_str()
        );
    }
    webui_http::download_https(uri, &source_policy(source), is_allowed_uri)
        .with_context(|| format!("failed to download the {} source", source.as_str()))
}

/// Minimal UTF-16LE → UTF-8 conversion (the KeyboxHub members are UTF-16LE with
/// a BOM). Handles surrogate pairs so supplementary-plane code points survive,
/// and turns an odd trailing byte into an error instead of a silent mangling.
fn utf16le_to_utf8(raw: &[u8]) -> Result<String> {
    let mut units = raw.to_vec();
    if units.len() >= 2 && units[0] == 0xFF && units[1] == 0xFE {
        units.drain(0..2);
    }
    if units.len() % 2 != 0 {
        bail!("UTF-16LE payload has an odd byte count");
    }
    let mut out = String::with_capacity(units.len() / 2);
    let (chunks, remainder) = units.as_chunks::<2>();
    if !remainder.is_empty() {
        bail!("UTF-16LE payload has an odd byte count");
    }
    let mut pending: Option<u32> = None;
    for pair in chunks {
        let unit = u16::from_le_bytes(*pair);
        match pending.take() {
            Some(high) => {
                if (0xDC00..=0xDFFF).contains(&unit) {
                    let cp = 0x10000 + ((high - 0xD800) << 10) + (u32::from(unit) - 0xDC00);
                    out.push(char::from_u32(cp).ok_or_else(|| anyhow!("invalid surrogate pair"))?);
                } else {
                    bail!("lone high surrogate in UTF-16LE payload");
                }
            }
            None => match unit {
                0x0000 => {}
                0xD800..=0xDBFF => pending = Some(u32::from(unit)),
                0xDC00..=0xDFFF => bail!("lone low surrogate in UTF-16LE payload"),
                _ => out.push(char::from_u32(u32::from(unit)).unwrap_or('\u{FFFD}')),
            },
        }
    }
    if pending.is_some() {
        bail!("dangling high surrogate in UTF-16LE payload");
    }
    Ok(out)
}

/// Decodes a raw candidate into UTF-8 keybox XML according to the source kind.
fn decode_candidate(source: MirrorSource, raw: &[u8]) -> Result<String> {
    match source {
        MirrorSource::Yurikey => {
            let trimmed = std::str::from_utf8(raw).context("mirror keybox is not valid UTF-8")?;
            let xml = BASE64_STANDARD
                .decode(trimmed.trim())
                .context("mirror keybox base64 payload is invalid")?;
            String::from_utf8(xml).context("decoded mirror keybox is not UTF-8")
        }
        MirrorSource::KeyboxHub => utf16le_to_utf8(raw),
        MirrorSource::KeyboxCollection => {
            String::from_utf8(raw.to_vec()).context("mirror keybox is not valid UTF-8")
        }
    }
}

/// Walks a gzip-compressed POSIX tarball held in memory and yields the raw
/// bytes of every regular file whose name ends in `.xml` (case-insensitive),
/// up to a bounded number of entries and candidates. Each entry body is read
/// and discarded (or kept for `.xml` members) plus its padding to the next
/// 512-byte block boundary.
fn tarball_xml_members(
    tarball: &[u8],
    limit_entries: usize,
    limit_candidates: usize,
) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    let mut stream = BufReader::new(GzDecoder::new(tarball));
    let mut entries = 0usize;
    let mut header = [0u8; 512];
    loop {
        if entries >= limit_entries {
            break;
        }
        entries += 1;
        header.fill(0);
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(_) => break,
        }
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_end = header
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(header.len());
        let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
        let size = parse_tar_size(&header[124..136]);
        let is_dir = name.ends_with('/');
        let is_xml = !is_dir && name.to_ascii_lowercase().ends_with(".xml");
        let padded = (size + 511) & !511;
        let mut body = vec![0u8; size as usize];
        if stream.read_exact(&mut body).is_err() {
            break;
        }
        if is_xml && candidates.len() < limit_candidates {
            candidates.push(body);
        }
        let padding = (padded - size) as usize;
        if padding > 0 {
            let mut skip = vec![0u8; padding];
            if stream.read_exact(&mut skip).is_err() {
                break;
            }
        }
    }
    candidates
}

/// Parses the octal ASCII size field (offset 124, 12 bytes) of a POSIX tar
/// header. Trailing NULs and spaces are ignored; garbage yields 0.
fn parse_tar_size(field: &[u8]) -> u64 {
    let ascii = field
        .iter()
        .map(|byte| char::from(*byte))
        .collect::<String>();
    let ascii = ascii.trim().trim_end_matches('\0').trim();
    if ascii.is_empty() {
        return 0;
    }
    u64::from_str_radix(ascii, 8).unwrap_or(0)
}

/// Fetches one mirror source and returns the first installable keybox XML it
/// yields. A source that contains no valid keybox produces an error message
/// describing why, so the caller can fall through to the next mirror.
fn fetch_from_source(source: MirrorSource) -> Result<String> {
    let raw = fetch_bytes(source)?;
    match source {
        MirrorSource::Yurikey => {
            let xml = decode_candidate(source, &raw)?;
            validate_keybox(xml.as_bytes())?;
            Ok(xml)
        }
        MirrorSource::KeyboxCollection | MirrorSource::KeyboxHub => {
            let members =
                tarball_xml_members(&raw, MAX_TARBALL_ENTRIES, MAX_CANDIDATES_PER_TARBALL);
            if members.is_empty() {
                bail!("{} tarball contains no keybox members", source.as_str());
            }
            for member in &members {
                let Ok(xml) = decode_candidate(source, member) else {
                    continue;
                };
                if validate_keybox(xml.as_bytes()).is_ok() {
                    return Ok(xml);
                }
            }
            bail!(
                "{} tarball contained no valid keybox ({} members checked)",
                source.as_str(),
                members.len()
            );
        }
    }
}

fn validate_keybox(xml: &[u8]) -> Result<()> {
    keybox::validate_keybox_xml(xml)
}

pub(crate) fn installed_keybox_digest() -> Option<String> {
    let contents = fs::read(keybox::KEYBOX_PATH).ok()?;
    Some(sha256_hex(&contents))
}

fn read_state() -> MirrorState {
    let Ok(contents) = fs::read_to_string(STATE_PATH) else {
        return MirrorState::default();
    };
    toml::from_str(&contents).unwrap_or_default()
}

fn write_state(status: &str, digest: Option<&str>, source: Option<&str>, error: Option<&str>) {
    let state = MirrorState {
        version: STATE_VERSION,
        last_fetch_unix: now_unix(),
        last_sha256: digest.unwrap_or_default().to_string(),
        last_source: source.unwrap_or_default().to_string(),
        last_status: status.to_string(),
        last_error: error.unwrap_or_default().to_string(),
    };
    let contents = match toml::to_string_pretty(&state) {
        Ok(contents) => contents,
        Err(error) => {
            log::warn!("failed to serialize the mirror keybox state: {error:#}");
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
        log::warn!("failed to persist the mirror keybox state: {error:#}");
    }
}

/// The installed keybox identity (or the bundled template) as an `ApplyReport`.
#[derive(Debug, Clone, Serialize)]
pub struct MirrorStatus {
    pub installed_sha256: String,
    pub installed_source: String,
    pub last_fetch_unix: i64,
    pub last_sha256: String,
    pub last_source: String,
    pub last_status: String,
    pub last_error: String,
}

impl MirrorStatus {
    fn from_state(state: &MirrorState, installed_sha256: String) -> Self {
        Self {
            installed_sha256,
            installed_source: "mirror".to_string(),
            last_fetch_unix: state.last_fetch_unix,
            last_sha256: state.last_sha256.clone(),
            last_source: state.last_source.clone(),
            last_status: state.last_status.clone(),
            last_error: state.last_error.clone(),
        }
    }
}

/// One-shot probe used by the boot self-check. Reports the last mirror fetch
/// outcome without touching the network or the installed keybox.
pub fn probe() -> Result<MirrorStatus> {
    Ok(MirrorStatus::from_state(
        &read_state(),
        installed_keybox_digest().unwrap_or_default(),
    ))
}

/// Fetches from the fixed mirror sources in priority order and installs the
/// first valid keybox. Returns a summary that distinguishes "applied",
/// "unchanged" and "failed" outcomes.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub ok: bool,
    pub applied: bool,
    pub source: String,
    pub sha256: String,
    pub size: usize,
    pub note: String,
}

/// Explicit "refresh now" action. Always downloads unless the source yields a
/// keybox identical to the installed one.
pub fn refresh_from_mirrors() -> Result<ApplyReport> {
    let installed = installed_keybox_digest();
    for source in SOURCES {
        match fetch_from_source(source) {
            Ok(xml) => {
                let digest = sha256_hex(xml.as_bytes());
                let applied = installed.as_deref() != Some(digest.as_str());
                if applied {
                    keybox::install_keybox_xml(xml.as_bytes())
                        .context("failed to install the mirror keybox")?;
                    let _ = webui_activity::record(
                        "mirror_keybox_applied",
                        &format!("{} {}", source.as_str(), &digest[..12]),
                    );
                }
                let report = ApplyReport {
                    ok: true,
                    applied,
                    source: source.as_str().to_string(),
                    sha256: digest.clone(),
                    size: xml.len(),
                    note: if applied {
                        "mirror keybox installed".to_string()
                    } else {
                        "the installed keybox is already the newest one".to_string()
                    },
                };
                write_state(
                    if applied { "applied" } else { "unchanged" },
                    Some(&digest),
                    Some(source.as_str()),
                    None,
                );
                log::info!(
                    "mirror keybox {}: source={} sha256={}",
                    if applied { "applied" } else { "unchanged" },
                    source.as_str(),
                    &digest[..16]
                );
                return Ok(report);
            }
            Err(error) => {
                log::warn!("mirror keybox source {} failed: {error:#}", source.as_str());
            }
        }
    }
    write_state("failed", None, None, None);
    Err(anyhow!(
        "all mirror keybox sources failed; see the individual source logs above"
    ))
}

/// WebUI status JSON: last outcome plus the installed keybox digest.
pub fn status_json() -> Result<String> {
    let status =
        MirrorStatus::from_state(&read_state(), installed_keybox_digest().unwrap_or_default());
    serde_json::to_string(&MirrorStatus {
        last_source: crate::sanitize_status_text(&status.last_source),
        last_status: crate::sanitize_status_text(&status.last_status),
        last_error: crate::sanitize_status_text(&status.last_error),
        ..status
    })
    .context("failed to serialize the mirror keybox status")
}

/// Status string for the boot self-check ("connected" / "unreachable" semantics
/// are preserved so the module description keeps its meaning).
pub fn boot_verdict() -> (bool, String) {
    let state = read_state();
    match state.last_status.as_str() {
        "applied" | "unchanged" => (true, format!("mirror: {}", state.last_source)),
        _ => (false, format!("mirror unreachable: {}", state.last_error)),
    }
}

/// Low frequency refresh worker: fetches the fixed mirrors every 24 hours after
/// boot. It performs no network work until `sys.boot_completed`.
pub fn spawn_worker() {
    WORKER_STARTED.get_or_init(|| {
        if let Err(error) = std::thread::Builder::new()
            .name("omk-mirror-keybox".to_string())
            .spawn(run_worker)
        {
            log::warn!("failed to start the mirror keybox worker: {error}");
        }
    });
}

fn run_worker() {
    let interval = REFRESH_INTERVAL.as_secs() as i64;
    loop {
        let now = now_unix();
        let last = read_state().last_fetch_unix;
        if global::boot_completed() && (last == 0 || now.saturating_sub(last) >= interval) {
            match refresh_from_mirrors() {
                Ok(report) => log::debug!("automatic mirror keybox check: {report:?}"),
                Err(error) => log::warn!("automatic mirror keybox update failed: {error:#}"),
            }
        }
        let elapsed = now_unix()
            .saturating_sub(read_state().last_fetch_unix)
            .max(0);
        let sleep = if elapsed >= interval {
            60
        } else {
            (interval - elapsed) as u64
        };
        std::thread::sleep(Duration::from_secs(sleep));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16le_with_bom_and_surrogates() {
        // "A🙂Z" encoded as UTF-16LE with BOM.
        let raw: Vec<u8> = vec![0xFF, 0xFE, 0x41, 0x00, 0x3D, 0xD8, 0x42, 0xDE, 0x5A, 0x00];
        assert_eq!(utf16le_to_utf8(&raw).unwrap(), "A\u{1F642}Z");
    }

    #[test]
    fn utf16le_rejects_odd_length_and_lone_surrogates() {
        assert!(utf16le_to_utf8(&[0x41, 0x00, 0x42]).is_err());
        // 0xDC00 as a lone low surrogate, little-endian bytes.
        assert!(utf16le_to_utf8(&[0x00, 0xDC]).is_err());
        // 0xD800 (high surrogate) followed by 'A' (0x0041), little-endian bytes.
        assert!(utf16le_to_utf8(&[0x00, 0xD8, 0x41, 0x00]).is_err());
    }

    #[test]
    fn allowlist_accepts_only_the_fixed_hosts() {
        for url in [
            "https://raw.githubusercontent.com/Yurii0307/yurikey/main/key",
            "https://codeload.github.com/rahmatsobrian/keybox-collection/tar.gz/refs/heads/main",
            "https://github.com/shall0e/KeyboxHub",
        ] {
            assert!(is_allowed_uri(&url.parse().unwrap()), "{url}");
        }
        for url in [
            "http://raw.githubusercontent.com/key",
            "https://evil.example/key",
            "https://raw.githubusercontent.com.evil.com/key",
            "https://raw.githubusercontent.com:8443/key",
        ] {
            assert!(!is_allowed_uri(&url.parse().unwrap()), "{url}");
        }
    }

    #[test]
    fn source_urls_are_static_and_https() {
        for source in SOURCES {
            let url = source.url();
            assert!(url.starts_with("https://"), "{url}");
            assert!(is_allowed_uri(&url.parse().unwrap()), "{url}");
        }
    }

    #[test]
    fn state_defaults_to_never_fetched() {
        let state = MirrorState::default();
        assert_eq!(state.version, STATE_VERSION);
        assert_eq!(state.last_fetch_unix, 0);
        assert_eq!(state.last_status, "");
    }

    /// Builds a minimal POSIX ustar tarball and gzips it in memory.
    fn make_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut tar = Vec::new();
        for (name, body) in entries {
            let mut header = [0u8; 512];
            let name_bytes = name.as_bytes();
            header[..name_bytes.len()].copy_from_slice(name_bytes);
            header[100] = b'0'; // regular file typeflag
            let size = format!("{:011o}", body.len());
            header[124..135].copy_from_slice(size.as_bytes());
            header[136] = b' ';
            header[156..158].copy_from_slice(b"00"); // checksum placeholder
            header[257..263].copy_from_slice(b"ustar\0");
            tar.extend_from_slice(&header);
            tar.extend_from_slice(body);
            let padded = (body.len() + 511) & !511;
            tar.extend(std::iter::repeat_n(0u8, padded - body.len()));
        }
        tar.extend(std::iter::repeat_n(0u8, 1024));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn tarball_walk_returns_only_xml_members() {
        let tar = make_tar_gz(&[
            ("dir/", b""),
            ("dir/banner.png", b"\x89PNG"),
            (
                "dir/Yurikey49.xml",
                b"<?xml version=\"1.0\"?><AndroidAttestation>",
            ),
            ("dir/readme.txt", b"hello"),
        ]);
        let members = tarball_xml_members(&tar, 100, 100);
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0],
            b"<?xml version=\"1.0\"?><AndroidAttestation>".to_vec()
        );
    }

    #[test]
    fn tarball_walk_respects_the_entry_and_candidate_limits() {
        let tar = make_tar_gz(&[("a.xml", b"<a/>"), ("b.xml", b"<b/>"), ("c.xml", b"<c/>")]);
        assert_eq!(tarball_xml_members(&tar, 100, 1).len(), 1);
        assert_eq!(tarball_xml_members(&tar, 1, 100).len(), 0);
        assert_eq!(tarball_xml_members(&tar, 100, 100).len(), 3);
    }

    #[test]
    fn tar_size_parses_octal_with_padding() {
        let mut field = [0u8; 12];
        field[..11].copy_from_slice(format!("{:011o}", 0o100644).as_bytes());
        assert_eq!(parse_tar_size(&field), 0o100644);
        assert_eq!(parse_tar_size(b"       00000"), 0);
    }
}
