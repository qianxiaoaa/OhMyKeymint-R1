//! Optional SOTER relay behind the software TA's native HAL service.
//!
//! This configuration is deliberately separate from the KeyMint/Integrity
//! relay. A disabled relay never touches the network or the local SOTER ledger.
//! An enabled relay that fails must not fall back to the local ledger: that
//! would mix two different ASK/AuthKey identities in the same application slot.

use std::io::Read;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use serde_json::{json, Value};

use crate::dispatch::{self, Outcome, Request};

pub const CONFIG_PATH: &str = "/data/misc/keystore/omk/data/soterta/remote.conf";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
static CLIENT: OnceLock<Mutex<Option<(bool, reqwest::blocking::Client)>>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_CONFIG_PATH: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(crate) fn config_path() -> std::borrow::Cow<'static, Path> {
    #[cfg(test)]
    if let Some(path) = TEST_CONFIG_PATH.with(|slot| slot.borrow().clone()) {
        return std::borrow::Cow::Owned(path);
    }
    std::borrow::Cow::Borrowed(Path::new(CONFIG_PATH))
}

#[cfg(test)]
pub(crate) struct TestConfigPath {
    previous: Option<PathBuf>,
    // A thread-local override must be restored on the thread that installed it.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
pub(crate) fn test_config_path(path: PathBuf) -> TestConfigPath {
    TestConfigPath {
        previous: TEST_CONFIG_PATH.with(|slot| slot.replace(Some(path))),
        _thread: std::marker::PhantomData,
    }
}

#[cfg(test)]
impl Drop for TestConfigPath {
    fn drop(&mut self) {
        TEST_CONFIG_PATH.with(|slot| slot.replace(self.previous.take()));
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub enabled: bool,
    pub url: String,
    pub token: String,
    pub device_id: String,
    pub tls_insecure: bool,
    pub uid_map: String,
}

impl Config {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut config = Self::default();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err("invalid SOTER remote config line".to_string());
            };
            let value = value.trim();
            match key.trim() {
                // `enabled` is the legacy spelling used by older OMK
                // installations.  New WebUI saves use `remote_enabled` so
                // the local software-TA takeover switch can be independent.
                "enabled" | "remote_enabled" => config.enabled = parse_bool(value)?,
                "url" => config.url = value.to_string(),
                "token" => config.token = value.to_string(),
                "device_id" => config.device_id = value.to_string(),
                "tls_insecure" => config.tls_insecure = parse_bool(value)?,
                "uid_map" => config.uid_map = value.to_string(),
                _ => return Err("unknown SOTER remote config key".to_string()),
            }
        }
        if config.enabled {
            let url = reqwest::Url::parse(&config.url).map_err(|_| "invalid SOTER URL")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err("SOTER URL must be HTTP(S) without embedded credentials".to_string());
            }
            if config.token.is_empty() || config.device_id.is_empty() {
                return Err("SOTER token and device_id are required when enabled".to_string());
            }
            if [
                config.token.as_str(),
                config.device_id.as_str(),
                config.uid_map.as_str(),
            ]
            .iter()
            .any(|value| value.contains(['\r', '\n']))
            {
                return Err("SOTER remote config contains a newline".to_string());
            }
        }
        Ok(config)
    }

    pub fn load() -> Result<Self, String> {
        match std::fs::read_to_string(config_path()) {
            Ok(raw) => Self::parse(&raw),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("cannot read SOTER remote config: {error}")),
        }
    }
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err("invalid SOTER remote boolean".to_string()),
    }
}

fn mapped_uid(uid: u32, mapping: &str) -> u32 {
    mapping
        .split([',', ';', ' '])
        .filter_map(|part| part.split_once('=').or_else(|| part.split_once(':')))
        .find_map(|(from, to)| {
            (from.trim().parse::<u32>().ok()? == uid)
                .then(|| to.trim().parse::<u32>().ok())
                .flatten()
        })
        .unwrap_or(uid)
}

fn request_body(config: &Config, tx: u32, request: &Request) -> Result<Value, String> {
    use dispatch::*;
    let op = match tx {
        TX_EXPORT_ASK => "export_ask_public_key",
        TX_EXPORT_AUTH => "export_auth_key_public_key",
        TX_FINISH_SIGN => "finish_sign",
        TX_GENERATE_ASK => "generate_ask_key_pair",
        TX_GENERATE_AUTH => "generate_auth_key_pair",
        TX_GET_DEVICE_ID => "get_device_id",
        TX_HAS_ASK => "has_ask_already",
        TX_HAS_AUTH => "has_auth_key",
        TX_INIT_SIGN => "init_sign",
        TX_REMOVE_ALL_UID_KEY => "remove_all_uid_key",
        TX_REMOVE_AUTH => "remove_auth_key",
        // The ATTK trio is this device's own factory key pair and has no relay
        // operation: the QTI B-side HAL exposes no verified ATTK, and `ffi`
        // answers these three codes from the local ledger before it ever
        // consults the relay. Reaching this point means the caller skipped that
        // split, so refuse instead of inventing a remote ATTK.
        TX_EXPORT_ATTK | TX_GENERATE_ATTK | TX_VERIFY_ATTK => {
            return Err("ATTK transactions are answered locally, not relayed".to_string())
        }
        _ => return Err("unknown SOTER transaction".to_string()),
    };
    let mut body = json!({"op": op, "device_id": config.device_id});
    match request {
        Request::None => {}
        Request::Uid(uid) => body["uid"] = json!(mapped_uid(*uid, &config.uid_map)),
        Request::UidKey { uid, kname } => {
            body["uid"] = json!(mapped_uid(*uid, &config.uid_map));
            body["alias"] = json!(kname);
        }
        Request::InitSign {
            uid,
            kname,
            challenge,
        } => {
            body["uid"] = json!(mapped_uid(*uid, &config.uid_map));
            body["alias"] = json!(kname);
            body["challenge"] = json!(challenge);
        }
        Request::Session(session) => {
            body["session"] = json!(*session as i64);
        }
        Request::Magic(_) => {
            return Err("ATTK transactions are answered locally, not relayed".to_string())
        }
    }
    Ok(body)
}

fn decode_reply(tx: u32, body: &Value) -> Result<Outcome, String> {
    let code = body
        .get("error_code")
        .and_then(Value::as_i64)
        .and_then(|v| i32::try_from(v).ok())
        .ok_or("remote SOTER reply has no valid error_code")?;
    if tx == dispatch::TX_INIT_SIGN {
        let session = match body.get("session") {
            Some(value) => value
                .as_i64()
                .map(|value| value as u64)
                .ok_or("remote SOTER init_sign reply has no valid session")?,
            // Failed init_sign calls from the relay carry only the vendor
            // error code (for example -5 when the AuthKey is absent).  The
            // stock HAL uses session 0 in that case, so do not turn an
            // otherwise valid error reply into a transport failure merely
            // because there is no session field.
            None if code != 0 => 0,
            None => return Err("remote SOTER init_sign reply has no valid session".to_string()),
        };
        return Ok(Outcome::Init { code, session });
    }
    if tx == dispatch::TX_GET_DEVICE_ID {
        let payload = match body.get("data").and_then(Value::as_str) {
            Some(encoded) => base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "remote SOTER reply has invalid base64")?,
            None if code != 0 => Vec::new(),
            None => return Err("remote SOTER success reply is missing data".to_string()),
        };
        let data = device_id_bytes(&payload);
        return Ok(Outcome::Buffer {
            code,
            field: data.len() as i32,
            data,
        });
    }
    if matches!(
        tx,
        dispatch::TX_EXPORT_ASK | dispatch::TX_EXPORT_AUTH | dispatch::TX_FINISH_SIGN
    ) {
        let data = match body.get("data").and_then(Value::as_str) {
            Some(encoded) => base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "remote SOTER reply has invalid base64")?,
            None if code != 0 => Vec::new(),
            None => return Err("remote SOTER success reply is missing data".to_string()),
        };
        let field = body
            .get("length")
            .and_then(Value::as_i64)
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(data.len() as i32);
        return Ok(Outcome::Buffer { code, data, field });
    }
    Ok(Outcome::Code(code))
}

/// The relay answers `get_device_id` the way the Java face spells it: 32 ASCII
/// hex characters with a trailing NUL (captured from the public relay,
/// 2026-09-28: 33 bytes for `090000005171734c42866bea148b21f5`). This TA replaces
/// the HAL underneath that Java layer, and a live HAL answers the transaction
/// with the 16 raw bytes whose hex is that string - the same bytes
/// [`crate::state::TaState::device_id`] hands out locally, and the same hex
/// every blob carries as `cpu_id`. Handing the spelling up instead would let one
/// device report two different ids.
fn device_id_bytes(payload: &[u8]) -> Vec<u8> {
    let kept = payload
        .iter()
        .rev()
        .skip_while(|byte| **byte == 0 || byte.is_ascii_whitespace())
        .count();
    let trimmed = &payload[..kept];
    match std::str::from_utf8(trimmed) {
        Ok(text) if text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
            hex::decode(text).unwrap_or_else(|_| payload.to_vec())
        }
        _ => payload.to_vec(),
    }
}

fn http_client(tls_insecure: bool) -> Result<reqwest::blocking::Client, String> {
    let cache = CLIENT.get_or_init(|| Mutex::new(None));
    let mut slot = cache.lock().unwrap_or_else(|error| error.into_inner());
    if let Some((current, client)) = slot.as_ref() {
        if *current == tls_insecure {
            return Ok(client.clone());
        }
    }
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(20))
        .danger_accept_invalid_certs(tls_insecure)
        .build()
        .map_err(|error| format!("SOTER client setup failed: {error}"))?;
    *slot = Some((tls_insecure, client.clone()));
    Ok(client)
}

pub fn forward(config: &Config, tx: u32, request: &Request) -> Result<Outcome, String> {
    let body = request_body(config, tx, request)?;
    let url = format!("{}/api/soter/", config.url.trim_end_matches('/'));
    let client = http_client(config.tls_insecure)?;
    let response = client
        .post(url)
        .header("X-Relay-Token", &config.token)
        .json(&body)
        .send()
        .map_err(|error| format!("SOTER relay transport failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("SOTER relay returned HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("SOTER relay read failed: {error}"))?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("SOTER relay reply is too large".to_string());
    }
    let reply: Value =
        serde_json::from_slice(&bytes).map_err(|_| "SOTER relay reply is not JSON".to_string())?;
    if reply.get("error").is_some() {
        return Err("SOTER relay could not serve this operation".to_string());
    }
    decode_reply(tx, &reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn config_fixture_is_thread_local_and_restores_the_previous_path() {
        let absent =
            std::env::temp_dir().join(format!("soterta-absent-config-{}", std::process::id()));
        let _outer = test_config_path(absent.clone());
        assert_eq!(Config::load().unwrap(), Config::default());
        let nested = absent.with_extension("nested");
        {
            let _inner = test_config_path(nested.clone());
            assert_eq!(config_path().as_ref(), nested.as_path());
            assert_eq!(
                std::thread::spawn(|| config_path().into_owned())
                    .join()
                    .unwrap(),
                PathBuf::from(CONFIG_PATH)
            );
        }
        assert_eq!(config_path().as_ref(), absent.as_path());
        assert_eq!(Config::load().unwrap(), Config::default());
    }

    #[test]
    fn separate_config_is_off_by_default_and_uid_map_is_explicit() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        // Enabling the relay without explicit identity fails closed instead
        // of resolving baked-in defaults.
        assert!(Config::parse("enabled=true").is_err());
        let defaults = Config::parse(
            "enabled=true\nurl=https://relay.example.test\ntoken=relay-token\ndevice_id=soter-b\n",
        )
        .unwrap();
        assert_eq!(defaults.url, "https://relay.example.test");
        assert_eq!(defaults.device_id, "soter-b");
        assert_eq!(defaults.token, "relay-token");
        for fields in 0..=7 {
            let raw = format!(
                "enabled=true\nurl={}\ndevice_id={}\ntoken={}",
                if fields & 1 != 0 {
                    "https://relay.example.test"
                } else {
                    ""
                },
                if fields & 2 != 0 { "soter-b" } else { "" },
                if fields & 4 != 0 { "relay-token" } else { "" },
            );
            if fields == 7 {
                assert!(Config::parse(&raw).unwrap() == defaults);
            } else {
                assert!(Config::parse(&raw).is_err());
            }
        }
        let custom = Config::parse(
            "enabled=true\nurl=https://custom.example.test\ntoken=custom-token\ndevice_id=custom-b\n",
        )
        .unwrap();
        assert_eq!(custom.url, "https://custom.example.test");
        assert_eq!(custom.device_id, "custom-b");
        assert_eq!(custom.token, "custom-token");
        let cfg = Config::parse(
            "enabled=true\nurl=https://example.test\ntoken=soter-only\ndevice_id=synthetic-b\nuid_map=10001=10002",
        )
        .unwrap();
        assert_eq!(cfg.device_id, "synthetic-b");
        assert_eq!(mapped_uid(10001, &cfg.uid_map), 10002);
        assert_eq!(mapped_uid(20001, &cfg.uid_map), 20001);
        let split = Config::parse(
            "remote_enabled=true\nurl=https://relay.example.test\ntoken=relay-token\ndevice_id=soter-b\n",
        )
        .unwrap();
        assert!(split.enabled);
        assert_eq!(split.url, "https://relay.example.test");
        let body = request_body(
            &cfg,
            dispatch::TX_INIT_SIGN,
            &Request::InitSign {
                uid: 10001,
                kname: "AuthKey".into(),
                challenge: "nonce".into(),
            },
        )
        .unwrap();
        assert_eq!(body["uid"], 10002);
        assert_eq!(body["device_id"], "synthetic-b");
        assert_eq!(body["challenge"], "nonce");
    }

    #[test]
    fn remote_reply_preserves_session_and_negative_vendor_status() {
        assert_eq!(
            decode_reply(
                dispatch::TX_INIT_SIGN,
                &json!({"error_code": 0, "session": 42}),
            )
            .unwrap(),
            Outcome::Init {
                code: 0,
                session: 42
            }
        );
        assert_eq!(
            decode_reply(
                dispatch::TX_FINISH_SIGN,
                &json!({"error_code": -26, "data": "", "length": 0}),
            )
            .unwrap(),
            Outcome::Buffer {
                code: -26,
                data: Vec::new(),
                field: 0,
            }
        );
        assert_eq!(
            decode_reply(dispatch::TX_INIT_SIGN, &json!({"error_code": -5}),).unwrap(),
            Outcome::Init {
                code: -5,
                session: 0,
            }
        );
        assert!(decode_reply(dispatch::TX_INIT_SIGN, &json!({"error_code": 0})).is_err());
        // The ATTK trio is answered from the local ledger (ffi never forwards
        // it), so the relay mapping must not invent a remote ATTK operation.
        assert!(
            request_body(&Config::default(), dispatch::TX_EXPORT_ATTK, &Request::None).is_err()
        );
        assert!(
            request_body(&Config::default(), dispatch::TX_VERIFY_ATTK, &Request::None).is_err()
        );
        let signed = decode_reply(
            dispatch::TX_INIT_SIGN,
            &json!({"error_code": 0, "session": -2}),
        )
        .unwrap();
        assert_eq!(
            signed,
            Outcome::Init {
                code: 0,
                session: (-2i64) as u64
            }
        );
    }

    #[test]
    fn the_relayed_device_id_is_handed_up_as_the_raw_hal_bytes() {
        // The relay spells the id the way the Java face does: 32 hex characters
        // plus a NUL, base64-wrapped (public relay capture, 2026-09-28).
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(b"090000005171734c42866bea148b21f5\0");
        assert_eq!(
            decode_reply(
                dispatch::TX_GET_DEVICE_ID,
                &json!({
                    "error_code": 0,
                    "data": encoded,
                    "length": 33,
                    "text": "090000005171734c42866bea148b21f5"
                }),
            )
            .unwrap(),
            Outcome::Buffer {
                code: 0,
                data: hex::decode("090000005171734c42866bea148b21f5").unwrap(),
                field: 16,
            }
        );
        // A reply that already carries raw bytes is passed through untouched.
        let raw = base64::engine::general_purpose::STANDARD.encode([0x0au8, 0xff, 0x00]);
        assert_eq!(
            decode_reply(
                dispatch::TX_GET_DEVICE_ID,
                &json!({"error_code": 0, "data": raw, "length": 3}),
            )
            .unwrap(),
            Outcome::Buffer {
                code: 0,
                data: vec![0x0a, 0xff, 0x00],
                field: 3,
            }
        );
    }

    #[test]
    fn forwards_to_the_soter_server_with_its_own_token_and_device() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let count = socket.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&request[..end]);
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|v| v.parse::<usize>().ok())
                        })
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let answer = br#"{"op":"init_sign","error_code":0,"session":42}"#;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        answer.len()
                    )
                    .as_bytes(),
                )
                .unwrap();
            socket.write_all(answer).unwrap();
            String::from_utf8(request).unwrap()
        });
        let config = Config {
            enabled: true,
            url: format!("http://127.0.0.1:{port}"),
            token: "soter-token".into(),
            device_id: "soter-b".into(),
            uid_map: "10001=10002".into(),
            ..Config::default()
        };
        let outcome = forward(
            &config,
            dispatch::TX_INIT_SIGN,
            &Request::InitSign {
                uid: 10001,
                kname: "AuthKey".into(),
                challenge: "nonce".into(),
            },
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome::Init {
                code: 0,
                session: 42
            }
        );
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /api/soter/ HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("x-relay-token: soter-token"));
        assert!(request.contains("\"device_id\":\"soter-b\""));
        assert!(request.contains("\"uid\":10002"));
    }
}
