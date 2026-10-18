//! Soter blob codec: `[u32 le jsonLen][json][rsa-pss signature]`.
//!
//! The shape was taken from the vendor HAL library pulled off the OnePlus 13
//! (`vendor.qti.hardware.soter-V1-ndk.so`, method `SoterBufferReturn::writeToParcel`)
//! and from captures of a working device: JSON key order is
//! `pub_key, cpu_id, counter, uid`, and the tail is RSA-PSS/SHA-256 with a
//! 20-byte salt over the exact JSON bytes.

use rsa::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::{Pss, RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Salt length used by the real device on every stage of the chain.
pub const PSS_SALT_LEN: usize = 20;

/// Signature size for the RSA-2048 keys the TA uses.
pub const SIGNATURE_LEN: usize = 256;

/// Values the stock TA reports for its own environment. They are constants here
/// because the local TA has no secure world to ask.
pub const TEE_NAME: &str = "QSEE";
pub const TEE_VERSION: &str = "5";
pub const FINGERPRINT_NAME: &str = "fingerprint";
pub const FINGERPRINT_VERSION: &str = "1";

#[derive(Serialize)]
struct KeyJson<'a> {
    pub_key: &'a str,
    cpu_id: &'a str,
    counter: u64,
    uid: String,
}

#[derive(Serialize)]
struct SignedJson<'a> {
    raw: &'a str,
    fid: &'a str,
    counter: u64,
    tee_n: &'a str,
    tee_v: &'a str,
    fp_n: &'a str,
    fp_v: &'a str,
    cpu_id: &'a str,
    uid: String,
}

/// JSON body of an ASK or AuthKey blob. `uid` is a string on the wire, the
/// counter is a number, and there is no certificate array (the Qualcomm backend
/// never returns one).
pub fn key_json(public_pem: &str, cpu_id: &str, counter: u64, uid: u32) -> Vec<u8> {
    let json = KeyJson {
        pub_key: public_pem,
        cpu_id,
        counter,
        uid: uid.to_string(),
    };
    serde_json::to_vec(&json).expect("key JSON is serializable")
}

/// JSON body of a `finishSign` result.
pub fn result_json(challenge: &str, fid: &str, counter: u64, cpu_id: &str, uid: u32) -> Vec<u8> {
    let json = SignedJson {
        raw: challenge,
        fid,
        counter,
        tee_n: TEE_NAME,
        tee_v: TEE_VERSION,
        fp_n: FINGERPRINT_NAME,
        fp_v: FINGERPRINT_VERSION,
        cpu_id,
        uid: uid.to_string(),
    };
    serde_json::to_vec(&json).expect("result JSON is serializable")
}

/// Wrap a JSON body and its signature into the blob the HAL hands out.
pub fn encode(json: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + json.len() + signature.len());
    blob.extend_from_slice(&(json.len() as u32).to_le_bytes());
    blob.extend_from_slice(json);
    blob.extend_from_slice(signature);
    blob
}

/// Split a blob back into its JSON body and signature.
pub fn parse(blob: &[u8]) -> Option<(&[u8], &[u8])> {
    if blob.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(blob[..4].try_into().ok()?) as usize;
    let json = blob.get(4..4 + len)?;
    let signature = blob.get(4 + len..)?;
    if signature.is_empty() {
        return None;
    }
    Some((json, signature))
}

/// RSA-PSS/SHA-256 with the device's 20-byte salt, over the JSON bytes.
pub fn sign(key: &RsaPrivateKey, data: &[u8]) -> Option<Vec<u8>> {
    let digest = Sha256::digest(data);
    let mut rng = rand_core::OsRng;
    key.sign_with_rng(
        &mut rng,
        Pss::new_with_salt::<Sha256>(PSS_SALT_LEN),
        &digest,
    )
    .ok()
}

/// Verify a blob tail produced by [`sign`].
pub fn verify(key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
    let digest = Sha256::digest(data);
    key.verify(
        Pss::new_with_salt::<Sha256>(PSS_SALT_LEN),
        &digest,
        signature,
    )
    .is_ok()
}

/// SPKI/PEM encoding of a public key, the spelling the blobs use.
pub fn public_key_pem(key: &RsaPublicKey) -> Option<String> {
    key.to_public_key_pem(LineEnding::LF).ok()
}

/// Parse an SPKI/PEM public key out of a blob's `pub_key` field.
pub fn public_key_from_pem(pem: &str) -> Option<RsaPublicKey> {
    RsaPublicKey::from_public_key_pem(pem).ok()
}
