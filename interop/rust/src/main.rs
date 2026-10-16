// Author: Julian Bolivar
// Version: 0.1.0
// Date: 2026-10-16
//! Interoperability tool that pins CryptoVault-Python to the `cryptovault` crate.
//!
//! Subcommand `fixtures` prints a JSON document of reference values produced by
//! the crate itself over a vault built with `NoFec`. The Python test suite reads
//! it from `tests/fixtures/rust_nofec.json`.

use std::process::ExitCode;

use cryptovault::{
    ARGON2_M_KIB, ARGON2_P, ARGON2_T, BLOB_VERSION, HEADER_LEN, KEY_LEN, MAX_B64_LEN,
    MAX_BLOB_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, RECOMMENDED_MAX_PAYLOAD, SALT_LEN, TAG_LEN,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cryptovault::cipher::Aes256GcmSivCipher;
use cryptovault::kdf::Argon2Kdf;
use cryptovault::{CryptoVault, NoFec, Result};
use serde_json::{json, Value};

/// Adversarial inputs paired with the crate's answers, one group per Python
/// test in `tests/test_vault.py` (fixture key `adversarial`).
fn adversarial(vault: &CryptoVault) -> Vec<Value> {
    let key = counting(0x00, KEY_LEN);
    let base = vault.encrypt_with_key(&key, "hi").expect("encrypt");
    let decoded = STANDARD.decode(&base).expect("own blob decodes");
    let mut cases = Vec::new();
    for i in 0..decoded.len() {
        for bit in 0..8 {
            let mut bytes = decoded.clone();
            bytes[i] ^= 1 << bit;
            let label = format!("flip byte {i} bit {bit}");
            let blob = STANDARD.encode(bytes);
            cases.push(decrypt_case(vault, "bit flip", &label, &key, &blob));
        }
    }
    let short = STANDARD.encode(&decoded[..decoded.len() - 1]);
    let encodings = [
        ("empty string", String::new()),
        ("padding removed", base.trim_end_matches('=').to_string()),
        ("extra padding", format!("{base}=")),
        ("padding only", "====".to_string()),
        ("trailing newline", format!("{base}\n")),
        ("leading space", format!(" {base}")),
        ("inner space", format!("{} {}", &base[..8], &base[8..])),
        ("url-safe dash", format!("-{}", &base[1..])),
        ("url-safe underscore", format!("_{}", &base[1..])),
        ("non-ascii character", format!("{base}\u{e9}")),
        ("length not a multiple of four", base[..base.len() - 2].to_string()),
        ("non-canonical trailing bits, one pad", non_canonical(&base)),
        ("non-canonical trailing bits, two pads", non_canonical(&short)),
        ("canonical two pads", short.clone()),
    ];
    for (label, blob) in &encodings {
        cases.push(decrypt_case(vault, "encoding", label, &key, blob));
    }
    // Group "key", read by test_master_key_must_be_exactly_32_bytes_as_in_the_crate.
    let mut long_key = key.clone();
    long_key.push(0);
    let keys = [
        ("wrong key", counting(0x80, KEY_LEN)),
        ("key of 31 bytes", key[..31].to_vec()),
        ("key of 33 bytes", long_key),
        ("empty key", Vec::new()),
    ];
    for (label, other) in &keys {
        cases.push(decrypt_case(vault, "key", label, other, &base));
    }
    cases
}

/// Replaces the last base64 character before the padding with its neighbour in
/// the alphabet, which changes only the trailing bits that carry no data.
fn non_canonical(b64: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut chars = b64.as_bytes().to_vec();
    let last = chars.iter().rposition(|c| *c != b'=').expect("non-empty base64");
    let index = ALPHABET.iter().position(|c| *c == chars[last]).expect("alphabet char");
    chars[last] = ALPHABET[index ^ 1];
    String::from_utf8(chars).expect("ASCII")
}

/// Records the crate's answer to `decrypt_with_key(key, blob)` for one case of
/// an adversarial `group`.
fn decrypt_case(vault: &CryptoVault, group: &str, label: &str, key: &[u8], blob: &str) -> Value {
    json!({
        "group": group,
        "label": label,
        "op": "decrypt",
        "key": hex::encode(key),
        "blob": blob,
        "expect": outcome(vault.decrypt_with_key(key, blob), |s| json!(s.as_str())),
    })
}

/// Builds the AEAD-only vault every fixture is produced with.
fn vault() -> CryptoVault {
    CryptoVault::new(Box::new(Argon2Kdf), Box::new(Aes256GcmSivCipher), Box::new(NoFec))
}

/// Returns `len` bytes counting up from `start`, a readable deterministic value.
fn counting(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

/// Maps a crate result to `{"ok": <value>}` or `{"error": "<Display>"}`.
fn outcome<T>(result: Result<T>, render: impl Fn(T) -> Value) -> Value {
    match result {
        Ok(value) => json!({ "ok": render(value) }),
        Err(error) => json!({ "error": error.to_string() }),
    }
}

/// `derive_key` outputs and errors for a fixed set of passwords and salts.
fn derive(vault: &CryptoVault) -> Vec<Value> {
    let inputs = [
        ("master-passphrase", vec![0u8; SALT_LEN]),
        ("correct horse battery staple", counting(0x10, SALT_LEN)),
        ("\u{f1}and\u{fa}-\u{1f510}", counting(0xf0, SALT_LEN)),
        ("", vec![0u8; SALT_LEN]),
        ("pw", vec![0u8; 15]),
        ("pw", vec![0u8; 17]),
        ("pw", Vec::new()),
    ];
    inputs
        .iter()
        .map(|(password, salt)| {
            json!({
                "password": password,
                "salt": hex::encode(salt),
                "expect": outcome(vault.derive_key(password, salt), |k| json!(hex::encode(&*k))),
            })
        })
        .collect()
}

/// AEAD sub-keys the crate's public `expand_aead_key` derives from master keys;
/// read by `test_aead_subkey_matches_rfc_5869_and_the_crate` (fixture key `hkdf`).
fn hkdf() -> Vec<Value> {
    [counting(0x00, KEY_LEN), vec![0xff; KEY_LEN], counting(0x60, KEY_LEN)]
        .iter()
        .map(|master| {
            let aead_key = cryptovault::kdf::expand_aead_key(master).expect("expand");
            json!({ "master": hex::encode(master), "aead_key": hex::encode(&*aead_key) })
        })
        .collect()
}

/// Data-path blobs the crate encrypts, from empty to `RECOMMENDED_MAX_PAYLOAD`;
/// read by `test_every_crate_data_blob_opens_to_its_plaintext` (key `data`).
fn data(vault: &CryptoVault) -> Vec<Value> {
    let key = counting(0x00, KEY_LEN);
    let plaintexts = [
        String::new(),
        "a".to_string(),
        "sk-secret".to_string(),
        "\u{f1}and\u{fa} \u{1f510} \u{4e2d}\u{6587}".to_string(),
        "x".repeat(1000),
        "0123456789abcdef".repeat(RECOMMENDED_MAX_PAYLOAD / 16),
    ];
    plaintexts
        .iter()
        .map(|pt| {
            json!({
                "key": hex::encode(&key),
                "plaintext": pt,
                "blob": vault.encrypt_with_key(&key, pt).expect("encrypt"),
            })
        })
        .collect()
}

/// Prints the full fixture document.
fn fixtures() -> ExitCode {
    let vault = vault();
    let document = json!({
        "crate": "cryptovault 0.3.0",
        "fec": "NoFec",
        "constants": {
            "KEY_LEN": KEY_LEN, "SALT_LEN": SALT_LEN, "NONCE_LEN": NONCE_LEN, "TAG_LEN": TAG_LEN,
            "HEADER_LEN": HEADER_LEN, "BLOB_VERSION": BLOB_VERSION,
            "MAX_PLAINTEXT_LEN": MAX_PLAINTEXT_LEN,
            "RECOMMENDED_MAX_PAYLOAD": RECOMMENDED_MAX_PAYLOAD,
            "MAX_BLOB_LEN": MAX_BLOB_LEN, "MAX_B64_LEN": MAX_B64_LEN,
            "ARGON2_M_KIB": ARGON2_M_KIB, "ARGON2_T": ARGON2_T, "ARGON2_P": ARGON2_P,
        },
        "derive": derive(&vault),
        "hkdf": hkdf(),
        "data": data(&vault),
        "adversarial": adversarial(&vault),
    });
    println!("{}", serde_json::to_string_pretty(&document).expect("serializable"));
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("fixtures") => fixtures(),
        _ => {
            eprintln!("usage: cryptovault-interop fixtures");
            ExitCode::from(2)
        }
    }
}
