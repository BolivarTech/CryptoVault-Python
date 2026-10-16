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
use serde_json::json;

/// Prints the full fixture document.
fn fixtures() -> ExitCode {
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
