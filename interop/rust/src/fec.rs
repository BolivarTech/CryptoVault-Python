// Author: Julian Bolivar
// Version: 0.2.0
// Date: 2026-10-16
//! Reference values for the FEC codecs of the `cryptovault` crate.
//!
//! Subcommand `fec-fixtures` prints them as one JSON document, which the Python
//! test suite reads from `tests/fixtures/rust_fec.json`.

use std::process::ExitCode;

use cryptovault::fec::{ErrorCorrection, ReedSolomonCodec};
use cryptovault::{
    RS_BLOCK, RS_DATA, RS_INTERLEAVE_MAX, RS_PARITY, TERMINATION_OVERHEAD, VITERBI_CHUNK,
};
use serde_json::{json, Value};

/// Returns `len` bytes of a fixed pseudo-random sequence seeded by `seed`.
fn pattern(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

/// RS(255, 223) codewords for inputs from empty to three codewords; read by
/// `test_rs_encode_matches_the_crate_codewords` (key `rs_encode`).
fn rs_encode() -> Vec<Value> {
    [0usize, 1, 33, 222, 223, 224, 600]
        .iter()
        .map(|&len| {
            let data = pattern(len as u32, len);
            json!({
                "data": hex::encode(&data),
                "encoded": hex::encode(ReedSolomonCodec.encode(&data)),
            })
        })
        .collect()
}

/// Prints the full FEC fixture document.
pub fn fec_fixtures() -> ExitCode {
    let document = json!({
        "crate": "cryptovault 0.3.0",
        "constants": {
            "RS_DATA": RS_DATA, "RS_PARITY": RS_PARITY, "RS_BLOCK": RS_BLOCK,
            "RS_INTERLEAVE_MAX": RS_INTERLEAVE_MAX, "VITERBI_CHUNK": VITERBI_CHUNK,
            "TERMINATION_OVERHEAD": TERMINATION_OVERHEAD,
        },
        "rs_encode": rs_encode(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("serializable")
    );
    ExitCode::SUCCESS
}
