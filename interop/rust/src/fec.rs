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

/// Maps a crate result to `{"ok": <hex>}` or `{"error": "<Display>"}`.
fn outcome(result: cryptovault::Result<Vec<u8>>) -> Value {
    match result {
        Ok(bytes) => json!({ "ok": hex::encode(bytes) }),
        Err(error) => json!({ "error": error.to_string() }),
    }
}

/// Records the crate's answer to `ReedSolomonCodec::decode(encoded, pre_len)`.
fn rs_decode_case(label: &str, encoded: &[u8], pre_len: usize) -> Value {
    json!({
        "label": label,
        "encoded": hex::encode(encoded),
        "pre_len": pre_len,
        "expect": outcome(ReedSolomonCodec.decode(encoded, pre_len)),
    })
}

/// Reed-Solomon decode outcomes: clean streams, 1 to 24 symbol errors in one
/// codeword, random blocks, and malformed lengths; read by
/// `test_rs_decode_corrects_and_fails_exactly_as_the_crate` (key `rs_decode`).
fn rs_decode() -> Vec<Value> {
    let mut cases = Vec::new();
    let data = pattern(7, 600);
    let clean = ReedSolomonCodec.encode(&data);
    cases.push(rs_decode_case("clean three codewords", &clean, data.len()));
    for errors in 1..=24usize {
        for trial in 0..4u32 {
            let mut bytes = clean.clone();
            let noise = pattern(1000 * errors as u32 + trial, 2 * errors);
            let mut used = Vec::new();
            for e in 0..errors {
                let mut pos = usize::from(noise[2 * e]) % RS_BLOCK + RS_BLOCK;
                while used.contains(&pos) {
                    pos = (pos + 1 - RS_BLOCK) % RS_BLOCK + RS_BLOCK;
                }
                used.push(pos);
                bytes[pos] ^= noise[2 * e + 1].max(1);
            }
            let label = format!("{errors} errors in codeword 1, trial {trial}");
            cases.push(rs_decode_case(&label, &bytes, data.len()));
        }
    }
    for trial in 0..40u32 {
        let block = pattern(50_000 + trial, RS_BLOCK);
        let label = format!("random codeword {trial}");
        cases.push(rs_decode_case(&label, &block, RS_DATA));
    }
    let single = ReedSolomonCodec.encode(&data[..RS_DATA]);
    let mut parity_hit = single.clone();
    for byte in parity_hit.iter_mut().skip(RS_DATA).take(16) {
        *byte ^= 0x5a;
    }
    let structural: [(&str, &[u8], usize); 9] = [
        ("16 errors in the parity bytes", &parity_hit, RS_DATA),
        ("empty stream, empty data", &[], 0),
        ("empty stream, data expected", &[], 5),
        (
            "one byte short of a codeword",
            &single[..RS_BLOCK - 1],
            RS_DATA,
        ),
        ("one byte past a codeword", &clean[..RS_BLOCK + 1], RS_DATA),
        ("pre_len zero for one codeword", &single, 0),
        ("pre_len one past a codeword", &single, RS_DATA + 1),
        ("pre_len of two codewords for one", &single, 2 * RS_DATA),
        ("pre_len shorter than the data", &single, 100),
    ];
    for (label, encoded, pre_len) in structural {
        cases.push(rs_decode_case(label, encoded, pre_len));
    }
    cases
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
        "rs_decode": rs_decode(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("serializable")
    );
    ExitCode::SUCCESS
}
