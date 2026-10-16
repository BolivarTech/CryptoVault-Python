// Author: Julian Bolivar
// Version: 0.2.0
// Date: 2026-10-16
//! Reference values for the FEC codecs of the `cryptovault` crate.
//!
//! Subcommand `fec-fixtures` prints them as one JSON document, which the Python
//! test suite reads from `tests/fixtures/rust_fec.json`.

use std::process::ExitCode;

use cryptovault::fec::{
    BlockInterleaver, CsprngLayer, ErrorCorrection, Interleaver, ReedSolomonCodec, ViterbiCodec,
};
use cryptovault::{
    KEY_LEN, MAX_BLOB_LEN, RS_BLOCK, RS_DATA, RS_INTERLEAVE_MAX, RS_PARITY, TERMINATION_OVERHEAD,
    VITERBI_CHUNK,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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

/// `ReedSolomonCodec::validate_pre_fec` over zeroed blobs of edge lengths;
/// read by `test_rs_validate_pre_fec_bounds_lengths_as_the_crate`.
fn rs_validate() -> Vec<Value> {
    let largest = MAX_BLOB_LEN - MAX_BLOB_LEN % RS_BLOCK;
    [0, 1, 254, 255, 256, 510, largest, MAX_BLOB_LEN + 1]
        .iter()
        .map(|&len| {
            let expect = match ReedSolomonCodec.validate_pre_fec(&vec![0u8; len]) {
                Ok(pre_len) => json!({ "ok": pre_len }),
                Err(error) => json!({ "error": error.to_string() }),
            };
            json!({ "received_len": len, "expect": expect })
        })
        .collect()
}

/// Stream lengths that cover empty, partial, whole and multi-window inputs.
const INTERLEAVE_LENGTHS: [usize; 6] = [
    0,
    100,
    RS_BLOCK,
    5 * RS_BLOCK + 100,
    10 * RS_BLOCK,
    16 * RS_BLOCK + 7,
];

/// Block-interleaver outputs for depths 1, 2, 5 and 16; read by
/// `test_block_interleaver_permutes_as_the_crate_and_inverts`.
fn block_interleave() -> Vec<Value> {
    let mut cases = Vec::new();
    for depth in [1usize, 2, 5, RS_INTERLEAVE_MAX] {
        let interleaver = BlockInterleaver::new(depth).expect("valid depth");
        for len in INTERLEAVE_LENGTHS {
            let stream = pattern((depth * 1000 + len) as u32, len);
            cases.push(json!({
                "depth": depth,
                "stream": hex::encode(&stream),
                "interleaved": hex::encode(interleaver.interleave(&stream)),
            }));
        }
    }
    cases
}

/// `BlockInterleaver::new` outcomes around the valid depth range; read by
/// `test_block_interleaver_accepts_only_the_crate_depth_range`.
fn interleaver_depth() -> Vec<Value> {
    [0usize, 1, RS_INTERLEAVE_MAX, RS_INTERLEAVE_MAX + 1, 1000]
        .iter()
        .map(|&depth| {
            let expect = match BlockInterleaver::new(depth) {
                Ok(interleaver) => json!({ "ok": interleaver.depth() }),
                Err(error) => json!({ "error": error.to_string() }),
            };
            json!({ "depth": depth, "expect": expect })
        })
        .collect()
}

/// CSPRNG-layer shuffles over several seeds, windows and stream lengths, the
/// crate's own golden case first; read by
/// `test_csprng_layer_shuffles_as_the_crate_and_inverts`.
fn csprng_interleave() -> Vec<Value> {
    let (seed_a, seed_b) = (pattern(71, KEY_LEN), pattern(72, KEY_LEN));
    let ramp: Vec<u8> = (0..RS_BLOCK).map(|i| i as u8).collect();
    let window = 5 * RS_BLOCK;
    let wide = RS_INTERLEAVE_MAX * RS_BLOCK;
    let inputs: [(Vec<u8>, usize, Vec<u8>); 12] = [
        (vec![0x42; KEY_LEN], RS_BLOCK, ramp),
        (vec![0x11; KEY_LEN], window, pattern(1, window + 137)),
        (vec![0x2a; KEY_LEN], window, pattern(2, window)),
        (seed_a.clone(), window, Vec::new()),
        (seed_a.clone(), window, pattern(3, 1)),
        (seed_a.clone(), window, pattern(4, 2)),
        (seed_a.clone(), RS_BLOCK, pattern(5, 100)),
        (seed_a, wide, pattern(6, 2 * wide + 37)),
        (seed_b.clone(), 2 * RS_BLOCK, pattern(7, 6 * RS_BLOCK)),
        (seed_b, window, pattern(8, 5 * window + 1)),
        (vec![0x00; KEY_LEN], window, pattern(9, window)),
        (vec![0xff; KEY_LEN], RS_BLOCK, pattern(10, 5 * RS_BLOCK - 1)),
    ];
    inputs
        .iter()
        .map(|(seed, window_len, stream)| {
            let layer = CsprngLayer::new(seed).expect("32-byte seed");
            json!({
                "seed": hex::encode(seed),
                "window_len": window_len,
                "stream": hex::encode(stream),
                "interleaved": hex::encode(layer.interleave(stream, *window_len)),
            })
        })
        .collect()
}

/// `CsprngLayer::new` outcomes around the 32-byte seed length; read by
/// `test_csprng_layer_accepts_only_a_32_byte_seed_as_the_crate`.
fn csprng_seed() -> Vec<Value> {
    [0usize, KEY_LEN - 1, KEY_LEN, KEY_LEN + 1]
        .iter()
        .map(|&len| {
            let expect = match CsprngLayer::new(&vec![0u8; len]) {
                Ok(_) => json!({ "ok": null }),
                Err(error) => json!({ "error": error.to_string() }),
            };
            json!({ "seed_len": len, "expect": expect })
        })
        .collect()
}

/// `Interleaver` outputs, block-only and block-then-CSPRNG; read by
/// `test_interleaver_composes_block_then_csprng_as_the_crate`.
fn interleaver() -> Vec<Value> {
    let seed = pattern(73, KEY_LEN);
    let inputs: [(usize, Option<&[u8]>, usize); 6] = [
        (5, None, 5 * RS_BLOCK + 42),
        (5, Some(&seed), 5 * RS_BLOCK + 42),
        (5, Some(&seed), 0),
        (3, Some(&seed), 7 * RS_BLOCK),
        (1, Some(&seed), 2 * RS_BLOCK + 1),
        (RS_INTERLEAVE_MAX, Some(&seed), 40 * RS_BLOCK),
    ];
    inputs
        .iter()
        .map(|&(depth, seed, len)| {
            let block = BlockInterleaver::new(depth).expect("valid depth");
            let interleaver = match seed {
                None => Interleaver::Block(block),
                Some(seed) => {
                    Interleaver::BlockThenCsprng(block, CsprngLayer::new(seed).expect("seed"))
                }
            };
            let stream = pattern((depth + len) as u32, len);
            json!({
                "depth": depth,
                "seed": seed.map(hex::encode),
                "stream": hex::encode(&stream),
                "interleaved": hex::encode(interleaver.interleave(&stream)),
            })
        })
        .collect()
}

/// Hex SHA-256 of `bytes`, which keeps long coded streams out of the fixture.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `ViterbiCodec::encode` lengths and digests, from empty to two sub-blocks;
/// read by `test_viterbi_encode_matches_the_crate_including_chunking`.
fn viterbi_encode() -> Vec<Value> {
    [
        0usize,
        1,
        33,
        RS_BLOCK,
        5 * RS_BLOCK,
        VITERBI_CHUNK + RS_BLOCK,
    ]
    .iter()
    .map(|&len| {
        let stream = pattern(len as u32 + 90, len);
        let encoded = ViterbiCodec.encode(&stream);
        json!({
            "stream_len": len,
            "stream": hex::encode(&stream),
            "encoded_len": encoded.len(),
            "encoded_sha256": sha256_hex(&encoded),
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
        "rs_decode": rs_decode(),
        "rs_validate": rs_validate(),
        "block_interleave": block_interleave(),
        "interleaver_depth": interleaver_depth(),
        "csprng_interleave": csprng_interleave(),
        "csprng_seed": csprng_seed(),
        "interleaver": interleaver(),
        "viterbi_encode": viterbi_encode(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("serializable")
    );
    ExitCode::SUCCESS
}
