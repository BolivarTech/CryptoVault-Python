// Author: Julian Bolivar
// Version: 0.2.0
// Date: 2026-10-16
//! Reference values for the FEC codecs of the `cryptovault` crate.
//!
//! Subcommand `fec-fixtures` prints them as one JSON document, which the Python
//! test suite reads from `tests/fixtures/rust_fec.json`.

use std::process::ExitCode;

use cryptovault::cipher::Aes256GcmSivCipher;
use cryptovault::fec::{
    BlockInterleaver, ConcatenatedFec, CsprngLayer, ErrorCorrection, Interleaver, ReedSolomonCodec,
    ViterbiCodec, ViterbiOnlyFec,
};
use cryptovault::kdf::Argon2Kdf;
use cryptovault::CryptoVault;
use cryptovault::{
    KEY_LEN, MAX_BLOB_LEN, RS_BLOCK, RS_DATA, RS_INTERLEAVE_MAX, RS_PARITY, SALT_LEN,
    TERMINATION_OVERHEAD, VITERBI_CHUNK,
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

/// Flips `count` distinct pseudo-random bits of `bytes` within `range`.
fn flip_bits(bytes: &mut [u8], range: std::ops::Range<usize>, count: usize, seed: u32) {
    let span = (range.end - range.start) * 8;
    let noise = pattern(seed, 4 * count);
    let mut used = Vec::new();
    for chunk in noise.chunks(4) {
        let draw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize;
        let mut bit = draw % span;
        while used.contains(&bit) {
            bit = (bit + 1) % span;
        }
        used.push(bit);
        bytes[range.start + bit / 8] ^= 0x80 >> (bit % 8);
    }
}

/// Records the crate's answer to `ViterbiCodec::decode(body)`, digesting the
/// output so wrong-but-decoded streams are pinned without bloating the file.
fn viterbi_decode_case(label: &str, body: &[u8]) -> Value {
    let expect = match ViterbiCodec.decode(body) {
        Ok(decoded) => json!({ "ok_len": decoded.len(), "ok_sha256": sha256_hex(&decoded) }),
        Err(error) => json!({ "error": error.to_string() }),
    };
    json!({ "label": label, "body": hex::encode(body), "expect": expect })
}

/// Viterbi decode outcomes: clean, sparse to dense bit errors, bursts, junk,
/// padding bits, malformed lengths and a corrupted second sub-block; read by
/// `test_viterbi_decode_recovers_and_miscorrects_exactly_as_the_crate`.
fn viterbi_decode() -> Vec<Value> {
    let mut cases = Vec::new();
    let clean = ViterbiCodec.encode(&pattern(91, RS_BLOCK));
    cases.push(viterbi_decode_case("clean codeword stream", &clean));
    for (i, flips) in [1usize, 2, 5, 10, 20, 40, 80, 160, 400, 1000]
        .iter()
        .enumerate()
    {
        let mut body = clean.clone();
        flip_bits(&mut body, 0..clean.len(), *flips, 200 + i as u32);
        cases.push(viterbi_decode_case(&format!("{flips} bit errors"), &body));
    }
    let mut burst = clean.clone();
    for byte in burst.iter_mut().skip(200).take(16) {
        *byte ^= 0xff;
    }
    cases.push(viterbi_decode_case("16-byte burst", &burst));
    let mut padding = clean.clone();
    *padding.last_mut().expect("non-empty") ^= 0x0f;
    cases.push(viterbi_decode_case("padding bits flipped", &padding));
    cases.push(viterbi_decode_case(
        "random body",
        &pattern(92, clean.len()),
    ));
    cases.push(viterbi_decode_case(
        "all-zero body",
        &vec![0x00; clean.len()],
    ));
    cases.push(viterbi_decode_case(
        "all-ones body",
        &vec![0xff; clean.len()],
    ));
    for len in [0usize, 2, 3, 4, 5, 6, 7, 512] {
        let label = format!("{len}-byte junk body");
        cases.push(viterbi_decode_case(&label, &pattern(93 + len as u32, len)));
    }
    let long = ViterbiCodec.encode(&pattern(94, VITERBI_CHUNK + RS_BLOCK));
    let full = 2 * VITERBI_CHUNK + TERMINATION_OVERHEAD;
    let mut second = long.clone();
    flip_bits(&mut second, full..long.len(), 3, 95);
    cases.push(viterbi_decode_case("3 bit errors in sub-block 2", &second));
    cases.push(viterbi_decode_case(
        "full sub-block plus 2 bytes",
        &long[..full + 2],
    ));
    cases
}

/// Renders a crate result as its value or its `Display` text.
fn value_or_error<T: Into<Value>>(result: cryptovault::Result<T>) -> Value {
    match result {
        Ok(value) => value.into(),
        Err(error) => json!(error.to_string()),
    }
}

/// `ViterbiOnlyFec` framing, decode and truncation over encoded payloads and
/// junk; read by `test_viterbi_only_fec_frames_and_truncates_as_the_crate`.
fn viterbi_only() -> Vec<Value> {
    let fec = ViterbiOnlyFec;
    let mut cases = Vec::new();
    let mut push = |label: &str, data: Option<Vec<u8>>, received: Vec<u8>, pre_len: usize| {
        let mut expect = json!({
            "validate": value_or_error(fec.validate_pre_fec(&received)),
            "decode": value_or_error(fec.decode(&received, pre_len).map(hex::encode)),
        });
        let mut case =
            json!({ "label": label, "received": hex::encode(&received), "pre_len": pre_len });
        if let Some(data) = data {
            expect["encode"] = json!(fec.encode(&data) == received);
            case["data"] = json!(hex::encode(&data));
        }
        case["expect"] = expect;
        cases.push(case);
    };
    for len in [0usize, 33, 100, 300, 700] {
        let data = pattern(300 + len as u32, len);
        let received = fec.encode(&data);
        push(&format!("{len}-byte payload"), Some(data), received, len);
    }
    let blob = fec.encode(&pattern(600, 300));
    push("truncate to 10 bytes", None, blob.clone(), 10);
    push("pre_len past the payload", None, blob, 1000);
    for len in [1usize, 3, 5, 7, 64] {
        push(
            &format!("{len}-byte junk"),
            None,
            pattern(700 + len as u32, len),
            len,
        );
    }
    cases
}

/// Builds the concatenated stack a fixture case names: depth and optional seed.
fn stack(depth: usize, seed: Option<&[u8]>) -> ConcatenatedFec {
    let block = BlockInterleaver::new(depth).expect("valid depth");
    let interleaver = match seed {
        None => Interleaver::Block(block),
        Some(seed) => Interleaver::BlockThenCsprng(block, CsprngLayer::new(seed).expect("seed")),
    };
    ConcatenatedFec::new(ReedSolomonCodec, interleaver, ViterbiCodec)
}

/// `ConcatenatedFec` framing, correction and failure over clean, burst,
/// obliterated and malformed bodies, on the default and injected stacks; read
/// by `test_concatenated_fec_encodes_corrects_and_fails_as_the_crate`.
fn concatenated() -> Vec<Value> {
    let seed = pattern(800, KEY_LEN);
    let mut cases = Vec::new();
    let mut push = |label: &str,
                    (depth, seed): (usize, Option<&[u8]>),
                    data: Option<&[u8]>,
                    received: &[u8],
                    pre_len: usize| {
        let fec = stack(depth, seed);
        let decode = match fec.decode(received, pre_len) {
            Ok(decoded) => json!(sha256_hex(&decoded)),
            Err(error) => json!(error.to_string()),
        };
        let mut expect = json!({
            "validate": value_or_error(fec.validate_pre_fec(received)),
            "decode": decode,
        });
        let mut case = json!({
            "label": label,
            "stack": { "depth": depth, "seed": seed.map(hex::encode) },
            "received": hex::encode(received),
            "pre_len": pre_len,
        });
        if let Some(data) = data {
            expect["encode"] = json!(fec.encode(data) == received);
            case["data"] = json!(hex::encode(data));
        }
        case["expect"] = expect;
        cases.push(case);
    };
    let default = (5, None);
    let fec = stack(5, None);
    let clean_data = pattern(801, 600);
    let clean = fec.encode(&clean_data);
    let rs_len = |body: &[u8]| fec.validate_pre_fec(body).unwrap_or(0);
    push(
        "clean 600 bytes",
        default,
        Some(&clean_data),
        &clean,
        rs_len(&clean),
    );
    let burst_data = pattern(802, 5 * RS_BLOCK);
    let mut burst = fec.encode(&burst_data);
    let start = burst.len() / 3;
    for byte in burst.iter_mut().skip(start).take(24) {
        *byte ^= 0xff;
    }
    push("24-byte burst", default, None, &burst, rs_len(&burst));
    let mut obliterated = fec.encode(&pattern(803, 2 * RS_BLOCK));
    let half = obliterated.len() / 2;
    for byte in obliterated.iter_mut().take(half) {
        *byte ^= 0xff;
    }
    push(
        "first half obliterated",
        default,
        None,
        &obliterated,
        rs_len(&obliterated),
    );
    push("empty payload", default, Some(&[]), &fec.encode(&[]), 0);
    push(
        "body of 100 info bytes",
        default,
        None,
        &pattern(804, 202),
        100,
    );
    push("5-byte junk", default, None, &pattern(805, 5), 0);
    push("pre_len 10", default, None, &clean, 10);
    push(
        "random 512-byte body",
        default,
        None,
        &pattern(806, 512),
        RS_DATA,
    );
    let shallow_data = pattern(807, 300);
    let shallow = stack(1, None).encode(&shallow_data);
    push(
        "depth 1",
        (1, None),
        Some(&shallow_data),
        &shallow,
        2 * RS_DATA,
    );
    let deep = (RS_INTERLEAVE_MAX, Some(seed.as_slice()));
    let deep_data = pattern(808, 2000);
    let deep_clean = stack(deep.0, deep.1).encode(&deep_data);
    push(
        "depth 16 with CSPRNG",
        deep,
        Some(&deep_data),
        &deep_clean,
        9 * RS_DATA,
    );
    let mut deep_noisy = deep_clean.clone();
    flip_bits(&mut deep_noisy, 0..deep_clean.len(), 40, 809);
    push(
        "depth 16 with CSPRNG, 40 bit errors",
        deep,
        None,
        &deep_noisy,
        9 * RS_DATA,
    );
    let mid = (3, Some(seed.as_slice()));
    let mut mid_burst = stack(mid.0, mid.1).encode(&pattern(810, 1000));
    for byte in mid_burst.iter_mut().skip(500).take(30) {
        *byte ^= 0x5a;
    }
    push(
        "depth 3 with CSPRNG, 30-byte burst",
        mid,
        None,
        &mid_burst,
        5 * RS_DATA,
    );
    cases
}

/// Interleaver seeds the crate's `expand_interleaver_seed` derives; read by
/// `test_interleaver_seed_matches_the_crate_and_differs_from_the_aead_key`.
fn interleaver_seed() -> Vec<Value> {
    [
        vec![0u8; KEY_LEN],
        vec![0xff; KEY_LEN],
        pattern(900, KEY_LEN),
    ]
    .iter()
    .map(|master| {
        let seed = cryptovault::kdf::expand_interleaver_seed(master).expect("expand");
        json!({ "master": hex::encode(master), "seed": hex::encode(&*seed) })
    })
    .collect()
}

/// `ConcatenatedFec::default` encodings; read by
/// `test_default_stack_encodes_as_the_crate_default`.
fn concatenated_default() -> Vec<Value> {
    [1usize, 600, 7 * RS_BLOCK]
        .iter()
        .map(|&len| {
            let data = pattern(950 + len as u32, len);
            json!({
                "data": hex::encode(&data),
                "encoded_sha256": sha256_hex(&ConcatenatedFec::default().encode(&data)),
            })
        })
        .collect()
}

/// `ConcatenatedFec::with_csprng_from_master` encodings and errors; read by
/// `test_csprng_stack_from_master_matches_the_crate_and_its_errors`.
fn concatenated_from_master() -> Vec<Value> {
    let master = pattern(970, KEY_LEN);
    let data = pattern(971, 900);
    let inputs: [(&str, Vec<u8>, usize); 6] = [
        ("depth 5", master.clone(), 5),
        ("depth 1", master.clone(), 1),
        ("depth 16", master.clone(), RS_INTERLEAVE_MAX),
        ("depth 0", master.clone(), 0),
        ("depth 17", master, RS_INTERLEAVE_MAX + 1),
        ("empty master", Vec::new(), 5),
    ];
    inputs
        .iter()
        .map(|(label, master, depth)| {
            let expect = match ConcatenatedFec::with_csprng_from_master(master, *depth) {
                Ok(fec) => sha256_hex(&fec.encode(&data)),
                Err(error) => error.to_string(),
            };
            json!({
                "label": label,
                "master": hex::encode(master),
                "depth": depth,
                "data": hex::encode(&data),
                "expect": expect,
            })
        })
        .collect()
}

/// The vault FEC strategies the fixtures cover, as the JSON spec Python reads.
fn strategies() -> Vec<Value> {
    vec![
        json!({ "name": "ConcatenatedFec" }),
        json!({ "name": "ViterbiOnlyFec" }),
        json!({ "name": "ReedSolomonCodec" }),
        json!({ "name": "CsprngFromMaster", "master": hex::encode(pattern(990, KEY_LEN)), "depth": 5 }),
    ]
}

/// Builds the vault a strategy spec names; panics on an unknown spec, which is
/// a bug in this tool.
pub fn vault_for(spec: &Value) -> CryptoVault {
    let fec: Box<dyn ErrorCorrection> = match spec["name"].as_str() {
        Some("ConcatenatedFec") => Box::new(ConcatenatedFec::default()),
        Some("ViterbiOnlyFec") => Box::new(ViterbiOnlyFec),
        Some("ReedSolomonCodec") => Box::new(ReedSolomonCodec),
        Some("CsprngFromMaster") => {
            let master = hex::decode(spec["master"].as_str().expect("master")).expect("hex");
            let depth = spec["depth"].as_u64().expect("depth") as usize;
            Box::new(ConcatenatedFec::with_csprng_from_master(&master, depth).expect("stack"))
        }
        other => panic!("unknown FEC strategy {other:?}"),
    };
    CryptoVault::new(Box::new(Argon2Kdf), Box::new(Aes256GcmSivCipher), fec)
}

/// Data and envelope blobs the crate produces under each FEC strategy; read by
/// `test_every_crate_blob_opens_under_its_fec_strategy`.
fn vault_blobs() -> Vec<Value> {
    let key = pattern(991, KEY_LEN);
    let kek = pattern(992, KEY_LEN);
    let plaintexts = [
        String::new(),
        "a".to_string(),
        "sk-secret".to_string(),
        "\u{f1}and\u{fa} \u{1f510} \u{4e2d}\u{6587}".to_string(),
        "x".repeat(1000),
    ];
    let envelopes = [
        (pattern(993, SALT_LEN), pattern(994, KEY_LEN)),
        (Vec::new(), pattern(995, KEY_LEN)),
        (pattern(996, SALT_LEN), Vec::new()),
        (vec![0xaa; 40], vec![0x55; 64]),
    ];
    let mut rows = Vec::new();
    for spec in strategies() {
        let vault = vault_for(&spec);
        for plaintext in &plaintexts {
            rows.push(json!({
                "fec": spec, "kind": "data", "key": hex::encode(&key), "plaintext": plaintext,
                "blob": vault.encrypt_with_key(&key, plaintext).expect("encrypt"),
            }));
        }
        for (salt, material) in &envelopes {
            rows.push(json!({
                "fec": spec, "kind": "envelope", "kek": hex::encode(&kek),
                "salt": hex::encode(salt), "key_material": hex::encode(material),
                "blob": vault.wrap_key(&kek, salt, material).expect("wrap"),
            }));
        }
    }
    rows
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
        "viterbi_decode": viterbi_decode(),
        "viterbi_only": viterbi_only(),
        "concatenated": concatenated(),
        "interleaver_seed": interleaver_seed(),
        "concatenated_default": concatenated_default(),
        "concatenated_from_master": concatenated_from_master(),
        "vault_blobs": vault_blobs(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("serializable")
    );
    ExitCode::SUCCESS
}
