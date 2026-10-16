// Author: Julian Bolivar
// Version: 0.2.0
// Date: 2026-10-16
//! Reference values for the FEC codecs of the `cryptovault` crate.
//!
//! Subcommand `fec-fixtures` prints them as one JSON document, which the Python
//! test suite reads from `tests/fixtures/rust_fec.json`.

use std::process::ExitCode;

use cryptovault::{
    RS_BLOCK, RS_DATA, RS_INTERLEAVE_MAX, RS_PARITY, TERMINATION_OVERHEAD, VITERBI_CHUNK,
};
use serde_json::json;

/// Prints the full FEC fixture document.
pub fn fec_fixtures() -> ExitCode {
    let document = json!({
        "crate": "cryptovault 0.3.0",
        "constants": {
            "RS_DATA": RS_DATA, "RS_PARITY": RS_PARITY, "RS_BLOCK": RS_BLOCK,
            "RS_INTERLEAVE_MAX": RS_INTERLEAVE_MAX, "VITERBI_CHUNK": VITERBI_CHUNK,
            "TERMINATION_OVERHEAD": TERMINATION_OVERHEAD,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("serializable")
    );
    ExitCode::SUCCESS
}
