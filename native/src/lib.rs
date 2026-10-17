// Author: Julian Bolivar
// Version: 0.2.0
// Date: 2026-10-16
//! Compiled codec primitives for `cryptovault.fec`.
//!
//! The four functions wrap the `reedsolomon` 0.2.0 and `viterbi` 0.2.0 crates
//! that the Rust `cryptovault` crate uses, with the same parameters, so their
//! output (miscorrections included) is the crate's by construction. They
//! mirror the pure-Python ports in `cryptovault.fec._reedsolomon` and
//! `cryptovault.fec._viterbi`, and they raise the same Python exceptions. The
//! GIL is released while a codec runs.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use reedsolomon::{ReedSolomon, RsError};
use viterbi::{
    CcsdsViterbiDecoder, CodeParams, CodedBlock, DecodeError, DecodedBlock, ViterbiEncoder,
};

/// Module holding the low-level Reed-Solomon exceptions.
const RS_ERRORS: &str = "cryptovault.fec._reedsolomon";
/// Module holding the domain exceptions.
const DOMAIN_ERRORS: &str = "cryptovault.error";
/// Message of every error that means "this blob cannot be framed".
const MALFORMED: &str = "malformed blob";
/// Message of every error that means "the codec could not recover the data".
const FEC_FAILED: &str = "forward error correction failed";
/// Padding bits after the 12-bit zero tail of a coded sub-block.
const PAD_BITS: usize = 4;
/// Coded bytes of the smallest sub-block body: one info byte plus the tail.
const MIN_BODY: usize = 4;
/// Register memory of the K=7 code.
const MEMORY: u32 = 6;
/// Mask of the 6-bit register state.
const STATE_MASK: u32 = (1 << MEMORY) - 1;
/// State taps of the first generator `0o171` (its input tap, bit 6, removed).
const FIRST_GENERATOR_STATE_TAPS: u32 = 0o171 & STATE_MASK;
/// Mask of the coded bits in the last byte of a body (the rest is padding).
const LAST_BYTE_CODED_MASK: u8 = 0xF0;

/// Build an instance of the Python exception `module.class(message)`.
///
/// A failure to import the module or build the instance is returned instead,
/// so an error is never lost.
fn python_error(py: Python<'_>, module: &str, class: &str, message: &str) -> PyErr {
    match py
        .import(module)
        .and_then(|m| m.getattr(class))
        .and_then(|cls| cls.call1((message,)))
    {
        Ok(instance) => PyErr::from_value(instance),
        Err(err) => err,
    }
}

/// `InvalidInputError("malformed blob")`, the crate's framing error.
fn malformed(py: Python<'_>) -> PyErr {
    python_error(py, DOMAIN_ERRORS, "InvalidInputError", MALFORMED)
}

/// `ErrorCorrectionError("forward error correction failed")`.
fn fec_failed(py: Python<'_>) -> PyErr {
    python_error(py, DOMAIN_ERRORS, "ErrorCorrectionError", FEC_FAILED)
}

/// Encode `data` into RS(255, 223) codewords, the last one zero-padded.
///
/// Complexity: O(len(data) * 32).
///
/// Raises:
///     RsInvalidInputError: If the stream length overflows (not reachable
///         for an in-memory buffer).
#[pyfunction]
fn rs_encode<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    match py.detach(|| ReedSolomon::default().encode(data)) {
        Ok(out) => Ok(PyBytes::new(py, &out)),
        Err(err) => Err(rs_error(py, err)),
    }
}

/// Correct whole RS(255, 223) codewords and truncate to `pre_len` bytes.
///
/// Complexity: O(len(encoded) * 32) per codeword pass.
///
/// Raises:
///     RsUncorrectableError: If a codeword has more than 16 bad bytes.
///     RsInvalidInputError: If the lengths are inconsistent.
#[pyfunction]
fn rs_decode<'py>(
    py: Python<'py>,
    encoded: &[u8],
    pre_len: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    match py.detach(|| ReedSolomon::default().decode(encoded, pre_len)) {
        Ok(out) => Ok(PyBytes::new(py, &out)),
        Err(err) => Err(rs_error(py, err)),
    }
}

/// Map a `reedsolomon` error to the matching Python exception.
fn rs_error(py: Python<'_>, err: RsError) -> PyErr {
    match err {
        RsError::Uncorrectable(message) => {
            python_error(py, RS_ERRORS, "RsUncorrectableError", &message)
        }
        RsError::InvalidInput(message) => {
            python_error(py, RS_ERRORS, "RsInvalidInputError", &message)
        }
    }
}

/// Encode one sub-block with the CCSDS K=7 R=1/2 code and a zero tail.
///
/// Complexity: O(len(chunk)).
///
/// Raises:
///     ErrorCorrectionError: If the chunk exceeds the encoder's limit (not
///         reachable for a `VITERBI_CHUNK`-byte sub-block).
#[pyfunction]
fn viterbi_encode<'py>(py: Python<'py>, chunk: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let coded = py.detach(|| {
        ViterbiEncoder::new(CodeParams::ccsds_r1_2())
            .ok()
            .and_then(|encoder| encoder.encode(chunk).ok())
    });
    match coded {
        Some(block) => Ok(PyBytes::new(py, &block.bytes)),
        None => Err(fec_failed(py)),
    }
}

/// Hard-decision Viterbi decode of one zero-tailed sub-block body.
///
/// `body` holds `2 * n + 2` bytes for `n` info bytes, read as
/// `8 * len(body) - 4` coded bits.
///
/// Complexity: O(len(body) * 64) time.
///
/// Raises:
///     InvalidInputError: If `body` is odd or shorter than 4 bytes.
///     ErrorCorrectionError: If the decoder cannot be allocated.
#[pyfunction]
fn viterbi_decode<'py>(py: Python<'py>, body: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if body.len() < MIN_BODY || !body.len().is_multiple_of(2) {
        return Err(malformed(py));
    }
    let decoded = py.detach(|| {
        if let Some(clean) = decode_exact_codeword(body) {
            return Ok(DecodedBlock {
                nbits: clean.len() * 8,
                bytes: clean,
            });
        }
        let info_bits = (body.len() / 2 - 1) * 8;
        let mut decoder = CcsdsViterbiDecoder::new(CodeParams::ccsds_r1_2(), info_bits)
            .map_err(|_| DecodeError::AllocationFailed)?;
        decoder.decode_block(&CodedBlock {
            bytes: body.to_vec(),
            nbits: 8 * body.len() - PAD_BITS,
        })
    });
    match decoded {
        Ok(block) => Ok(PyBytes::new(py, &block.bytes)),
        Err(DecodeError::AllocationFailed) => Err(fec_failed(py)),
        Err(DecodeError::LengthMismatch | DecodeError::InputTooLong { .. }) => Err(malformed(py)),
    }
}

/// Decode `body` directly when it is an exact codeword, the clean-channel case.
///
/// The first output of each symbol is the input bit XOR a parity of the
/// register state, so the info bits follow from the symbols alone. The
/// candidate is accepted only if the crate's encoder reproduces `body`; a
/// codeword's zero-distance path is then the only survivor, so the full
/// trellis would return the same bytes.
///
/// Complexity: O(len(body)).
fn decode_exact_codeword(body: &[u8]) -> Option<Vec<u8>> {
    let info_bytes = body.len() / 2 - 1;
    let mut candidate = Vec::with_capacity(info_bytes);
    let mut state = 0u32;
    for index in 0..info_bytes * 8 {
        // Symbol `index` holds bits 2*index (first output) and 2*index + 1.
        let position = 2 * index;
        let first_output = u32::from(body[position / 8] >> (7 - position % 8)) & 1;
        let bit = first_output ^ ((state & FIRST_GENERATOR_STATE_TAPS).count_ones() & 1);
        if index % 8 == 0 {
            candidate.push(0);
        }
        // The cast keeps the single info bit, at its MSB-first position.
        *candidate.last_mut()? |= (bit as u8) << (7 - index % 8);
        state = ((bit << MEMORY) | state) >> 1;
    }
    let coded = ViterbiEncoder::new(CodeParams::ccsds_r1_2())
        .ok()?
        .encode(&candidate)
        .ok()?
        .bytes;
    let (last, head) = body.split_last()?;
    let exact = coded.len() == body.len()
        && coded[..head.len()] == *head
        && coded[head.len()] == last & LAST_BYTE_CODED_MASK;
    exact.then_some(candidate)
}

/// The `cryptovault._native` extension module.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rs_encode, m)?)?;
    m.add_function(wrap_pyfunction!(rs_decode, m)?)?;
    m.add_function(wrap_pyfunction!(viterbi_encode, m)?)?;
    m.add_function(wrap_pyfunction!(viterbi_decode, m)?)?;
    Ok(())
}
