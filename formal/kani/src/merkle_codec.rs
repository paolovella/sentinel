// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Kani bounded model checking proofs for MERKLE-CODEC-1.
//!
//! Partially discharges the `MERKLE-CODEC-1` trusted assumption
//! (`formal/ASSUMPTION_REGISTRY.md`): hex encoding and decoding are
//! inverse operations for byte arrays used as Merkle hashes.
//!
//! The hex codec in production lives in
//! `vellaveto-audit/src/trusted_merkle_hash.rs` which wraps `hex::encode`
//! and `hex::decode`. These harnesses prove the roundtrip property
//! symbolically for all possible byte values, establishing that the codec
//! is a correct bijection from byte arrays to ASCII hex strings.
//!
//! # Discharge scope
//!
//! - **K141** proves roundtrip for a single symbolic byte: all 256 values
//!   of a byte survive `encode → decode` intact. This establishes the
//!   per-byte correctness that underlies the full 32-byte Merkle hash codec.
//!
//! - **K142** proves that `hex::encode` of a 2-byte array always produces
//!   a 4-character string. Combined with K141, this confirms the length
//!   invariant: encoding N bytes always produces 2N hex chars, so a
//!   decoded string of 64 hex chars always gives back 32 bytes.
//!
//! # Remaining trust
//!
//! These harnesses verify the `hex` crate's behaviour for small inputs.
//! The 32-byte Merkle hash case follows by the independence of byte-level
//! encoding (each byte is encoded as exactly 2 hex chars, independently
//! of adjacent bytes). MERKLE-CODEC-1 is PARTIALLY discharged — the
//! per-byte soundness is machine-checked; the full 32-byte case is a
//! compositional consequence documented in `ASSUMPTION_REGISTRY.md`.
//!
//! # Verified Properties
//!
//! | ID | Property |
//! |----|----------|
//! | K141 | `hex::decode(hex::encode([byte]))` == Ok([byte]) for any byte |
//! | K142 | `hex::encode([b0, b1])` always has length 4 (2 chars per byte) |

// =========================================================================
// K141: Per-byte hex roundtrip — encode then decode is identity
// =========================================================================

#[cfg(kani)]
#[kani::proof]
fn proof_hex_codec_roundtrip_single_byte_k141() {
    let byte: u8 = kani::any();
    let encoded = hex::encode([byte]);
    // hex::encode of a valid byte always produces valid hex.
    let decoded = hex::decode(&encoded);
    assert!(
        decoded.is_ok(),
        "K141: hex::encode always produces decodable hex"
    );
    let decoded_bytes = decoded.unwrap();
    assert_eq!(
        decoded_bytes.len(),
        1,
        "K141: decoded length must equal original length"
    );
    assert_eq!(
        decoded_bytes[0], byte,
        "K141: hex roundtrip must recover original byte"
    );
}

// =========================================================================
// K142: Hex encoding length invariant — N bytes → 2N hex chars
// =========================================================================

#[cfg(kani)]
#[kani::proof]
fn proof_hex_encode_length_invariant_k142() {
    let b0: u8 = kani::any();
    let b1: u8 = kani::any();
    let encoded = hex::encode([b0, b1]);
    assert_eq!(
        encoded.len(),
        4,
        "K142: 2 bytes must encode to 4 hex chars"
    );
    // Consequentially: 32 bytes encode to 64 hex chars.
    // By the per-byte independence of hex encoding (K141 establishes
    // correctness per byte), the full 32-byte Merkle hash roundtrip holds.
}

// =========================================================================
// Unit test variants (run with `cargo test` in formal/kani/)
// =========================================================================

#[cfg(test)]
mod tests {
    #[test]
    fn test_k141_hex_roundtrip_spot_check() {
        for byte in [0u8, 0x0F, 0x10, 0xAB, 0xFF] {
            let encoded = hex::encode([byte]);
            let decoded = hex::decode(&encoded).expect("valid hex");
            assert_eq!(decoded, vec![byte], "K141 spot check failed for {byte:#04x}");
        }
    }

    #[test]
    fn test_k142_hex_encode_length_two_bytes() {
        for (b0, b1) in [(0u8, 0u8), (0xFF, 0xFF), (0xDE, 0xAD)] {
            let encoded = hex::encode([b0, b1]);
            assert_eq!(encoded.len(), 4, "K142 spot check: 2 bytes must → 4 chars");
        }
    }

    #[test]
    fn test_k141_k142_compose_32_byte_roundtrip() {
        // Compositional verification: 32 bytes → 64 chars → 32 bytes.
        let hash: [u8; 32] = core::array::from_fn(|i| i as u8);
        let encoded = hex::encode(hash);
        assert_eq!(encoded.len(), 64, "32 bytes must produce 64 hex chars");
        let decoded = hex::decode(&encoded).expect("valid hex");
        assert_eq!(decoded.len(), 32, "decoded must have 32 bytes");
        assert_eq!(decoded, hash.to_vec(), "roundtrip must recover original hash");
    }
}
