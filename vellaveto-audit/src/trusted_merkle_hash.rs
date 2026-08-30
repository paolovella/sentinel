// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Explicit trusted boundary for Merkle hashing and hash encoding.
//!
//! Verus proves the structural Merkle logic around these operations, but not
//! the SHA-256 primitive or the hex codec itself. This module keeps that
//! remaining trust surface narrow and named in one place.

use crate::types::AuditError;
use sha2::{Digest, Sha256};

/// RFC 6962 domain separation byte for leaf hashes.
const LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 domain separation byte for internal hashes.
const INTERNAL_PREFIX: u8 = 0x01;

/// Hash a Merkle leaf with the RFC 6962 leaf prefix.
#[must_use = "Merkle hash results must not be discarded"]
pub(crate) fn hash_leaf_rfc6962(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a Merkle internal node with the RFC 6962 internal prefix.
#[must_use = "Merkle hash results must not be discarded"]
pub(crate) fn hash_internal_rfc6962(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Encode a 32-byte hash as lowercase hex.
#[must_use = "Merkle root/proof encodings must not be discarded"]
pub(crate) fn encode_hash_hex(hash: [u8; 32]) -> String {
    hex::encode(hash)
}

/// Decode a hex-encoded hash string.
///
/// Length validation stays at the verified Merkle guard call site so the
/// fail-closed boundary remains explicit there.
pub(crate) fn decode_hash_hex(hash_hex: &str) -> Result<Vec<u8>, AuditError> {
    hex::decode(hash_hex)
        .map_err(|e| AuditError::Validation(format!("Invalid sibling hash hex: {e}")))
}

/// Compare a computed hash against a trusted hex-encoded root.
#[must_use = "Merkle root comparisons must not be discarded"]
pub(crate) fn hash_matches_trusted_root(hash: [u8; 32], trusted_root: &str) -> bool {
    encode_hash_hex(hash) == trusted_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_hash_hex_roundtrip() {
        let hash = [0x5au8; 32];
        let encoded = encode_hash_hex(hash);
        let decoded = decode_hash_hex(&encoded).expect("valid hex");
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_decode_hash_hex_rejects_invalid_hex() {
        let err = decode_hash_hex("not-hex").expect_err("invalid hex");
        match err {
            AuditError::Validation(msg) => assert!(msg.contains("Invalid sibling hash hex")),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_hash_matches_trusted_root_requires_exact_encoding() {
        let hash = [0x42u8; 32];
        assert!(hash_matches_trusted_root(hash, &encode_hash_hex(hash)));
        assert!(!hash_matches_trusted_root(hash, &"0".repeat(64)));
    }

    #[test]
    fn test_hash_leaf_and_internal_preserve_domain_separation() {
        let data = [0xa5u8; 32];
        assert_ne!(
            hash_leaf_rfc6962(&data),
            hash_internal_rfc6962(&data, &data)
        );
    }

    #[test]
    fn test_hash_internal_is_order_sensitive() {
        let left = [0x01u8; 32];
        let right = [0x02u8; 32];
        assert_ne!(
            hash_internal_rfc6962(&left, &right),
            hash_internal_rfc6962(&right, &left)
        );
    }
}

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(
    clippy::manual_range_contains,
    clippy::needless_borrows_for_generic_args,
    dead_code,
    unused_imports
)]
mod kani_merkle_sanity_extraction {
    include!(concat!(
        env!("OUT_DIR"),
        "/kani_merkle_sanity_extraction.rs"
    ));
}

#[cfg(test)]
mod kani_parity_differential_merkle_sanity {
    //! Differential binding for `PARITY-HAND-2` — RFC 6962 Merkle hashing.
    //!
    //! K121-K125 bridge the **axiomatized** Merkle trust boundary: the Verus
    //! proofs treat SHA-256 as an uninterpreted function, and these checks
    //! assert the real implementation behaves as axiomatized — 32-byte output,
    //! determinism, domain separation, 64-char hex, and distinctness on
    //! distinct inputs.
    //!
    //! That makes the correspondence unusually load-bearing. If the Kani copy
    //! hashes differently from production — a different prefix, a different
    //! field order — then the axioms are being sanity-checked against a
    //! function nobody runs, and the whole Merkle argument rests on an
    //! unexamined assumption instead of a checked one.
    //!
    //! Collision resistance remains a cryptographic assumption. K125 is a
    //! sanity check, not a proof, and the binding says so rather than implying
    //! otherwise.

    use super::kani_merkle_sanity_extraction as extracted;
    use super::{encode_hash_hex, hash_internal_rfc6962, hash_leaf_rfc6962};

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/merkle_sanity.rs was not found, so this binding \
             compared nothing"
        );
    }

    /// The leaf hash must be byte-identical between the two, across payload
    /// shapes including the empty leaf and one longer than a SHA-256 block.
    #[test]
    fn test_leaf_hash_matches_production() {
        let long = vec![0xABu8; 200];
        let inputs: [&[u8]; 8] = [
            b"",
            b"a",
            b"ab",
            b"audit entry",
            &[0x00],
            &[0x01],
            &[0xFF; 32],
            &long,
        ];
        for data in inputs {
            assert_eq!(
                extracted::merkle_leaf_hash(data),
                hash_leaf_rfc6962(data),
                "PARITY-HAND-2: leaf hashes differ for a {}-byte payload — the \
                 Merkle axioms are being checked against a function that is not \
                 the one building the audit chain",
                data.len()
            );
        }
    }

    /// The internal-node hash, over pairs that include equal children (where a
    /// field-order bug would be invisible) and unequal ones (where it is not).
    #[test]
    fn test_internal_hash_matches_production() {
        let a = hash_leaf_rfc6962(b"left");
        let b = hash_leaf_rfc6962(b"right");
        for (left, right) in [(a, b), (b, a), (a, a), ([0u8; 32], [0xFFu8; 32])] {
            assert_eq!(
                extracted::merkle_internal_hash(&left, &right),
                hash_internal_rfc6962(&left, &right),
                "PARITY-HAND-2: internal-node hashes differ"
            );
        }
        // Order matters — a Merkle tree whose internal hash is commutative
        // admits a second preimage by swapping siblings.
        assert_ne!(
            hash_internal_rfc6962(&a, &b),
            hash_internal_rfc6962(&b, &a),
            "internal hashing is order-independent, so sibling swaps are invisible"
        );
    }

    /// K123: RFC 6962 domain separation, stated as the attack it prevents.
    ///
    /// The real requirement is not "the prefixes differ" — it is that a leaf
    /// hash over `0x01 ‖ a ‖ b` cannot equal the internal hash of `(a, b)`.
    /// Testing only the prefix constants would pass while a second preimage
    /// remained possible, which is the weaker check this campaign has caught
    /// elsewhere.
    #[test]
    fn test_domain_separation_prevents_the_second_preimage() {
        let a = hash_leaf_rfc6962(b"a");
        let b = hash_leaf_rfc6962(b"b");

        let internal = hash_internal_rfc6962(&a, &b);

        // The forgery a second-preimage attacker would attempt: present the
        // concatenation of two node hashes as leaf data.
        let mut forged_payload = Vec::with_capacity(64);
        forged_payload.extend_from_slice(&a);
        forged_payload.extend_from_slice(&b);
        let forged = hash_leaf_rfc6962(&forged_payload);

        assert_ne!(
            internal, forged,
            "K123: a leaf hash over two concatenated node hashes equalled the \
             internal hash of those nodes — RFC 6962 domain separation is not \
             holding and a second preimage is constructible"
        );

        // And the model agrees on both sides of that inequality.
        assert_eq!(extracted::merkle_leaf_hash(&forged_payload), forged);
        assert_eq!(extracted::merkle_internal_hash(&a, &b), internal);
    }

    /// K121 and K124: fixed widths, in both.
    #[test]
    fn test_widths_match_production() {
        for data in [b"".as_slice(), b"x", b"a longer audit payload"] {
            let production = hash_leaf_rfc6962(data);
            assert_eq!(production.len(), 32, "K121: leaf hash is not 32 bytes");
            assert_eq!(
                extracted::merkle_leaf_hash(data).len(),
                32,
                "K121: the model's leaf hash is not 32 bytes"
            );
            assert_eq!(
                encode_hash_hex(production).len(),
                64,
                "K124: hex encoding of a 32-byte hash is not 64 chars"
            );
            assert_eq!(
                extracted::hex_encode(&production),
                encode_hash_hex(production),
                "PARITY-HAND-2: hex encoding differs between the model and production"
            );
        }
    }

    /// K122 and K125, stated for what they are.
    ///
    /// Determinism is checkable. Distinctness on the inputs tried is a sanity
    /// check and **not** a collision-resistance proof — that remains a
    /// cryptographic assumption, recorded in the Verus boundary axioms.
    #[test]
    fn test_determinism_and_distinctness_sanity() {
        for data in [b"".as_slice(), b"entry-1", b"entry-2"] {
            assert_eq!(
                hash_leaf_rfc6962(data),
                hash_leaf_rfc6962(data),
                "K122: hashing is not deterministic"
            );
        }
        assert_ne!(
            hash_leaf_rfc6962(b"entry-1"),
            hash_leaf_rfc6962(b"entry-2"),
            "K125 sanity: two distinct entries hashed alike"
        );
    }
}
