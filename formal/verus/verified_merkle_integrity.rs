// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified end-to-end Merkle tree integrity composition.
//!
//! Bridges the structural Merkle proofs (verified_merkle.rs,
//! verified_merkle_fold.rs, verified_merkle_path.rs) with the hash
//! function axioms (merkle_boundary_axioms.rs) to derive end-to-end
//! tamper-evidence and domain-separation guarantees at the tree level.
//!
//! This is the "axiomatized hash proof" referenced in Phase 4 of
//! `formal/LOCAL_VERIFICATION_PLAN.md`: the first Verus file that actively
//! USES the trusted boundary axioms for `MERKLE-HASH-1`, `MERKLE-HASH-2`,
//! and `MERKLE-CODEC-1` to derive meaningful security lemmas.
//!
//! # Production correspondence
//!
//! - `vellaveto-audit/src/merkle.rs` — Merkle tree construction and proof
//! - `vellaveto-audit/src/trusted_merkle_hash.rs` — concrete hash boundary
//! - `formal/verus/merkle_boundary_axioms.rs` — trusted axiom layer
//!
//! # Properties Verified
//!
//! | ID | Property |
//! |----|----------|
//! | MERKL-INT-1 | Leaf hash uniqueness: different data ⟹ different leaf hashes |
//! | MERKL-INT-2 | Internal hash uniqueness: different (left, right) ⟹ different internal hashes |
//! | MERKL-INT-3 | Domain separation at tree level: leaf and internal hashes never collide |
//! | MERKL-INT-4 | Codec roundtrip: encoding then decoding a 32-byte hash returns the original |
//! | MERKL-INT-5 | Tamper evidence at depth 1: distinct leaves produce distinct parent hashes |
//!
//! # Trust boundary
//!
//! This kernel depends on the trusted `MERKLE-HASH-1`, `MERKLE-HASH-2`, and
//! `MERKLE-CODEC-1` assumptions from `formal/ASSUMPTION_REGISTRY.md`, which
//! are axiomatized in `formal/verus/merkle_boundary_axioms.rs` and mirrored
//! in `formal/MERKLE_TRUST_BOUNDARY.md`.
//!
//! No new trusted assumptions are introduced by this file.
//!
//! # To verify
//!
//! ```sh
//! verus --triggers-mode silent formal/verus/verified_merkle_integrity.rs
//! ```

#[path = "assumptions.rs"]
mod assumptions;
#[path = "merkle_boundary_axioms.rs"]
mod merkle_boundary_axioms;

#[allow(unused_imports)]
use vstd::prelude::*;

use merkle_boundary_axioms::{
    axiom_merkle_codec_decoded_hash_len, axiom_merkle_codec_roundtrip,
    axiom_merkle_internal_hash_len, axiom_merkle_internal_second_preimage_resistance,
    axiom_merkle_leaf_hash_len, axiom_merkle_leaf_second_preimage_resistance,
    axiom_merkle_rfc6962_domain_separation, merkle_decode_hash_hex, merkle_encode_hash_hex,
    merkle_internal_hash, merkle_leaf_hash,
};

verus! {

// ── MERKL-INT-1: Leaf hash uniqueness ─────────────────────────────────────────

/// Different input data produces different leaf hashes.
/// Directly from `MERKLE-HASH-2` (SHA-256 second-preimage resistance).
pub proof fn lemma_leaf_hash_unique(data1: Seq<u8>, data2: Seq<u8>)
    requires data1 != data2,
    ensures merkle_leaf_hash(data1) != merkle_leaf_hash(data2),
{
    axiom_merkle_leaf_second_preimage_resistance(data1, data2);
    // axiom: leaf_hash(d1) == leaf_hash(d2) => d1 == d2
    // contrapositive: d1 != d2 => leaf_hash(d1) != leaf_hash(d2)
}

/// All leaf hashes have length 32 (from `MERKLE-HASH-1`).
pub proof fn lemma_leaf_hash_len_is_32(data: Seq<u8>)
    ensures merkle_leaf_hash(data).len() == 32,
{
    axiom_merkle_leaf_hash_len(data);
}

// ── MERKL-INT-2: Internal hash uniqueness ────────────────────────────────────

/// Different (left, right) pairs produce different internal hashes.
/// Directly from `MERKLE-HASH-2` (SHA-256 second-preimage resistance for internal nodes).
pub proof fn lemma_internal_hash_unique(
    left1: Seq<u8>,
    right1: Seq<u8>,
    left2: Seq<u8>,
    right2: Seq<u8>,
)
    requires
        left1.len() == 32,
        right1.len() == 32,
        left2.len() == 32,
        right2.len() == 32,
        (left1, right1) != (left2, right2),
    ensures
        merkle_internal_hash(left1, right1) != merkle_internal_hash(left2, right2),
{
    axiom_merkle_internal_second_preimage_resistance(left1, right1, left2, right2);
    // axiom: internal_hash(l1,r1) == internal_hash(l2,r2) => (l1==l2 && r1==r2)
    // contrapositive: (l1,r1) != (l2,r2) => hashes differ
}

/// All internal hashes have length 32 (from `MERKLE-HASH-1`).
pub proof fn lemma_internal_hash_len_is_32(left: Seq<u8>, right: Seq<u8>)
    requires left.len() == 32, right.len() == 32,
    ensures merkle_internal_hash(left, right).len() == 32,
{
    axiom_merkle_internal_hash_len(left, right);
}

// ── MERKL-INT-3: Domain separation at tree level ──────────────────────────────

/// A leaf hash can never equal an internal hash, regardless of the inputs.
/// Directly from `MERKLE-HASH-1` (RFC 6962 domain separation — leaf prefix 0x00,
/// internal prefix 0x01 prevents type confusion).
pub proof fn lemma_leaf_and_internal_hash_never_equal(
    data: Seq<u8>,
    left: Seq<u8>,
    right: Seq<u8>,
)
    requires left.len() == 32, right.len() == 32,
    ensures merkle_leaf_hash(data) != merkle_internal_hash(left, right),
{
    axiom_merkle_rfc6962_domain_separation(data, left, right);
}

/// Corollary: a hash cannot simultaneously be a valid leaf hash and a valid
/// internal hash. This prevents the attacker from substituting a leaf node
/// for an internal node in a Merkle proof.
pub proof fn lemma_no_type_confusion_in_proof(
    data: Seq<u8>,
    left: Seq<u8>,
    right: Seq<u8>,
    h: Seq<u8>,
)
    requires
        left.len() == 32,
        right.len() == 32,
        h == merkle_leaf_hash(data),
    ensures
        h != merkle_internal_hash(left, right),
{
    lemma_leaf_and_internal_hash_never_equal(data, left, right);
}

// ── MERKL-INT-4: Codec roundtrip ─────────────────────────────────────────────

/// A 32-byte hash encoded to hex and then decoded gives back the original hash.
/// Directly from `MERKLE-CODEC-1`.
pub proof fn lemma_codec_roundtrip(hash: Seq<u8>)
    requires hash.len() == 32,
    ensures merkle_decode_hash_hex(merkle_encode_hash_hex(hash)) == Option::Some(hash),
{
    axiom_merkle_codec_roundtrip(hash);
}

/// A decoded hash (when decoding succeeds) has exactly 32 bytes.
pub proof fn lemma_decoded_hash_len(encoded: Seq<u8>, decoded: Seq<u8>)
    requires merkle_decode_hash_hex(encoded) == Option::Some(decoded),
    ensures decoded.len() == 32,
{
    axiom_merkle_codec_decoded_hash_len(encoded, decoded);
}

/// Encoding is injective: if two hashes encode to the same hex string and
/// both decode successfully, they must be equal.
pub proof fn lemma_encoding_injective(hash1: Seq<u8>, hash2: Seq<u8>)
    requires
        hash1.len() == 32,
        hash2.len() == 32,
        merkle_encode_hash_hex(hash1) == merkle_encode_hash_hex(hash2),
    ensures
        hash1 == hash2,
{
    axiom_merkle_codec_roundtrip(hash1);
    axiom_merkle_codec_roundtrip(hash2);
    // Both decode to themselves via the same encoded form, so they must be equal.
}

// ── MERKL-INT-5: Tamper evidence at depth 1 ───────────────────────────────────

/// Tamper evidence at depth 1: if two leaves contain different data, any
/// parent node that includes one leaf hash will differ from a parent that
/// includes the other leaf hash instead.
///
/// This is the first compositional tamper-evidence lemma — it shows that the
/// second-preimage resistance of leaf hashes (MERKL-INT-1) propagates through
/// one level of the tree: changing a leaf changes any parent that covers it.
pub proof fn lemma_different_leaf_means_different_parent(
    data1: Seq<u8>,
    data2: Seq<u8>,
    sibling: Seq<u8>,
    sibling_on_left: bool,
)
    requires
        data1 != data2,
        sibling.len() == 32,
    ensures
        if sibling_on_left {
            merkle_internal_hash(sibling, merkle_leaf_hash(data1))
                != merkle_internal_hash(sibling, merkle_leaf_hash(data2))
        } else {
            merkle_internal_hash(merkle_leaf_hash(data1), sibling)
                != merkle_internal_hash(merkle_leaf_hash(data2), sibling)
        },
{
    // Step 1: different data → different leaf hashes.
    lemma_leaf_hash_unique(data1, data2);
    let h1 = merkle_leaf_hash(data1);
    let h2 = merkle_leaf_hash(data2);
    assert(h1 != h2);
    assert(h1.len() == 32) by { axiom_merkle_leaf_hash_len(data1); };
    assert(h2.len() == 32) by { axiom_merkle_leaf_hash_len(data2); };

    // Step 2: different leaf hashes → different parent hashes.
    if sibling_on_left {
        // Parent1 = internal(sibling, h1), Parent2 = internal(sibling, h2).
        // (sibling, h1) != (sibling, h2) since h1 != h2.
        axiom_merkle_internal_second_preimage_resistance(sibling, h1, sibling, h2);
    } else {
        // Parent1 = internal(h1, sibling), Parent2 = internal(h2, sibling).
        // (h1, sibling) != (h2, sibling) since h1 != h2.
        axiom_merkle_internal_second_preimage_resistance(h1, sibling, h2, sibling);
    }
}

/// Tamper evidence at depth 2: if two leaves differ and share the same
/// ancestor at depth 2, the depth-2 ancestor hashes also differ.
///
/// This extends MERKL-INT-5 one level up: a changed leaf propagates its
/// difference all the way to any ancestor, not just the immediate parent.
pub proof fn lemma_different_leaf_means_different_grandparent(
    data1: Seq<u8>,
    data2: Seq<u8>,
    leaf_sibling: Seq<u8>,    // sibling of the changed leaf
    parent_sibling: Seq<u8>,  // sibling of the parent
    leaf_on_left: bool,
    parent_on_left: bool,
)
    requires
        data1 != data2,
        leaf_sibling.len() == 32,
        parent_sibling.len() == 32,
    ensures
        (if leaf_on_left {
            if parent_on_left {
                merkle_internal_hash(
                    parent_sibling,
                    merkle_internal_hash(merkle_leaf_hash(data1), leaf_sibling),
                ) != merkle_internal_hash(
                    parent_sibling,
                    merkle_internal_hash(merkle_leaf_hash(data2), leaf_sibling),
                )
            } else {
                merkle_internal_hash(
                    merkle_internal_hash(merkle_leaf_hash(data1), leaf_sibling),
                    parent_sibling,
                ) != merkle_internal_hash(
                    merkle_internal_hash(merkle_leaf_hash(data2), leaf_sibling),
                    parent_sibling,
                )
            }
        } else {
            if parent_on_left {
                merkle_internal_hash(
                    parent_sibling,
                    merkle_internal_hash(leaf_sibling, merkle_leaf_hash(data1)),
                ) != merkle_internal_hash(
                    parent_sibling,
                    merkle_internal_hash(leaf_sibling, merkle_leaf_hash(data2)),
                )
            } else {
                merkle_internal_hash(
                    merkle_internal_hash(leaf_sibling, merkle_leaf_hash(data1)),
                    parent_sibling,
                ) != merkle_internal_hash(
                    merkle_internal_hash(leaf_sibling, merkle_leaf_hash(data2)),
                    parent_sibling,
                )
            }
        }),
{
    let h1 = merkle_leaf_hash(data1);
    let h2 = merkle_leaf_hash(data2);
    assert(h1.len() == 32) by { axiom_merkle_leaf_hash_len(data1); };
    assert(h2.len() == 32) by { axiom_merkle_leaf_hash_len(data2); };

    lemma_leaf_hash_unique(data1, data2);

    // Compute the two parent hashes.
    let p1 = if leaf_on_left {
        merkle_internal_hash(h1, leaf_sibling)
    } else {
        merkle_internal_hash(leaf_sibling, h1)
    };
    let p2 = if leaf_on_left {
        merkle_internal_hash(h2, leaf_sibling)
    } else {
        merkle_internal_hash(leaf_sibling, h2)
    };

    // Step 1: parent hashes differ (from depth-1 tamper evidence).
    lemma_different_leaf_means_different_parent(data1, data2, leaf_sibling, !leaf_on_left);
    assert(p1.len() == 32) by {
        if leaf_on_left {
            axiom_merkle_internal_hash_len(h1, leaf_sibling);
        } else {
            axiom_merkle_internal_hash_len(leaf_sibling, h1);
        }
    };
    assert(p2.len() == 32) by {
        if leaf_on_left {
            axiom_merkle_internal_hash_len(h2, leaf_sibling);
        } else {
            axiom_merkle_internal_hash_len(leaf_sibling, h2);
        }
    };
    assert(p1 != p2);

    // Step 2: different parents → different grandparents (from MERKL-INT-2).
    if parent_on_left {
        axiom_merkle_internal_second_preimage_resistance(parent_sibling, p1, parent_sibling, p2);
    } else {
        axiom_merkle_internal_second_preimage_resistance(p1, parent_sibling, p2, parent_sibling);
    }
}

// ── Assumption registration ────────────────────────────────────────────────────

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::merkle_integrity_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
