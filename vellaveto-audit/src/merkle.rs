// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Incremental append-only Merkle tree for audit log inclusion proofs.
//!
//! Uses RFC 6962 domain separation to prevent second-preimage attacks:
//! - Leaf hash: `SHA-256(0x00 || data)`
//! - Internal hash: `SHA-256(0x01 || left || right)`
//!
//! The tree is maintained as a set of O(log n) "peaks" (the top-level hashes
//! of complete binary sub-trees), enabling O(log n) amortized append and
//! O(log n) proof generation.
//!
//! Leaf hashes are persisted to a binary file (32 bytes per leaf) for
//! crash recovery and proof generation without replaying the full log.

use crate::types::AuditError;
use crate::{
    trusted_audit_fs, trusted_merkle_hash, verified_merkle, verified_merkle_fold,
    verified_merkle_path,
};
use std::path::PathBuf;
/// Size of a SHA-256 hash in bytes.
const HASH_SIZE: usize = 32;

/// Default maximum number of leaves allowed in a single Merkle tree.
/// SECURITY (FIND-R46-001): Prevents OOM when loading large leaf files.
const DEFAULT_MAX_LEAF_COUNT: u64 = 1_000_000;

/// Incremental append-only Merkle tree.
///
/// Stores leaf hashes in a binary file and maintains O(log n) peaks
/// in memory for efficient root computation and proof generation.
pub struct MerkleTree {
    /// Number of leaves appended to the tree.
    leaf_count: u64,
    /// Peaks of complete binary sub-trees. `peaks[i]` is the root of a
    /// sub-tree of size 2^i, or `None` if no such sub-tree exists in the
    /// current decomposition.
    peaks: Vec<Option<[u8; 32]>>,
    /// Path to the binary file storing leaf hashes (32 bytes per leaf).
    leaf_file_path: PathBuf,
    /// Maximum number of leaves allowed in the tree.
    /// SECURITY (FIND-R46-001): Prevents OOM from unbounded leaf accumulation.
    max_leaf_count: u64,
}

/// Inclusion proof for a single leaf in the Merkle tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleProof {
    /// Index of the leaf being proved (0-based).
    pub leaf_index: u64,
    /// Total number of leaves when the proof was generated.
    pub tree_size: u64,
    /// Bottom-up list of sibling hashes needed to reconstruct the root.
    pub siblings: Vec<ProofStep>,
    /// Root hash at `tree_size` (hex-encoded).
    pub root_hash: String,
}

/// A single step in a Merkle inclusion proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofStep {
    /// Hex-encoded sibling hash.
    pub hash: String,
    /// Whether this sibling is on the left side of the concatenation.
    pub is_left: bool,
}

/// Result of verifying a Merkle inclusion proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleVerification {
    /// Whether the proof is valid.
    pub valid: bool,
    /// Reason for failure, if any.
    pub failure_reason: Option<String>,
}

/// Compute a leaf hash with RFC 6962 domain separation.
///
/// `hash_leaf(data) = SHA-256(0x00 || data)`
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    trusted_merkle_hash::hash_leaf_rfc6962(data)
}

/// Compute an internal node hash with RFC 6962 domain separation.
///
/// `hash_internal(left, right) = SHA-256(0x01 || left || right)`
///
/// The `0x01` prefix is the RFC 6962 domain separation byte for internal
/// (non-leaf) nodes. This prevents second-preimage attacks where an
/// attacker tries to reinterpret a leaf as an internal node or vice versa.
///
/// This function is public so that external verifiers can reconstruct
/// Merkle proofs independently using the same domain-separated hash.
pub fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    trusted_merkle_hash::hash_internal_rfc6962(left, right)
}

impl MerkleTree {
    /// Create a new empty Merkle tree that stores leaf hashes at the given path.
    pub fn new(leaf_file_path: PathBuf) -> Self {
        Self {
            leaf_count: 0,
            peaks: Vec::new(),
            leaf_file_path,
            max_leaf_count: DEFAULT_MAX_LEAF_COUNT,
        }
    }

    /// Set a custom maximum leaf count.
    /// SECURITY (FIND-R46-001): Configure the OOM protection threshold.
    pub fn with_max_leaf_count(mut self, max: u64) -> Self {
        self.max_leaf_count = max;
        self
    }

    /// Return the number of leaves in the tree.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Append a leaf hash to the tree.
    ///
    /// The leaf hash is persisted to the binary leaf file and the in-memory
    /// peaks are updated. This is O(log n) amortized.
    pub fn append(&mut self, leaf_hash: [u8; 32]) -> Result<(), AuditError> {
        // SECURITY (FIND-R46-001): Reject appends that would exceed the max leaf count.
        if !verified_merkle::append_allowed(self.leaf_count, self.max_leaf_count) {
            return Err(AuditError::Validation(format!(
                "Merkle tree leaf count limit reached ({} >= {})",
                self.leaf_count, self.max_leaf_count
            )));
        }

        // Persist the leaf hash to the binary file.
        trusted_audit_fs::append_bytes_sync(
            &self.leaf_file_path,
            &leaf_hash,
            trusted_audit_fs::Durability::SyncData,
            "Merkle leaf file",
        )?;

        // Update peaks: carry-merge like binary addition
        let mut carry = leaf_hash;
        let mut level = 0usize;
        loop {
            if level >= self.peaks.len() {
                self.peaks.push(Some(carry));
                break;
            }
            match self.peaks[level].take() {
                Some(existing) => {
                    // Merge: existing is the left child, carry is the right
                    carry = hash_internal(&existing, &carry);
                    level += 1;
                }
                None => {
                    self.peaks[level] = Some(carry);
                    break;
                }
            }
        }

        // SECURITY (FIND-R186-006): saturating_add for coding standard compliance.
        self.leaf_count = self.leaf_count.saturating_add(1);
        Ok(())
    }

    /// Compute the current root hash.
    ///
    /// Folds peaks low-to-high: the smallest sub-tree (lowest peak) starts
    /// as the accumulator, and each higher peak is placed on the left.
    /// This matches the RFC 6962 / standard binary Merkle tree structure
    /// where the split is at the largest power of 2 less than n.
    /// Returns `None` if the tree is empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.leaf_count == 0 {
            return None;
        }

        let mut root: Option<[u8; 32]> = None;
        // Iterate from lowest peak to highest; accumulator goes on the right
        for p in self.peaks.iter().flatten() {
            root = Some(match root {
                Some(r) => verified_merkle_fold::fold_peak_into_root(*p, r),
                None => *p,
            });
        }
        root
    }

    /// Return the current root hash as a hex string, or `None` if empty.
    pub fn root_hex(&self) -> Option<String> {
        self.root().map(trusted_merkle_hash::encode_hash_hex)
    }

    /// Reset the tree state for log rotation.
    ///
    /// Clears in-memory peaks and leaf count. Does NOT delete the leaf file
    /// (the caller is responsible for renaming it alongside the rotated log).
    pub fn reset(&mut self) {
        self.leaf_count = 0;
        self.peaks.clear();
    }

    /// Rebuild the in-memory peaks from an existing leaf file.
    ///
    /// Call this at startup to recover state after a crash. If the leaf file
    /// has a partial write (not a multiple of 32 bytes), the trailing bytes
    /// are truncated.
    pub fn initialize(&mut self) -> Result<(), AuditError> {
        self.leaf_count = 0;
        self.peaks.clear();

        // SECURITY (FIND-R46-001/002): Check file size before reading to prevent OOM.
        match trusted_audit_fs::metadata_if_exists_sync(&self.leaf_file_path)? {
            Some(meta) => {
                // SECURITY (R239-AUD-1): Use saturating_mul to prevent overflow.
                let max_file_size = self.max_leaf_count.saturating_mul(HASH_SIZE as u64);
                if meta.len() > max_file_size {
                    return Err(AuditError::Validation(format!(
                        "Merkle leaf file too large ({} bytes, max {} bytes for {} leaves)",
                        meta.len(),
                        max_file_size,
                        self.max_leaf_count
                    )));
                }
            }
            None => return Ok(()),
        }

        let data = match trusted_audit_fs::read_if_exists_sync(&self.leaf_file_path)? {
            Some(data) => data,
            None => return Ok(()),
        };

        // Truncate partial writes
        let valid_len = (data.len() / HASH_SIZE) * HASH_SIZE;
        if valid_len < data.len() {
            tracing::warn!(
                path = %self.leaf_file_path.display(),
                file_len = data.len(),
                valid_len = valid_len,
                "Merkle leaf file has partial write, truncating to last complete hash"
            );
            // Truncate the file to remove partial write
            trusted_audit_fs::truncate_file_sync(&self.leaf_file_path, valid_len as u64)?;
        }

        // SECURITY (FIND-R46-001): Check leaf count before replaying.
        let leaf_count = (valid_len / HASH_SIZE) as u64;
        if !verified_merkle::stored_leaf_count_valid(leaf_count, self.max_leaf_count) {
            return Err(AuditError::Validation(format!(
                "Merkle leaf file contains too many leaves ({} > {})",
                leaf_count, self.max_leaf_count
            )));
        }

        // Replay leaf hashes into peaks (without re-writing to file)
        for chunk in data[..valid_len].chunks_exact(HASH_SIZE) {
            let mut leaf_hash = [0u8; 32];
            leaf_hash.copy_from_slice(chunk);
            self.replay_leaf(leaf_hash);
        }

        Ok(())
    }

    /// Replay a leaf hash into peaks without writing to the leaf file.
    /// Used during initialization from an existing leaf file.
    fn replay_leaf(&mut self, leaf_hash: [u8; 32]) {
        let mut carry = leaf_hash;
        let mut level = 0usize;
        loop {
            if level >= self.peaks.len() {
                self.peaks.push(Some(carry));
                break;
            }
            match self.peaks[level].take() {
                Some(existing) => {
                    carry = hash_internal(&existing, &carry);
                    level += 1;
                }
                None => {
                    self.peaks[level] = Some(carry);
                    break;
                }
            }
        }
        // SECURITY (FIND-R186-006): saturating_add for coding standard compliance.
        self.leaf_count = self.leaf_count.saturating_add(1);
    }

    /// Generate an inclusion proof for the leaf at `index`.
    ///
    /// Reads leaf hashes from the binary file and computes the sibling
    /// path from the leaf to the root. The proof can be verified without
    /// access to the full tree.
    pub fn generate_proof(&self, index: u64) -> Result<MerkleProof, AuditError> {
        if index >= self.leaf_count {
            return Err(AuditError::Validation(format!(
                "Leaf index {} out of range (tree has {} leaves)",
                index, self.leaf_count
            )));
        }

        let root = self.root().ok_or_else(|| {
            AuditError::Validation("Cannot generate proof for empty tree".to_string())
        })?;

        // SECURITY (FIND-R46-004): Check file size before reading to prevent OOM.
        let file_meta = trusted_audit_fs::metadata_required_sync(&self.leaf_file_path)?;
        // SECURITY (R239-AUD-1): Use saturating_mul to prevent overflow.
        let max_file_size = self.max_leaf_count.saturating_mul(HASH_SIZE as u64);
        if file_meta.len() > max_file_size {
            return Err(AuditError::Validation(format!(
                "Merkle leaf file too large for proof generation ({} bytes, max {} bytes)",
                file_meta.len(),
                max_file_size
            )));
        }

        // Read all leaf hashes from the file
        let data = trusted_audit_fs::read_required_sync(&self.leaf_file_path)?;
        // SECURITY (R235-AUD-3): Use try_from instead of `as usize` to prevent
        // silent truncation on 32-bit platforms.
        let n = usize::try_from(self.leaf_count).map_err(|_| {
            AuditError::Validation(format!(
                "leaf_count {} exceeds platform usize capacity",
                self.leaf_count
            ))
        })?;
        if data.len() < n * HASH_SIZE {
            return Err(AuditError::Validation(
                "Leaf file is shorter than expected".to_string(),
            ));
        }

        let leaves: Vec<[u8; 32]> = data[..n * HASH_SIZE]
            .chunks_exact(HASH_SIZE)
            .map(|chunk| {
                let mut h = [0u8; 32];
                h.copy_from_slice(chunk);
                h
            })
            .collect();

        // Build the proof by walking up the tree
        let idx = usize::try_from(index).map_err(|_| {
            AuditError::Validation(format!(
                "leaf index {index} exceeds platform usize capacity"
            ))
        })?;
        let siblings = self.compute_siblings(&leaves, idx)?;

        Ok(MerkleProof {
            leaf_index: index,
            tree_size: self.leaf_count,
            siblings,
            root_hash: trusted_merkle_hash::encode_hash_hex(root),
        })
    }

    /// Compute the sibling path for a leaf at the given index.
    ///
    /// This handles the general case of non-power-of-2 trees by
    /// building sub-trees from the binary decomposition of n.
    ///
    /// ## Edge Cases (GAP-S07)
    ///
    /// - **Empty tree** (`n == 0`): returns empty sibling list.
    /// - **Single leaf** (`n == 1`): returns empty sibling list (the leaf IS the root).
    /// - **Odd node at level boundary**: promoted without a sibling, so no ProofStep
    ///   is emitted for that level.
    fn compute_siblings(
        &self,
        leaves: &[[u8; 32]],
        index: usize,
    ) -> Result<Vec<ProofStep>, AuditError> {
        let n = leaves.len();
        if n == 0 || n == 1 {
            return Ok(Vec::new());
        }

        // Build the full hash tree level by level
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
        levels.push(leaves.to_vec());

        let mut current = leaves.to_vec();
        while current.len() > 1 {
            let next = verified_merkle_fold::next_level_hashes(&current);
            levels.push(next.clone());
            current = next;
        }

        // Walk from the leaf level upward, collecting siblings
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &levels[..levels.len() - 1] {
            if verified_merkle_path::proof_level_has_sibling(idx, level.len()) {
                let sibling_idx = verified_merkle_path::proof_sibling_index(idx);
                siblings.push(ProofStep {
                    hash: trusted_merkle_hash::encode_hash_hex(level[sibling_idx]),
                    is_left: verified_merkle_path::proof_step_is_left(idx),
                });
            }
            // A trailing odd node is promoted unchanged and emits no ProofStep.
            idx = verified_merkle_path::proof_parent_index(idx);
        }

        Ok(siblings)
    }

    /// Verify a Merkle inclusion proof against a trusted root.
    ///
    /// This is a static method — it requires no disk access, only the
    /// leaf hash, the proof, and a trusted root hash (hex-encoded) obtained
    /// from the Merkle tree state or a signed checkpoint.
    ///
    /// SECURITY (FIND-R46-MRK-002): The `trusted_root` parameter MUST come
    /// from a trusted source (e.g., the live Merkle tree or a signed checkpoint),
    /// NOT from the proof itself. Comparing against the proof's own `root_hash`
    /// would allow an attacker to forge self-consistent proofs.
    pub fn verify_proof(
        leaf_hash: [u8; 32],
        proof: &MerkleProof,
        trusted_root: &str,
    ) -> Result<MerkleVerification, AuditError> {
        // SECURITY (FIND-R52-AUDIT-003): Bound proof siblings to 64. A tree with
        // 2^64 leaves is physically impossible, so any proof claiming more siblings
        // is malicious or corrupt. This prevents CPU waste iterating forged proofs.
        if !verified_merkle::proof_sibling_count_valid(proof.siblings.len()) {
            return Err(AuditError::Validation(format!(
                "Proof has too many siblings ({}, max {})",
                proof.siblings.len(),
                verified_merkle::MAX_PROOF_SIBLINGS
            )));
        }

        if !verified_merkle::proof_tree_size_valid(proof.tree_size) {
            return Ok(MerkleVerification {
                valid: false,
                failure_reason: Some("Proof has zero tree size".to_string()),
            });
        }

        if !verified_merkle::proof_leaf_index_valid(proof.leaf_index, proof.tree_size) {
            return Ok(MerkleVerification {
                valid: false,
                failure_reason: Some(format!(
                    "Leaf index {} >= tree size {}",
                    proof.leaf_index, proof.tree_size
                )),
            });
        }

        let mut current = leaf_hash;
        for step in &proof.siblings {
            let sibling = trusted_merkle_hash::decode_hash_hex(&step.hash)?;
            if !verified_merkle::sibling_hash_len_valid(sibling.len()) {
                return Ok(MerkleVerification {
                    valid: false,
                    failure_reason: Some(format!(
                        "Sibling hash has wrong length: {} (expected {})",
                        sibling.len(),
                        HASH_SIZE
                    )),
                });
            }
            let mut sibling_arr = [0u8; 32];
            sibling_arr.copy_from_slice(&sibling);

            current = verified_merkle_fold::fold_proof_step(
                current,
                sibling_arr,
                verified_merkle_path::proof_step_places_sibling_left(step.is_left),
            );
        }

        if trusted_merkle_hash::hash_matches_trusted_root(current, trusted_root) {
            Ok(MerkleVerification {
                valid: true,
                failure_reason: None,
            })
        } else {
            let computed_root = trusted_merkle_hash::encode_hash_hex(current);
            Ok(MerkleVerification {
                valid: false,
                failure_reason: Some(format!(
                    "Root mismatch: computed {computed_root} but trusted root is {trusted_root}"
                )),
            })
        }
    }

    /// Return the path to the leaf file.
    pub fn leaf_file_path(&self) -> &std::path::Path {
        &self.leaf_file_path
    }
}

#[cfg(test)]
mod verus_integrity_differential {
    //! Differential binding for `PARITY-HAND-1`, kernel
    //! `formal/verus/verified_merkle_integrity.rs`.
    //!
    //! That kernel declares no spec functions of its own — it is twelve proof
    //! obligations restating the trusted Merkle axioms (`MERKLE-HASH-1/2`,
    //! `MERKLE-CODEC-1`) and deriving consequences from them.
    //!
    //! The axioms stay trusted; they are registered in the allowlist and are
    //! about SHA-256's collision and second-preimage resistance, which no test
    //! can establish. What *is* checkable is that the **consequences** hold of
    //! the shipped hashing: RFC 6962 domain separation, the 32-byte lengths,
    //! codec round-tripping and injectivity, and that a changed leaf changes
    //! its parent and grandparent.
    //!
    //! So this is a property discharge of the derived layer, with the
    //! cryptographic assumptions left where they belong — named, not tested.

    use super::*;

    fn corpus() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x01],
            b"a".to_vec(),
            b"b".to_vec(),
            b"audit-entry-1".to_vec(),
            b"audit-entry-2".to_vec(),
            vec![0xff; 64],
        ]
    }

    /// `lemma_leaf_hash_len_is_32` / `lemma_internal_hash_len_is_32`.
    #[test]
    fn test_hash_outputs_are_always_32_bytes() {
        for d in corpus() {
            assert_eq!(
                hash_leaf(&d).len(),
                32,
                "PARITY-HAND-1: leaf hash of {d:?} is not 32 bytes"
            );
        }
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        assert_eq!(hash_internal(&a, &b).len(), 32);
    }

    /// `lemma_leaf_and_internal_hash_never_equal` and
    /// `lemma_no_type_confusion_in_proof` — RFC 6962 domain separation. Without
    /// distinct prefixes an attacker can present an internal node as a leaf and
    /// forge an inclusion proof for data that was never logged.
    #[test]
    fn test_leaf_and_internal_hashes_are_domain_separated() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let internal = hash_internal(&a, &b);

        // The concatenation an attacker would try to pass off as leaf data.
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&b);

        assert_ne!(
            internal,
            hash_leaf(&concat),
            "PARITY-HAND-1: an internal node hashes identically to a leaf over the same bytes — \
             domain separation is missing and inclusion proofs can be forged by type confusion"
        );

        // And no leaf in the corpus collides with the internal node either.
        for d in corpus() {
            assert_ne!(
                hash_leaf(&d),
                internal,
                "PARITY-HAND-1: leaf {d:?} collides with an internal node hash"
            );
        }

        // The RFC 6962 second-preimage attack itself. Without the *leaf*
        // prefix, hash_leaf(0x01 || a || b) reduces to SHA-256(0x01 || a || b),
        // which is exactly hash_internal(a, b) — so an attacker submits an
        // internal node's preimage as leaf data and the tree cannot tell them
        // apart. Mutation testing found this: dropping the leaf prefix passed
        // every other case here, because the internal prefix alone still kept
        // plain concatenations distinct.
        let mut forged_leaf = Vec::with_capacity(65);
        forged_leaf.push(0x01);
        forged_leaf.extend_from_slice(&a);
        forged_leaf.extend_from_slice(&b);
        assert_ne!(
            hash_leaf(&forged_leaf),
            internal,
            "PARITY-HAND-1: a leaf carrying an internal node's preimage hashes to that node — \
             the RFC 6962 leaf prefix is missing and second-preimage forgery is possible"
        );
    }

    /// `lemma_leaf_hash_unique` / `lemma_internal_hash_unique`, in the only
    /// direction a test can establish: distinct inputs in this corpus produce
    /// distinct digests. The converse — that no collision exists anywhere — is
    /// `MERKLE-HASH-2` and stays trusted.
    #[test]
    fn test_distinct_inputs_give_distinct_hashes_in_the_corpus() {
        let c = corpus();
        for (i, x) in c.iter().enumerate() {
            for (j, y) in c.iter().enumerate() {
                if i < j {
                    assert_ne!(
                        hash_leaf(x),
                        hash_leaf(y),
                        "PARITY-HAND-1: distinct leaves {x:?} and {y:?} share a digest"
                    );
                }
            }
        }
    }

    /// `lemma_internal_hash_unique` in its argument-order sense: swapping left
    /// and right must change the parent, or the tree shape carries no
    /// information and a proof can be replayed against a reordered tree.
    #[test]
    fn test_internal_hash_is_order_sensitive() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        assert_ne!(
            hash_internal(&a, &b),
            hash_internal(&b, &a),
            "PARITY-HAND-1: hash_internal is order-insensitive, so sibling order carries no \
             information and an inclusion proof can be replayed against a reordered tree"
        );
    }

    /// `lemma_different_leaf_means_different_parent` and
    /// `..._grandparent` — a change to any leaf must propagate to the root.
    /// This is the tamper-evidence property the whole structure exists for.
    #[test]
    fn test_a_changed_leaf_changes_parent_and_grandparent() {
        let a = hash_leaf(b"audit-entry-1");
        let a_tampered = hash_leaf(b"audit-entry-2");
        let b = hash_leaf(b"sibling");
        let c = hash_leaf(b"uncle");

        let parent = hash_internal(&a, &b);
        let parent_tampered = hash_internal(&a_tampered, &b);
        assert_ne!(
            parent, parent_tampered,
            "PARITY-HAND-1: changing a leaf did not change its parent"
        );

        let grandparent = hash_internal(&parent, &c);
        let grandparent_tampered = hash_internal(&parent_tampered, &c);
        assert_ne!(
            grandparent, grandparent_tampered,
            "PARITY-HAND-1: changing a leaf did not propagate to the grandparent — tampering \
             would not reach the root"
        );
    }

    /// `lemma_codec_roundtrip`, `lemma_decoded_hash_len` and
    /// `lemma_encoding_injective` (`MERKLE-CODEC-1`). K141/K142 discharge the
    /// per-byte roundtrip under Kani; this checks the whole-digest form against
    /// the encoding production actually uses.
    #[test]
    fn test_hex_codec_roundtrips_and_is_injective() {
        let mut seen = std::collections::HashSet::new();
        for d in corpus() {
            let h = hash_leaf(&d);
            let encoded = hex::encode(h);
            assert_eq!(
                encoded.len(),
                64,
                "PARITY-HAND-1: a 32-byte hash did not encode to 64 hex chars"
            );

            let decoded = hex::decode(&encoded).expect("round-trip decode");
            assert_eq!(
                decoded.len(),
                32,
                "PARITY-HAND-1: decoded hash is not 32 bytes"
            );
            assert_eq!(
                decoded.as_slice(),
                h.as_slice(),
                "PARITY-HAND-1: hex round-trip did not preserve the digest"
            );
            assert!(
                seen.insert(encoded),
                "PARITY-HAND-1: two distinct digests encoded to the same string — encoding is \
                 not injective"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // The properties are only meaningful if the hashes genuinely differ.
        assert_ne!(hash_leaf(b"a"), hash_leaf(b"b"));
        assert_eq!(hash_leaf(b"a"), hash_leaf(b"a"));
        let a = hash_leaf(b"a");
        assert_ne!(hash_internal(&a, &a), a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_tree() -> (MerkleTree, TempDir) {
        let tmp = TempDir::new().expect("temp dir");
        let leaf_path = tmp.path().join("test.merkle-leaves");
        let tree = MerkleTree::new(leaf_path);
        (tree, tmp)
    }

    // ── hash_leaf vs hash_internal domain separation ────────────────

    #[test]
    fn test_hash_leaf_vs_hash_internal_different() {
        // RFC 6962 domain separation: hash_leaf(data) != hash_internal(data, data)
        let data = [0xABu8; 32];
        let leaf = hash_leaf(&data);
        let internal = hash_internal(&data, &data);
        assert_ne!(
            leaf, internal,
            "Leaf and internal hashes must differ (domain separation)"
        );
    }

    #[test]
    fn test_hash_leaf_deterministic() {
        let data = [0x42u8; 32];
        let h1 = hash_leaf(&data);
        let h2 = hash_leaf(&data);
        assert_eq!(h1, h2, "hash_leaf must be deterministic");
    }

    #[test]
    fn test_hash_internal_deterministic() {
        let left = [0x01u8; 32];
        let right = [0x02u8; 32];
        let h1 = hash_internal(&left, &right);
        let h2 = hash_internal(&left, &right);
        assert_eq!(h1, h2, "hash_internal must be deterministic");
    }

    #[test]
    fn test_hash_internal_order_matters() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let h1 = hash_internal(&a, &b);
        let h2 = hash_internal(&b, &a);
        assert_ne!(h1, h2, "hash_internal(a,b) != hash_internal(b,a)");
    }

    #[test]
    fn test_verify_proof_invalid_sibling_hex_rejected() {
        let proof = MerkleProof {
            leaf_index: 0,
            tree_size: 1,
            siblings: vec![ProofStep {
                hash: "zz".to_string(),
                is_left: false,
            }],
            root_hash: "0".repeat(64),
        };

        let err = MerkleTree::verify_proof([0u8; 32], &proof, &"0".repeat(64))
            .expect_err("invalid sibling hex");
        match err {
            AuditError::Validation(msg) => assert!(msg.contains("Invalid sibling hash hex")),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    // ── Basic tree operations ───────────────────────────────────────

    #[test]
    fn test_empty_tree_root_is_none() {
        let (tree, _tmp) = make_tree();
        assert!(tree.root().is_none());
        assert!(tree.root_hex().is_none());
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_append_single_leaf() {
        let (mut tree, _tmp) = make_tree();
        let leaf = hash_leaf(&[1u8; 32]);
        tree.append(leaf).expect("append");
        assert_eq!(tree.leaf_count(), 1);
        assert!(tree.root().is_some());
        // Single leaf: root == the leaf hash itself
        assert_eq!(tree.root().expect("root"), leaf);
    }

    #[test]
    fn test_append_two_leaves_root() {
        let (mut tree, _tmp) = make_tree();
        let leaf0 = hash_leaf(&[0u8; 32]);
        let leaf1 = hash_leaf(&[1u8; 32]);
        tree.append(leaf0).expect("append 0");
        tree.append(leaf1).expect("append 1");
        assert_eq!(tree.leaf_count(), 2);
        let expected_root = hash_internal(&leaf0, &leaf1);
        assert_eq!(tree.root().expect("root"), expected_root);
    }

    #[test]
    fn test_append_three_leaves_root() {
        let (mut tree, _tmp) = make_tree();
        let leaf0 = hash_leaf(&[0u8; 32]);
        let leaf1 = hash_leaf(&[1u8; 32]);
        let leaf2 = hash_leaf(&[2u8; 32]);
        tree.append(leaf0).expect("append 0");
        tree.append(leaf1).expect("append 1");
        tree.append(leaf2).expect("append 2");
        assert_eq!(tree.leaf_count(), 3);
        // For 3 leaves: peaks are [None (level 0 = leaf2), Some(internal(leaf0, leaf1)) at level 1]
        // Root = hash_internal(peaks[1], peaks[0]) = hash_internal(hash_internal(leaf0, leaf1), leaf2)
        let internal_01 = hash_internal(&leaf0, &leaf1);
        let expected_root = hash_internal(&internal_01, &leaf2);
        assert_eq!(tree.root().expect("root"), expected_root);
    }

    #[test]
    fn test_root_hex_format() {
        let (mut tree, _tmp) = make_tree();
        let leaf = hash_leaf(&[42u8; 32]);
        tree.append(leaf).expect("append");
        let hex_root = tree.root_hex().expect("root_hex");
        assert_eq!(hex_root.len(), 64, "SHA-256 hex should be 64 chars");
        assert!(hex_root.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── Proof generation and verification ───────────────────────────

    #[test]
    fn test_proof_single_leaf() {
        let (mut tree, _tmp) = make_tree();
        let data = [0xAAu8; 32];
        let leaf = hash_leaf(&data);
        tree.append(leaf).expect("append");

        let proof = tree.generate_proof(0).expect("proof");
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.tree_size, 1);
        assert!(proof.siblings.is_empty(), "Single leaf needs no siblings");

        let trusted_root = tree.root_hex().expect("root");
        let result = MerkleTree::verify_proof(leaf, &proof, &trusted_root).expect("verify");
        assert!(result.valid, "Proof for single leaf should verify");
    }

    #[test]
    fn test_proof_two_leaves() {
        let (mut tree, _tmp) = make_tree();
        let leaf0 = hash_leaf(&[0u8; 32]);
        let leaf1 = hash_leaf(&[1u8; 32]);
        tree.append(leaf0).expect("append 0");
        tree.append(leaf1).expect("append 1");

        let trusted_root = tree.root_hex().expect("root");

        // Proof for leaf 0
        let proof0 = tree.generate_proof(0).expect("proof 0");
        let result0 = MerkleTree::verify_proof(leaf0, &proof0, &trusted_root).expect("verify 0");
        assert!(result0.valid, "Proof for leaf 0 should verify");

        // Proof for leaf 1
        let proof1 = tree.generate_proof(1).expect("proof 1");
        let result1 = MerkleTree::verify_proof(leaf1, &proof1, &trusted_root).expect("verify 1");
        assert!(result1.valid, "Proof for leaf 1 should verify");
    }

    #[test]
    fn test_proof_four_leaves() {
        let (mut tree, _tmp) = make_tree();
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| hash_leaf(&[i; 32])).collect();
        for leaf in &leaves {
            tree.append(*leaf).expect("append");
        }

        let trusted_root = tree.root_hex().expect("root");
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(idx as u64).expect("proof");
            let result = MerkleTree::verify_proof(*leaf, &proof, &trusted_root).expect("verify");
            assert!(result.valid, "Proof for leaf {idx} should verify");
        }
    }

    #[test]
    fn test_proof_five_leaves_non_power_of_two() {
        let (mut tree, _tmp) = make_tree();
        let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| hash_leaf(&[i; 32])).collect();
        for leaf in &leaves {
            tree.append(*leaf).expect("append");
        }

        let trusted_root = tree.root_hex().expect("root");
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(idx as u64).expect("proof");
            let result = MerkleTree::verify_proof(*leaf, &proof, &trusted_root).expect("verify");
            assert!(
                result.valid,
                "Proof for leaf {idx} (5-leaf tree) should verify"
            );
        }
    }

    #[test]
    fn test_proof_three_leaves_promoted_tail_skips_first_level() {
        let (mut tree, _tmp) = make_tree();
        let leaves: Vec<[u8; 32]> = (0..3u8).map(|i| hash_leaf(&[i; 32])).collect();
        for leaf in &leaves {
            tree.append(*leaf).expect("append");
        }

        let proof = tree.generate_proof(2).expect("proof");
        assert_eq!(
            proof.siblings.len(),
            1,
            "promoted tail should skip one level"
        );
        assert!(
            proof.siblings[0].is_left,
            "promoted tail should meet a left sibling at the parent level"
        );
    }

    #[test]
    fn test_proof_four_leaves_encodes_left_right_directions() {
        let (mut tree, _tmp) = make_tree();
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| hash_leaf(&[i; 32])).collect();
        for leaf in &leaves {
            tree.append(*leaf).expect("append");
        }

        let proof = tree.generate_proof(1).expect("proof");
        assert_eq!(proof.siblings.len(), 2);
        assert!(
            proof.siblings[0].is_left,
            "leaf 1 first meets leaf 0 on the left"
        );
        assert!(
            !proof.siblings[1].is_left,
            "the parent of leaves 0/1 then meets the right subtree on the right"
        );
    }

    #[test]
    fn test_proof_wrong_root_fails() {
        let (mut tree, _tmp) = make_tree();
        let leaf = hash_leaf(&[0u8; 32]);
        tree.append(leaf).expect("append");

        let proof = tree.generate_proof(0).expect("proof");
        let wrong_root = "0".repeat(64);
        let result = MerkleTree::verify_proof(leaf, &proof, &wrong_root).expect("verify");
        assert!(!result.valid, "Wrong root should fail verification");
        assert!(result.failure_reason.is_some());
    }

    #[test]
    fn test_proof_out_of_range_rejected() {
        let (mut tree, _tmp) = make_tree();
        let leaf = hash_leaf(&[0u8; 32]);
        tree.append(leaf).expect("append");

        let err = tree.generate_proof(1).expect_err("out of range");
        match err {
            AuditError::Validation(msg) => {
                assert!(msg.contains("out of range"));
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    // ── verify_proof edge cases ─────────────────────────────────────

    #[test]
    fn test_verify_proof_zero_tree_size() {
        let proof = MerkleProof {
            leaf_index: 0,
            tree_size: 0,
            siblings: vec![],
            root_hash: "0".repeat(64),
        };
        let result = MerkleTree::verify_proof([0u8; 32], &proof, &"0".repeat(64)).expect("verify");
        assert!(!result.valid);
        assert!(result
            .failure_reason
            .as_ref()
            .expect("reason")
            .contains("zero tree size"));
    }

    #[test]
    fn test_verify_proof_leaf_index_ge_tree_size() {
        let proof = MerkleProof {
            leaf_index: 5,
            tree_size: 3,
            siblings: vec![],
            root_hash: "0".repeat(64),
        };
        let result = MerkleTree::verify_proof([0u8; 32], &proof, &"0".repeat(64)).expect("verify");
        assert!(!result.valid);
        assert!(result
            .failure_reason
            .as_ref()
            .expect("reason")
            .contains(">="));
    }

    #[test]
    fn test_verify_proof_too_many_siblings_rejected() {
        let siblings: Vec<ProofStep> = (0..65)
            .map(|_| ProofStep {
                hash: "0".repeat(64),
                is_left: false,
            })
            .collect();
        let proof = MerkleProof {
            leaf_index: 0,
            tree_size: 1,
            siblings,
            root_hash: "0".repeat(64),
        };
        let err = MerkleTree::verify_proof([0u8; 32], &proof, &"0".repeat(64))
            .expect_err("too many siblings");
        match err {
            AuditError::Validation(msg) => {
                assert!(msg.contains("too many siblings"));
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_merkle_proof_deny_unknown_fields() {
        let json = r#"{
            "leaf_index": 0,
            "tree_size": 1,
            "siblings": [],
            "root_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "extra": true
        }"#;

        let result: Result<MerkleProof, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_step_deny_unknown_fields() {
        let json = r#"{
            "hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "is_left": false,
            "extra": true
        }"#;

        let result: Result<ProofStep, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_verification_deny_unknown_fields() {
        let json = r#"{
            "valid": true,
            "failure_reason": null,
            "extra": true
        }"#;

        let result: Result<MerkleVerification, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ── Crash recovery (initialize) ─────────────────────────────────

    #[test]
    fn test_initialize_recovers_from_leaf_file() {
        let tmp = TempDir::new().expect("temp dir");
        let leaf_path = tmp.path().join("test.merkle-leaves");

        // Build a tree with 4 leaves
        let mut tree1 = MerkleTree::new(leaf_path.clone());
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| hash_leaf(&[i; 32])).collect();
        for leaf in &leaves {
            tree1.append(*leaf).expect("append");
        }
        let root1 = tree1.root_hex().expect("root");

        // Create a new tree from the same leaf file
        let mut tree2 = MerkleTree::new(leaf_path);
        tree2.initialize().expect("initialize");
        assert_eq!(tree2.leaf_count(), 4);
        let root2 = tree2.root_hex().expect("root");
        assert_eq!(root1, root2, "Recovered root should match original");
    }

    #[test]
    fn test_initialize_truncates_partial_write() {
        let tmp = TempDir::new().expect("temp dir");
        let leaf_path = tmp.path().join("test.merkle-leaves");

        // Write a valid leaf + 10 trailing bytes (simulating a crash mid-write)
        let leaf = hash_leaf(&[0u8; 32]);
        let mut data = leaf.to_vec();
        data.extend_from_slice(&[0xFF; 10]); // partial write
        std::fs::write(&leaf_path, &data).expect("write");

        let mut tree = MerkleTree::new(leaf_path.clone());
        tree.initialize().expect("initialize");
        assert_eq!(tree.leaf_count(), 1, "Should have only 1 complete leaf");

        // Verify the file was truncated
        let meta = std::fs::metadata(&leaf_path).expect("metadata");
        assert_eq!(meta.len(), 32, "File should be truncated to 32 bytes");
    }

    #[test]
    fn test_initialize_nonexistent_file_ok() {
        let tmp = TempDir::new().expect("temp dir");
        let leaf_path = tmp.path().join("nonexistent.merkle-leaves");
        let mut tree = MerkleTree::new(leaf_path);
        tree.initialize().expect("initialize");
        assert_eq!(tree.leaf_count(), 0);
    }

    // ── Max leaf count enforcement ──────────────────────────────────

    #[test]
    fn test_append_rejects_at_max_leaf_count() {
        let tmp = TempDir::new().expect("temp dir");
        let leaf_path = tmp.path().join("test.merkle-leaves");
        let mut tree = MerkleTree::new(leaf_path).with_max_leaf_count(2);

        tree.append(hash_leaf(&[0u8; 32])).expect("append 0");
        tree.append(hash_leaf(&[1u8; 32])).expect("append 1");

        let err = tree
            .append(hash_leaf(&[2u8; 32]))
            .expect_err("should reject at limit");
        match err {
            AuditError::Validation(msg) => {
                assert!(msg.contains("limit reached"));
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    // ── Reset ───────────────────────────────────────────────────────

    #[test]
    fn test_reset_clears_state() {
        let (mut tree, _tmp) = make_tree();
        tree.append(hash_leaf(&[0u8; 32])).expect("append");
        tree.append(hash_leaf(&[1u8; 32])).expect("append");
        assert_eq!(tree.leaf_count(), 2);

        tree.reset();
        assert_eq!(tree.leaf_count(), 0);
        assert!(tree.root().is_none());
    }
}
