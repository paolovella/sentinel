// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Groth16 batch prover for audit chain proofs (Phase 37.2).
//!
//! Generates and verifies zero-knowledge proofs that a batch of audit entries
//! forms a valid hash chain, without revealing intermediate entry hashes.
//!
//! The prover operates over the BN254 pairing curve using the Groth16 proving
//! system from arkworks.

use std::fs;
use std::io::Cursor;
use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof as Groth16Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use sha2::{Digest, Sha256};

use super::circuit::{hash_to_field, AuditChainCircuit};
use super::witness::EntryWitness;
use super::ZkError;

/// Maximum allowed size for proving/verifying key files (64 MB).
///
/// Prevents OOM when loading untrusted key files from disk.
const MAX_KEY_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// Groth16 batch prover for audit chain integrity proofs.
///
/// Generates and verifies zero-knowledge proofs that a batch of audit
/// entries forms a valid hash chain, without revealing intermediate hashes.
///
/// The prover is initialized via `setup()` (one-time trusted setup) or
/// `from_files()` (load pre-computed keys). Keys can be saved with `save_keys()`.
///
/// SECURITY (IMP-R118-016): Custom Debug impl redacts `proving_key` (trusted
/// setup toxic waste). If Debug were derived, the proving key bytes would leak.
pub struct ZkBatchProver {
    proving_key: ProvingKey<Bn254>,
    verifying_key: VerifyingKey<Bn254>,
    max_batch_size: usize,
}

impl std::fmt::Debug for ZkBatchProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkBatchProver")
            .field("proving_key", &"[REDACTED]")
            .field("verifying_key", &"[REDACTED]")
            .field("max_batch_size", &self.max_batch_size)
            .finish()
    }
}

impl ZkBatchProver {
    /// Generate proving and verifying keys via Groth16 trusted setup.
    ///
    /// `max_batch_size` determines the maximum number of entries per batch proof.
    /// The circuit is parameterized at this size and smaller batches are padded.
    pub fn setup(max_batch_size: usize) -> Result<Self, ZkError> {
        if max_batch_size == 0 {
            return Err(ZkError::Key("max_batch_size must be > 0".to_string()));
        }

        let circuit = AuditChainCircuit::<Fr>::template(max_batch_size);
        let mut rng = ark_std::rand::rng();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ZkError::Key(format!("Groth16 setup failed: {}", e)))?;

        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
            max_batch_size,
        })
    }

    /// Load proving and verifying keys from serialized files.
    pub fn from_files(
        pk_path: &Path,
        vk_path: &Path,
        max_batch_size: usize,
    ) -> Result<Self, ZkError> {
        // SECURITY (FIND-R113-002): Check file sizes before reading to prevent OOM
        // on attacker-controlled key files.
        let pk_meta = fs::metadata(pk_path)
            .map_err(|e| ZkError::Key(format!("Failed to stat proving key: {}", e)))?;
        if pk_meta.len() > MAX_KEY_FILE_SIZE {
            return Err(ZkError::Key(format!(
                "Proving key file too large: {} bytes (max {})",
                pk_meta.len(),
                MAX_KEY_FILE_SIZE
            )));
        }
        let vk_meta = fs::metadata(vk_path)
            .map_err(|e| ZkError::Key(format!("Failed to stat verifying key: {}", e)))?;
        if vk_meta.len() > MAX_KEY_FILE_SIZE {
            return Err(ZkError::Key(format!(
                "Verifying key file too large: {} bytes (max {})",
                vk_meta.len(),
                MAX_KEY_FILE_SIZE
            )));
        }

        let pk_bytes = fs::read(pk_path)
            .map_err(|e| ZkError::Key(format!("Failed to read proving key: {}", e)))?;
        let vk_bytes = fs::read(vk_path)
            .map_err(|e| ZkError::Key(format!("Failed to read verifying key: {}", e)))?;

        let proving_key = ProvingKey::<Bn254>::deserialize_compressed(&mut Cursor::new(&pk_bytes))
            .map_err(|e| ZkError::Serialization(format!("PK deserialization failed: {}", e)))?;
        let verifying_key =
            VerifyingKey::<Bn254>::deserialize_compressed(&mut Cursor::new(&vk_bytes))
                .map_err(|e| ZkError::Serialization(format!("VK deserialization failed: {}", e)))?;

        Ok(Self {
            proving_key,
            verifying_key,
            max_batch_size,
        })
    }

    /// Save proving and verifying keys to files.
    pub fn save_keys(&self, pk_path: &Path, vk_path: &Path) -> Result<(), ZkError> {
        let mut pk_bytes = Vec::new();
        self.proving_key
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| ZkError::Serialization(format!("PK serialization failed: {}", e)))?;
        fs::write(pk_path, &pk_bytes)
            .map_err(|e| ZkError::Key(format!("Failed to write proving key: {}", e)))?;

        let mut vk_bytes = Vec::new();
        self.verifying_key
            .serialize_compressed(&mut vk_bytes)
            .map_err(|e| ZkError::Serialization(format!("VK serialization failed: {}", e)))?;
        fs::write(vk_path, &vk_bytes)
            .map_err(|e| ZkError::Key(format!("Failed to write verifying key: {}", e)))?;

        Ok(())
    }

    /// Prove a batch of entry witnesses.
    ///
    /// The witnesses must be ordered by sequence number and form a valid chain.
    /// If the batch is smaller than `max_batch_size`, it is padded with the
    /// final entry hash to preserve chain linkage constraints.
    pub fn prove(
        &self,
        witnesses: &[EntryWitness],
    ) -> Result<vellaveto_types::ZkBatchProof, ZkError> {
        if witnesses.is_empty() {
            return Err(ZkError::Proof("Cannot prove empty batch".to_string()));
        }
        if witnesses.len() > self.max_batch_size {
            return Err(ZkError::Proof(format!(
                "Batch size {} exceeds max {}",
                witnesses.len(),
                self.max_batch_size
            )));
        }

        let actual_count = witnesses.len();

        // Convert witnesses to field elements
        let mut entry_hashes: Vec<Fr> = witnesses
            .iter()
            .map(|w| hash_to_field(&w.entry_hash))
            .collect();
        let mut prev_hashes: Vec<Fr> = witnesses
            .iter()
            .map(|w| hash_to_field(&w.prev_hash))
            .collect();

        // Public inputs
        let first_prev_hash = prev_hashes[0];
        let final_hash = entry_hashes[actual_count - 1];

        // Pad to max_batch_size with final_hash (preserves chain linkage)
        for _ in actual_count..self.max_batch_size {
            entry_hashes.push(final_hash);
            prev_hashes.push(final_hash);
        }

        // Build circuit with concrete witnesses
        let circuit = AuditChainCircuit::with_witnesses(
            self.max_batch_size,
            first_prev_hash,
            final_hash,
            entry_hashes,
            prev_hashes,
        )
        .map_err(|e| ZkError::Proof(format!("Circuit construction failed: {}", e)))?;

        // Generate proof
        let mut rng = ark_std::rand::rng();
        let proof = Groth16::<Bn254>::prove(&self.proving_key, circuit, &mut rng)
            .map_err(|e| ZkError::Proof(format!("Groth16 proving failed: {}", e)))?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| ZkError::Serialization(format!("Proof serialization failed: {}", e)))?;

        // Compute batch digest (SHA-256 over all entry hashes)
        let mut digest = Sha256::new();
        for w in witnesses {
            digest.update(w.entry_hash);
        }
        let merkle_root = hex::encode(digest.finalize());

        Ok(vellaveto_types::ZkBatchProof {
            proof: hex::encode(proof_bytes),
            batch_id: uuid::Uuid::new_v4().to_string(),
            entry_range: (witnesses[0].sequence, witnesses[actual_count - 1].sequence),
            merkle_root,
            first_prev_hash: hex::encode(witnesses[0].prev_hash),
            final_entry_hash: hex::encode(witnesses[actual_count - 1].entry_hash),
            created_at: chrono::Utc::now().to_rfc3339(),
            entry_count: actual_count,
        })
    }

    /// Verify a batch proof.
    ///
    /// Checks that the Groth16 proof is valid for the public inputs
    /// (first_prev_hash, final_entry_hash) embedded in the `ZkBatchProof`.
    pub fn verify(
        &self,
        batch_proof: &vellaveto_types::ZkBatchProof,
    ) -> Result<vellaveto_types::ZkVerifyResult, ZkError> {
        // Decode public inputs from proof
        let first_prev_bytes = hex_to_hash(&batch_proof.first_prev_hash)?;
        let final_hash_bytes = hex_to_hash(&batch_proof.final_entry_hash)?;

        let first_prev_field: Fr = hash_to_field(&first_prev_bytes);
        let final_hash_field: Fr = hash_to_field(&final_hash_bytes);

        // Decode proof
        let proof_bytes = hex::decode(&batch_proof.proof)
            .map_err(|e| ZkError::Serialization(format!("Proof hex decode failed: {}", e)))?;
        let groth16_proof = Groth16Proof::<Bn254>::deserialize_compressed(&mut Cursor::new(
            &proof_bytes,
        ))
        .map_err(|e| ZkError::Serialization(format!("Proof deserialization failed: {}", e)))?;

        // Public inputs must match the allocation order in generate_constraints:
        // [first_prev_hash, final_hash]
        let public_inputs = vec![first_prev_field, final_hash_field];

        let pvk = Groth16::<Bn254>::process_vk(&self.verifying_key)
            .map_err(|e| ZkError::Verification(format!("VK processing failed: {}", e)))?;

        let valid =
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &groth16_proof)
                .map_err(|e| ZkError::Verification(format!("Verification error: {}", e)))?;

        Ok(vellaveto_types::ZkVerifyResult {
            valid,
            batch_id: batch_proof.batch_id.clone(),
            entry_range: batch_proof.entry_range,
            verified_at: chrono::Utc::now().to_rfc3339(),
            error: if valid {
                None
            } else {
                Some("Proof verification failed".to_string())
            },
        })
    }

    /// Return the maximum batch size this prover supports.
    pub fn max_batch_size(&self) -> usize {
        self.max_batch_size
    }

    /// Return a reference to the verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.verifying_key
    }
}

/// Convert a hex string to a 32-byte hash array.
fn hex_to_hash(hex_str: &str) -> Result<[u8; 32], ZkError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ZkError::Serialization(format!("Hex decode failed: {}", e)))?;
    if bytes.len() != 32 {
        return Err(ZkError::Serialization(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
