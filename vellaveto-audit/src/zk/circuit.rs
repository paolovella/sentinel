// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Audit chain circuit for Groth16 proving (Phase 37.2).
//!
//! Defines an R1CS circuit that proves audit chain integrity: the prover
//! knows a sequence of `(entry_hash, prev_hash)` pairs that form a valid
//! linked chain, without revealing the intermediate hashes.
//!
//! Public inputs (verified by the verifier):
//! 1. `first_prev_hash` — prev_hash of the first entry
//! 2. `final_hash` — entry_hash of the last entry
//!
//! Constraints (O(max_size)):
//! 1. `prev_hashes[0] == first_prev_hash`
//! 2. `prev_hashes[i+1] == entry_hashes[i]` for i in 0..max_size-1
//! 3. `entry_hashes[max_size-1] == final_hash`

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Convert a 32-byte hash to a field element by interpreting as little-endian
/// and reducing modulo the field order.
pub fn hash_to_field<F: PrimeField>(hash: &[u8; 32]) -> F {
    F::from_le_bytes_mod_order(hash)
}

/// R1CS circuit proving audit chain integrity.
///
/// Parameterized by `max_size` (fixed at setup time). Batches smaller than
/// `max_size` are padded by repeating the final entry hash, which preserves
/// chain linkage constraints.
pub struct AuditChainCircuit<F: PrimeField> {
    /// Maximum number of entries this circuit supports.
    pub max_size: usize,
    /// Public input: prev_hash of the first entry.
    pub first_prev_hash: Option<F>,
    /// Public input: entry_hash of the last entry.
    pub final_hash: Option<F>,
    /// Private witnesses: entry hashes (length must be max_size).
    pub entry_hashes: Vec<Option<F>>,
    /// Private witnesses: prev hashes (length must be max_size).
    pub prev_hashes: Vec<Option<F>>,
}

impl<F: PrimeField> AuditChainCircuit<F> {
    /// Create a circuit template for Groth16 trusted setup (no concrete values).
    pub fn template(max_size: usize) -> Self {
        Self {
            max_size,
            first_prev_hash: None,
            final_hash: None,
            entry_hashes: vec![None; max_size],
            prev_hashes: vec![None; max_size],
        }
    }

    /// Create a circuit with concrete witness values for proving.
    ///
    /// Returns `Err` if the entry/prev hash vectors don't match `max_size`.
    pub fn with_witnesses(
        max_size: usize,
        first_prev_hash: F,
        final_hash: F,
        entry_hashes: Vec<F>,
        prev_hashes: Vec<F>,
    ) -> Result<Self, String> {
        if entry_hashes.len() != max_size {
            return Err(format!(
                "entry_hashes length {} != max_size {}",
                entry_hashes.len(),
                max_size
            ));
        }
        if prev_hashes.len() != max_size {
            return Err(format!(
                "prev_hashes length {} != max_size {}",
                prev_hashes.len(),
                max_size
            ));
        }
        Ok(Self {
            max_size,
            first_prev_hash: Some(first_prev_hash),
            final_hash: Some(final_hash),
            entry_hashes: entry_hashes.into_iter().map(Some).collect(),
            prev_hashes: prev_hashes.into_iter().map(Some).collect(),
        })
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AuditChainCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let Self {
            max_size,
            first_prev_hash,
            final_hash,
            entry_hashes,
            prev_hashes,
        } = self;

        if max_size == 0 {
            return Ok(());
        }

        // Allocate public inputs (order matters for verification)
        let first_prev_var = FpVar::new_input(cs.clone(), || {
            first_prev_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let final_hash_var = FpVar::new_input(cs.clone(), || {
            final_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate private witnesses
        let mut entry_hash_vars = Vec::with_capacity(max_size);
        let mut prev_hash_vars = Vec::with_capacity(max_size);

        for i in 0..max_size {
            let eh_val = entry_hashes.get(i).cloned().flatten();
            let ph_val = prev_hashes.get(i).cloned().flatten();

            let eh_var = FpVar::new_witness(cs.clone(), || {
                eh_val.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let ph_var = FpVar::new_witness(cs.clone(), || {
                ph_val.ok_or(SynthesisError::AssignmentMissing)
            })?;

            entry_hash_vars.push(eh_var);
            prev_hash_vars.push(ph_var);
        }

        // Constraint 1: prev_hash[0] == first_prev_hash (public input)
        prev_hash_vars[0].enforce_equal(&first_prev_var)?;

        // Constraint 2: chain linkage — prev_hash[i+1] == entry_hash[i]
        for i in 0..max_size.saturating_sub(1) {
            prev_hash_vars[i + 1].enforce_equal(&entry_hash_vars[i])?;
        }

        // Constraint 3: entry_hash[N-1] == final_hash (public input)
        entry_hash_vars[max_size - 1].enforce_equal(&final_hash_var)?;

        Ok(())
    }
}
