// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Shared Verus-facing names for the current trusted assumption registry.
//!
//! This module gives the standalone Verus kernels one shared place to
//! reference the currently reviewed trust boundary described in
//! `formal/ASSUMPTION_REGISTRY.md`.
//!
//! The predicates below are deliberately kernel-scoped. Each standalone Verus
//! file binds itself to the narrowest named trust boundary it currently needs,
//! and the trusted-assumption checker enforces that mapping.

#[path = "audit_fs_boundary_axioms.rs"]
pub mod audit_fs_boundary_axioms;
#[path = "float_boundary_axioms.rs"]
pub mod float_boundary_axioms;
#[path = "merkle_boundary_axioms.rs"]
pub mod merkle_boundary_axioms;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn assumption_verus_escape_1_registered() -> bool {
    true
}

pub open spec fn assumption_merkle_hash_1_registered() -> bool {
    true
}

pub open spec fn assumption_merkle_hash_2_registered() -> bool {
    true
}

pub open spec fn assumption_merkle_codec_1_registered() -> bool {
    true
}

pub open spec fn assumption_audit_fs_1_registered() -> bool {
    true
}

pub open spec fn assumption_audit_fs_2_registered() -> bool {
    true
}

pub open spec fn assumption_audit_fs_3_registered() -> bool {
    true
}

pub open spec fn assumption_audit_fs_4_registered() -> bool {
    true
}

pub open spec fn assumption_audit_fs_5_registered() -> bool {
    true
}

pub open spec fn merkle_trust_boundary_registered() -> bool {
    assumption_merkle_hash_1_registered()
        && assumption_merkle_hash_2_registered()
        && assumption_merkle_codec_1_registered()
        && merkle_boundary_axioms::merkle_boundary_axioms_hold()
}

pub open spec fn audit_filesystem_trust_boundary_registered() -> bool {
    assumption_audit_fs_1_registered()
        && assumption_audit_fs_2_registered()
        && assumption_audit_fs_3_registered()
        && assumption_audit_fs_4_registered()
        && assumption_audit_fs_5_registered()
        && audit_fs_boundary_axioms::audit_filesystem_boundary_axioms_hold()
}

pub open spec fn escape_hatch_inventory_registered() -> bool {
    assumption_verus_escape_1_registered()
}

pub open spec fn engine_core_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn constraint_eval_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn entropy_gate_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn entropy_pipeline_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn entropy_fixed_point_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
        && float_boundary_axioms::float_boundary_axioms_hold()
}

pub open spec fn dlp_core_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn cross_call_dlp_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn cross_call_split_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn path_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn deputy_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_chain_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_context_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_delegation_context_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_coverage_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_domain_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn context_delegation_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn bridge_principal_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn deputy_handoff_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn delegation_projection_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn evaluation_context_projection_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn transport_context_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn acis_envelope_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn approval_scope_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn approval_consumption_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn presented_approval_id_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn server_approval_id_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn approval_drift_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn transitive_revoke_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn evidence_signing_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn warm_restart_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_attenuation_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_grant_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_glob_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_glob_subset_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_identity_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_literal_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_pattern_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_path_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_selection_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn capability_verification_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn nhi_delegation_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn nhi_graph_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn refinement_safety_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn refinement_completeness_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn acis_action_summary_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn source_taint_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn intent_scope_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn sequence_analysis_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn audit_chain_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
}

pub open spec fn audit_integrity_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered() && audit_filesystem_trust_boundary_registered()
}

pub open spec fn merkle_integrity_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered() && merkle_trust_boundary_registered()
}

pub open spec fn audit_filesystem_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered() && audit_filesystem_trust_boundary_registered()
}

pub open spec fn merkle_kernel_assumptions_registered() -> bool {
    escape_hatch_inventory_registered() && merkle_trust_boundary_registered()
}

pub open spec fn audit_append_kernel_assumptions_registered() -> bool {
    audit_filesystem_kernel_assumptions_registered()
}

pub open spec fn merkle_guard_kernel_assumptions_registered() -> bool {
    merkle_kernel_assumptions_registered()
}

pub open spec fn merkle_fold_kernel_assumptions_registered() -> bool {
    merkle_kernel_assumptions_registered()
}

pub open spec fn merkle_path_kernel_assumptions_registered() -> bool {
    merkle_kernel_assumptions_registered()
}

pub open spec fn rotation_manifest_kernel_assumptions_registered() -> bool {
    audit_filesystem_kernel_assumptions_registered()
}

pub open spec fn shared_formal_assumptions_registered() -> bool {
    escape_hatch_inventory_registered()
        && merkle_trust_boundary_registered()
        && audit_filesystem_trust_boundary_registered()
}

pub proof fn lemma_shared_formal_assumptions_registered()
    ensures shared_formal_assumptions_registered(),
{
    assert(merkle_boundary_axioms::merkle_boundary_axioms_hold()) by {
        broadcast use merkle_boundary_axioms::group_merkle_boundary_axioms;

        assert forall|data: Seq<u8>| #[trigger] merkle_boundary_axioms::merkle_leaf_hash(data).len() == 32 by {
            merkle_boundary_axioms::axiom_merkle_leaf_hash_len(data);
        };

        assert forall|left: Seq<u8>, right: Seq<u8>|
            if left.len() == 32 && right.len() == 32 {
                #[trigger] merkle_boundary_axioms::merkle_internal_hash(left, right).len() == 32
            } else {
                true
            } by {
            if left.len() == 32 && right.len() == 32 {
                merkle_boundary_axioms::axiom_merkle_internal_hash_len(left, right);
            }
        };

        assert forall|data: Seq<u8>, left: Seq<u8>, right: Seq<u8>|
            #![trigger merkle_boundary_axioms::merkle_leaf_hash(data), merkle_boundary_axioms::merkle_internal_hash(left, right)]
            left.len() == 32 && right.len() == 32
                ==> merkle_boundary_axioms::merkle_leaf_hash(data)
                    != merkle_boundary_axioms::merkle_internal_hash(left, right) by {
            if left.len() == 32 && right.len() == 32 {
                merkle_boundary_axioms::axiom_merkle_rfc6962_domain_separation(data, left, right);
            }
        };

        assert forall|data1: Seq<u8>, data2: Seq<u8>|
            #![trigger merkle_boundary_axioms::merkle_leaf_hash(data1), merkle_boundary_axioms::merkle_leaf_hash(data2)]
            merkle_boundary_axioms::merkle_leaf_hash(data1)
                == merkle_boundary_axioms::merkle_leaf_hash(data2) ==> data1 == data2 by {
            merkle_boundary_axioms::axiom_merkle_leaf_second_preimage_resistance(data1, data2);
        };

        assert forall|left1: Seq<u8>, right1: Seq<u8>, left2: Seq<u8>, right2: Seq<u8>|
            #![trigger merkle_boundary_axioms::merkle_internal_hash(left1, right1), merkle_boundary_axioms::merkle_internal_hash(left2, right2)]
            left1.len() == 32 && right1.len() == 32 && left2.len() == 32 && right2.len() == 32
                ==> merkle_boundary_axioms::merkle_internal_hash(left1, right1)
                    == merkle_boundary_axioms::merkle_internal_hash(left2, right2)
                    ==> left1 == left2 && right1 == right2 by {
            if left1.len() == 32 && right1.len() == 32 && left2.len() == 32 && right2.len() == 32 {
                merkle_boundary_axioms::axiom_merkle_internal_second_preimage_resistance(
                    left1,
                    right1,
                    left2,
                    right2,
                );
            }
        };

        assert forall|hash: Seq<u8>|
            if hash.len() == 32 {
                #[trigger] merkle_boundary_axioms::merkle_decode_hash_hex(
                    merkle_boundary_axioms::merkle_encode_hash_hex(hash),
                ) == Option::Some(hash)
            } else {
                true
            } by {
            if hash.len() == 32 {
                merkle_boundary_axioms::axiom_merkle_codec_roundtrip(hash);
            }
        };

        assert forall|encoded: Seq<u8>, decoded: Seq<u8>|
            #![trigger merkle_boundary_axioms::merkle_decode_hash_hex(encoded), decoded.len()]
            merkle_boundary_axioms::merkle_decode_hash_hex(encoded) == Option::Some(decoded)
                ==> decoded.len() == 32 by {
            if merkle_boundary_axioms::merkle_decode_hash_hex(encoded) == Option::Some(decoded) {
                merkle_boundary_axioms::axiom_merkle_codec_decoded_hash_len(encoded, decoded);
            }
        };
    };

    assert(audit_fs_boundary_axioms::audit_filesystem_boundary_axioms_hold()) by {
        broadcast use audit_fs_boundary_axioms::group_audit_fs_boundary_axioms;

        assert forall|prior: Seq<u8>, appended: Seq<u8>|
            #[trigger] audit_fs_boundary_axioms::fs_append_bytes(prior, appended) == prior + appended by {
            audit_fs_boundary_axioms::axiom_fs_append_targets_intended_file(prior, appended);
        };

        assert forall|contents: Seq<u8>|
            #[trigger] audit_fs_boundary_axioms::fs_metadata_len(contents) == contents.len() by {
            audit_fs_boundary_axioms::axiom_fs_metadata_matches_state(contents);
        };

        assert forall|contents: Seq<u8>| #[trigger] audit_fs_boundary_axioms::fs_read_bytes(contents) == contents by {
            audit_fs_boundary_axioms::axiom_fs_read_matches_state(contents);
        };

        assert forall|contents: Seq<u8>, len: nat|
            if len <= contents.len() {
                #[trigger] audit_fs_boundary_axioms::fs_truncate_bytes(contents, len)
                    == contents.subrange(0, len as int)
            } else {
                true
            } by {
            if len <= contents.len() {
                audit_fs_boundary_axioms::axiom_fs_truncate_preserves_prefix(contents, len);
            }
        };

        assert forall|contents: Seq<u8>|
            #[trigger] audit_fs_boundary_axioms::fs_rename_contents(contents) == contents by {
            audit_fs_boundary_axioms::axiom_fs_rename_preserves_contents(contents);
        };

        assert forall|sync_data: bool, contents: Seq<u8>|
            #[trigger] audit_fs_boundary_axioms::fs_durability_respected(sync_data, contents) by {
            audit_fs_boundary_axioms::axiom_fs_durability_contract(sync_data, contents);
        };
    };
}

} // verus!
