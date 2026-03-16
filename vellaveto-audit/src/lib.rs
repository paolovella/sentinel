// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Tamper-evident audit logging for the Vellaveto MCP tool firewall.
//!
//! Records every policy decision in an append-only, hash-chained audit log
//! with Ed25519-signed checkpoints and Merkle proof generation. Supports
//! export to CEF, JSONL, OCSF, webhook, and syslog formats, plus dual-write
//! to PostgreSQL. Compliance registries map audit events to EU AI Act, SOC 2,
//! DORA, NIS2, OWASP ASI, and 6 additional regulatory frameworks.

// vellaveto-audit: Append-only tamper-evident audit logging for policy decisions.
//
// Submodules:
//   types       — Error, entry, report, checkpoint, redaction-level types
//   redaction   — Sensitive-key and PII redaction logic
//   logger      — AuditLogger struct, constructors, builders, core log_entry
//   rotation    — Log rotation and cross-rotation verification
//   verification— Hash chain verification, duplicate detection, reports
//   checkpoints — Ed25519-signed checkpoint creation and verification
//   events      — Security event logging helpers (heartbeat, circuit breaker, etc.)
//   etdi_audit  — ETDI cryptographic tool security audit helpers

// ── New submodules (split from the former monolithic lib.rs) ──────────────────
mod checkpoints;
mod etdi_audit;
mod events;
pub mod logger;
pub mod merkle;
mod redaction;
mod rotation;
pub(crate) mod trusted_audit_fs;
pub(crate) mod trusted_merkle_hash;
mod types;
mod verification;
pub(crate) mod verified_audit_append;
pub(crate) mod verified_audit_chain;
pub(crate) mod verified_merkle;
pub(crate) mod verified_merkle_fold;
pub(crate) mod verified_merkle_path;
pub(crate) mod verified_rotation_manifest;

// ── Phase 19: Immutable audit log archive ────────────────────────────────────
#[cfg(feature = "archive")]
pub mod archive;

// ── Phase 37: Zero-Knowledge Audit Trails ────────────────────────────────────
#[cfg(feature = "zk-audit")]
pub mod zk;

// ── Phase 54: Post-Quantum Cryptography (ML-DSA-65 hybrid signatures) ────────
#[cfg(feature = "pqc-hybrid")]
pub mod pqc;

// ── Phase 43: Centralized Audit Store ────────────────────────────────────────
pub mod query;
pub mod sink;

// ── Phase 38: SOC 2 Type II Access Review Reports ───────────────────────────
pub mod access_review;

// ── Phase 2: OpenTelemetry span generation ──────────────────────────────────
pub mod otel_spans;

// ── Phase 4: Compliance evidence factory ────────────────────────────────────
pub mod annex_iv;
pub mod article73;
pub mod fria;

// ── Pre-existing submodules ──────────────────────────────────────────────────
pub mod aivss;
pub mod atlas;
pub mod eu_ai_act;
pub mod evidence_pack;
pub mod exec_graph;
pub mod export;
pub mod iso27090;
pub mod nist_rmf;
pub mod observability;
pub mod pii;
pub mod soc2;
pub mod streaming;

// ── Phase 19.3: CoSAI/Adversa threat coverage registries ────────────────────
pub mod adversa_top25;
pub mod cosai;
pub mod data_governance;
pub mod dora;
pub mod gap_analysis;
pub mod iso42001;
pub mod nis2;

// ── Phase 41: OWASP Agentic Security Index (ASI) registry ───────────────────
pub mod owasp_asi;

// ── R226: OWASP MCP Top 10 compliance registry ─────────────────────────────
pub mod owasp_mcp;

// ── R226: Cross-regulation incident reporting ───────────────────────────────
pub mod incident_report;

// ── NIST AI 600-1 GenAI Profile compliance registry ────────────────────────
pub mod nist_ai600;

// ── Phase 68: Runtime Analytics & Insights API ─────────────────────────────
pub mod analytics;

// ── Re-exports: preserve exact public API ────────────────────────────────────

// Types
pub use types::{
    AuditEntry, AuditError, AuditReport, ChainVerification, Checkpoint, CheckpointVerification,
    ErrorLogEntry, RedactionLevel, RotationVerification,
};

// Core logger
pub use logger::AuditLogger;

// Redaction (free function used by external crates)
pub use redaction::redact_keys_and_patterns;

// Observability re-exports
pub use observability::{
    ActionSummary, DetectionType, ObservabilityError, ObservabilityExporter,
    ObservabilityExporterConfig, RedactionConfig, SamplingConfig as ObservabilitySamplingConfig,
    SecurityDetection, SecuritySpan, SecuritySpanBuilder, SpanKind, SpanSampler, TraceContext,
    VerdictSummary,
};

// Merkle tree re-exports
pub use merkle::{MerkleProof, MerkleTree, MerkleVerification, ProofStep};

// PII re-exports
pub use pii::{validate_regex_safety, CustomPiiPattern, PiiMatch, PiiScanner};

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests;
