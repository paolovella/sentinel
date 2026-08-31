// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Consumer Shield: bidirectional PII sanitization, session isolation,
//! encrypted local audit, and credential-based session unlinkability
//! for consumer AI interactions.

pub mod context_isolation;
pub mod credential_vault;
pub mod crypto;
pub mod error;
#[cfg(test)]
mod kani_credential_vault_differential;
#[cfg(test)]
mod kani_sanitizer_differential;
pub mod local_audit;
pub mod sanitizer;
pub mod session_isolator;
pub mod session_unlinker;
pub mod stylometric;

#[cfg(test)]
mod tests;

pub use context_isolation::ContextIsolator;
pub use credential_vault::CredentialVault;
pub use crypto::EncryptedAuditStore;
pub use error::ShieldError;
pub use local_audit::LocalAuditManager;
pub use sanitizer::QuerySanitizer;
pub use session_isolator::SessionIsolator;
pub use session_unlinker::SessionUnlinker;
pub use stylometric::{NormalizationLevel, StylometricNormalizer};
