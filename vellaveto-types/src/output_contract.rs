// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 3 (WP 3D): Semantic output contract types.
//!
//! Tools declare their expected output semantic type (e.g., Data, Url,
//! CommandLike). The runtime classifies actual responses and flags
//! violations — a tool typed as "Data" that returns "CommandLike" content
//! is a rug-pull indicator.

use serde::{Deserialize, Serialize};

use crate::ContextChannel;

/// A declared output contract for a tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputContract {
    /// Tool name or glob pattern.
    pub tool_pattern: String,
    /// Expected output semantic types. The response must classify as one of these.
    pub expected_channels: Vec<ContextChannel>,
    /// Action on violation.
    pub on_violation: ContractViolationAction,
}

/// What to do when an output contract is violated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ContractViolationAction {
    /// Log the violation but allow the response.
    #[default]
    Log,
    /// Quarantine the response (add taint, lower trust).
    Quarantine,
    /// Block the response entirely.
    Block,
}

/// Result of checking a response against its output contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractCheckResult {
    /// Response matches the declared contract.
    Compliant,
    /// No contract defined for this tool.
    NoContract,
    /// Response violates the contract.
    Violation {
        expected: Vec<ContextChannel>,
        observed: ContextChannel,
        action: ContractViolationAction,
    },
}

/// Check a tool response against its output contract.
///
/// `observed_channel` is the classified semantic type of the actual response.
pub fn check_output_contract(
    tool_name: &str,
    observed_channel: ContextChannel,
    contracts: &[OutputContract],
) -> ContractCheckResult {
    // Find matching contract
    let contract = contracts
        .iter()
        .find(|c| tool_matches(&c.tool_pattern, tool_name));

    let contract = match contract {
        Some(c) => c,
        None => return ContractCheckResult::NoContract,
    };

    if contract.expected_channels.contains(&observed_channel) {
        ContractCheckResult::Compliant
    } else {
        ContractCheckResult::Violation {
            expected: contract.expected_channels.clone(),
            observed: observed_channel,
            action: contract.on_violation.clone(),
        }
    }
}

fn tool_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(star) = pattern.find('*') {
        let prefix = &pattern[..star];
        let suffix = &pattern[star + 1..];
        name.starts_with(prefix) && name.ends_with(suffix)
    } else {
        pattern == name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliant_response() {
        let contracts = vec![OutputContract {
            tool_pattern: "read_file".to_string(),
            expected_channels: vec![ContextChannel::Data, ContextChannel::ResourceContent],
            on_violation: ContractViolationAction::Block,
        }];
        let result = check_output_contract("read_file", ContextChannel::Data, &contracts);
        assert_eq!(result, ContractCheckResult::Compliant);
    }

    #[test]
    fn test_violation_detected() {
        let contracts = vec![OutputContract {
            tool_pattern: "read_file".to_string(),
            expected_channels: vec![ContextChannel::Data],
            on_violation: ContractViolationAction::Block,
        }];
        let result = check_output_contract("read_file", ContextChannel::CommandLike, &contracts);
        match result {
            ContractCheckResult::Violation {
                observed, action, ..
            } => {
                assert_eq!(observed, ContextChannel::CommandLike);
                assert_eq!(action, ContractViolationAction::Block);
            }
            _ => panic!("Expected violation"),
        }
    }

    #[test]
    fn test_no_contract_for_tool() {
        let contracts = vec![OutputContract {
            tool_pattern: "read_file".to_string(),
            expected_channels: vec![ContextChannel::Data],
            on_violation: ContractViolationAction::Log,
        }];
        let result = check_output_contract("write_file", ContextChannel::Data, &contracts);
        assert_eq!(result, ContractCheckResult::NoContract);
    }

    #[test]
    fn test_glob_pattern_matching() {
        let contracts = vec![OutputContract {
            tool_pattern: "read_*".to_string(),
            expected_channels: vec![ContextChannel::Data],
            on_violation: ContractViolationAction::Quarantine,
        }];
        let result = check_output_contract("read_database", ContextChannel::Url, &contracts);
        match result {
            ContractCheckResult::Violation { action, .. } => {
                assert_eq!(action, ContractViolationAction::Quarantine);
            }
            _ => panic!("Expected violation"),
        }
    }

    #[test]
    fn test_wildcard_contract() {
        let contracts = vec![OutputContract {
            tool_pattern: "*".to_string(),
            expected_channels: vec![ContextChannel::Data, ContextChannel::FreeText],
            on_violation: ContractViolationAction::Log,
        }];
        // CommandLike from any tool violates the wildcard contract
        let result = check_output_contract("anything", ContextChannel::CommandLike, &contracts);
        assert!(matches!(result, ContractCheckResult::Violation { .. }));
    }
}
