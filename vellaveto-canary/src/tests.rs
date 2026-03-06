// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

use super::*;

fn test_signing_key() -> String {
    // Generate a deterministic test key
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    hex::encode(signing_key.to_bytes())
}

fn other_signing_key() -> String {
    let signing_key = SigningKey::from_bytes(&[99u8; 32]);
    hex::encode(signing_key.to_bytes())
}

#[test]
fn test_create_verify_roundtrip() {
    let key = test_signing_key();
    let canary = create_canary("No government surveillance orders received.", 90, &key)
        .expect("create should succeed");

    assert_eq!(canary.version, CANARY_VERSION);
    assert!(!canary.signature.is_empty());

    let verification = verify_canary(&canary).expect("verify should succeed");
    assert!(verification.signature_valid);
    assert!(!verification.expired);
    assert!(verification.days_remaining >= 89); // at least 89 days remaining
}

#[test]
fn test_expired_canary_detected() {
    let key = test_signing_key();
    let mut canary = create_canary("Test statement.", 90, &key).expect("create should succeed");

    // Manually set expires_date to the past
    canary.expires_date = "2020-01-01".to_string();
    // Re-sign with correct payload (otherwise signature will be invalid too)
    let key_bytes = hex::decode(&key).unwrap();
    let key_array: [u8; 32] = key_bytes.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&key_array);
    let payload = canonical_payload(
        canary.version,
        &canary.signed_date,
        &canary.expires_date,
        &canary.statement,
    );
    let sig = signing_key.sign(&payload);
    canary.signature = hex::encode(sig.to_bytes());

    let verification = verify_canary(&canary).expect("verify should succeed");
    assert!(verification.signature_valid);
    assert!(verification.expired);
    assert!(verification.days_remaining < 0);
}

#[test]
fn test_tampered_statement_rejected() {
    let key = test_signing_key();
    let mut canary = create_canary("Original statement.", 90, &key).expect("create should succeed");

    canary.statement = "Tampered statement.".to_string();

    let verification = verify_canary(&canary).expect("verify should succeed");
    assert!(
        !verification.signature_valid,
        "tampered canary should fail verification"
    );
}

#[test]
fn test_wrong_key_rejected() {
    let key = test_signing_key();
    let other_key = other_signing_key();

    let canary = create_canary("Test statement.", 90, &key).expect("create should succeed");

    // Create a new canary with a different key and swap the verifying key
    let other_canary =
        create_canary("Test statement.", 90, &other_key).expect("create should succeed");

    let mut tampered = canary.clone();
    tampered.verifying_key = other_canary.verifying_key;

    let verification = verify_canary(&tampered).expect("verify should succeed");
    assert!(
        !verification.signature_valid,
        "wrong key should fail verification"
    );
}

#[test]
fn test_max_statement_length_enforced() {
    let key = test_signing_key();
    let long_statement = "a".repeat(MAX_STATEMENT_LENGTH + 1);
    let result = create_canary(&long_statement, 90, &key);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("max length"));
}

#[test]
fn test_dangerous_chars_rejected() {
    let key = test_signing_key();
    let result = create_canary("test\u{200B}statement", 90, &key);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("dangerous"));
}
