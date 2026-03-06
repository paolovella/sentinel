// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

use super::*;
use vellaveto_audit::{CustomPiiPattern, PiiScanner};

// ═══════════════════════════════════════════════════════════════════
// Sanitizer Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_sanitizer_email_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Contact user@example.com").unwrap();
    assert!(!result.contains("user@example.com"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_ssn_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("SSN: 123-45-6789").unwrap();
    assert!(!result.contains("123-45-6789"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_cc_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Card: 4111111111111111").unwrap();
    assert!(!result.contains("4111111111111111"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_phone_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Call 555-123-4567").unwrap();
    assert!(!result.contains("555-123-4567"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_roundtrip() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let original = "Email user@example.com and SSN 123-45-6789 here";
    let sanitized = sanitizer.sanitize(original).unwrap();
    assert!(!sanitized.contains("user@example.com"));
    assert!(!sanitized.contains("123-45-6789"));

    let restored = sanitizer.desanitize(&sanitized).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn test_sanitizer_json_recursive() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let input = serde_json::json!({
        "name": "test",
        "email": "user@example.com",
        "nested": {
            "ssn": "123-45-6789"
        }
    });
    let sanitized = sanitizer.sanitize_json(&input).unwrap();
    let sanitized_str = serde_json::to_string(&sanitized).unwrap();
    assert!(!sanitized_str.contains("user@example.com"));
    assert!(!sanitized_str.contains("123-45-6789"));

    let restored = sanitizer.desanitize_json(&sanitized).unwrap();
    assert_eq!(restored, input);
}

#[test]
fn test_sanitizer_max_mappings_fail_closed() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    // Fill up mappings (each unique email creates a mapping)
    for i in 0..50_000 {
        let input = format!("user{}@example.com", i);
        let _ = sanitizer.sanitize(&input);
    }
    // Next sanitize should fail
    let result = sanitizer.sanitize("overflow@example.com");
    assert!(result.is_err());
}

#[test]
fn test_sanitizer_custom_patterns() {
    let custom = vec![CustomPiiPattern {
        name: "employee_id".to_string(),
        pattern: r"EMP-\d{6}".to_string(),
    }];
    let scanner = PiiScanner::new(&custom);
    let sanitizer = QuerySanitizer::new(scanner);
    let result = sanitizer.sanitize("Employee EMP-123456 logged in").unwrap();
    assert!(!result.contains("EMP-123456"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_clear() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let _ = sanitizer.sanitize("user@example.com").unwrap();
    assert!(sanitizer.mapping_count() > 0);
    sanitizer.clear();
    assert_eq!(sanitizer.mapping_count(), 0);
}

#[test]
fn test_sanitizer_empty_unchanged() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("").unwrap();
    assert_eq!(result, "");
}

#[test]
fn test_sanitizer_no_pii_unchanged() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let input = "Normal text with no PII";
    let result = sanitizer.sanitize(input).unwrap();
    assert_eq!(result, input);
}

// ═══════════════════════════════════════════════════════════════════
// Session Isolator Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_session_create() {
    let isolator = SessionIsolator::new();
    let result = isolator.sanitize_in_session("s1", "user@example.com");
    assert!(result.is_ok());
    assert_eq!(isolator.session_count(), 1);
}

#[test]
fn test_session_max_fail_closed() {
    let isolator = SessionIsolator::with_limits(2, 100);
    let _ = isolator.sanitize_in_session("s1", "test").unwrap();
    let _ = isolator.sanitize_in_session("s2", "test").unwrap();
    let result = isolator.sanitize_in_session("s3", "test");
    assert!(result.is_err());
}

#[test]
fn test_session_independent_pii_maps() {
    let isolator = SessionIsolator::new();
    let s1_result = isolator
        .sanitize_in_session("s1", "user1@example.com")
        .unwrap();
    let s2_result = isolator
        .sanitize_in_session("s2", "user2@example.com")
        .unwrap();

    // Both sessions have PII replaced
    assert!(!s1_result.contains("user1@example.com"));
    assert!(!s2_result.contains("user2@example.com"));

    // Desanitize in the correct session restores the original
    let restored = isolator.desanitize_in_session("s1", &s1_result).unwrap();
    assert_eq!(restored, "user1@example.com");

    // Cross-session desanitization should NOT restore the other session's PII
    let cross_restored = isolator.desanitize_in_session("s2", &s1_result).unwrap();
    assert_ne!(
        cross_restored, "user1@example.com",
        "session isolation should prevent cross-session PII restoration"
    );
}

#[test]
fn test_session_end_clears() {
    let isolator = SessionIsolator::new();
    let _ = isolator
        .sanitize_in_session("s1", "user@example.com")
        .unwrap();
    assert_eq!(isolator.session_count(), 1);
    isolator.end_session("s1");
    assert_eq!(isolator.session_count(), 0);
}

#[test]
fn test_session_history_bounded() {
    let isolator = SessionIsolator::with_limits(10, 3);
    let _ = isolator.sanitize_in_session("s1", "first").unwrap();
    let _ = isolator.sanitize_in_session("s1", "second").unwrap();
    let _ = isolator.sanitize_in_session("s1", "third").unwrap();
    let _ = isolator.sanitize_in_session("s1", "fourth").unwrap();
    // Should not error — old entries evicted
    assert_eq!(isolator.session_count(), 1);
}

// ═══════════════════════════════════════════════════════════════════
// Crypto Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_crypto_encrypt_decrypt_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase").unwrap();

    let plaintext = b"sensitive audit data";
    let encrypted = store.encrypt(plaintext).unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_crypto_wrong_passphrase_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");

    let store1 = EncryptedAuditStore::new(path.clone(), "correct-passphrase").unwrap();
    store1.write_encrypted_entry(b"secret data").unwrap();

    let store2 = EncryptedAuditStore::new(path, "wrong-passphrase").unwrap();
    let result = store2.read_all_entries();
    assert!(result.is_err());
}

#[test]
fn test_crypto_empty_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase").unwrap();

    let encrypted = store.encrypt(b"").unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_crypto_large_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase").unwrap();

    let large = vec![0xABu8; 1_000_000];
    let encrypted = store.encrypt(&large).unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, large);
}

#[test]
fn test_crypto_salt_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");

    let store1 = EncryptedAuditStore::new(path.clone(), "passphrase").unwrap();
    store1.write_encrypted_entry(b"entry 1").unwrap();

    // Re-open with same passphrase — should read same salt
    let store2 = EncryptedAuditStore::new(path, "passphrase").unwrap();
    let entries = store2.read_all_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], b"entry 1");
}

// ═══════════════════════════════════════════════════════════════════
// Local Audit Tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_local_audit_encrypted_not_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path.clone(), "secret").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store);

    manager
        .log_shield_event("test", "sensitive details")
        .await
        .unwrap();

    // Read raw file — should NOT contain plaintext
    let raw = std::fs::read(&enc_path).unwrap();
    let raw_str = String::from_utf8_lossy(&raw);
    assert!(!raw_str.contains("sensitive details"));
}

#[tokio::test]
async fn test_local_audit_merkle_proof_valid() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path, "secret").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store).with_merkle();

    manager
        .log_shield_event("event1", "details1")
        .await
        .unwrap();
    manager
        .log_shield_event("event2", "details2")
        .await
        .unwrap();

    let proof = manager.generate_proof(0);
    assert!(proof.is_ok());
    assert!(manager.merkle_root().is_some());
}

#[tokio::test]
async fn test_local_audit_read_decrypts() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path, "secret").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store);

    manager
        .log_shield_event("test_event", "test_details")
        .await
        .unwrap();

    let entries = manager.read_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["event"], "test_event");
}

// ═══════════════════════════════════════════════════════════════════
// BlindCredential Type Tests
// ═══════════════════════════════════════════════════════════════════

fn make_test_credential(epoch: u64) -> vellaveto_types::BlindCredential {
    vellaveto_types::BlindCredential {
        credential: vec![1, 2, 3, 4],
        signature: vec![5, 6, 7, 8],
        provider_key_id: "test-key-001".to_string(),
        issued_epoch: epoch,
        credential_type: vellaveto_types::CredentialType::Subscriber,
    }
}

#[test]
fn test_blind_credential_validate_valid() {
    let cred = make_test_credential(42);
    assert!(cred.validate().is_ok());
}

#[test]
fn test_blind_credential_validate_empty_credential() {
    let mut cred = make_test_credential(0);
    cred.credential = Vec::new();
    assert!(cred
        .validate()
        .unwrap_err()
        .contains("credential must not be empty"));
}

#[test]
fn test_blind_credential_validate_empty_signature() {
    let mut cred = make_test_credential(0);
    cred.signature = Vec::new();
    assert!(cred
        .validate()
        .unwrap_err()
        .contains("signature must not be empty"));
}

#[test]
fn test_blind_credential_validate_oversized_credential() {
    let mut cred = make_test_credential(0);
    cred.credential = vec![0u8; vellaveto_types::MAX_CREDENTIAL_LEN + 1];
    assert!(cred.validate().unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_blind_credential_validate_oversized_signature() {
    let mut cred = make_test_credential(0);
    cred.signature = vec![0u8; vellaveto_types::MAX_SIGNATURE_LEN + 1];
    assert!(cred.validate().unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_blind_credential_validate_empty_key_id() {
    let mut cred = make_test_credential(0);
    cred.provider_key_id = String::new();
    assert!(cred
        .validate()
        .unwrap_err()
        .contains("provider_key_id must not be empty"));
}

#[test]
fn test_blind_credential_validate_dangerous_key_id() {
    let mut cred = make_test_credential(0);
    cred.provider_key_id = "key\u{200B}id".to_string(); // zero-width space
    assert!(cred
        .validate()
        .unwrap_err()
        .contains("dangerous characters"));
}

#[test]
fn test_blind_credential_validate_oversized_key_id() {
    let mut cred = make_test_credential(0);
    cred.provider_key_id = "k".repeat(vellaveto_types::MAX_PROVIDER_KEY_ID_LEN + 1);
    assert!(cred.validate().unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_blind_credential_validate_epoch_overflow() {
    let mut cred = make_test_credential(0);
    cred.issued_epoch = vellaveto_types::MAX_CREDENTIAL_EPOCH + 1;
    assert!(cred.validate().unwrap_err().contains("issued_epoch"));
}

#[test]
fn test_blind_credential_debug_redacts_secrets() {
    let cred = make_test_credential(42);
    let debug_str = format!("{:?}", cred);
    assert!(debug_str.contains("REDACTED"));
    assert!(!debug_str.contains("[1, 2, 3, 4]"));
    assert!(!debug_str.contains("[5, 6, 7, 8]"));
    assert!(debug_str.contains("test-key-001")); // key_id is NOT secret
}

#[test]
fn test_blind_credential_serde_roundtrip() {
    let cred = make_test_credential(99);
    let json = serde_json::to_string(&cred).unwrap();
    let parsed: vellaveto_types::BlindCredential = serde_json::from_str(&json).unwrap();
    assert_eq!(cred, parsed);
}

#[test]
fn test_blind_credential_deny_unknown_fields() {
    let json = r#"{
        "credential": [1,2,3],
        "signature": [4,5,6],
        "provider_key_id": "key",
        "issued_epoch": 0,
        "credential_type": "subscriber",
        "unknown_field": true
    }"#;
    let result: Result<vellaveto_types::BlindCredential, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// CredentialVault Tests
// ═══════════════════════════════════════════════════════════════════

fn make_test_vault(pool_size: usize, threshold: usize) -> (CredentialVault, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase").unwrap();
    let vault = CredentialVault::new(store, pool_size, threshold).unwrap();
    (vault, dir)
}

#[test]
fn test_vault_add_and_consume() {
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();

    let status = vault.status();
    assert_eq!(status.total, 1);
    assert_eq!(status.available, 1);

    let (cred, idx) = vault.consume_credential().unwrap();
    assert_eq!(cred.issued_epoch, 1);

    let status = vault.status();
    assert_eq!(status.available, 0);
    assert_eq!(status.active, 1);

    vault.mark_consumed(idx).unwrap();
    let status = vault.status();
    assert_eq!(status.consumed, 1);
    assert_eq!(status.active, 0);
}

#[test]
fn test_vault_consume_empty_fail_closed() {
    let (vault, _dir) = make_test_vault(10, 3);
    let result = vault.consume_credential();
    assert!(result.is_err());
}

#[test]
fn test_vault_needs_replenishment() {
    let (vault, _dir) = make_test_vault(10, 3);
    // Empty vault → needs replenishment
    assert!(vault.status().needs_replenishment);

    // Add 3 credentials → still below threshold? No, 3 == threshold, not below
    for i in 0..3 {
        vault.add_credential(make_test_credential(i)).unwrap();
    }
    assert!(!vault.status().needs_replenishment);

    // Consume 1 → 2 available, below threshold of 3
    vault.consume_credential().unwrap();
    assert!(vault.status().needs_replenishment);
}

#[test]
fn test_vault_expire_old_epochs() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();
    vault.add_credential(make_test_credential(5)).unwrap();

    // Expire everything before epoch 3
    let expired = vault.expire_old_epochs(3).unwrap();
    assert_eq!(expired, 2);
    assert_eq!(vault.available_count(), 1); // Only epoch 5 remains

    // Epoch in status updated
    assert_eq!(vault.status().current_epoch, 5);
}

#[test]
fn test_vault_invalid_credential_rejected() {
    let (vault, _dir) = make_test_vault(10, 3);
    let mut bad = make_test_credential(1);
    bad.credential = Vec::new(); // invalid
    let result = vault.add_credential(bad);
    assert!(result.is_err());
}

#[test]
fn test_vault_mark_consumed_out_of_bounds() {
    let (vault, _dir) = make_test_vault(10, 3);
    let result = vault.mark_consumed(999);
    assert!(result.is_err());
}

#[test]
fn test_vault_debug_no_secrets() {
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();
    let debug_str = format!("{:?}", vault);
    assert!(debug_str.contains("CredentialVault"));
    assert!(debug_str.contains("available"));
    // Should not contain raw credential bytes
    assert!(!debug_str.contains("[1, 2, 3, 4]"));
}

#[test]
fn test_vault_persistence_across_instances() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");

    // Create vault and add credentials
    {
        let store = EncryptedAuditStore::new(path.clone(), "test-pass").unwrap();
        let vault = CredentialVault::new(store, 10, 3).unwrap();
        vault.add_credential(make_test_credential(1)).unwrap();
        vault.add_credential(make_test_credential(2)).unwrap();
    }

    // Re-open with same passphrase — credentials should be loaded
    {
        let store = EncryptedAuditStore::new(path, "test-pass").unwrap();
        let vault = CredentialVault::new(store, 10, 3).unwrap();
        assert_eq!(vault.status().total, 2);
        assert_eq!(vault.available_count(), 2);
    }
}

// ═══════════════════════════════════════════════════════════════════
// SessionUnlinker Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_unlinker_start_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let cred = unlinker.start_session("session-1").unwrap();
    assert_eq!(cred.issued_epoch, 1);
    assert_eq!(unlinker.active_session_count(), 1);
    assert!(unlinker.is_session_active("session-1"));
}

#[test]
fn test_unlinker_end_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("session-1").unwrap();
    unlinker.end_session("session-1").unwrap();

    assert_eq!(unlinker.active_session_count(), 0);
    assert!(!unlinker.is_session_active("session-1"));
    assert_eq!(unlinker.vault().status().consumed, 1);
}

#[test]
fn test_unlinker_no_credentials_fail_closed() {
    let (vault, _dir) = make_test_vault(10, 1);
    let unlinker = SessionUnlinker::new(vault);
    let result = unlinker.start_session("session-1");
    assert!(result.is_err());
}

#[test]
fn test_unlinker_duplicate_session_rejected() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("session-1").unwrap();
    let result = unlinker.start_session("session-1");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already active"));
}

#[test]
fn test_unlinker_capacity_exhaustion_fail_closed() {
    let (vault, _dir) = make_test_vault(100, 1);
    for i in 0..5 {
        vault
            .add_credential(make_test_credential(i as u64))
            .unwrap();
    }

    let unlinker = SessionUnlinker::with_max_sessions(vault, 3);
    unlinker.start_session("s1").unwrap();
    unlinker.start_session("s2").unwrap();
    unlinker.start_session("s3").unwrap();

    let result = unlinker.start_session("s4");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("capacity exhausted"));
}

#[test]
fn test_unlinker_get_session_credential() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(42)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let original = unlinker.start_session("s1").unwrap();
    let retrieved = unlinker.get_session_credential("s1").unwrap();
    assert_eq!(original, retrieved);
}

#[test]
fn test_unlinker_get_binding() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("s1").unwrap();

    let binding = unlinker.get_binding("s1").unwrap();
    assert_eq!(binding.session_id, "s1");
    assert_eq!(binding.binding_sequence, 0);
}

#[test]
fn test_unlinker_monotonic_sequence() {
    let (vault, _dir) = make_test_vault(10, 1);
    for i in 0..3 {
        vault.add_credential(make_test_credential(i)).unwrap();
    }

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("s1").unwrap();
    unlinker.start_session("s2").unwrap();
    unlinker.start_session("s3").unwrap();

    let b1 = unlinker.get_binding("s1").unwrap();
    let b2 = unlinker.get_binding("s2").unwrap();
    let b3 = unlinker.get_binding("s3").unwrap();
    assert!(b1.binding_sequence < b2.binding_sequence);
    assert!(b2.binding_sequence < b3.binding_sequence);
}

#[test]
fn test_unlinker_dangerous_session_id_rejected() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let result = unlinker.start_session("session\u{200B}id");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("dangerous"));
}

#[test]
fn test_unlinker_unknown_session_end_rejected() {
    let (vault, _dir) = make_test_vault(10, 1);
    let unlinker = SessionUnlinker::new(vault);
    let result = unlinker.end_session("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_unlinker_independent_credentials_per_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let cred1 = unlinker.start_session("s1").unwrap();
    let cred2 = unlinker.start_session("s2").unwrap();

    // Each session gets a different credential (unlinkable)
    assert_ne!(cred1.issued_epoch, cred2.issued_epoch);
}

// ═══════════════════════════════════════════════════════════════════
// ShieldConfig Credential Extensions Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_shield_config_credential_defaults() {
    let config = vellaveto_config::ShieldConfig::default();
    assert!(config.session_unlinkability);
    assert_eq!(config.credential_pool_size, 50);
    assert_eq!(config.replenish_threshold, 10);
    assert_eq!(config.credential_epoch_interval, 100);
    assert!(config.validate().is_ok());
}

#[test]
fn test_shield_config_zero_pool_rejected() {
    let config = vellaveto_config::ShieldConfig {
        credential_pool_size: 0,
        ..Default::default()
    };
    assert!(config
        .validate()
        .unwrap_err()
        .contains("credential_pool_size"));
}

#[test]
fn test_shield_config_threshold_ge_pool_rejected() {
    let config = vellaveto_config::ShieldConfig {
        replenish_threshold: 50, // equal to pool_size
        ..Default::default()
    };
    assert!(config
        .validate()
        .unwrap_err()
        .contains("replenish_threshold"));
}

#[test]
fn test_shield_config_zero_epoch_interval_rejected() {
    let config = vellaveto_config::ShieldConfig {
        credential_epoch_interval: 0,
        ..Default::default()
    };
    assert!(config
        .validate()
        .unwrap_err()
        .contains("credential_epoch_interval"));
}

// ═══════════════════════════════════════════════════════════════════
// ContextIsolator Tests
// ═══════════════════════════════════════════════════════════════════
#[test]
fn test_context_record_and_retrieve() {
    let ctx = ContextIsolator::new();
    ctx.record("s1", "user", "What is the weather?").unwrap();
    ctx.record("s1", "assistant", "It's sunny today.").unwrap();

    let entries = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0],
        ("user".to_string(), "What is the weather?".to_string())
    );
    assert_eq!(
        entries[1],
        ("assistant".to_string(), "It's sunny today.".to_string())
    );
}

#[test]
fn test_context_session_isolation() {
    let ctx = ContextIsolator::new();
    ctx.record("s1", "user", "Session 1 context").unwrap();
    ctx.record("s2", "user", "Session 2 context").unwrap();

    let s1 = ctx.get_recent_context("s1", 10).unwrap();
    let s2 = ctx.get_recent_context("s2", 10).unwrap();

    assert_eq!(s1.len(), 1);
    assert_eq!(s2.len(), 1);
    assert_eq!(s1[0].1, "Session 1 context");
    assert_eq!(s2[0].1, "Session 2 context");
}

#[test]
fn test_context_entry_limit_evicts_oldest() {
    let ctx = ContextIsolator::with_limits(3, 100);
    ctx.record("s1", "user", "first").unwrap();
    ctx.record("s1", "user", "second").unwrap();
    ctx.record("s1", "user", "third").unwrap();
    ctx.record("s1", "user", "fourth").unwrap(); // should evict "first"

    let entries = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].1, "second");
}

#[test]
fn test_context_session_capacity_fail_closed() {
    let ctx = ContextIsolator::with_limits(100, 2);
    ctx.record("s1", "user", "ok").unwrap();
    ctx.record("s2", "user", "ok").unwrap();
    let result = ctx.record("s3", "user", "fail");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("capacity exhausted"));
}

#[test]
fn test_context_end_session_clears() {
    let ctx = ContextIsolator::new();
    ctx.record("s1", "user", "data").unwrap();
    assert_eq!(ctx.session_count(), 1);
    ctx.end_session("s1");
    assert_eq!(ctx.session_count(), 0);
}

#[test]
fn test_context_oversized_entry_rejected() {
    let ctx = ContextIsolator::new();
    let huge = "x".repeat(65_537); // MAX_CONTEXT_ENTRY_LEN + 1
    let result = ctx.record("s1", "user", &huge);
    assert!(result.is_err());
}

#[test]
fn test_context_recent_returns_last_n() {
    let ctx = ContextIsolator::new();
    for i in 0..10 {
        ctx.record("s1", "user", &format!("msg-{}", i)).unwrap();
    }
    let recent = ctx.get_recent_context("s1", 3).unwrap();
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].1, "msg-7");
    assert_eq!(recent[2].1, "msg-9");
}

#[test]
fn test_context_unknown_session_error() {
    let ctx = ContextIsolator::new();
    let result = ctx.get_recent_context("nonexistent", 10);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// StylometricNormalizer Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_stylometric_none_passthrough() {
    let norm = StylometricNormalizer::new(NormalizationLevel::None);
    let input = "Hello!!!  world...  🎉";
    assert_eq!(norm.normalize(input).unwrap(), input);
}

#[test]
fn test_stylometric_level1_whitespace() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let result = norm.normalize("Hello   world    test").unwrap();
    assert_eq!(result, "Hello world test");
}

#[test]
fn test_stylometric_level1_repeated_punctuation() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    assert_eq!(norm.normalize("wow!!!").unwrap(), "wow!");
    assert_eq!(norm.normalize("really???").unwrap(), "really?");
}

#[test]
fn test_stylometric_level1_ellipsis() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    assert_eq!(norm.normalize("hmm....").unwrap(), "hmm...");
    assert_eq!(norm.normalize("wait\u{2026}").unwrap(), "wait...");
    // Single dot preserved
    assert_eq!(norm.normalize("end.").unwrap(), "end.");
}

#[test]
fn test_stylometric_level1_emoji_stripped() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let result = norm.normalize("Great job! 🎉🚀👍").unwrap();
    assert_eq!(result, "Great job!");
}

#[test]
fn test_stylometric_level1_smart_quotes() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let result = norm.normalize("\u{201C}Hello\u{201D} he said").unwrap();
    assert_eq!(result, "\"Hello\" he said");
}

#[test]
fn test_stylometric_level1_dashes() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    // em dash
    let result = norm.normalize("word\u{2014}another").unwrap();
    assert_eq!(result, "word-another");
    // en dash
    let result = norm.normalize("pages 1\u{2013}10").unwrap();
    assert_eq!(result, "pages 1-10");
}

#[test]
fn test_stylometric_level2_filler_words() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let result = norm
        .normalize("I just really want to basically understand")
        .unwrap();
    assert!(!result.contains("just"));
    assert!(!result.contains("really"));
    assert!(!result.contains("basically"));
    assert!(result.contains("want"));
    assert!(result.contains("understand"));
}

#[test]
fn test_stylometric_level2_multiword_filler() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let result = norm
        .normalize("I kind of want to sort of understand this, you know")
        .unwrap();
    assert!(!result.contains("kind of"));
    assert!(!result.contains("sort of"));
}

#[test]
fn test_stylometric_level2_preserves_semantics() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let result = norm.normalize("What is the capital of France?").unwrap();
    // No fillers to remove — should be essentially unchanged
    assert!(result.contains("capital"));
    assert!(result.contains("France"));
}

#[test]
fn test_stylometric_oversized_input_rejected() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let huge = "x".repeat(1_048_577);
    assert!(norm.normalize(&huge).is_err());
}

#[test]
fn test_stylometric_combined_normalization() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let input = "Wow!!!  I\u{2019}m  just  basically  saying\u{2026}\u{2026}  it\u{2019}s  really  great  🎉🎉";
    let result = norm.normalize(input).unwrap();

    // Multiple ! → single
    assert!(!result.contains("!!!"));
    // Smart quotes → ASCII
    assert!(!result.contains('\u{2019}'));
    // Emoji stripped
    assert!(!result.contains('🎉'));
    // Fillers removed
    assert!(!result.contains("just"));
    assert!(!result.contains("basically"));
    assert!(!result.contains("really"));
    // Multiple spaces collapsed
    assert!(!result.contains("  "));
    // Semantic content preserved
    assert!(result.contains("Wow"));
    assert!(result.contains("great"));
}

#[test]
fn test_shield_config_serde_roundtrip_with_credentials() {
    let config = vellaveto_config::ShieldConfig {
        session_unlinkability: true,
        credential_pool_size: 100,
        replenish_threshold: 20,
        credential_epoch_interval: 200,
        ..Default::default()
    };
    let json_str = serde_json::to_string(&config).unwrap();
    let parsed: vellaveto_config::ShieldConfig = serde_json::from_str(&json_str).unwrap();
    assert_eq!(config, parsed);
}

// ═══════════════════════════════════════════════════════════════════
// StylometricNormalizer JSON Tests (Sprint 4)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_stylometric_normalize_json_strings() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let input = serde_json::json!({
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {
                "query": "Hello!!!  world  🎉",
                "count": 5
            }
        }
    });
    let result = norm.normalize_json(&input).unwrap();
    assert_eq!(
        result["params"]["arguments"]["query"].as_str().unwrap(),
        "Hello! world"
    );
    // Non-string values preserved
    assert_eq!(result["params"]["arguments"]["count"], 5);
    // Keys preserved
    assert!(result["params"]["name"].as_str().is_some());
}

#[test]
fn test_stylometric_normalize_json_array() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let input = serde_json::json!(["I   basically   want", "really   good", 42]);
    let result = norm.normalize_json(&input).unwrap();
    let s0 = result[0].as_str().unwrap();
    assert!(!s0.contains("basically"));
    assert!(!s0.contains("  "));
    assert_eq!(result[2], 42);
}

#[test]
fn test_stylometric_normalize_json_depth_limit() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    // Build deeply nested JSON
    let mut val = serde_json::json!("leaf");
    for _ in 0..25 {
        val = serde_json::json!({"inner": val});
    }
    let result = norm.normalize_json(&val);
    assert!(result.is_err());
}

#[test]
fn test_stylometric_normalize_json_none_passthrough() {
    let norm = StylometricNormalizer::new(NormalizationLevel::None);
    let input = serde_json::json!({"text": "Hello!!!  🎉"});
    let result = norm.normalize_json(&input).unwrap();
    assert_eq!(result["text"].as_str().unwrap(), "Hello!!!  🎉");
}

// ═══════════════════════════════════════════════════════════════════
// ContextIsolator JSON Recording Tests (Sprint 4)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_context_record_json_response_tool_result() {
    let ctx = ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {"type": "text", "text": "Paris is the capital of France."}
            ]
        }
    });
    ctx.record_json_response("s1", &msg).unwrap();
    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].0, "assistant");
    assert!(recent[0].1.contains("Paris"));
}

#[test]
fn test_context_record_json_response_error() {
    let ctx = ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32000,
            "message": "Tool execution failed"
        }
    });
    ctx.record_json_response("s1", &msg).unwrap();
    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 1);
    assert!(recent[0].1.contains("Tool execution failed"));
}

#[test]
fn test_context_record_json_response_no_result_skipped() {
    let ctx = ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress"
    });
    ctx.record_json_response("s1", &msg).unwrap();
    assert_eq!(ctx.entry_count("s1"), 0);
}

#[test]
fn test_context_record_json_request() {
    let ctx = ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {"query": "capital of France"}
        }
    });
    ctx.record_json_request("s1", &msg).unwrap();
    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].0, "user");
    assert!(recent[0].1.contains("tools/call"));
}

#[test]
fn test_context_json_bidirectional_recording() {
    let ctx = ContextIsolator::new();

    // Record outbound request
    let req = serde_json::json!({
        "method": "tools/call",
        "params": {"name": "search", "arguments": {"q": "test"}}
    });
    ctx.record_json_request("s1", &req).unwrap();

    // Record inbound response
    let resp = serde_json::json!({
        "id": 1,
        "result": {"content": [{"type": "text", "text": "search result"}]}
    });
    ctx.record_json_response("s1", &resp).unwrap();

    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].0, "user");
    assert_eq!(recent[1].0, "assistant");
}

// ═══════════════════════════════════════════════════════════════════
// SessionUnlinker Vault Ownership Tests (Sprint 4)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_unlinker_vault_accessor() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let status = unlinker.vault().status();
    assert_eq!(status.total, 1);
    assert_eq!(status.available, 1);
}

#[test]
fn test_unlinker_vault_status_after_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("s1").unwrap();

    // One credential consumed (active), one still available
    let status = unlinker.vault().status();
    assert_eq!(status.available, 1);
    assert_eq!(status.active, 1);

    // End session marks consumed
    unlinker.end_session("s1").unwrap();
    let status = unlinker.vault().status();
    assert_eq!(status.consumed, 1);
    assert_eq!(status.active, 0);
}

// ═══════════════════════════════════════════════════════════════════
// Full Shield Pipeline Integration Tests (Sprint 4)
// ═══════════════════════════════════════════════════════════════════

/// Test the full outbound pipeline: PII sanitize → stylometric normalize.
/// Verifies that PII is replaced AND writing style is stripped.
#[test]
fn test_pipeline_sanitize_then_stylometric() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let normalizer = StylometricNormalizer::new(NormalizationLevel::Level2);

    let input = serde_json::json!({
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {
                "query": "I basically really want to find user@example.com!!!  🎉"
            }
        }
    });

    // Step 1: PII sanitization
    let sanitized = sanitizer.sanitize_json(&input).unwrap();
    let sanitized_query = sanitized["params"]["arguments"]["query"].as_str().unwrap();
    assert!(!sanitized_query.contains("user@example.com"));
    assert!(sanitized_query.contains("[PII_"));

    // Step 2: Stylometric normalization
    let normalized = normalizer.normalize_json(&sanitized).unwrap();
    let normalized_query = normalized["params"]["arguments"]["query"].as_str().unwrap();
    // Fillers removed
    assert!(!normalized_query.contains("basically"));
    assert!(!normalized_query.contains("really"));
    // Repeated punctuation normalized
    assert!(!normalized_query.contains("!!!"));
    // Emoji stripped
    assert!(!normalized_query.contains('🎉'));
    // PII placeholder preserved through normalization
    assert!(normalized_query.contains("[PII_"));
    // Semantic content preserved
    assert!(normalized_query.contains("want"));
    assert!(normalized_query.contains("find"));
}

/// Test the full inbound pipeline: desanitize → context record.
/// Verifies that PII is restored AND context is recorded.
#[test]
fn test_pipeline_desanitize_then_context_record() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let context = ContextIsolator::new();

    // Simulate outbound: sanitize via JSON (so the mapping is established)
    let outbound = serde_json::json!({
        "params": {
            "arguments": {
                "query": "Email user@example.com for details"
            }
        }
    });
    let sanitized = sanitizer.sanitize_json(&outbound).unwrap();
    let sanitized_text = sanitized["params"]["arguments"]["query"].as_str().unwrap();
    assert!(sanitized_text.contains("[PII_"));

    // Extract the actual PII placeholder the sanitizer produced
    let placeholder = sanitized_text
        .split_whitespace()
        .find(|s| s.starts_with("[PII_"))
        .unwrap_or("[PII_EMAIL_000001]");

    // Simulate inbound response using the actual placeholder
    let response = serde_json::json!({
        "id": 1,
        "result": {
            "content": [{
                "type": "text",
                "text": format!("Contact {} for more information", placeholder)
            }]
        }
    });

    // Step 1: Desanitize
    let desanitized = sanitizer.desanitize_json(&response).unwrap();
    let restored = desanitized["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(restored.contains("user@example.com"));
    assert!(!restored.contains("[PII_"));

    // Step 2: Record context (with desanitized response)
    context
        .record_json_response("session-1", &desanitized)
        .unwrap();
    let entries = context.get_recent_context("session-1", 10).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "assistant");
    assert!(entries[0].1.contains("user@example.com"));
}

/// Test context isolation between sessions.
/// Verifies that recording in one session doesn't affect another.
#[test]
fn test_pipeline_context_session_isolation() {
    let context = ContextIsolator::new();

    let req1 = serde_json::json!({"method": "tools/call", "params": {"name": "tool_a"}});
    let req2 = serde_json::json!({"method": "tools/call", "params": {"name": "tool_b"}});

    context.record_json_request("session-1", &req1).unwrap();
    context.record_json_request("session-2", &req2).unwrap();

    let ctx1 = context.get_recent_context("session-1", 10).unwrap();
    let ctx2 = context.get_recent_context("session-2", 10).unwrap();

    assert_eq!(ctx1.len(), 1);
    assert_eq!(ctx2.len(), 1);
    assert!(ctx1[0].1.contains("tool_a"));
    assert!(ctx2[0].1.contains("tool_b"));
    // No cross-session leakage
    assert!(!ctx1[0].1.contains("tool_b"));
    assert!(!ctx2[0].1.contains("tool_a"));
}

/// Test full session lifecycle: start → tool calls → end.
/// Verifies credential consumption and vault state changes.
#[test]
fn test_pipeline_session_lifecycle() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();

    let context = ContextIsolator::new();
    let unlinker = SessionUnlinker::new(vault);

    // Start session
    let cred = unlinker.start_session("s1").unwrap();
    assert_eq!(cred.issued_epoch, 1);

    // Simulate tool call context
    let req = serde_json::json!({
        "method": "tools/call",
        "params": {"name": "search", "arguments": {"q": "test"}}
    });
    context.record_json_request("s1", &req).unwrap();

    // Simulate response context
    let resp = serde_json::json!({
        "id": 1,
        "result": {"content": [{"type": "text", "text": "result data"}]}
    });
    context.record_json_response("s1", &resp).unwrap();

    // Verify context recorded
    assert_eq!(context.entry_count("s1"), 2);

    // End session
    unlinker.end_session("s1").unwrap();
    context.end_session("s1");

    // Verify cleanup
    assert!(!unlinker.is_session_active("s1"));
    assert_eq!(context.entry_count("s1"), 0);
    assert_eq!(unlinker.vault().status().consumed, 1);
}

/// Test that disabled stylometric normalizer passes through unchanged.
#[test]
fn test_pipeline_stylometric_disabled_passthrough() {
    let normalizer = StylometricNormalizer::new(NormalizationLevel::None);
    let input = serde_json::json!({
        "params": {
            "arguments": {
                "text": "I basically really want this!!!  🎉"
            }
        }
    });
    let result = normalizer.normalize_json(&input).unwrap();
    // Everything preserved when disabled
    assert_eq!(
        result["params"]["arguments"]["text"].as_str().unwrap(),
        "I basically really want this!!!  🎉"
    );
}

/// Test the complete roundtrip: sanitize → normalize → forward → desanitize.
/// Verifies PII integrity through the full pipeline.
#[test]
fn test_pipeline_full_roundtrip_pii_integrity() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let normalizer = StylometricNormalizer::new(NormalizationLevel::Level1);

    // Outbound: user query with PII
    let user_input = "Call admin@corp.com for details";
    let sanitized = sanitizer.sanitize(user_input).unwrap();
    assert!(!sanitized.contains("admin@corp.com"));
    assert!(sanitized.contains("[PII_"));

    // Stylometric normalize (shouldn't affect PII placeholders)
    let normalized = normalizer.normalize(&sanitized).unwrap();
    // PII placeholders have specific format — should survive normalization
    assert!(normalized.contains("[PII_"));

    // Extract the placeholder from the normalized text
    let placeholder = normalized
        .split_whitespace()
        .find(|s| s.starts_with("[PII_"))
        .unwrap();

    // Simulate: provider responds with the placeholder
    let provider_response = format!("Please contact {placeholder} for assistance");

    // Inbound: desanitize
    let desanitized = sanitizer.desanitize(&provider_response).unwrap();
    // Original value restored
    assert!(desanitized.contains("admin@corp.com"));
    assert!(!desanitized.contains("[PII_"));
}

/// Test error path: sanitizer capacity exhausted doesn't break stylometric.
#[test]
fn test_pipeline_error_isolation() {
    let normalizer = StylometricNormalizer::new(NormalizationLevel::Level1);

    // Even if sanitizer fails (not tested here), stylometric should work
    // independently on any JSON input
    let input = serde_json::json!({"text": "hello   world!!!"});
    let result = normalizer.normalize_json(&input).unwrap();
    assert_eq!(result["text"].as_str().unwrap(), "hello world!");
}

/// Test that context isolator handles rapid session creation/teardown.
#[test]
fn test_pipeline_rapid_session_churn() {
    let context = ContextIsolator::new();

    for i in 0..100 {
        let session_id = format!("session-{i}");
        let req = serde_json::json!({"method": "tools/call", "params": {"name": "test"}});
        context.record_json_request(&session_id, &req).unwrap();
        context.end_session(&session_id);
    }

    // All sessions cleaned up
    assert_eq!(context.session_count(), 0);
}
