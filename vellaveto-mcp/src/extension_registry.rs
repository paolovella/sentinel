// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Protocol extension registry.
//!
//! Manages loaded extensions, routes `x-` prefixed method calls to the
//! appropriate handler, and enforces allow/block patterns from configuration.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::RwLock;
use vellaveto_types::{
    ExtensionDescriptor, ExtensionError, ExtensionNegotiationResult, ExtensionResourceLimits,
};

/// Maximum number of registered extensions.
const MAX_EXTENSIONS: usize = 256;

/// Lifecycle hook for extension integration.
///
/// Implementors handle `x-<extension_id>/...` method calls.
/// The trait is `Send + Sync` for safe sharing across async tasks.
pub trait ExtensionHandler: Send + Sync {
    /// Called when the extension is loaded into the registry.
    fn on_load(&self, descriptor: &ExtensionDescriptor) -> Result<(), ExtensionError>;

    /// Called when the extension is unloaded from the registry.
    fn on_unload(&self, extension_id: &str);

    /// Handle a method call routed to this extension.
    fn handle_method(&self, method: &str, params: &Value) -> Result<Value, ExtensionError>;

    /// Return the extension descriptor.
    fn descriptor(&self) -> &ExtensionDescriptor;
}

/// A registered extension with its handler and resource limits.
struct RegisteredExtension {
    handler: Box<dyn ExtensionHandler>,
    _limits: ExtensionResourceLimits,
}

/// Registry of loaded protocol extensions.
///
/// Thread-safe via `RwLock`. Method routing uses a separate map for O(1) dispatch.
pub struct ExtensionRegistry {
    extensions: RwLock<HashMap<String, RegisteredExtension>>,
    method_routes: RwLock<HashMap<String, String>>,
    allowed_patterns: Vec<String>,
    blocked_patterns: Vec<String>,
    require_signatures: bool,
    trusted_keys: Vec<String>,
    default_limits: ExtensionResourceLimits,
}

impl ExtensionRegistry {
    /// Create a new extension registry from configuration.
    pub fn new(
        allowed_patterns: Vec<String>,
        blocked_patterns: Vec<String>,
        require_signatures: bool,
        trusted_keys: Vec<String>,
        default_limits: ExtensionResourceLimits,
    ) -> Self {
        Self {
            extensions: RwLock::new(HashMap::new()),
            method_routes: RwLock::new(HashMap::new()),
            allowed_patterns,
            blocked_patterns,
            require_signatures,
            trusted_keys,
            default_limits,
        }
    }

    /// Register an extension handler.
    ///
    /// Validates the descriptor, checks allow/block patterns, registers method routes,
    /// and calls `on_load` on the handler.
    pub fn register(&self, handler: Box<dyn ExtensionHandler>) -> Result<(), ExtensionError> {
        let descriptor = handler.descriptor().clone();
        descriptor.validate()?;

        // Check if blocked
        if self.is_blocked(&descriptor.id) {
            return Err(ExtensionError::Blocked(format!(
                "Extension '{}' is blocked by configuration",
                descriptor.id
            )));
        }

        // Check if allowed
        if !self.is_allowed(&descriptor.id) {
            return Err(ExtensionError::Blocked(format!(
                "Extension '{}' is not in the allow list",
                descriptor.id
            )));
        }

        // SECURITY (FIND-R46-EXT-001): Verify extension signatures when required.
        // Previously, only checked for signature *presence* but never verified it,
        // allowing any arbitrary signature string to pass.
        if self.require_signatures {
            let sig_hex = match &descriptor.signature {
                Some(s) => s,
                None => {
                    return Err(ExtensionError::Validation(format!(
                        "Extension '{}' requires a signature but none provided",
                        descriptor.id
                    )));
                }
            };
            let pub_key_hex = match &descriptor.public_key {
                Some(k) => k,
                None => {
                    return Err(ExtensionError::Validation(format!(
                        "Extension '{}' requires a public_key for signature verification",
                        descriptor.id
                    )));
                }
            };

            // Verify the public key is in the trusted keys list
            if !self.trusted_keys.iter().any(|k| k == pub_key_hex) {
                return Err(ExtensionError::Validation(format!(
                    "Extension '{}' signed by untrusted key: {}",
                    descriptor.id,
                    if pub_key_hex.len() > 16 {
                        &pub_key_hex[..16]
                    } else {
                        pub_key_hex
                    }
                )));
            }

            // Verify the Ed25519 signature over the canonical descriptor
            // (with signature and public_key fields set to None)
            let verify_result = verify_extension_signature(&descriptor, sig_hex, pub_key_hex);
            if let Err(e) = verify_result {
                return Err(ExtensionError::Validation(format!(
                    "Extension '{}' signature verification failed: {}",
                    descriptor.id, e
                )));
            }
        }

        // Check max extensions
        let extensions = self
            .extensions
            .read()
            .map_err(|e| ExtensionError::HandlerFailed(format!("Lock poisoned: {e}")))?;
        if extensions.len() >= MAX_EXTENSIONS {
            return Err(ExtensionError::Validation(format!(
                "Too many extensions: max {MAX_EXTENSIONS}"
            )));
        }
        if extensions.contains_key(&descriptor.id) {
            return Err(ExtensionError::AlreadyRegistered(descriptor.id.clone()));
        }
        drop(extensions);

        // Check for method conflicts (early fast path under read lock)
        {
            let routes = self
                .method_routes
                .read()
                .map_err(|e| ExtensionError::HandlerFailed(format!("Lock poisoned: {e}")))?;
            for method in &descriptor.methods {
                if let Some(existing) = routes.get(method) {
                    return Err(ExtensionError::AlreadyRegistered(format!(
                        "Method '{method}' already registered by extension '{existing}'"
                    )));
                }
            }
        }

        // Call on_load
        handler.on_load(&descriptor)?;

        // Register method routes
        //
        // SECURITY (FIND-R111-005): Re-check for method conflicts under the write lock
        // before inserting. The read-lock check above is a fast path that catches most
        // conflicts, but there is a TOCTOU window between releasing the read lock and
        // acquiring the write lock during which a concurrent caller may have registered
        // the same methods. Re-checking under the write lock closes this race and
        // ensures the check-and-insert is atomic.
        {
            let mut routes = self
                .method_routes
                .write()
                .map_err(|e| ExtensionError::HandlerFailed(format!("Lock poisoned: {e}")))?;
            // Re-check for conflicts under write lock to close TOCTOU race
            for method in &descriptor.methods {
                if let Some(existing) = routes.get(method) {
                    return Err(ExtensionError::AlreadyRegistered(format!(
                        "Method '{method}' already registered by extension '{existing}' (concurrent registration race)"
                    )));
                }
            }
            for method in &descriptor.methods {
                routes.insert(method.clone(), descriptor.id.clone());
            }
        }

        // Register extension
        {
            let mut extensions = self
                .extensions
                .write()
                .map_err(|e| ExtensionError::HandlerFailed(format!("Lock poisoned: {e}")))?;

            // SECURITY (FIND-R63-MCP-003): Re-check capacity and duplicate after
            // acquiring write lock to close TOCTOU race between the earlier read-lock
            // check and this write-lock insertion.
            if extensions.len() >= MAX_EXTENSIONS {
                // SECURITY (FIND-R176-001): Roll back method routes inserted above
                // to prevent orphaned entries blocking future registrations.
                // SECURITY (FIND-R192-006): Handle poisoned lock with error logging.
                match self.method_routes.write() {
                    Ok(mut routes) => {
                        for method in &descriptor.methods {
                            routes.remove(method);
                        }
                    }
                    Err(_) => {
                        tracing::error!(
                            target: "vellaveto::security",
                            "method_routes write lock poisoned during rollback (max extensions) — orphaned routes may remain"
                        );
                    }
                }
                return Err(ExtensionError::Validation(format!(
                    "Too many extensions: max {MAX_EXTENSIONS}"
                )));
            }
            if extensions.contains_key(&descriptor.id) {
                // SECURITY (FIND-R176-001): Roll back method routes inserted above.
                // SECURITY (FIND-R192-006): Handle poisoned lock with error logging.
                match self.method_routes.write() {
                    Ok(mut routes) => {
                        for method in &descriptor.methods {
                            routes.remove(method);
                        }
                    }
                    Err(_) => {
                        tracing::error!(
                            target: "vellaveto::security",
                            "method_routes write lock poisoned during rollback (duplicate extension) — orphaned routes may remain"
                        );
                    }
                }
                return Err(ExtensionError::AlreadyRegistered(descriptor.id.clone()));
            }

            extensions.insert(
                descriptor.id.clone(),
                RegisteredExtension {
                    handler,
                    _limits: self.default_limits.clone(),
                },
            );
        }

        tracing::info!(
            extension_id = %descriptor.id,
            version = %descriptor.version,
            methods = ?descriptor.methods,
            "Extension registered"
        );

        Ok(())
    }

    /// Unregister an extension by ID.
    pub fn unregister(&self, extension_id: &str) -> Result<(), ExtensionError> {
        let mut extensions = self
            .extensions
            .write()
            .map_err(|e| ExtensionError::HandlerFailed(format!("Lock poisoned: {e}")))?;

        let ext = extensions.remove(extension_id).ok_or_else(|| {
            ExtensionError::NotFound(format!("Extension '{extension_id}' not found"))
        })?;

        // Remove method routes
        let methods = ext.handler.descriptor().methods.clone();
        drop(extensions);

        {
            let mut routes = self
                .method_routes
                .write()
                .map_err(|e| ExtensionError::HandlerFailed(format!("Lock poisoned: {e}")))?;
            for method in &methods {
                routes.remove(method);
            }
        }

        // Call on_unload
        ext.handler.on_unload(extension_id);

        tracing::info!(extension_id = %extension_id, "Extension unregistered");
        Ok(())
    }

    /// Negotiate which extensions from a requested list are available.
    pub fn negotiate(&self, requested: &[String]) -> ExtensionNegotiationResult {
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();

        // SECURITY (FIND-R173-001): Cap iteration to prevent OOM from
        // attacker-supplied extension lists with millions of entries.
        const MAX_EXTENSION_REQUESTS: usize = 1000;
        for id in requested.iter().take(MAX_EXTENSION_REQUESTS) {
            if self.is_blocked(id) {
                rejected.push((id.clone(), "Blocked by configuration".to_string()));
            } else if !self.is_allowed(id) {
                rejected.push((id.clone(), "Not in allow list".to_string()));
            } else {
                accepted.push(id.clone());
            }
        }

        ExtensionNegotiationResult { accepted, rejected }
    }

    /// Route a method call to the appropriate extension handler.
    pub fn route_method(&self, method: &str, params: &Value) -> Result<Value, ExtensionError> {
        let extension_id = {
            let routes = self
                .method_routes
                .read()
                .map_err(|e| ExtensionError::HandlerFailed(format!("Lock poisoned: {e}")))?;
            routes.get(method).cloned().ok_or_else(|| {
                ExtensionError::MethodNotFound(format!("No handler for method '{method}'"))
            })?
        };

        let extensions = self
            .extensions
            .read()
            .map_err(|e| ExtensionError::HandlerFailed(format!("Lock poisoned: {e}")))?;

        let ext = extensions.get(&extension_id).ok_or_else(|| {
            ExtensionError::NotFound(format!(
                "Extension '{extension_id}' not found (method '{method}')"
            ))
        })?;

        ext.handler.handle_method(method, params)
    }

    /// List all registered extension descriptors.
    pub fn list_extensions(&self) -> Vec<ExtensionDescriptor> {
        let extensions = match self.extensions.read() {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        extensions
            .values()
            .map(|e| e.handler.descriptor().clone())
            .collect()
    }

    /// Check if an extension ID is allowed by the allow patterns.
    /// Phase 1: Check if an extension method is permitted by the registry's
    /// allow/block patterns. Returns Ok(()) if allowed, Err(reason) if denied.
    pub fn check_method_permitted(&self, extension_id: &str) -> Result<(), String> {
        if self.is_blocked(extension_id) {
            return Err(format!(
                "extension '{}' blocked by registry pattern",
                &extension_id[..extension_id.len().min(64)]
            ));
        }
        if !self.is_allowed(extension_id) {
            return Err(format!(
                "extension '{}' not in registry allowed patterns",
                &extension_id[..extension_id.len().min(64)]
            ));
        }
        Ok(())
    }

    fn is_allowed(&self, id: &str) -> bool {
        if self.allowed_patterns.is_empty() {
            return true; // Empty allowlist = allow all (subject to blocklist)
        }
        self.allowed_patterns.iter().any(|p| glob_match(p, id))
    }

    /// Check if an extension ID is blocked by the block patterns.
    fn is_blocked(&self, id: &str) -> bool {
        self.blocked_patterns.iter().any(|p| glob_match(p, id))
    }
}

/// Verify an Ed25519 signature over the canonical extension descriptor.
///
/// SECURITY (FIND-R46-EXT-001): The signed content is the canonical JSON of the
/// descriptor with `signature` and `public_key` fields set to `None`.
fn verify_extension_signature(
    descriptor: &ExtensionDescriptor,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};

    // Decode the public key
    let pub_key_bytes =
        hex::decode(public_key_hex).map_err(|e| format!("invalid public key hex: {e}"))?;
    if pub_key_bytes.len() != 32 {
        return Err(format!(
            "public key has wrong length: {} (expected 32)",
            pub_key_bytes.len()
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pub_key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;

    // Decode the signature
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("invalid signature hex: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature has wrong length: {} (expected 64)",
            sig_bytes.len()
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    // Build canonical content: descriptor with signature and public_key removed
    let mut canonical = descriptor.clone();
    canonical.signature = None;
    canonical.public_key = None;
    let canonical_json = serde_json::to_vec(&canonical)
        .map_err(|e| format!("failed to serialize canonical descriptor: {e}"))?;

    // Verify
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(&canonical_json, &signature)
        .map_err(|_| "Ed25519 signature verification failed".to_string())
}

/// Simple glob matching supporting `*` (any characters) and `?` (single character).
///
/// Delegates to the shared implementation in `crate::util`.
fn glob_match(pattern: &str, text: &str) -> bool {
    crate::util::glob_match(pattern, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A simple test extension handler.
    struct TestHandler {
        descriptor: ExtensionDescriptor,
    }

    impl TestHandler {
        fn new(id: &str, methods: Vec<String>) -> Self {
            Self {
                descriptor: ExtensionDescriptor {
                    id: id.to_string(),
                    name: format!("Test {id}"),
                    version: "1.0.0".to_string(),
                    capabilities: vec![],
                    methods,
                    signature: None,
                    public_key: None,
                },
            }
        }
    }

    impl ExtensionHandler for TestHandler {
        fn on_load(&self, _descriptor: &ExtensionDescriptor) -> Result<(), ExtensionError> {
            Ok(())
        }
        fn on_unload(&self, _extension_id: &str) {}
        fn handle_method(&self, method: &str, _params: &Value) -> Result<Value, ExtensionError> {
            Ok(json!({"handled": method}))
        }
        fn descriptor(&self) -> &ExtensionDescriptor {
            &self.descriptor
        }
    }

    fn test_registry() -> ExtensionRegistry {
        ExtensionRegistry::new(
            vec![],
            vec![],
            false,
            vec![],
            ExtensionResourceLimits::default(),
        )
    }

    #[test]
    fn test_register_and_route() {
        let registry = test_registry();
        let handler = TestHandler::new("x-test", vec!["x-test/hello".to_string()]);
        registry.register(Box::new(handler)).unwrap();

        let result = registry.route_method("x-test/hello", &json!({})).unwrap();
        assert_eq!(result["handled"], "x-test/hello");
    }

    #[test]
    fn test_unregister() {
        let registry = test_registry();
        let handler = TestHandler::new("x-test", vec!["x-test/hello".to_string()]);
        registry.register(Box::new(handler)).unwrap();
        registry.unregister("x-test").unwrap();

        let result = registry.route_method("x-test/hello", &json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn test_negotiate_allowed() {
        let registry = ExtensionRegistry::new(
            vec!["x-allowed-*".to_string()],
            vec![],
            false,
            vec![],
            ExtensionResourceLimits::default(),
        );
        let result =
            registry.negotiate(&["x-allowed-foo".to_string(), "x-blocked-bar".to_string()]);
        assert_eq!(result.accepted, vec!["x-allowed-foo"]);
        assert_eq!(result.rejected.len(), 1);
        assert_eq!(result.rejected[0].0, "x-blocked-bar");
    }

    #[test]
    fn test_negotiate_blocked() {
        let registry = ExtensionRegistry::new(
            vec![],
            vec!["x-evil-*".to_string()],
            false,
            vec![],
            ExtensionResourceLimits::default(),
        );
        let result = registry.negotiate(&["x-evil-ext".to_string()]);
        assert!(result.accepted.is_empty());
        assert_eq!(result.rejected.len(), 1);
    }

    #[test]
    fn test_unknown_method_error() {
        let registry = test_registry();
        let result = registry.route_method("x-nonexistent/method", &json!({}));
        assert!(matches!(result, Err(ExtensionError::MethodNotFound(_))));
    }

    #[test]
    fn test_duplicate_method_rejection() {
        let registry = test_registry();
        let handler1 = TestHandler::new("x-ext1", vec!["x-shared/method".to_string()]);
        registry.register(Box::new(handler1)).unwrap();

        let handler2 = TestHandler::new("x-ext2", vec!["x-shared/method".to_string()]);
        let result = registry.register(Box::new(handler2));
        assert!(matches!(result, Err(ExtensionError::AlreadyRegistered(_))));
    }

    #[test]
    fn test_duplicate_extension_rejection() {
        let registry = test_registry();
        let handler1 = TestHandler::new("x-dup", vec!["x-dup/a".to_string()]);
        registry.register(Box::new(handler1)).unwrap();

        let handler2 = TestHandler::new("x-dup", vec!["x-dup/b".to_string()]);
        let result = registry.register(Box::new(handler2));
        assert!(matches!(result, Err(ExtensionError::AlreadyRegistered(_))));
    }

    #[test]
    fn test_list_extensions() {
        let registry = test_registry();
        let handler = TestHandler::new("x-list-test", vec!["x-list-test/a".to_string()]);
        registry.register(Box::new(handler)).unwrap();

        let list = registry.list_extensions();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "x-list-test");
    }

    #[test]
    fn test_signature_required_but_missing() {
        let registry = ExtensionRegistry::new(
            vec![],
            vec![],
            true, // require signatures
            vec![],
            ExtensionResourceLimits::default(),
        );
        let handler = TestHandler::new("x-unsigned", vec![]);
        let result = registry.register(Box::new(handler));
        assert!(matches!(result, Err(ExtensionError::Validation(_))));
    }

    // SECURITY (FIND-R46-EXT-001): Extension signature verification tests

    #[test]
    fn test_signature_required_but_no_public_key() {
        let registry = ExtensionRegistry::new(
            vec![],
            vec![],
            true,
            vec![],
            ExtensionResourceLimits::default(),
        );
        let mut handler = TestHandler::new("x-nokey", vec![]);
        handler.descriptor.signature = Some("deadbeef".repeat(8));
        // No public_key → should fail
        let result = registry.register(Box::new(handler));
        assert!(
            matches!(result, Err(ExtensionError::Validation(ref msg)) if msg.contains("public_key"))
        );
    }

    #[test]
    fn test_signature_required_untrusted_key() {
        let registry = ExtensionRegistry::new(
            vec![],
            vec![],
            true,
            vec!["aaaa".repeat(16)], // trusted key that doesn't match
            ExtensionResourceLimits::default(),
        );
        let mut handler = TestHandler::new("x-untrusted", vec![]);
        handler.descriptor.signature = Some("deadbeef".repeat(8));
        handler.descriptor.public_key = Some("bbbb".repeat(16)); // not in trusted list
        let result = registry.register(Box::new(handler));
        assert!(
            matches!(result, Err(ExtensionError::Validation(ref msg)) if msg.contains("untrusted"))
        );
    }

    #[test]
    fn test_signature_required_invalid_signature() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::generate(&mut rand::rng());
        let pub_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let registry = ExtensionRegistry::new(
            vec![],
            vec![],
            true,
            vec![pub_key_hex.clone()],
            ExtensionResourceLimits::default(),
        );
        let mut handler = TestHandler::new("x-badsig", vec![]);
        handler.descriptor.signature = Some("00".repeat(64)); // invalid signature
        handler.descriptor.public_key = Some(pub_key_hex);
        let result = registry.register(Box::new(handler));
        assert!(
            matches!(result, Err(ExtensionError::Validation(ref msg)) if msg.contains("verification failed"))
        );
    }

    #[test]
    fn test_signature_required_valid_signature() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::generate(&mut rand::rng());
        let pub_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

        // Build descriptor, sign the canonical form
        let mut descriptor = ExtensionDescriptor {
            id: "x-signed".to_string(),
            name: "Signed Extension".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec![],
            methods: vec![],
            signature: None,
            public_key: None,
        };
        let canonical_json = serde_json::to_vec(&descriptor).unwrap();
        let sig = signing_key.sign(&canonical_json);
        let sig_hex = hex::encode(sig.to_bytes());

        descriptor.signature = Some(sig_hex);
        descriptor.public_key = Some(pub_key_hex.clone());

        let registry = ExtensionRegistry::new(
            vec![],
            vec![],
            true,
            vec![pub_key_hex],
            ExtensionResourceLimits::default(),
        );

        struct SignedHandler {
            descriptor: ExtensionDescriptor,
        }
        impl ExtensionHandler for SignedHandler {
            fn on_load(&self, _: &ExtensionDescriptor) -> Result<(), ExtensionError> {
                Ok(())
            }
            fn on_unload(&self, _: &str) {}
            fn handle_method(&self, method: &str, _: &Value) -> Result<Value, ExtensionError> {
                Ok(json!({"handled": method}))
            }
            fn descriptor(&self) -> &ExtensionDescriptor {
                &self.descriptor
            }
        }

        let handler = SignedHandler { descriptor };
        let result = registry.register(Box::new(handler));
        assert!(
            result.is_ok(),
            "Valid signature should be accepted: {:?}",
            result.err()
        );
    }

    // --- glob_match tests ---

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("x-*", "x-foo"));
        assert!(glob_match("x-*", "x-"));
        assert!(!glob_match("x-*", "y-foo"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("x-fo?", "x-foo"));
        assert!(!glob_match("x-fo?", "x-fooo"));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("x-exact", "x-exact"));
        assert!(!glob_match("x-exact", "x-other"));
    }
}
