// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Canonical JSON Schema hashing for MCP tool definitions.
//!
//! This normalizes internal `$ref` indirection before hashing and rejects
//! external references so tool-definition pins cannot hide SSRF or fetch-DoS
//! behavior behind schema resolution.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX_SCHEMA_BYTES: usize = 256 * 1024;
const MAX_SCHEMA_DEPTH: usize = 64;
const MAX_REF_EXPANSIONS: usize = 256;
const MAX_POINTER_TOKENS: usize = 128;
const MAX_REF_DISPLAY_BYTES: usize = 160;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaCanonicalError {
    Oversized { size: usize, max: usize },
    DepthExceeded { max: usize },
    RefExpansionLimit { max: usize },
    RefMustBeString,
    ExternalRef { reference: String },
    InvalidPointer { reference: String },
    MissingRef { reference: String },
    CyclicRef { reference: String },
    Serialization(String),
    Canonicalization(String),
}

impl std::fmt::Display for SchemaCanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversized { size, max } => {
                write!(f, "schema size {size} exceeds maximum {max} bytes")
            }
            Self::DepthExceeded { max } => write!(f, "schema depth limit {max} exceeded"),
            Self::RefExpansionLimit { max } => {
                write!(f, "schema $ref expansion limit {max} exceeded")
            }
            Self::RefMustBeString => write!(f, "schema $ref must be a string"),
            Self::ExternalRef { reference } => {
                write!(f, "external schema $ref is not allowed: {reference}")
            }
            Self::InvalidPointer { reference } => {
                write!(
                    f,
                    "schema $ref is not a supported JSON pointer: {reference}"
                )
            }
            Self::MissingRef { reference } => {
                write!(f, "schema $ref target not found: {reference}")
            }
            Self::CyclicRef { reference } => write!(f, "cyclic schema $ref detected: {reference}"),
            Self::Serialization(err) => write!(f, "schema serialization failed: {err}"),
            Self::Canonicalization(err) => write!(f, "schema canonicalization failed: {err}"),
        }
    }
}

impl std::error::Error for SchemaCanonicalError {}

#[derive(Default)]
struct CanonicalContext {
    ref_stack: Vec<String>,
    ref_expansions: usize,
}

/// Compute the canonical SHA-256 hash for a JSON Schema value.
pub fn canonical_schema_hash(schema: &Value) -> Result<String, SchemaCanonicalError> {
    let bytes = canonical_schema_bytes(schema)?;
    Ok(sha256_hex(&bytes))
}

/// Compute the manifest hash for an optional MCP `inputSchema`.
///
/// Missing schemas preserve the existing manifest contract: hash the empty
/// string. Present schemas are normalized and hashed.
pub fn manifest_input_schema_hash(schema: Option<&Value>) -> Result<String, SchemaCanonicalError> {
    match schema {
        Some(schema) => canonical_schema_hash(schema),
        None => Ok(sha256_hex(b"")),
    }
}

/// Return RFC 8785 canonical JSON bytes after schema-specific normalization.
pub fn canonical_schema_bytes(schema: &Value) -> Result<Vec<u8>, SchemaCanonicalError> {
    ensure_size_bound(schema)?;
    validate_refs(schema, 0)?;
    let mut ctx = CanonicalContext::default();
    let normalized = normalize_schema_value(schema, schema, 0, None, &mut ctx)?;
    serde_json_canonicalizer::to_string(&normalized)
        .map(|s| s.into_bytes())
        .map_err(|err| SchemaCanonicalError::Canonicalization(err.to_string()))
}

fn ensure_size_bound(value: &Value) -> Result<(), SchemaCanonicalError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|err| SchemaCanonicalError::Serialization(err.to_string()))?;
    if bytes.len() > MAX_SCHEMA_BYTES {
        return Err(SchemaCanonicalError::Oversized {
            size: bytes.len(),
            max: MAX_SCHEMA_BYTES,
        });
    }
    Ok(())
}

fn validate_refs(value: &Value, depth: usize) -> Result<(), SchemaCanonicalError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaCanonicalError::DepthExceeded {
            max: MAX_SCHEMA_DEPTH,
        });
    }
    match value {
        Value::Array(items) => {
            for item in items {
                validate_refs(item, depth + 1)?;
            }
        }
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref") {
                let Some(reference) = reference.as_str() else {
                    return Err(SchemaCanonicalError::RefMustBeString);
                };
                validate_local_ref(reference)?;
            }
            for child in object.values() {
                validate_refs(child, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize_schema_value(
    root: &Value,
    value: &Value,
    depth: usize,
    parent_key: Option<&str>,
    ctx: &mut CanonicalContext,
) -> Result<Value, SchemaCanonicalError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaCanonicalError::DepthExceeded {
            max: MAX_SCHEMA_DEPTH,
        });
    }

    match value {
        Value::Object(object) => normalize_schema_object(root, object, depth, ctx),
        Value::Array(items) => normalize_schema_array(root, items, depth, parent_key, ctx),
        _ => Ok(value.clone()),
    }
}

fn normalize_schema_object(
    root: &Value,
    object: &Map<String, Value>,
    depth: usize,
    ctx: &mut CanonicalContext,
) -> Result<Value, SchemaCanonicalError> {
    if let Some(reference) = object.get("$ref") {
        let Some(reference) = reference.as_str() else {
            return Err(SchemaCanonicalError::RefMustBeString);
        };
        validate_local_ref(reference)?;
        if ctx.ref_expansions >= MAX_REF_EXPANSIONS {
            return Err(SchemaCanonicalError::RefExpansionLimit {
                max: MAX_REF_EXPANSIONS,
            });
        }
        if ctx.ref_stack.iter().any(|active| active == reference) {
            return Err(SchemaCanonicalError::CyclicRef {
                reference: display_ref(reference),
            });
        }

        ctx.ref_expansions += 1;
        ctx.ref_stack.push(reference.to_string());
        let target = resolve_local_ref(root, reference)?;
        let expanded = normalize_schema_value(root, target, depth + 1, Some("$ref"), ctx)?;
        ctx.ref_stack.pop();

        let siblings = normalize_sibling_keywords(root, object, depth, ctx)?;
        if siblings.is_empty() {
            Ok(expanded)
        } else {
            Ok(serde_json::json!({
                "allOf": [expanded, Value::Object(siblings)]
            }))
        }
    } else {
        let mut normalized = Map::new();
        for (key, child) in object {
            if is_definition_container(key) {
                continue;
            }
            normalized.insert(
                key.clone(),
                normalize_schema_value(root, child, depth + 1, Some(key.as_str()), ctx)?,
            );
        }
        Ok(Value::Object(normalized))
    }
}

fn normalize_sibling_keywords(
    root: &Value,
    object: &Map<String, Value>,
    depth: usize,
    ctx: &mut CanonicalContext,
) -> Result<Map<String, Value>, SchemaCanonicalError> {
    let mut siblings = Map::new();
    for (key, child) in object {
        if key == "$ref" || is_definition_container(key) {
            continue;
        }
        siblings.insert(
            key.clone(),
            normalize_schema_value(root, child, depth + 1, Some(key.as_str()), ctx)?,
        );
    }
    Ok(siblings)
}

fn normalize_schema_array(
    root: &Value,
    items: &[Value],
    depth: usize,
    parent_key: Option<&str>,
    ctx: &mut CanonicalContext,
) -> Result<Value, SchemaCanonicalError> {
    let mut normalized = Vec::with_capacity(items.len());
    for item in items {
        normalized.push(normalize_schema_value(root, item, depth + 1, None, ctx)?);
    }
    if parent_key.is_some_and(is_unordered_array_keyword) {
        normalized.sort_by(|left, right| {
            let left = serde_json_canonicalizer::to_string(left).unwrap_or_default();
            let right = serde_json_canonicalizer::to_string(right).unwrap_or_default();
            left.cmp(&right)
        });
    }
    Ok(Value::Array(normalized))
}

fn is_definition_container(key: &str) -> bool {
    key == "$defs" || key == "definitions"
}

fn is_unordered_array_keyword(key: &str) -> bool {
    matches!(
        key,
        "allOf" | "anyOf" | "oneOf" | "enum" | "required" | "type"
    )
}

fn validate_local_ref(reference: &str) -> Result<(), SchemaCanonicalError> {
    if !reference.starts_with('#') {
        return Err(SchemaCanonicalError::ExternalRef {
            reference: display_ref(reference),
        });
    }
    if reference == "#" || reference.starts_with("#/") {
        decode_pointer_tokens(reference)?;
        return Ok(());
    }
    Err(SchemaCanonicalError::InvalidPointer {
        reference: display_ref(reference),
    })
}

fn resolve_local_ref<'a>(
    root: &'a Value,
    reference: &str,
) -> Result<&'a Value, SchemaCanonicalError> {
    let tokens = decode_pointer_tokens(reference)?;
    let mut current = root;
    for token in tokens {
        match current {
            Value::Object(object) => {
                current = object
                    .get(&token)
                    .ok_or_else(|| SchemaCanonicalError::MissingRef {
                        reference: display_ref(reference),
                    })?;
            }
            Value::Array(items) => {
                let index =
                    token
                        .parse::<usize>()
                        .map_err(|_| SchemaCanonicalError::InvalidPointer {
                            reference: display_ref(reference),
                        })?;
                current = items
                    .get(index)
                    .ok_or_else(|| SchemaCanonicalError::MissingRef {
                        reference: display_ref(reference),
                    })?;
            }
            _ => {
                return Err(SchemaCanonicalError::MissingRef {
                    reference: display_ref(reference),
                });
            }
        }
    }
    Ok(current)
}

fn decode_pointer_tokens(reference: &str) -> Result<Vec<String>, SchemaCanonicalError> {
    if reference == "#" {
        return Ok(Vec::new());
    }
    let Some(pointer) = reference.strip_prefix("#/") else {
        return Err(SchemaCanonicalError::InvalidPointer {
            reference: display_ref(reference),
        });
    };
    let parts: Vec<&str> = pointer.split('/').collect();
    if parts.len() > MAX_POINTER_TOKENS {
        return Err(SchemaCanonicalError::InvalidPointer {
            reference: display_ref(reference),
        });
    }
    let mut tokens = Vec::with_capacity(parts.len());
    for part in parts {
        tokens.push(decode_pointer_token(part).ok_or_else(|| {
            SchemaCanonicalError::InvalidPointer {
                reference: display_ref(reference),
            }
        })?);
    }
    Ok(tokens)
}

fn decode_pointer_token(token: &str) -> Option<String> {
    let mut decoded = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' {
            match chars.next()? {
                '0' => decoded.push('~'),
                '1' => decoded.push('/'),
                _ => return None,
            }
        } else {
            decoded.push(ch);
        }
    }
    Some(decoded)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn display_ref(reference: &str) -> String {
    if reference.len() <= MAX_REF_DISPLAY_BYTES {
        reference.to_string()
    } else {
        let truncated: String = reference.chars().take(MAX_REF_DISPLAY_BYTES).collect();
        format!("{truncated}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_hash_ignores_object_key_order_and_required_order() {
        let left = json!({
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            }
        });
        let right: Value = serde_json::from_str(
            r#"{
                "properties": {
                    "age": {"type": "integer"},
                    "name": {"type": "string"}
                },
                "required": ["age", "name"],
                "type": "object"
            }"#,
        )
        .expect("test schema parses");

        assert_eq!(
            canonical_schema_hash(&left).expect("left canonicalizes"),
            canonical_schema_hash(&right).expect("right canonicalizes")
        );
    }

    #[test]
    fn canonical_hash_inlines_local_defs_refs() {
        let referenced = json!({
            "$defs": {
                "Path": {"type": "string", "minLength": 1}
            },
            "type": "object",
            "properties": {
                "path": {"$ref": "#/$defs/Path"}
            }
        });
        let inline = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1}
            }
        });

        assert_eq!(
            canonical_schema_hash(&referenced).expect("ref schema canonicalizes"),
            canonical_schema_hash(&inline).expect("inline schema canonicalizes")
        );
    }

    #[test]
    fn external_ref_is_rejected() {
        let schema = json!({"$ref": "https://metadata.internal/schema.json"});
        let err = canonical_schema_hash(&schema).expect_err("external refs fail closed");
        assert!(matches!(err, SchemaCanonicalError::ExternalRef { .. }));
    }

    #[test]
    fn cyclic_ref_is_rejected() {
        let schema = json!({
            "$defs": {
                "Node": {"$ref": "#/$defs/Node"}
            },
            "$ref": "#/$defs/Node"
        });
        let err = canonical_schema_hash(&schema).expect_err("cyclic refs fail closed");
        assert!(matches!(err, SchemaCanonicalError::CyclicRef { .. }));
    }

    #[test]
    fn missing_manifest_schema_hashes_empty_string() {
        assert_eq!(
            manifest_input_schema_hash(None).expect("missing schema hashes"),
            sha256_hex(b"")
        );
    }
}
