// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! JSON-RPC message framing for MCP stdio transport.
//!
//! MCP uses newline-delimited JSON over stdin/stdout.
//! Each message is a single line of JSON followed by a newline.

use std::collections::HashSet;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Maximum line length (1 MB). Lines exceeding this are rejected to prevent OOM.
const MAX_LINE_LENGTH: usize = 1_048_576;

/// Read a single newline-delimited JSON message from a reader.
///
/// Returns `Ok(None)` on EOF, `Ok(Some(value))` on success.
/// Empty lines are skipped (not treated as EOF).
/// Lines exceeding `MAX_LINE_LENGTH` are rejected BEFORE full allocation
/// to prevent OOM from oversized messages.
pub async fn read_message<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<Value>, FramingError> {
    loop {
        let line_bytes = read_bounded_line(reader).await?;

        // EOF — no more data
        let line_bytes = match line_bytes {
            Some(b) => b,
            None => return Ok(None),
        };

        // Convert to string (MCP messages are always UTF-8 JSON)
        let line = String::from_utf8(line_bytes).map_err(|e| {
            FramingError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        // SECURITY (R10-FRAME-5): Strip UTF-8 BOM (U+FEFF, bytes EF BB BF)
        // from line start. Some clients/intermediaries prepend a BOM which
        // would cause an opaque JSON parse error. Consistent with the
        // zero-width char stripping done by normalize_method in extractor.rs.
        let line = line.strip_prefix('\u{FEFF}').unwrap_or(&line);

        // Fix #14: Skip empty lines instead of treating them as EOF.
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Defense-in-depth: reject JSON with duplicate keys at any nesting level.
        // serde_json uses last-key-wins, but other parsers may use first-key-wins.
        // An attacker could send {"path":"safe","path":"malicious"} to exploit
        // parser disagreement (CVE-2017-12635, CVE-2020-16250).
        if let Some(dup_key) = find_duplicate_json_key(trimmed) {
            return Err(FramingError::DuplicateKeys(dup_key));
        }

        let value: Value = serde_json::from_str(trimmed).map_err(FramingError::Json)?;

        // SECURITY (TI-2026-001 / CVE-2026-27896): JSON-RPC key case-folding smuggling.
        // Delegates to the extracted public function for transport-parity reuse.
        if let Some(key) = check_json_rpc_key_case_folding(&value) {
            return Err(FramingError::CaseFoldingSmuggle(key));
        }

        // MCP 2025-06-18 removed JSON-RPC batching. Reject arrays at the
        // transport layer so that batch payloads never reach the classifier.
        if value.is_array() {
            return Err(FramingError::BatchNotAllowed);
        }

        return Ok(Some(value));
    }
}

/// Read a single line from the reader, bounded by MAX_LINE_LENGTH.
///
/// Uses `fill_buf`/`consume` to check accumulated size BEFORE allocating,
/// preventing OOM from oversized lines without a newline.
/// Returns `Ok(None)` on EOF, `Ok(Some(bytes))` on success.
async fn read_bounded_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<Vec<u8>>, FramingError> {
    let mut accumulated = Vec::with_capacity(256);

    loop {
        let buf = reader.fill_buf().await.map_err(FramingError::Io)?;

        if buf.is_empty() {
            // EOF
            if accumulated.is_empty() {
                return Ok(None);
            }
            // Partial line at EOF — return what we have
            return Ok(Some(accumulated));
        }

        // Look for newline in the current buffer chunk
        match buf.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                // Found newline — check total size before allocating
                let needed = pos + 1; // include the newline
                if accumulated.len() + needed > MAX_LINE_LENGTH {
                    reader.consume(needed);
                    return Err(FramingError::LineTooLong(accumulated.len() + needed));
                }
                accumulated.extend_from_slice(&buf[..needed]);
                reader.consume(needed);
                return Ok(Some(accumulated));
            }
            None => {
                // No newline in this chunk — check total size before extending
                let chunk_len = buf.len();
                if accumulated.len() + chunk_len > MAX_LINE_LENGTH {
                    reader.consume(chunk_len);
                    // SECURITY (R10-FRAME-7): Drain the remainder of the
                    // oversized line up to the next newline (or EOF). Without
                    // this, a retry would pick up a fragment that could be
                    // crafted as valid JSON, causing framing desync.
                    drain_until_newline(reader).await;
                    return Err(FramingError::LineTooLong(accumulated.len() + chunk_len));
                }
                accumulated.extend_from_slice(buf);
                reader.consume(chunk_len);
            }
        }
    }
}

/// Drain bytes from the reader until a newline or EOF is reached.
///
/// Used after a `LineTooLong` error to re-synchronize the reader to the
/// next message boundary. Without this, a retry after an oversized line
/// would pick up a tail fragment that could be crafted as valid JSON.
async fn drain_until_newline<R: tokio::io::AsyncRead + Unpin>(reader: &mut BufReader<R>) {
    loop {
        match reader.fill_buf().await {
            Ok([]) => break, // EOF
            Ok(buf) => {
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    reader.consume(pos + 1);
                    break;
                }
                let len = buf.len();
                reader.consume(len);
            }
            Err(_) => break,
        }
    }
}

/// Write a JSON-RPC message followed by a newline to a writer.
///
/// Uses `to_vec` to serialize directly to bytes, then appends a newline
/// and writes the whole buffer in a single `write_all` call.
pub async fn write_message<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Value,
) -> Result<(), FramingError> {
    let mut buf = serde_json::to_vec(msg).map_err(FramingError::Json)?;
    buf.push(b'\n');
    writer.write_all(&buf).await.map_err(FramingError::Io)?;
    writer.flush().await.map_err(FramingError::Io)?;
    Ok(())
}

/// Check a parsed JSON-RPC value for key case-folding smuggling.
///
/// Go's `encoding/json` performs case-insensitive key matching and folds
/// Unicode confusables U+017F (ſ→s) and U+212A (K→k). An attacker can
/// send `{"Method":"evil"}` or `{"methOd":"evil"}` to smuggle fields past
/// a proxy that checks exact-case `"method"`. This function rejects any
/// top-level key that case-folds to a JSON-RPC 2.0 key but is not exact-case.
///
/// Returns `Some(offending_key)` if a case-folding attack is detected, `None` if clean.
///
/// # Security
///
/// SECURITY (R258-TRANSPORT-1): Extracted from `read_message()` for reuse
/// across HTTP, WebSocket, and gRPC transports.
pub fn check_json_rpc_key_case_folding(value: &Value) -> Option<String> {
    let obj = value.as_object()?;
    for key in obj.keys() {
        // SECURITY (R231/TI-2026-002): Go's encoding/json folds not
        // only ASCII case but also Unicode confusables U+017F (ſ→s)
        // and U+212A (K→k). Normalize both before matching.
        let normalized: String = key
            .chars()
            .map(|c| match c {
                '\u{017F}' => 's', // Latin small letter long s
                '\u{212A}' => 'k', // Kelvin sign
                other => other.to_ascii_lowercase(),
            })
            .collect();
        let is_jsonrpc_key = matches!(
            normalized.as_str(),
            "jsonrpc" | "method" | "params" | "id" | "result" | "error"
        );
        if is_jsonrpc_key && key.as_str() != normalized.as_str() {
            return Some(key.clone());
        }
    }
    None
}

/// Scan raw JSON for duplicate keys at any object nesting level.
///
/// Returns the first duplicate key name found, or `None` if no duplicates exist.
/// Uses a minimal state machine to track JSON string boundaries and object scopes.
///
/// This prevents parser-disagreement attacks where an attacker sends
/// `{"path":"safe","path":"malicious"}` and exploits the difference between
/// first-key-wins and last-key-wins parsers (CVE-2017-12635, CVE-2020-16250).
/// Maximum JSON nesting depth for duplicate key detection.
/// Matches serde_json's default recursion limit (128).
const MAX_DUPLICATE_KEY_DEPTH: usize = 128;

pub fn find_duplicate_json_key(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    // Stack of seen-key sets, one per object nesting level.
    // `None` entries represent array scopes (no key tracking needed).
    let mut stack: Vec<Option<HashSet<String>>> = Vec::new();
    // After `{` or `,` inside an object, the next string token is a key.
    let mut next_string_is_key = false;

    while i < len {
        // Skip whitespace
        while i < len && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= len {
            break;
        }

        match bytes[i] {
            b'{' => {
                // SECURITY (R10-FRAME-8): Limit nesting depth to prevent
                // excessive HashSet allocations from deeply nested input.
                if stack.len() >= MAX_DUPLICATE_KEY_DEPTH {
                    return Some(format!("<nesting depth exceeds {MAX_DUPLICATE_KEY_DEPTH}>"));
                }
                stack.push(Some(HashSet::new()));
                next_string_is_key = true;
                i += 1;
            }
            b'[' => {
                if stack.len() >= MAX_DUPLICATE_KEY_DEPTH {
                    return Some(format!("<nesting depth exceeds {MAX_DUPLICATE_KEY_DEPTH}>"));
                }
                stack.push(None);
                next_string_is_key = false;
                i += 1;
            }
            b'}' => {
                stack.pop();
                // Restore key expectation state: after closing an object that was
                // a value, we're no longer expecting a key.
                next_string_is_key = false;
                i += 1;
            }
            b']' => {
                stack.pop();
                next_string_is_key = false;
                i += 1;
            }
            b'"' => {
                let start = i;
                i += 1; // skip opening quote
                        // Walk through string content, handling escape sequences
                while i < len {
                    if bytes[i] == b'\\' {
                        i += 1; // skip backslash
                        if i < len {
                            if bytes[i] == b'u' {
                                // \uXXXX — skip u + 4 hex digits (6 bytes total including \)
                                i += 5.min(len - i);
                            } else {
                                i += 1; // skip single escaped char
                            }
                        }
                    } else if bytes[i] == b'"' {
                        i += 1; // skip closing quote
                        break;
                    } else {
                        i += 1;
                    }
                }

                if next_string_is_key {
                    // Extract the key using serde_json to correctly handle escapes.
                    // SECURITY (R10-FRAME-1): If the key bytes are not valid UTF-8
                    // or serde_json cannot parse the key string, treat the entire
                    // message as having a malformed key and reject it. Silently
                    // skipping would allow an attacker to create a "phantom" key
                    // that shadows a later duplicate.
                    if let Ok(key_str) = std::str::from_utf8(&bytes[start..i]) {
                        match serde_json::from_str::<String>(key_str) {
                            Ok(parsed_key) => {
                                if let Some(Some(seen_keys)) = stack.last_mut() {
                                    if !seen_keys.insert(parsed_key.clone()) {
                                        return Some(parsed_key);
                                    }
                                }
                            }
                            Err(_) => {
                                // Unparseable key — return it as a "duplicate" to
                                // trigger rejection. This is fail-closed: if we
                                // can't understand a key, we reject the message.
                                return Some(format!("<malformed key at byte {start}>"));
                            }
                        }
                    } else {
                        return Some(format!("<invalid UTF-8 key at byte {start}>"));
                    }
                    next_string_is_key = false;
                }
            }
            b':' => {
                // After a colon, the next token is a value (not a key)
                next_string_is_key = false;
                i += 1;
            }
            b',' => {
                // After a comma in an object scope, the next string is a key
                if let Some(Some(_)) = stack.last() {
                    next_string_is_key = true;
                }
                i += 1;
            }
            _ => {
                // Numbers, true, false, null — skip individual bytes
                i += 1;
            }
        }
    }

    None
}

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(serde_json::Error),
    #[error("Line too long: {0} bytes (max {MAX_LINE_LENGTH})")]
    LineTooLong(usize),
    #[error("Duplicate JSON key detected: \"{0}\"")]
    DuplicateKeys(String),
    #[error("JSON-RPC batching is not allowed (MCP 2025-06-18)")]
    BatchNotAllowed,
    #[error("JSON-RPC key case-folding smuggle detected: \"{0}\" (CVE-2026-27896)")]
    CaseFoldingSmuggle(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_message_valid() {
        let data = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let msg = read_message(&mut reader).await.unwrap();
        assert!(msg.is_some());
        let val = msg.unwrap();
        assert_eq!(val["method"], "ping");
    }

    #[tokio::test]
    async fn test_read_message_eof() {
        let data = b"";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let msg = read_message(&mut reader).await.unwrap();
        assert!(msg.is_none());
    }

    #[tokio::test]
    async fn test_read_message_invalid_json() {
        let data = b"not json\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_write_message() {
        let mut buf = Vec::new();
        let msg = json!({"jsonrpc": "2.0", "id": 1, "result": "ok"});
        write_message(&mut buf, &msg).await.unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.ends_with('\n'));
        let parsed: Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(parsed["result"], "ok");
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let msg =
            json!({"jsonrpc": "2.0", "id": 42, "method": "tools/call", "params": {"name": "read"}});

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let cursor = Cursor::new(buf);
        let mut reader = BufReader::new(cursor);
        let read_back = read_message(&mut reader).await.unwrap().unwrap();

        assert_eq!(read_back["id"], 42);
        assert_eq!(read_back["method"], "tools/call");
    }

    // === Security regression tests ===

    #[tokio::test]
    async fn test_fix6_line_too_long_rejected() {
        // Fix #6: Lines exceeding MAX_LINE_LENGTH must be rejected
        let long_payload = "x".repeat(MAX_LINE_LENGTH + 100);
        let data = format!("{long_payload}\n");
        let cursor = Cursor::new(data.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FramingError::LineTooLong(_)),
            "Expected LineTooLong, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_fix14_empty_line_does_not_terminate_session() {
        // Fix #14: Empty lines between valid messages must be skipped, not treated as EOF
        let data = b"\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let msg = read_message(&mut reader).await.unwrap();
        assert!(
            msg.is_some(),
            "Empty lines should be skipped, not terminate"
        );
        assert_eq!(msg.unwrap()["method"], "ping");
    }

    #[tokio::test]
    async fn test_fix14_only_empty_lines_returns_eof() {
        // All empty lines followed by true EOF → should return None (EOF)
        let data = b"\n\n\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let msg = read_message(&mut reader).await.unwrap();
        assert!(msg.is_none(), "Only empty lines + EOF should return None");
    }

    // === Duplicate key detection tests (Challenge #5) ===

    #[test]
    fn test_no_duplicate_keys_in_valid_json() {
        let json = r#"{"a": 1, "b": 2, "c": {"d": 3}}"#;
        assert!(find_duplicate_json_key(json).is_none());
    }

    #[test]
    fn test_detects_top_level_duplicate_key() {
        let json = r#"{"path": "safe", "path": "malicious"}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("path".to_string()));
    }

    #[test]
    fn test_detects_nested_duplicate_key() {
        let json = r#"{"params": {"name": "a", "name": "b"}}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("name".to_string()));
    }

    #[test]
    fn test_same_key_different_scopes_is_ok() {
        // "id" appears in two different objects — not a duplicate
        let json = r#"{"id": 1, "params": {"id": "inner"}}"#;
        assert!(find_duplicate_json_key(json).is_none());
    }

    #[test]
    fn test_no_duplicates_in_array() {
        // Arrays don't have keys, strings inside arrays aren't keys
        let json = r#"{"items": ["a", "a", "b"]}"#;
        assert!(find_duplicate_json_key(json).is_none());
    }

    #[test]
    fn test_handles_escaped_quotes_in_keys() {
        // Key with escaped quote — distinct from other keys
        let json = r#"{"a\"b": 1, "c": 2}"#;
        assert!(find_duplicate_json_key(json).is_none());
    }

    #[test]
    fn test_handles_escaped_quotes_duplicate() {
        let json = r#"{"a\"b": 1, "a\"b": 2}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("a\"b".to_string()));
    }

    #[test]
    fn test_deeply_nested_duplicate() {
        let json = r#"{"a": {"b": {"c": 1, "c": 2}}}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("c".to_string()));
    }

    #[test]
    fn test_mcp_tools_call_duplicate_attack() {
        // The actual attack vector: duplicate params.name in tools/call
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"path":"/tmp"},"name":"dangerous_tool"}}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("name".to_string()));
    }

    #[tokio::test]
    async fn test_read_message_rejects_duplicate_keys() {
        let data = b"{\"a\":1,\"a\":2}\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(result.is_err(), "Should reject JSON with duplicate keys");
        let err = result.unwrap_err();
        assert!(
            matches!(err, FramingError::DuplicateKeys(ref k) if k == "a"),
            "Expected DuplicateKeys(\"a\"), got {err:?}"
        );
    }

    #[test]
    fn test_empty_json_object_no_duplicates() {
        assert!(find_duplicate_json_key("{}").is_none());
    }

    #[test]
    fn test_mixed_arrays_and_objects() {
        let json = r#"{"a": [{"b": 1}, {"b": 2}], "c": 3}"#;
        // "b" appears in different array element objects — not duplicates
        assert!(find_duplicate_json_key(json).is_none());
    }

    // === JSON-RPC batch rejection tests (MCP 2025-06-18) ===

    #[tokio::test]
    async fn test_read_message_rejects_batch() {
        let data = b"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}]\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(result.is_err(), "Batch requests must be rejected");
        assert!(
            matches!(result.unwrap_err(), FramingError::BatchNotAllowed),
            "Error should be BatchNotAllowed"
        );
    }

    #[tokio::test]
    async fn test_read_message_rejects_empty_batch() {
        let data = b"[]\n";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(matches!(result.unwrap_err(), FramingError::BatchNotAllowed));
    }

    // === R10-FRAME-1: Malformed key rejection ===

    #[test]
    fn test_malformed_key_lone_surrogate_rejected() {
        // Lone high surrogate \uD800 cannot be decoded to a valid String.
        // The duplicate key detector must reject the message, not silently skip.
        let json = r#"{"good": 1, "\uD800bad": 2}"#;
        let result = find_duplicate_json_key(json);
        assert!(
            result.is_some(),
            "Malformed key (lone surrogate) must cause rejection"
        );
    }

    #[test]
    fn test_unicode_escape_keys_detected_as_duplicate() {
        // \u0070\u0061\u0074\u0068 == "path" — must detect duplicate
        let json = r#"{"path": "safe", "\u0070\u0061\u0074\u0068": "malicious"}"#;
        let dup = find_duplicate_json_key(json);
        assert_eq!(dup, Some("path".to_string()));
    }

    // === R10-FRAME-7: LineTooLong drains oversized line remainder ===

    #[tokio::test]
    async fn test_line_too_long_drains_remainder() {
        // Send an oversized line followed by a valid message.
        // After LineTooLong, the next read_message should get the valid message,
        // NOT a fragment of the oversized line.
        let long_payload = "x".repeat(MAX_LINE_LENGTH + 100);
        let valid_msg = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let data = format!("{long_payload}\n{valid_msg}\n");
        let cursor = Cursor::new(data.into_bytes());
        let mut reader = BufReader::new(cursor);

        // First read should fail with LineTooLong
        let result = read_message(&mut reader).await;
        assert!(matches!(result, Err(FramingError::LineTooLong(_))));

        // Second read should get the valid message (not a fragment)
        let msg = read_message(&mut reader).await.unwrap();
        assert!(
            msg.is_some(),
            "Should read valid message after oversized line"
        );
        assert_eq!(msg.unwrap()["method"], "ping");
    }

    /// TI-2026-001: Reject "Method" (uppercase M) as case-folding smuggle.
    #[tokio::test]
    async fn test_r230_case_folding_smuggle_method() {
        let data = r#"{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{}}"#;
        let input = format!("{data}\n");
        let cursor = Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(
            matches!(result, Err(FramingError::CaseFoldingSmuggle(_))),
            "Should reject 'Method' as case-folding smuggle: {result:?}"
        );
    }

    /// TI-2026-001: Reject "PARAMS" (all uppercase) as case-folding smuggle.
    #[tokio::test]
    async fn test_r230_case_folding_smuggle_params() {
        let data = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","PARAMS":{}}"#;
        let input = format!("{data}\n");
        let cursor = Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(
            matches!(result, Err(FramingError::CaseFoldingSmuggle(_))),
            "Should reject 'PARAMS' as case-folding smuggle: {result:?}"
        );
    }

    /// TI-2026-001: Exact lowercase keys pass validation.
    #[tokio::test]
    async fn test_r230_case_folding_exact_lowercase_passes() {
        let data = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
        let input = format!("{data}\n");
        let cursor = Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(
            result.is_ok(),
            "Exact lowercase keys should pass: {result:?}"
        );
    }

    /// TI-2026-001: Non-JSON-RPC keys with mixed case are allowed.
    #[tokio::test]
    async fn test_r230_case_folding_custom_keys_allowed() {
        let data = r#"{"jsonrpc":"2.0","id":1,"method":"ping","customField":"value"}"#;
        let input = format!("{data}\n");
        let cursor = Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(
            result.is_ok(),
            "Custom keys with mixed case should pass: {result:?}"
        );
    }

    /// TI-2026-002: U+017F (Latin small letter long s) folds to 's' —
    /// "param\u{017F}" → "params" smuggles a JSON-RPC key.
    #[tokio::test]
    async fn test_r231_unicode_confusable_long_s_smuggle() {
        let data = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"param\u{017F}\":{}}";
        let input = format!("{data}\n");
        let cursor = Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(
            matches!(result, Err(FramingError::CaseFoldingSmuggle(_))),
            "U+017F in 'param\u{017F}' should be rejected: {result:?}"
        );
    }

    /// TI-2026-002: U+212A (Kelvin sign) in non-JSON-RPC key passes.
    #[tokio::test]
    async fn test_r231_unicode_confusable_kelvin_non_jsonrpc_passes() {
        let data = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"temp\u{212A}ey\":1}";
        let input = format!("{data}\n");
        let cursor = Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(
            result.is_ok(),
            "Kelvin sign in non-JSON-RPC key should pass: {result:?}"
        );
    }

    /// TI-2026-002: U+017F smuggling "result" detected.
    #[tokio::test]
    async fn test_r231_unicode_confusable_long_s_result_smuggle() {
        let data = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"re\u{017F}ult\":{}}";
        let input = format!("{data}\n");
        let cursor = Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let result = read_message(&mut reader).await;
        assert!(
            matches!(result, Err(FramingError::CaseFoldingSmuggle(_))),
            "U+017F smuggling 'result' should be rejected: {result:?}"
        );
    }
}
