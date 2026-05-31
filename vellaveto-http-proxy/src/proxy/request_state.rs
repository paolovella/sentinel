// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.

//! requestState sealing for MCP multi-round-trip continuations.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{digest::KeyInit, Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::session::{RequestStateRecord, SessionState};

type HmacSha256 = Hmac<Sha256>;

const TOKEN_PREFIX: &str = "vvrs1";
const REQUEST_STATE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_PENDING_REQUEST_STATES: usize = 128;
const MAX_REQUEST_STATE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RequestStateError {
    MissingSession,
    InvalidShape,
    Oversized,
    InvalidToken,
    UnknownOrReplayed,
    Expired,
    Capacity,
    Serialization,
}

impl RequestStateError {
    pub(super) fn message(&self) -> &'static str {
        match self {
            Self::MissingSession => "requestState cannot be validated without session state",
            Self::InvalidShape => "requestState must be a Vellaveto-sealed string",
            Self::Oversized => "requestState exceeds size limit",
            Self::InvalidToken => "requestState token is invalid",
            Self::UnknownOrReplayed => "requestState token is unknown or already used",
            Self::Expired => "requestState token expired",
            Self::Capacity => "requestState capacity exceeded",
            Self::Serialization => "requestState serialization failed",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RequestStatePayload {
    session_id: String,
    nonce: String,
    step: u64,
    expires_at: u64,
    state_hash: String,
    originating_method: String,
}

fn now_unix_secs() -> Result<u64, RequestStateError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RequestStateError::Serialization)
}

fn state_hash(value: &Value) -> Result<String, RequestStateError> {
    let serialized = serde_json::to_vec(value).map_err(|_| RequestStateError::Serialization)?;
    if serialized.len() > MAX_REQUEST_STATE_BYTES {
        return Err(RequestStateError::Oversized);
    }
    let digest = Sha256::digest(&serialized);
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

fn sign(scope_binding: &str, payload_b64: &str) -> Result<String, RequestStateError> {
    let mut mac = HmacSha256::new_from_slice(scope_binding.as_bytes())
        .map_err(|_| RequestStateError::Serialization)?;
    mac.update(payload_b64.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn verify_signature(scope_binding: &str, payload_b64: &str, signature_b64: &str) -> bool {
    let Ok(expected) = sign(scope_binding, payload_b64) else {
        return false;
    };
    let Ok(expected_bytes) = URL_SAFE_NO_PAD.decode(expected) else {
        return false;
    };
    let Ok(provided_bytes) = URL_SAFE_NO_PAD.decode(signature_b64) else {
        return false;
    };
    if expected_bytes.len() != provided_bytes.len() {
        return false;
    }
    expected_bytes
        .iter()
        .zip(provided_bytes.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn evict_expired(session: &mut SessionState) {
    let now = Instant::now();
    session
        .pending_request_states
        .retain(|_, record| record.expires_at > now);
}

pub(super) fn seal_value(
    session: &mut SessionState,
    state_value: Value,
    originating_method: &str,
) -> Result<String, RequestStateError> {
    evict_expired(session);
    if session.pending_request_states.len() >= MAX_PENDING_REQUEST_STATES {
        return Err(RequestStateError::Capacity);
    }

    session.next_request_state_step = session.next_request_state_step.saturating_add(1);
    let step = session.next_request_state_step;
    let hash = state_hash(&state_value)?;
    let expires_at = now_unix_secs()?.saturating_add(REQUEST_STATE_TTL.as_secs());
    let payload = RequestStatePayload {
        session_id: session.session_id.clone(),
        nonce: uuid::Uuid::new_v4().to_string(),
        step,
        expires_at,
        state_hash: hash.clone(),
        originating_method: originating_method.to_string(),
    };
    let payload_json =
        serde_json::to_vec(&payload).map_err(|_| RequestStateError::Serialization)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let signature_b64 = sign(&session.session_scope_binding, &payload_b64)?;
    let token = format!("{TOKEN_PREFIX}.{payload_b64}.{signature_b64}");

    session.pending_request_states.insert(
        token.clone(),
        RequestStateRecord {
            original_state: state_value,
            expires_at: Instant::now() + REQUEST_STATE_TTL,
            state_hash: hash,
            step,
        },
    );

    Ok(token)
}

pub(super) fn unseal_value(
    session: &mut SessionState,
    token: &str,
) -> Result<Value, RequestStateError> {
    if token.len() > MAX_REQUEST_STATE_BYTES {
        return Err(RequestStateError::Oversized);
    }
    let mut parts = token.split('.');
    if parts.next() != Some(TOKEN_PREFIX) {
        return Err(RequestStateError::InvalidShape);
    }
    let Some(payload_b64) = parts.next() else {
        return Err(RequestStateError::InvalidToken);
    };
    let Some(signature_b64) = parts.next() else {
        return Err(RequestStateError::InvalidToken);
    };
    if parts.next().is_some()
        || !verify_signature(&session.session_scope_binding, payload_b64, signature_b64)
    {
        return Err(RequestStateError::InvalidToken);
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| RequestStateError::InvalidToken)?;
    let payload: RequestStatePayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| RequestStateError::InvalidToken)?;
    if payload.session_id != session.session_id {
        return Err(RequestStateError::InvalidToken);
    }
    if payload.expires_at < now_unix_secs()? {
        session.pending_request_states.remove(token);
        return Err(RequestStateError::Expired);
    }

    let Some(record) = session.pending_request_states.remove(token) else {
        return Err(RequestStateError::UnknownOrReplayed);
    };
    if record.expires_at <= Instant::now() {
        return Err(RequestStateError::Expired);
    }
    if record.step != payload.step || record.state_hash != payload.state_hash {
        return Err(RequestStateError::InvalidToken);
    }
    if state_hash(&record.original_state)? != payload.state_hash {
        return Err(RequestStateError::InvalidToken);
    }

    Ok(record.original_state)
}

pub(super) fn seal_response_request_state(
    response: &mut Value,
    session: &mut SessionState,
) -> Result<bool, RequestStateError> {
    let method = response
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("response")
        .to_string();
    let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) else {
        return Ok(false);
    };
    let Some(state_value) = result.get("requestState").cloned() else {
        return Ok(false);
    };
    let token = seal_value(session, state_value, &method)?;
    result.insert("requestState".to_string(), Value::String(token));
    Ok(true)
}

pub(super) fn unwrap_inbound_request_state(
    msg: &mut Value,
    session: &mut SessionState,
) -> Result<bool, RequestStateError> {
    let Some(params) = msg.get_mut("params").and_then(Value::as_object_mut) else {
        return Ok(false);
    };
    let Some(state_value) = params.get("requestState") else {
        return Ok(false);
    };
    let Some(token) = state_value.as_str() else {
        return Err(RequestStateError::InvalidShape);
    };
    let original = unseal_value(session, token)?;
    params.insert("requestState".to_string(), original);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn seals_and_unseals_once() {
        let mut session = SessionState::new("session-1".to_string());
        let token = seal_value(&mut session, json!("opaque"), "demo/start").unwrap();
        assert!(token.starts_with("vvrs1."));
        assert_eq!(unseal_value(&mut session, &token).unwrap(), json!("opaque"));
        assert_eq!(
            unseal_value(&mut session, &token).unwrap_err(),
            RequestStateError::UnknownOrReplayed
        );
    }

    #[test]
    fn rejects_tampered_token() {
        let mut session = SessionState::new("session-1".to_string());
        let mut token = seal_value(&mut session, json!("opaque"), "demo/start").unwrap();
        token.push('x');
        assert_eq!(
            unseal_value(&mut session, &token).unwrap_err(),
            RequestStateError::InvalidToken
        );
    }

    #[test]
    fn rejects_token_from_different_session() {
        let mut minting_session = SessionState::new("session-1".to_string());
        let mut other_session = SessionState::new("session-2".to_string());
        let token = seal_value(&mut minting_session, json!("opaque"), "demo/start").unwrap();

        assert_eq!(
            unseal_value(&mut other_session, &token).unwrap_err(),
            RequestStateError::InvalidToken
        );
    }

    #[test]
    fn rewrites_response_and_inbound_message() {
        let mut session = SessionState::new("session-1".to_string());
        let mut response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"requestState": "server-state"}
        });
        assert!(seal_response_request_state(&mut response, &mut session).unwrap());
        let token = response["result"]["requestState"].as_str().unwrap();
        assert_ne!(token, "server-state");

        let mut msg = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "demo/continue",
            "params": {"requestState": token}
        });
        assert!(unwrap_inbound_request_state(&mut msg, &mut session).unwrap());
        assert_eq!(msg["params"]["requestState"], json!("server-state"));
    }

    #[test]
    fn rejects_unsealed_inbound_request_state() {
        let mut session = SessionState::new("session-1".to_string());
        let mut msg = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "demo/continue",
            "params": {"requestState": "server-state"}
        });

        assert_eq!(
            unwrap_inbound_request_state(&mut msg, &mut session).unwrap_err(),
            RequestStateError::InvalidShape
        );
    }
}
