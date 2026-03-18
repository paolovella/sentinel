// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Policy evaluation methods for `ProxyBridge`.
//!
//! Handles evaluating tool calls and resource reads against the policy engine,
//! producing `ProxyDecision` results for the relay loop.

use super::ProxyBridge;
use super::ToolAnnotations;
use crate::extractor::{
    extract_action, extract_resource_action, make_approval_response, make_denial_response,
};
use crate::mediation::{mediate_with_security_context, MediationResult};
use crate::proxy::types::ProxyDecision;
use serde_json::{json, Value};
use vellaveto_types::{EvaluationContext, EvaluationTrace, RuntimeSecurityContext, Verdict};

/// Log evaluation trace details at debug level.
fn log_trace(label: &str, trace: &EvaluationTrace) {
    tracing::debug!(
        "Trace ({}): {} policies checked, {} matched, {}us",
        label,
        trace.policies_checked,
        trace.policies_matched,
        trace.duration_us
    );
}

#[derive(Debug)]
pub(super) struct MediatedProxyDecision {
    pub decision: ProxyDecision,
    pub result: MediationResult,
}

pub(super) struct ToolCallEvaluationInput<'a> {
    pub id: &'a Value,
    pub action: &'a vellaveto_types::Action,
    pub tool_name: &'a str,
    pub annotations: Option<&'a ToolAnnotations>,
    pub context: Option<&'a EvaluationContext>,
    pub security_context: Option<&'a RuntimeSecurityContext>,
    pub session_id: Option<&'a str>,
    pub tenant_id: Option<&'a str>,
}

pub(super) struct ResourceReadEvaluationInput<'a> {
    pub id: &'a Value,
    pub action: &'a vellaveto_types::Action,
    pub uri: &'a str,
    pub context: Option<&'a EvaluationContext>,
    pub security_context: Option<&'a RuntimeSecurityContext>,
    pub session_id: Option<&'a str>,
    pub tenant_id: Option<&'a str>,
}

impl ProxyBridge {
    /// Evaluate an action against policies, optionally producing a trace.
    ///
    /// When `context` is provided, uses context-aware evaluation for time windows,
    /// call limits, agent identity, and action history.
    #[allow(deprecated)] // evaluate_action_with_context: migration tracked in FIND-CREATIVE-005
    pub(super) fn evaluate_action_inner(
        &self,
        action: &vellaveto_types::Action,
        context: Option<&EvaluationContext>,
    ) -> Result<(Verdict, Option<EvaluationTrace>), vellaveto_engine::EngineError> {
        if self.enable_trace {
            let (verdict, trace) = self
                .engine
                .evaluate_action_traced_with_context(action, context)?;
            Ok((verdict, Some(trace)))
        } else {
            let verdict =
                self.engine
                    .evaluate_action_with_context(action, &self.policies, context)?;
            Ok((verdict, None))
        }
    }

    /// Evaluate an action and produce an ACIS decision envelope.
    ///
    /// This wraps [`evaluate_action_inner`] and attaches an ACIS envelope to
    /// every decision. Transports should call this when they want structured
    /// decision metadata for audit entries.
    ///
    /// DLP and injection findings should be passed in from the caller's
    /// pre-pipeline scanning (the relay runs these before engine evaluation).
    ///
    /// **Migration (E2):** The canonical mediation entrypoint is
    /// Evaluate a tool call and decide whether to forward or block.
    ///
    /// If `annotations` are provided (from a prior `tools/list` response),
    /// they are included in audit metadata for the decision.
    ///
    /// Returns `(ProxyDecision, Option<EvaluationTrace>)` so callers can
    /// inject decision explanations into responses (Art 50(2)).
    pub fn evaluate_tool_call(
        &self,
        id: &Value,
        tool_name: &str,
        arguments: &Value,
        annotations: Option<&ToolAnnotations>,
        context: Option<&EvaluationContext>,
    ) -> (ProxyDecision, Option<EvaluationTrace>) {
        let action = extract_action(tool_name, arguments);

        match self.evaluate_action_inner(&action, context) {
            Ok((Verdict::Allow, trace)) => {
                // Log awareness when allowing destructive tools
                if let Some(ann) = annotations {
                    if ann.destructive_hint && !ann.read_only_hint {
                        tracing::info!(
                            "Allowing destructive tool '{}' (destructiveHint=true)",
                            tool_name
                        );
                    }
                }
                if let Some(ref t) = trace {
                    log_trace("allow", t);
                }
                (ProxyDecision::Forward, trace)
            }
            Ok((Verdict::Deny { reason }, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("deny", t);
                }
                // SECURITY (R239-MCP-3): Genericize deny reason in response to avoid
                // leaking policy details. Raw reason preserved in Verdict for audit.
                let response =
                    make_denial_response(id, "Request blocked: security policy violation");
                (
                    ProxyDecision::Block(response, Verdict::Deny { reason }),
                    trace,
                )
            }
            Ok((Verdict::RequireApproval { reason }, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("approval", t);
                }
                // SECURITY (R239-MCP-3): Genericize approval reason in response.
                let response =
                    make_approval_response(id, "Request blocked: security policy violation");
                (
                    ProxyDecision::Block(response, Verdict::RequireApproval { reason }),
                    trace,
                )
            }
            // Handle future Verdict variants - fail closed (deny)
            Ok((_, trace)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                (
                    ProxyDecision::Block(
                        make_denial_response(id, "Request blocked: security policy violation"),
                        Verdict::Deny { reason },
                    ),
                    trace,
                )
            }
            Err(e) => {
                tracing::error!("Policy evaluation error for tool '{}': {}", tool_name, e);
                let reason = "Policy evaluation failed".to_string();
                (
                    ProxyDecision::Block(
                        make_denial_response(id, "Request blocked: security policy violation"),
                        Verdict::Deny { reason },
                    ),
                    None,
                )
            }
        }
    }

    /// Build audit metadata for a tool call, including annotations if available.
    pub(super) fn tool_call_audit_metadata(
        tool_name: &str,
        annotations: Option<&ToolAnnotations>,
    ) -> Value {
        let mut meta = json!({"source": "proxy", "tool": tool_name});
        if let Some(ann) = annotations {
            meta["annotations"] = json!({
                "readOnlyHint": ann.read_only_hint,
                "destructiveHint": ann.destructive_hint,
                "idempotentHint": ann.idempotent_hint,
                "openWorldHint": ann.open_world_hint,
            });
        }
        meta
    }

    /// Evaluate a tool call using a pre-built Action.
    ///
    /// Used when the action needs pre-processing (e.g., DNS resolution to
    /// populate `resolved_ips`) before policy evaluation. This achieves parity
    /// with the HTTP/WebSocket/gRPC proxy handlers.
    ///
    /// SECURITY (FIND-R78-001): Added for DNS rebinding protection in stdio proxy.
    #[allow(dead_code)] // Retained for focused bridge unit tests and edge-case callers.
    pub(super) fn evaluate_tool_call_with_action(
        &self,
        id: &Value,
        action: &vellaveto_types::Action,
        tool_name: &str,
        annotations: Option<&ToolAnnotations>,
        context: Option<&EvaluationContext>,
    ) -> (ProxyDecision, Option<EvaluationTrace>) {
        let evaluated = self.evaluate_tool_call_with_security_context(ToolCallEvaluationInput {
            id,
            action,
            tool_name,
            annotations,
            context,
            security_context: None,
            session_id: None,
            tenant_id: context.and_then(|ctx| ctx.tenant_id.as_deref()),
        });
        let trace = if self.enable_trace {
            evaluated.result.trace.clone()
        } else {
            None
        };
        (evaluated.decision, trace)
    }

    pub(super) fn evaluate_tool_call_with_security_context(
        &self,
        input: ToolCallEvaluationInput<'_>,
    ) -> MediatedProxyDecision {
        let decision_id = uuid::Uuid::new_v4().to_string().replace('-', "");
        let result = mediate_with_security_context(
            &decision_id,
            input.action,
            &self.engine,
            input.context,
            input.security_context,
            "stdio",
            &self.mediation_config,
            input.session_id,
            input.tenant_id,
        );
        let trace = if self.enable_trace {
            result.trace.as_ref()
        } else {
            None
        };
        let decision = self.proxy_decision_from_result(
            input.id,
            input.tool_name,
            input.annotations,
            &result,
            trace,
        );
        MediatedProxyDecision { decision, result }
    }

    /// Evaluate a `resources/read` using a pre-built Action.
    ///
    /// SECURITY (FIND-R78-001): Added for DNS rebinding protection in stdio proxy.
    #[allow(dead_code)] // Retained for focused bridge unit tests and edge-case callers.
    pub(super) fn evaluate_resource_read_with_action(
        &self,
        id: &Value,
        action: &vellaveto_types::Action,
        uri: &str,
        context: Option<&EvaluationContext>,
    ) -> ProxyDecision {
        self.evaluate_resource_read_with_security_context(ResourceReadEvaluationInput {
            id,
            action,
            uri,
            context,
            security_context: None,
            session_id: None,
            tenant_id: context.and_then(|ctx| ctx.tenant_id.as_deref()),
        })
        .decision
    }

    pub(super) fn evaluate_resource_read_with_security_context(
        &self,
        input: ResourceReadEvaluationInput<'_>,
    ) -> MediatedProxyDecision {
        let decision_id = uuid::Uuid::new_v4().to_string().replace('-', "");
        let result = mediate_with_security_context(
            &decision_id,
            input.action,
            &self.engine,
            input.context,
            input.security_context,
            "stdio",
            &self.mediation_config,
            input.session_id,
            input.tenant_id,
        );
        let trace = if self.enable_trace {
            result.trace.as_ref()
        } else {
            None
        };
        let decision =
            self.proxy_decision_from_resource_result(input.id, input.uri, &result, trace);
        MediatedProxyDecision { decision, result }
    }

    /// Evaluate a `resources/read` request and decide whether to forward or block.
    pub fn evaluate_resource_read(
        &self,
        id: &Value,
        uri: &str,
        context: Option<&EvaluationContext>,
    ) -> ProxyDecision {
        let action = extract_resource_action(uri);

        match self.evaluate_action_inner(&action, context) {
            Ok((Verdict::Allow, trace)) => {
                if let Some(ref t) = trace {
                    log_trace("resource_read allow", t);
                }
                ProxyDecision::Forward
            }
            Ok((Verdict::Deny { reason }, _)) => {
                // SECURITY (R239-MCP-3): Genericize deny reason in response.
                let response =
                    make_denial_response(id, "Request blocked: security policy violation");
                ProxyDecision::Block(response, Verdict::Deny { reason })
            }
            Ok((Verdict::RequireApproval { reason }, _)) => {
                // SECURITY (R239-MCP-3): Genericize approval reason in response.
                let response =
                    make_approval_response(id, "Request blocked: security policy violation");
                ProxyDecision::Block(response, Verdict::RequireApproval { reason })
            }
            // Handle future Verdict variants - fail closed (deny)
            Ok((_, _)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                ProxyDecision::Block(
                    make_denial_response(id, "Request blocked: security policy violation"),
                    Verdict::Deny { reason },
                )
            }
            Err(e) => {
                tracing::error!("Policy evaluation error for resource '{}': {}", uri, e);
                let reason = "Policy evaluation failed".to_string();
                ProxyDecision::Block(
                    make_denial_response(id, "Request blocked: security policy violation"),
                    Verdict::Deny { reason },
                )
            }
        }
    }

    fn proxy_decision_from_result(
        &self,
        id: &Value,
        tool_name: &str,
        annotations: Option<&ToolAnnotations>,
        result: &MediationResult,
        trace: Option<&EvaluationTrace>,
    ) -> ProxyDecision {
        match &result.verdict {
            Verdict::Allow => {
                if let Some(ann) = annotations {
                    if ann.destructive_hint && !ann.read_only_hint {
                        tracing::info!(
                            "Allowing destructive tool '{}' (destructiveHint=true)",
                            tool_name
                        );
                    }
                }
                if let Some(trace) = trace {
                    log_trace("allow", trace);
                }
                ProxyDecision::Forward
            }
            Verdict::Deny { reason } => {
                if let Some(trace) = trace {
                    log_trace("deny", trace);
                }
                ProxyDecision::Block(
                    make_denial_response(id, "Request blocked: security policy violation"),
                    Verdict::Deny {
                        reason: reason.clone(),
                    },
                )
            }
            Verdict::RequireApproval { reason } => {
                if let Some(trace) = trace {
                    log_trace("approval", trace);
                }
                ProxyDecision::Block(
                    make_approval_response(id, "Request blocked: security policy violation"),
                    Verdict::RequireApproval {
                        reason: reason.clone(),
                    },
                )
            }
            _ => {
                if let Some(trace) = trace {
                    log_trace("deny", trace);
                }
                ProxyDecision::Block(
                    make_denial_response(id, "Request blocked: security policy violation"),
                    Verdict::Deny {
                        reason: "Unknown verdict type - failing closed".to_string(),
                    },
                )
            }
        }
    }

    fn proxy_decision_from_resource_result(
        &self,
        id: &Value,
        uri: &str,
        result: &MediationResult,
        trace: Option<&EvaluationTrace>,
    ) -> ProxyDecision {
        match &result.verdict {
            Verdict::Allow => {
                if let Some(trace) = trace {
                    log_trace("resource_read allow", trace);
                }
                ProxyDecision::Forward
            }
            Verdict::Deny { reason } => ProxyDecision::Block(
                make_denial_response(id, "Request blocked: security policy violation"),
                Verdict::Deny {
                    reason: reason.clone(),
                },
            ),
            Verdict::RequireApproval { reason } => ProxyDecision::Block(
                make_approval_response(id, "Request blocked: security policy violation"),
                Verdict::RequireApproval {
                    reason: reason.clone(),
                },
            ),
            _ => {
                tracing::warn!(
                    resource = %uri,
                    "Unknown resource verdict type from mediation pipeline - failing closed"
                );
                ProxyDecision::Block(
                    make_denial_response(id, "Request blocked: security policy violation"),
                    Verdict::Deny {
                        reason: "Unknown verdict type - failing closed".to_string(),
                    },
                )
            }
        }
    }
}
