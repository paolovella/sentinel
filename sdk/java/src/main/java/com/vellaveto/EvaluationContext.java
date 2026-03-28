package com.vellaveto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Provides session and identity context for policy evaluation.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EvaluationContext {

    static final int MAX_SESSION_ID_LENGTH = 256;
    static final int MAX_AGENT_ID_LENGTH = 256;
    static final int MAX_TENANT_ID_LENGTH = 64;
    static final int MAX_CALL_CHAIN_LENGTH = 100;
    static final int MAX_CALL_CHAIN_ENTRY_LENGTH = 256;
    static final int MAX_METADATA_ENTRIES = 100;

    @JsonProperty("session_id")
    private final String sessionId;

    @JsonProperty("agent_id")
    private final String agentId;

    @JsonProperty("tenant_id")
    private final String tenantId;

    @JsonProperty("call_chain")
    private final List<String> callChain;

    @JsonProperty("metadata")
    private final Map<String, Object> metadata;

    public EvaluationContext(String sessionId, String agentId, String tenantId,
                            List<String> callChain, Map<String, Object> metadata) {
        this.sessionId = sessionId;
        this.agentId = agentId;
        this.tenantId = tenantId;
        this.callChain = callChain;
        this.metadata = metadata;
    }

    public String getSessionId() { return sessionId; }
    public String getAgentId() { return agentId; }
    public String getTenantId() { return tenantId; }
    public List<String> getCallChain() { return callChain; }
    public Map<String, Object> getMetadata() { return metadata; }

    /**
     * Validates context fields for safe bounds.
     * SECURITY: Prevents oversized or malicious context fields.
     *
     * @throws VellavetoException if validation fails
     */
    public void validate() throws VellavetoException {
        if (sessionId != null) {
            if (sessionId.length() > MAX_SESSION_ID_LENGTH) {
                throw new VellavetoException("session_id exceeds max length " + MAX_SESSION_ID_LENGTH);
            }
            ValidationUtils.rejectControlAndFormatChars(sessionId, "session_id");
        }
        if (agentId != null) {
            if (agentId.length() > MAX_AGENT_ID_LENGTH) {
                throw new VellavetoException("agent_id exceeds max length " + MAX_AGENT_ID_LENGTH);
            }
            ValidationUtils.rejectControlAndFormatChars(agentId, "agent_id");
        }
        if (tenantId != null) {
            if (tenantId.length() > MAX_TENANT_ID_LENGTH) {
                throw new VellavetoException("tenant_id exceeds max length " + MAX_TENANT_ID_LENGTH);
            }
            ValidationUtils.rejectControlAndFormatChars(tenantId, "tenant_id");
        }
        if (callChain != null) {
            if (callChain.size() > MAX_CALL_CHAIN_LENGTH) {
                throw new VellavetoException("call_chain has " + callChain.size()
                        + " entries, max " + MAX_CALL_CHAIN_LENGTH);
            }
            for (int i = 0; i < callChain.size(); i++) {
                String entry = callChain.get(i);
                if (entry == null) continue;
                if (entry.length() > MAX_CALL_CHAIN_ENTRY_LENGTH) {
                    throw new VellavetoException("call_chain[" + i + "] exceeds max length "
                            + MAX_CALL_CHAIN_ENTRY_LENGTH);
                }
                ValidationUtils.rejectControlAndFormatChars(entry, "call_chain[" + i + "]");
            }
        }
        if (metadata != null && metadata.size() > MAX_METADATA_ENTRIES) {
            throw new VellavetoException("metadata has " + metadata.size()
                    + " entries, max " + MAX_METADATA_ENTRIES);
        }
    }
}
