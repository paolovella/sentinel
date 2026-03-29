package com.vellaveto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Logger;

/**
 * Java client for the Vellaveto Agent Interaction Firewall API.
 *
 * <p>Thread-safe after construction. All fields are read-only post-construction.</p>
 *
 * <p>Supports all 33+ API methods with full parity to the Go, Python, and TypeScript SDKs:
 * evaluate, approve/deny, simulate, batch, validate, diff, discovery, projector, ZK audit,
 * compliance, federation, and usage/billing.</p>
 *
 * <p>SECURITY: Input validation, retry with jittered backoff, response body size limits,
 * secret redaction in toString(), CRLF header injection prevention, cross-domain redirect
 * protection.</p>
 */
public class VellavetoClient implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(VellavetoClient.class.getName());

    /** Maximum response body size (10 MB). */
    static final long MAX_RESPONSE_BODY_SIZE = 10L * 1024 * 1024;

    /** Maximum bytes of response body included in error messages. */
    private static final int MAX_ERROR_BODY_DISPLAY = 256;

    /** Default timeout (10 seconds), aligned across all SDKs. */
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration MIN_TIMEOUT = Duration.ofMillis(100);
    private static final Duration MAX_TIMEOUT = Duration.ofSeconds(300);

    /** Retry parameters for transient HTTP failures. */
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final Duration DEFAULT_INITIAL_BACKOFF = Duration.ofMillis(500);

    private final String baseUrl;
    private final String apiKey;
    private final HttpClient httpClient;
    private final Duration timeout;
    private final Map<String, String> headers;
    private final ObjectMapper mapper;
    private final boolean failClosed;

    private VellavetoClient(Builder builder) {
        this.baseUrl = builder.baseUrl;
        this.apiKey = builder.apiKey;
        this.timeout = builder.timeout;
        this.headers = Collections.unmodifiableMap(builder.headers);
        this.failClosed = builder.failClosed;
        this.mapper = new ObjectMapper()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        this.httpClient = builder.httpClient != null
                ? builder.httpClient
                : HttpClient.newBuilder()
                    .connectTimeout(this.timeout)
                    // SECURITY (R240-JAVA-1): NEVER follow redirects automatically.
                    // HttpClient.Redirect.NORMAL carries the Authorization header
                    // across domains, leaking the API key to attacker-controlled
                    // redirect targets. Parity with Python (no follow), TypeScript
                    // (redirect: "manual"), and Go (strip Authorization on cross-domain).
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
    }

    /**
     * Creates a new client builder.
     *
     * @param baseUrl the Vellaveto server URL (must use http:// or https://)
     * @return a new Builder
     */
    public static Builder builder(String baseUrl) {
        return new Builder(baseUrl);
    }

    /**
     * Returns a redacted string representation (API key masked).
     * SECURITY: Prevents API key leakage in logs and debug output.
     */
    @Override
    public String toString() {
        return "VellavetoClient{baseUrl='" + baseUrl + "', apiKey=***}";
    }

    @Override
    public void close() {
        // HttpClient in Java 11 doesn't require explicit close
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Core Evaluation
    // ═══════════════════════════════════════════════════════════════════════

    /** Checks the Vellaveto server health. */
    public Map<String, Object> health() throws VellavetoException {
        return doJsonGet("/health", new TypeReference<Map<String, Object>>() {});
    }

    /**
     * Sends an action to the policy engine for evaluation.
     *
     * <p>The server expects Action fields flattened at the root level of the JSON body
     * (not nested under an "action" key) because the Rust server uses {@code #[serde(flatten)]}.</p>
     */
    public EvaluationResult evaluate(Action action, EvaluationContext context, boolean trace)
            throws VellavetoException {
        action.validate();
        validateParametersSize(action.getParameters());
        if (context != null) {
            context.validate();
        }

        Map<String, Object> body = new HashMap<>();
        body.put("tool", action.getTool());
        if (action.getFunction() != null) body.put("function", action.getFunction());
        if (action.getParameters() != null) body.put("parameters", action.getParameters());
        if (action.getTargetPaths() != null) body.put("target_paths", action.getTargetPaths());
        if (action.getTargetDomains() != null) body.put("target_domains", action.getTargetDomains());
        if (action.getResolvedIps() != null) body.put("resolved_ips", action.getResolvedIps());
        if (context != null) body.put("context", context);

        String path = trace ? "/api/evaluate?trace=true" : "/api/evaluate";
        try {
            JsonNode raw = doJsonPostRaw(path, body);
            return parseEvaluationResult(raw);
        } catch (VellavetoException e) {
            if (failClosed && isConnectionError(e)) {
                LOG.warning("Vellaveto server unreachable (failClosed=true), denying: " + e.getMessage());
                return new EvaluationResult(
                        Verdict.DENY,
                        "Server unreachable (fail-closed): " + e.getMessage(),
                        null, null, null, null);
            }
            throw e;
        }
    }

    /**
     * Returns true if the exception represents a network connectivity failure
     * (as opposed to a server-side error with an HTTP status code).
     */
    private static boolean isConnectionError(VellavetoException e) {
        return e.getStatusCode() == 0 && e.getCause() instanceof IOException;
    }

    /**
     * Like {@link #evaluate} but returns typed exceptions for Deny and RequireApproval.
     * On Allow, returns normally. Use evaluate() directly if you need the full result.
     */
    public void evaluateOrRaise(Action action, EvaluationContext context) throws VellavetoException {
        EvaluationResult result = evaluate(action, context, false);
        switch (result.getVerdict()) {
            case ALLOW:
                return;
            case DENY:
                throw new PolicyDeniedException(result.getReason(), result.getPolicyId());
            case REQUIRE_APPROVAL:
                throw new ApprovalRequiredException(result.getReason(), result.getApprovalId());
            default:
                throw new PolicyDeniedException("unknown verdict", null); // fail-closed
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Policy Management
    // ═══════════════════════════════════════════════════════════════════════

    /** Returns all loaded policies. */
    public List<Map<String, Object>> listPolicies() throws VellavetoException {
        return doJsonGet("/api/policies", new TypeReference<List<Map<String, Object>>>() {});
    }

    /** Triggers a policy reload on the server. */
    public Map<String, Object> reloadPolicies() throws VellavetoException {
        return doJsonPost("/api/policies/reload", null, new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Simulator
    // ═══════════════════════════════════════════════════════════════════════

    /** Evaluates an action with full trace information via the simulator endpoint. */
    public Map<String, Object> simulate(Action action, EvaluationContext context) throws VellavetoException {
        action.validate();
        validateParametersSize(action.getParameters());
        if (context != null) context.validate();
        Map<String, Object> body = new HashMap<>();
        body.put("action", action);
        if (context != null) body.put("context", context);
        return doJsonPost("/api/simulator/evaluate", body, new TypeReference<Map<String, Object>>() {});
    }

    /** Evaluates multiple actions in a single request. */
    public Map<String, Object> batchEvaluate(List<Action> actions, Map<String, Object> policyConfig)
            throws VellavetoException {
        for (int i = 0; i < actions.size(); i++) {
            actions.get(i).validate();
            validateParametersSize(actions.get(i).getParameters());
        }
        Map<String, Object> body = new HashMap<>();
        body.put("actions", actions);
        if (policyConfig != null) body.put("policy_config", policyConfig);
        return doJsonPost("/api/simulator/batch", body, new TypeReference<Map<String, Object>>() {});
    }

    /** Validates a policy configuration without loading it. */
    public Map<String, Object> validateConfig(Map<String, Object> config, boolean strict) throws VellavetoException {
        Map<String, Object> body = new HashMap<>();
        body.put("config", config);
        if (strict) body.put("strict", true);
        return doJsonPost("/api/simulator/validate", body, new TypeReference<Map<String, Object>>() {});
    }

    /** Compares two policy configurations. */
    public Map<String, Object> diffConfigs(Map<String, Object> before, Map<String, Object> after)
            throws VellavetoException {
        Map<String, Object> body = new HashMap<>();
        body.put("before", before);
        body.put("after", after);
        return doJsonPost("/api/simulator/diff", body, new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Approval Management
    // ═══════════════════════════════════════════════════════════════════════

    /** Returns all pending approval requests. */
    public List<Map<String, Object>> listPendingApprovals() throws VellavetoException {
        return doJsonGet("/api/approvals/pending", new TypeReference<List<Map<String, Object>>>() {});
    }

    /** Approves a pending approval by ID. */
    public void approveApproval(String id, String reason) throws VellavetoException {
        ValidationUtils.validateApprovalId(id);
        if (reason != null) ValidationUtils.validateReason(reason);
        Map<String, Object> body = null;
        if (reason != null && !reason.isEmpty()) {
            body = Collections.singletonMap("reason", reason);
        }
        doJsonPost("/api/approvals/" + urlEncode(id) + "/approve", body,
                new TypeReference<Map<String, Object>>() {});
    }

    /** Denies a pending approval by ID. */
    public void denyApproval(String id, String reason) throws VellavetoException {
        ValidationUtils.validateApprovalId(id);
        if (reason != null) ValidationUtils.validateReason(reason);
        Map<String, Object> body = null;
        if (reason != null && !reason.isEmpty()) {
            body = Collections.singletonMap("reason", reason);
        }
        doJsonPost("/api/approvals/" + urlEncode(id) + "/deny", body,
                new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Discovery
    // ═══════════════════════════════════════════════════════════════════════

    /** Searches the tool discovery index. */
    public Map<String, Object> discover(String query, int maxResults, Integer tokenBudget)
            throws VellavetoException {
        if (query == null || query.trim().isEmpty()) {
            throw new VellavetoException("discovery query must not be empty");
        }
        if (query.length() > ValidationUtils.MAX_DISCOVER_QUERY_LENGTH) {
            throw new VellavetoException("discovery query exceeds max length ("
                    + ValidationUtils.MAX_DISCOVER_QUERY_LENGTH + "), got " + query.length());
        }
        if (maxResults < 1 || maxResults > ValidationUtils.MAX_DISCOVER_RESULTS) {
            throw new VellavetoException("maxResults must be in [1, "
                    + ValidationUtils.MAX_DISCOVER_RESULTS + "], got " + maxResults);
        }
        if (tokenBudget != null && tokenBudget < 0) {
            throw new VellavetoException("tokenBudget must be non-negative");
        }
        Map<String, Object> body = new HashMap<>();
        body.put("query", query);
        body.put("max_results", maxResults);
        if (tokenBudget != null) body.put("token_budget", tokenBudget);
        return doJsonPost("/api/discovery/search", body, new TypeReference<Map<String, Object>>() {});
    }

    /** Returns statistics about the tool discovery index. */
    public Map<String, Object> discoveryStats() throws VellavetoException {
        return doJsonGet("/api/discovery/index/stats", new TypeReference<Map<String, Object>>() {});
    }

    /** Triggers a full rebuild of the IDF weights. */
    public Map<String, Object> discoveryReindex() throws VellavetoException {
        return doJsonPost("/api/discovery/reindex", null, new TypeReference<Map<String, Object>>() {});
    }

    /** Lists all indexed tools, optionally filtered by server ID and sensitivity. */
    public Map<String, Object> discoveryTools(String serverId, String sensitivity) throws VellavetoException {
        if (serverId != null && !serverId.isEmpty()) {
            if (serverId.length() > ValidationUtils.MAX_DISCOVERY_SERVER_ID_LENGTH) {
                throw new VellavetoException("serverID exceeds maximum length ("
                        + ValidationUtils.MAX_DISCOVERY_SERVER_ID_LENGTH + "), got " + serverId.length());
            }
            ValidationUtils.rejectControlAndFormatChars(serverId, "serverID");
        }
        if (sensitivity != null && !sensitivity.isEmpty()) {
            if (!"low".equals(sensitivity) && !"medium".equals(sensitivity) && !"high".equals(sensitivity)) {
                throw new VellavetoException("sensitivity must be one of [low, medium, high], got \""
                        + sensitivity + "\"");
            }
        }
        String path = "/api/discovery/tools";
        String qs = buildQueryString(
                "server_id", serverId,
                "sensitivity", sensitivity
        );
        if (!qs.isEmpty()) path += "?" + qs;
        return doJsonGet(path, new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Projector
    // ═══════════════════════════════════════════════════════════════════════

    /** Lists supported model families in the projector registry. */
    public Map<String, Object> projectorModels() throws VellavetoException {
        return doJsonGet("/api/projector/models", new TypeReference<Map<String, Object>>() {});
    }

    /** Projects a canonical tool schema for a given model family. */
    public Map<String, Object> projectSchema(Map<String, Object> schema, String modelFamily)
            throws VellavetoException {
        if (modelFamily == null || modelFamily.trim().isEmpty()) {
            throw new VellavetoException("modelFamily must not be empty");
        }
        Map<String, Object> body = new HashMap<>();
        body.put("schema", schema);
        body.put("model_family", modelFamily);
        return doJsonPost("/api/projector/transform", body, new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Zero-Knowledge Audit
    // ═══════════════════════════════════════════════════════════════════════

    /** Returns the current ZK audit scheduler status. */
    public Map<String, Object> zkStatus() throws VellavetoException {
        return doJsonGet("/api/zk-audit/status", new TypeReference<Map<String, Object>>() {});
    }

    /** Lists stored ZK batch proofs with pagination. */
    public Map<String, Object> zkProofs(int limit, int offset) throws VellavetoException {
        if (limit < 1 || limit > ValidationUtils.MAX_ZK_PROOFS_LIMIT) {
            throw new VellavetoException("ZkProofs: limit must be in [1, "
                    + ValidationUtils.MAX_ZK_PROOFS_LIMIT + "], got " + limit);
        }
        if (offset < 0) {
            throw new VellavetoException("ZkProofs: offset must be non-negative, got " + offset);
        }
        String path = "/api/zk-audit/proofs?" + buildQueryString(
                "limit", String.valueOf(limit),
                "offset", String.valueOf(offset)
        );
        return doJsonGet(path, new TypeReference<Map<String, Object>>() {});
    }

    /** Verifies a stored ZK batch proof by batch ID. */
    public Map<String, Object> zkVerify(String batchId) throws VellavetoException {
        if (batchId == null || batchId.trim().isEmpty()) {
            throw new VellavetoException("batchID must not be empty");
        }
        Map<String, Object> body = Collections.singletonMap("batch_id", batchId);
        return doJsonPost("/api/zk-audit/verify", body, new TypeReference<Map<String, Object>>() {});
    }

    /** Lists Pedersen commitments for audit entries in a sequence range. */
    public Map<String, Object> zkCommitments(long from, long to) throws VellavetoException {
        if (from > to) {
            throw new VellavetoException("ZkCommitments: from (" + from + ") must be <= to (" + to + ")");
        }
        String path = "/api/zk-audit/commitments?" + buildQueryString(
                "from", String.valueOf(from),
                "to", String.valueOf(to)
        );
        return doJsonGet(path, new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Compliance & Evidence
    // ═══════════════════════════════════════════════════════════════════════

    /** Generates a SOC 2 Type II access review report. */
    public Map<String, Object> soc2AccessReview(String period, String format, String agentId)
            throws VellavetoException {
        ValidationUtils.validatePeriod(period);
        ValidationUtils.validateFormat(format);
        if (agentId != null) {
            if (agentId.length() > 128) {
                throw new VellavetoException("agent_id exceeds max length (128)");
            }
            ValidationUtils.rejectControlAndFormatChars(agentId, "agent_id");
        }
        String path = "/api/compliance/soc2/access-review";
        String qs = buildQueryString("period", period, "format", format, "agent_id", agentId);
        if (!qs.isEmpty()) path += "?" + qs;
        return doJsonGet(path, new TypeReference<Map<String, Object>>() {});
    }

    /** Retrieves the OWASP Agentic Security Index coverage report. */
    public Map<String, Object> owaspAsiCoverage() throws VellavetoException {
        return doJsonGet("/api/compliance/owasp-agentic", new TypeReference<Map<String, Object>>() {});
    }

    /** Generates a compliance evidence pack for the specified framework. */
    public Map<String, Object> evidencePack(String framework, String format) throws VellavetoException {
        if (framework == null || framework.isEmpty()) {
            throw new VellavetoException("framework must be a non-empty string");
        }
        if (!"dora".equals(framework) && !"nis2".equals(framework)
                && !"iso42001".equals(framework) && !"eu-ai-act".equals(framework)) {
            throw new VellavetoException("framework must be one of dora, nis2, iso42001, eu-ai-act, got \""
                    + framework + "\"");
        }
        ValidationUtils.validateFormat(format);
        String path = "/api/compliance/evidence-pack/" + urlEncode(framework);
        if (format != null && !format.isEmpty() && !"json".equals(format)) {
            path += "?format=" + urlEncode(format);
        }
        return doJsonGet(path, new TypeReference<Map<String, Object>>() {});
    }

    /** Retrieves which evidence pack frameworks are available. */
    public Map<String, Object> evidencePackStatus() throws VellavetoException {
        return doJsonGet("/api/compliance/evidence-pack/status", new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Federation
    // ═══════════════════════════════════════════════════════════════════════

    /** Returns the federation resolver status. */
    public Map<String, Object> federationStatus() throws VellavetoException {
        return doJsonGet("/api/federation/status", new TypeReference<Map<String, Object>>() {});
    }

    /** Returns configured federation trust anchors (optionally filtered by orgId). */
    public Map<String, Object> federationTrustAnchors(String orgId) throws VellavetoException {
        if (orgId != null) {
            if (orgId.length() > 128) {
                throw new VellavetoException("org_id exceeds max length (128)");
            }
            ValidationUtils.rejectControlAndFormatChars(orgId, "org_id");
        }
        String path = "/api/federation/trust-anchors";
        if (orgId != null && !orgId.isEmpty()) {
            path += "?org_id=" + urlEncode(orgId);
        }
        return doJsonGet(path, new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Usage & Billing
    // ═══════════════════════════════════════════════════════════════════════

    /** Retrieves current-period usage metrics for a tenant. */
    public Map<String, Object> usage(String tenantId) throws VellavetoException {
        ValidationUtils.validateTenantId(tenantId);
        return doJsonGet("/api/billing/usage/" + urlEncode(tenantId),
                new TypeReference<Map<String, Object>>() {});
    }

    /** Retrieves quota status (usage vs limits) for a tenant. */
    public Map<String, Object> quotaStatus(String tenantId) throws VellavetoException {
        ValidationUtils.validateTenantId(tenantId);
        return doJsonGet("/api/billing/quotas/" + urlEncode(tenantId),
                new TypeReference<Map<String, Object>>() {});
    }

    /** Retrieves usage history across billing periods for a tenant. */
    public Map<String, Object> usageHistory(String tenantId, int periods) throws VellavetoException {
        ValidationUtils.validateTenantId(tenantId);
        if (periods < 1 || periods > 120) {
            throw new VellavetoException("periods must be between 1 and 120, got " + periods);
        }
        return doJsonGet("/api/billing/usage/" + urlEncode(tenantId)
                        + "/history?periods=" + periods,
                new TypeReference<Map<String, Object>>() {});
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Content-Bound Attestation Verification
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Verifies the proxy's content-bound attestation on a response.
     *
     * <p>Returns {@code true} if the attestation HMAC is valid and the content hash
     * matches the response body. Returns {@code false} if verification fails or
     * no attestation is present.</p>
     *
     * @param response the JSON-RPC response map from the proxy
     * @param hmacKey  the shared HMAC secret (same as VELLAVETO_ATTESTATION_SECRET)
     * @return true if attestation is present and valid, false otherwise
     */
    @SuppressWarnings("unchecked")
    public static boolean verifyAttestation(Map<String, Object> response, byte[] hmacKey) {
        Object metaRaw = response.get("_meta");
        if (!(metaRaw instanceof Map)) return false;
        Map<String, Object> meta = (Map<String, Object>) metaRaw;

        Object attRaw = meta.get("vellaveto_attestation");
        if (!(attRaw instanceof Map)) return false;
        Map<String, Object> att = (Map<String, Object>) attRaw;

        try {
            // Verify content hash matches
            Object content = response.containsKey("result") ? response.get("result") : response.get("error");
            ObjectMapper m = new ObjectMapper();
            String canonical = m.writeValueAsString(content);
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            String expectedHash = sb.toString();
            String contentHash = String.valueOf(att.get("content_hash"));
            if (!expectedHash.equals(contentHash)) return false;

            // Extract attestation fields
            int version = ((Number) att.get("version")).intValue();
            long timestamp = ((Number) att.get("timestamp")).longValue();
            boolean injClean = Boolean.TRUE.equals(att.get("injection_clean"));
            boolean dlpClean = Boolean.TRUE.equals(att.get("dlp_clean"));
            boolean schemaValid = Boolean.TRUE.equals(att.get("schema_valid"));
            String trustTier = String.valueOf(att.get("trust_tier"));
            int scanPasses = ((Number) att.get("scan_passes")).intValue();
            String signature = String.valueOf(att.get("signature"));

            // Verify HMAC signature
            String signingContent = String.format("v%d:%d:%s:%s:%s:%s:%s:%d",
                    version, timestamp, contentHash,
                    String.valueOf(injClean).toLowerCase(),
                    String.valueOf(dlpClean).toLowerCase(),
                    String.valueOf(schemaValid).toLowerCase(),
                    trustTier, scanPasses);
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(hmacKey, "HmacSHA256"));
            byte[] sigBytes = mac.doFinal(signingContent.getBytes(StandardCharsets.UTF_8));
            StringBuilder sigHex = new StringBuilder();
            for (byte b : sigBytes) {
                sigHex.append(String.format("%02x", b));
            }
            return java.security.MessageDigest.isEqual(
                    signature.getBytes(StandardCharsets.UTF_8),
                    sigHex.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HTTP Infrastructure
    // ═══════════════════════════════════════════════════════════════════════

    private <T> T doJsonGet(String path, TypeReference<T> typeRef) throws VellavetoException {
        return doJsonRequest("GET", path, null, typeRef);
    }

    private <T> T doJsonPost(String path, Object body, TypeReference<T> typeRef) throws VellavetoException {
        return doJsonRequest("POST", path, body, typeRef);
    }

    private JsonNode doJsonPostRaw(String path, Object body) throws VellavetoException {
        byte[] respBytes = doRequestWithRetry("POST", path, body);
        try {
            return mapper.readTree(respBytes);
        } catch (IOException e) {
            throw new VellavetoException("decode response: " + e.getMessage(), e);
        }
    }

    private <T> T doJsonRequest(String method, String path, Object body, TypeReference<T> typeRef)
            throws VellavetoException {
        byte[] respBytes = doRequestWithRetry(method, path, body);
        if (respBytes == null || respBytes.length == 0) {
            return null;
        }
        try {
            return mapper.readValue(respBytes, typeRef);
        } catch (IOException e) {
            throw new VellavetoException("decode response: " + e.getMessage(), e);
        }
    }

    /**
     * Executes a request with retry for transient HTTP failures.
     * SECURITY: Retries on 429, 502, 503, 504 with exponential backoff and full jitter.
     */
    private byte[] doRequestWithRetry(String method, String path, Object body) throws VellavetoException {
        long backoffMs = DEFAULT_INITIAL_BACKOFF.toMillis();
        VellavetoException lastError = null;

        for (int attempt = 0; attempt <= DEFAULT_MAX_RETRIES; attempt++) {
            if (attempt > 0) {
                long jittered = ThreadLocalRandom.current().nextLong(0, backoffMs + 1);
                try {
                    Thread.sleep(jittered);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new VellavetoException("request interrupted", e);
                }
                backoffMs = Math.min(backoffMs * 2, MAX_TIMEOUT.toMillis());
            }

            try {
                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + path))
                        .timeout(timeout)
                        .header("Content-Type", "application/json");

                if (apiKey != null && !apiKey.isEmpty()) {
                    reqBuilder.header("Authorization", "Bearer " + apiKey);
                }
                for (Map.Entry<String, String> h : headers.entrySet()) {
                    reqBuilder.header(h.getKey(), h.getValue());
                }

                if (body != null) {
                    byte[] bodyBytes = mapper.writeValueAsBytes(body);
                    reqBuilder.method(method, HttpRequest.BodyPublishers.ofByteArray(bodyBytes));
                } else if ("POST".equals(method)) {
                    reqBuilder.method(method, HttpRequest.BodyPublishers.ofByteArray(new byte[0]));
                } else {
                    reqBuilder.method(method, HttpRequest.BodyPublishers.noBody());
                }

                HttpResponse<InputStream> resp = httpClient.send(
                        reqBuilder.build(),
                        HttpResponse.BodyHandlers.ofInputStream());

                // Read body with size limit
                byte[] respBody;
                try (InputStream is = resp.body()) {
                    respBody = readLimited(is, MAX_RESPONSE_BODY_SIZE);
                }

                int status = resp.statusCode();
                if (status >= 200 && status < 300) {
                    return respBody;
                }

                String msg = respBody.length > 0
                        ? new String(respBody, 0, Math.min(respBody.length, MAX_ERROR_BODY_DISPLAY), StandardCharsets.UTF_8)
                        : "empty response";
                if (respBody.length > MAX_ERROR_BODY_DISPLAY) {
                    msg += "...(truncated)";
                }

                lastError = new VellavetoException("unexpected status: " + msg, status);
                if (!isRetryableStatus(status)) {
                    throw lastError;
                }

            } catch (VellavetoException e) {
                if (e.getStatusCode() > 0 && !isRetryableStatus(e.getStatusCode())) {
                    throw e;
                }
                lastError = e;
            } catch (JsonProcessingException e) {
                throw new VellavetoException("marshal request: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new VellavetoException("request interrupted", e);
            } catch (IOException e) {
                lastError = new VellavetoException("request failed: " + e.getMessage(), e);
                // Only retry IO exceptions (network issues) — not all IOExceptions
            }
        }

        if (lastError != null) throw lastError;
        throw new VellavetoException("request failed after " + (DEFAULT_MAX_RETRIES + 1) + " attempts");
    }

    private static boolean isRetryableStatus(int status) {
        return status == 429 || status == 502 || status == 503 || status == 504;
    }

    /**
     * Reads from an InputStream with a size limit.
     * SECURITY: Prevents OOM from unbounded response bodies.
     */
    private static byte[] readLimited(InputStream is, long maxSize) throws IOException, VellavetoException {
        byte[] buffer = new byte[8192];
        int totalRead = 0;
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        int n;
        while ((n = is.read(buffer)) != -1) {
            totalRead += n;
            if (totalRead > maxSize) {
                throw new VellavetoException("response body exceeds " + maxSize + " byte limit");
            }
            baos.write(buffer, 0, n);
        }
        return baos.toByteArray();
    }

    /**
     * Parses the evaluation result handling both string and object verdict forms.
     * String: {"verdict": "allow"}
     * Object: {"verdict": {"Deny": {"reason": "..."}}}
     */
    private EvaluationResult parseEvaluationResult(JsonNode raw) {
        JsonNode verdictNode = raw.get("verdict");
        Verdict verdict;
        String objReason = null;

        if (verdictNode != null && verdictNode.isTextual()) {
            verdict = Verdict.fromString(verdictNode.asText());
        } else if (verdictNode != null && verdictNode.isObject()) {
            var fields = verdictNode.fields();
            if (fields.hasNext()) {
                var entry = fields.next();
                verdict = Verdict.fromString(entry.getKey());
                JsonNode inner = entry.getValue();
                if (inner.has("reason")) {
                    objReason = inner.get("reason").asText();
                }
            } else {
                verdict = Verdict.DENY; // fail-closed
            }
        } else {
            verdict = Verdict.DENY; // fail-closed
        }

        String reason = raw.has("reason") && !raw.get("reason").asText().isEmpty()
                ? raw.get("reason").asText()
                : objReason;

        String policyId = raw.has("policy_id") ? raw.get("policy_id").asText() : null;
        String policyName = raw.has("policy_name") ? raw.get("policy_name").asText() : null;
        String approvalId = raw.has("approval_id") ? raw.get("approval_id").asText() : null;
        Map<String, Object> trace = null;
        if (raw.has("trace")) {
            try {
                trace = mapper.convertValue(raw.get("trace"), new TypeReference<Map<String, Object>>() {});
            } catch (Exception ignored) {
                // trace is optional, don't fail on parse error
            }
        }

        return new EvaluationResult(verdict, reason, policyId, policyName, approvalId, trace);
    }

    private void validateParametersSize(Map<String, Object> parameters) throws VellavetoException {
        if (parameters == null || parameters.isEmpty()) return;
        try {
            byte[] serialized = mapper.writeValueAsBytes(parameters);
            if (serialized.length > ValidationUtils.MAX_PARAMETERS_SIZE) {
                throw new VellavetoException("parameters exceed maximum size ("
                        + ValidationUtils.MAX_PARAMETERS_SIZE + " bytes)");
            }
        } catch (JsonProcessingException e) {
            throw new VellavetoException("failed to serialize parameters: " + e.getMessage(), e);
        }
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String buildQueryString(String... pairs) {
        StringJoiner sj = new StringJoiner("&");
        for (int i = 0; i < pairs.length; i += 2) {
            String key = pairs[i];
            String value = pairs[i + 1];
            if (value != null && !value.isEmpty()) {
                sj.add(urlEncode(key) + "=" + urlEncode(value));
            }
        }
        return sj.toString();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Builder
    // ═══════════════════════════════════════════════════════════════════════

    public static class Builder {
        private final String baseUrl;
        private String apiKey;
        private Duration timeout = DEFAULT_TIMEOUT;
        private HttpClient httpClient;
        private boolean failClosed;
        private final Map<String, String> headers = new HashMap<>();

        Builder(String baseUrl) {
            Objects.requireNonNull(baseUrl, "baseUrl must not be null");
            this.baseUrl = baseUrl.replaceAll("/+$", "");
        }

        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        /**
         * Sets the HTTP request timeout.
         * SECURITY: Clamped to [100ms, 300s] matching all SDK parity.
         */
        public Builder timeout(Duration timeout) {
            if (timeout.compareTo(MIN_TIMEOUT) < 0) {
                LOG.warning("timeout " + timeout + " below minimum " + MIN_TIMEOUT + ", clamping");
                this.timeout = MIN_TIMEOUT;
            } else if (timeout.compareTo(MAX_TIMEOUT) > 0) {
                LOG.warning("timeout " + timeout + " above maximum " + MAX_TIMEOUT + ", clamping");
                this.timeout = MAX_TIMEOUT;
            } else {
                this.timeout = timeout;
            }
            return this;
        }

        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /**
         * Enables fail-closed mode: when the server is unreachable, evaluate()
         * returns a Deny verdict instead of throwing an exception.
         */
        public Builder failClosed(boolean failClosed) {
            this.failClosed = failClosed;
            return this;
        }

        /**
         * Adds custom headers to every request.
         * SECURITY: Validates headers for CRLF injection and blocks security-sensitive overrides.
         */
        public Builder headers(Map<String, String> headers) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                String k = entry.getKey();
                String v = entry.getValue();
                // SECURITY: Block CRLF injection
                if (k.contains("\r") || k.contains("\n") || v.contains("\r") || v.contains("\n")) {
                    continue;
                }
                // SECURITY: Block security-sensitive header overrides
                String lower = k.toLowerCase();
                if ("content-type".equals(lower) || "authorization".equals(lower)) {
                    continue;
                }
                this.headers.put(k, v);
            }
            return this;
        }

        /**
         * Sets the tenant ID for multi-tenancy support.
         * Must be 1-64 chars, alphanumeric + hyphen + underscore only.
         */
        public Builder tenant(String tenantId) {
            if (tenantId == null || tenantId.isEmpty() || tenantId.length() > ValidationUtils.MAX_TENANT_ID_LENGTH) {
                LOG.warning("tenant ID length out of range [1, 64], ignoring");
                return this;
            }
            if (!ValidationUtils.TENANT_ID_PATTERN.matcher(tenantId).matches()) {
                LOG.warning("tenant ID contains invalid characters, ignoring");
                return this;
            }
            this.headers.put("X-Tenant-ID", tenantId);
            return this;
        }

        /**
         * Builds the client.
         *
         * @throws IllegalArgumentException if baseUrl is invalid
         */
        public VellavetoClient build() {
            // Validate base URL
            if (baseUrl.isEmpty()) {
                throw new IllegalArgumentException("vellaveto: baseURL must not be empty");
            }
            URI uri;
            try {
                uri = URI.create(baseUrl);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("vellaveto: invalid baseURL: " + e.getMessage());
            }
            String scheme = uri.getScheme();
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                throw new IllegalArgumentException(
                        "vellaveto: baseURL must use http:// or https:// scheme, got \"" + scheme + "\"");
            }
            if (uri.getHost() == null || uri.getHost().isEmpty()) {
                throw new IllegalArgumentException("vellaveto: baseURL must have a host");
            }
            // SECURITY: Reject URLs containing credentials (userinfo)
            if (uri.getUserInfo() != null) {
                throw new IllegalArgumentException(
                        "vellaveto: baseURL must not contain credentials (userinfo)");
            }
            return new VellavetoClient(this);
        }
    }
}
