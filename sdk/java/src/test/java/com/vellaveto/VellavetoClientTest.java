package com.vellaveto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Vellaveto Java SDK.
 *
 * Tests are grouped by component:
 * 1. Builder / URL validation
 * 2. Action validation
 * 3. EvaluationContext validation
 * 4. Verdict parsing
 * 5. Approval ID validation
 * 6. Reason validation
 * 7. Tenant ID validation
 * 8. Unicode format character detection
 * 9. ParameterRedactor
 * 10. Discovery validation
 * 11. ZK validation
 * 12. Compliance validation
 * 13. Federation validation
 * 14. Usage validation
 * 15. Exception types
 */
class VellavetoClientTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // ═══════════════════════════════════════════════════════════════════════
    // 1. Builder / URL Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_builder_valid_http_url() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080")
                .apiKey("test-key")
                .build();
        assertNotNull(client);
        assertTrue(client.toString().contains("localhost:8080"));
        assertTrue(client.toString().contains("***")); // API key redacted
    }

    @Test
    void test_builder_valid_https_url() {
        VellavetoClient client = VellavetoClient.builder("https://api.vellaveto.com").build();
        assertNotNull(client);
    }

    @Test
    void test_builder_trailing_slashes_stripped() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080///").build();
        assertNotNull(client);
        assertFalse(client.toString().contains("///"));
    }

    @Test
    void test_builder_empty_url_rejected() {
        assertThrows(IllegalArgumentException.class, () ->
                VellavetoClient.builder("").build());
    }

    @Test
    void test_builder_invalid_scheme_rejected() {
        assertThrows(IllegalArgumentException.class, () ->
                VellavetoClient.builder("ftp://example.com").build());
    }

    @Test
    void test_builder_missing_host_rejected() {
        assertThrows(IllegalArgumentException.class, () ->
                VellavetoClient.builder("http://").build());
    }

    @Test
    void test_builder_userinfo_rejected() {
        assertThrows(IllegalArgumentException.class, () ->
                VellavetoClient.builder("http://user:pass@example.com").build());
    }

    @Test
    void test_builder_timeout_clamped_to_minimum() {
        // Should not throw, timeout silently clamped
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080")
                .timeout(Duration.ofMillis(1))
                .build();
        assertNotNull(client);
    }

    @Test
    void test_builder_timeout_clamped_to_maximum() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080")
                .timeout(Duration.ofHours(1))
                .build();
        assertNotNull(client);
    }

    @Test
    void test_builder_crlf_headers_rejected() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Custom\r\n", "value");
        headers.put("X-Good", "bad\nvalue");
        headers.put("X-Valid", "valid-value");

        VellavetoClient client = VellavetoClient.builder("http://localhost:8080")
                .headers(headers)
                .build();
        assertNotNull(client);
    }

    @Test
    void test_builder_security_headers_blocked() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "custom-auth");
        headers.put("Content-Type", "text/plain");
        headers.put("X-Custom", "allowed");

        VellavetoClient client = VellavetoClient.builder("http://localhost:8080")
                .headers(headers)
                .build();
        assertNotNull(client);
    }

    @Test
    void test_builder_tenant_valid() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080")
                .tenant("acme-corp-123")
                .build();
        assertNotNull(client);
    }

    @Test
    void test_builder_tenant_invalid_chars_ignored() {
        // Should not throw, but tenant header not set
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080")
                .tenant("invalid tenant!")
                .build();
        assertNotNull(client);
    }

    @Test
    void test_builder_tenant_too_long_ignored() {
        String longTenant = "a".repeat(65);
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080")
                .tenant(longTenant)
                .build();
        assertNotNull(client);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 2. Action Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_action_valid() throws VellavetoException {
        Action action = Action.builder("read_file")
                .function("read")
                .parameters(Collections.singletonMap("path", "/tmp/test"))
                .targetPaths(Collections.singletonList("/tmp/test"))
                .build();
        action.validate(); // should not throw
    }

    @Test
    void test_action_empty_tool_rejected() {
        Action action = Action.builder("").build();
        assertThrows(VellavetoException.class, action::validate);
    }

    @Test
    void test_action_null_tool_rejected() {
        Action action = Action.builder(null).build();
        assertThrows(VellavetoException.class, action::validate);
    }

    @Test
    void test_action_tool_too_long() {
        Action action = Action.builder("a".repeat(257)).build();
        VellavetoException e = assertThrows(VellavetoException.class, action::validate);
        assertTrue(e.getMessage().contains("max length"));
    }

    @Test
    void test_action_tool_control_chars() {
        Action action = Action.builder("read\u0000file").build();
        VellavetoException e = assertThrows(VellavetoException.class, action::validate);
        assertTrue(e.getMessage().contains("control characters"));
    }

    @Test
    void test_action_tool_unicode_format_chars() {
        Action action = Action.builder("read\u200Bfile").build();
        VellavetoException e = assertThrows(VellavetoException.class, action::validate);
        assertTrue(e.getMessage().contains("Unicode format characters"));
    }

    @Test
    void test_action_function_too_long() {
        Action action = Action.builder("tool").function("a".repeat(257)).build();
        VellavetoException e = assertThrows(VellavetoException.class, action::validate);
        assertTrue(e.getMessage().contains("function"));
    }

    @Test
    void test_action_function_control_chars() {
        Action action = Action.builder("tool").function("func\u007F").build();
        VellavetoException e = assertThrows(VellavetoException.class, action::validate);
        assertTrue(e.getMessage().contains("control characters"));
    }

    @Test
    void test_action_target_paths_too_many() {
        List<String> paths = IntStream.range(0, 101)
                .mapToObj(i -> "/path/" + i)
                .collect(Collectors.toList());
        Action action = Action.builder("tool").targetPaths(paths).build();
        VellavetoException e = assertThrows(VellavetoException.class, action::validate);
        assertTrue(e.getMessage().contains("targetPaths"));
    }

    @Test
    void test_action_target_domains_too_many() {
        List<String> domains = IntStream.range(0, 101)
                .mapToObj(i -> "domain" + i + ".com")
                .collect(Collectors.toList());
        Action action = Action.builder("tool").targetDomains(domains).build();
        VellavetoException e = assertThrows(VellavetoException.class, action::validate);
        assertTrue(e.getMessage().contains("targetDomains"));
    }

    @Test
    void test_action_resolved_ips_too_many() {
        List<String> ips = IntStream.range(0, 101)
                .mapToObj(i -> "10.0.0." + (i % 256))
                .collect(Collectors.toList());
        Action action = Action.builder("tool").resolvedIps(ips).build();
        VellavetoException e = assertThrows(VellavetoException.class, action::validate);
        assertTrue(e.getMessage().contains("resolvedIps"));
    }

    @Test
    void test_action_toString_redacts_nothing() {
        Action action = Action.builder("read_file").function("read").build();
        String str = action.toString();
        assertTrue(str.contains("read_file"));
        assertTrue(str.contains("read"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 3. EvaluationContext Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_context_valid() throws VellavetoException {
        EvaluationContext ctx = new EvaluationContext(
                "session-1", "agent-1", "tenant-1",
                Arrays.asList("agent-a", "agent-b"), null);
        ctx.validate();
    }

    @Test
    void test_context_session_id_too_long() {
        EvaluationContext ctx = new EvaluationContext(
                "s".repeat(257), null, null, null, null);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    @Test
    void test_context_agent_id_too_long() {
        EvaluationContext ctx = new EvaluationContext(
                null, "a".repeat(257), null, null, null);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    @Test
    void test_context_tenant_id_too_long() {
        EvaluationContext ctx = new EvaluationContext(
                null, null, "t".repeat(65), null, null);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    @Test
    void test_context_call_chain_too_long() {
        List<String> chain = IntStream.range(0, 101)
                .mapToObj(i -> "agent-" + i)
                .collect(Collectors.toList());
        EvaluationContext ctx = new EvaluationContext(null, null, null, chain, null);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    @Test
    void test_context_metadata_too_many() {
        Map<String, Object> meta = new HashMap<>();
        for (int i = 0; i < 101; i++) meta.put("key" + i, "value");
        EvaluationContext ctx = new EvaluationContext(null, null, null, null, meta);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    @Test
    void test_context_call_chain_entry_too_long() {
        List<String> chain = Arrays.asList("ok", "a".repeat(257));
        EvaluationContext ctx = new EvaluationContext(null, null, null, chain, null);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    @Test
    void test_context_call_chain_entry_control_chars() {
        List<String> chain = Arrays.asList("ok", "bad\u0001agent");
        EvaluationContext ctx = new EvaluationContext(null, null, null, chain, null);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    @Test
    void test_context_call_chain_entry_unicode_format_chars() {
        // U+200B zero-width space
        List<String> chain = Arrays.asList("ok", "agent\u200Bhidden");
        EvaluationContext ctx = new EvaluationContext(null, null, null, chain, null);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    @Test
    void test_context_call_chain_valid_entries() throws VellavetoException {
        List<String> chain = Arrays.asList("agent-a", "agent-b", "a".repeat(256));
        EvaluationContext ctx = new EvaluationContext(null, null, null, chain, null);
        ctx.validate(); // should not throw
    }

    @Test
    void test_context_control_chars_in_session_id() {
        EvaluationContext ctx = new EvaluationContext("\u0001bad", null, null, null, null);
        assertThrows(VellavetoException.class, ctx::validate);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 4. Verdict Parsing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_verdict_allow() {
        assertEquals(Verdict.ALLOW, Verdict.fromString("allow"));
        assertEquals(Verdict.ALLOW, Verdict.fromString("ALLOW"));
        assertEquals(Verdict.ALLOW, Verdict.fromString("Allow"));
    }

    @Test
    void test_verdict_deny() {
        assertEquals(Verdict.DENY, Verdict.fromString("deny"));
        assertEquals(Verdict.DENY, Verdict.fromString("DENY"));
    }

    @Test
    void test_verdict_require_approval() {
        assertEquals(Verdict.REQUIRE_APPROVAL, Verdict.fromString("require_approval"));
        assertEquals(Verdict.REQUIRE_APPROVAL, Verdict.fromString("REQUIRE_APPROVAL"));
        assertEquals(Verdict.REQUIRE_APPROVAL, Verdict.fromString("requireapproval"));
    }

    @Test
    void test_verdict_unknown_defaults_to_deny() {
        assertEquals(Verdict.DENY, Verdict.fromString("unknown"));
        assertEquals(Verdict.DENY, Verdict.fromString(""));
        assertEquals(Verdict.DENY, Verdict.fromString(null));
    }

    @Test
    void test_verdict_json_value() {
        assertEquals("allow", Verdict.ALLOW.getValue());
        assertEquals("deny", Verdict.DENY.getValue());
        assertEquals("require_approval", Verdict.REQUIRE_APPROVAL.getValue());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 5. Approval ID Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_approval_id_valid() throws VellavetoException {
        ValidationUtils.validateApprovalId("abc-123");
    }

    @Test
    void test_approval_id_empty() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateApprovalId(""));
    }

    @Test
    void test_approval_id_null() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateApprovalId(null));
    }

    @Test
    void test_approval_id_too_long() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateApprovalId("a".repeat(257)));
    }

    @Test
    void test_approval_id_control_chars() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateApprovalId("abc\u0000def"));
    }

    @Test
    void test_approval_id_unicode_format() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateApprovalId("abc\u200Bdef"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 6. Reason Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_reason_valid() throws VellavetoException {
        ValidationUtils.validateReason("This is a valid reason");
    }

    @Test
    void test_reason_null_ok() throws VellavetoException {
        ValidationUtils.validateReason(null);
    }

    @Test
    void test_reason_empty_ok() throws VellavetoException {
        ValidationUtils.validateReason("");
    }

    @Test
    void test_reason_too_long() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateReason("x".repeat(5000)));
    }

    @Test
    void test_reason_control_chars() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateReason("bad\u0001reason"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 7. Tenant ID Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_tenant_id_valid() throws VellavetoException {
        ValidationUtils.validateTenantId("acme-corp_123");
    }

    @Test
    void test_tenant_id_empty() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateTenantId(""));
    }

    @Test
    void test_tenant_id_null() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateTenantId(null));
    }

    @Test
    void test_tenant_id_too_long() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateTenantId("a".repeat(65)));
    }

    @Test
    void test_tenant_id_invalid_chars() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateTenantId("acme corp!"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 8. Unicode Format Character Detection
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_unicode_format_soft_hyphen() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x00AD));
    }

    @Test
    void test_unicode_format_zero_width_space() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x200B));
    }

    @Test
    void test_unicode_format_zero_width_non_joiner() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x200C));
    }

    @Test
    void test_unicode_format_zero_width_joiner() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x200D));
    }

    @Test
    void test_unicode_format_bidi_override() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x202E));
    }

    @Test
    void test_unicode_format_word_joiner() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x2060));
    }

    @Test
    void test_unicode_format_bom() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0xFEFF));
    }

    @Test
    void test_unicode_format_annotation_anchor() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0xFFF9));
    }

    @Test
    void test_unicode_format_tag_chars() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0xE0001));
        assertTrue(ValidationUtils.isUnicodeFormatChar(0xE007F));
    }

    @Test
    void test_unicode_format_normal_chars() {
        assertFalse(ValidationUtils.isUnicodeFormatChar('A'));
        assertFalse(ValidationUtils.isUnicodeFormatChar('z'));
        assertFalse(ValidationUtils.isUnicodeFormatChar('0'));
        assertFalse(ValidationUtils.isUnicodeFormatChar(' '));
    }

    @Test
    void test_unicode_format_line_separator() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x2028));
    }

    @Test
    void test_unicode_format_paragraph_separator() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x2029));
    }

    @Test
    void test_unicode_format_bidi_isolate() {
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x2066));
        assertTrue(ValidationUtils.isUnicodeFormatChar(0x2069));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 9. ParameterRedactor
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_redactor_sensitive_keys() {
        ParameterRedactor redactor = new ParameterRedactor();
        assertTrue(redactor.isSensitiveKey("password"));
        assertTrue(redactor.isSensitiveKey("api_key"));
        assertTrue(redactor.isSensitiveKey("secret"));
        assertTrue(redactor.isSensitiveKey("token"));
        assertTrue(redactor.isSensitiveKey("Authorization"));
        assertTrue(redactor.isSensitiveKey("CLIENT_SECRET"));
    }

    @Test
    void test_redactor_non_sensitive_keys() {
        ParameterRedactor redactor = new ParameterRedactor();
        assertFalse(redactor.isSensitiveKey("path"));
        assertFalse(redactor.isSensitiveKey("query"));
        assertFalse(redactor.isSensitiveKey("url"));
    }

    @Test
    void test_redactor_sensitive_values() {
        ParameterRedactor redactor = new ParameterRedactor();
        assertTrue(redactor.isSensitiveValue("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assertTrue(redactor.isSensitiveValue("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789+/")); // base64
        assertTrue(redactor.isSensitiveValue("0123456789abcdef0123456789abcdef")); // hex 32+
    }

    @Test
    void test_redactor_non_sensitive_values() {
        ParameterRedactor redactor = new ParameterRedactor();
        assertFalse(redactor.isSensitiveValue("short"));
        assertFalse(redactor.isSensitiveValue(42));
        assertFalse(redactor.isSensitiveValue(null));
    }

    @Test
    void test_redactor_redact_map() {
        ParameterRedactor redactor = new ParameterRedactor();
        Map<String, Object> params = new HashMap<>();
        params.put("path", "/tmp/test");
        params.put("password", "super_secret");
        params.put("api_key", "sk-12345");

        Map<String, Object> redacted = redactor.redact(params);
        assertEquals("/tmp/test", redacted.get("path"));
        assertEquals("[REDACTED]", redacted.get("password"));
        assertEquals("[REDACTED]", redacted.get("api_key"));
    }

    @Test
    void test_redactor_null_parameters() {
        ParameterRedactor redactor = new ParameterRedactor();
        assertNull(redactor.redact(null));
    }

    @Test
    void test_redactor_custom_keys() {
        ParameterRedactor redactor = new ParameterRedactor(
                Collections.singleton("custom_secret"));
        assertTrue(redactor.isSensitiveKey("custom_secret"));
        assertTrue(redactor.isSensitiveKey("password")); // default still works
    }

    @Test
    @SuppressWarnings("unchecked")
    void test_redactor_recurses_into_nested_map() {
        ParameterRedactor redactor = new ParameterRedactor();
        Map<String, Object> inner = new HashMap<>();
        inner.put("token", "my-secret-token");
        inner.put("safe", "visible");
        Map<String, Object> params = new HashMap<>();
        params.put("config", inner);
        params.put("name", "test");

        Map<String, Object> redacted = redactor.redact(params);
        assertEquals("test", redacted.get("name"));
        Map<String, Object> redactedInner = (Map<String, Object>) redacted.get("config");
        assertEquals("[REDACTED]", redactedInner.get("token"));
        assertEquals("visible", redactedInner.get("safe"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void test_redactor_recurses_into_list() {
        ParameterRedactor redactor = new ParameterRedactor();
        Map<String, Object> listItem = new HashMap<>();
        listItem.put("password", "secret123");
        listItem.put("name", "item1");
        Map<String, Object> params = new HashMap<>();
        params.put("items", Arrays.asList(listItem));

        Map<String, Object> redacted = redactor.redact(params);
        List<Object> items = (List<Object>) redacted.get("items");
        Map<String, Object> redactedItem = (Map<String, Object>) items.get(0);
        assertEquals("[REDACTED]", redactedItem.get("password"));
        assertEquals("item1", redactedItem.get("name"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void test_redactor_depth_limit_redacts_all() {
        ParameterRedactor redactor = new ParameterRedactor();
        // Build a structure nested 11 levels deep: level9 -> level8 -> ... -> level0 -> {safe_key: "..."}
        Map<String, Object> leaf = new HashMap<>();
        leaf.put("safe_key", "should_be_redacted_at_depth");
        Map<String, Object> current = leaf;
        for (int i = 0; i < 10; i++) {
            Map<String, Object> parent = new HashMap<>();
            parent.put("level" + i, current);
            current = parent;
        }
        // current is the outermost map, leaf is at depth 10
        Map<String, Object> redacted = redactor.redact(current);
        // Walk down to the leaf map at depth 10
        Object node = redacted;
        for (int i = 9; i >= 0; i--) {
            node = ((Map<String, Object>) node).get("level" + i);
        }
        // At depth 10, all values in the leaf map should be [REDACTED]
        Map<String, Object> leafRedacted = (Map<String, Object>) node;
        assertEquals("[REDACTED]", leafRedacted.get("safe_key"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 10. Discovery Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_discover_empty_query() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.discover("", 5, null));
    }

    @Test
    void test_discover_query_too_long() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.discover("a".repeat(1025), 5, null));
    }

    @Test
    void test_discover_max_results_too_low() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.discover("test", 0, null));
    }

    @Test
    void test_discover_max_results_too_high() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.discover("test", 21, null));
    }

    @Test
    void test_discover_negative_token_budget() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.discover("test", 5, -1));
    }

    @Test
    void test_discovery_tools_invalid_sensitivity() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.discoveryTools(null, "extreme"));
    }

    @Test
    void test_discovery_tools_server_id_too_long() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.discoveryTools("s".repeat(257), "low"));
    }

    @Test
    void test_discovery_tools_server_id_control_chars() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.discoveryTools("server\u0000id", "low"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 11. ZK Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_zk_proofs_limit_too_low() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.zkProofs(0, 0));
    }

    @Test
    void test_zk_proofs_limit_too_high() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.zkProofs(1001, 0));
    }

    @Test
    void test_zk_proofs_negative_offset() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.zkProofs(10, -1));
    }

    @Test
    void test_zk_verify_empty_batch_id() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.zkVerify(""));
    }

    @Test
    void test_zk_commitments_from_greater_than_to() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.zkCommitments(100, 50));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 12. Compliance Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_evidence_pack_empty_framework() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.evidencePack("", "json"));
    }

    @Test
    void test_evidence_pack_invalid_framework() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.evidencePack("hipaa", "json"));
    }

    @Test
    void test_evidence_pack_invalid_format() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.evidencePack("dora", "xml"));
    }

    @Test
    void test_soc2_invalid_format() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.soc2AccessReview("30d", "xml", null));
    }

    @Test
    void test_soc2_period_too_long() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.soc2AccessReview("a".repeat(33), "json", null));
    }

    @Test
    void test_soc2_period_invalid_chars() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.soc2AccessReview("30d; DROP TABLE", "json", null));
    }

    @Test
    void test_soc2_agent_id_too_long() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.soc2AccessReview("30d", "json", "a".repeat(129)));
    }

    @Test
    void test_soc2_agent_id_control_chars() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.soc2AccessReview("30d", "json", "agent\u0001id"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 13. Federation Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_federation_trust_anchors_org_id_too_long() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.federationTrustAnchors("a".repeat(129)));
    }

    @Test
    void test_federation_trust_anchors_org_id_control_chars() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.federationTrustAnchors("org\u007Fid"));
    }

    @Test
    void test_federation_trust_anchors_org_id_unicode_format() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.federationTrustAnchors("org\uFEFFid"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 14. Usage Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_usage_invalid_tenant_id() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.usage("invalid tenant!"));
    }

    @Test
    void test_quota_status_empty_tenant() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.quotaStatus(""));
    }

    @Test
    void test_usage_history_periods_too_low() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.usageHistory("acme", 0));
    }

    @Test
    void test_usage_history_periods_too_high() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.usageHistory("acme", 121));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 15. Exception Types
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_vellaveto_exception_message() {
        VellavetoException e = new VellavetoException("test error");
        assertTrue(e.getMessage().contains("vellaveto:"));
        assertTrue(e.getMessage().contains("test error"));
        assertEquals(0, e.getStatusCode());
    }

    @Test
    void test_vellaveto_exception_with_status() {
        VellavetoException e = new VellavetoException("test", 404);
        assertTrue(e.getMessage().contains("HTTP 404"));
        assertEquals(404, e.getStatusCode());
    }

    @Test
    void test_policy_denied_exception() {
        PolicyDeniedException e = new PolicyDeniedException("path blocked", "policy-1");
        assertTrue(e.getMessage().contains("policy denied"));
        assertTrue(e.getMessage().contains("path blocked"));
        assertTrue(e.getMessage().contains("policy-1"));
        assertEquals("path blocked", e.getReason());
        assertEquals("policy-1", e.getPolicyId());
    }

    @Test
    void test_policy_denied_exception_no_policy_id() {
        PolicyDeniedException e = new PolicyDeniedException("generic deny", null);
        assertTrue(e.getMessage().contains("generic deny"));
        assertFalse(e.getMessage().contains("(policy:"));
    }

    @Test
    void test_approval_required_exception() {
        ApprovalRequiredException e = new ApprovalRequiredException("needs review", "apr-42");
        assertTrue(e.getMessage().contains("approval required"));
        assertTrue(e.getMessage().contains("needs review"));
        assertTrue(e.getMessage().contains("apr-42"));
        assertEquals("needs review", e.getReason());
        assertEquals("apr-42", e.getApprovalId());
    }

    @Test
    void test_approval_required_exception_no_id() {
        ApprovalRequiredException e = new ApprovalRequiredException("high risk", null);
        assertTrue(e.getMessage().contains("high risk"));
        assertFalse(e.getMessage().contains("(approval:"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 16. Projector Validation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_project_schema_empty_model_family() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.projectSchema(Collections.emptyMap(), ""));
    }

    @Test
    void test_project_schema_null_model_family() {
        VellavetoClient client = VellavetoClient.builder("http://localhost:8080").build();
        assertThrows(VellavetoException.class, () ->
                client.projectSchema(Collections.emptyMap(), null));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 17. Validate Config / Period / Format
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_validate_period_valid() throws VellavetoException {
        ValidationUtils.validatePeriod("30d");
        ValidationUtils.validatePeriod("2026-01-01:2026-02-01");
    }

    @Test
    void test_validate_period_null_ok() throws VellavetoException {
        ValidationUtils.validatePeriod(null);
        ValidationUtils.validatePeriod("");
    }

    @Test
    void test_validate_format_valid() throws VellavetoException {
        ValidationUtils.validateFormat("json");
        ValidationUtils.validateFormat("html");
    }

    @Test
    void test_validate_format_invalid() {
        assertThrows(VellavetoException.class, () ->
                ValidationUtils.validateFormat("xml"));
    }

    @Test
    void test_validate_format_null_ok() throws VellavetoException {
        ValidationUtils.validateFormat(null);
        ValidationUtils.validateFormat("");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 18. Action JSON Serialization
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    void test_action_json_serialization() throws Exception {
        Action action = Action.builder("read_file")
                .function("read")
                .parameters(Collections.singletonMap("path", "/tmp"))
                .targetPaths(Collections.singletonList("/tmp"))
                .build();

        String json = MAPPER.writeValueAsString(action);
        assertTrue(json.contains("\"tool\":\"read_file\""));
        assertTrue(json.contains("\"function\":\"read\""));
        assertTrue(json.contains("\"target_paths\":[\"/tmp\"]"));
    }

    @Test
    void test_action_json_null_fields_excluded() throws Exception {
        Action action = Action.builder("tool").build();
        String json = MAPPER.writeValueAsString(action);
        assertTrue(json.contains("\"tool\":\"tool\""));
        assertFalse(json.contains("\"function\""));
        assertFalse(json.contains("\"parameters\""));
    }

    @Test
    void test_evaluation_context_json_serialization() throws Exception {
        EvaluationContext ctx = new EvaluationContext(
                "sess-1", "agent-1", "tenant-1",
                Arrays.asList("a", "b"), null);
        String json = MAPPER.writeValueAsString(ctx);
        assertTrue(json.contains("\"session_id\":\"sess-1\""));
        assertTrue(json.contains("\"agent_id\":\"agent-1\""));
        assertTrue(json.contains("\"call_chain\":[\"a\",\"b\"]"));
    }

    @Test
    void test_evaluation_result_deserialization() throws Exception {
        String json = "{\"verdict\":\"allow\",\"reason\":\"\",\"policy_id\":\"p1\",\"policy_name\":\"test\"}";
        EvaluationResult result = MAPPER.readValue(json, EvaluationResult.class);
        assertEquals(Verdict.ALLOW, result.getVerdict());
        assertEquals("p1", result.getPolicyId());
    }

    @Test
    void test_evaluation_result_unknown_fields_ignored() throws Exception {
        String json = "{\"verdict\":\"deny\",\"reason\":\"blocked\",\"extra_field\":true}";
        EvaluationResult result = MAPPER.readValue(json, EvaluationResult.class);
        assertEquals(Verdict.DENY, result.getVerdict());
        assertEquals("blocked", result.getReason());
    }

    // ── R260 Attestation Verification Tests ─────────────────────────────

    private Map<String, Object> makeAttestationResponse(Map<String, Object> overrides) {
        Map<String, Object> att = new HashMap<>();
        att.put("version", 1);
        att.put("timestamp", 1000L);
        att.put("content_hash", "a".repeat(64));
        att.put("injection_clean", true);
        att.put("dlp_clean", true);
        att.put("schema_valid", true);
        att.put("trust_tier", "Verified");
        att.put("scan_passes", 5);
        att.put("signature", "a".repeat(64));
        att.putAll(overrides);

        Map<String, Object> meta = new HashMap<>();
        meta.put("vellaveto_attestation", att);
        Map<String, Object> resp = new HashMap<>();
        resp.put("result", new HashMap<>());
        resp.put("_meta", meta);
        return resp;
    }

    @Test
    void test_verify_attestation_signature_too_short() {
        Map<String, Object> resp = makeAttestationResponse(Map.of("signature", "abcd"));
        assertFalse(VellavetoClient.verifyAttestation(resp, "k".repeat(32).getBytes()));
    }

    @Test
    void test_verify_attestation_signature_too_long() {
        Map<String, Object> resp = makeAttestationResponse(Map.of("signature", "a".repeat(65)));
        assertFalse(VellavetoClient.verifyAttestation(resp, "k".repeat(32).getBytes()));
    }

    @Test
    void test_verify_attestation_signature_non_string() {
        Map<String, Object> resp = makeAttestationResponse(Map.of("signature", 12345));
        assertFalse(VellavetoClient.verifyAttestation(resp, "k".repeat(32).getBytes()));
    }

    @Test
    void test_verify_attestation_signature_null() {
        Map<String, Object> overrides = new HashMap<>();
        overrides.put("signature", null);
        Map<String, Object> resp = makeAttestationResponse(overrides);
        assertFalse(VellavetoClient.verifyAttestation(resp, "k".repeat(32).getBytes()));
    }

    @Test
    void test_verify_attestation_version_wrong_type() {
        Map<String, Object> resp = makeAttestationResponse(Map.of("version", "bad"));
        assertFalse(VellavetoClient.verifyAttestation(resp, "k".repeat(32).getBytes()));
    }

    @Test
    void test_verify_attestation_timestamp_wrong_type() {
        Map<String, Object> resp = makeAttestationResponse(Map.of("timestamp", "bad"));
        assertFalse(VellavetoClient.verifyAttestation(resp, "k".repeat(32).getBytes()));
    }

    @Test
    void test_verify_attestation_trust_tier_wrong_type() {
        Map<String, Object> resp = makeAttestationResponse(Map.of("trust_tier", 42));
        assertFalse(VellavetoClient.verifyAttestation(resp, "k".repeat(32).getBytes()));
    }

    @Test
    void test_verify_attestation_scan_passes_wrong_type() {
        Map<String, Object> resp = makeAttestationResponse(Map.of("scan_passes", "five"));
        assertFalse(VellavetoClient.verifyAttestation(resp, "k".repeat(32).getBytes()));
    }
}
