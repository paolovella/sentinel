package com.vellaveto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Client-side secret redaction for action parameters.
 *
 * <p>Detects sensitive keys (e.g., "password", "api_key", "secret") and sensitive
 * values (e.g., strings matching common secret patterns) and replaces them with
 * "[REDACTED]".</p>
 *
 * <p>SECURITY: Prevents accidental leakage of secrets in audit logs, error messages,
 * and debug output.</p>
 */
public class ParameterRedactor {

    private static final String REDACTED = "[REDACTED]";
    private static final int MAX_REDACT_DEPTH = 10;

    private static final Set<String> DEFAULT_SENSITIVE_KEYS;
    static {
        Set<String> keys = new HashSet<>(Arrays.asList(
                "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
                "api_secret", "apisecret", "access_token", "accesstoken", "refresh_token",
                "refreshtoken", "private_key", "privatekey", "credential", "credentials",
                "authorization", "auth_token", "authtoken", "bearer", "client_secret",
                "clientsecret", "connection_string", "connectionstring", "database_url",
                "databaseurl", "db_password", "dbpassword", "encryption_key", "encryptionkey",
                "signing_key", "signingkey", "ssh_key", "sshkey"
        ));
        DEFAULT_SENSITIVE_KEYS = Collections.unmodifiableSet(keys);
    }

    // Patterns for values that look like secrets
    private static final Pattern BEARER_TOKEN = Pattern.compile("^Bearer\\s+\\S+", Pattern.CASE_INSENSITIVE);
    private static final Pattern BASE64_SECRET = Pattern.compile("^[A-Za-z0-9+/]{32,}={0,3}$");
    private static final Pattern HEX_SECRET = Pattern.compile("^[0-9a-fA-F]{32,}$");

    private final Set<String> sensitiveKeys;

    public ParameterRedactor() {
        this.sensitiveKeys = DEFAULT_SENSITIVE_KEYS;
    }

    public ParameterRedactor(Set<String> additionalKeys) {
        Set<String> merged = new HashSet<>(DEFAULT_SENSITIVE_KEYS);
        for (String key : additionalKeys) {
            merged.add(key.toLowerCase());
        }
        this.sensitiveKeys = Collections.unmodifiableSet(merged);
    }

    /**
     * Returns true if the key name suggests a sensitive value.
     */
    public boolean isSensitiveKey(String key) {
        if (key == null) return false;
        return sensitiveKeys.contains(key.toLowerCase());
    }

    /**
     * Returns true if the value matches common secret patterns.
     */
    public boolean isSensitiveValue(Object value) {
        if (!(value instanceof String)) return false;
        String s = (String) value;
        if (s.length() < 16) return false;
        if (BEARER_TOKEN.matcher(s).matches()) return true;
        if (BASE64_SECRET.matcher(s).matches()) return true;
        if (HEX_SECRET.matcher(s).matches()) return true;
        return false;
    }

    /**
     * Redacts sensitive entries from a parameter map.
     * Returns a new map with sensitive values replaced by "[REDACTED]".
     * SECURITY: Recurses into nested Maps and Lists up to depth 10 to prevent
     * secrets hiding in nested structures. Matches TypeScript SDK parity.
     */
    public Map<String, Object> redact(Map<String, Object> parameters) {
        if (parameters == null) return null;
        return redactMap(parameters, 0);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> redactMap(Map<String, Object> parameters, int depth) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            if (isSensitiveKey(entry.getKey()) || isSensitiveValue(entry.getValue())) {
                result.put(entry.getKey(), REDACTED);
            } else if (depth >= MAX_REDACT_DEPTH) {
                // Beyond max depth, redact all values to prevent unbounded recursion
                result.put(entry.getKey(), REDACTED);
            } else if (entry.getValue() instanceof Map) {
                result.put(entry.getKey(),
                        redactMap((Map<String, Object>) entry.getValue(), depth + 1));
            } else if (entry.getValue() instanceof List) {
                result.put(entry.getKey(),
                        redactList((List<Object>) entry.getValue(), depth + 1));
            } else {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private List<Object> redactList(List<Object> items, int depth) {
        if (depth >= MAX_REDACT_DEPTH) {
            List<Object> result = new ArrayList<>(items.size());
            for (int i = 0; i < items.size(); i++) {
                result.add(REDACTED);
            }
            return result;
        }
        List<Object> result = new ArrayList<>(items.size());
        for (Object item : items) {
            if (item instanceof Map) {
                result.add(redactMap((Map<String, Object>) item, depth + 1));
            } else if (item instanceof List) {
                result.add(redactList((List<Object>) item, depth + 1));
            } else {
                result.add(item);
            }
        }
        return result;
    }
}
