package vellaveto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// maxResponseBodySize limits the maximum response body size to prevent OOM
// from malicious or misconfigured servers.
// SECURITY (FIND-R46-GO-001): Without this limit, io.ReadAll on an unbounded
// response body allows a malicious server to cause OOM.
const maxResponseBodySize = 10 * 1024 * 1024 // 10 MB

// SECURITY (FIND-R56-SDK-003): Aligned default timeout across all SDKs (Python/Go/TS = 10s).
const defaultTimeout = 10 * time.Second

// Default retry parameters for transient HTTP failures (FIND-R58-CFG-008).
const defaultMaxRetries = 3
const defaultInitialBackoff = 500 * time.Millisecond

// tenantIDPattern validates tenant IDs: 1-64 chars, alphanumeric + hyphen + underscore only.
var tenantIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// retryableStatus returns true for HTTP status codes that should be retried.
func retryableStatus(code int) bool {
	return code == 429 || code == 502 || code == 503 || code == 504
}

// isRetryableError determines whether a network error is transient and safe to retry.
//
// SECURITY (FIND-R213-001): Non-retryable errors — TLS certificate failures, DNS
// resolution errors, and context cancellation — must not be retried, because:
// - TLS errors indicate an untrusted server and retrying won't fix it.
// - DNS errors indicate a misconfigured hostname; retrying adds load but no value.
// - Context cancellation/deadline means the caller has given up.
// Only connection-level transient errors (timeout, connection refused/reset) are retried.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	// Never retry context cancellation or deadline exceeded.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Never retry TLS errors — they indicate certificate/handshake issues.
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return false
	}
	// Also catch tls.RecordHeaderError and other TLS-related errors by checking
	// the error chain for any tls-prefixed error message.
	var tlsRecordErr tls.RecordHeaderError
	if errors.As(err, &tlsRecordErr) {
		return false
	}
	// Never retry DNS resolution failures.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return false
	}
	// Retry on net.Error with Timeout() == true (connection timeouts, etc.)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Retry on connection-level errors (connection refused, reset, etc.)
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	// For url.Error (wraps transport errors), inspect the inner error.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isRetryableError(urlErr.Err)
	}
	// Default: do not retry unknown errors (fail-closed).
	return false
}

// jitteredBackoff returns a randomized duration between 0 and maxBackoff (full jitter).
//
// SECURITY (FIND-R213-002): Full jitter prevents thundering herd when multiple
// clients retry simultaneously against the same server after a transient failure.
func jitteredBackoff(maxBackoff time.Duration) time.Duration {
	if maxBackoff <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(maxBackoff)))
}

// Client is the Vellaveto API client.
//
// SECURITY (FIND-R46-GO-006): Thread safety — Client is safe for concurrent use
// after construction. All fields are read-only after NewClient returns: baseURL,
// apiKey, and headers are never mutated. httpClient is shared but http.Client is
// documented as safe for concurrent use. No mutexes are needed because there is
// no mutable state post-construction.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	headers    map[string]string
	// failClosed causes Evaluate to return a Deny verdict instead of an error
	// when the server is unreachable. This makes the client fail-closed without
	// requiring error handling in application code.
	failClosed bool
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the API key for authentication.
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

// minTimeout is the minimum allowed timeout (100ms).
// SECURITY (FIND-R80-001): Zero or very small timeouts cause immediate cancellation.
const minTimeout = 100 * time.Millisecond

// maxTimeout is the maximum allowed timeout (5 minutes / 300s).
// SECURITY (FIND-R80-001): Parity with TypeScript SDK [100ms, 300000ms].
const maxTimeout = 300 * time.Second

// WithTimeout sets the HTTP request timeout.
//
// SECURITY (FIND-R80-001): Clamps the duration to [100ms, 300s]. Values outside
// this range are silently clamped with a warning log, matching TypeScript SDK
// validation range [100, 300000] ms. Zero/negative durations would cause
// immediate request cancellation.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d < minTimeout {
			log.Printf("[vellaveto] WARNING: timeout %v below minimum %v, clamping to %v", d, minTimeout, minTimeout)
			d = minTimeout
		} else if d > maxTimeout {
			log.Printf("[vellaveto] WARNING: timeout %v above maximum %v, clamping to %v", d, maxTimeout, maxTimeout)
			d = maxTimeout
		}
		c.httpClient.Timeout = d
	}
}

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithHeaders adds custom headers to every request.
//
// SECURITY (FIND-R71-SDK-015): Validates headers for CRLF injection and blocks
// overrides of security-sensitive headers (content-type, authorization).
// Invalid headers are silently skipped to avoid breaking initialization.
func WithHeaders(h map[string]string) Option {
	return func(c *Client) {
		for k, v := range h {
			// SECURITY: Block CRLF injection in header keys and values.
			if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
				continue
			}
			// SECURITY: Block overriding security-sensitive headers.
			lower := strings.ToLower(k)
			if lower == "content-type" || lower == "authorization" {
				continue
			}
			c.headers[k] = v
		}
	}
}

// WithFailClosed makes Evaluate return a Deny verdict instead of an error
// when the Vellaveto server is unreachable. Without this, callers must handle
// connection errors explicitly; with it, the client automatically denies when
// enforcement is unavailable.
func WithFailClosed() Option {
	return func(c *Client) { c.failClosed = true }
}

// WithTenant sets the tenant ID for multi-tenancy support (Phase 44).
// The tenant ID is sent as X-Tenant-ID header on every request.
// Must be 1-64 chars, alphanumeric + hyphen + underscore only.
func WithTenant(tenant string) Option {
	return func(c *Client) {
		if len(tenant) == 0 || len(tenant) > 64 {
			log.Printf("[vellaveto] WARNING: tenant ID length %d out of range [1, 64], ignoring", len(tenant))
			return
		}
		if !tenantIDPattern.MatchString(tenant) {
			log.Printf("[vellaveto] WARNING: tenant ID %q contains invalid characters, ignoring", tenant)
			return
		}
		c.headers["X-Tenant-ID"] = tenant
	}
}

// NewClient creates a new Vellaveto API client.
//
// SECURITY (FIND-GAP-011): Validates that baseURL is a well-formed URL with
// http:// or https:// scheme and a non-empty host. Returns an error if invalid.
// SECURITY (FIND-R46-GO-004): Default HTTP client strips Authorization header
// on cross-domain redirects to prevent API key leakage.
func NewClient(baseURL string, opts ...Option) (*Client, error) {
	trimmed := strings.TrimRight(baseURL, "/")
	if trimmed == "" {
		return nil, fmt.Errorf("vellaveto: baseURL must not be empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("vellaveto: invalid baseURL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("vellaveto: baseURL must use http:// or https:// scheme, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("vellaveto: baseURL must have a host")
	}
	// SECURITY (FIND-R67-SDK-003): Reject URLs containing credentials (userinfo).
	// Credentials in the URL leak into logs, HTTP headers, and error messages.
	if parsed.User != nil {
		return nil, fmt.Errorf("vellaveto: baseURL must not contain credentials (userinfo)")
	}

	c := &Client{
		baseURL: trimmed,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("vellaveto: stopped after 10 redirects")
				}
				// SECURITY (FIND-R101-005): Reject redirects to non-HTTP(S) schemes.
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("vellaveto: redirect to unsupported scheme %q", req.URL.Scheme)
				}
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					// Cross-domain redirect: strip Authorization to prevent API key leak.
					req.Header.Del("Authorization")
				}
				return nil
			},
		},
		headers: make(map[string]string),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// String returns a human-readable representation of the client with the API key redacted.
// SECURITY (FIND-R56-SDK-005): Prevents API key leakage in logs and debug output.
func (c *Client) String() string {
	return fmt.Sprintf("vellaveto.Client{baseURL: %q, apiKey: ***}", c.baseURL)
}

// do executes a single HTTP request and returns the response body.
// NOTE (FIND-R67-SDK-GO-002): This method does not retry. Use doJSON for
// automatic retry with exponential backoff on transient failures (429/502/503/504).
func (c *Client) do(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("vellaveto: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("vellaveto: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("vellaveto: request failed: %w", err)
	}
	defer resp.Body.Close()

	// SECURITY (FIND-R46-GO-001): Limit response body size to prevent OOM DoS.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("vellaveto: read response: %w", err)
	}
	if int64(len(respBody)) > maxResponseBodySize {
		return nil, resp.StatusCode, fmt.Errorf("vellaveto: response body exceeds %d byte limit", maxResponseBodySize)
	}

	return respBody, resp.StatusCode, nil
}

// maxErrorBodyDisplay is the maximum number of bytes from a response body
// included in error messages to prevent information disclosure.
// SECURITY (FIND-R46-GO-005): Full response bodies in errors can leak
// sensitive server internals (stack traces, config, internal paths).
const maxErrorBodyDisplay = 256

// doJSON executes a request with retry for transient HTTP failures.
//
// SECURITY (FIND-R58-CFG-008): Retries on 429, 502, 503, 504 with
// exponential backoff matching Python SDK parity.
// SECURITY (FIND-R213-001): Only retries transient network errors (timeouts,
// connection refused/reset). Non-retryable errors (TLS, DNS, context
// cancellation) are returned immediately.
// SECURITY (FIND-R213-002): Uses full jitter on backoff to prevent thundering herd.
func (c *Client) doJSON(ctx context.Context, method, path string, body interface{}, dst interface{}) error {
	backoff := defaultInitialBackoff
	var lastErr error

	for attempt := 0; attempt <= defaultMaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(jitteredBackoff(backoff)):
			}
			backoff *= 2
		}

		respBody, status, err := c.do(ctx, method, path, body)
		if err != nil {
			// SECURITY (FIND-R213-001): Only retry transient network errors.
			// TLS, DNS, and context cancellation errors are not retryable.
			if !isRetryableError(err) {
				return err
			}
			lastErr = err
			continue
		}
		if status >= 200 && status < 300 {
			if dst != nil {
				if err := json.Unmarshal(respBody, dst); err != nil {
					return fmt.Errorf("vellaveto: decode response: %w", err)
				}
			}
			return nil
		}
		// SECURITY (FIND-R46-GO-005): Truncate response body in error messages.
		msg := string(respBody)
		if len(msg) > maxErrorBodyDisplay {
			msg = msg[:maxErrorBodyDisplay] + "...(truncated)"
		}
		lastErr = &VellavetoError{
			Message:    fmt.Sprintf("unexpected status: %s", msg),
			StatusCode: status,
		}
		if !retryableStatus(status) {
			return lastErr
		}
	}
	return lastErr
}

// Health checks the Vellaveto server health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.doJSON(ctx, http.MethodGet, "/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// parseVerdict handles both string and object verdict forms from the API.
// String: {"verdict": "allow"}
// Object: {"verdict": {"Deny": {"reason": "..."}}}
func parseVerdictField(raw json.RawMessage) (Verdict, string) {
	// Try string form first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return ParseVerdict(s), ""
	}

	// Try object form: {"Allow": {}} or {"Deny": {"reason": "..."}}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for key, val := range obj {
			v := ParseVerdict(key)
			var inner struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(val, &inner)
			return v, inner.Reason
		}
	}

	return VerdictDeny, "" // fail-closed
}

// evaluateRaw is the internal raw response struct for verdict parsing.
type evaluateRaw struct {
	Verdict    json.RawMessage        `json:"verdict"`
	Reason     string                 `json:"reason,omitempty"`
	PolicyID   string                 `json:"policy_id,omitempty"`
	PolicyName string                 `json:"policy_name,omitempty"`
	ApprovalID string                 `json:"approval_id,omitempty"`
	Trace      map[string]interface{} `json:"trace,omitempty"`
}

// Evaluate sends an action to the policy engine for evaluation.
//
// The server expects Action fields flattened at the root level of the JSON body
// (not nested under an "action" key) because the Rust server uses #[serde(flatten)].
// The trace flag is passed as a query parameter (?trace=true).
//
// SECURITY (FIND-R72-SDK-001): Retries on 429, 502, 503, 504 with exponential
// backoff (500ms, 1s, 2s) matching doJSON() parity. Previous implementation used
// c.do() directly without retry, unlike all other methods that use doJSON().
func (c *Client) Evaluate(ctx context.Context, action Action, evalCtx *EvaluationContext, trace bool) (*EvaluationResult, error) {
	// SECURITY (FIND-R54-SDK-008): Validate action fields before sending to server.
	if err := action.Validate(); err != nil {
		return nil, err
	}
	// SECURITY (FIND-R101-004): Validate parameters size.
	if err := validateParameters(action.Parameters); err != nil {
		return nil, err
	}
	// SECURITY (FIND-R101-003): Validate evaluation context bounds and chars.
	if evalCtx != nil {
		if err := evalCtx.Validate(); err != nil {
			return nil, err
		}
	}

	reqBody := EvaluateRequest{
		Tool:          action.Tool,
		Function:      action.Function,
		Parameters:    action.Parameters,
		TargetPaths:   action.TargetPaths,
		TargetDomains: action.TargetDomains,
		ResolvedIPs:   action.ResolvedIPs,
		Context:       evalCtx,
	}

	path := "/api/evaluate"
	if trace {
		path += "?trace=true"
	}

	backoff := defaultInitialBackoff
	var lastErr error

	for attempt := 0; attempt <= defaultMaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(jitteredBackoff(backoff)):
			}
			backoff *= 2
		}

		respBody, status, err := c.do(ctx, http.MethodPost, path, reqBody)
		if err != nil {
			// SECURITY (FIND-R213-001): Only retry transient network errors.
			if !isRetryableError(err) {
				if c.failClosed {
					log.Printf("[vellaveto] server unreachable (fail_closed=true), denying: %v", err)
					return &EvaluationResult{
						Verdict: VerdictDeny,
						Reason:  fmt.Sprintf("Server unreachable (fail-closed): %v", err),
					}, nil
				}
				return nil, err
			}
			lastErr = err
			continue
		}
		if status >= 200 && status < 300 {
			var raw evaluateRaw
			if err := json.Unmarshal(respBody, &raw); err != nil {
				return nil, fmt.Errorf("vellaveto: decode response: %w", err)
			}

			verdict, objReason := parseVerdictField(raw.Verdict)
			reason := raw.Reason
			if reason == "" {
				reason = objReason
			}

			return &EvaluationResult{
				Verdict:    verdict,
				Reason:     reason,
				PolicyID:   raw.PolicyID,
				PolicyName: raw.PolicyName,
				ApprovalID: raw.ApprovalID,
				Trace:      raw.Trace,
			}, nil
		}
		// SECURITY (FIND-R46-GO-005): Truncate response body in error messages.
		msg := string(respBody)
		if len(msg) > maxErrorBodyDisplay {
			msg = msg[:maxErrorBodyDisplay] + "...(truncated)"
		}
		lastErr = &VellavetoError{
			Message:    fmt.Sprintf("unexpected status: %s", msg),
			StatusCode: status,
		}
		if !retryableStatus(status) {
			return nil, lastErr
		}
	}
	if c.failClosed && lastErr != nil {
		log.Printf("[vellaveto] server unreachable after retries (fail_closed=true), denying: %v", lastErr)
		return &EvaluationResult{
			Verdict: VerdictDeny,
			Reason:  fmt.Sprintf("Server unreachable (fail-closed): %v", lastErr),
		}, nil
	}
	return nil, lastErr
}

// EvaluateOrError is like Evaluate but returns typed errors for Deny and RequireApproval verdicts.
// On Allow, nil is returned and the EvaluationResult is discarded. Use Evaluate directly
// if you need access to the full result (policy_id, trace, etc.) on Allow verdicts.
func (c *Client) EvaluateOrError(ctx context.Context, action Action, evalCtx *EvaluationContext) error {
	result, err := c.Evaluate(ctx, action, evalCtx, false)
	if err != nil {
		return err
	}
	switch result.Verdict {
	case VerdictAllow:
		return nil
	case VerdictDeny:
		return &PolicyDeniedError{Reason: result.Reason, PolicyID: result.PolicyID}
	case VerdictRequireApproval:
		return &ApprovalRequiredError{Reason: result.Reason, ApprovalID: result.ApprovalID}
	default:
		return &PolicyDeniedError{Reason: "unknown verdict"} // fail-closed
	}
}

// ListPolicies returns all loaded policies.
func (c *Client) ListPolicies(ctx context.Context) ([]PolicySummary, error) {
	var policies []PolicySummary
	if err := c.doJSON(ctx, http.MethodGet, "/api/policies", nil, &policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// ReloadPoliciesResponse is the response from a policy reload operation.
type ReloadPoliciesResponse struct {
	Count   int    `json:"count,omitempty"`
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

// ReloadPolicies triggers a policy reload on the server and returns the server response.
// SECURITY (FIND-GAP-016): Captures and returns the server response body so callers
// can verify the reload was successful and inspect the reloaded policy count.
func (c *Client) ReloadPolicies(ctx context.Context) (*ReloadPoliciesResponse, error) {
	var resp ReloadPoliciesResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/policies/reload", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Simulate evaluates an action with full trace information.
//
// SECURITY (FIND-R80-002): Validates action fields before sending, matching
// Evaluate() parity.
// SECURITY (FIND-R115-060): Validates parameters size and context bounds,
// matching Evaluate() parity. Without this, oversized payloads or malicious
// context fields bypass client-side guards via the simulate path.
func (c *Client) Simulate(ctx context.Context, action Action, evalCtx *EvaluationContext) (*SimulateResponse, error) {
	if err := action.Validate(); err != nil {
		return nil, err
	}
	// SECURITY (FIND-R115-060): Validate parameters size — parity with Evaluate().
	if err := validateParameters(action.Parameters); err != nil {
		return nil, err
	}
	// SECURITY (FIND-R115-060): Validate evaluation context — parity with Evaluate().
	if evalCtx != nil {
		if err := evalCtx.Validate(); err != nil {
			return nil, err
		}
	}
	reqBody := SimulateRequest{
		Action:  action,
		Context: evalCtx,
	}
	var resp SimulateResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/simulator/evaluate", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// BatchEvaluate evaluates multiple actions in a single request.
//
// SECURITY (FIND-R80-002): Validates all action fields before sending, matching
// Evaluate() parity.
// SECURITY (FIND-R115-061): Validates parameters size per action, matching
// Evaluate() parity. Without this, N actions each near 512KB bypass the
// client-side parameters size guard.
func (c *Client) BatchEvaluate(ctx context.Context, actions []Action, policyConfig map[string]interface{}) (*BatchResponse, error) {
	for i := range actions {
		if err := actions[i].Validate(); err != nil {
			return nil, fmt.Errorf("vellaveto: action[%d]: %w", i, err)
		}
		// SECURITY (FIND-R115-061): Validate parameters size — parity with Evaluate().
		if err := validateParameters(actions[i].Parameters); err != nil {
			return nil, fmt.Errorf("vellaveto: action[%d]: %w", i, err)
		}
	}
	reqBody := BatchRequest{
		Actions:      actions,
		PolicyConfig: policyConfig,
	}
	var resp BatchResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/simulator/batch", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ValidateConfig validates a policy configuration.
func (c *Client) ValidateConfig(ctx context.Context, config map[string]interface{}, strict bool) (*ValidateResponse, error) {
	reqBody := ValidateRequest{
		Config: config,
		Strict: strict,
	}
	var resp ValidateResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/simulator/validate", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DiffConfigs compares two policy configurations.
func (c *Client) DiffConfigs(ctx context.Context, before, after map[string]interface{}) (*DiffResponse, error) {
	reqBody := DiffRequest{
		Before: before,
		After:  after,
	}
	var resp DiffResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/simulator/diff", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListPendingApprovals returns all pending approval requests.
func (c *Client) ListPendingApprovals(ctx context.Context) ([]Approval, error) {
	var approvals []Approval
	if err := c.doJSON(ctx, http.MethodGet, "/api/approvals/pending", nil, &approvals); err != nil {
		return nil, err
	}
	return approvals, nil
}

// maxApprovalIDLength is the maximum allowed length for an approval ID.
const maxApprovalIDLength = 256

// isUnicodeFormatChar returns true if the rune is a Unicode format character
// that can be used for invisible text manipulation attacks.
// SECURITY (FIND-R80-003): Covers zero-width chars, bidi overrides, BOM,
// interlinear annotation anchors, and other format characters.
// SECURITY (FIND-R110-SDK-003): Extended to include U+2028-U+202F, which covers
// U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR, and the broader bidi
// embedding controls (U+202A-U+202E). The range 0x2028-0x202F supersedes the
// old 0x202A-0x202E range, so the narrower check is removed.
func isUnicodeFormatChar(r rune) bool {
	// Soft hyphen: U+00AD
	// SECURITY (FIND-R157-002): Parity with Rust canonical is_unicode_format_char().
	if r == 0x00AD {
		return true
	}
	// Zero-width and joining chars: U+200B-U+200F
	if r >= 0x200B && r <= 0x200F {
		return true
	}
	// Line/paragraph separators + bidi embedding controls: U+2028-U+202F
	// (supersedes old U+202A-U+202E range — 2028-202F is a strict superset)
	if r >= 0x2028 && r <= 0x202F {
		return true
	}
	// Word joiner and invisible chars: U+2060-U+2069
	if r >= 0x2060 && r <= 0x2069 {
		return true
	}
	// BOM / zero-width no-break space: U+FEFF
	if r == 0xFEFF {
		return true
	}
	// Interlinear annotation anchors: U+FFF9-U+FFFB
	if r >= 0xFFF9 && r <= 0xFFFB {
		return true
	}
	// TAG characters: U+E0001-U+E007F
	// SECURITY (FIND-R157-002): Parity with Rust canonical is_unicode_format_char().
	if r >= 0xE0001 && r <= 0xE007F {
		return true
	}
	return false
}

// validateApprovalID checks that an approval ID is non-empty, within length
// bounds, and contains no control or Unicode format characters.
// SECURITY (FIND-R54-SDK-003): Prevents empty/oversized/malicious approval IDs.
// SECURITY (FIND-R80-003): Also rejects Unicode format characters (zero-width,
// bidi overrides, BOM, etc.) that can be used for invisible text manipulation.
func validateApprovalID(id string) error {
	if id == "" {
		return fmt.Errorf("vellaveto: approval ID must not be empty")
	}
	if len(id) > maxApprovalIDLength {
		return fmt.Errorf("vellaveto: approval ID exceeds max length %d", maxApprovalIDLength)
	}
	for _, c := range id {
		if c < ' ' || (c >= 0x7F && c <= 0x9F) {
			return fmt.Errorf("vellaveto: approval ID contains control characters")
		}
		if isUnicodeFormatChar(c) {
			return fmt.Errorf("vellaveto: approval ID contains Unicode format characters")
		}
	}
	return nil
}

// resolveBody is the JSON body for approve/deny requests.
// SECURITY (IMP-R212-002): SDK parity with Python resolve_approval().
type resolveBody struct {
	Reason string `json:"reason,omitempty"`
}

// validateReason validates the optional reason string for approval resolution.
// SECURITY (IMP-R212-002): Parity with Python/TS SDK and server-side validation.
func validateReason(reason string) error {
	if reason == "" {
		return nil
	}
	// SECURITY (FIND-R218-008): Go len() measures bytes, matching server's Rust str::len().
	if len(reason) > 4096 {
		return fmt.Errorf("vellaveto: reason exceeds maximum length (4096 bytes, got %d)", len(reason))
	}
	for _, c := range reason {
		if c < ' ' || (c >= 0x7F && c <= 0x9F) {
			return fmt.Errorf("vellaveto: reason contains control characters")
		}
		if isUnicodeFormatChar(c) {
			return fmt.Errorf("vellaveto: reason contains Unicode format characters")
		}
	}
	return nil
}

// ApproveApproval approves a pending approval by ID.
// SECURITY (FIND-R46-GO-002): URL-encode the approval ID to prevent path injection.
// SECURITY (FIND-R54-SDK-003): Validate approval ID format before sending.
// SECURITY (IMP-R212-002): Optional reason parameter for audit trail.
func (c *Client) ApproveApproval(ctx context.Context, id string, reason ...string) error {
	if err := validateApprovalID(id); err != nil {
		return err
	}
	var body interface{}
	if len(reason) > 0 && reason[0] != "" {
		if err := validateReason(reason[0]); err != nil {
			return err
		}
		body = resolveBody{Reason: reason[0]}
	}
	return c.doJSON(ctx, http.MethodPost, "/api/approvals/"+url.PathEscape(id)+"/approve", body, nil)
}

// DenyApproval denies a pending approval by ID.
// SECURITY (FIND-R46-GO-002): URL-encode the approval ID to prevent path injection.
// SECURITY (FIND-R54-SDK-003): Validate approval ID format before sending.
// SECURITY (IMP-R212-002): Optional reason parameter for audit trail.
func (c *Client) DenyApproval(ctx context.Context, id string, reason ...string) error {
	if err := validateApprovalID(id); err != nil {
		return err
	}
	var body interface{}
	if len(reason) > 0 && reason[0] != "" {
		if err := validateReason(reason[0]); err != nil {
			return err
		}
		body = resolveBody{Reason: reason[0]}
	}
	return c.doJSON(ctx, http.MethodPost, "/api/approvals/"+url.PathEscape(id)+"/deny", body, nil)
}

// maxDiscoverResults is the maximum allowed value for maxResults in Discover().
// SECURITY (FIND-R110-SDK-002): Prevents unbounded result set requests.
const maxDiscoverResults = 20

// maxDiscoverQueryLen is the maximum allowed length for a discovery query string.
// SECURITY (FIND-R113-002): Aligned with Python/TS SDKs at 1024 (was 4096).
// Prevents oversized query strings from causing OOM or excessive processing on
// the server.
const maxDiscoverQueryLen = 1024

// Discover searches the tool discovery index for tools matching a query.
// SECURITY (FIND-R54-SDK-017): Validates query is non-empty before sending.
// SECURITY (FIND-R110-SDK-002): Validates maxResults in [1, 20] and tokenBudget >= 0.
// SECURITY (FIND-R113-002): Validates query length <= 1024 characters.
func (c *Client) Discover(ctx context.Context, query string, maxResults int, tokenBudget *int) (*DiscoveryResult, error) {
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("vellaveto: discovery query must not be empty")
	}
	if len(query) > maxDiscoverQueryLen {
		return nil, fmt.Errorf("vellaveto: discovery query exceeds max length (%d), got %d", maxDiscoverQueryLen, len(query))
	}
	if maxResults < 1 || maxResults > maxDiscoverResults {
		return nil, fmt.Errorf("vellaveto: maxResults must be in [1, %d], got %d", maxDiscoverResults, maxResults)
	}
	if tokenBudget != nil && *tokenBudget < 0 {
		return nil, fmt.Errorf("vellaveto: tokenBudget must be non-negative")
	}
	reqBody := DiscoverRequest{
		Query:       query,
		MaxResults:  maxResults,
		TokenBudget: tokenBudget,
	}
	var resp DiscoveryResult
	if err := c.doJSON(ctx, http.MethodPost, "/api/discovery/search", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DiscoveryStats returns statistics about the tool discovery index.
func (c *Client) DiscoveryStats(ctx context.Context) (*DiscoveryIndexStats, error) {
	var resp DiscoveryIndexStats
	if err := c.doJSON(ctx, http.MethodGet, "/api/discovery/index/stats", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DiscoveryReindex triggers a full rebuild of the IDF weights.
func (c *Client) DiscoveryReindex(ctx context.Context) (*DiscoveryReindexResponse, error) {
	var resp DiscoveryReindexResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/discovery/reindex", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// validDiscoverySensitivities is the set of accepted sensitivity filter values.
var validDiscoverySensitivities = map[string]struct{}{
	"low":    {},
	"medium": {},
	"high":   {},
}

// maxDiscoveryServerIDLen is the maximum length for the server_id filter parameter.
// SECURITY (FIND-R111-009): Bounds the query parameter to prevent OOM and log injection.
const maxDiscoveryServerIDLen = 256

// DiscoveryTools lists all indexed tools, optionally filtered by server ID and sensitivity.
// SECURITY (FIND-R46-GO-003): Use url.Values for proper URL encoding of query parameters.
// SECURITY (FIND-R111-009): Validates serverID and sensitivity parameters. Pass empty
// strings to omit filters entirely.
func (c *Client) DiscoveryTools(ctx context.Context, serverID, sensitivity string) (*DiscoveryToolsResponse, error) {
	if serverID != "" {
		if len(serverID) > maxDiscoveryServerIDLen {
			return nil, fmt.Errorf("vellaveto: serverID exceeds maximum length (%d), got %d", maxDiscoveryServerIDLen, len(serverID))
		}
		for _, r := range serverID {
			if r < ' ' || (r >= 0x7F && r <= 0x9F) {
				return nil, fmt.Errorf("vellaveto: serverID contains control characters")
			}
			// SECURITY (FIND-R157-002): Reject Unicode format characters (zero-width,
			// bidi overrides, soft hyphen, TAG chars). Parity with approval ID and
			// agent ID validation.
			if isUnicodeFormatChar(r) {
				return nil, fmt.Errorf("vellaveto: serverID contains Unicode format characters")
			}
		}
	}
	if sensitivity != "" {
		if _, ok := validDiscoverySensitivities[sensitivity]; !ok {
			return nil, fmt.Errorf("vellaveto: sensitivity must be one of [low, medium, high], got %q", sensitivity)
		}
	}
	path := "/api/discovery/tools"
	q := url.Values{}
	if serverID != "" {
		q.Set("server_id", serverID)
	}
	if sensitivity != "" {
		q.Set("sensitivity", sensitivity)
	}
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var resp DiscoveryToolsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProjectorModels lists supported model families in the projector registry.
func (c *Client) ProjectorModels(ctx context.Context) (*ProjectorModelsResponse, error) {
	var resp ProjectorModelsResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/projector/models", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProjectSchema projects a canonical tool schema for a given model family.
// SECURITY (FIND-R55-SDK-007): Validates modelFamily is non-empty.
func (c *Client) ProjectSchema(ctx context.Context, schema CanonicalToolSchema, modelFamily string) (*ProjectorTransformResponse, error) {
	if strings.TrimSpace(modelFamily) == "" {
		return nil, fmt.Errorf("vellaveto: modelFamily must not be empty")
	}
	reqBody := ProjectorTransformRequest{
		Schema:      schema,
		ModelFamily: modelFamily,
	}
	var resp ProjectorTransformResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/projector/transform", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ZkStatus returns the current ZK audit scheduler status.
func (c *Client) ZkStatus(ctx context.Context) (*ZkSchedulerStatus, error) {
	var resp ZkSchedulerStatus
	if err := c.doJSON(ctx, http.MethodGet, "/api/zk-audit/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// maxZkProofsLimit is the maximum allowed value for limit in ZkProofs().
// SECURITY (FIND-R112-001): Prevents unbounded result set requests that could
// cause OOM on the server side.
const maxZkProofsLimit = 1000

// ZkProofs lists stored ZK batch proofs with pagination.
// SECURITY (FIND-R46-GO-003): Use url.Values for proper URL encoding of query parameters.
// SECURITY (FIND-R112-001): Validates limit in [1, 1000] and offset >= 0.
func (c *Client) ZkProofs(ctx context.Context, limit, offset int) (*ZkProofsResponse, error) {
	if limit < 1 || limit > maxZkProofsLimit {
		return nil, fmt.Errorf("vellaveto: ZkProofs: limit must be in [1, %d], got %d", maxZkProofsLimit, limit)
	}
	if offset < 0 {
		return nil, fmt.Errorf("vellaveto: ZkProofs: offset must be non-negative, got %d", offset)
	}
	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("offset", fmt.Sprintf("%d", offset))
	path := "/api/zk-audit/proofs?" + q.Encode()
	var resp ZkProofsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ZkVerify verifies a stored ZK batch proof by batch ID.
// SECURITY (FIND-R54-SDK-017): Validates batchID is non-empty before sending.
func (c *Client) ZkVerify(ctx context.Context, batchID string) (*ZkVerifyResult, error) {
	if strings.TrimSpace(batchID) == "" {
		return nil, fmt.Errorf("vellaveto: batchID must not be empty")
	}
	reqBody := ZkVerifyRequest{BatchID: batchID}
	var resp ZkVerifyResult
	if err := c.doJSON(ctx, http.MethodPost, "/api/zk-audit/verify", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ZkCommitments lists Pedersen commitments for audit entries in a sequence range.
// SECURITY (FIND-R46-GO-003): Use url.Values for proper URL encoding of query parameters.
// SECURITY (FIND-R111-008): Validate that from <= to. Without this check, callers
// can pass (from=100, to=0) which reaches the server and produces either an error
// or an unexpectedly empty result, making bugs harder to diagnose.
func (c *Client) ZkCommitments(ctx context.Context, from, to uint64) (*ZkCommitmentsResponse, error) {
	if from > to {
		return nil, fmt.Errorf("vellaveto: ZkCommitments: from (%d) must be <= to (%d)", from, to)
	}
	q := url.Values{}
	q.Set("from", fmt.Sprintf("%d", from))
	q.Set("to", fmt.Sprintf("%d", to))
	path := "/api/zk-audit/commitments?" + q.Encode()
	var resp ZkCommitmentsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// maxPeriodLength is the maximum allowed length for the period query parameter.
const maxPeriodLength = 32

// periodPattern validates period values: alphanumeric, dashes, and colons only.
// Covers ISO date ranges like "2026-01-01:2026-02-01" and shorthand like "30d".
var periodPattern = regexp.MustCompile(`^[a-zA-Z0-9\-:]+$`)

// Soc2AccessReview generates a SOC 2 Type II access review report.
// SECURITY (FIND-R46-GO-003): Use url.Values for proper URL encoding of query parameters.
func (c *Client) Soc2AccessReview(ctx context.Context, period, format, agentID string) (*AccessReviewReport, error) {
	if len(agentID) > 128 {
		return nil, &VellavetoError{Message: "agent_id exceeds max length (128)"}
	}
	// SECURITY (FIND-R67-SDK-GO-001): Validate format parameter.
	if format != "" && format != "json" && format != "html" {
		return nil, &VellavetoError{Message: fmt.Sprintf("format must be \"json\" or \"html\", got %q", format)}
	}
	// SECURITY (FIND-R80-004): Validate period parameter to prevent injection via query string.
	// Parity with TypeScript SDK validation.
	if period != "" {
		if len(period) > maxPeriodLength {
			return nil, &VellavetoError{Message: fmt.Sprintf("period exceeds max length (%d)", maxPeriodLength)}
		}
		if !periodPattern.MatchString(period) {
			return nil, &VellavetoError{Message: "period contains invalid characters: only alphanumeric, dashes, and colons are allowed"}
		}
	}
	// SECURITY (FIND-R55-SDK-005): Reject control chars. Parity with FederationTrustAnchors.
	for _, ch := range agentID {
		if ch < ' ' || (ch >= 0x7F && ch <= 0x9F) {
			return nil, &VellavetoError{Message: "agent_id contains control characters"}
		}
		// SECURITY (FIND-R80-003): Reject Unicode format characters.
		if isUnicodeFormatChar(ch) {
			return nil, &VellavetoError{Message: "agent_id contains Unicode format characters"}
		}
	}
	q := url.Values{}
	if period != "" {
		q.Set("period", period)
	}
	if format != "" {
		q.Set("format", format)
	}
	if agentID != "" {
		q.Set("agent_id", agentID)
	}
	path := "/api/compliance/soc2/access-review"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var resp AccessReviewReport
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FederationStatus returns the federation resolver status.
func (c *Client) FederationStatus(ctx context.Context) (*FederationStatusResponse, error) {
	var resp FederationStatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/federation/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FederationTrustAnchors returns configured federation trust anchors.
// orgID is optional; pass empty string to list all.
// SECURITY: Validates orgID length (max 128) and rejects control characters.
func (c *Client) FederationTrustAnchors(ctx context.Context, orgID string) (*FederationTrustAnchorsResponse, error) {
	if len(orgID) > 128 {
		return nil, &VellavetoError{Message: "org_id exceeds max length (128)"}
	}
	// SECURITY (FIND-R50-037): Catch DEL (0x7F) and C1 control chars (0x80-0x9F)
	// SECURITY (FIND-R80-003): Also reject Unicode format characters.
	for _, c := range orgID {
		if c < ' ' || (c >= 0x7F && c <= 0x9F) {
			return nil, &VellavetoError{Message: "org_id contains control characters"}
		}
		if isUnicodeFormatChar(c) {
			return nil, &VellavetoError{Message: "org_id contains Unicode format characters"}
		}
	}
	path := "/api/federation/trust-anchors"
	if orgID != "" {
		q := url.Values{}
		q.Set("org_id", orgID)
		path += "?" + q.Encode()
	}
	var resp FederationTrustAnchorsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OwaspAsiCoverage retrieves the OWASP Agentic Security Index coverage report.
func (c *Client) OwaspAsiCoverage(ctx context.Context) (*OwaspAsiCoverageResponse, error) {
	var resp OwaspAsiCoverageResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/compliance/owasp-agentic", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// evidencePackFrameworks is the allowlist of valid framework identifiers.
var evidencePackFrameworks = map[string]bool{
	"dora":      true,
	"nis2":      true,
	"iso42001":  true,
	"eu-ai-act": true,
}

// EvidencePack generates a compliance evidence pack for the specified framework.
// framework must be one of: "dora", "nis2", "iso42001", "eu-ai-act".
// format must be "json" or "html" (empty defaults to "json").
func (c *Client) EvidencePack(ctx context.Context, framework, format string) (*EvidencePack, error) {
	if framework == "" {
		return nil, &VellavetoError{Message: "framework must be a non-empty string"}
	}
	if !evidencePackFrameworks[framework] {
		return nil, &VellavetoError{Message: fmt.Sprintf("framework must be one of dora, nis2, iso42001, eu-ai-act, got %q", framework)}
	}
	if format != "" && format != "json" && format != "html" {
		return nil, &VellavetoError{Message: fmt.Sprintf("format must be \"json\" or \"html\", got %q", format)}
	}
	params := url.Values{}
	if format != "" && format != "json" {
		params.Set("format", format)
	}
	path := "/api/compliance/evidence-pack/" + url.PathEscape(framework)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	var resp EvidencePack
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EvidencePackStatus retrieves which evidence pack frameworks are available.
func (c *Client) EvidencePackStatus(ctx context.Context) (*EvidencePackStatus, error) {
	var resp EvidencePackStatus
	if err := c.doJSON(ctx, http.MethodGet, "/api/compliance/evidence-pack/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 50: Usage Metering & Billing
// ═══════════════════════════════════════════════════════════════════════

// UsageMetrics represents per-tenant usage counters for a billing period.
type UsageMetrics struct {
	TenantID           string `json:"tenant_id"`
	PeriodStart        string `json:"period_start"`
	PeriodEnd          string `json:"period_end"`
	Evaluations        uint64 `json:"evaluations"`
	EvaluationsAllowed uint64 `json:"evaluations_allowed"`
	EvaluationsDenied  uint64 `json:"evaluations_denied"`
	PoliciesCreated    uint64 `json:"policies_created"`
	ApprovalsProcessed uint64 `json:"approvals_processed"`
	AuditEntries       uint64 `json:"audit_entries"`
}

// QuotaStatus represents usage vs limits for a tenant.
type QuotaStatus struct {
	TenantID             string `json:"tenant_id"`
	EvaluationsUsed      uint64 `json:"evaluations_used"`
	EvaluationsLimit     uint64 `json:"evaluations_limit"`
	EvaluationsRemaining uint64 `json:"evaluations_remaining"`
	PoliciesUsed         uint64 `json:"policies_used"`
	PoliciesLimit        uint64 `json:"policies_limit"`
	PeriodStart          string `json:"period_start"`
	PeriodEnd            string `json:"period_end"`
	QuotaExceeded        bool   `json:"quota_exceeded"`
}

// UsageSummary represents historical usage across billing periods.
type UsageSummary struct {
	TenantID         string         `json:"tenant_id"`
	Periods          []UsageMetrics `json:"periods"`
	TotalEvaluations uint64         `json:"total_evaluations"`
}

func validateTenantID(tenantID string) error {
	if len(tenantID) == 0 || len(tenantID) > 64 {
		return fmt.Errorf("tenantID must be 1-64 characters, got %d", len(tenantID))
	}
	if !tenantIDPattern.MatchString(tenantID) {
		return fmt.Errorf("tenantID %q contains invalid characters", tenantID)
	}
	return nil
}

// Usage retrieves current-period usage metrics for a tenant.
func (c *Client) Usage(ctx context.Context, tenantID string) (*UsageMetrics, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}
	var resp UsageMetrics
	path := "/api/billing/usage/" + url.PathEscape(tenantID)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// QuotaStatus retrieves quota status (usage vs limits) for a tenant.
func (c *Client) QuotaStatus(ctx context.Context, tenantID string) (*QuotaStatus, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}
	var resp QuotaStatus
	path := "/api/billing/quotas/" + url.PathEscape(tenantID)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UsageHistory retrieves usage history across billing periods for a tenant.
func (c *Client) UsageHistory(ctx context.Context, tenantID string, periods int) (*UsageSummary, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}
	if periods < 1 || periods > 120 {
		return nil, fmt.Errorf("periods must be between 1 and 120, got %d", periods)
	}
	var resp UsageSummary
	path := fmt.Sprintf("/api/billing/usage/%s/history?periods=%d", url.PathEscape(tenantID), periods)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// VerifyAttestation verifies the proxy's content-bound attestation on a response.
//
// Returns true if the attestation HMAC is valid and the content hash matches
// the response body. Returns false if verification fails or no attestation is present.
func VerifyAttestation(response map[string]interface{}, hmacKey []byte) bool {
	metaRaw, ok := response["_meta"]
	if !ok {
		return false
	}
	meta, ok := metaRaw.(map[string]interface{})
	if !ok {
		return false
	}
	attRaw, ok := meta["vellaveto_attestation"]
	if !ok {
		return false
	}
	att, ok := attRaw.(map[string]interface{})
	if !ok {
		return false
	}

	// Verify content hash matches
	content := response["result"]
	if content == nil {
		content = response["error"]
	}
	canonical, err := json.Marshal(content)
	if err != nil {
		return false
	}
	h := sha256.Sum256(canonical)
	expectedHash := fmt.Sprintf("%x", h[:])
	contentHash, _ := att["content_hash"].(string)
	if contentHash != expectedHash {
		return false
	}

	// Extract attestation fields
	version, _ := att["version"].(float64)
	timestamp, _ := att["timestamp"].(float64)
	injClean, _ := att["injection_clean"].(bool)
	dlpClean, _ := att["dlp_clean"].(bool)
	schemaValid, _ := att["schema_valid"].(bool)
	trustTier, _ := att["trust_tier"].(string)
	scanPasses, _ := att["scan_passes"].(float64)
	signature, _ := att["signature"].(string)

	// Verify HMAC signature
	signingContent := fmt.Sprintf("v%d:%d:%s:%t:%t:%t:%s:%d",
		int(version), int(timestamp), contentHash,
		injClean, dlpClean, schemaValid, trustTier, int(scanPasses))
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(signingContent))
	expectedSig := fmt.Sprintf("%x", mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}
