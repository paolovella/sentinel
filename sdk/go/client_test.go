package vellaveto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// helper: create a test server that returns the given status and JSON body.
func testServer(t *testing.T, wantMethod, wantPath string, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod {
			t.Errorf("method = %s, want %s", r.Method, wantMethod)
		}
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
	}))
}

// testServerWithBodyCheck creates a test server that also captures and validates the request body.
func testServerWithBodyCheck(t *testing.T, wantMethod, wantPath string, status int, respBody interface{}, bodyCheck func(t *testing.T, body []byte)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod {
			t.Errorf("method = %s, want %s", r.Method, wantMethod)
		}
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if bodyCheck != nil {
			reqBody, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}
			bodyCheck(t, reqBody)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if respBody != nil {
			if err := json.NewEncoder(w).Encode(respBody); err != nil {
				t.Fatal(err)
			}
		}
	}))
}

// mustNewClient creates a new client, failing the test on error.
func mustNewClient(t *testing.T, baseURL string, opts ...Option) *Client {
	t.Helper()
	c, err := NewClient(baseURL, opts...)
	if err != nil {
		t.Fatalf("NewClient(%q) error: %v", baseURL, err)
	}
	return c
}

func TestHealth(t *testing.T) {
	srv := testServer(t, "GET", "/health", 200, HealthResponse{Status: "ok", Version: "6.0.0"})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
	if resp.Version != "6.0.0" {
		t.Errorf("Version = %q, want %q", resp.Version, "6.0.0")
	}
}

func TestEvaluate_Allow(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict":   "allow",
		"policy_id": "p1",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	result, err := c.Evaluate(context.Background(), Action{Tool: "read_file"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result.Verdict != VerdictAllow {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictAllow)
	}
	if result.PolicyID != "p1" {
		t.Errorf("PolicyID = %q, want %q", result.PolicyID, "p1")
	}
}

func TestEvaluate_Deny(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict":   "deny",
		"reason":    "blocked by policy",
		"policy_id": "p2",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	result, err := c.Evaluate(context.Background(), Action{Tool: "exec"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result.Verdict != VerdictDeny {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictDeny)
	}
	if result.Reason != "blocked by policy" {
		t.Errorf("Reason = %q, want %q", result.Reason, "blocked by policy")
	}
}

func TestEvaluate_ObjectVerdict(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict": map[string]interface{}{
			"Deny": map[string]interface{}{
				"reason": "object-form deny",
			},
		},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	result, err := c.Evaluate(context.Background(), Action{Tool: "exec"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result.Verdict != VerdictDeny {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictDeny)
	}
	if result.Reason != "object-form deny" {
		t.Errorf("Reason = %q, want %q", result.Reason, "object-form deny")
	}
}

func TestEvaluate_UnknownVerdict_FailClosed(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict": "unknown_value",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	result, err := c.Evaluate(context.Background(), Action{Tool: "x"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result.Verdict != VerdictDeny {
		t.Errorf("Verdict = %q, want %q (fail-closed)", result.Verdict, VerdictDeny)
	}
}

func TestEvaluateOrError_Allow(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict": "allow",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	err := c.EvaluateOrError(context.Background(), Action{Tool: "read"}, nil)
	if err != nil {
		t.Fatalf("EvaluateOrError() should be nil for allow, got: %v", err)
	}
}

func TestEvaluateOrError_Deny(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict":   "deny",
		"reason":    "no access",
		"policy_id": "p3",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	err := c.EvaluateOrError(context.Background(), Action{Tool: "write"}, nil)
	if err == nil {
		t.Fatal("EvaluateOrError() should return error for deny")
	}
	denied, ok := err.(*PolicyDeniedError)
	if !ok {
		t.Fatalf("error type = %T, want *PolicyDeniedError", err)
	}
	if denied.Reason != "no access" {
		t.Errorf("Reason = %q, want %q", denied.Reason, "no access")
	}
	if denied.PolicyID != "p3" {
		t.Errorf("PolicyID = %q, want %q", denied.PolicyID, "p3")
	}
}

func TestEvaluateOrError_RequireApproval(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict":     "require_approval",
		"reason":      "needs review",
		"approval_id": "apr-1",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	err := c.EvaluateOrError(context.Background(), Action{Tool: "deploy"}, nil)
	if err == nil {
		t.Fatal("EvaluateOrError() should return error for require_approval")
	}
	approval, ok := err.(*ApprovalRequiredError)
	if !ok {
		t.Fatalf("error type = %T, want *ApprovalRequiredError", err)
	}
	if approval.Reason != "needs review" {
		t.Errorf("Reason = %q, want %q", approval.Reason, "needs review")
	}
	if approval.ApprovalID != "apr-1" {
		t.Errorf("ApprovalID = %q, want %q", approval.ApprovalID, "apr-1")
	}
}

func TestListPolicies(t *testing.T) {
	policies := []PolicySummary{
		{ID: "p1", Name: "allow-reads", PolicyType: "allow", Priority: 10},
		{ID: "p2", Name: "deny-exec", PolicyType: "deny", Priority: 20},
	}
	srv := testServer(t, "GET", "/api/policies", 200, policies)
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	result, err := c.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies() error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0].Name != "allow-reads" {
		t.Errorf("result[0].Name = %q, want %q", result[0].Name, "allow-reads")
	}
}

func TestReloadPolicies(t *testing.T) {
	srv := testServer(t, "POST", "/api/policies/reload", 200, map[string]interface{}{
		"count":  3,
		"status": "ok",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ReloadPolicies(context.Background())
	if err != nil {
		t.Fatalf("ReloadPolicies() error: %v", err)
	}
	if resp.Count != 3 {
		t.Errorf("Count = %d, want 3", resp.Count)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
}

func TestSimulate(t *testing.T) {
	srv := testServer(t, "POST", "/api/simulator/evaluate", 200, SimulateResponse{
		Verdict:         VerdictAllow,
		PoliciesChecked: 3,
		DurationUs:      42,
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.Simulate(context.Background(), Action{Tool: "read_file"}, nil)
	if err != nil {
		t.Fatalf("Simulate() error: %v", err)
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("Verdict = %q, want %q", resp.Verdict, VerdictAllow)
	}
	if resp.PoliciesChecked != 3 {
		t.Errorf("PoliciesChecked = %d, want 3", resp.PoliciesChecked)
	}
}

func TestBatchEvaluate(t *testing.T) {
	srv := testServer(t, "POST", "/api/simulator/batch", 200, BatchResponse{
		Results: []BatchResult{
			{ActionIndex: 0, Verdict: VerdictAllow},
			{ActionIndex: 1, Verdict: VerdictDeny},
		},
		Summary: BatchSummary{Total: 2, Allowed: 1, Denied: 1},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.BatchEvaluate(context.Background(), []Action{
		{Tool: "read_file"},
		{Tool: "exec"},
	}, nil)
	if err != nil {
		t.Fatalf("BatchEvaluate() error: %v", err)
	}
	if resp.Summary.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Summary.Total)
	}
	if resp.Results[1].Verdict != VerdictDeny {
		t.Errorf("Results[1].Verdict = %q, want %q", resp.Results[1].Verdict, VerdictDeny)
	}
}

func TestValidateConfig(t *testing.T) {
	srv := testServer(t, "POST", "/api/simulator/validate", 200, ValidateResponse{
		Valid:       true,
		PolicyCount: 5,
		Summary:     ValidationSummary{TotalPolicies: 5, Valid: true},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ValidateConfig(context.Background(), map[string]interface{}{"policies": []string{}}, false)
	if err != nil {
		t.Fatalf("ValidateConfig() error: %v", err)
	}
	if !resp.Valid {
		t.Error("Valid = false, want true")
	}
}

func TestDiffConfigs(t *testing.T) {
	srv := testServer(t, "POST", "/api/simulator/diff", 200, DiffResponse{
		Added:     []PolicySummary{{ID: "p3", Name: "new-policy"}},
		Removed:   []PolicySummary{},
		Modified:  []PolicyDiff{},
		Unchanged: 2,
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.DiffConfigs(context.Background(), map[string]interface{}{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("DiffConfigs() error: %v", err)
	}
	if len(resp.Added) != 1 {
		t.Fatalf("Added len = %d, want 1", len(resp.Added))
	}
	if resp.Added[0].Name != "new-policy" {
		t.Errorf("Added[0].Name = %q, want %q", resp.Added[0].Name, "new-policy")
	}
}

func TestListPendingApprovals(t *testing.T) {
	approvals := []Approval{
		{ID: "apr-1", Reason: "needs review", CreatedAt: "2026-01-01T00:00:00Z"},
	}
	srv := testServer(t, "GET", "/api/approvals/pending", 200, approvals)
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	result, err := c.ListPendingApprovals(context.Background())
	if err != nil {
		t.Fatalf("ListPendingApprovals() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
	if result[0].ID != "apr-1" {
		t.Errorf("ID = %q, want %q", result[0].ID, "apr-1")
	}
}

func TestApproveApproval(t *testing.T) {
	srv := testServer(t, "POST", "/api/approvals/apr-1/approve", 200, map[string]string{"status": "approved"})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	err := c.ApproveApproval(context.Background(), "apr-1")
	if err != nil {
		t.Fatalf("ApproveApproval() error: %v", err)
	}
}

func TestDenyApproval(t *testing.T) {
	srv := testServer(t, "POST", "/api/approvals/apr-1/deny", 200, map[string]string{"status": "denied"})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	err := c.DenyApproval(context.Background(), "apr-1")
	if err != nil {
		t.Fatalf("DenyApproval() error: %v", err)
	}
}

func TestAPIKey_Header(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key-123" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer test-key-123")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL, WithAPIKey("test-key-123"))
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
}

func TestNoAPIKey_NoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("Authorization header should be empty, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
}

func TestCustomHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "value" {
			t.Errorf("X-Custom = %q, want %q", r.Header.Get("X-Custom"), "value")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL, WithHeaders(map[string]string{"X-Custom": "value"}))
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
}

func TestHTTPError(t *testing.T) {
	srv := testServer(t, "GET", "/health", 500, map[string]string{"error": "internal"})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("Health() should return error for 500")
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", sentErr.StatusCode)
	}
}

func TestUnauthorizedError(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 401, map[string]string{"error": "unauthorized"})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Evaluate(context.Background(), Action{Tool: "x"}, nil, false)
	if err == nil {
		t.Fatal("Evaluate() should return error for 401")
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", sentErr.StatusCode)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL, WithTimeout(50*time.Millisecond))
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("Health() should return error on timeout")
	}
}

func TestTrailingSlashRemoved(t *testing.T) {
	srv := testServer(t, "GET", "/health", 200, HealthResponse{Status: "ok"})
	defer srv.Close()

	c := mustNewClient(t, srv.URL + "/")
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
}

func TestEvaluateWithContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server uses #[serde(flatten)] so fields are at root level, not nested.
		var req EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Tool != "read" {
			t.Errorf("Tool = %q, want %q", req.Tool, "read")
		}
		if req.Context == nil {
			t.Fatal("context should not be nil")
		}
		if req.Context.SessionID != "sess-1" {
			t.Errorf("SessionID = %q, want %q", req.Context.SessionID, "sess-1")
		}
		if req.Context.AgentID != "agent-1" {
			t.Errorf("AgentID = %q, want %q", req.Context.AgentID, "agent-1")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"verdict": "allow"})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Evaluate(context.Background(), Action{Tool: "read"}, &EvaluationContext{
		SessionID: "sess-1",
		AgentID:   "agent-1",
	}, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
}

func TestParseVerdict(t *testing.T) {
	tests := []struct {
		input string
		want  Verdict
	}{
		{"allow", VerdictAllow},
		{"Allow", VerdictAllow},
		{"ALLOW", VerdictAllow},
		{"aLlOw", VerdictAllow},
		{"deny", VerdictDeny},
		{"Deny", VerdictDeny},
		{"DENY", VerdictDeny},
		{"dEnY", VerdictDeny},
		{"require_approval", VerdictRequireApproval},
		{"RequireApproval", VerdictRequireApproval},
		{"REQUIRE_APPROVAL", VerdictRequireApproval},
		{"Require_Approval", VerdictRequireApproval},
		{"requireapproval", VerdictRequireApproval},
		{"REQUIREAPPROVAL", VerdictRequireApproval},
		{"", VerdictDeny},        // fail-closed
		{"unknown", VerdictDeny}, // fail-closed
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseVerdict(tt.input)
			if got != tt.want {
				t.Errorf("ParseVerdict(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestErrorMessages(t *testing.T) {
	t.Run("VellavetoError with status", func(t *testing.T) {
		e := &VellavetoError{Message: "not found", StatusCode: 404}
		want := "vellaveto: not found (HTTP 404)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("VellavetoError without status", func(t *testing.T) {
		e := &VellavetoError{Message: "connection failed"}
		want := "vellaveto: connection failed"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("PolicyDeniedError with policy", func(t *testing.T) {
		e := &PolicyDeniedError{Reason: "blocked", PolicyID: "p1"}
		want := "vellaveto: policy denied: blocked (policy: p1)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("PolicyDeniedError without policy", func(t *testing.T) {
		e := &PolicyDeniedError{Reason: "blocked"}
		want := "vellaveto: policy denied: blocked"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("ApprovalRequiredError with id", func(t *testing.T) {
		e := &ApprovalRequiredError{Reason: "review", ApprovalID: "a1"}
		want := "vellaveto: approval required: review (approval: a1)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("ApprovalRequiredError without id", func(t *testing.T) {
		e := &ApprovalRequiredError{Reason: "review"}
		want := "vellaveto: approval required: review"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})
}

func TestWithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 10 * time.Second}
	c := mustNewClient(t, "http://localhost", WithHTTPClient(custom))
	if c.httpClient != custom {
		t.Error("httpClient should be the custom client")
	}
}

// SECURITY (FIND-R46-GO-007): Action.Validate() tests
func TestActionValidate_EmptyTool(t *testing.T) {
	a := &Action{}
	err := a.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty Tool")
	}
}

func TestActionValidate_ValidAction(t *testing.T) {
	a := &Action{Tool: "read_file", Function: "read"}
	err := a.Validate()
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestActionValidate_ToolTooLong(t *testing.T) {
	longTool := make([]byte, 300)
	for i := range longTool {
		longTool[i] = 'x'
	}
	a := &Action{Tool: string(longTool)}
	err := a.Validate()
	if err == nil {
		t.Fatal("Validate() should reject oversized Tool")
	}
}

func TestActionValidate_TooManyTargetPaths(t *testing.T) {
	paths := make([]string, 101)
	for i := range paths {
		paths[i] = "/some/path"
	}
	a := &Action{Tool: "fs", TargetPaths: paths}
	err := a.Validate()
	if err == nil {
		t.Fatal("Validate() should reject >100 TargetPaths")
	}
}

func TestActionValidate_TooManyTargetDomains(t *testing.T) {
	domains := make([]string, 101)
	for i := range domains {
		domains[i] = "example.com"
	}
	a := &Action{Tool: "http", TargetDomains: domains}
	err := a.Validate()
	if err == nil {
		t.Fatal("Validate() should reject >100 TargetDomains")
	}
}

// SECURITY (FIND-R46-GO-003): Verify query parameters are properly URL-encoded.
// SECURITY (FIND-R111-009): After adding sensitivity validation, this test now uses
// an empty sensitivity filter and focuses URL-encoding verification on server_id,
// which accepts arbitrary ASCII strings (only control chars and length are bounded).
func TestDiscoveryTools_QueryParamEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the query parameters are properly encoded
		serverID := r.URL.Query().Get("server_id")
		if serverID != "server&evil=1" {
			t.Errorf("server_id = %q, want %q", serverID, "server&evil=1")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DiscoveryToolsResponse{Tools: []ToolMetadata{}, Total: 0})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	// server_id value contains '&' and '=' which must be URL-encoded by url.Values.
	// Sensitivity is left empty because it is now validated against an enum.
	_, err := c.DiscoveryTools(context.Background(), "server&evil=1", "")
	if err != nil {
		t.Fatalf("DiscoveryTools() error: %v", err)
	}
}

// TestDiscoveryTools_SensitivityValidation verifies that invalid sensitivity values
// are rejected before the network call.
// SECURITY (FIND-R111-009): Enum validation for sensitivity parameter.
func TestDiscoveryTools_SensitivityValidation(t *testing.T) {
	c := mustNewClient(t, "http://localhost:0") // no server needed
	_, err := c.DiscoveryTools(context.Background(), "", "invalid")
	if err == nil {
		t.Fatal("expected error for invalid sensitivity, got nil")
	}
	// Verify valid values are accepted (network not called because server is unreachable,
	// but validation must pass before the dial attempt).
	for _, valid := range []string{"low", "medium", "high", ""} {
		// A dial error is expected; a validation error is not.
		_, err2 := c.DiscoveryTools(context.Background(), "", valid)
		if err2 != nil {
			// Accept connection errors (expected since no server), reject validation errors.
			errMsg := err2.Error()
			if strings.Contains(errMsg, "sensitivity must be") {
				t.Errorf("valid sensitivity %q was rejected: %v", valid, err2)
			}
		}
	}
}

// SECURITY (FIND-R46-GO-004): Verify Authorization header is stripped on cross-domain redirect.
func TestRedirectStripsAuthOnCrossDomain(t *testing.T) {
	// Target server that checks there's no Authorization header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("Authorization header should be stripped on cross-domain redirect, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer target.Close()

	// Origin server that redirects to target
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/health", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c := mustNewClient(t, origin.URL, WithAPIKey("secret-key"))
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
}

// SECURITY (FIND-R46-GO-004): Verify Authorization header is preserved on same-domain redirect.
func TestRedirectPreservesAuthOnSameDomain(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			// First call: redirect to /health on same server
			http.Redirect(w, r, "/health", http.StatusTemporaryRedirect)
			return
		}
		// Second call: verify auth header is still present
		auth := r.Header.Get("Authorization")
		if auth != "Bearer my-key" {
			t.Errorf("Authorization header should be preserved on same-domain redirect, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL, WithAPIKey("my-key"))
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
}

// SECURITY (FIND-R46-GO-005): Verify error messages truncate large response bodies.
func TestErrorBodyTruncation(t *testing.T) {
	// Return a very large error body
	largeBody := make([]byte, 1024)
	for i := range largeBody {
		largeBody[i] = 'X'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write(largeBody)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("Health() should return error for 500")
	}
	errMsg := err.Error()
	// The error message should be truncated, not contain the full 1024-byte body
	if len(errMsg) > 400 {
		t.Errorf("Error message should be truncated, got %d chars", len(errMsg))
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", sentErr.StatusCode)
	}
}

// SECURITY (P0-2): Verify Evaluate sends flattened Action fields at root level.
func TestEvaluate_FlattenedPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Decode into a generic map to verify field layout
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}

		// Fields must be at the root level (flattened), NOT nested under "action"
		if _, hasAction := body["action"]; hasAction {
			t.Error("body should NOT have nested 'action' key — server uses #[serde(flatten)]")
		}
		if tool, ok := body["tool"].(string); !ok || tool != "read_file" {
			t.Errorf("body[\"tool\"] = %v, want %q", body["tool"], "read_file")
		}
		if fn, ok := body["function"].(string); !ok || fn != "read" {
			t.Errorf("body[\"function\"] = %v, want %q", body["function"], "read")
		}
		params, ok := body["parameters"].(map[string]interface{})
		if !ok {
			t.Fatalf("body[\"parameters\"] type = %T, want map", body["parameters"])
		}
		if params["path"] != "/etc/hosts" {
			t.Errorf("parameters.path = %v, want %q", params["path"], "/etc/hosts")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"verdict": "allow"})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Evaluate(context.Background(), Action{
		Tool:     "read_file",
		Function: "read",
		Parameters: map[string]interface{}{
			"path": "/etc/hosts",
		},
	}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
}

// Verify trace=true becomes a query parameter, not a body field.
func TestEvaluate_TraceQueryParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// trace should be a query parameter
		if r.URL.Query().Get("trace") != "true" {
			t.Errorf("query param trace = %q, want %q", r.URL.Query().Get("trace"), "true")
		}

		// trace should NOT be in the body
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, hasTrace := body["trace"]; hasTrace {
			t.Error("body should NOT have 'trace' field — it is a query parameter")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"verdict": "allow"})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Evaluate(context.Background(), Action{Tool: "x"}, nil, true)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
}

// Verify trace=false does NOT add query parameter.
func TestEvaluate_NoTraceQueryParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("URL should have no query params when trace=false, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"verdict": "allow"})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Evaluate(context.Background(), Action{Tool: "x"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// ZK Audit tests (P1-11)
// ═══════════════════════════════════════════════════════════════════

func TestZkStatus(t *testing.T) {
	seq := uint64(42)
	at := "2026-02-16T12:00:00Z"
	srv := testServer(t, "GET", "/api/zk-audit/status", 200, ZkSchedulerStatus{
		Active:             true,
		PendingWitnesses:   5,
		CompletedProofs:    10,
		LastProvedSequence: &seq,
		LastProofAt:        &at,
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ZkStatus(context.Background())
	if err != nil {
		t.Fatalf("ZkStatus() error: %v", err)
	}
	if !resp.Active {
		t.Error("Active = false, want true")
	}
	if resp.PendingWitnesses != 5 {
		t.Errorf("PendingWitnesses = %d, want 5", resp.PendingWitnesses)
	}
	if resp.CompletedProofs != 10 {
		t.Errorf("CompletedProofs = %d, want 10", resp.CompletedProofs)
	}
	if resp.LastProvedSequence == nil || *resp.LastProvedSequence != 42 {
		t.Errorf("LastProvedSequence = %v, want 42", resp.LastProvedSequence)
	}
	if resp.LastProofAt == nil || *resp.LastProofAt != "2026-02-16T12:00:00Z" {
		t.Errorf("LastProofAt = %v, want %q", resp.LastProofAt, "2026-02-16T12:00:00Z")
	}
}

func TestZkStatus_Inactive(t *testing.T) {
	srv := testServer(t, "GET", "/api/zk-audit/status", 200, ZkSchedulerStatus{
		Active:           false,
		PendingWitnesses: 0,
		CompletedProofs:  0,
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ZkStatus(context.Background())
	if err != nil {
		t.Fatalf("ZkStatus() error: %v", err)
	}
	if resp.Active {
		t.Error("Active = true, want false")
	}
	if resp.LastProvedSequence != nil {
		t.Errorf("LastProvedSequence should be nil, got %v", resp.LastProvedSequence)
	}
}

func TestZkProofs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/zk-audit/proofs" {
			t.Errorf("path = %s, want /api/zk-audit/proofs", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("limit = %q, want %q", r.URL.Query().Get("limit"), "10")
		}
		if r.URL.Query().Get("offset") != "5" {
			t.Errorf("offset = %q, want %q", r.URL.Query().Get("offset"), "5")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ZkProofsResponse{
			Proofs: []ZkBatchProof{
				{
					Proof:          "abc123",
					BatchID:        "batch-1",
					EntryRange:     [2]uint64{0, 99},
					MerkleRoot:     "deadbeef",
					FirstPrevHash:  "0000",
					FinalEntryHash: "ffff",
					CreatedAt:      "2026-02-16T12:00:00Z",
					EntryCount:     100,
				},
			},
			Total:  1,
			Offset: 5,
			Limit:  10,
		})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ZkProofs(context.Background(), 10, 5)
	if err != nil {
		t.Fatalf("ZkProofs() error: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("Total = %d, want 1", resp.Total)
	}
	if len(resp.Proofs) != 1 {
		t.Fatalf("len(Proofs) = %d, want 1", len(resp.Proofs))
	}
	if resp.Proofs[0].BatchID != "batch-1" {
		t.Errorf("BatchID = %q, want %q", resp.Proofs[0].BatchID, "batch-1")
	}
	if resp.Proofs[0].EntryRange != [2]uint64{0, 99} {
		t.Errorf("EntryRange = %v, want [0, 99]", resp.Proofs[0].EntryRange)
	}
	if resp.Proofs[0].EntryCount != 100 {
		t.Errorf("EntryCount = %d, want 100", resp.Proofs[0].EntryCount)
	}
}

func TestZkVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/zk-audit/verify" {
			t.Errorf("path = %s, want /api/zk-audit/verify", r.URL.Path)
		}
		var req ZkVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.BatchID != "batch-1" {
			t.Errorf("BatchID = %q, want %q", req.BatchID, "batch-1")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ZkVerifyResult{
			Valid:      true,
			BatchID:    "batch-1",
			EntryRange: [2]uint64{0, 99},
			VerifiedAt: "2026-02-16T12:30:00Z",
		})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ZkVerify(context.Background(), "batch-1")
	if err != nil {
		t.Fatalf("ZkVerify() error: %v", err)
	}
	if !resp.Valid {
		t.Error("Valid = false, want true")
	}
	if resp.BatchID != "batch-1" {
		t.Errorf("BatchID = %q, want %q", resp.BatchID, "batch-1")
	}
	if resp.EntryRange != [2]uint64{0, 99} {
		t.Errorf("EntryRange = %v, want [0, 99]", resp.EntryRange)
	}
	if resp.VerifiedAt != "2026-02-16T12:30:00Z" {
		t.Errorf("VerifiedAt = %q, want %q", resp.VerifiedAt, "2026-02-16T12:30:00Z")
	}
	if resp.Error != nil {
		t.Errorf("Error = %v, want nil", resp.Error)
	}
}

func TestZkVerify_WithError(t *testing.T) {
	errMsg := "proof invalid"
	srv := testServer(t, "POST", "/api/zk-audit/verify", 200, ZkVerifyResult{
		Valid:      false,
		BatchID:    "batch-bad",
		EntryRange: [2]uint64{0, 49},
		VerifiedAt: "2026-02-16T13:00:00Z",
		Error:      &errMsg,
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ZkVerify(context.Background(), "batch-bad")
	if err != nil {
		t.Fatalf("ZkVerify() error: %v", err)
	}
	if resp.Valid {
		t.Error("Valid = true, want false")
	}
	if resp.Error == nil || *resp.Error != "proof invalid" {
		t.Errorf("Error = %v, want %q", resp.Error, "proof invalid")
	}
}

func TestZkCommitments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/zk-audit/commitments" {
			t.Errorf("path = %s, want /api/zk-audit/commitments", r.URL.Path)
		}
		if r.URL.Query().Get("from") != "0" {
			t.Errorf("from = %q, want %q", r.URL.Query().Get("from"), "0")
		}
		if r.URL.Query().Get("to") != "100" {
			t.Errorf("to = %q, want %q", r.URL.Query().Get("to"), "100")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ZkCommitmentsResponse{
			Commitments: []ZkCommitmentEntry{
				{Sequence: 0, Commitment: "aabb", Timestamp: "2026-02-16T12:00:00Z"},
				{Sequence: 1, Commitment: "ccdd", Timestamp: "2026-02-16T12:01:00Z"},
			},
			Total: 2,
			Range: [2]uint64{0, 100},
		})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ZkCommitments(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("ZkCommitments() error: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
	if len(resp.Commitments) != 2 {
		t.Fatalf("len(Commitments) = %d, want 2", len(resp.Commitments))
	}
	if resp.Commitments[0].Sequence != 0 {
		t.Errorf("Commitments[0].Sequence = %d, want 0", resp.Commitments[0].Sequence)
	}
	if resp.Commitments[0].Commitment != "aabb" {
		t.Errorf("Commitments[0].Commitment = %q, want %q", resp.Commitments[0].Commitment, "aabb")
	}
	if resp.Range != [2]uint64{0, 100} {
		t.Errorf("Range = %v, want [0, 100]", resp.Range)
	}
}

func TestZkStatus_HTTPError(t *testing.T) {
	srv := testServer(t, "GET", "/api/zk-audit/status", 500, map[string]string{"error": "internal"})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.ZkStatus(context.Background())
	if err == nil {
		t.Fatal("ZkStatus() should return error for 500")
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", sentErr.StatusCode)
	}
}

func TestZkProofs_Empty(t *testing.T) {
	srv := testServer(t, "GET", "/api/zk-audit/proofs", 200, ZkProofsResponse{
		Proofs: []ZkBatchProof{},
		Total:  0,
		Offset: 0,
		Limit:  20,
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ZkProofs(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("ZkProofs() error: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
	if len(resp.Proofs) != 0 {
		t.Errorf("len(Proofs) = %d, want 0", len(resp.Proofs))
	}
}

func TestZkCommitments_Empty(t *testing.T) {
	srv := testServer(t, "GET", "/api/zk-audit/commitments", 200, ZkCommitmentsResponse{
		Commitments: []ZkCommitmentEntry{},
		Total:       0,
		Range:       [2]uint64{50, 60},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ZkCommitments(context.Background(), 50, 60)
	if err != nil {
		t.Fatalf("ZkCommitments() error: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
	if resp.Range != [2]uint64{50, 60} {
		t.Errorf("Range = %v, want [50, 60]", resp.Range)
	}
}

// ── Phase 38: SOC 2 Type II Access Review Tests ─────────────────────────────

func TestSoc2AccessReview(t *testing.T) {
	srv := testServer(t, "GET", "/api/compliance/soc2/access-review", 200, AccessReviewReport{
		GeneratedAt:      "2026-02-16T00:00:00Z",
		OrganizationName: "Acme",
		PeriodStart:      "2026-01-01T00:00:00Z",
		PeriodEnd:        "2026-02-01T00:00:00Z",
		TotalAgents:      2,
		TotalEvaluations: 100,
		Entries:          []AccessReviewEntry{},
		CC6Evidence: Cc6Evidence{
			CC61Evidence: "test",
			CC62Evidence: "test",
			CC63Evidence: "test",
			OptimalCount: 1,
		},
		Attestation: ReviewerAttestation{
			Status: "pending",
		},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.Soc2AccessReview(context.Background(), "30d", "json", "")
	if err != nil {
		t.Fatalf("Soc2AccessReview() error: %v", err)
	}
	if resp.TotalAgents != 2 {
		t.Errorf("TotalAgents = %d, want 2", resp.TotalAgents)
	}
	if resp.TotalEvaluations != 100 {
		t.Errorf("TotalEvaluations = %d, want 100", resp.TotalEvaluations)
	}
	if resp.CC6Evidence.OptimalCount != 1 {
		t.Errorf("OptimalCount = %d, want 1", resp.CC6Evidence.OptimalCount)
	}
}

func TestSoc2AccessReview_AgentIDTooLong(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	longID := ""
	for i := 0; i < 129; i++ {
		longID += "a"
	}
	_, err := c.Soc2AccessReview(context.Background(), "30d", "json", longID)
	if err == nil {
		t.Fatal("expected error for agent_id > 128 chars")
	}
	if !strings.Contains(err.Error(), "agent_id exceeds max length") {
		t.Errorf("error = %q, want 'agent_id exceeds max length'", err.Error())
	}
}

func TestSoc2AccessReview_NotFound(t *testing.T) {
	srv := testServer(t, "GET", "/api/compliance/soc2/access-review", 404, map[string]string{
		"error": "SOC 2 compliance is not enabled in configuration",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Soc2AccessReview(context.Background(), "30d", "json", "")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}


// ── FIND-GAP-011: NewClient URL validation ──────────────────

func TestNewClient_EmptyURL(t *testing.T) {
	_, err := NewClient("")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("error = %q, want contains 'must not be empty'", err.Error())
	}
}

func TestNewClient_NoScheme(t *testing.T) {
	_, err := NewClient("example.com")
	if err == nil {
		t.Fatal("expected error for URL without scheme")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error = %q, want contains 'scheme'", err.Error())
	}
}

func TestNewClient_InvalidScheme(t *testing.T) {
	_, err := NewClient("ftp://example.com")
	if err == nil {
		t.Fatal("expected error for ftp:// scheme")
	}
	if !strings.Contains(err.Error(), "http:// or https://") {
		t.Errorf("error = %q, want contains 'http:// or https://'", err.Error())
	}
}

func TestNewClient_NoHost(t *testing.T) {
	_, err := NewClient("http://")
	if err == nil {
		t.Fatal("expected error for URL without host")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("error = %q, want contains 'host'", err.Error())
	}
}

func TestNewClient_ValidHTTP(t *testing.T) {
	c, err := NewClient("http://localhost:3000")
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("client should not be nil")
	}
}

func TestNewClient_ValidHTTPS(t *testing.T) {
	c, err := NewClient("https://api.example.com")
	if err != nil {
		t.Fatalf("NewClient() unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("client should not be nil")
	}
}

func TestNewClient_WSScheme(t *testing.T) {
	_, err := NewClient("ws://example.com")
	if err == nil {
		t.Fatal("expected error for ws:// scheme")
	}
}

// ── FIND-R67-SDK-003: Reject credentials in baseURL ─────────

func TestNewClient_RejectsUserinfo(t *testing.T) {
	_, err := NewClient("http://user:password@localhost:3000")
	if err == nil {
		t.Fatal("expected error for URL with credentials")
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Errorf("error = %q, want contains 'credentials'", err.Error())
	}
}

func TestNewClient_RejectsUserinfoNoPassword(t *testing.T) {
	_, err := NewClient("http://user@localhost:3000")
	if err == nil {
		t.Fatal("expected error for URL with username-only userinfo")
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Errorf("error = %q, want contains 'credentials'", err.Error())
	}
}

func TestNewClient_RejectsHTTPSUserinfo(t *testing.T) {
	_, err := NewClient("https://admin:secret@api.example.com")
	if err == nil {
		t.Fatal("expected error for HTTPS URL with credentials")
	}
	if !strings.Contains(err.Error(), "userinfo") {
		t.Errorf("error = %q, want contains 'userinfo'", err.Error())
	}
}

// ── FIND-R67-SDK-GO-001: Soc2AccessReview format validation ──

func TestSoc2AccessReview_InvalidFormat(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.Soc2AccessReview(context.Background(), "30d", "xml", "")
	if err == nil {
		t.Fatal("expected error for invalid format 'xml'")
	}
	if !strings.Contains(err.Error(), "format must be") {
		t.Errorf("error = %q, want contains 'format must be'", err.Error())
	}
}

func TestSoc2AccessReview_EmptyFormatAllowed(t *testing.T) {
	srv := testServer(t, "GET", "/api/compliance/soc2/access-review", 200, AccessReviewReport{
		GeneratedAt: "2026-02-16T00:00:00Z",
		TotalAgents: 0,
		Entries:     []AccessReviewEntry{},
		CC6Evidence: Cc6Evidence{},
		Attestation: ReviewerAttestation{Status: "pending"},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Soc2AccessReview(context.Background(), "", "", "")
	if err != nil {
		t.Fatalf("Soc2AccessReview() error: %v (empty format should be allowed)", err)
	}
}

func TestSoc2AccessReview_HTMLFormatAllowed(t *testing.T) {
	srv := testServer(t, "GET", "/api/compliance/soc2/access-review", 200, AccessReviewReport{
		GeneratedAt: "2026-02-16T00:00:00Z",
		TotalAgents: 0,
		Entries:     []AccessReviewEntry{},
		CC6Evidence: Cc6Evidence{},
		Attestation: ReviewerAttestation{Status: "pending"},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Soc2AccessReview(context.Background(), "", "html", "")
	if err != nil {
		t.Fatalf("Soc2AccessReview() error: %v (html format should be allowed)", err)
	}
}

// ── FIND-GAP-010: Discovery and Projector method tests ──────

func TestDiscoverySearch(t *testing.T) {
	tokenBudget := 1000
	srv := testServerWithBodyCheck(t, "POST", "/api/discovery/search", 200,
		DiscoveryResult{
			Tools: []DiscoveredTool{
				{
					Metadata:       ToolMetadata{ToolID: "t1", Name: "read_file", Description: "reads files", ServerID: "s1"},
					RelevanceScore: 0.95,
					TTLSecs:        300,
				},
			},
			Query:           "file reading",
			TotalCandidates: 5,
			PolicyFiltered:  2,
		},
		func(t *testing.T, body []byte) {
			var req DiscoverRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("failed to unmarshal request body: %v", err)
			}
			if req.Query != "file reading" {
				t.Errorf("Query = %q, want %q", req.Query, "file reading")
			}
			if req.MaxResults != 10 {
				t.Errorf("MaxResults = %d, want 10", req.MaxResults)
			}
			if req.TokenBudget == nil || *req.TokenBudget != 1000 {
				t.Errorf("TokenBudget = %v, want 1000", req.TokenBudget)
			}
		},
	)
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	result, err := c.Discover(context.Background(), "file reading", 10, &tokenBudget)
	if err != nil {
		t.Fatalf("Discover() error: %v", err)
	}
	if len(result.Tools) != 1 {
		t.Fatalf("Tools count = %d, want 1", len(result.Tools))
	}
	if result.Tools[0].Metadata.Name != "read_file" {
		t.Errorf("Tool name = %q, want %q", result.Tools[0].Metadata.Name, "read_file")
	}
	if result.Query != "file reading" {
		t.Errorf("Query = %q, want %q", result.Query, "file reading")
	}
	if result.TotalCandidates != 5 {
		t.Errorf("TotalCandidates = %d, want 5", result.TotalCandidates)
	}
	if result.PolicyFiltered != 2 {
		t.Errorf("PolicyFiltered = %d, want 2", result.PolicyFiltered)
	}
}

// ── FIND-R110-SDK-002: Discover() max_results and token_budget validation ─────

func TestDiscover_MaxResultsZeroRejected(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.Discover(context.Background(), "test", 0, nil)
	if err == nil {
		t.Fatal("expected error for maxResults=0")
	}
	if !strings.Contains(err.Error(), "maxResults") {
		t.Errorf("error = %q, want contains 'maxResults'", err.Error())
	}
}

func TestDiscover_MaxResultsTooLargeRejected(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.Discover(context.Background(), "test", 21, nil)
	if err == nil {
		t.Fatal("expected error for maxResults=21")
	}
	if !strings.Contains(err.Error(), "maxResults") {
		t.Errorf("error = %q, want contains 'maxResults'", err.Error())
	}
}

func TestDiscover_MaxResultsValidAccepted(t *testing.T) {
	srv := testServer(t, "POST", "/api/discovery/search", 200, DiscoveryResult{
		Tools: []DiscoveredTool{}, Query: "test", TotalCandidates: 0, PolicyFiltered: 0,
	})
	defer srv.Close()
	c := mustNewClient(t, srv.URL)
	_, err := c.Discover(context.Background(), "test", 20, nil)
	if err != nil {
		t.Fatalf("maxResults=20 should be accepted, got: %v", err)
	}
}

func TestDiscover_TokenBudgetNegativeRejected(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	negative := -1
	_, err := c.Discover(context.Background(), "test", 5, &negative)
	if err == nil {
		t.Fatal("expected error for negative tokenBudget")
	}
	if !strings.Contains(err.Error(), "tokenBudget") {
		t.Errorf("error = %q, want contains 'tokenBudget'", err.Error())
	}
}

func TestDiscoveryStats(t *testing.T) {
	srv := testServer(t, "GET", "/api/discovery/index/stats", 200,
		DiscoveryIndexStats{
			TotalTools:    42,
			MaxCapacity:   1000,
			ConfigEnabled: true,
		},
	)
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	stats, err := c.DiscoveryStats(context.Background())
	if err != nil {
		t.Fatalf("DiscoveryStats() error: %v", err)
	}
	if stats.TotalTools != 42 {
		t.Errorf("TotalTools = %d, want 42", stats.TotalTools)
	}
	if stats.MaxCapacity != 1000 {
		t.Errorf("MaxCapacity = %d, want 1000", stats.MaxCapacity)
	}
	if !stats.ConfigEnabled {
		t.Error("ConfigEnabled = false, want true")
	}
}

func TestDiscoveryReindex(t *testing.T) {
	srv := testServer(t, "POST", "/api/discovery/reindex", 200,
		DiscoveryReindexResponse{
			Status:     "ok",
			TotalTools: 42,
		},
	)
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.DiscoveryReindex(context.Background())
	if err != nil {
		t.Fatalf("DiscoveryReindex() error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
	if resp.TotalTools != 42 {
		t.Errorf("TotalTools = %d, want 42", resp.TotalTools)
	}
}

func TestDiscoveryTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/discovery/tools" {
			t.Errorf("path = %s, want /api/discovery/tools", r.URL.Path)
		}
		// Verify query parameters
		if sid := r.URL.Query().Get("server_id"); sid != "srv-1" {
			t.Errorf("server_id = %q, want %q", sid, "srv-1")
		}
		if sens := r.URL.Query().Get("sensitivity"); sens != "high" {
			t.Errorf("sensitivity = %q, want %q", sens, "high")
		}
		w.Header().Set("Content-Type", "application/json")
		resp := DiscoveryToolsResponse{
			Tools: []ToolMetadata{
				{ToolID: "t1", Name: "dangerous_exec", ServerID: "srv-1", Sensitivity: "high"},
			},
			Total: 1,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.DiscoveryTools(context.Background(), "srv-1", "high")
	if err != nil {
		t.Fatalf("DiscoveryTools() error: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("Total = %d, want 1", resp.Total)
	}
	if len(resp.Tools) != 1 {
		t.Fatalf("Tools count = %d, want 1", len(resp.Tools))
	}
	if resp.Tools[0].Name != "dangerous_exec" {
		t.Errorf("Tool name = %q, want %q", resp.Tools[0].Name, "dangerous_exec")
	}
}

func TestDiscoveryTools_NoFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query params, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := DiscoveryToolsResponse{Tools: []ToolMetadata{}, Total: 0}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.DiscoveryTools(context.Background(), "", "")
	if err != nil {
		t.Fatalf("DiscoveryTools() error: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
}

func TestProjectorModels(t *testing.T) {
	srv := testServer(t, "GET", "/api/projector/models", 200,
		ProjectorModelsResponse{
			ModelFamilies: []string{"claude", "openai", "deepseek", "qwen", "generic"},
		},
	)
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ProjectorModels(context.Background())
	if err != nil {
		t.Fatalf("ProjectorModels() error: %v", err)
	}
	if len(resp.ModelFamilies) != 5 {
		t.Fatalf("ModelFamilies count = %d, want 5", len(resp.ModelFamilies))
	}
	if resp.ModelFamilies[0] != "claude" {
		t.Errorf("ModelFamilies[0] = %q, want %q", resp.ModelFamilies[0], "claude")
	}
}

func TestProjectSchema(t *testing.T) {
	srv := testServerWithBodyCheck(t, "POST", "/api/projector/transform", 200,
		ProjectorTransformResponse{
			ProjectedSchema: map[string]interface{}{"type": "function"},
			TokenEstimate:   150,
			ModelFamily:     "openai",
		},
		func(t *testing.T, body []byte) {
			var req ProjectorTransformRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("failed to unmarshal request body: %v", err)
			}
			if req.ModelFamily != "openai" {
				t.Errorf("ModelFamily = %q, want %q", req.ModelFamily, "openai")
			}
			if req.Schema.Name != "read_file" {
				t.Errorf("Schema.Name = %q, want %q", req.Schema.Name, "read_file")
			}
		},
	)
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	schema := CanonicalToolSchema{
		Name:        "read_file",
		Description: "Reads a file",
		InputSchema: map[string]interface{}{"type": "object"},
	}
	resp, err := c.ProjectSchema(context.Background(), schema, "openai")
	if err != nil {
		t.Fatalf("ProjectSchema() error: %v", err)
	}
	if resp.ModelFamily != "openai" {
		t.Errorf("ModelFamily = %q, want %q", resp.ModelFamily, "openai")
	}
	if resp.TokenEstimate != 150 {
		t.Errorf("TokenEstimate = %d, want 150", resp.TokenEstimate)
	}
}

// ── FIND-GAP-016: ReloadPolicies response capture ──────────

func TestReloadPolicies_WithMessage(t *testing.T) {
	srv := testServer(t, "POST", "/api/policies/reload", 200, map[string]interface{}{
		"count":   5,
		"status":  "reloaded",
		"message": "5 policies loaded from config",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.ReloadPolicies(context.Background())
	if err != nil {
		t.Fatalf("ReloadPolicies() error: %v", err)
	}
	if resp.Count != 5 {
		t.Errorf("Count = %d, want 5", resp.Count)
	}
	if resp.Status != "reloaded" {
		t.Errorf("Status = %q, want %q", resp.Status, "reloaded")
	}
	if resp.Message != "5 policies loaded from config" {
		t.Errorf("Message = %q, want %q", resp.Message, "5 policies loaded from config")
	}
}

func TestReloadPolicies_HTTPError(t *testing.T) {
	srv := testServer(t, "POST", "/api/policies/reload", 500, map[string]interface{}{
		"error": "internal server error",
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.ReloadPolicies(context.Background())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// ── Phase 39: Federation Tests ──────────────────────────────────────────────

func TestFederationStatus(t *testing.T) {
	srv := testServer(t, "GET", "/api/federation/status", 200, FederationStatusResponse{
		Enabled:          true,
		TrustAnchorCount: 1,
		Anchors: []FederationAnchorStatus{
			{
				OrgID:                 "partner-org",
				DisplayName:           "Partner",
				TrustLevel:            "limited",
				SuccessfulValidations: 42,
				FailedValidations:     3,
			},
		},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.FederationStatus(context.Background())
	if err != nil {
		t.Fatalf("FederationStatus() error: %v", err)
	}
	if !resp.Enabled {
		t.Error("Enabled = false, want true")
	}
	if resp.TrustAnchorCount != 1 {
		t.Errorf("TrustAnchorCount = %d, want 1", resp.TrustAnchorCount)
	}
	if len(resp.Anchors) != 1 {
		t.Fatalf("len(Anchors) = %d, want 1", len(resp.Anchors))
	}
	if resp.Anchors[0].OrgID != "partner-org" {
		t.Errorf("Anchors[0].OrgID = %q, want %q", resp.Anchors[0].OrgID, "partner-org")
	}
	if resp.Anchors[0].SuccessfulValidations != 42 {
		t.Errorf("SuccessfulValidations = %d, want 42", resp.Anchors[0].SuccessfulValidations)
	}
}

func TestFederationStatus_Disabled(t *testing.T) {
	srv := testServer(t, "GET", "/api/federation/status", 200, FederationStatusResponse{
		Enabled:          false,
		TrustAnchorCount: 0,
		Anchors:          []FederationAnchorStatus{},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.FederationStatus(context.Background())
	if err != nil {
		t.Fatalf("FederationStatus() error: %v", err)
	}
	if resp.Enabled {
		t.Error("Enabled = true, want false")
	}
	if resp.TrustAnchorCount != 0 {
		t.Errorf("TrustAnchorCount = %d, want 0", resp.TrustAnchorCount)
	}
}

func TestFederationStatus_HTTPError(t *testing.T) {
	srv := testServer(t, "GET", "/api/federation/status", 500, map[string]string{"error": "internal"})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.FederationStatus(context.Background())
	if err == nil {
		t.Fatal("FederationStatus() should return error for 500")
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", sentErr.StatusCode)
	}
}

func TestFederationTrustAnchors_All(t *testing.T) {
	srv := testServer(t, "GET", "/api/federation/trust-anchors", 200, FederationTrustAnchorsResponse{
		Anchors: []FederationTrustAnchor{
			{OrgID: "org-1", DisplayName: "Org 1", TrustLevel: "full"},
			{OrgID: "org-2", DisplayName: "Org 2", TrustLevel: "limited"},
		},
		Total: 2,
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.FederationTrustAnchors(context.Background(), "")
	if err != nil {
		t.Fatalf("FederationTrustAnchors() error: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
	if len(resp.Anchors) != 2 {
		t.Fatalf("len(Anchors) = %d, want 2", len(resp.Anchors))
	}
	if resp.Anchors[0].OrgID != "org-1" {
		t.Errorf("Anchors[0].OrgID = %q, want %q", resp.Anchors[0].OrgID, "org-1")
	}
}

func TestFederationTrustAnchors_WithFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/federation/trust-anchors" {
			t.Errorf("path = %s, want /api/federation/trust-anchors", r.URL.Path)
		}
		if orgID := r.URL.Query().Get("org_id"); orgID != "partner" {
			t.Errorf("org_id = %q, want %q", orgID, "partner")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(FederationTrustAnchorsResponse{
			Anchors: []FederationTrustAnchor{
				{OrgID: "partner", DisplayName: "Partner Org", TrustLevel: "limited"},
			},
			Total: 1,
		})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.FederationTrustAnchors(context.Background(), "partner")
	if err != nil {
		t.Fatalf("FederationTrustAnchors() error: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("Total = %d, want 1", resp.Total)
	}
	if resp.Anchors[0].OrgID != "partner" {
		t.Errorf("Anchors[0].OrgID = %q, want %q", resp.Anchors[0].OrgID, "partner")
	}
}

func TestFederationTrustAnchors_OrgIDTooLong(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	longID := strings.Repeat("a", 129)
	_, err := c.FederationTrustAnchors(context.Background(), longID)
	if err == nil {
		t.Fatal("expected error for org_id > 128 chars")
	}
	if !strings.Contains(err.Error(), "org_id exceeds max length") {
		t.Errorf("error = %q, want 'org_id exceeds max length'", err.Error())
	}
}

func TestFederationTrustAnchors_OrgIDControlChars(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.FederationTrustAnchors(context.Background(), "org\x00id")
	if err == nil {
		t.Fatal("expected error for org_id with control characters")
	}
	if !strings.Contains(err.Error(), "org_id contains control characters") {
		t.Errorf("error = %q, want 'org_id contains control characters'", err.Error())
	}
}

func TestFederationTrustAnchors_OrgIDNewline(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.FederationTrustAnchors(context.Background(), "org\nid")
	if err == nil {
		t.Fatal("expected error for org_id with newline")
	}
	if !strings.Contains(err.Error(), "org_id contains control characters") {
		t.Errorf("error = %q, want 'org_id contains control characters'", err.Error())
	}
}

func TestFederationTrustAnchors_Empty(t *testing.T) {
	srv := testServer(t, "GET", "/api/federation/trust-anchors", 200, FederationTrustAnchorsResponse{
		Anchors: []FederationTrustAnchor{},
		Total:   0,
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.FederationTrustAnchors(context.Background(), "")
	if err != nil {
		t.Fatalf("FederationTrustAnchors() error: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
	if len(resp.Anchors) != 0 {
		t.Errorf("len(Anchors) = %d, want 0", len(resp.Anchors))
	}
}

func TestFederationTrustAnchors_QueryParamEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the query parameter is properly URL-encoded
		orgID := r.URL.Query().Get("org_id")
		if orgID != "org&evil=1" {
			t.Errorf("org_id = %q, want %q", orgID, "org&evil=1")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(FederationTrustAnchorsResponse{
			Anchors: []FederationTrustAnchor{},
			Total:   0,
		})
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.FederationTrustAnchors(context.Background(), "org&evil=1")
	if err != nil {
		t.Fatalf("FederationTrustAnchors() error: %v", err)
	}
}

// ── FIND-R80-001: WithTimeout clamping ──────────────────────

func TestWithTimeout_ClampsZero(t *testing.T) {
	c := mustNewClient(t, "http://localhost:3000", WithTimeout(0))
	if c.httpClient.Timeout != 100*time.Millisecond {
		t.Errorf("Timeout = %v, want 100ms (clamped from 0)", c.httpClient.Timeout)
	}
}

func TestWithTimeout_ClampsNegative(t *testing.T) {
	c := mustNewClient(t, "http://localhost:3000", WithTimeout(-5*time.Second))
	if c.httpClient.Timeout != 100*time.Millisecond {
		t.Errorf("Timeout = %v, want 100ms (clamped from negative)", c.httpClient.Timeout)
	}
}

func TestWithTimeout_ClampsAboveMax(t *testing.T) {
	c := mustNewClient(t, "http://localhost:3000", WithTimeout(10*time.Minute))
	if c.httpClient.Timeout != 300*time.Second {
		t.Errorf("Timeout = %v, want 300s (clamped from 10min)", c.httpClient.Timeout)
	}
}

func TestWithTimeout_AcceptsValid(t *testing.T) {
	c := mustNewClient(t, "http://localhost:3000", WithTimeout(5*time.Second))
	if c.httpClient.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", c.httpClient.Timeout)
	}
}

func TestWithTimeout_AcceptsMinBoundary(t *testing.T) {
	c := mustNewClient(t, "http://localhost:3000", WithTimeout(100*time.Millisecond))
	if c.httpClient.Timeout != 100*time.Millisecond {
		t.Errorf("Timeout = %v, want 100ms", c.httpClient.Timeout)
	}
}

func TestWithTimeout_AcceptsMaxBoundary(t *testing.T) {
	c := mustNewClient(t, "http://localhost:3000", WithTimeout(300*time.Second))
	if c.httpClient.Timeout != 300*time.Second {
		t.Errorf("Timeout = %v, want 300s", c.httpClient.Timeout)
	}
}

// ── FIND-R80-002: Simulate/BatchEvaluate action validation ──

func TestSimulate_RejectsEmptyTool(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.Simulate(context.Background(), Action{}, nil)
	if err == nil {
		t.Fatal("Simulate() should reject empty Tool")
	}
	if !strings.Contains(err.Error(), "Tool must not be empty") {
		t.Errorf("error = %q, want contains 'Tool must not be empty'", err.Error())
	}
}

func TestSimulate_RejectsOversizedTool(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	longTool := strings.Repeat("x", 300)
	_, err := c.Simulate(context.Background(), Action{Tool: longTool}, nil)
	if err == nil {
		t.Fatal("Simulate() should reject oversized Tool")
	}
	if !strings.Contains(err.Error(), "exceeds max length") {
		t.Errorf("error = %q, want contains 'exceeds max length'", err.Error())
	}
}

func TestBatchEvaluate_RejectsEmptyTool(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.BatchEvaluate(context.Background(), []Action{{Tool: "valid"}, {}}, nil)
	if err == nil {
		t.Fatal("BatchEvaluate() should reject action with empty Tool")
	}
	if !strings.Contains(err.Error(), "action[1]") {
		t.Errorf("error = %q, want contains 'action[1]'", err.Error())
	}
}

func TestBatchEvaluate_RejectsTooManyTargetPaths(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	paths := make([]string, 101)
	for i := range paths {
		paths[i] = "/path"
	}
	_, err := c.BatchEvaluate(context.Background(), []Action{{Tool: "fs", TargetPaths: paths}}, nil)
	if err == nil {
		t.Fatal("BatchEvaluate() should reject >100 TargetPaths")
	}
	if !strings.Contains(err.Error(), "action[0]") {
		t.Errorf("error = %q, want contains 'action[0]'", err.Error())
	}
}

// ── FIND-R80-003: Unicode format char validation ──────────────

func TestValidateApprovalID_RejectsZeroWidthSpace(t *testing.T) {
	err := validateApprovalID("abc\u200Bdef")
	if err == nil {
		t.Fatal("validateApprovalID should reject zero-width space U+200B")
	}
	if !strings.Contains(err.Error(), "Unicode format characters") {
		t.Errorf("error = %q, want contains 'Unicode format characters'", err.Error())
	}
}

func TestValidateApprovalID_RejectsBidiOverride(t *testing.T) {
	err := validateApprovalID("abc\u202Edef")
	if err == nil {
		t.Fatal("validateApprovalID should reject bidi override U+202E")
	}
	if !strings.Contains(err.Error(), "Unicode format characters") {
		t.Errorf("error = %q, want contains 'Unicode format characters'", err.Error())
	}
}

func TestValidateApprovalID_RejectsBOM(t *testing.T) {
	err := validateApprovalID("\uFEFFabc")
	if err == nil {
		t.Fatal("validateApprovalID should reject BOM U+FEFF")
	}
	if !strings.Contains(err.Error(), "Unicode format characters") {
		t.Errorf("error = %q, want contains 'Unicode format characters'", err.Error())
	}
}

func TestValidateApprovalID_RejectsWordJoiner(t *testing.T) {
	err := validateApprovalID("abc\u2060def")
	if err == nil {
		t.Fatal("validateApprovalID should reject word joiner U+2060")
	}
	if !strings.Contains(err.Error(), "Unicode format characters") {
		t.Errorf("error = %q, want contains 'Unicode format characters'", err.Error())
	}
}

func TestValidateApprovalID_AcceptsNormalUnicode(t *testing.T) {
	err := validateApprovalID("approval-123-valid")
	if err != nil {
		t.Fatalf("validateApprovalID unexpected error: %v", err)
	}
}

func TestIsUnicodeFormatChar(t *testing.T) {
	tests := []struct {
		r    rune
		want bool
		name string
	}{
		{0x200B, true, "ZWSP"},
		{0x200C, true, "ZWNJ"},
		{0x200D, true, "ZWJ"},
		{0x200E, true, "LRM"},
		{0x200F, true, "RLM"},
		// FIND-R110-SDK-003: U+2028-202F range (supersedes old 202A-202E)
		{0x2028, true, "LINE SEPARATOR"},
		{0x2029, true, "PARAGRAPH SEPARATOR"},
		{0x202A, true, "LRE"},
		{0x202E, true, "RLO"},
		{0x202F, true, "NNBSP"},
		{0x2060, true, "WJ"},
		{0x2069, true, "PDI"},
		{0xFEFF, true, "BOM"},
		{0xFFF9, true, "IAA"},
		{0xFFFB, true, "IAT"},
		{'a', false, "ASCII letter"},
		{'0', false, "ASCII digit"},
		{'-', false, "hyphen"},
		{0x0100, false, "Latin Extended"},
		{0x2027, false, "HYPHENATION POINT (just below range)"},
		{0x2030, false, "PER MILLE SIGN (just above range)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnicodeFormatChar(tt.r)
			if got != tt.want {
				t.Errorf("isUnicodeFormatChar(%U) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

// ── FIND-R80-004: Soc2AccessReview period validation ──────────

func TestSoc2AccessReview_PeriodTooLong(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	longPeriod := strings.Repeat("a", 33)
	_, err := c.Soc2AccessReview(context.Background(), longPeriod, "json", "")
	if err == nil {
		t.Fatal("expected error for period > 32 chars")
	}
	if !strings.Contains(err.Error(), "period exceeds max length") {
		t.Errorf("error = %q, want contains 'period exceeds max length'", err.Error())
	}
}

func TestSoc2AccessReview_PeriodInvalidChars(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.Soc2AccessReview(context.Background(), "30d;rm -rf /", "json", "")
	if err == nil {
		t.Fatal("expected error for period with invalid characters")
	}
	if !strings.Contains(err.Error(), "period contains invalid characters") {
		t.Errorf("error = %q, want contains 'period contains invalid characters'", err.Error())
	}
}

func TestSoc2AccessReview_PeriodAcceptsValid(t *testing.T) {
	srv := testServer(t, "GET", "/api/compliance/soc2/access-review", 200, AccessReviewReport{
		GeneratedAt: "2026-02-16T00:00:00Z",
		TotalAgents: 0,
		Entries:     []AccessReviewEntry{},
		CC6Evidence: Cc6Evidence{},
		Attestation: ReviewerAttestation{Status: "pending"},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	// ISO date range with colons and dashes should be accepted
	_, err := c.Soc2AccessReview(context.Background(), "2026-01-01:2026-02-01", "json", "")
	if err != nil {
		t.Fatalf("Soc2AccessReview() error: %v (valid period should be accepted)", err)
	}
}

func TestSoc2AccessReview_PeriodAccepts30d(t *testing.T) {
	srv := testServer(t, "GET", "/api/compliance/soc2/access-review", 200, AccessReviewReport{
		GeneratedAt: "2026-02-16T00:00:00Z",
		TotalAgents: 0,
		Entries:     []AccessReviewEntry{},
		CC6Evidence: Cc6Evidence{},
		Attestation: ReviewerAttestation{Status: "pending"},
	})
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	_, err := c.Soc2AccessReview(context.Background(), "30d", "json", "")
	if err != nil {
		t.Fatalf("Soc2AccessReview() error: %v (30d period should be accepted)", err)
	}
}

// ── FIND-R80-003: FederationTrustAnchors Unicode format char validation ──

func TestFederationTrustAnchors_OrgIDUnicodeFormatChar(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	_, err := c.FederationTrustAnchors(context.Background(), "org\u200Bid")
	if err == nil {
		t.Fatal("expected error for org_id with zero-width space")
	}
	if !strings.Contains(err.Error(), "Unicode format characters") {
		t.Errorf("error = %q, want contains 'Unicode format characters'", err.Error())
	}
}

func TestOwaspAsiCoverage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/compliance/owasp-agentic" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, `{"total_categories":10,"covered_categories":10,"total_controls":33,"covered_controls":33,"coverage_percent":100.0}`)
	}))
	defer srv.Close()

	c := mustNewClient(t, srv.URL)
	resp, err := c.OwaspAsiCoverage(context.Background())
	if err != nil {
		t.Fatalf("OwaspAsiCoverage() error: %v", err)
	}
	if resp.TotalCategories != 10 {
		t.Errorf("TotalCategories = %d, want 10", resp.TotalCategories)
	}
	if resp.TotalControls != 33 {
		t.Errorf("TotalControls = %d, want 33", resp.TotalControls)
	}
	if resp.CoveragePercent != 100.0 {
		t.Errorf("CoveragePercent = %f, want 100.0", resp.CoveragePercent)
	}
}

// SECURITY (FIND-R101-004): Oversized Parameters should be rejected.
func TestActionValidate_OversizedParameters(t *testing.T) {
	largeParams := make(map[string]interface{})
	for i := 0; i < 50000; i++ {
		largeParams[fmt.Sprintf("key_%06d", i)] = "value"
	}
	a := &Action{Tool: "x", Parameters: largeParams}
	err := validateParameters(a.Parameters)
	if err == nil {
		t.Fatal("validateParameters() should reject oversized Parameters")
	}
	if !strings.Contains(err.Error(), "Parameters exceeds max serialized size") {
		t.Errorf("unexpected error: %v", err)
	}
}

// SECURITY (FIND-R101-003): EvaluationContext validation tests.
func TestEvaluationContextValidate_Valid(t *testing.T) {
	ctx := &EvaluationContext{
		SessionID: "session-123",
		AgentID:   "agent-1",
		TenantID:  "tenant-1",
		CallChain: []string{"tool_a", "tool_b"},
		Metadata:  map[string]interface{}{"key": "value"},
	}
	if err := ctx.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestEvaluationContextValidate_ControlCharsInAgentID(t *testing.T) {
	ctx := &EvaluationContext{AgentID: "agent" + string(rune(0)) + "evil"}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject control chars in agent_id")
	}
	if !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEvaluationContextValidate_UnicodeFormatCharsInSessionID(t *testing.T) {
	ctx := &EvaluationContext{SessionID: "session" + string(rune(0x200B)) + "hidden"}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject Unicode format chars in session_id")
	}
	if !strings.Contains(err.Error(), "Unicode format characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEvaluationContextValidate_TooManyCallChain(t *testing.T) {
	chain := make([]string, 101)
	for i := range chain {
		chain[i] = "tool"
	}
	ctx := &EvaluationContext{CallChain: chain}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject >100 CallChain entries")
	}
}

func TestEvaluationContextValidate_LongCallChainEntry(t *testing.T) {
	longEntry := strings.Repeat("x", 300)
	ctx := &EvaluationContext{CallChain: []string{longEntry}}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject oversized CallChain entry")
	}
}

func TestEvaluationContextValidate_TooManyMetadataKeys(t *testing.T) {
	meta := make(map[string]interface{})
	for i := 0; i < 101; i++ {
		meta[fmt.Sprintf("key_%d", i)] = "val"
	}
	ctx := &EvaluationContext{Metadata: meta}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject >100 Metadata keys")
	}
}

func TestEvaluationContextValidate_LongFieldLength(t *testing.T) {
	longID := strings.Repeat("a", 300)
	ctx := &EvaluationContext{TenantID: longID}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject oversized tenant_id")
	}
}

// ── FIND-R114-003: CallChain entry control/format character validation ──

func TestEvaluationContextValidate_CallChainControlChars(t *testing.T) {
	ctx := &EvaluationContext{CallChain: []string{"tool\x00evil"}}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject CallChain entry with control characters")
	}
	if !strings.Contains(err.Error(), "CallChain[0] contains control characters") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEvaluationContextValidate_CallChainC1ControlChars(t *testing.T) {
	// Use \u0080 (valid UTF-8 C1 control char) — \x80 is an invalid UTF-8 byte
	// that Go's range produces as U+FFFD (replacement character), not 0x80.
	ctx := &EvaluationContext{CallChain: []string{"ok", "tool\u0080bad"}}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject CallChain entry with C1 control characters")
	}
	if !strings.Contains(err.Error(), "CallChain[1] contains control characters") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEvaluationContextValidate_CallChainUnicodeFormatChars(t *testing.T) {
	ctx := &EvaluationContext{CallChain: []string{"tool\u200bhidden"}}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject CallChain entry with Unicode format characters")
	}
	if !strings.Contains(err.Error(), "CallChain[0] contains Unicode format characters") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEvaluationContextValidate_CallChainBidiOverride(t *testing.T) {
	ctx := &EvaluationContext{CallChain: []string{"safe", "tool\u202Aoverride"}}
	err := ctx.Validate()
	if err == nil {
		t.Fatal("Validate() should reject CallChain entry with bidi override")
	}
	if !strings.Contains(err.Error(), "CallChain[1] contains Unicode format characters") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ── FIND-R115-060: Simulate validates parameters size ──────────

func TestSimulate_RejectsOversizedParameters(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	// Build parameters exceeding 512KB
	bigVal := strings.Repeat("x", 600000)
	params := map[string]interface{}{"data": bigVal}
	action := Action{Tool: "test", Parameters: params}
	_, err := c.Simulate(context.Background(), action, nil)
	if err == nil {
		t.Fatal("Simulate() should reject parameters exceeding 512KB")
	}
	if !strings.Contains(err.Error(), "exceeds max serialized size") {
		t.Errorf("error = %q, want contains 'exceeds max serialized size'", err.Error())
	}
}

func TestSimulate_RejectsInvalidContext(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	action := Action{Tool: "test"}
	ctx := &EvaluationContext{SessionID: strings.Repeat("a", 300)}
	_, err := c.Simulate(context.Background(), action, ctx)
	if err == nil {
		t.Fatal("Simulate() should reject context with oversized session_id")
	}
	if !strings.Contains(err.Error(), "exceeds max length") {
		t.Errorf("error = %q, want contains 'exceeds max length'", err.Error())
	}
}

func TestSimulate_RejectsContextControlChars(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	action := Action{Tool: "test"}
	ctx := &EvaluationContext{AgentID: "agent\x01id"}
	_, err := c.Simulate(context.Background(), action, ctx)
	if err == nil {
		t.Fatal("Simulate() should reject context with control characters")
	}
	if !strings.Contains(err.Error(), "contains control characters") {
		t.Errorf("error = %q, want contains 'contains control characters'", err.Error())
	}
}

// ── FIND-R115-061: BatchEvaluate validates parameters size ─────

func TestBatchEvaluate_RejectsOversizedParameters(t *testing.T) {
	c := mustNewClient(t, "http://localhost:1")
	bigVal := strings.Repeat("x", 600000)
	params := map[string]interface{}{"data": bigVal}
	actions := []Action{{Tool: "test", Parameters: params}}
	_, err := c.BatchEvaluate(context.Background(), actions, nil)
	if err == nil {
		t.Fatal("BatchEvaluate() should reject action with parameters exceeding 512KB")
	}
	if !strings.Contains(err.Error(), "action[0]") {
		t.Errorf("error = %q, want contains 'action[0]'", err.Error())
	}
	if !strings.Contains(err.Error(), "exceeds max serialized size") {
		t.Errorf("error = %q, want contains 'exceeds max serialized size'", err.Error())
	}
}

// ── WithFailClosed option tests ──

func TestEvaluate_WithFailClosed_ConnectionRefused(t *testing.T) {
	// Port 1 will refuse connections on any standard system
	c, err := NewClient("http://127.0.0.1:1",
		WithAPIKey("test"),
		WithFailClosed(),
		WithTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	result, err := c.Evaluate(context.Background(), Action{Tool: "fs"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() should not error with WithFailClosed(), got: %v", err)
	}
	if result.Verdict != VerdictDeny {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictDeny)
	}
	if !strings.Contains(result.Reason, "fail-closed") {
		t.Errorf("Reason = %q, should contain 'fail-closed'", result.Reason)
	}
}

func TestEvaluate_WithoutFailClosed_ConnectionRefused(t *testing.T) {
	c, err := NewClient("http://127.0.0.1:1",
		WithAPIKey("test"),
		WithTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	_, err = c.Evaluate(context.Background(), Action{Tool: "fs"}, nil, false)
	if err == nil {
		t.Fatal("Evaluate() should error when server unreachable without WithFailClosed()")
	}
}

// ── R260 Attestation Verification Tests ─────────────────────────────────

func TestVerifyAttestation_SignatureTooShort(t *testing.T) {
	resp := map[string]interface{}{
		"_meta": map[string]interface{}{
			"vellaveto_attestation": map[string]interface{}{
				"signature": "abcd",
			},
		},
	}
	if VerifyAttestation(resp, []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")) {
		t.Fatal("short signature should return false")
	}
}

func TestVerifyAttestation_SignatureTooLong(t *testing.T) {
	resp := map[string]interface{}{
		"_meta": map[string]interface{}{
			"vellaveto_attestation": map[string]interface{}{
				"signature": strings.Repeat("a", 65),
			},
		},
	}
	if VerifyAttestation(resp, []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")) {
		t.Fatal("long signature should return false")
	}
}

func TestVerifyAttestation_SignatureNonString(t *testing.T) {
	resp := map[string]interface{}{
		"_meta": map[string]interface{}{
			"vellaveto_attestation": map[string]interface{}{
				"signature": 12345,
			},
		},
	}
	if VerifyAttestation(resp, []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")) {
		t.Fatal("non-string signature should return false")
	}
}

func makeTestAttestation(overrides map[string]interface{}) map[string]interface{} {
	att := map[string]interface{}{
		"version":         float64(1),
		"timestamp":       float64(1000),
		"content_hash":    strings.Repeat("a", 64),
		"injection_clean": true,
		"dlp_clean":       true,
		"schema_valid":    true,
		"trust_tier":      "Verified",
		"scan_passes":     float64(5),
		"signature":       strings.Repeat("a", 64),
	}
	for k, v := range overrides {
		att[k] = v
	}
	return map[string]interface{}{
		"result": map[string]interface{}{},
		"_meta": map[string]interface{}{
			"vellaveto_attestation": att,
		},
	}
}

func TestVerifyAttestation_VersionWrongType(t *testing.T) {
	resp := makeTestAttestation(map[string]interface{}{"version": "bad"})
	if VerifyAttestation(resp, []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")) {
		t.Fatal("version as string should return false")
	}
}

func TestVerifyAttestation_TimestampWrongType(t *testing.T) {
	resp := makeTestAttestation(map[string]interface{}{"timestamp": "bad"})
	if VerifyAttestation(resp, []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")) {
		t.Fatal("timestamp as string should return false")
	}
}

func TestVerifyAttestation_TrustTierWrongType(t *testing.T) {
	resp := makeTestAttestation(map[string]interface{}{"trust_tier": float64(42)})
	if VerifyAttestation(resp, []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")) {
		t.Fatal("trust_tier as number should return false")
	}
}

func TestVerifyAttestation_ScanPassesWrongType(t *testing.T) {
	resp := makeTestAttestation(map[string]interface{}{"scan_passes": "five"})
	if VerifyAttestation(resp, []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")) {
		t.Fatal("scan_passes as string should return false")
	}
}
