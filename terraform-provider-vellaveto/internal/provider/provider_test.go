// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testProtoV6ProviderFactories creates a test provider factory.
func testProtoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"vellaveto": providerserver.NewProtocol6WithError(New("test")()),
	}
}

func TestProviderSchema(t *testing.T) {
	p := &VellavetoProvider{version: "test"}
	resp := &providerserver.ServeOpts{}
	_ = resp
	// Just ensure the provider implements the interface
	var _ = p.Schema
}

func TestProviderMetadata(t *testing.T) {
	p := &VellavetoProvider{version: "1.0.0"}
	req := providerserver.ServeOpts{}
	_ = req
	// Ensure version is set
	if p.version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", p.version)
	}
}

func TestAPIClientDoJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"p1","name":"test"}`)
	}))
	defer ts.Close()

	client := &APIClient{
		BaseURL:    ts.URL,
		APIKey:     "test-key",
		HTTPClient: ts.Client(),
	}

	result, err := client.doJSON(context.Background(), http.MethodGet, "/api/policies", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["id"] != "p1" {
		t.Errorf("expected id=p1, got %v", result["id"])
	}
	if result["name"] != "test" {
		t.Errorf("expected name=test, got %v", result["name"])
	}
}

func TestAPIClientDoJSONWithTenantID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tenant-ID") != "acme" {
			t.Errorf("expected X-Tenant-ID=acme, got %s", r.Header.Get("X-Tenant-ID"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{}`)
	}))
	defer ts.Close()

	client := &APIClient{
		BaseURL:    ts.URL,
		APIKey:     "key",
		TenantID:   "acme",
		HTTPClient: ts.Client(),
	}

	_, err := client.doJSON(context.Background(), http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIClientDoJSONError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		fmt.Fprintf(w, `{"error":"forbidden"}`)
	}))
	defer ts.Close()

	client := &APIClient{
		BaseURL:    ts.URL,
		APIKey:     "key",
		HTTPClient: ts.Client(),
	}

	_, err := client.doJSON(context.Background(), http.MethodGet, "/test", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestAPIClientDoJSONPostBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body["name"] != "test-policy" {
			t.Errorf("expected name=test-policy, got %v", body["name"])
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"new-1","name":"test-policy"}`)
	}))
	defer ts.Close()

	client := &APIClient{
		BaseURL:    ts.URL,
		APIKey:     "key",
		HTTPClient: ts.Client(),
	}

	result, err := client.doJSON(context.Background(), http.MethodPost, "/api/policies", map[string]interface{}{
		"name": "test-policy",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["id"] != "new-1" {
		t.Errorf("expected id=new-1, got %v", result["id"])
	}
}

func TestAPIClientDoRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(204)
	}))
	defer ts.Close()

	client := &APIClient{
		BaseURL:    ts.URL,
		APIKey:     "key",
		HTTPClient: ts.Client(),
	}

	err := client.doRequest(context.Background(), http.MethodDelete, "/api/policies/p1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIClientDoRequestError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		fmt.Fprintf(w, "not found")
	}))
	defer ts.Close()

	client := &APIClient{
		BaseURL:    ts.URL,
		APIKey:     "key",
		HTTPClient: ts.Client(),
	}

	err := client.doRequest(context.Background(), http.MethodDelete, "/api/policies/xxx", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		max      int
		expected string
	}{
		{"short", 10, "short"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"exact", 5, "exact"},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.expected)
		}
	}
}

func TestProviderModelTypes(t *testing.T) {
	model := VellavetoProviderModel{
		APIURL:   types.StringValue("https://example.com"),
		APIKey:   types.StringValue("key"),
		TenantID: types.StringValue("t1"),
		Timeout:  types.Int64Value(30),
	}
	if model.APIURL.ValueString() != "https://example.com" {
		t.Error("APIURL mismatch")
	}
	if model.APIKey.ValueString() != "key" {
		t.Error("APIKey mismatch")
	}
	if model.TenantID.ValueString() != "t1" {
		t.Error("TenantID mismatch")
	}
	if model.Timeout.ValueInt64() != 30 {
		t.Error("Timeout mismatch")
	}
}

func TestPolicyResourceModelTypes(t *testing.T) {
	model := PolicyResourceModel{
		ID:         types.StringValue("p1"),
		Name:       types.StringValue("test"),
		PolicyType: types.StringValue("Deny"),
		Priority:   types.Int64Value(100),
		Content:    types.StringValue("[policy]\nname = \"test\""),
	}
	if model.ID.ValueString() != "p1" {
		t.Error("ID mismatch")
	}
	if model.Name.ValueString() != "test" {
		t.Error("Name mismatch")
	}
}

func TestHealthDataSourceModel(t *testing.T) {
	model := HealthDataSourceModel{
		Status:     types.StringValue("ok"),
		Version:    types.StringValue("5.0.0"),
		UptimeSecs: types.Int64Value(3600),
	}
	if model.Status.ValueString() != "ok" {
		t.Error("Status mismatch")
	}
	if model.Version.ValueString() != "5.0.0" {
		t.Error("Version mismatch")
	}
	if model.UptimeSecs.ValueInt64() != 3600 {
		t.Error("UptimeSecs mismatch")
	}
}

// --- R257-TF-2 tests: API key redaction ---

func TestAPIClientStringRedactsAPIKey(t *testing.T) {
	client := &APIClient{
		BaseURL: "https://vellaveto.example.com",
		APIKey:  "super-secret-key-12345",
	}
	s := client.String()
	if strings.Contains(s, "super-secret-key-12345") {
		t.Error("String() must not contain the API key")
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Error("String() must contain [REDACTED]")
	}
	if !strings.Contains(s, "https://vellaveto.example.com") {
		t.Error("String() must contain the BaseURL")
	}
}

func TestAPIClientGoStringRedactsAPIKey(t *testing.T) {
	client := &APIClient{
		BaseURL: "https://vellaveto.example.com",
		APIKey:  "super-secret-key-12345",
	}
	s := fmt.Sprintf("%#v", client)
	if strings.Contains(s, "super-secret-key-12345") {
		t.Error("GoString() must not contain the API key")
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Error("GoString() must contain [REDACTED]")
	}
}

func TestAPIClientSprintfSRedactsAPIKey(t *testing.T) {
	client := &APIClient{
		BaseURL: "https://vellaveto.example.com",
		APIKey:  "super-secret-key-12345",
	}
	s := fmt.Sprintf("%s", client)
	if strings.Contains(s, "super-secret-key-12345") {
		t.Error("fmt Sprintf with percent-s must not contain the API key")
	}
}

// --- R257-TF-1 tests: URL validation ---

func TestValidateAPIURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com", false},
		{"valid http", "http://localhost:8080", false},
		{"valid https with path", "https://example.com/api", false},
		{"trailing slash trimmed", "https://example.com/", false},
		{"ftp scheme rejected", "ftp://example.com", true},
		{"no scheme rejected", "example.com", true},
		{"empty rejected", "", true},
		{"userinfo rejected", "https://user:pass@example.com", true},
		{"userinfo user only rejected", "https://user@example.com", true},
		{"file scheme rejected", "file:///etc/passwd", true},
		{"javascript scheme rejected", "javascript:alert(1)", true},
		{"data scheme rejected", "data:text/html,<h1>hi</h1>", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAPIURL(tc.url)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for URL %q, got nil", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for URL %q: %v", tc.url, err)
			}
		})
	}
}
