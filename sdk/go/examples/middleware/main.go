// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 Vellaveto Contributors

// Package main demonstrates an HTTP middleware pattern that enforces Vellaveto
// policies before forwarding requests to an upstream handler.
//
// The middleware extracts tool-call metadata from incoming HTTP requests (using
// a custom header convention), evaluates the action against the Vellaveto policy
// engine, and either forwards allowed requests or returns 403 Forbidden for
// denied ones.
//
// Usage:
//
//	export VELLAVETO_URL=http://localhost:3000
//	export VELLAVETO_API_KEY=your-api-key
//	go run .
//
// Then test with:
//
//	curl -H "X-Tool-Name: read_file" -H "X-Tool-Target-Path: /data/report.csv" http://localhost:8080/api/tool-call
//	curl -H "X-Tool-Name: exec_command" -H "X-Tool-Function: shell" http://localhost:8080/api/tool-call
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	vellaveto "github.com/paolovella/vellaveto/sdk/go"
)

// vellavetoMiddleware wraps an http.Handler and evaluates Vellaveto policies
// before forwarding the request. If the policy engine denies the action, the
// middleware returns 403 Forbidden with a JSON error body.
func vellavetoMiddleware(client *vellaveto.Client, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract tool-call metadata from request headers.
		// In a real application, you might extract this from the request body,
		// a gRPC metadata field, or an MCP message instead.
		toolName := r.Header.Get("X-Tool-Name")
		if toolName == "" {
			// No tool header -- pass through without policy evaluation.
			next.ServeHTTP(w, r)
			return
		}

		action := vellaveto.Action{
			Tool:     toolName,
			Function: r.Header.Get("X-Tool-Function"),
		}

		// Parse target paths (comma-separated).
		if paths := r.Header.Get("X-Tool-Target-Path"); paths != "" {
			action.TargetPaths = splitAndTrim(paths)
		}

		// Parse target domains (comma-separated).
		if domains := r.Header.Get("X-Tool-Target-Domain"); domains != "" {
			action.TargetDomains = splitAndTrim(domains)
		}

		// Build evaluation context from request metadata.
		evalCtx := &vellaveto.EvaluationContext{
			SessionID: r.Header.Get("X-Session-ID"),
			AgentID:   r.Header.Get("X-Agent-ID"),
		}

		// Use the request context so cancellation propagates.
		ctx := r.Context()

		// Evaluate the action against the policy engine.
		result, err := client.Evaluate(ctx, action, evalCtx, false)
		if err != nil {
			log.Printf("[vellaveto-middleware] evaluation error: %v", err)
			// Fail-closed: return 503 on evaluation errors so the tool call
			// is not silently allowed when the policy engine is unreachable.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "policy evaluation unavailable",
			})
			return
		}

		switch result.Verdict {
		case vellaveto.VerdictAllow:
			// Policy allows the action -- forward to the upstream handler.
			log.Printf("[vellaveto-middleware] ALLOW tool=%s function=%s", action.Tool, action.Function)
			next.ServeHTTP(w, r)

		case vellaveto.VerdictDeny:
			log.Printf("[vellaveto-middleware] DENY tool=%s reason=%s", action.Tool, result.Reason)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":     "policy denied",
				"reason":    result.Reason,
				"policy_id": result.PolicyID,
			})

		case vellaveto.VerdictRequireApproval:
			log.Printf("[vellaveto-middleware] REQUIRE_APPROVAL tool=%s approval_id=%s", action.Tool, result.ApprovalID)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":       "approval required",
				"reason":      result.Reason,
				"approval_id": result.ApprovalID,
			})

		default:
			// Fail-closed: unknown verdict is treated as denied.
			log.Printf("[vellaveto-middleware] UNKNOWN VERDICT tool=%s verdict=%s", action.Tool, result.Verdict)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "policy denied",
			})
		}
	})
}

// toolCallHandler is a sample upstream handler that processes the tool call
// after it has been approved by the Vellaveto middleware.
func toolCallHandler(w http.ResponseWriter, r *http.Request) {
	toolName := r.Header.Get("X-Tool-Name")
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "executed",
		"tool":   toolName,
	})
}

func main() {
	// Read configuration from environment variables.
	serverURL := os.Getenv("VELLAVETO_URL")
	if serverURL == "" {
		serverURL = "http://localhost:3000"
	}
	apiKey := os.Getenv("VELLAVETO_API_KEY")

	// Create the Vellaveto client.
	client, err := vellaveto.NewClient(serverURL,
		vellaveto.WithAPIKey(apiKey),
		vellaveto.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create Vellaveto client: %v", err)
	}

	// Verify connectivity before starting the server.
	health, err := client.Health(context.Background())
	if err != nil {
		log.Fatalf("Cannot reach Vellaveto server at %s: %v", serverURL, err)
	}
	log.Printf("Connected to Vellaveto server: status=%s", health.Status)

	// Wire up the middleware around the tool-call handler.
	mux := http.NewServeMux()
	mux.Handle("/api/tool-call", vellavetoMiddleware(client, http.HandlerFunc(toolCallHandler)))

	addr := ":8080"
	log.Printf("Listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// --- helpers ---

// splitAndTrim splits a comma-separated string and trims whitespace from each element.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[vellaveto-middleware] failed to write response: %v", err)
	}
}
