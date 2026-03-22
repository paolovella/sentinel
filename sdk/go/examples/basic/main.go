// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 Vellaveto Contributors

// Package main demonstrates basic usage of the Vellaveto Go SDK.
//
// This example creates a client, checks server health, evaluates a tool call
// against the policy engine, and handles the three possible verdict outcomes:
// Allow, Deny, and RequireApproval.
//
// Usage:
//
//	export VELLAVETO_URL=http://localhost:3000
//	export VELLAVETO_API_KEY=your-api-key
//	go run .
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	vellaveto "github.com/paolovella/vellaveto/sdk/go"
)

func main() {
	// Read configuration from environment variables.
	serverURL := os.Getenv("VELLAVETO_URL")
	if serverURL == "" {
		serverURL = "http://localhost:3000"
	}
	apiKey := os.Getenv("VELLAVETO_API_KEY")

	// Create a client with an API key and a custom timeout.
	client, err := vellaveto.NewClient(serverURL,
		vellaveto.WithAPIKey(apiKey),
		vellaveto.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// --- Health check ---
	health, err := client.Health(ctx)
	if err != nil {
		log.Fatalf("Health check failed: %v", err)
	}
	fmt.Printf("Server status: %s (version: %s)\n\n", health.Status, health.Version)

	// --- Evaluate a file-read action ---
	// Build an Action describing the tool call an AI agent wants to make.
	action := vellaveto.Action{
		Tool:        "filesystem",
		Function:    "read_file",
		Parameters:  map[string]interface{}{"path": "/data/reports/q4.csv"},
		TargetPaths: []string{"/data/reports/q4.csv"},
	}

	// Optionally attach session/agent context for context-aware policies.
	evalCtx := &vellaveto.EvaluationContext{
		SessionID: "sess-abc-123",
		AgentID:   "data-analyst-agent",
		TenantID:  "acme-corp",
	}

	// Evaluate the action. The fourth argument enables trace output.
	result, err := client.Evaluate(ctx, action, evalCtx, false)
	if err != nil {
		log.Fatalf("Evaluate failed: %v", err)
	}

	// Handle the verdict.
	switch result.Verdict {
	case vellaveto.VerdictAllow:
		fmt.Printf("ALLOWED: Tool %q is permitted.\n", action.Tool)
		fmt.Printf("  Policy: %s (%s)\n", result.PolicyName, result.PolicyID)
	case vellaveto.VerdictDeny:
		fmt.Printf("DENIED: Tool %q was blocked.\n", action.Tool)
		fmt.Printf("  Reason: %s\n", result.Reason)
		fmt.Printf("  Policy: %s (%s)\n", result.PolicyName, result.PolicyID)
	case vellaveto.VerdictRequireApproval:
		fmt.Printf("APPROVAL REQUIRED: Tool %q needs human approval.\n", action.Tool)
		fmt.Printf("  Reason: %s\n", result.Reason)
		fmt.Printf("  Approval ID: %s\n", result.ApprovalID)
	}

	fmt.Println()

	// --- EvaluateOrError: typed-error pattern ---
	// EvaluateOrError returns nil on Allow, and typed errors on Deny or
	// RequireApproval. This is convenient when you only need to proceed on Allow.
	err = client.EvaluateOrError(ctx, vellaveto.Action{
		Tool:          "http",
		Function:      "fetch",
		Parameters:    map[string]interface{}{"url": "https://api.example.com/data"},
		TargetDomains: []string{"api.example.com"},
	}, evalCtx)

	if err == nil {
		fmt.Println("HTTP fetch allowed -- proceeding with request.")
	} else {
		switch e := err.(type) {
		case *vellaveto.PolicyDeniedError:
			fmt.Printf("HTTP fetch denied: %s (policy: %s)\n", e.Reason, e.PolicyID)
		case *vellaveto.ApprovalRequiredError:
			fmt.Printf("HTTP fetch needs approval: %s (id: %s)\n", e.Reason, e.ApprovalID)
		default:
			log.Fatalf("Unexpected error: %v", err)
		}
	}

	fmt.Println()

	// --- List loaded policies ---
	policies, err := client.ListPolicies(ctx)
	if err != nil {
		log.Fatalf("ListPolicies failed: %v", err)
	}
	fmt.Printf("Loaded policies (%d):\n", len(policies))
	for _, p := range policies {
		fmt.Printf("  [%d] %s (%s) -- %s\n", p.Priority, p.Name, p.ID, p.PolicyType)
	}
}
