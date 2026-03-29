// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure PolicyResource satisfies resource.Resource.
var _ resource.Resource = &PolicyResource{}
var _ resource.ResourceWithConfigure = &PolicyResource{}

// PolicyResource manages a Vellaveto policy.
type PolicyResource struct {
	client *APIClient
}

// PolicyResourceModel describes the resource data model.
type PolicyResourceModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	PolicyType types.String `tfsdk:"policy_type"`
	Priority   types.Int64  `tfsdk:"priority"`
	Content    types.String `tfsdk:"content"`
}

func NewPolicyResource() resource.Resource {
	return &PolicyResource{}
}

func (r *PolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *PolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Vellaveto security policy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Policy unique identifier.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Human-readable policy name.",
				Required:    true,
			},
			"policy_type": schema.StringAttribute{
				Description: "Policy type: Allow, Deny, or Conditional.",
				Required:    true,
			},
			"priority": schema.Int64Attribute{
				Description: "Policy evaluation priority (higher = evaluated first).",
				Required:    true,
			},
			"content": schema.StringAttribute{
				Description: "Policy definition in TOML format.",
				Required:    true,
				// R262-TF-1: Mark as sensitive to prevent leakage in state files
				// and plan output. Policy definitions may contain security-critical
				// path patterns, domain allowlists, and configuration details.
				Sensitive: true,
			},
		},
	}
}

func (r *PolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*APIClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *APIClient, got: %T", req.ProviderData),
		)
		return
	}
	r.client = client
}

func (r *PolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PolicyResourceModel
	diags := req.Plan.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]interface{}{
		"name":        data.Name.ValueString(),
		"policy_type": data.PolicyType.ValueString(),
		"priority":    data.Priority.ValueInt64(),
		"content":     data.Content.ValueString(),
	}

	result, err := r.client.doJSON(ctx, http.MethodPost, "/api/policies", body)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create policy", err.Error())
		return
	}

	if id, ok := result["id"].(string); ok {
		data.ID = types.StringValue(id)
	}

	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
}

func (r *PolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PolicyResourceModel
	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := fmt.Sprintf("/api/policies/%s", url.PathEscape(data.ID.ValueString()))
	result, err := r.client.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read policy", err.Error())
		return
	}

	if name, ok := result["name"].(string); ok {
		data.Name = types.StringValue(name)
	}
	if pt, ok := result["policy_type"].(string); ok {
		data.PolicyType = types.StringValue(pt)
	}
	if p, ok := result["priority"].(float64); ok {
		data.Priority = types.Int64Value(int64(p))
	}

	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
}

func (r *PolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PolicyResourceModel
	diags := req.Plan.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]interface{}{
		"name":        data.Name.ValueString(),
		"policy_type": data.PolicyType.ValueString(),
		"priority":    data.Priority.ValueInt64(),
		"content":     data.Content.ValueString(),
	}

	path := fmt.Sprintf("/api/policies/%s", url.PathEscape(data.ID.ValueString()))
	_, err := r.client.doJSON(ctx, http.MethodPut, path, body)
	if err != nil {
		resp.Diagnostics.AddError("Failed to update policy", err.Error())
		return
	}

	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
}

func (r *PolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PolicyResourceModel
	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := fmt.Sprintf("/api/policies/%s", url.PathEscape(data.ID.ValueString()))
	err := r.client.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		resp.Diagnostics.AddError("Failed to delete policy", err.Error())
		return
	}
}

// doJSON sends a JSON request and returns the parsed response body.
func (c *APIClient) doJSON(ctx context.Context, method, path string, body interface{}) (map[string]interface{}, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	if c.TenantID != "" {
		req.Header.Set("X-Tenant-ID", c.TenantID)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	// Limit response body to 10MB
	limited := io.LimitReader(resp.Body, 10*1024*1024)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, truncate(string(respBody), 256))
	}

	if len(respBody) == 0 {
		return nil, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return result, nil
}

// doRequest sends a request without parsing the response body.
func (c *APIClient) doRequest(ctx context.Context, method, path string, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	if c.TenantID != "" {
		req.Header.Set("X-Tenant-ID", c.TenantID)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited := io.LimitReader(resp.Body, 256)
		b, _ := io.ReadAll(limited)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
