// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

// Package provider implements the Vellaveto Terraform provider.
package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure VellavetoProvider satisfies the provider.Provider interface.
var _ provider.Provider = &VellavetoProvider{}

// VellavetoProvider implements the Vellaveto Terraform provider.
type VellavetoProvider struct {
	version string
}

// VellavetoProviderModel describes the provider data model.
type VellavetoProviderModel struct {
	APIURL   types.String `tfsdk:"api_url"`
	APIKey   types.String `tfsdk:"api_key"`
	TenantID types.String `tfsdk:"tenant_id"`
	Timeout  types.Int64  `tfsdk:"timeout"`
}

// APIClient wraps HTTP communication with the Vellaveto server.
type APIClient struct {
	BaseURL    string
	APIKey     string
	TenantID   string
	HTTPClient *http.Client
}

// String returns a human-readable representation with the API key redacted.
// SECURITY (R257-TF-2): Prevents API key leakage in logs and debug output.
func (c *APIClient) String() string {
	return fmt.Sprintf("APIClient{BaseURL: %q, APIKey: [REDACTED]}", c.BaseURL)
}

// GoString implements fmt.GoStringer for %#v formatting with the API key redacted.
// SECURITY (R257-TF-2): Prevents API key leakage via fmt.Fprintf(w, "%#v", client).
func (c *APIClient) GoString() string {
	return c.String()
}

// validateAPIURL validates a base URL for the Vellaveto API.
// SECURITY (R257-TF-1): Rejects non-http(s) schemes, missing hosts, and userinfo.
func validateAPIURL(rawURL string) error {
	trimmed := strings.TrimRight(rawURL, "/")
	if trimmed == "" {
		return fmt.Errorf("api_url must not be empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("api_url is not a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("api_url must use http:// or https:// scheme")
	}
	if parsed.Host == "" {
		return fmt.Errorf("api_url must include a host")
	}
	if parsed.User != nil {
		return fmt.Errorf("api_url must not contain credentials (user:pass@host)")
	}
	return nil
}

// New creates a new provider factory function.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &VellavetoProvider{version: version}
	}
}

func (p *VellavetoProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vellaveto"
	resp.Version = p.version
}

func (p *VellavetoProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for Vellaveto MCP Firewall — manage policies, tenants, and agent discovery.",
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				Description: "The URL of the Vellaveto server API (e.g., https://vellaveto.example.com).",
				Required:    true,
			},
			"api_key": schema.StringAttribute{
				Description: "API key for authentication with the Vellaveto server.",
				Required:    true,
				Sensitive:   true,
			},
			"tenant_id": schema.StringAttribute{
				Description: "Default tenant ID for multi-tenant deployments.",
				Optional:    true,
			},
			"timeout": schema.Int64Attribute{
				Description: "HTTP request timeout in seconds (default: 30).",
				Optional:    true,
			},
		},
	}
}

func (p *VellavetoProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config VellavetoProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.APIURL.IsUnknown() || config.APIURL.IsNull() {
		resp.Diagnostics.AddError(
			"Missing API URL",
			"The provider requires api_url to be configured.",
		)
		return
	}

	if config.APIKey.IsUnknown() || config.APIKey.IsNull() {
		resp.Diagnostics.AddError(
			"Missing API Key",
			"The provider requires api_key to be configured.",
		)
		return
	}

	// SECURITY (R257-TF-1): Validate base URL before creating the client.
	// Matches the Go SDK validation pattern (FIND-R46-GO-004, FIND-R67-SDK-003).
	rawURL := strings.TrimRight(config.APIURL.ValueString(), "/")
	if err := validateAPIURL(rawURL); err != nil {
		resp.Diagnostics.AddError(
			"Invalid API URL",
			err.Error(),
		)
		return
	}

	timeout := int64(30)
	if !config.Timeout.IsNull() && !config.Timeout.IsUnknown() {
		timeout = config.Timeout.ValueInt64()
		if timeout < 1 || timeout > 300 {
			resp.Diagnostics.AddError(
				"Invalid Timeout",
				fmt.Sprintf("timeout must be between 1 and 300 seconds, got %d", timeout),
			)
			return
		}
	}

	client := &APIClient{
		BaseURL:  rawURL,
		APIKey:   config.APIKey.ValueString(),
		TenantID: config.TenantID.ValueString(),
		HTTPClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			// SECURITY (R257-TF-1): Strip Authorization header on cross-domain redirects
			// to prevent API key leakage to third-party hosts.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				// Reject redirects to non-HTTP(S) schemes.
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
				}
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					// Cross-domain redirect: strip Authorization to prevent API key leak.
					req.Header.Del("Authorization")
				}
				return nil
			},
		},
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *VellavetoProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewPolicyResource,
	}
}

func (p *VellavetoProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewPoliciesDataSource,
		NewHealthDataSource,
	}
}
