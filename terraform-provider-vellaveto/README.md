# Terraform Provider for Vellaveto

Terraform provider for managing [Vellaveto](https://github.com/paolovella/vellaveto) policies and configuration as code.

## Installation

```hcl
terraform {
  required_providers {
    vellaveto = {
      source  = "vellaveto/vellaveto"
      version = "~> 6.0"
    }
  }
}

provider "vellaveto" {
  endpoint = "http://localhost:3000"  # or VELLAVETO_ENDPOINT env var
  api_key  = var.vellaveto_api_key    # or VELLAVETO_API_KEY env var
}
```

## Resources

### `vellaveto_policy`

```hcl
resource "vellaveto_policy" "restrict_filesystem" {
  name          = "restrict-filesystem"
  policy_type   = "tool"
  tool_pattern  = "filesystem.*"
  priority      = 100

  path_rules {
    allowed_paths = ["/home/user/project/**"]
    blocked_paths = ["/etc/**", "/root/**", "**/.ssh/**", "**/.aws/**"]
  }

  network_rules {
    allowed_domains = ["api.example.com"]
    blocked_domains = ["*.ngrok.io", "*.evil.com"]
  }
}
```

## Data Sources

### `vellaveto_health`

```hcl
data "vellaveto_health" "status" {}

output "server_status" {
  value = data.vellaveto_health.status.status
}
```

### `vellaveto_policies`

```hcl
data "vellaveto_policies" "all" {}

output "policy_count" {
  value = length(data.vellaveto_policies.all.policies)
}
```

## Authentication

The provider accepts credentials via:

1. Provider block attributes (`endpoint`, `api_key`)
2. Environment variables (`VELLAVETO_ENDPOINT`, `VELLAVETO_API_KEY`)

## Development

```bash
go build -o terraform-provider-vellaveto
go test ./...

# Install locally for testing
make install
```

## Tests

```bash
# Unit tests
go test ./...

# Acceptance tests (requires running Vellaveto server)
TF_ACC=1 go test ./... -v
```

## License

See [LICENSING.md](../LICENSING.md) for repository licensing details.
