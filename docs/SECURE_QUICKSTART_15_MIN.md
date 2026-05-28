# 15-Minute Secure Start

This guide walks through a minimal end-to-end security flow:

1. start Vellaveto with deny-by-default policy
2. execute one allowed and one denied tool call
3. verify audit trail integrity

## Prerequisites

- Vellaveto installed (one-liner: `curl -fsSL https://raw.githubusercontent.com/paolovella/vellaveto/main/scripts/install.sh | sh` — or build from source with `cargo`)
- `curl` and `jq`
- free local port `3000`

## 1) Create a deny-by-default policy

Create `policy.toml`:

```toml
[[policies]]
name = "Allow file reads in /tmp"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 100
[policies.path_rules]
allowed_globs = ["/tmp/**"]

[[policies]]
name = "Default deny"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Deny"
priority = 0
```

## 2) Run Vellaveto

```bash
export VELLAVETO_API_KEY="$(openssl rand -hex 32)"
vellaveto serve --config policy.toml --port 3000
# Or from source: cargo run -p vellaveto-server -- serve --config policy.toml --port 3000
```

Keep this terminal open.

## 3) Trigger one allow and one deny

In a second terminal:

```bash
# Allowed: /tmp is explicitly allowlisted
curl -s http://localhost:3000/api/evaluate \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/tmp/demo.txt"}}' | jq .

# Denied: /etc is not allowlisted, falls through to default deny
curl -s http://localhost:3000/api/evaluate \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/etc/passwd"}}' | jq .
```

Expected outcome:

- first response verdict is `Allow`
- second response verdict is `Deny`

## 4) Verify audit integrity

```bash
curl -s http://localhost:3000/api/audit/verify \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" | jq .
```

Expected outcome:

- `"valid": true`
- `"first_broken_at": null`

Optional checkpoint signature verification:

```bash
curl -s http://localhost:3000/api/audit/checkpoints/verify \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" | jq .
```

## 5) Success criteria

You have validated the core security loop:

- complete mediation of tool calls
- fail-closed deny-by-default behavior
- tamper-evident audit verification
