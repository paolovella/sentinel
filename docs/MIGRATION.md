# Migration Guide: Vellaveto v1.x to v2.0

This guide covers upgrading from Vellaveto v1.x to v2.0, including breaking changes, new features, and step-by-step instructions.

## Table of Contents

- [Overview](#overview)
- [Breaking Changes](#breaking-changes)
- [New Features](#new-features)
- [Step-by-Step Upgrade](#step-by-step-upgrade)
- [Configuration Changes](#configuration-changes)
- [API Changes](#api-changes)
- [Rollback Procedure](#rollback-procedure)

---

## Overview

Vellaveto v2.0 is a major release that adds significant new capabilities while maintaining backward compatibility for core functionality.

**Upgrade Path:** v1.x → v2.0 (direct upgrade supported)

**Estimated Downtime:** 1-5 minutes (depends on deployment method)

**Risk Level:** Low (no breaking changes to core evaluation API)

---

## Breaking Changes

### None for Core Functionality

Vellaveto v2.0 maintains full backward compatibility for:
- Policy file format (TOML/JSON)
- `/api/evaluate` endpoint request/response format
- Policy evaluation semantics
- Audit log format

### Deprecated Features

The following features are deprecated and will be removed in v3.0:

| Feature | Deprecated | Alternative |
|---------|------------|-------------|
| `--log-level` CLI flag | v2.0 | Use `RUST_LOG` environment variable |
| `api_key` in config file | v2.0 | Use `VELLAVETO_API_KEY` environment variable |

### Changed Defaults

| Setting | v1.x Default | v2.0 Default | Reason |
|---------|--------------|--------------|--------|
| `strict_mode` | `false` | `true` | Fail-closed by default |
| `rate_limit.evaluate` | Unlimited | 1000 req/s | DoS protection |
| `rate_limit.admin` | Unlimited | 20 req/s | DoS protection |

To restore v1.x behavior:

```toml
# config.toml
strict_mode = false

[rate_limit]
evaluate = 0  # Disabled
admin = 0     # Disabled
```

> Current loader hardening (as of 2026-02-19): config files must be non-empty,
> and only `.toml` or `.json` files are accepted by `PolicyConfig::load_file`.
> Use `vellaveto check --config <file>` to validate before rollout.

---

## New Features

### Phase 1: MCP 2025-11-25 Compliance

- **Async Tasks:** Policy enforcement for long-running operations
- **Resource Indicators:** OAuth RFC 8707 support
- **Step-Up Authentication:** Configurable auth level requirements

### Phase 2: Advanced Threat Detection

- **Circuit Breaker:** Cascading failure protection
- **Shadow Agent Detection:** Agent impersonation prevention
- **Schema Poisoning Detection:** Tool schema mutation alerts
- **Sampling Attack Detection:** LLM sampling abuse prevention

### Phase 3: Cross-Agent Security

- **Agent Trust Graph:** Multi-agent trust tracking
- **Privilege Escalation Detection:** Cross-agent attack prevention
- **Message Signing:** Ed25519 inter-agent integrity

### Phase 4: Standards Alignment

- **MITRE ATLAS:** 14 technique mappings
- **OWASP AIVSS:** AI vulnerability scoring
- **NIST AI RMF:** Compliance reporting

### Phase 5: Enterprise Features

- **mTLS/SPIFFE:** Zero-trust workload identity
- **OPA Integration:** External policy evaluation
- **Threat Intelligence:** TAXII/MISP feed integration
- **JIT Access:** Temporary elevated permissions

### Phase 6: Observability

- **Execution Graphs:** Visual call chain analysis
- **Policy Validation CLI:** `vellaveto check` enhancements
- **Attack Simulation:** Red-teaming framework

---

## Step-by-Step Upgrade

### Pre-Upgrade Checklist

- [ ] Backup current configuration
- [ ] Backup audit logs
- [ ] Note current version: `vellaveto --version`
- [ ] Review breaking changes above
- [ ] Test upgrade in staging environment

### Docker Upgrade

```bash
# 1. Stop current container
docker stop vellaveto

# 2. Backup configuration
docker cp vellaveto:/etc/vellaveto/config.toml ./config-backup.toml

# 3. Pull new image
docker pull ghcr.io/paolovella/vellaveto:2.0.0

# 4. Start with new image
docker run -d --name vellaveto-v2 \
  -p 3000:3000 \
  -v /path/to/config.toml:/etc/vellaveto/config.toml:ro \
  -v /path/to/audit:/var/log/vellaveto \
  ghcr.io/paolovella/vellaveto:2.0.0

# 5. Verify health
curl http://localhost:3000/health

# 6. Test evaluation
curl -X POST http://localhost:3000/api/evaluate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"test","function":"ping"}'

# 7. Remove old container (after verification)
docker rm vellaveto
docker rename vellaveto-v2 vellaveto
```

### Kubernetes/Helm Upgrade

```bash
# 1. Backup current values
helm get values vellaveto -n vellaveto > values-backup.yaml

# 2. Update Helm repository
helm repo update

# 3. Review changes
helm diff upgrade vellaveto ./helm/vellaveto \
  -n vellaveto \
  -f values.yaml

# 4. Perform upgrade
helm upgrade vellaveto ./helm/vellaveto \
  -n vellaveto \
  -f values.yaml \
  --set image.tag=2.0.0

# 5. Monitor rollout
kubectl rollout status deployment/vellaveto -n vellaveto

# 6. Verify pods
kubectl get pods -n vellaveto
```

### Binary Upgrade

```bash
# 1. Stop service
sudo systemctl stop vellaveto

# 2. Backup binary
sudo cp /usr/local/bin/vellaveto /usr/local/bin/vellaveto.v1.backup

# 3. Download new binary
curl -L https://github.com/paolovella/vellaveto/releases/download/v2.0.0/vellaveto-linux-amd64 \
  -o /tmp/vellaveto

# 4. Verify checksum
sha256sum /tmp/vellaveto
# Compare with published checksum

# 5. Install
sudo mv /tmp/vellaveto /usr/local/bin/vellaveto
sudo chmod +x /usr/local/bin/vellaveto

# 6. Verify version
vellaveto --version
# Expected: vellaveto 2.0.0

# 7. Start service
sudo systemctl start vellaveto

# 8. Check status
sudo systemctl status vellaveto
```

---

## Configuration Changes

### New Configuration Sections

The following configuration sections are new in v2.0:

```toml
# ═══════════════════════════════════════════════════════════════
# Phase 1: MCP 2025-11-25 Compliance (Optional)
# ═══════════════════════════════════════════════════════════════

[async_tasks]
enabled = false
max_task_duration = "1h"
max_concurrent_tasks = 100

[step_up_auth]
enabled = false
default_level = "basic"
sensitive_tools = ["bash", "file_write"]

# ═══════════════════════════════════════════════════════════════
# Phase 2: Advanced Threat Detection (Optional)
# ═══════════════════════════════════════════════════════════════

[circuit_breaker]
enabled = false
failure_threshold = 5
success_threshold = 3
open_duration_secs = 30

[shadow_agent]
enabled = false
require_fingerprint = false

[schema_poisoning]
enabled = false
similarity_threshold = 0.9

[sampling_detection]
enabled = false
max_requests_per_session = 100

# ═══════════════════════════════════════════════════════════════
# Phase 3: Cross-Agent Security (Optional)
# ═══════════════════════════════════════════════════════════════

[cross_agent]
enabled = false
max_chain_depth = 5
require_message_signing = false

# ═══════════════════════════════════════════════════════════════
# Phase 5: Enterprise Features (Optional)
# ═══════════════════════════════════════════════════════════════

[tls]
enabled = false
cert_path = "/etc/vellaveto/tls/server.crt"
key_path = "/etc/vellaveto/tls/server.key"

[mtls]
enabled = false
client_ca_path = "/etc/vellaveto/tls/ca.crt"

[opa]
enabled = false
endpoint = "http://localhost:8181"
decision_path = "/v1/data/vellaveto/allow"

[threat_intel]
enabled = false
# providers = [...]

[jit_access]
enabled = false
default_ttl_secs = 3600
```

### Minimal Upgrade Configuration

For a minimal upgrade with no new features:

```toml
# config.toml - v2.0 minimal (v1.x compatible)

# Restore v1.x defaults
strict_mode = false

[rate_limit]
evaluate = 0
admin = 0
readonly = 0

# Your existing policies...
[[policies]]
# ...
```

### Recommended Configuration

For a recommended upgrade with key v2.0 features:

```toml
# config.toml - v2.0 recommended

strict_mode = true  # Fail-closed (new default)

# Rate limiting (new defaults - recommended)
[rate_limit]
evaluate = 1000
admin = 20
readonly = 200

# Enable circuit breaker for stability
[circuit_breaker]
enabled = true
failure_threshold = 5

# Enable schema poisoning detection
[schema_poisoning]
enabled = true
similarity_threshold = 0.9

# Your existing policies...
[[policies]]
# ...
```

---

## API Changes

### New Endpoints

v2.0 adds many new API endpoints. All are optional and disabled by default:

| Endpoint | Feature | Enable With |
|----------|---------|-------------|
| `/api/circuit-breaker/*` | Circuit Breaker | `circuit_breaker.enabled = true` |
| `/api/shadow-agents/*` | Shadow Agent Detection | `shadow_agent.enabled = true` |
| `/api/schema-lineage/*` | Schema Poisoning | `schema_poisoning.enabled = true` |
| `/api/tasks/*` | Async Tasks | `async_tasks.enabled = true` |
| `/api/auth-levels/*` | Step-Up Auth | `step_up_auth.enabled = true` |
| `/api/sampling/*` | Sampling Detection | `sampling_detection.enabled = true` |
| `/api/deputy/*` | Deputy Delegation | `cross_agent.enabled = true` |
| `/api/graphs/*` | Execution Graphs | `exec_graphs.enabled = true` |

### Response Format Additions

The `/api/evaluate` response may include additional fields (backward compatible):

```json
{
  "verdict": { "Allow": {} },
  "action": { "tool": "file_read", "function": "read" },

  // New optional fields in v2.0:
  "detection_results": {
    "injection_detected": false,
    "dlp_findings": [],
    "anomaly_score": 0.1
  },
  "policy_chain": ["policy-1", "policy-2"],
  "evaluation_time_ms": 2
}
```

### CLI Changes

New CLI commands and options:

```bash
# New: Policy validation with enhanced checks
vellaveto check --config config.toml --strict --format json

# New: Attack simulation
vellaveto simulate --scenario prompt-injection --config config.toml

# Enhanced: Evaluate with context
vellaveto evaluate --tool bash --function execute \
  --params '{"command":"ls"}' \
  --context '{"agent_id":"agent-1"}' \
  --config config.toml
```

---

## Rollback Procedure

If issues occur after upgrade:

### Docker Rollback

```bash
# Stop v2.0 container
docker stop vellaveto

# Start v1.x container
docker run -d --name vellaveto \
  -p 3000:3000 \
  -v /path/to/config-backup.toml:/etc/vellaveto/config.toml:ro \
  ghcr.io/paolovella/vellaveto:1.0.0
```

### Kubernetes Rollback

```bash
# Rollback to previous revision
helm rollback vellaveto -n vellaveto

# Or specify revision
helm rollback vellaveto 1 -n vellaveto
```

### Binary Rollback

```bash
# Stop service
sudo systemctl stop vellaveto

# Restore backup
sudo mv /usr/local/bin/vellaveto.v1.backup /usr/local/bin/vellaveto

# Start service
sudo systemctl start vellaveto
```

---

## Post-Upgrade Validation

Run these checks after upgrading:

```bash
# 1. Version check
vellaveto --version
# Expected: vellaveto 2.0.0

# 2. Health check
curl http://localhost:3000/health
# Expected: {"status":"healthy"}

# 3. Policy validation
vellaveto check --config /etc/vellaveto/config.toml

# 4. Test evaluation
curl -X POST http://localhost:3000/api/evaluate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"file_read","function":"read","parameters":{"path":"/tmp/test.txt"}}'

# 5. Audit log check
curl http://localhost:3000/api/audit/entries?limit=10 \
  -H "Authorization: Bearer $API_KEY"

# 6. Metrics check
curl http://localhost:3000/metrics \
  -H "Authorization: Bearer $API_KEY"
```

---

## Support

If you encounter issues during migration:

1. Check the [troubleshooting guide](./OPERATIONS.md#troubleshooting)
2. Search [GitHub Issues](https://github.com/paolovella/vellaveto/issues)
3. Open a new issue with:
   - Source version
   - Target version
   - Configuration (redacted)
   - Error messages
   - Logs
