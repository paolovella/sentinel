# Vellaveto Deployment Guide — SI Partner Kit

## Overview

This guide helps System Integrators deploy Vellaveto for enterprise pilots. Vellaveto is an **Agent Interaction Firewall** that intercepts AI agent tool calls, enforces security policies, and maintains tamper-evident audit trails.

**Target deployment time:** < 2 hours for a single-node evaluation.

---

## Prerequisites

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 512 MB | 2 GB |
| Disk | 1 GB | 10 GB (audit logs) |
| OS | Linux (amd64/arm64) | Ubuntu 22.04+ |
| Container | Docker 20.10+ | K8s 1.27+ with Helm |
| Database | File-based (default) | PostgreSQL 14+ |

---

## Quick Start: Docker

```bash
# 1. Pull the image
docker pull ghcr.io/paolovella/vellaveto:latest

# 2. Create a minimal config
cat > vellaveto.toml <<'EOF'
[server]
bind = "0.0.0.0:3000"
auth_level = "none"  # Use "jwt" for production

[[policies]]
id = "default-deny"
name = "Default Deny"
policy_type = "Deny"
priority = 0

[[policies]]
id = "allow-read"
name = "Allow Read Operations"
policy_type = "Allow"
priority = 100
[policies.tool_match]
tools = ["file_read", "web_search", "database_query"]
EOF

# 3. Run
docker run -d \
  --name vellaveto \
  -p 3000:3000 \
  -v $(pwd)/vellaveto.toml:/etc/vellaveto/vellaveto.toml \
  ghcr.io/paolovella/vellaveto:latest

# 4. Verify
curl http://localhost:3000/health
```

---

## Kubernetes Deployment (Helm)

```bash
# 1. Add the Helm repo
helm repo add vellaveto https://vellaveto.github.io/vellaveto-helm
helm repo update

# 2. Install with default values
helm install vellaveto vellaveto/vellaveto \
  --namespace vellaveto \
  --create-namespace \
  --set server.replicas=3 \
  --set postgresql.enabled=true

# 3. Verify
kubectl -n vellaveto get pods
kubectl -n vellaveto port-forward svc/vellaveto 3000:3000
curl http://localhost:3000/health
```

### Kubernetes Operator (CRDs)

For production deployments, use the Vellaveto operator with custom resources:

```yaml
apiVersion: vellaveto.io/v1alpha1
kind: VellavetoCluster
metadata:
  name: production
spec:
  replicas: 3
  version: "5.0.0"
  postgresql:
    host: "pg-primary.db.svc"
    database: "vellaveto"
    secretRef:
      name: vellaveto-pg-credentials
---
apiVersion: vellaveto.io/v1alpha1
kind: VellavetoPolicy
metadata:
  name: banking-policy
spec:
  clusterRef: production
  content: |
    id = "banking-strict"
    name = "Banking Compliance"
    policy_type = "Deny"
    priority = 200
    [tool_match]
    blocked_domains = ["*.pastebin.com", "*.transfer.sh"]
    [path_rules]
    blocked_paths = ["/etc/**", "/var/log/**"]
```

---

## Enterprise IAM Integration

### OIDC (Okta / Azure AD / Keycloak)

```toml
[iam.oidc]
issuer = "https://your-idp.example.com"
client_id = "vellaveto-admin"
client_secret_env = "OIDC_CLIENT_SECRET"
redirect_uri = "https://vellaveto.internal/iam/callback"
scopes = ["openid", "profile", "email"]
```

### SAML 2.0

```toml
[iam.saml]
entity_id = "https://vellaveto.internal/saml/metadata"
acs_url = "https://vellaveto.internal/iam/saml/acs"
metadata_url = "https://your-idp.example.com/saml/metadata"
```

### RBAC Roles

| Role | Permissions |
|------|------------|
| `admin` | Full access: policies, IAM, billing, settings |
| `operator` | Policy CRUD, approvals, agent management |
| `auditor` | Read-only audit logs, compliance reports |
| `viewer` | Dashboard, agent inventory (read-only) |

---

## SDK Integration

### Python (LangChain / CrewAI / Google ADK / OpenAI Agents)

```bash
pip install vellaveto-sdk[all]
```

```python
from vellaveto import VellavetoClient
from vellaveto.langchain import VellavetoCallbackHandler
from vellaveto.crewai import VellavetoCrewGuard
from vellaveto.google_adk import VellavetoADKGuard
from vellaveto.openai_agents import VellavetoAgentGuard

client = VellavetoClient(url="https://vellaveto.internal:3000", api_key="sk_...")
```

### Java / TypeScript / Go

```bash
# Java (Gradle)
implementation 'com.vellaveto:vellaveto-sdk:6.0.0'

# TypeScript (npm)
npm install @vellaveto-sdk/typescript

# Go
go get github.com/paolovella/vellaveto/sdk/go
```

### Terraform

```hcl
terraform {
  required_providers {
    vellaveto = {
      source  = "vellaveto/vellaveto"
      version = "~> 1.0"
    }
  }
}

provider "vellaveto" {
  api_url   = "https://vellaveto.internal:3000"
  api_key   = var.vellaveto_api_key
  tenant_id = "acme-corp"
}
```

---

## Compliance Frameworks

Vellaveto ships with built-in compliance mapping for:

| Framework | Controls | Auto-Evidence |
|-----------|----------|---------------|
| **DORA** (ICT Risk) | 23 articles | Evidence packs |
| **NIS2** (Cybersecurity) | 18 measures | Evidence packs |
| **EU AI Act** | Art 10-50 | Risk classification, Art 12 records |
| **ISO 42001** | 15 controls | AI management evidence |
| **SOC 2 Type II** | CC1-CC9 | Access reviews, control evidence |
| **OWASP ASI** | ASI01-ASI10 | Threat coverage matrix |

Generate evidence packs:
```bash
curl https://vellaveto.internal:3000/api/compliance/evidence-pack?framework=dora -o dora-evidence.zip
```

---

## Monitoring

### OpenTelemetry

```toml
[observability]
otlp_endpoint = "http://otel-collector:4317"
service_name = "vellaveto"
```

### Prometheus Metrics

Metrics available at `/metrics` (requires authentication):
- `vellaveto_evaluations_total` — total policy evaluations
- `vellaveto_evaluations_denied` — denied evaluations
- `vellaveto_evaluation_latency_seconds` — P50/P99 latency
- `vellaveto_active_policies` — loaded policy count
- `vellaveto_audit_entries_total` — audit log entries

---

## Demo Script (30 minutes)

See `DEMO_SCRIPT.md` for a step-by-step pilot demonstration covering:
1. Deploy and verify health (5 min)
2. Create allow/deny policies (5 min)
3. Evaluate tool calls via API and SDK (5 min)
4. Admin console walkthrough (5 min)
5. Compliance report generation (5 min)
6. Audit log verification (5 min)
