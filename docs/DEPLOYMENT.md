# Vellaveto Deployment Guide

This guide covers deploying the Vellaveto agent interaction firewall in production environments using Docker, Kubernetes (Helm), or bare metal installations.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
  - [Single Container](#single-container)
  - [Docker Compose](#docker-compose)
- [Kubernetes Deployment](#kubernetes-deployment)
  - [Using Helm](#using-helm)
  - [Custom Values](#custom-values)
  - [High Availability](#high-availability)
  - [Kubernetes Operator (CRDs)](#kubernetes-operator-crds)
- [Bare Metal Deployment](#bare-metal-deployment)
  - [Building from Source](#building-from-source)
  - [Systemd Service](#systemd-service)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Policy Configuration](#policy-configuration)
- [Health Checks](#health-checks)
- [TLS/HTTPS](#tlshttps)
- [Production Checklist](#production-checklist)

---

## Prerequisites

### Hardware Requirements

| Deployment | CPU | Memory | Disk |
|------------|-----|--------|------|
| Minimum | 1 core | 64 MB | 100 MB |
| Recommended | 2 cores | 128 MB | 1 GB |
| High-traffic | 4+ cores | 256 MB | 10 GB |

Vellaveto is designed for low resource usage: <5ms P99 evaluation latency and <50MB memory baseline.

### Software Requirements

- **Docker**: 20.10+ (for containerized deployment)
- **Kubernetes**: 1.25+ with Helm 3.10+ (for K8s deployment)
- **Rust**: 1.82+ (for building from source)

---

## Quick Start

### Stdio Proxy (local MCP servers, Claude Desktop, Cursor)

The fastest way to protect a local MCP server — no config file needed:

```bash
# One-command install (no Rust toolchain needed; SHA-256 verified):
curl -fsSL https://raw.githubusercontent.com/paolovella/vellaveto/main/scripts/install.sh | sh

# Or from source:
cargo install vellaveto-proxy

vellaveto-proxy --protect shield -- npx @modelcontextprotocol/server-filesystem /tmp
```

Three protection levels: `shield` (8 policies — credentials, SANDWORM defense, exfil blocking, system files), `fortress` (11 policies — adds package config protection, sudo approval, memory tracking), `vault` (11 policies — deny-by-default, source reads allowed, writes need approval). See [CLI Reference](CLI.md) for details.

### HTTP Server (Docker)

```bash
docker run -p 3000:3000 ghcr.io/paolovella/vellaveto:latest
curl http://localhost:3000/health
```

---

## Docker Deployment

### Single Container

#### Pull and Run

```bash
# Pull the latest image
docker pull ghcr.io/paolovella/vellaveto:latest

# Run with default configuration
docker run -d \
  --name vellaveto \
  -p 3000:3000 \
  ghcr.io/paolovella/vellaveto:latest

# Run with custom configuration
docker run -d \
  --name vellaveto \
  -p 3000:3000 \
  -v /path/to/config.toml:/etc/vellaveto/config.toml:ro \
  -v /path/to/policies:/etc/vellaveto/policies:ro \
  -v vellaveto-data:/var/lib/vellaveto \
  ghcr.io/paolovella/vellaveto:latest
```

#### Build from Source

```bash
# Clone the repository
git clone https://github.com/paolovella/vellaveto.git
cd vellaveto

# Build the Docker image
docker build -t vellaveto:local .

# Run your local build
docker run -d \
  --name vellaveto \
  -p 3000:3000 \
  vellaveto:local
```

### Docker Compose

Create a `docker-compose.yml`:

```yaml
version: "3.8"

services:
  vellaveto:
    image: ghcr.io/paolovella/vellaveto:latest
    container_name: vellaveto
    ports:
      - "3000:3000"
    volumes:
      - ./config.toml:/etc/vellaveto/config.toml:ro
      - ./policies:/etc/vellaveto/policies:ro
      - vellaveto-data:/var/lib/vellaveto
      - vellaveto-logs:/var/log/vellaveto
    environment:
      - RUST_LOG=info
      - VELLAVETO_STRICT_MODE=true
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:3000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped
    # Security: run as non-root
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp

volumes:
  vellaveto-data:
  vellaveto-logs:
```

With Redis for clustering:

```yaml
version: "3.8"

services:
  vellaveto:
    image: ghcr.io/paolovella/vellaveto:latest
    ports:
      - "3000:3000"
    volumes:
      - ./config.toml:/etc/vellaveto/config.toml:ro
    environment:
      - RUST_LOG=info
      - VELLAVETO_CLUSTER_ENABLED=true
      - VELLAVETO_REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped

volumes:
  redis-data:
```

---

## Kubernetes Deployment

### Using Helm

```bash
# Add the Helm repository (if published)
# helm repo add vellaveto https://charts.vellaveto.online
# helm repo update

# Or install from local chart
helm install vellaveto ./helm/vellaveto \
  --namespace vellaveto \
  --create-namespace

# Check deployment status
kubectl -n vellaveto get pods
kubectl -n vellaveto get svc
```

### Custom Values

Create a `values-production.yaml`:

```yaml
# Production values for Vellaveto

replicaCount: 3

image:
  repository: ghcr.io/paolovella/vellaveto
  tag: "6.0.0"
  pullPolicy: IfNotPresent

# Resource limits
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 64Mi

# Enable autoscaling
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

# Ingress configuration
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1s"
  hosts:
    - host: vellaveto.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vellaveto-tls
      hosts:
        - vellaveto.example.com

# Vellaveto configuration
vellaveto:
  logLevel: info
  strictMode: true

  injection:
    enabled: true
    blocking: true

  dlp:
    enabled: true
    blocking: true

  audit:
    redactionLevel: "High"

# Enable Prometheus metrics
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 15s
    labels:
      release: prometheus

# Pod disruption budget
podDisruptionBudget:
  enabled: true
  minAvailable: 2

# Anti-affinity for HA
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: vellaveto
          topologyKey: kubernetes.io/hostname
```

Deploy with custom values:

```bash
helm upgrade --install vellaveto ./helm/vellaveto \
  --namespace vellaveto \
  --create-namespace \
  -f values-production.yaml
```

### High Availability

For HA deployments, enable clustering with Redis:

```yaml
# values-ha.yaml

replicaCount: 3

vellaveto:
  cluster:
    enabled: true
    backend: redis
    redisUrl: redis://redis-master.redis.svc.cluster.local:6379

# External Redis (use Bitnami chart or managed Redis)
redis:
  enabled: false  # Use external Redis
```

Deploy Redis first (example using Bitnami):

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install redis bitnami/redis \
  --namespace vellaveto \
  --set auth.enabled=false \
  --set architecture=standalone
```

### Kubernetes Operator (CRDs)

Phase 49 adds an optional Kubernetes operator that enables declarative management of Vellaveto via Custom Resource Definitions. The operator watches three CRDs and reconciles them against the Vellaveto server REST API.

#### Install CRDs and Operator

```bash
# Install CRDs (always required first)
kubectl apply -f helm/vellaveto/crds/

# Deploy with operator enabled
helm upgrade --install vellaveto ./helm/vellaveto \
  --namespace vellaveto \
  --create-namespace \
  --set operator.enabled=true
```

#### Declare a Cluster

```yaml
apiVersion: vellaveto.io/v1alpha1
kind: VellavetoCluster
metadata:
  name: production
  namespace: vellaveto
spec:
  replicas: 3
  image: ghcr.io/paolovella/vellaveto:6.0.0
  config:
    security_mode: strict
    audit_enabled: true
    dora_enabled: true
  resources:
    cpu_request: "250m"
    memory_request: "256Mi"
    cpu_limit: "1"
    memory_limit: "512Mi"
```

#### Declare a Policy

```yaml
apiVersion: vellaveto.io/v1alpha1
kind: VellavetoPolicy
metadata:
  name: deny-bash
  namespace: vellaveto
spec:
  clusterRef: production
  policy:
    id: deny-bash
    name: "Deny all bash commands"
    policyType: Deny
    priority: 100
    pathRules:
      blocked:
        - "/bin/bash"
        - "/bin/sh"
```

#### Declare a Tenant

```yaml
apiVersion: vellaveto.io/v1alpha1
kind: VellavetoTenant
metadata:
  name: acme-corp
  namespace: vellaveto
spec:
  clusterRef: production
  tenantId: acme-corp
  name: "ACME Corporation"
  enabled: true
  quotas:
    maxEvaluationsPerMinute: 5000
    maxPolicies: 100
  metadata:
    env: production
    team: platform
```

#### Monitor Resources

```bash
kubectl get vellavetoclusters -n vellaveto
kubectl get vellavetopolicies -n vellaveto
kubectl get vellavetotenants -n vellaveto
```

The operator is optional — existing Helm chart deployments are unaffected when `operator.enabled` is `false` (default).

---

## Bare Metal Deployment

### Building from Source

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/paolovella/vellaveto.git
cd vellaveto

# Build release binaries
cargo build --release

# Binaries are in target/release/
ls -la target/release/vellaveto
ls -la target/release/vellaveto-http-proxy

# Install to system
sudo cp target/release/vellaveto /usr/local/bin/
sudo cp target/release/vellaveto-http-proxy /usr/local/bin/

# Verify installation
vellaveto --version
```

### Directory Structure

```bash
# Create directories
sudo mkdir -p /etc/vellaveto
sudo mkdir -p /var/lib/vellaveto
sudo mkdir -p /var/log/vellaveto

# Create vellaveto user
sudo useradd -r -s /sbin/nologin vellaveto
sudo chown -R vellaveto:vellaveto /var/lib/vellaveto /var/log/vellaveto

# Copy configuration
sudo cp examples/production.toml /etc/vellaveto/config.toml
sudo chmod 640 /etc/vellaveto/config.toml
```

### Systemd Service

Create `/etc/systemd/system/vellaveto.service`:

```ini
[Unit]
Description=Vellaveto Agent Interaction Firewall
Documentation=https://github.com/paolovella/vellaveto
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vellaveto
Group=vellaveto
ExecStart=/usr/local/bin/vellaveto serve \
    --config /etc/vellaveto/config.toml \
    --bind 0.0.0.0:3000
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vellaveto /var/log/vellaveto
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Resource limits
MemoryMax=256M
CPUQuota=200%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vellaveto

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable vellaveto

# Start the service
sudo systemctl start vellaveto

# Check status
sudo systemctl status vellaveto

# View logs
sudo journalctl -u vellaveto -f
```

### HTTP Proxy Mode (Systemd)

Create `/etc/systemd/system/vellaveto-http-proxy.service`:

```ini
[Unit]
Description=Vellaveto HTTP Proxy
Documentation=https://github.com/paolovella/vellaveto
After=network-online.target vellaveto.service
Wants=network-online.target

[Service]
Type=simple
User=vellaveto
Group=vellaveto
ExecStart=/usr/local/bin/vellaveto-http-proxy \
    --listen 0.0.0.0:3000 \
    --vellaveto http://localhost:3000 \
    --upstream http://localhost:9000
Restart=on-failure
RestartSec=5

# Security hardening (same as above)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level (trace, debug, info, warn, error) | `info` |
| `VELLAVETO_STRICT_MODE` | Deny unknown tools by default | `false` |
| `VELLAVETO_CONFIG` | Path to config file | `/etc/vellaveto/config.toml` |
| `VELLAVETO_BIND` | Listen address | `0.0.0.0:3000` |
| `VELLAVETO_API_KEY` | API key for admin endpoints | (none) |
| `VELLAVETO_CLUSTER_ENABLED` | Enable distributed clustering | `false` |
| `VELLAVETO_REDIS_URL` | Redis URL for clustering | (none) |

### Policy Configuration

Policies can be defined in the config file or loaded from a directory:

> Loader guardrails (fail-closed):
> - Config files must be non-empty (whitespace-only files are rejected).
> - Supported extensions are `.toml` and `.json` only.
> - Files larger than 10 MB are rejected before parsing.

```toml
# In config.toml

# Inline policy
[[policies]]
name = "Block credential access"
tool_pattern = "*"
function_pattern = "*"
priority = 300

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**", on_match = "deny" },
]

# Or load from directory
[policies]
directory = "/etc/vellaveto/policies.d"
watch = true  # Hot reload on changes
```

---

## Health Checks

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness check (returns 200 if running) |
| `/ready` | GET | Readiness check (returns 200 if ready to serve) |
| `/metrics` | GET | Prometheus metrics |

### Example Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/vellaveto-healthcheck.sh

set -e

VELLAVETO_URL="${VELLAVETO_URL:-http://localhost:3000}"

# Check health endpoint
response=$(curl -s -o /dev/null -w "%{http_code}" "${VELLAVETO_URL}/health")

if [ "$response" != "200" ]; then
    echo "Health check failed: HTTP $response"
    exit 1
fi

echo "Vellaveto is healthy"
exit 0
```

---

## TLS/HTTPS

Vellaveto itself serves plain HTTP. For TLS termination, use a reverse proxy:

For staged post-quantum TLS policy rollout when Vellaveto terminates TLS directly, see `./quantum-migration.md`.

### With Nginx

```nginx
# /etc/nginx/conf.d/vellaveto.conf

upstream vellaveto {
    server 127.0.0.1:3000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name vellaveto.example.com;

    ssl_certificate /etc/ssl/certs/vellaveto.crt;
    ssl_certificate_key /etc/ssl/private/vellaveto.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://vellaveto;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
}
```

### With Caddy

```caddyfile
# Caddyfile

vellaveto.example.com {
    reverse_proxy localhost:3000 {
        health_uri /health
        health_interval 30s
    }
}
```

---

## Production Checklist

Before going to production, verify:

### Security
- [ ] API key configured for admin endpoints (`VELLAVETO_API_KEY`)
- [ ] Running as non-root user
- [ ] TLS termination configured
- [ ] Audit logging enabled with appropriate redaction
- [ ] Rate limiting configured
- [ ] `strictMode` enabled (deny unknown tools)

### Reliability
- [ ] Health checks configured in orchestrator
- [ ] Restart policy set (systemd `Restart=on-failure` or K8s `restartPolicy`)
- [ ] Resource limits defined
- [ ] Multiple replicas for HA (if using K8s)
- [ ] Redis configured for clustering (if multiple instances)

### Observability
- [ ] Logs shipping to centralized logging
- [ ] Prometheus metrics endpoint exposed
- [ ] Alerts configured for:
  - High error rate
  - Elevated latency (P99 > 10ms)
  - Policy evaluation failures
  - Approval queue depth

### Operations
- [ ] Backup strategy for audit logs
- [ ] Runbook documented for common issues
- [ ] Policy hot-reload tested
- [ ] Rollback procedure documented

### Example Pre-flight Check

```bash
#!/bin/bash
# pre-flight-check.sh

echo "=== Vellaveto Pre-flight Check ==="

# Check binary
if ! command -v vellaveto &> /dev/null; then
    echo "[FAIL] vellaveto binary not found"
    exit 1
fi
echo "[OK] vellaveto binary installed"

# Check config
if [ ! -f /etc/vellaveto/config.toml ]; then
    echo "[FAIL] Config file not found"
    exit 1
fi
echo "[OK] Config file exists"

# Validate config
if ! vellaveto check --config /etc/vellaveto/config.toml; then
    echo "[FAIL] Config validation failed"
    exit 1
fi
echo "[OK] Config is valid"

# Check directories
for dir in /var/lib/vellaveto /var/log/vellaveto; do
    if [ ! -d "$dir" ]; then
        echo "[FAIL] Directory $dir not found"
        exit 1
    fi
    if [ ! -w "$dir" ]; then
        echo "[FAIL] Directory $dir not writable"
        exit 1
    fi
done
echo "[OK] Data directories exist and are writable"

# Check API key
if [ -z "$VELLAVETO_API_KEY" ]; then
    echo "[WARN] VELLAVETO_API_KEY not set - admin endpoints unprotected"
else
    echo "[OK] API key configured"
fi

echo ""
echo "=== All checks passed ==="
```

---

## Next Steps

- [Operations Runbook](./OPERATIONS.md) - Monitoring, troubleshooting, maintenance
- [Security Hardening Guide](./SECURITY.md) - Advanced security configuration
- [API Reference](./API.md) - Complete API documentation
