# Vellaveto Operations Runbook

This runbook covers day-to-day operations, monitoring, troubleshooting, and maintenance procedures for Vellaveto deployments.

## Table of Contents

- [Monitoring](#monitoring)
  - [Prometheus Metrics](#prometheus-metrics)
  - [Key Metrics to Watch](#key-metrics-to-watch)
  - [Alerting Rules](#alerting-rules)
  - [Grafana Dashboard](#grafana-dashboard)
- [Troubleshooting](#troubleshooting)
  - [Service Won't Start](#service-wont-start)
  - [High Latency](#high-latency)
  - [High Deny Rate](#high-deny-rate)
  - [Audit Log Issues](#audit-log-issues)
  - [Clustering Issues](#clustering-issues)
- [Maintenance](#maintenance)
  - [Policy Updates](#policy-updates)
  - [Log Rotation](#log-rotation)
  - [Backup Procedures](#backup-procedures)
  - [Version Upgrades](#version-upgrades)
- [Common Tasks](#common-tasks)
  - [Checking Service Health](#checking-service-health)
  - [Viewing Recent Decisions](#viewing-recent-decisions)
  - [Managing Approvals](#managing-approvals)
  - [Exporting Audit Logs](#exporting-audit-logs)
- [Emergency Procedures](#emergency-procedures)
  - [Service Degradation](#service-degradation)
  - [Security Incident Response](#security-incident-response)

---

## Monitoring

### Prometheus Metrics

Vellaveto exposes Prometheus metrics at the `/metrics` endpoint. All metrics use the `vellaveto_` prefix.

#### Core Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vellaveto_evaluations_total` | counter | Total policy evaluations (labels: verdict, tool, tenant_id) |
| `vellaveto_evaluation_duration_seconds` | histogram | Policy evaluation latency |
| `vellaveto_policies_loaded` | gauge | Number of loaded policies |
| `vellaveto_uptime_seconds` | gauge | Server uptime |

#### Security Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vellaveto_dlp_findings_total` | counter | DLP findings detected (label: pattern_type) |
| `vellaveto_injection_detections_total` | counter | Injection attempts (label: injection_type) |
| `vellaveto_rug_pull_detections_total` | counter | Tool rug-pull attacks detected |
| `vellaveto_squatting_detections_total` | counter | Tool squatting attempts |
| `vellaveto_anomaly_detections_total` | counter | Behavioral anomalies detected |

#### Session & Auth Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vellaveto_active_sessions` | gauge | Currently active sessions |
| `vellaveto_auth_failures_total` | counter | Authentication failures (label: reason) |
| `vellaveto_rate_limit_rejections_total` | counter | Rate limit rejections |

#### Audit Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vellaveto_audit_entries_total` | counter | Audit log entries written |
| `vellaveto_audit_acis_entries_total` | counter | Entries with ACIS decision envelopes |
| `vellaveto_audit_checkpoint_total` | counter | Audit checkpoints created |
| `vellaveto_audit_rotation_total` | counter | Audit log rotations |

#### Network Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vellaveto_dns_resolutions_total` | counter | DNS resolutions (label: status) |
| `vellaveto_dns_resolution_duration_seconds` | histogram | DNS resolution latency |
| `vellaveto_blocked_ips_total` | counter | Blocked IP addresses |

#### Observability Exporter Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vellaveto_exporter_events_total` | counter | Events sent to observability exporters (label: backend) |
| `vellaveto_exporter_errors_total` | counter | Exporter delivery errors (label: backend) |
| `vellaveto_exporter_latency_seconds` | histogram | Exporter delivery latency (label: backend) |

#### Cluster Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vellaveto_cluster_backend_latency_seconds` | histogram | Cluster backend latency (label: operation) |

### AI Observability Exporters

Vellaveto can stream `SecuritySpan` events to AI observability platforms in real time:

| Backend | Description | Configuration Key |
|---------|-------------|-------------------|
| **Langfuse** | Open-source LLM observability | `observability.langfuse` |
| **Arize Phoenix** | ML observability and monitoring | `observability.arize` |
| **Helicone** | LLM proxy and analytics | `observability.helicone` |
| **Webhook** | Generic HTTP webhook for custom pipelines | `observability.webhook` |

Example configuration:

```toml
[observability]
enabled = true

[observability.langfuse]
enabled = true
endpoint = "https://cloud.langfuse.com"
public_key_env = "LANGFUSE_PUBLIC_KEY"
secret_key_env = "LANGFUSE_SECRET_KEY"

[observability.arize]
enabled = true
endpoint = "https://api.arize.com"
api_key_env = "ARIZE_API_KEY"
space_key_env = "ARIZE_SPACE_KEY"

[observability.webhook]
enabled = true
url = "https://your-pipeline.example.com/ingest"
batch_size = 50
flush_interval_secs = 10
```

Each exporter receives `SecuritySpan` events containing:
- Tool name, function, and verdict
- Detection results (injection, DLP, anomaly scores)
- Evaluation latency and policy chain
- Session and agent context

### Key Metrics to Watch

#### Performance SLIs

```promql
# P99 evaluation latency (should be <5ms)
histogram_quantile(0.99, rate(vellaveto_evaluation_duration_seconds_bucket[5m]))

# Evaluation throughput
rate(vellaveto_evaluations_total[5m])

# Error rate (deny due to errors, not policy)
rate(vellaveto_evaluations_total{verdict="error"}[5m]) / rate(vellaveto_evaluations_total[5m])
```

#### Security SLIs

```promql
# Injection detection rate
rate(vellaveto_injection_detections_total[5m])

# DLP finding rate
rate(vellaveto_dlp_findings_total[5m])

# Anomaly detection rate
rate(vellaveto_anomaly_detections_total[5m])
```

### Alerting Rules

Example Prometheus alerting rules:

```yaml
# prometheus-rules.yaml

groups:
  - name: vellaveto
    rules:
      # Service health
      - alert: VellavetoDown
        expr: up{job="vellaveto"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Vellaveto is down"
          description: "Vellaveto instance {{ $labels.instance }} has been down for more than 1 minute."

      # High latency
      - alert: VellavetoHighLatency
        expr: histogram_quantile(0.99, rate(vellaveto_evaluation_duration_seconds_bucket[5m])) > 0.010
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Vellaveto P99 latency is high"
          description: "P99 evaluation latency is {{ $value | humanizeDuration }} (threshold: 10ms)"

      # High error rate
      - alert: VellavetoHighErrorRate
        expr: rate(vellaveto_evaluations_total{verdict="error"}[5m]) / rate(vellaveto_evaluations_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Vellaveto error rate is high"
          description: "Error rate is {{ $value | humanizePercentage }} (threshold: 1%)"

      # Security: High injection rate
      - alert: VellavetoHighInjectionRate
        expr: rate(vellaveto_injection_detections_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High injection detection rate"
          description: "Detecting {{ $value }} injections per second. Possible attack in progress."

      # Security: Rug-pull detected
      - alert: VellavetoRugPullDetected
        expr: increase(vellaveto_rug_pull_detections_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Rug-pull attack detected"
          description: "A tool schema change (rug-pull attack) was detected. Review immediately."

      # Security: Anomaly spike
      - alert: VellavetoAnomalySpike
        expr: increase(vellaveto_anomaly_detections_total[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Behavioral anomaly spike"
          description: "{{ $value }} anomalies detected in 5 minutes. Investigate agent behavior."

      # Rate limiting active
      - alert: VellavetoRateLimiting
        expr: rate(vellaveto_rate_limit_rejections_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High rate limit rejections"
          description: "Rate limiting {{ $value }} requests/second. Possible abuse or misconfiguration."

      # Auth failures
      - alert: VellavetoAuthFailures
        expr: rate(vellaveto_auth_failures_total[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }} auth failures/second. Possible credential stuffing attack."

      # Cluster backend latency
      - alert: VellavetoClusterLatency
        expr: histogram_quantile(0.99, rate(vellaveto_cluster_backend_latency_seconds_bucket[5m])) > 0.100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Cluster backend latency is high"
          description: "Redis latency is {{ $value | humanizeDuration }}. Check Redis health."
```

### Grafana Dashboard

A sample Grafana dashboard JSON is available at `examples/grafana-dashboard.json`. Import it via:

1. Navigate to Grafana > Dashboards > Import
2. Upload the JSON file or paste its contents
3. Select your Prometheus data source
4. Click Import

Key panels:
- **Evaluation Rate**: Requests per second by verdict
- **Latency**: P50, P95, P99 latency over time
- **Security Events**: Injection, DLP, anomaly detections
- **Error Rate**: Percentage of error verdicts
- **Policies**: Number of loaded policies over time

---

## Troubleshooting

### Service Won't Start

#### Symptoms
- Service exits immediately after starting
- "Address already in use" error
- Configuration parse errors

#### Diagnosis

```bash
# Check service status
sudo systemctl status vellaveto

# View startup logs
sudo journalctl -u vellaveto -n 50 --no-pager

# Validate configuration
vellaveto check --config /etc/vellaveto/config.toml

# Check for port conflicts
sudo lsof -i :3000
```

#### Common Causes

| Error | Cause | Solution |
|-------|-------|----------|
| `Address already in use` | Port 3000 is taken | Change port or stop conflicting service |
| `TOML parse error` | Invalid config syntax | Run `vellaveto check --config` to find the issue |
| `Config file '...' is empty` | Empty or whitespace-only config file | Ensure the config file has content, then re-run `vellaveto check --config` |
| `unsupported extension` | Config file is not `.toml` or `.json` | Rename/convert to `.toml` or `.json` and re-run `vellaveto check --config` |
| `Policy compilation error` | Invalid regex/glob | Check policy patterns in config |
| `Permission denied` | Wrong file permissions | Ensure vellaveto user can read config |

#### Resolution

```bash
# Fix permissions
sudo chown vellaveto:vellaveto /etc/vellaveto/config.toml
sudo chmod 640 /etc/vellaveto/config.toml

# Change port (in config.toml or command line)
# bind = "0.0.0.0:3001"

# Restart after fixing
sudo systemctl restart vellaveto
```

### High Latency

#### Symptoms
- P99 latency > 10ms
- Slow API responses
- Timeouts in client applications

#### Diagnosis

```bash
# Check current latency
curl -s localhost:3000/metrics | grep vellaveto_evaluation_duration

# Check CPU and memory
top -p $(pgrep vellaveto)

# Check for policy complexity
vellaveto stats --config /etc/vellaveto/config.toml
```

#### Common Causes

| Cause | Indicator | Solution |
|-------|-----------|----------|
| Complex regex patterns | High CPU during evaluation | Simplify regex, use glob where possible |
| Too many policies | High policy_compilation_errors | Consolidate policies |
| Redis latency (clustering) | High cluster_backend_latency | Check Redis, reduce round-trips |
| DNS resolution | High dns_resolution_duration | Use local DNS cache |

#### Resolution

```bash
# Profile policy evaluation (if built with profiling)
VELLAVETO_PROFILE=1 vellaveto serve --config /etc/vellaveto/config.toml

# Optimize Redis (if using clustering)
# Reduce key TTL, use pipelining, check network

# Enable local DNS caching
sudo systemctl enable --now systemd-resolved
```

### High Deny Rate

#### Symptoms
- Many legitimate requests being denied
- Users reporting access issues
- High `vellaveto_evaluations_total{verdict="deny"}`

#### Diagnosis

```bash
# Check recent denials in audit log
grep '"verdict":"deny"' /var/lib/vellaveto/audit.log | tail -20

# Check which policies are matching
curl -s localhost:3000/metrics | grep vellaveto_policy_matches_total

# Test a specific action
curl -X POST localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool": "file_read", "function": "read", "parameters": {"path": "/tmp/test"}}'
```

#### Common Causes

| Cause | Indicator | Solution |
|-------|-----------|----------|
| Overly restrictive policy | Single policy_id has most matches | Review and adjust policy |
| Missing allow policy | No allow policies matching | Add appropriate allow rules |
| Glob pattern too broad | Policy matches unintended tools | Narrow the pattern |
| Priority ordering issue | Wrong policy evaluated first | Adjust priorities |

#### Resolution

```bash
# Temporarily disable a policy (add to config)
# [[policies]]
# name = "Temporary disable"
# tool_pattern = "problematic_tool"
# policy_type = "Allow"
# priority = 999  # Higher than blocking policy

# Hot reload policies
curl -X POST localhost:3000/api/policies/reload

# Or restart
sudo systemctl restart vellaveto
```

### Audit Log Issues

#### Symptoms
- Audit log file growing too large
- Log file corruption
- Missing audit entries

#### Diagnosis

```bash
# Check log file size
ls -lh /var/lib/vellaveto/audit.log

# Verify log integrity
vellaveto audit verify --path /var/lib/vellaveto/audit.log

# Check disk space
df -h /var/lib/vellaveto

# Check recent entries
tail -10 /var/lib/vellaveto/audit.log
```

#### Common Causes

| Cause | Indicator | Solution |
|-------|-----------|----------|
| No log rotation | File > 1GB | Configure logrotate |
| Disk full | df shows 100% | Clean old logs, add disk |
| Hash chain broken | verify fails | Investigate, may need manual repair |
| Write permission | Entries missing | Fix permissions |

#### Resolution

```bash
# Manual rotation
cd /var/lib/vellaveto
mv audit.log audit.log.$(date +%Y%m%d)
sudo systemctl restart vellaveto

# Configure logrotate
cat > /etc/logrotate.d/vellaveto << 'EOF'
/var/lib/vellaveto/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

# Clean old logs
find /var/lib/vellaveto -name "audit.log.*" -mtime +30 -delete
```

### Clustering Issues

#### Symptoms
- Approvals not syncing across instances
- Redis connection errors in logs
- Inconsistent state between replicas

#### Diagnosis

```bash
# Check Redis connectivity
redis-cli -h redis-host -p 6379 PING

# Check cluster backend latency
curl -s localhost:3000/metrics | grep vellaveto_cluster_backend

# Check Redis memory
redis-cli -h redis-host INFO memory

# List Vellaveto keys in Redis
redis-cli -h redis-host KEYS "vellaveto:*"
```

#### Common Causes

| Cause | Indicator | Solution |
|-------|-----------|----------|
| Redis unreachable | Connection refused | Check Redis, firewall rules |
| Network partition | Intermittent failures | Check network, use closer Redis |
| Redis OOM | Memory errors | Increase Redis memory, add eviction |
| Key expiry | Stale data | Adjust TTLs in config |

#### Resolution

```bash
# Test Redis connection
redis-cli -h redis-host -p 6379 PING

# Check and increase Redis max memory
redis-cli -h redis-host CONFIG GET maxmemory
redis-cli -h redis-host CONFIG SET maxmemory 256mb

# Clear stale Vellaveto keys (use with caution)
redis-cli -h redis-host KEYS "vellaveto:*" | xargs redis-cli -h redis-host DEL
```

---

## Maintenance

### Policy Updates

#### Hot Reload (No Downtime)

```bash
# Edit policies
sudo vim /etc/vellaveto/config.toml

# Trigger hot reload
curl -X POST localhost:3000/api/policies/reload

# Verify new policy count
curl -s localhost:3000/metrics | grep vellaveto_policies_loaded
```

#### Full Restart (If Hot Reload Fails)

```bash
# Validate first
vellaveto check --config /etc/vellaveto/config.toml

# Restart
sudo systemctl restart vellaveto

# Verify health
curl localhost:3000/health
```

### Log Rotation

Configure automatic rotation:

```bash
# /etc/logrotate.d/vellaveto

/var/lib/vellaveto/audit.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    postrotate
        # Signal Vellaveto to reopen log file (if supported)
        systemctl kill -s HUP vellaveto || true
    endscript
}

/var/log/vellaveto/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

### Backup Procedures

#### What to Back Up

| Item | Location | Frequency |
|------|----------|-----------|
| Configuration | `/etc/vellaveto/` | On change |
| Audit logs | `/var/lib/vellaveto/audit.log*` | Daily |
| Manifest (if pinning) | `/etc/vellaveto/manifest.json` | On change |
| Approval state | Redis or `/var/lib/vellaveto/approvals/` | Hourly |

#### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/vellaveto-backup.sh

BACKUP_DIR="/backup/vellaveto/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Config
cp -r /etc/vellaveto "$BACKUP_DIR/config"

# Audit logs (compress recent)
cp /var/lib/vellaveto/audit.log "$BACKUP_DIR/"
gzip "$BACKUP_DIR/audit.log"

# Approval state
if [ -d /var/lib/vellaveto/approvals ]; then
    cp -r /var/lib/vellaveto/approvals "$BACKUP_DIR/"
fi

# Checksum
sha256sum "$BACKUP_DIR"/* > "$BACKUP_DIR/checksums.sha256"

echo "Backup completed: $BACKUP_DIR"
```

### Version Upgrades

#### Pre-Upgrade Checklist

- [ ] Read release notes for breaking changes
- [ ] Back up configuration and data
- [ ] Test upgrade in staging environment
- [ ] Schedule maintenance window
- [ ] Notify dependent teams

#### Upgrade Procedure

```bash
# 1. Back up
/usr/local/bin/vellaveto-backup.sh

# 2. Stop service
sudo systemctl stop vellaveto

# 3. Download + verify + install (the script SHA-256-verifies every binary
#    against the published checksums file before writing it).
#    Pin VELLAVETO_VERSION to the version you're upgrading to.
sudo curl -fsSL https://raw.githubusercontent.com/paolovella/vellaveto/main/scripts/install.sh \
  | sudo VELLAVETO_INSTALL_DIR=/usr/local/bin \
         VELLAVETO_BINARY=vellaveto \
         VELLAVETO_VERSION=6.1.1 \
         VELLAVETO_FORCE=1 sh

# 4. Validate config with new version
vellaveto check --config /etc/vellaveto/config.toml

# 5. Start service
sudo systemctl start vellaveto

# 6. Verify health
curl localhost:3000/health
curl -s localhost:3000/metrics | head -20
```

#### Rollback

```bash
# Stop service
sudo systemctl stop vellaveto

# Restore previous binary
sudo cp /backup/vellaveto/vellaveto.bak /usr/local/bin/vellaveto

# Restore config if changed
sudo cp -r /backup/vellaveto/config/* /etc/vellaveto/

# Start service
sudo systemctl start vellaveto
```

---

## Common Tasks

### Checking Service Health

```bash
# Quick health check
curl localhost:3000/health

# Detailed status
curl localhost:3000/ready

# Full metrics
curl localhost:3000/metrics

# Service status
sudo systemctl status vellaveto
```

### Viewing Recent Decisions

```bash
# Last 10 decisions
tail -10 /var/lib/vellaveto/audit.log | jq .

# Filter by verdict
grep '"verdict":"deny"' /var/lib/vellaveto/audit.log | tail -5 | jq .

# Filter by tool
grep '"tool":"bash"' /var/lib/vellaveto/audit.log | tail -5 | jq .

# Count decisions by verdict (last 1000 entries)
tail -1000 /var/lib/vellaveto/audit.log | jq -r '.verdict' | sort | uniq -c
```

### Managing Approvals

```bash
# List pending approvals
curl localhost:3000/api/approvals | jq .

# Approve a request
curl -X POST localhost:3000/api/approvals/{id}/approve \
  -H "Content-Type: application/json" \
  -d '{"approved_by": "operator@example.com"}'

# Deny a request
curl -X POST localhost:3000/api/approvals/{id}/deny \
  -H "Content-Type: application/json" \
  -d '{"denied_by": "operator@example.com", "reason": "Not authorized"}'
```

### Exporting Audit Logs

```bash
# Export to JSON Lines
curl "localhost:3000/api/audit/export?format=jsonl&start=$(date -d '1 hour ago' +%s)" > audit-export.jsonl

# Export to CEF (Common Event Format)
curl "localhost:3000/api/audit/export?format=cef" > audit-export.cef

# Export with redaction
curl "localhost:3000/api/audit/export?format=jsonl&redact=high" > audit-redacted.jsonl
```

---

## Emergency Procedures

### Service Degradation

If Vellaveto is degrading but not completely down:

1. **Assess impact**
   ```bash
   curl -s localhost:3000/metrics | grep -E "(evaluations_total|evaluation_duration)"
   ```

2. **Check resource usage**
   ```bash
   top -p $(pgrep vellaveto)
   ```

3. **Enable bypass mode (if critical)**

   Edit config to add a high-priority allow-all policy:
   ```toml
   [[policies]]
   name = "Emergency bypass"
   tool_pattern = "*"
   function_pattern = "*"
   policy_type = "Allow"
   priority = 9999
   ```

   Then reload:
   ```bash
   curl -X POST localhost:3000/api/policies/reload
   ```

4. **Investigate root cause** while traffic flows

5. **Remove bypass policy** once resolved

### Security Incident Response

If Vellaveto detects a potential attack:

1. **Assess the alert**
   ```bash
   # Check recent security events
   curl -s localhost:3000/metrics | grep -E "(injection|rug_pull|squatting|anomaly)"

   # Review audit log for details
   grep -E "(injection_detected|rug_pull|squatting)" /var/lib/vellaveto/audit.log | tail -20 | jq .
   ```

2. **Identify affected agents/tools**
   ```bash
   # Extract agent IDs from suspicious events
   grep '"injection_detected":true' /var/lib/vellaveto/audit.log | jq -r '.agent_id' | sort -u
   ```

3. **Isolate if necessary**

   Add blocking policy for specific agent:
   ```toml
   [[policies]]
   name = "Block compromised agent"
   tool_pattern = "*"
   function_pattern = "*"
   priority = 1000

   [policies.policy_type.Conditional.conditions]
   on_no_match = "continue"
   context_constraints = [
     { key = "agent_id", value = "compromised-agent-123", on_match = "deny" }
   ]
   ```

4. **Preserve evidence**
   ```bash
   # Copy current audit log
   cp /var/lib/vellaveto/audit.log /backup/incident-$(date +%Y%m%d%H%M%S).log

   # Export recent entries
   tail -10000 /var/lib/vellaveto/audit.log > /backup/incident-recent.jsonl
   ```

5. **Notify security team** with relevant logs and metrics

6. **Document timeline and actions taken**

---

## Contact and Escalation

| Issue Type | Primary Contact | Escalation |
|------------|-----------------|------------|
| Service down | On-call SRE | Infrastructure lead |
| Security alert | Security team | CISO |
| Policy questions | Platform team | Security architect |
| Bug/feature | GitHub issues | Maintainers |

---

## Related Documentation

- [Deployment Guide](./DEPLOYMENT.md) - Installation and configuration
- [Security Hardening](./SECURITY.md) - Security best practices
- [API Reference](./API.md) - Complete API documentation
