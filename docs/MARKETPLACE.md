# Cloud Marketplace Deployment Guide

Deploy Vellaveto on major cloud marketplaces for self-service customer onboarding.

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│  Cloud Marketplace (AWS/Azure/GCP)              │
│  ┌───────────────┐  ┌─────────────────────────┐ │
│  │ Listing Page   │  │ Billing Integration     │ │
│  │ (SaaS/BYOL)   │  │ (Paddle/Stripe webhook) │ │
│  └───────┬───────┘  └────────────┬────────────┘ │
│          │                       │               │
│          ▼                       ▼               │
│  ┌───────────────────────────────────────────┐   │
│  │          POST /api/signup                  │   │
│  │  (self-service tenant provisioning)        │   │
│  └───────────────────┬───────────────────────┘   │
│                      │                           │
│  ┌───────────────────▼───────────────────────┐   │
│  │         Vellaveto Server                   │   │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────┐ │   │
│  │  │ Policies │ │  Audit   │ │   Usage    │ │   │
│  │  │  Engine  │ │ Logger   │ │  Tracker   │ │   │
│  │  └──────────┘ └──────────┘ └────────────┘ │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

---

## AWS Marketplace

### Deployment Model: ECS Fargate + SaaS Contract

**Prerequisites:**
- AWS Marketplace seller account
- ECR repository for container image
- Route 53 hosted zone (optional, for custom domain)

### 1. Container Image

```bash
# Build and push to ECR
aws ecr get-login-password --region eu-south-1 | \
  docker login --username AWS --password-stdin <account>.dkr.ecr.eu-south-1.amazonaws.com

docker build -t vellaveto-server .
docker tag vellaveto-server:latest <account>.dkr.ecr.eu-south-1.amazonaws.com/vellaveto:latest
docker push <account>.dkr.ecr.eu-south-1.amazonaws.com/vellaveto:latest
```

### 2. ECS Task Definition

```json
{
  "family": "vellaveto-server",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [{
    "name": "vellaveto",
    "image": "<account>.dkr.ecr.eu-south-1.amazonaws.com/vellaveto:latest",
    "portMappings": [{"containerPort": 3000, "protocol": "tcp"}],
    "environment": [
      {"name": "VELLAVETO_PORT", "value": "3000"},
      {"name": "VELLAVETO_MULTI_TENANT", "value": "true"},
      {"name": "VELLAVETO_BILLING_ENABLED", "value": "true"}
    ],
    "secrets": [
      {"name": "VELLAVETO_API_KEY", "valueFrom": "arn:aws:secretsmanager:eu-south-1:<account>:secret:vellaveto/api-key"},
      {"name": "VELLAVETO_PADDLE_WEBHOOK_SECRET", "valueFrom": "arn:aws:secretsmanager:eu-south-1:<account>:secret:vellaveto/paddle-secret"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/vellaveto",
        "awslogs-region": "eu-south-1",
        "awslogs-stream-prefix": "server"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:3000/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3
    }
  }]
}
```

### 3. ALB + Auto Scaling

```bash
# Create ALB target group
aws elbv2 create-target-group \
  --name vellaveto-tg \
  --protocol HTTP \
  --port 3000 \
  --vpc-id vpc-xxx \
  --target-type ip \
  --health-check-path /health

# Create ECS service with auto-scaling
aws ecs create-service \
  --cluster vellaveto \
  --service-name vellaveto-server \
  --task-definition vellaveto-server:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=arn:aws:...,containerName=vellaveto,containerPort=3000"
```

### 4. AWS Marketplace SaaS Integration

```yaml
# marketplace-integration.yaml
product:
  title: "Vellaveto — Agent Interaction Firewall"
  short_description: "Agent interaction firewall for MCP and AI tool calls"
  categories:
    - Security
    - AI/ML
  pricing:
    model: SaaS_Contract
    dimensions:
      - name: evaluations
        description: "Policy evaluations per month"
        unit: "Evaluation"
        tiers:
          - from: 0
            to: 1000
            price: 0.00  # Free tier
          - from: 1001
            to: 50000
            price: 0.001
          - from: 50001
            price: 0.0005
      - name: agents
        description: "Active AI agents"
        unit: "Agent"
        price: 5.00

  fulfillment:
    type: SaaS
    redirect_url: "https://vellaveto.example.com/api/signup"
    metering_endpoint: "https://vellaveto.example.com/api/billing/usage"
```

---

## Azure Marketplace

### Deployment Model: Azure Container Apps

### 1. Container Apps Environment

```bash
# Create resource group (Milan region for EU data residency)
az group create --name vellaveto-rg --location italynorth

# Create Container Apps environment
az containerapp env create \
  --name vellaveto-env \
  --resource-group vellaveto-rg \
  --location italynorth

# Deploy container app
az containerapp create \
  --name vellaveto-server \
  --resource-group vellaveto-rg \
  --environment vellaveto-env \
  --image ghcr.io/paolovella/vellaveto:6.0.0 \
  --target-port 3000 \
  --ingress external \
  --min-replicas 2 \
  --max-replicas 10 \
  --cpu 1.0 \
  --memory 2Gi \
  --env-vars \
    VELLAVETO_PORT=3000 \
    VELLAVETO_MULTI_TENANT=true \
    VELLAVETO_BILLING_ENABLED=true \
  --secrets \
    api-key=<api-key-value> \
    paddle-secret=<paddle-webhook-secret>
```

### 2. Azure Marketplace SaaS Offer

```yaml
# azure-marketplace-offer.yaml
offer:
  id: vellaveto-agentic-control-plane
  display_name: "Vellaveto — Agent Interaction Firewall"
  publisher: vellaveto
  categories:
    - security
    - ai-machine-learning

  plans:
    - id: free
      display_name: "Free"
      description: "Up to 1,000 evaluations/day, 3 agents"
      pricing:
        model: flat_rate
        price: 0

    - id: starter
      display_name: "Starter"
      description: "Up to 50,000 evaluations/day, 20 agents"
      pricing:
        model: flat_rate
        price: 49
        billing_term: monthly

    - id: team
      display_name: "Team"
      description: "Up to 500,000 evaluations/day, 100 agents, SSO"
      pricing:
        model: flat_rate
        price: 299
        billing_term: monthly

    - id: enterprise
      display_name: "Enterprise"
      description: "Unlimited evaluations, SAML/SCIM, dedicated support"
      pricing:
        model: custom
        contact_sales: true

  technical_configuration:
    landing_page_url: "https://vellaveto.example.com/api/signup"
    connection_webhook: "https://vellaveto.example.com/api/billing/azure/webhook"
    tenant_id: "<azure-ad-tenant>"
```

---

## Google Cloud Marketplace

### Deployment Model: Cloud Run

### 1. Cloud Run Service

```bash
# Deploy to Cloud Run (Milan region)
gcloud run deploy vellaveto-server \
  --image ghcr.io/paolovella/vellaveto:6.0.0 \
  --platform managed \
  --region europe-west8 \
  --port 3000 \
  --min-instances 1 \
  --max-instances 20 \
  --memory 2Gi \
  --cpu 2 \
  --set-env-vars "VELLAVETO_PORT=3000,VELLAVETO_MULTI_TENANT=true,VELLAVETO_BILLING_ENABLED=true" \
  --set-secrets "VELLAVETO_API_KEY=vellaveto-api-key:latest,VELLAVETO_PADDLE_WEBHOOK_SECRET=vellaveto-paddle:latest" \
  --allow-unauthenticated
```

### 2. GCP Marketplace Integration

```yaml
# gcp-marketplace-listing.yaml
product:
  name: vellaveto-agentic-control-plane
  title: "Vellaveto — Agent Interaction Firewall"
  description: "Agent interaction firewall for MCP and AI tool calls"
  icon: gs://vellaveto-assets/icon-512.png

  pricing:
    type: USAGE_BASED
    metrics:
      - name: evaluations
        display_name: "Policy Evaluations"
        metric_kind: DELTA
        value_type: INT64
      - name: active_agents
        display_name: "Active AI Agents"
        metric_kind: GAUGE
        value_type: INT64

  deployment:
    type: MANAGED_SERVICE
    signup_url: "https://vellaveto.example.com/api/signup"
    dashboard_url: "https://vellaveto.example.com/dashboard"
```

---

## Kubernetes Marketplace (Helm)

For customers who prefer self-hosted deployment:

```bash
# Add Vellaveto Helm repository
helm repo add vellaveto https://charts.vellaveto.io
helm repo update

# Install with marketplace defaults
helm install vellaveto vellaveto/vellaveto \
  --namespace vellaveto-system \
  --create-namespace \
  --set server.multiTenant=true \
  --set billing.enabled=true \
  --set billing.provider=stripe \
  --set-string billing.stripeWebhookSecret=$STRIPE_SECRET \
  --set server.replicas=2 \
  --set monitoring.enabled=true
```

---

## Self-Service Signup Flow

### API Endpoint

```
POST /api/signup
Content-Type: application/json

{
  "org_name": "Acme Corp",
  "email": "admin@acme.com",
  "plan": "starter"
}
```

### Response

```json
{
  "tenant_id": "acme-corp-a1b2c3",
  "api_key": "vvt_<64-char-hex>",
  "plan": "starter",
  "server_url": "https://vellaveto.example.com",
  "next_steps": [
    "1. Install an SDK: pip install vellaveto-sdk / npm install @vellaveto-sdk/typescript",
    "2. Configure: VELLAVETO_URL=https://... VELLAVETO_API_KEY=<key> VELLAVETO_TENANT_ID=acme-corp-a1b2c3",
    "3. Create a policy config — see examples/presets/ for templates",
    "4. Start the proxy: vellaveto serve --config your-policy.toml",
    "5. Open the Admin Console at /dashboard to manage policies"
  ]
}
```

### Plan Tiers

| Plan | Evaluations/Day | Agents | Policies | Price |
|------|-----------------|--------|----------|-------|
| Free | 1,000 | 3 | 10 | $0 |
| Starter | 50,000 | 20 | 50 | $49/mo |
| Team | 500,000 | 100 | 200 | $299/mo |
| Enterprise Trial | 1,000,000 | 500 | 500 | Contact |

### SDK Quick Start (post-signup)

**Python:**
```python
from vellaveto import VellavetoClient

client = VellavetoClient(
    base_url="https://vellaveto.example.com",
    api_key="vvt_...",
    tenant_id="acme-corp-a1b2c3",
)

result = client.evaluate(tool="file_read", function="read", parameters={"path": "/data/report.csv"})
print(result.verdict)  # Allow / Deny / RequireApproval
```

**TypeScript:**
```typescript
import { VellavetoClient } from '@vellaveto-sdk/typescript';

const client = new VellavetoClient({
  baseUrl: 'https://vellaveto.example.com',
  apiKey: 'vvt_...',
  tenantId: 'acme-corp-a1b2c3',
});

const result = await client.evaluate({
  tool: 'file_read',
  function: 'read',
  parameters: { path: '/data/report.csv' },
});
```

**Go:**
```go
client := vellaveto.NewClient(
    "https://vellaveto.example.com",
    vellaveto.WithAPIKey("vvt_..."),
    vellaveto.WithTenant("acme-corp-a1b2c3"),
)

result, err := client.Evaluate(ctx, vellaveto.Action{
    Tool:     "file_read",
    Function: "read",
}, nil, false)
```

---

## Security Considerations

1. **Rate limiting**: Signup endpoint is rate-limited to 1 request per IP per minute
2. **API key security**: Keys are shown once at signup; implement key rotation via `/api/nhi/agents/{id}/rotate`
3. **Data residency**: Deploy in the customer's preferred region (default: eu-south-1 / italynorth / europe-west8)
4. **Tenant isolation**: Each tenant has isolated policy namespace, audit trail, and usage quotas
5. **Webhook verification**: Paddle/Stripe webhooks use HMAC-SHA256 signature verification
6. **GDPR compliance**: Email stored in tenant metadata; implement right-to-deletion via tenant delete API
