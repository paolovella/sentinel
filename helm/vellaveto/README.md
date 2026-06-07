# Vellaveto Helm Chart

Helm chart for deploying [Vellaveto](https://github.com/paolovella/vellaveto) on Kubernetes.

## Prerequisites

- Kubernetes 1.26+
- Helm 3.x

## Installation

```bash
helm install vellaveto helm/vellaveto/ \
  --set vellaveto.extraEnv[0].name=VELLAVETO_API_KEY \
  --set vellaveto.extraEnv[0].value="your-api-key"
```

### With custom values

Create a `my-values.yaml`:

```yaml
vellaveto:
  extraEnv:
    - name: VELLAVETO_API_KEY
      valueFrom:
        secretKeyRef:
          name: vellaveto-secrets
          key: api-key
```

```bash
helm install vellaveto helm/vellaveto/ -f my-values.yaml
```

## Key Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `replicaCount` | `1` | Number of replicas |
| `image.repository` | `ghcr.io/paolovella/vellaveto` | Container image |
| `image.tag` | `Chart appVersion` | Image tag |
| `service.type` | `ClusterIP` | Service type |
| `service.port` | `3000` | Service port |
| `ingress.enabled` | `false` | Enable ingress |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `128Mi` | Memory limit |
| `autoscaling.enabled` | `false` | Enable HPA |
| `networkPolicy.enabled` | `true` | Enable NetworkPolicy |
| `networkPolicy.allowedNamespaces` | `[]` | Namespaces allowed to reach Vellaveto; empty means same namespace only |
| `networkPolicy.allowAllNamespaces` | `false` | Explicitly allow ingress from all namespaces |

## Security

The chart enforces security best practices by default:

- Non-root user (UID 1000)
- Read-only root filesystem
- No privilege escalation
- Dropped capabilities

## CRDs

When used with the Vellaveto Operator, the following CRDs are available:

- `VellavetoPolicySet` — declare policies as Kubernetes resources
- `VellavetoPolicyBinding` — bind policies to namespaces or workloads
- `VellavetoPolicyOverride` — environment-specific policy overrides

## Uninstall

```bash
helm uninstall vellaveto
```

## License

See [LICENSING.md](../../LICENSING.md) for repository licensing details.
