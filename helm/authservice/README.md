# Auth Service Helm Chart

This Helm chart deploys the Auth Service application on a Kubernetes cluster.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- MongoDB instance accessible from the cluster

## Installation

### Basic Installation

```bash
helm install authservice ./helm/authservice
```

### Installation with Custom Values

```bash
helm install authservice ./helm/authservice -f my-values.yaml
```

### Upgrade

```bash
helm upgrade authservice ./helm/authservice
```

### Uninstall

```bash
helm uninstall authservice
```

## Configuration

The following table lists the configurable parameters and their default values:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Image repository | `authservice` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `8083` |
| `mongodb.connectionString` | MongoDB connection string | `mongodb://root:secret123@212.64.215.155:32169/` |
| `mongodb.database` | MongoDB database name | `vcluster` |
| `mongodb.collection` | MongoDB collection name | `users` |
| `jwt.secret` | JWT secret key | `mysecret123` |
| `app.port` | Application port | `8083` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `250m` |
| `resources.requests.memory` | Memory request | `256Mi` |
| `autoscaling.enabled` | Enable horizontal pod autoscaling | `false` |
| `autoscaling.minReplicas` | Minimum replicas for HPA | `2` |
| `autoscaling.maxReplicas` | Maximum replicas for HPA | `10` |
| `ingress.enabled` | Enable ingress | `false` |

## Example: Custom Values File

Create a `custom-values.yaml` file:

```yaml
replicaCount: 3

image:
  repository: your-registry/authservice
  tag: v1.0.0

mongodb:
  connectionString: "mongodb://user:password@mongodb-service:27017/"
  database: "production"
  collection: "users"

jwt:
  secret: "your-secret-key-here"

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

ingress:
  enabled: true
  className: "nginx"
  hosts:
    - host: auth.example.com
      paths:
        - path: /
          pathType: Prefix
```

Then install with:

```bash
helm install authservice ./helm/authservice -f custom-values.yaml
```

## Building and Pushing Docker Image

```bash
# Build the image
docker build -t your-registry/authservice:latest .

# Push to registry
docker push your-registry/authservice:latest
```

## Health Checks

The application includes health check endpoints:
- `/health` - Health check endpoint used by Kubernetes probes

## Security Notes

- **Important**: Change the default JWT secret in production
- Use Kubernetes secrets for sensitive values like MongoDB connection strings and JWT secrets
- Consider using `imagePullSecrets` for private registries

## Using Kubernetes Secrets

For better security, use Kubernetes secrets:

```bash
# Create secret for MongoDB
kubectl create secret generic mongodb-secret \
  --from-literal=connection-string="mongodb://user:pass@host:port/"

# Create secret for JWT
kubectl create secret generic jwt-secret \
  --from-literal=secret="your-secret-key"
```

Then update `values.yaml` to reference these secrets in the deployment template.

