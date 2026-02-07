# Prometheus Metrics

This service exposes Prometheus-compatible metrics for monitoring and observability.

## Metrics Endpoint

The service exposes metrics at `/metrics` endpoint. Prometheus can scrape this endpoint to collect metrics.

## Available Metrics

### HTTP Metrics

- **`http_requests_total`** (Counter): Total number of HTTP requests
  - Labels: `method`, `endpoint`, `status`
  - Example: `http_requests_total{method="POST",endpoint="/login",status="200"}`

- **`http_request_duration_seconds`** (Histogram): Duration of HTTP requests in seconds
  - Labels: `method`, `endpoint`
  - Example: `http_request_duration_seconds{method="POST",endpoint="/login"}`

- **`http_request_size_bytes`** (Histogram): Size of HTTP requests in bytes
  - Labels: `method`, `endpoint`

- **`http_response_size_bytes`** (Histogram): Size of HTTP responses in bytes
  - Labels: `method`, `endpoint`

- **`active_connections`** (Gauge): Number of active connections

### Authentication Metrics

- **`auth_attempts_total`** (Counter): Total number of authentication attempts
  - Labels: `method` (login, apikey, validate), `status` (success, failure)
  - Example: `auth_attempts_total{method="login",status="success"}`

- **`auth_duration_seconds`** (Histogram): Duration of authentication operations in seconds
  - Labels: `method`
  - Example: `auth_duration_seconds{method="login"}`

### API Key Metrics

- **`apikey_operations_total`** (Counter): Total number of API key operations
  - Labels: `operation` (create, list, delete, authenticate)
  - Example: `apikey_operations_total{operation="create"}`

### Database Metrics

- **`db_operations_total`** (Counter): Total number of database operations
  - Labels: `operation` (find, insert, update, delete), `status` (success, error)

- **`db_operation_duration_seconds`** (Histogram): Duration of database operations in seconds
  - Labels: `operation`

## Prometheus Configuration

Add the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'authservice'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8083']  # Update with your service address
        metrics_path: '/metrics'
```

## Grafana Dashboard Queries

### Request Rate
```
rate(http_requests_total[5m])
```

### Request Duration (p95)
```
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

### Authentication Success Rate
```
rate(auth_attempts_total{status="success"}[5m]) / rate(auth_attempts_total[5m])
```

### Active Connections
```
active_connections
```

### API Key Operations Rate
```
rate(apikey_operations_total[5m])
```

### Error Rate
```
rate(http_requests_total{status=~"5.."}[5m])
```

## Example Grafana Dashboard

You can create a Grafana dashboard with the following panels:

1. **Request Rate**: Line graph showing requests per second
2. **Response Time**: Line graph showing p50, p95, p99 latencies
3. **Error Rate**: Line graph showing 4xx and 5xx errors
4. **Authentication Metrics**: Bar chart showing success vs failure rates
5. **Active Connections**: Single stat showing current connections
6. **API Key Operations**: Bar chart showing create/list/delete operations

## Testing Metrics

You can test the metrics endpoint:

```bash
curl http://localhost:8083/metrics
```

This will return all metrics in Prometheus format.

