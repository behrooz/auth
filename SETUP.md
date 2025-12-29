# Auth Service Setup

## Quick Start

1. **Install dependencies:**
   ```bash
   cd /home/behrooz/Projects/authservice
   go mod tidy
   ```

2. **Configure database connection:**
   Edit `db/db.go` to set your MongoDB connection string.

3. **Run the service:**
   ```bash
   go run main.go
   ```

The service will start on port **8083**.

## Configuration

### Port
Default port is `8083`. To change it, edit `main.go`:
```go
port := ":YOUR_PORT"
```

### JWT Secret
JWT secret is in `handlers/auth.go`:
```go
var jwtKey = []byte("mysecret123")
```

**Important**: Use the same secret in all services that validate tokens.

### Token Expiration
Default expiration is 120 minutes. To change it, edit `handlers/auth.go`:
```go
expirationTime := time.Now().Add(120 * time.Minute)
```

## Testing

### Health Check
```bash
curl http://192.168.1.4:8083/health
```

### Register User
```bash
curl -X POST http://192.168.1.4:8083/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

### Login
```bash
curl -X POST http://192.168.1.4:8083/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### Validate Token
```bash
curl -X POST http://192.168.1.4:8083/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_TOKEN_HERE"
  }'
```

## Integration

See `INTEGRATION_GUIDE.md` for details on integrating with other services.

