# Auth Service

A separate authorization service that handles user authentication and JWT token validation.

## Features

- User registration
- User login with JWT token generation
- Token validation endpoint
- MongoDB integration for user storage

## Endpoints

### POST `/register`
Register a new user.

**Request:**
```json
{
  "username": "user123",
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "User registered successfully"
}
```

### POST `/login`
Login and get JWT token.

**Request:**
```json
{
  "username": "user123",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### POST `/validate`
Validate a JWT token.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (Valid):**
```json
{
  "valid": true,
  "username": "user123",
  "message": "Token is valid"
}
```

**Response (Invalid):**
```json
{
  "valid": false,
  "message": "Invalid or expired token"
}
```

### GET `/health`
Health check endpoint.

**Response:**
```json
{
  "status": "ok"
}
```

## Configuration

- **Port**: 8083 (default)
- **JWT Secret**: `mysecret123` (configured in `handlers/auth.go`)
- **Token Expiration**: 120 minutes
- **Database**: MongoDB connection string in `db/db.go`

## Running

```bash
cd /home/behrooz/Projects/authservice
go mod tidy
go run main.go
```

The service will start on port 8083.

## Integration

Other services (main API, secrets API) should call the `/validate` endpoint to verify tokens before processing requests.

