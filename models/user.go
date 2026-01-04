package models

import "time"

type User struct {
	ID       string `json:"id,omitempty" bson:"_id,omitempty"`
	Username string `json:"username" bson:"username"`
	Email    string `json:"email" bson:"email"`
	Password string `json:"password,omitempty" bson:"password,omitempty"`
}

type Claims struct {
	Username string `json:"username"`
}

type TokenValidationRequest struct {
	Token string `json:"token"`
}

type TokenValidationResponse struct {
	Valid    bool   `json:"valid"`
	UserID   string `json:"userID,omitempty"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Message  string `json:"message,omitempty"`
}

type LogoutRequest struct {
	Token string `json:"token"`
}

type LogoutResponse struct {
	Message string `json:"message"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	Message string `json:"message"`
}

// APIKey represents an access key and secret key pair
type APIKey struct {
	ID          string    `json:"id,omitempty" bson:"_id,omitempty"`
	UserID      string    `json:"userID" bson:"userID"`
	AccessKey   string    `json:"accessKey" bson:"accessKey"`
	SecretKey   string    `json:"secretKey" bson:"secretKey"` // Hashed secret key
	Description string    `json:"description,omitempty" bson:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt" bson:"createdAt"`
	LastUsedAt  time.Time `json:"lastUsedAt,omitempty" bson:"lastUsedAt,omitempty"`
	IsActive    bool      `json:"isActive" bson:"isActive"`
}

// CreateAPIKeyRequest request to create a new API key
type CreateAPIKeyRequest struct {
	Description string `json:"description,omitempty"`
}

// CreateAPIKeyResponse response after creating an API key
type CreateAPIKeyResponse struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"` // Only shown once during creation
	Message   string `json:"message"`
}

// ListAPIKeysResponse response for listing API keys
type ListAPIKeysResponse struct {
	APIKeys []APIKeyInfo `json:"apiKeys"`
}

// APIKeyInfo represents API key info (without secret)
type APIKeyInfo struct {
	ID          string    `json:"id"`
	AccessKey   string    `json:"accessKey"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	LastUsedAt  time.Time `json:"lastUsedAt,omitempty"`
	IsActive    bool      `json:"isActive"`
}

// DeleteAPIKeyRequest request to delete an API key
type DeleteAPIKeyRequest struct {
	AccessKey string `json:"accessKey"`
}

// DeleteAPIKeyResponse response after deleting an API key
type DeleteAPIKeyResponse struct {
	Message string `json:"message"`
}

// AccessKeyAuthRequest request to authenticate with access key and secret key
type AccessKeyAuthRequest struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

// AccessKeyAuthResponse response after authenticating with access key
type AccessKeyAuthResponse struct {
	Token    string `json:"token"`
	UserID   string `json:"userID"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Message  string `json:"message"`
}

