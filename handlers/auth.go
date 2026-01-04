package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"authservice/cache"
	"authservice/db"
	"authservice/models"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey []byte

func init() {
	// Get JWT secret from environment variable or use default
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "mysecret123"
		log.Println("Warning: JWT_SECRET not set, using default")
	}
	jwtKey = []byte(secret)
}

func isValidEmail(email string) error {
	const emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	if !re.MatchString(email) {
		return errors.New("invalid email format")
	}
	return nil
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message": "Invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if req.Email == "" || req.Username == "" || req.Password == "" {
		http.Error(w, `{"message": "please fill required fields"}`, http.StatusBadRequest)
		return
	}

	if err := isValidEmail(req.Email); err != nil {
		http.Error(w, `{"message": "Email format is not correct"}`, http.StatusBadRequest)
		return
	}

	var existUser models.User
	err := db.UserCollection.FindOne(context.TODO(), bson.M{"email": req.Email}).Decode(&existUser)
	if err == nil && existUser.Email == req.Email {
		http.Error(w, `{"message": "User already registered"}`, http.StatusUnauthorized)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"message": "Could not hash password"}`, http.StatusInternalServerError)
		return
	}

	user := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
	}

	_, err = db.UserCollection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, `{"message": "Could not create user"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.RegisterResponse{
		Message: "User registered successfully",
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message": "Invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	var storedUser models.User
	err := db.UserCollection.FindOne(context.TODO(), bson.M{"username": req.Username}).Decode(&storedUser)
	if err != nil {
		http.Error(w, `{"message": "Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(req.Password))
	if err != nil {
		http.Error(w, `{"message": "Invalid username or password"}`, http.StatusUnauthorized)
		return
	}
	fmt.Println(storedUser)
	expirationTime := time.Now().Add(120 * time.Minute)
	claims := jwt.MapClaims{
		"username": req.Username,
		"exp":      expirationTime.Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("Error generating token: %v\n", err)
		http.Error(w, `{"message": "Error generating token"}`, http.StatusInternalServerError)
		return
	}

	// Store user session in cache
	cache.SetSession(tokenString, storedUser.ID, storedUser.Username, storedUser.Email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.LoginResponse{
		Token: tokenString,
	})
}

func ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req models.TokenValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message": "Invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, `{"message": "Token is required"}`, http.StatusBadRequest)
		return
	}

	// Strip "Bearer " prefix if present
	token := req.Token
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil || !parsedToken.Valid {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.TokenValidationResponse{
			Valid:   false,
			Message: "Invalid or expired token",
		})
		return
	}

	// Check if token is expired
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(models.TokenValidationResponse{
				Valid:   false,
				Message: "Token has expired",
			})
			return
		}
	}

	// Extract username
	username, ok := claims["username"].(string)
	if !ok || username == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.TokenValidationResponse{
			Valid:   false,
			Message: "Invalid token claims",
		})
		return
	}

	// Check cache first - if session exists in cache, token is valid
	session, found := cache.GetSession(token)
	if found {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.TokenValidationResponse{
			Valid:    true,
			UserID:   session["userID"],
			Username: session["username"],
			Email:    session["email"],
			Message:  "Token is valid",
		})
		fmt.Println(session["username"])
		return
	}

	// If not in cache, validate user exists in database (fallback)
	count, err := db.UserCollection.CountDocuments(context.TODO(), bson.M{"username": username})
	if err != nil || count <= 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.TokenValidationResponse{
			Valid:   false,
			Message: "User not found or session expired",
		})
		return
	}

	// User exists but not in cache - token might be valid but session expired
	// For security, we'll return invalid if not in cache
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.TokenValidationResponse{
		Valid:   false,
		Message: "Session expired or invalid",
	})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var req models.LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message": "Invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, `{"message": "Token is required"}`, http.StatusBadRequest)
		return
	}

	// Strip "Bearer " prefix if present
	token := req.Token
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	// Remove token from cache
	cache.DeleteSession(token)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.LogoutResponse{
		Message: "Logged out successfully",
	})
}

// Helper function to extract user info from JWT token in Authorization header
func getUserFromToken(r *http.Request) (string, string, string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", "", errors.New("authorization header missing")
	}

	// Strip "Bearer " prefix if present
	token := authHeader
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = authHeader[7:]
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil || !parsedToken.Valid {
		return "", "", "", errors.New("invalid token")
	}

	// Check if token is expired
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return "", "", "", errors.New("token expired")
		}
	}

	username, ok := claims["username"].(string)
	if !ok || username == "" {
		return "", "", "", errors.New("invalid token claims")
	}

	// Get user from database
	var user models.User
	err = db.UserCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		return "", "", "", errors.New("user not found")
	}

	return user.ID, user.Username, user.Email, nil
}

// generateAPIKey generates a secure random API key
func generateAPIKey(prefix string) (string, error) {
	bytes := make([]byte, 32) // 32 bytes = 64 hex characters
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(bytes), nil
}

// CreateAPIKeyHandler creates a new API key for the authenticated user
func CreateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	userID, _, _, err := getUserFromToken(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"message": "Unauthorized: `+err.Error()+`"}`, http.StatusUnauthorized)
		return
	}

	var req models.CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message": "Invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	// Generate access key and secret key
	accessKey, err := generateAPIKey("ak_")
	if err != nil {
		log.Printf("Error generating access key: %v\n", err)
		http.Error(w, `{"message": "Error generating API key"}`, http.StatusInternalServerError)
		return
	}

	secretKey, err := generateAPIKey("sk_")
	if err != nil {
		log.Printf("Error generating secret key: %v\n", err)
		http.Error(w, `{"message": "Error generating API key"}`, http.StatusInternalServerError)
		return
	}

	// Hash the secret key before storing
	hashedSecretKey, err := bcrypt.GenerateFromPassword([]byte(secretKey), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing secret key: %v\n", err)
		http.Error(w, `{"message": "Error processing API key"}`, http.StatusInternalServerError)
		return
	}

	// Create API key document
	apiKey := models.APIKey{
		ID:          primitive.NewObjectID().Hex(),
		UserID:      userID,
		AccessKey:   accessKey,
		SecretKey:   string(hashedSecretKey),
		Description: req.Description,
		CreatedAt:   time.Now(),
		IsActive:    true,
	}

	_, err = db.APIKeyCollection.InsertOne(context.TODO(), apiKey)
	if err != nil {
		log.Printf("Error inserting API key: %v\n", err)
		http.Error(w, `{"message": "Error creating API key"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.CreateAPIKeyResponse{
		AccessKey: accessKey,
		SecretKey: secretKey, // Only shown once
		Message:   "API key created successfully. Please save the secret key as it will not be shown again.",
	})
}

// ListAPIKeysHandler lists all API keys for the authenticated user
func ListAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	userID, _, _, err := getUserFromToken(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"message": "Unauthorized: `+err.Error()+`"}`, http.StatusUnauthorized)
		return
	}

	cursor, err := db.APIKeyCollection.Find(context.TODO(), bson.M{"userID": userID})
	if err != nil {
		log.Printf("Error finding API keys: %v\n", err)
		http.Error(w, `{"message": "Error retrieving API keys"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var apiKeys []models.APIKey
	if err = cursor.All(context.TODO(), &apiKeys); err != nil {
		log.Printf("Error decoding API keys: %v\n", err)
		http.Error(w, `{"message": "Error retrieving API keys"}`, http.StatusInternalServerError)
		return
	}

	// Convert to APIKeyInfo (without secret)
	apiKeyInfos := make([]models.APIKeyInfo, len(apiKeys))
	for i, key := range apiKeys {
		apiKeyInfos[i] = models.APIKeyInfo{
			ID:          key.ID,
			AccessKey:   key.AccessKey,
			Description: key.Description,
			CreatedAt:   key.CreatedAt,
			LastUsedAt:  key.LastUsedAt,
			IsActive:    key.IsActive,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.ListAPIKeysResponse{
		APIKeys: apiKeyInfos,
	})
}

// DeleteAPIKeyHandler deletes an API key for the authenticated user
func DeleteAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	userID, _, _, err := getUserFromToken(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"message": "Unauthorized: `+err.Error()+`"}`, http.StatusUnauthorized)
		return
	}

	var req models.DeleteAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message": "Invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	if req.AccessKey == "" {
		http.Error(w, `{"message": "Access key is required"}`, http.StatusBadRequest)
		return
	}

	// Verify the API key belongs to the user
	var apiKey models.APIKey
	err = db.APIKeyCollection.FindOne(context.TODO(), bson.M{"accessKey": req.AccessKey, "userID": userID}).Decode(&apiKey)
	if err != nil {
		http.Error(w, `{"message": "API key not found"}`, http.StatusNotFound)
		return
	}

	// Delete the API key
	result, err := db.APIKeyCollection.DeleteOne(context.TODO(), bson.M{"accessKey": req.AccessKey, "userID": userID})
	if err != nil {
		log.Printf("Error deleting API key: %v\n", err)
		http.Error(w, `{"message": "Error deleting API key"}`, http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, `{"message": "API key not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(models.DeleteAPIKeyResponse{
		Message: "API key deleted successfully",
	})
}

// AccessKeyAuthHandler authenticates using access key and secret key
func AccessKeyAuthHandler(w http.ResponseWriter, r *http.Request) {
	var req models.AccessKeyAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message": "Invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	if req.AccessKey == "" || req.SecretKey == "" {
		http.Error(w, `{"message": "Access key and secret key are required"}`, http.StatusBadRequest)
		return
	}

	// Find the API key
	var apiKey models.APIKey
	err := db.APIKeyCollection.FindOne(context.TODO(), bson.M{"accessKey": req.AccessKey, "isActive": true}).Decode(&apiKey)
	if err != nil {
		http.Error(w, `{"message": "Invalid access key or secret key"}`, http.StatusUnauthorized)
		return
	}

	// Verify the secret key
	err = bcrypt.CompareHashAndPassword([]byte(apiKey.SecretKey), []byte(req.SecretKey))
	if err != nil {
		http.Error(w, `{"message": "Invalid access key or secret key"}`, http.StatusUnauthorized)
		return
	}

	// Get user information
	var user models.User
	// Convert string ID to ObjectID if it's a valid ObjectID, otherwise use as string
	userIDFilter := bson.M{"_id": apiKey.UserID}
	if objectID, err := primitive.ObjectIDFromHex(apiKey.UserID); err == nil {
		userIDFilter = bson.M{"_id": objectID}
	}
	err = db.UserCollection.FindOne(context.TODO(), userIDFilter).Decode(&user)
	if err != nil {
		log.Printf("Error finding user: %v\n", err)
		http.Error(w, `{"message": "User not found"}`, http.StatusInternalServerError)
		return
	}

	// Update last used timestamp
	_, err = db.APIKeyCollection.UpdateOne(
		context.TODO(),
		bson.M{"_id": apiKey.ID},
		bson.M{"$set": bson.M{"lastUsedAt": time.Now()}},
	)
	if err != nil {
		log.Printf("Error updating last used timestamp: %v\n", err)
		// Don't fail the request if this update fails
	}

	// Generate JWT token
	expirationTime := time.Now().Add(120 * time.Minute)
	claims := jwt.MapClaims{
		"username": user.Username,
		"exp":      expirationTime.Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("Error generating token: %v\n", err)
		http.Error(w, `{"message": "Error generating token"}`, http.StatusInternalServerError)
		return
	}

	// Store user session in cache
	cache.SetSession(tokenString, user.ID, user.Username, user.Email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.AccessKeyAuthResponse{
		Token:    tokenString,
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Message:  "Authentication successful",
	})
}
