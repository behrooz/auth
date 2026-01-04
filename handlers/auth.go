package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"authservice/cache"
	"authservice/db"
	"authservice/models"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
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
