package main

import (
	"authservice/db"
	"authservice/handlers"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	// Initialize database
	db.InitDB()

	// Create router
	router := mux.NewRouter()

	// Public endpoints
	router.HandleFunc("/register", handlers.RegisterHandler).Methods("POST")
	router.HandleFunc("/login", handlers.LoginHandler).Methods("POST")

	// Token validation endpoint
	router.HandleFunc("/validate", handlers.ValidateTokenHandler).Methods("POST")

	// Logout endpoint
	router.HandleFunc("/logout", handlers.LogoutHandler).Methods("POST")

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}).Methods("GET")

	// Enable CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"},
		ExposedHeaders:   []string{"Content-Length"},
		AllowCredentials: false,
		Debug:            false,
	})

	// Start server
	port := ":8083"
	log.Printf("Auth service starting on port %s", port)
	log.Fatal(http.ListenAndServe(port, c.Handler(router)))
}

