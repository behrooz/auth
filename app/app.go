package app

import (
	"authservice/handlers"
	"authservice/metrics"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
)

// Handler returns the configured HTTP handler for the auth service (used by tests and main).
func Handler() http.Handler {
	router := mux.NewRouter()

	// Add Prometheus metrics middleware
	router.Use(metrics.HTTPMetricsMiddleware())

	// Add logging middleware to debug requests
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Incoming request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			next.ServeHTTP(w, r)
		})
	})

	// Public endpoints
	router.HandleFunc("/register", handlers.RegisterHandler).Methods("POST")
	router.HandleFunc("/login", handlers.LoginHandler).Methods("POST")
	router.HandleFunc("/auth/apikey", handlers.AccessKeyAuthHandler).Methods("POST")

	// Token validation endpoint
	router.HandleFunc("/validate", handlers.ValidateTokenHandler).Methods("POST")

	// Logout endpoint
	router.HandleFunc("/logout", handlers.LogoutHandler).Methods("POST")

	// API Key management endpoints (require JWT authentication)
	router.HandleFunc("/apikeys", handlers.CreateAPIKeyHandler).Methods("POST")
	router.HandleFunc("/apikeys", handlers.ListAPIKeysHandler).Methods("GET")
	router.HandleFunc("/apikeys/delete", handlers.DeleteAPIKeyHandler).Methods("POST")

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}).Methods("GET")

	// Prometheus metrics endpoint
	router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// Handle 404 with logging
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("404 Not Found: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found", "path": "` + r.URL.Path + `"}`))
	})

	// Enable CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"},
		ExposedHeaders:   []string{"Content-Length"},
		AllowCredentials: false,
		Debug:            false,
	})

	return c.Handler(router)
}
