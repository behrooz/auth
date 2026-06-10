package main

import (
	"authservice/app"
	"authservice/db"
	"log"
	"net/http"
	"os"
)

func main() {
	// Initialize database
	db.InitDB()

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
	}
	// Add colon if missing
	if port[0] != ':' {
		port = ":" + port
	}
	log.Printf("Auth service starting on port %s", port)
	log.Fatal(http.ListenAndServe(port, app.Handler()))
}
