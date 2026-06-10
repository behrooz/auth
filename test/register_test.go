package test

import (
	"authservice/app"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegister_InvalidJSON(t *testing.T) {
	handler := app.Handler()
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if body := rec.Body.String(); !bytes.Contains([]byte(body), []byte("Invalid JSON")) {
		t.Errorf("unexpected body: %q", body)
	}
}

func TestRegister_MissingRequiredFields(t *testing.T) {
	handler := app.Handler()
	tests := []struct {
		name     string
		username string
		email    string
		password string
	}{
		{"empty username", "", "user@example.com", "password123"},
		{"empty email", "user", "", "password123"},
		{"empty password", "user", "user@example.com", ""},
		{"all empty", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]string{
				"username": tt.username,
				"email":    tt.email,
				"password": tt.password,
			}
			bodyBytes, _ := json.Marshal(body)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
			}
			if body := rec.Body.String(); !bytes.Contains([]byte(body), []byte("required")) {
				t.Errorf("unexpected body: %q", body)
			}
		})
	}
}

func TestRegister_InvalidEmailFormat(t *testing.T) {
	handler := app.Handler()
	tests := []struct {
		name  string
		email string
	}{
		{"no at sign", "notanemail"},
		{"no domain", "user@"},
		{"no local part", "@example.com"},
		{"invalid TLD", "user@example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]string{
				"username": "testuser",
				"email":    tt.email,
				"password": "password123",
			}
			bodyBytes, _ := json.Marshal(body)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
			}
			if body := rec.Body.String(); !bytes.Contains([]byte(body), []byte("Email")) {
				t.Errorf("unexpected body: %q", body)
			}
		})
	}
}
