package test

import (
	"authservice/app"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateToken_InvalidJSON(t *testing.T) {
	handler := app.Handler()
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader([]byte("not json")))
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

func TestValidateToken_MissingToken(t *testing.T) {
	handler := app.Handler()
	body := map[string]string{}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if body := rec.Body.String(); !bytes.Contains([]byte(body), []byte("Token is required")) {
		t.Errorf("unexpected body: %q", body)
	}
}
