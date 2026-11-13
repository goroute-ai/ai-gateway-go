package domain

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteAnthropicHTTPError(t *testing.T) {
	t.Run("GatewayError uses Anthropic envelope", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteAnthropicHTTPError(rec, &GatewayError{
			StatusCode:    http.StatusTooManyRequests,
			Type:          ErrorTypeRateLimit,
			Code:          "rate_limit",
			Message:       "Too many requests",
			RetryAfterSec: 12,
		})

		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", rec.Code)
		}
		if rec.Header().Get("Retry-After") != "12" {
			t.Fatalf("expected Retry-After=12, got %q", rec.Header().Get("Retry-After"))
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("expected application/json, got %q", rec.Header().Get("Content-Type"))
		}

		var body AnthropicErrorEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if body.Type != "error" || body.Error == nil {
			t.Fatalf("unexpected envelope: %+v", body)
		}
		if body.Error.Type != "rate_limit_error" || body.Error.Message != "Too many requests" {
			t.Fatalf("unexpected inner error: %+v", body.Error)
		}
	})

	t.Run("non-GatewayError maps to api_error 500", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteAnthropicHTTPError(rec, errors.New("boom"))

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
		var body AnthropicErrorEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if body.Type != "error" || body.Error == nil || body.Error.Type != "api_error" || body.Error.Message != "boom" {
			t.Fatalf("unexpected envelope: %+v", body)
		}
	})
}
