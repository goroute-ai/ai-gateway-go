package server

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestBudgetQuoteUsesKnownRatesAndFailsUnknownModels(t *testing.T) {
	s := &GatewayServer{repo: storage.NewMemoryRepository()}
	quote, err := s.tokenBudgetUpperBound(context.Background(), "", "openai/gpt-4.1", 100, 200)
	if err != nil {
		t.Fatalf("known model quote: %v", err)
	}
	if quote <= 0 {
		t.Fatalf("expected positive upper-bound quote, got %d", quote)
	}
	if _, err := s.tokenBudgetUpperBound(context.Background(), "", "custom/unpriced-model", 100, 200); err == nil {
		t.Fatal("expected unknown pricing to fail closed")
	}
}

func TestBudgetedUnsupportedEndpointRejectsBeforeDispatch(t *testing.T) {
	id := &domain.IdentityContext{KeyMaxBudgetMicros: 100}
	w := httptest.NewRecorder()
	if !rejectBudgetedUnsupported(w, id) {
		t.Fatal("expected a budgeted unsupported endpoint to be rejected")
	}
	if w.Code != 503 {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if rejectBudgetedUnsupported(httptest.NewRecorder(), &domain.IdentityContext{}) {
		t.Fatal("unbudgeted request should continue")
	}
}
