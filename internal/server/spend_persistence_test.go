package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type unavailableSpendOutbox struct {
	storage.Repository
}

func (unavailableSpendOutbox) EnqueueSpendEvent(context.Context, domain.SpendEvent) error {
	return errors.New("database unavailable")
}

func TestSpendPersistenceFailureReturnsUnavailableBeforeSuccess(t *testing.T) {
	repo := unavailableSpendOutbox{Repository: storage.NewMemoryRepository()}
	s := &GatewayServer{spendWorker: finops.NewSpendWorker(repo, nil, config.FinOpsConfig{})}
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	if s.persistSpendEvent(w, r, domain.SpendEvent{RequestID: "request-1"}) {
		t.Fatal("persistSpendEvent succeeded with unavailable repository")
	}
	if w.Code != 503 {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}
