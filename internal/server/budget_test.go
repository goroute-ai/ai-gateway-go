package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
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

func TestBudgetAliasUsesCachedPricingSummaryAndRefreshes(t *testing.T) {
	repo := storage.NewMemoryRepository()
	stats := &budgetLookupStats{}
	s := &GatewayServer{repo: repo, budgetStats: stats}
	for i := 0; i < 2; i++ {
		if _, err := s.tokenBudgetUpperBound(context.Background(), "", "auto", 100, 100); err != nil {
			t.Fatalf("alias quote %d: %v", i+1, err)
		}
	}
	if got := stats.catalogScans.Load(); got != 1 {
		t.Fatalf("catalog summary scans = %d, want 1 across repeated alias requests", got)
	}

	if _, err := repo.UpdateModelPricing(context.Background(), "openai/gpt-4.1", 777777777, 666666666, -1, -1, domain.PricingStatusVerified, "test", "", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.tokenBudgetUpperBound(context.Background(), "", "auto", 100, 100); err != nil {
		t.Fatalf("alias quote after pricing update: %v", err)
	}
	if got := stats.catalogScans.Load(); got != 2 {
		t.Fatalf("catalog summary scans after pricing update = %d, want 2", got)
	}
}

func TestUnverifiedBudgetLookupDoesNotRescanCatalog(t *testing.T) {
	repo := storage.NewMemoryRepository()
	if err := repo.UpsertGlobalModel(context.Background(), &domain.GlobalModel{
		ID: "custom/unpriced-budget-model", Provider: domain.ProviderOpenAI, ModelName: "unpriced-budget-model", PricingStatus: domain.PricingStatusUnknown,
	}); err != nil {
		t.Fatal(err)
	}
	stats := &budgetLookupStats{}
	s := &GatewayServer{repo: repo, budgetStats: stats}
	_, err := s.tokenBudgetUpperBound(context.Background(), "", "unpriced-budget-model", 100, 100)
	if !errors.Is(err, errBudgetPricingUnverified) {
		t.Fatalf("unpriced model error = %v, want unverified pricing", err)
	}
	if got := stats.catalogScans.Load(); got != 0 {
		t.Fatalf("unverified model lookup performed %d catalog scans, want 0", got)
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

func TestNonTokenModalityEndpointsRejectBudgetedRequests(t *testing.T) {
	repo := storage.NewMemoryRepository()
	s := &GatewayServer{
		repo:      repo,
		rbac:      auth.NewRBACEngine(repo),
		collector: observability.NewCollector(),
	}
	id := &domain.IdentityContext{
		VirtualKeyID:       "vk-budget",
		OrgID:              "org-budget",
		KeyMaxBudgetMicros: 1000,
	}

	assertBudgetEstimateUnavailable := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, want 503 (body=%s)", name, w.Code, w.Body.String())
		}
		var errResp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("%s: decode error body: %v", name, err)
		}
		if errResp.Error.Code != "budget_estimate_unavailable" {
			t.Fatalf("%s: error.code = %q, want budget_estimate_unavailable", name, errResp.Error.Code)
		}
	}

	// 1. Images generations
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewBufferString(`{"model":"dall-e-3","prompt":"a cat"}`))
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleImageGenerations(w, req)
		assertBudgetEstimateUnavailable("images/generations", w)
	}

	// 2. Audio speech
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/audio/speech", bytes.NewBufferString(`{"model":"tts-1","input":"hello"}`))
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleAudioSpeech(w, req)
		assertBudgetEstimateUnavailable("audio/speech", w)
	}

	// 3. Audio transcriptions (multipart)
	{
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("file", "sample.wav")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("RIFF0000WAVE"))
		_ = mw.WriteField("model", "whisper-1")
		_ = mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleAudioTranscriptions(w, req)
		assertBudgetEstimateUnavailable("audio/transcriptions", w)
	}

	// 4. Moderations
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/moderations", bytes.NewBufferString(`{"model":"omni-moderation-latest","input":"hello"}`))
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleModerations(w, req)
		assertBudgetEstimateUnavailable("moderations", w)
	}

	// 5. Rerank
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/rerank", bytes.NewBufferString(`{"model":"rerank-english-v3.0","query":"q","documents":["doc1"]}`))
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleRerank(w, req)
		assertBudgetEstimateUnavailable("rerank", w)
	}
}
