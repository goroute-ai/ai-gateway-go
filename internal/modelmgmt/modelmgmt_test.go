package modelmgmt_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/modelmgmt"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestFourLayerModelIsolationAndAutomatedDiscovery(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	svc := modelmgmt.NewService(repo)

	orgA := &domain.Organization{Name: "Org A", Slug: "org-a", IsActive: true}
	orgB := &domain.Organization{Name: "Org B", Slug: "org-b", IsActive: true}
	_ = repo.CreateOrganization(ctx, orgA)
	_ = repo.CreateOrganization(ctx, orgB)

	// Org A subscribes ONLY to OpenAI; Org B subscribes ONLY to Gemini
	_ = repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID: orgA.ID, Provider: domain.ProviderOpenAI, IsEnabled: true,
	})
	_ = repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID: orgB.ID, Provider: domain.ProviderGemini, IsEnabled: true,
	})

	// Verify Org A only sees OpenAI models
	listA, err := svc.ListVisibleModelsForIdentity(ctx, &domain.IdentityContext{OrgID: orgA.ID})
	if err != nil || len(listA.Data) == 0 {
		t.Fatalf("list models for Org A failed: %v", err)
	}
	for _, m := range listA.Data {
		if m.Provider != string(domain.ProviderOpenAI) {
			t.Fatalf("Org A should only see OpenAI models, got %s (%s)", m.ID, m.Provider)
		}
	}

	// Verify Org B only sees Gemini models
	listB, err := svc.ListVisibleModelsForIdentity(ctx, &domain.IdentityContext{OrgID: orgB.ID})
	if err != nil || len(listB.Data) == 0 {
		t.Fatalf("list models for Org B failed: %v", err)
	}
	for _, m := range listB.Data {
		if m.Provider != string(domain.ProviderGemini) {
			t.Fatalf("Org B should only see Gemini models, got %s (%s)", m.ID, m.Provider)
		}
	}

	// Test Automated Model Discovery Worker discovering a brand-new frontier model ("gpt-5-preview")
	mockOAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"object":"list","data":[{"id":"gpt-5-preview","object":"model","created":1750000000,"owned_by":"openai"}]}`)
	}))
	defer mockOAI.Close()

	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	cred := &domain.ProviderCredential{
		OrgID:    orgA.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "openai-discovery",
		BaseURL:  mockOAI.URL,
		IsActive: true,
	}
	_ = vault.EncryptCredential(cred, "sk-test-123")
	_ = repo.CreateProviderCredential(ctx, cred)

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(mockOAI.Client()))

	worker := modelmgmt.NewDiscoveryWorker(repo, reg, vault, nil, time.Hour, true)
	report, err := worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("discovery sync failed: %v", err)
	}
	if len(report.NewModels) != 1 || report.NewModels[0] != "openai/gpt-5-preview" {
		t.Fatalf("expected openai/gpt-5-preview to be newly discovered, got %+v", report)
	}

	// Org B still must NOT see openai/gpt-5-preview because Org B is not subscribed to OpenAI!
	listBAfter, _ := svc.ListVisibleModelsForIdentity(ctx, &domain.IdentityContext{OrgID: orgB.ID})
	for _, m := range listBAfter.Data {
		if m.ID == "gpt-5-preview" {
			t.Fatalf("Org B leaked unsubscribed model gpt-5-preview")
		}
	}
}
