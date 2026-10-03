package health

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestActiveHealthMonitorAndRecovery(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef")

	var upstreamHealthy atomic.Bool
	upstreamHealthy.Store(false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !upstreamHealthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"message":"upstream down"}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"object":"list","data":[{"id":"gpt-4.1-mini","object":"model"}]}`)
	}))
	defer srv.Close()

	org := &domain.Organization{Name: "Health Org", Slug: "health-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "probed-cred",
		BaseURL:  srv.URL,
		IsActive: true,
	}
	_ = vault.EncryptCredential(cred, "sk-test-probe")
	_ = repo.CreateProviderCredential(ctx, cred)

	mg := &domain.ModelGroup{OrgID: org.ID, Alias: "fast", IsActive: true}
	_ = repo.CreateModelGroup(ctx, mg)

	dep := &domain.Deployment{
		ModelGroupID:   mg.ID,
		GlobalModelID:  "openai/gpt-4.1-mini",
		CredentialID:   cred.ID,
		DeploymentName: "probed-dep",
		Status:         domain.DeploymentStatusActive,
	}
	_ = repo.CreateDeployment(ctx, dep)

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(srv.Client()))

	mon := NewMonitor(repo, reg, vault, 10*time.Second, 2*time.Second)

	// 1. First probe when upstream is down -> marks deployment Unhealthy
	reports, err := mon.ProbeAllNow(ctx)
	if err != nil || len(reports) != 1 {
		t.Fatalf("expected 1 health report, got %d (err=%v)", len(reports), err)
	}
	if reports[0].Status != StateUnhealthy || mon.IsHealthy(dep.ID) {
		t.Fatalf("expected deployment to be unhealthy, got %+v", reports[0])
	}

	// 2. Upstream recovers -> next probe marks deployment Healthy
	upstreamHealthy.Store(true)
	reports, _ = mon.ProbeAllNow(ctx)
	if reports[0].Status != StateHealthy || !mon.IsHealthy(dep.ID) {
		t.Fatalf("expected deployment to recover to healthy, got %+v", reports[0])
	}
}
