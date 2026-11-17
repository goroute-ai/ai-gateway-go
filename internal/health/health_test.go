package health

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
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

	pol, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	oaiAdp := openai.NewAdapter(srv.Client())
	oaiAdp.SetSSRFPolicy(pol)
	reg := adapter.NewRegistry()
	reg.Register(oaiAdp)

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

func TestMonitorIsHealthyWithMaxAgeAndReportAge(t *testing.T) {
	t.Run("nil monitor defaults to healthy", func(t *testing.T) {
		var nilMon *Monitor
		if !nilMon.IsHealthy("dep-1") {
			t.Fatal("expected nil monitor IsHealthy to return true")
		}
		if !nilMon.IsHealthyWithMaxAge("dep-1", time.Minute) {
			t.Fatal("expected nil monitor IsHealthyWithMaxAge to return true")
		}
		state, age, ok := nilMon.ReportAge("dep-1")
		if ok || state != "" || age != 0 {
			t.Fatalf("expected nil monitor ReportAge (\"\", 0, false), got (%q, %v, %v)", state, age, ok)
		}
	})

	t.Run("unprobed deployment defaults to healthy", func(t *testing.T) {
		mon := NewMonitor(nil, nil, nil, 0, 0)
		if !mon.IsHealthyWithMaxAge("missing", time.Minute) {
			t.Fatal("expected unprobed deployment to be healthy")
		}
		state, age, ok := mon.ReportAge("missing")
		if ok || state != "" || age != 0 {
			t.Fatalf("expected unprobed ReportAge (\"\", 0, false), got (%q, %v, %v)", state, age, ok)
		}
	})

	t.Run("healthy and degraded reports remain healthy regardless of age", func(t *testing.T) {
		mon := NewMonitor(nil, nil, nil, 0, 0)
		mon.mu.Lock()
		mon.reports["healthy-fresh"] = &DeploymentHealthReport{
			DeploymentID:  "healthy-fresh",
			Status:        StateHealthy,
			LastCheckedAt: time.Now().UTC().Add(-5 * time.Second),
		}
		mon.reports["healthy-old"] = &DeploymentHealthReport{
			DeploymentID:  "healthy-old",
			Status:        StateHealthy,
			LastCheckedAt: time.Now().UTC().Add(-10 * time.Minute),
		}
		mon.reports["degraded-old"] = &DeploymentHealthReport{
			DeploymentID:  "degraded-old",
			Status:        StateDegraded,
			LastCheckedAt: time.Now().UTC().Add(-10 * time.Minute),
		}
		mon.mu.Unlock()

		for _, id := range []string{"healthy-fresh", "healthy-old", "degraded-old"} {
			if !mon.IsHealthyWithMaxAge(id, time.Minute) {
				t.Fatalf("expected %s to be healthy", id)
			}
		}

		state, age, ok := mon.ReportAge("healthy-old")
		if !ok || state != StateHealthy || age < 9*time.Minute {
			t.Fatalf("unexpected ReportAge for healthy-old: state=%q age=%v ok=%v", state, age, ok)
		}
	})

	t.Run("unhealthy within maxAge stays unhealthy", func(t *testing.T) {
		mon := NewMonitor(nil, nil, nil, 0, 0)
		mon.mu.Lock()
		mon.reports["dep-recent-fail"] = &DeploymentHealthReport{
			DeploymentID:  "dep-recent-fail",
			Status:        StateUnhealthy,
			LastCheckedAt: time.Now().UTC().Add(-10 * time.Second),
		}
		mon.mu.Unlock()

		if mon.IsHealthyWithMaxAge("dep-recent-fail", time.Minute) {
			t.Fatal("expected recent unhealthy report within maxAge to return false")
		}
		state, age, ok := mon.ReportAge("dep-recent-fail")
		if !ok || state != StateUnhealthy || age < 9*time.Second || age > 30*time.Second {
			t.Fatalf("unexpected ReportAge for dep-recent-fail: state=%q age=%v ok=%v", state, age, ok)
		}
	})

	t.Run("unhealthy expired beyond maxAge returns healthy", func(t *testing.T) {
		mon := NewMonitor(nil, nil, nil, 0, 0)
		mon.mu.Lock()
		mon.reports["dep-stale-fail"] = &DeploymentHealthReport{
			DeploymentID:  "dep-stale-fail",
			Status:        StateUnhealthy,
			LastCheckedAt: time.Now().UTC().Add(-2 * time.Minute),
		}
		mon.mu.Unlock()

		if !mon.IsHealthyWithMaxAge("dep-stale-fail", time.Minute) {
			t.Fatal("expected stale unhealthy report older than maxAge to expire and return true")
		}
		if mon.IsHealthy("dep-stale-fail") {
			t.Fatal("expected IsHealthy without maxAge to still return false")
		}
		if mon.IsHealthyWithMaxAge("dep-stale-fail", 0) {
			t.Fatal("expected maxAge=0 to disable staleness expiration")
		}
		if mon.IsHealthyWithMaxAge("dep-stale-fail", -time.Second) {
			t.Fatal("expected negative maxAge to disable staleness expiration")
		}
	})

	t.Run("unhealthy with zero LastCheckedAt does not expire", func(t *testing.T) {
		mon := NewMonitor(nil, nil, nil, 0, 0)
		mon.mu.Lock()
		mon.reports["dep-zero-ts"] = &DeploymentHealthReport{
			DeploymentID: "dep-zero-ts",
			Status:       StateUnhealthy,
		}
		mon.mu.Unlock()

		if mon.IsHealthyWithMaxAge("dep-zero-ts", time.Minute) {
			t.Fatal("expected unhealthy report with zero timestamp not to expire")
		}
		state, age, ok := mon.ReportAge("dep-zero-ts")
		if !ok || state != StateUnhealthy || age != 0 {
			t.Fatalf("expected (StateUnhealthy, 0, true), got (%q, %v, %v)", state, age, ok)
		}
	})

	t.Run("concurrent readers and writers", func(t *testing.T) {
		mon := NewMonitor(nil, nil, nil, 0, 0)
		dep := &domain.Deployment{
			ID:             "dep-race",
			DeploymentName: "race-dep",
			GlobalModel: &domain.GlobalModel{
				Provider:  domain.ProviderOpenAI,
				ModelName: "gpt-4.1-mini",
			},
		}

		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					if (id+j)%2 == 0 {
						mon.recordOutcome(dep, 5, nil)
					} else {
						mon.recordOutcome(dep, 5, fmt.Errorf("probe error"))
					}
				}
			}(i)
		}
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					_ = mon.IsHealthyWithMaxAge(dep.ID, time.Second)
					_, _, _ = mon.ReportAge(dep.ID)
				}
			}()
		}
		wg.Wait()
	})
}
