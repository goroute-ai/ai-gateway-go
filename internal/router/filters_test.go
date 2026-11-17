package router

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/health"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func makeFilterTestDeployment(id, region string, tags []string, gm *domain.GlobalModel) *domain.Deployment {
	if gm == nil {
		gm = &domain.GlobalModel{
			ID:                "openai/gpt-4.1",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "gpt-4.1",
			MaxInputTokens:    128000,
			SupportsInference: true,
			SupportsStreaming: true,
			SupportsTools:     true,
			SupportsVision:    true,
			SupportsReasoning: true,
			Capabilities: domain.ModelCapabilities{
				Streaming:         domain.CapabilitySupported,
				Tools:             domain.CapabilitySupported,
				Vision:            domain.CapabilitySupported,
				StructuredOutputs: domain.CapabilitySupported,
				Reasoning:         domain.CapabilitySupported,
			},
			LifecycleStatus: domain.ModelStatusActive,
		}
	}
	return &domain.Deployment{
		ID:             id,
		ModelGroupID:   "group-1",
		GlobalModelID:  gm.ID,
		DeploymentName: id,
		Region:         region,
		Tags:           tags,
		Weight:         100,
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    gm,
	}
}

func assertDeploymentIDs(t *testing.T, got []*domain.Deployment, wantIDs ...string) {
	t.Helper()
	if len(got) != len(wantIDs) {
		gotIDs := make([]string, len(got))
		for i, d := range got {
			if d != nil {
				gotIDs[i] = d.ID
			}
		}
		t.Fatalf("got %d deployments %v, want %v", len(got), gotIDs, wantIDs)
	}
	for i, want := range wantIDs {
		if got[i].ID != want {
			t.Fatalf("index %d: got %q, want %q", i, got[i].ID, want)
		}
	}
}

func TestDeploymentFilter_StatusModelAndCredentials(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)

	p := NewFilterPipeline(nil, nil, config.RouterConfig{})
	p.now = func() time.Time { return now }

	activeNoCred := makeFilterTestDeployment("active-no-cred", "us-east", nil, nil)
	cooldownDep := makeFilterTestDeployment("cooldown", "us-east", nil, nil)
	cooldownDep.Status = domain.DeploymentStatusCooldown
	disabledDep := makeFilterTestDeployment("disabled", "us-east", nil, nil)
	disabledDep.Status = domain.DeploymentStatusDisabled
	nilModelDep := makeFilterTestDeployment("nil-model", "us-east", nil, nil)
	nilModelDep.GlobalModel = nil

	inactiveCredDep := makeFilterTestDeployment("inactive-cred", "us-east", nil, nil)
	inactiveCredDep.Credential = &domain.ProviderCredential{ID: "c1", IsActive: false}

	expiredCredDep := makeFilterTestDeployment("expired-cred", "us-east", nil, nil)
	expiredCredDep.Credential = &domain.ProviderCredential{ID: "c2", IsActive: true, ExpiresAt: &past}

	boundaryCredDep := makeFilterTestDeployment("boundary-cred", "us-east", nil, nil)
	boundaryCredDep.Credential = &domain.ProviderCredential{ID: "c3", IsActive: true, ExpiresAt: &now}

	validCredDep := makeFilterTestDeployment("valid-cred", "us-east", nil, nil)
	validCredDep.Credential = &domain.ProviderCredential{ID: "c4", IsActive: true, ExpiresAt: &future}

	input := []*domain.Deployment{
		nil,
		cooldownDep,
		activeNoCred,
		disabledDep,
		nilModelDep,
		inactiveCredDep,
		expiredCredDep,
		boundaryCredDep,
		validCredDep,
	}
	origLen := len(input)

	got, err := p.FilterEligibleDeployments(ctx, "org-1", "gpt-4.1", nil, input, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertDeploymentIDs(t, got, "active-no-cred", "valid-cred")

	if len(input) != origLen || input[0] != nil || input[2] != activeNoCred {
		t.Fatalf("FilterEligibleDeployments mutated caller input slice")
	}

	// All ineligible should return empty slice and nil error.
	gotEmpty, err := p.FilterEligibleDeployments(ctx, "org-1", "gpt-4.1", nil, []*domain.Deployment{cooldownDep, disabledDep}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotEmpty) != 0 {
		t.Fatalf("expected 0 eligible deployments, got %d", len(gotEmpty))
	}
}

func TestDeploymentFilter_ActiveHealthStalenessAndSafetyNet(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)

	org := &domain.Organization{ID: "org-health", Name: "Health Org"}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	mg := &domain.ModelGroup{
		ID:       "mg-health",
		OrgID:    org.ID,
		Alias:    "health-group",
		IsActive: true,
	}
	if err := repo.CreateModelGroup(ctx, mg); err != nil {
		t.Fatalf("CreateModelGroup: %v", err)
	}
	gm := &domain.GlobalModel{
		ID:                "openai/gpt-health",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-health",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
	}
	if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
		t.Fatalf("UpsertGlobalModel: %v", err)
	}
	// Expired cred causes ProbeAllNow to record StateUnhealthy deterministically without network I/O,
	// while a deployment without a credential in the filter list (or with a valid one) stays unprobed/healthy.
	badCred := &domain.ProviderCredential{
		ID:        "cred-expired-probe",
		OrgID:     org.ID,
		Provider:  domain.ProviderOpenAI,
		Name:      "expired-probe",
		IsActive:  true,
		ExpiresAt: &past,
	}
	if err := repo.CreateProviderCredential(ctx, badCred); err != nil {
		t.Fatalf("CreateProviderCredential: %v", err)
	}
	// Unknown provider also causes ProbeAllNow to record StateUnhealthy via missing adapter.
	validCred := &domain.ProviderCredential{
		ID:        "cred-unreg-adapter",
		OrgID:     org.ID,
		Provider:  domain.ProviderType("unregistered_probe_provider"),
		Name:      "unreg",
		IsActive:  true,
		ExpiresAt: &future,
	}
	if err := repo.CreateProviderCredential(ctx, validCred); err != nil {
		t.Fatalf("CreateProviderCredential valid: %v", err)
	}
	unregGM := &domain.GlobalModel{
		ID:                "unregistered_probe_provider/m1",
		Provider:          domain.ProviderType("unregistered_probe_provider"),
		ModelName:         "m1",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
	}
	if err := repo.UpsertGlobalModel(ctx, unregGM); err != nil {
		t.Fatalf("UpsertGlobalModel unreg: %v", err)
	}

	depUnhealthyA := &domain.Deployment{
		ID:             "dep-unhealthy-a",
		ModelGroupID:   mg.ID,
		GlobalModelID:  unregGM.ID,
		CredentialID:   validCred.ID,
		DeploymentName: "dep-unhealthy-a",
		Status:         domain.DeploymentStatusActive,
	}
	depUnhealthyB := &domain.Deployment{
		ID:             "dep-unhealthy-b",
		ModelGroupID:   mg.ID,
		GlobalModelID:  unregGM.ID,
		CredentialID:   validCred.ID,
		DeploymentName: "dep-unhealthy-b",
		Status:         domain.DeploymentStatusActive,
	}
	if err := repo.CreateDeployment(ctx, depUnhealthyA); err != nil {
		t.Fatalf("CreateDeployment A: %v", err)
	}
	if err := repo.CreateDeployment(ctx, depUnhealthyB); err != nil {
		t.Fatalf("CreateDeployment B: %v", err)
	}

	mon := health.NewMonitor(repo, adapter.NewRegistry(), nil, time.Minute, time.Second)
	if _, err := mon.ProbeAllNow(ctx); err != nil {
		t.Fatalf("ProbeAllNow: %v", err)
	}

	// Hydrate GlobalModel on candidates for FilterPipeline.
	depUnhealthyA.GlobalModel = unregGM
	depUnhealthyB.GlobalModel = unregGM
	depHealthy := makeFilterTestDeployment("dep-healthy", "us-east", nil, gm)

	t.Run("prunes unhealthy when healthy candidate exists", func(t *testing.T) {
		p := NewFilterPipeline(mon, nil, config.RouterConfig{HealthStalenessThreshold: time.Minute})
		got, err := p.FilterEligibleDeployments(ctx, org.ID, mg.Alias, nil, []*domain.Deployment{depUnhealthyA, depHealthy}, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, got, "dep-healthy")
	})

	t.Run("all-unhealthy safety net retains all candidates", func(t *testing.T) {
		p := NewFilterPipeline(mon, nil, config.RouterConfig{HealthStalenessThreshold: time.Minute})
		got, err := p.FilterEligibleDeployments(ctx, org.ID, mg.Alias, nil, []*domain.Deployment{depUnhealthyA, depUnhealthyB}, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, got, "dep-unhealthy-a", "dep-unhealthy-b")
	})

	t.Run("stale unhealthy report expires beyond HealthStalenessThreshold", func(t *testing.T) {
		time.Sleep(25 * time.Millisecond)
		p := NewFilterPipeline(mon, nil, config.RouterConfig{HealthStalenessThreshold: 10 * time.Millisecond})
		got, err := p.FilterEligibleDeployments(ctx, org.ID, mg.Alias, nil, []*domain.Deployment{depUnhealthyA, depHealthy}, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, got, "dep-unhealthy-a", "dep-healthy")
	})
}

func TestDeploymentFilter_CapabilitiesAndContextWindow(t *testing.T) {
	ctx := context.Background()
	p := NewFilterPipeline(nil, nil, config.RouterConfig{})

	fullModel := &domain.GlobalModel{
		ID:             "openai/gpt-full",
		Provider:       domain.ProviderOpenAI,
		ModelName:      "gpt-full",
		MaxInputTokens: 32000,
		Capabilities: domain.ModelCapabilities{
			Streaming:         domain.CapabilitySupported,
			Tools:             domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
		},
	}
	unknownCapsModel := &domain.GlobalModel{
		ID:             "custom/unknown-caps",
		Provider:       domain.ProviderOpenAI,
		ModelName:      "unknown-caps",
		MaxInputTokens: 16000,
	}
	noStream := &domain.GlobalModel{
		ID:             "m/no-stream",
		ModelName:      "no-stream",
		MaxInputTokens: 64000,
		Capabilities:   domain.ModelCapabilities{Streaming: domain.CapabilityUnsupported},
	}
	noTools := &domain.GlobalModel{
		ID:             "m/no-tools",
		ModelName:      "no-tools",
		MaxInputTokens: 64000,
		Capabilities:   domain.ModelCapabilities{Tools: domain.CapabilityUnsupported},
	}
	noVision := &domain.GlobalModel{
		ID:             "m/no-vision",
		ModelName:      "no-vision",
		MaxInputTokens: 64000,
		Capabilities:   domain.ModelCapabilities{Vision: domain.CapabilityUnsupported},
	}
	noJSONSchema := &domain.GlobalModel{
		ID:             "m/no-schema",
		ModelName:      "no-schema",
		MaxInputTokens: 64000,
		Capabilities:   domain.ModelCapabilities{StructuredOutputs: domain.CapabilityUnsupported},
	}
	noReasoning := &domain.GlobalModel{
		ID:             "m/no-reason",
		ModelName:      "no-reason",
		MaxInputTokens: 64000,
		Capabilities:   domain.ModelCapabilities{Reasoning: domain.CapabilityUnsupported},
	}

	dFull := makeFilterTestDeployment("d-full", "", nil, fullModel)
	dUnknown := makeFilterTestDeployment("d-unknown", "", nil, unknownCapsModel)
	dNoStream := makeFilterTestDeployment("d-no-stream", "", nil, noStream)
	dNoTools := makeFilterTestDeployment("d-no-tools", "", nil, noTools)
	dNoVision := makeFilterTestDeployment("d-no-vision", "", nil, noVision)
	dNoSchema := makeFilterTestDeployment("d-no-schema", "", nil, noJSONSchema)
	dNoReasoning := makeFilterTestDeployment("d-no-reason", "", nil, noReasoning)

	all := []*domain.Deployment{dFull, dUnknown, dNoStream, dNoTools, dNoVision, dNoSchema, dNoReasoning}

	req := &domain.CanonicalChatRequest{
		Stream:          true,
		Tools:           []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "fn"}}},
		ResponseFormat:  &domain.ResponseFormat{Type: "json_schema"},
		ReasoningEffort: "high",
		Messages: []domain.CanonicalMessage{{
			Role: "user",
			Parts: []domain.ContentPart{
				{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/img.png"}},
			},
		}},
	}

	got, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", req, all, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertDeploymentIDs(t, got, "d-full", "d-unknown")

	// Individual capability checks isolate each unsupported dimension.
	for _, tc := range []struct {
		name string
		req  *domain.CanonicalChatRequest
		bad  *domain.Deployment
	}{
		{
			name: "stream",
			req:  &domain.CanonicalChatRequest{Stream: true},
			bad:  dNoStream,
		},
		{
			name: "tools",
			req:  &domain.CanonicalChatRequest{Tools: []domain.CanonicalTool{{Type: "function"}}},
			bad:  dNoTools,
		},
		{
			name: "vision",
			req: &domain.CanonicalChatRequest{Messages: []domain.CanonicalMessage{{
				Role:  "user",
				Parts: []domain.ContentPart{{Type: "input_image", ImageURL: &domain.ImageURL{URL: "https://example.com/a.png"}}},
			}}},
			bad: dNoVision,
		},
		{
			name: "json_schema",
			req:  &domain.CanonicalChatRequest{ResponseFormat: &domain.ResponseFormat{Type: "json_schema"}},
			bad:  dNoSchema,
		},
		{
			name: "reasoning_effort",
			req:  &domain.CanonicalChatRequest{ReasoningEffort: "medium"},
			bad:  dNoReasoning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", tc.req, []*domain.Deployment{dFull, tc.bad}, 100)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertDeploymentIDs(t, res, "d-full")
		})
	}

	t.Run("context window prunes smaller models when larger model fits", func(t *testing.T) {
		res, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", &domain.CanonicalChatRequest{}, []*domain.Deployment{dUnknown, dFull}, 20000)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, res, "d-full")
	})

	t.Run("all pruned solely due to context length returns typed ContextWindowExhaustedError", func(t *testing.T) {
		res, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", &domain.CanonicalChatRequest{}, []*domain.Deployment{dUnknown, dFull}, 50000)
		if err == nil {
			t.Fatal("expected *ContextWindowExhaustedError, got nil")
		}
		if len(res) != 0 {
			t.Fatalf("expected nil/empty candidates on error, got %d", len(res))
		}
		var cwErr *ContextWindowExhaustedError
		if !errors.As(err, &cwErr) {
			t.Fatalf("expected errors.As *ContextWindowExhaustedError, got %T (%v)", err, err)
		}
		if cwErr.EstimatedTokens != 50000 || cwErr.MaxInputTokens != 32000 {
			t.Fatalf("unexpected ContextWindowExhaustedError fields: %+v", cwErr)
		}
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) {
			t.Fatalf("expected errors.As *domain.GatewayError, got %T", err)
		}
		if gwErr.StatusCode != http.StatusBadRequest || gwErr.Type != domain.ErrorTypeInvalidRequest || gwErr.Code != "context_length_exceeded" {
			t.Fatalf("unexpected GatewayError: %+v", gwErr)
		}
	})

	t.Run("mixed capability and context failure does not return ContextWindowExhaustedError", func(t *testing.T) {
		res, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", &domain.CanonicalChatRequest{Stream: true}, []*domain.Deployment{dNoStream, dFull}, 50000)
		if err != nil {
			t.Fatalf("expected nil error when capability also failed, got %v", err)
		}
		if len(res) != 0 {
			t.Fatalf("expected 0 candidates, got %d", len(res))
		}
	})
}

func TestDeploymentFilter_RegionFilter(t *testing.T) {
	ctx := context.Background()
	p := NewFilterPipeline(nil, nil, config.RouterConfig{})

	us := makeFilterTestDeployment("dep-us", "us-east", nil, nil)
	eu := makeFilterTestDeployment("dep-eu", "EU-West", nil, nil)
	ap := makeFilterTestDeployment("dep-ap", "ap-south", nil, nil)
	all := []*domain.Deployment{us, eu, ap}

	got, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", &domain.CanonicalChatRequest{
		GoRouteExtensions: &domain.GoRouteExtensions{AllowedRegion: "eu-west"},
	}, all, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertDeploymentIDs(t, got, "dep-eu")

	// Non-existent region returns empty without safety fallback.
	gotNone, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", &domain.CanonicalChatRequest{
		GoRouteExtensions: &domain.GoRouteExtensions{AllowedRegion: "sa-east"},
	}, all, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotNone) != 0 {
		t.Fatalf("expected 0 deployments for unmatched region, got %d", len(gotNone))
	}
}

func TestDeploymentFilter_TagMatching(t *testing.T) {
	cases := []struct {
		name     string
		depTags  []string
		reqTags  []string
		matchAll bool
		want     bool
	}{
		{name: "empty req tags", depTags: nil, reqTags: nil, matchAll: false, want: true},
		{name: "plain any match", depTags: []string{"eu", "cpu"}, reqTags: []string{"us", "eu"}, matchAll: false, want: true},
		{name: "plain any miss", depTags: []string{"ap"}, reqTags: []string{"us", "eu"}, matchAll: false, want: false},
		{name: "plain all match", depTags: []string{"eu", "gpu"}, reqTags: []string{"eu", "gpu"}, matchAll: true, want: true},
		{name: "plain all miss", depTags: []string{"eu"}, reqTags: []string{"eu", "gpu"}, matchAll: true, want: false},
		{name: "required &tag present with any plain", depTags: []string{"gpu", "us"}, reqTags: []string{"&gpu", "eu", "us"}, matchAll: false, want: true},
		{name: "required &tag missing even when plain matches", depTags: []string{"eu"}, reqTags: []string{"&gpu", "eu", "us"}, matchAll: false, want: false},
		{name: "excluded !tag rejects match", depTags: []string{"eu", "legacy"}, reqTags: []string{"eu", "!legacy"}, matchAll: false, want: false},
		{name: "excluded !tag only allows clean deployment", depTags: []string{"prod"}, reqTags: []string{"!legacy"}, matchAll: false, want: true},
		{name: "excluded !tag only allows empty deployment tags", depTags: nil, reqTags: []string{"!legacy"}, matchAll: false, want: true},
		{name: "prefix wildcard match", depTags: []string{"eu-west-1"}, reqTags: []string{"eu-*"}, matchAll: false, want: true},
		{name: "required and excluded prefix wildcards", depTags: []string{"gpu-h100", "prod"}, reqTags: []string{"&gpu-*", "!legacy-*"}, matchAll: false, want: true},
		{name: "excluded prefix wildcard rejects", depTags: []string{"gpu-h100", "legacy-v1"}, reqTags: []string{"&gpu-*", "!legacy-*"}, matchAll: false, want: false},
		{name: "case insensitive and trimmed", depTags: []string{" EU-West "}, reqTags: []string{" eu-* "}, matchAll: false, want: true},
		{name: "star wildcard requires at least one tag", depTags: nil, reqTags: []string{"*"}, matchAll: false, want: false},
		{name: "star wildcard matches non-empty tag", depTags: []string{"any"}, reqTags: []string{"*"}, matchAll: false, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchDeploymentTags(tc.depTags, tc.reqTags, tc.matchAll); got != tc.want {
				t.Fatalf("matchDeploymentTags(%v, %v, %v) = %v, want %v", tc.depTags, tc.reqTags, tc.matchAll, got, tc.want)
			}
		})
	}

	ctx := context.Background()
	p := NewFilterPipeline(nil, nil, config.RouterConfig{})
	d1 := makeFilterTestDeployment("d1", "eu-west", []string{"eu-west-1", "gpu-a100"}, nil)
	d2 := makeFilterTestDeployment("d2", "eu-west", []string{"eu-west-1", "gpu-a100", "legacy-v1"}, nil)
	d3 := makeFilterTestDeployment("d3", "us-east", []string{"us-east-1"}, nil)

	got, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", &domain.CanonicalChatRequest{
		GoRouteExtensions: &domain.GoRouteExtensions{
			Tags: []string{"&gpu-*", "eu-*", "us-*", "!legacy-*"},
		},
	}, []*domain.Deployment{d1, d2, d3}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertDeploymentIDs(t, got, "d1")
}

func TestDeploymentFilter_CapacitySaturationGate(t *testing.T) {
	ctx := context.Background()

	t.Run("local RPM and TPM saturation across all strategies", func(t *testing.T) {
		lb := NewLoadBalancer()
		depRPM := makeFilterTestDeployment("dep-rpm-sat", "us-east", nil, nil)
		depRPM.RPMCapacity = 2
		depTPM := makeFilterTestDeployment("dep-tpm-sat", "us-east", nil, nil)
		depTPM.TPMCapacity = 1000
		depFree := makeFilterTestDeployment("dep-free", "us-east", nil, nil)
		depFree.RPMCapacity = 5
		depFree.TPMCapacity = 1000

		// Saturate depRPM (usedRPM=2 >= 2)
		lb.OnRequestStart(depRPM.ID)
		lb.OnRequestEnd(depRPM.ID, 10, 10)
		lb.OnRequestStart(depRPM.ID)
		lb.OnRequestEnd(depRPM.ID, 10, 10)

		// Put 900 TPM on depTPM (900 + 200 > 1000 => saturated; 900 + 100 == 1000 => allowed)
		lb.OnRequestStart(depTPM.ID)
		lb.OnRequestEnd(depTPM.ID, 10, 900)

		// Put 100 TPM and 1 RPM on depFree (not saturated)
		lb.OnRequestStart(depFree.ID)
		lb.OnRequestEnd(depFree.ID, 10, 100)

		p := NewFilterPipeline(nil, lb, config.RouterConfig{})
		candidates := []*domain.Deployment{depRPM, depTPM, depFree}

		// With estTokens=200: both depRPM and depTPM are saturated, only depFree survives,
		// and LoadBalancer.Select across every strategy receives only depFree.
		eligible, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", nil, candidates, 200)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, eligible, "dep-free")

		for _, strat := range []domain.RoutingStrategy{
			domain.StrategyWeightedShuffle,
			domain.StrategyLeastBusy,
			domain.StrategyLatencyBased,
			domain.StrategyUsageBasedHeadroom,
			domain.StrategyLowestCost,
			domain.StrategyRoundRobin,
		} {
			if sel := lb.Select(strat, eligible); sel == nil || sel.ID != "dep-free" {
				t.Fatalf("strategy %s: expected dep-free, got %v", strat, sel)
			}
		}

		// Boundary: estTokens=100 fits exactly in depTPM (900+100 == 1000).
		eligibleBoundary, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", nil, candidates, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, eligibleBoundary, "dep-tpm-sat", "dep-free")
	})

	t.Run("all saturated fallback vs StrictCapacityFiltering", func(t *testing.T) {
		lb := NewLoadBalancer()
		d1 := makeFilterTestDeployment("d1", "us-east", nil, nil)
		d1.RPMCapacity = 1
		d2 := makeFilterTestDeployment("d2", "us-east", nil, nil)
		d2.TPMCapacity = 500

		lb.OnRequestStart(d1.ID)
		lb.OnRequestStart(d2.ID)
		lb.OnRequestEnd(d2.ID, 10, 450)

		candidates := []*domain.Deployment{d1, d2}

		nonStrict := NewFilterPipeline(nil, lb, config.RouterConfig{StrictCapacityFiltering: false})
		gotNonStrict, err := nonStrict.FilterEligibleDeployments(ctx, "org-1", "alias", nil, candidates, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, gotNonStrict, "d1", "d2")

		strict := NewFilterPipeline(nil, lb, config.RouterConfig{StrictCapacityFiltering: true})
		gotStrict, err := strict.FilterEligibleDeployments(ctx, "org-1", "alias", nil, candidates, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(gotStrict) != 0 {
			t.Fatalf("expected 0 candidates under StrictCapacityFiltering, got %d", len(gotStrict))
		}
	})

	t.Run("expired 1m window clears local saturation", func(t *testing.T) {
		lb := NewLoadBalancer()
		d1 := makeFilterTestDeployment("d1", "us-east", nil, nil)
		d1.RPMCapacity = 1
		d2 := makeFilterTestDeployment("d2", "us-east", nil, nil)
		d2.RPMCapacity = 5

		lb.OnRequestStart(d1.ID)
		lb.mu.Lock()
		lb.metrics[d1.ID].windowStart = time.Now().Add(-65 * time.Second)
		lb.mu.Unlock()

		p := NewFilterPipeline(nil, lb, config.RouterConfig{StrictCapacityFiltering: true})
		got, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", nil, []*domain.Deployment{d1, d2}, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, got, "d1", "d2")
	})

	t.Run("Redis shared signals pipeline and local fallback on Redis outage", func(t *testing.T) {
		server := miniredis.RunT(t)
		redisA := storage.NewRedisFabric(server.Addr(), "", 0)
		redisB := storage.NewRedisFabric(server.Addr(), "", 0)
		defer redisA.Client().Close()
		defer redisB.Client().Close()

		lbA := NewLoadBalancer(redisA)
		lbB := NewLoadBalancer(redisB)

		d1 := makeFilterTestDeployment("dep-redis-1", "us-east", nil, nil)
		d1.TPMCapacity = 1000
		d2 := makeFilterTestDeployment("dep-redis-2", "us-east", nil, nil)
		d2.TPMCapacity = 1000
		candidates := []*domain.Deployment{d1, d2}

		// Replica A records 900 tokens on d1 in Redis; lbB local metrics remain empty.
		lbA.OnRequestStart(d1.ID)
		lbA.OnRequestEnd(d1.ID, 15, 900)

		pB := NewFilterPipeline(nil, lbB, config.RouterConfig{StrictCapacityFiltering: true})
		got, err := pB.FilterEligibleDeployments(ctx, "org-1", "alias", nil, candidates, 200)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, got, "dep-redis-2")
		if !lbB.SharedSignalsAvailable() {
			t.Fatal("expected lbB.SharedSignalsAvailable() to be true after pipeline read")
		}

		// Record local saturation on d2 in lbB, then shut down Redis to verify local fallback.
		lbB.OnRequestStart(d2.ID)
		lbB.OnRequestEnd(d2.ID, 15, 950)
		server.Close()

		gotFallback, err := pB.FilterEligibleDeployments(ctx, "org-1", "alias", nil, candidates, 100)
		if err != nil {
			t.Fatalf("unexpected error on Redis fallback: %v", err)
		}
		assertDeploymentIDs(t, gotFallback, "dep-redis-1")
		if lbB.SharedSignalsAvailable() {
			t.Fatal("expected lbB.SharedSignalsAvailable() to report false after Redis failure")
		}
	})
}

func TestDeploymentFilter_BudgetGateAndRoutingPlugins(t *testing.T) {
	ctx := context.Background()
	d1 := makeFilterTestDeployment("d1", "us-east", nil, nil)
	d2 := makeFilterTestDeployment("d2", "us-east", nil, nil)
	d3 := makeFilterTestDeployment("d3", "us-east", nil, nil)

	t.Run("budget gate and ordered plugins", func(t *testing.T) {
		p := NewFilterPipeline(nil, nil, config.RouterConfig{})
		p.SetBudgetCheck(func(_ context.Context, orgID string, dep *domain.Deployment) bool {
			return orgID == "org-1" && dep.ID != "d3"
		})

		var order []string
		p.AddPlugin(RoutingPluginFunc{
			PluginName: "drop-d1",
			Fn: func(_ context.Context, rc *RoutingContext) ([]*domain.Deployment, error) {
				order = append(order, "drop-d1")
				if rc.GroupAlias != "fast" || rc.EstimatedTokens != 42 {
					t.Fatalf("unexpected RoutingContext: %+v", rc)
				}
				var out []*domain.Deployment
				for _, d := range rc.Candidates {
					if d.ID != "d1" {
						out = append(out, d)
					}
				}
				return out, nil
			},
		})
		p.AddPlugin(RoutingPluginFunc{
			PluginName: "keep-only-d2",
			Fn: func(_ context.Context, rc *RoutingContext) ([]*domain.Deployment, error) {
				order = append(order, "keep-only-d2")
				assertDeploymentIDs(t, rc.Candidates, "d2")
				return rc.Candidates, nil
			},
		})

		got, err := p.FilterEligibleDeployments(ctx, "org-1", "fast", nil, []*domain.Deployment{d1, d2, d3}, 42)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, got, "d2")
		if len(order) != 2 || order[0] != "drop-d1" || order[1] != "keep-only-d2" {
			t.Fatalf("unexpected plugin execution order: %v", order)
		}
	})

	t.Run("plugin error aborts pipeline", func(t *testing.T) {
		wantErr := errors.New("plugin policy failure")
		secondCalled := false
		p := NewFilterPipeline(nil, nil, config.RouterConfig{},
			RoutingPluginFunc{
				PluginName: "failer",
				Fn: func(_ context.Context, _ *RoutingContext) ([]*domain.Deployment, error) {
					return nil, wantErr
				},
			},
			RoutingPluginFunc{
				PluginName: "after",
				Fn: func(_ context.Context, rc *RoutingContext) ([]*domain.Deployment, error) {
					secondCalled = true
					return rc.Candidates, nil
				},
			},
		)

		_, err := p.FilterEligibleDeployments(ctx, "org-1", "fast", nil, []*domain.Deployment{d1, d2}, 0)
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
		if secondCalled {
			t.Fatal("expected subsequent plugin not to run after error")
		}
	})

	t.Run("RoutingPluginFunc with nil Fn passes candidates through", func(t *testing.T) {
		pf := RoutingPluginFunc{PluginName: "noop"}
		if pf.Name() != "noop" {
			t.Fatalf("unexpected plugin name: %q", pf.Name())
		}
		p := NewFilterPipeline(nil, nil, config.RouterConfig{}, pf)
		got, err := p.FilterContext(ctx, &RoutingContext{
			OrgID:      "org-1",
			GroupAlias: "fast",
			Candidates: []*domain.Deployment{d1, d2},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertDeploymentIDs(t, got, "d1", "d2")
	})
}

func TestDeploymentFilter_ZeroAllocFastPath(t *testing.T) {
	ctx := context.Background()
	mon := health.NewMonitor(nil, nil, nil, time.Minute, time.Second)
	lb := NewLoadBalancer()
	p := NewFilterPipeline(mon, lb, config.RouterConfig{HealthStalenessThreshold: time.Minute})

	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4.1",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}
	candidates := []*domain.Deployment{
		makeFilterTestDeployment("d1", "us-east", []string{"prod"}, nil),
		makeFilterTestDeployment("d2", "eu-west", []string{"prod"}, nil),
	}

	allocs := testing.AllocsPerRun(100, func() {
		got, err := p.FilterEligibleDeployments(ctx, "org-1", "gpt-4.1", req, candidates, 0)
		if err != nil || len(got) != 2 {
			t.Fatalf("unexpected result: len=%d err=%v", len(got), err)
		}
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocations on fast path, got %.2f", allocs)
	}
}

func TestDeploymentFilter_ConcurrentSafety(t *testing.T) {
	ctx := context.Background()
	lb := NewLoadBalancer()
	mon := health.NewMonitor(nil, nil, nil, time.Minute, time.Second)
	p := NewFilterPipeline(mon, lb, config.RouterConfig{HealthStalenessThreshold: time.Minute})

	d1 := makeFilterTestDeployment("d1", "us-east", []string{"eu", "gpu"}, nil)
	d1.RPMCapacity = 100
	d2 := makeFilterTestDeployment("d2", "eu-west", []string{"eu", "gpu"}, nil)
	d2.RPMCapacity = 100
	candidates := []*domain.Deployment{d1, d2}

	req := &domain.CanonicalChatRequest{
		Stream: true,
		GoRouteExtensions: &domain.GoRouteExtensions{
			Tags: []string{"&gpu", "eu"},
		},
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				depID := d1.ID
				if (id+i)%2 == 1 {
					depID = d2.ID
				}
				lb.OnRequestStart(depID)
				res, err := p.FilterEligibleDeployments(ctx, "org-1", "alias", req, candidates, 100)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(res) == 0 {
					t.Errorf("expected non-empty result under non-strict capacity fallback")
				}
				lb.OnRequestEnd(depID, 10, 50)
			}
		}(g)
	}
	wg.Wait()
}
