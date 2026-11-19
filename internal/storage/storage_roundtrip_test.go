package storage

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestMemoryRepository_GlobalModelModalityAndOperationsRoundTrip(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()
	depDate := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)

	gm := &domain.GlobalModel{
		ID:                            "openai/gpt-test-omni",
		Provider:                      domain.ProviderOpenAI,
		ModelName:                     "gpt-test-omni",
		DisplayName:                   "GPT Test Omni",
		MaxInputTokens:                128000,
		MaxOutputTokens:               16384,
		SupportedOperations:           []domain.OperationType{domain.OperationChat, domain.OperationResponses, domain.OperationImageGeneration},
		SupportsStreaming:             true,
		SupportsTools:                 true,
		SupportsInference:             true,
		InputCostMicrosPer1M:          2500000,
		OutputCostMicrosPer1M:         10000000,
		CachedInputCostMicrosPer1M:    1250000,
		CacheWriteCostMicrosPer1M:     3125000,
		ReasoningCostMicrosPer1M:      15000000,
		RerankCostMicrosPerSearchUnit: 2000,
		ImageCostMicrosBase:           40000,
		ImageCostMicrosHD:             80000,
		AudioSTTCostMicrosPerSecond:   100,
		AudioTTSCostMicrosPer1KChars:  15000,
		ModalityPricingJSON:           map[string]any{"hd_1024x1024": float64(80000)},
		PricingStatus:                 domain.PricingStatusCustom,
		PricingProvenanceSource:       "operator-verified",
		QualityTier:                   3,
		LifecycleStatus:               domain.ModelStatusActive,
		DeprecationDate:               &depDate,
	}

	if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
		t.Fatalf("UpsertGlobalModel failed: %v", err)
	}

	// Mutate caller's slice/map after upsert to ensure repository deep-copied them.
	gm.SupportedOperations[0] = domain.OperationRerank
	gm.ModalityPricingJSON["hd_1024x1024"] = float64(999)

	got, err := repo.GetGlobalModel(ctx, "openai/gpt-test-omni")
	if err != nil {
		t.Fatalf("GetGlobalModel failed: %v", err)
	}
	if got.CacheWriteCostMicrosPer1M != 3125000 {
		t.Errorf("CacheWriteCostMicrosPer1M = %d, want 3125000", got.CacheWriteCostMicrosPer1M)
	}
	if got.RerankCostMicrosPerSearchUnit != 2000 || got.ImageCostMicrosBase != 40000 || got.ImageCostMicrosHD != 80000 {
		t.Errorf("unexpected modality rates: %+v", got)
	}
	if got.AudioSTTCostMicrosPerSecond != 100 || got.AudioTTSCostMicrosPer1KChars != 15000 {
		t.Errorf("unexpected audio rates: stt=%d tts=%d", got.AudioSTTCostMicrosPerSecond, got.AudioTTSCostMicrosPer1KChars)
	}
	if got.DeprecationDate == nil || !got.DeprecationDate.Equal(depDate) {
		t.Errorf("DeprecationDate = %v, want %v", got.DeprecationDate, depDate)
	}
	if got.QualityTier != 3 {
		t.Errorf("QualityTier = %d, want 3", got.QualityTier)
	}
	if !got.SupportsOperation(domain.OperationChat) || !got.SupportsOperation(domain.OperationImageGeneration) || got.SupportsOperation(domain.OperationRerank) {
		t.Errorf("unexpected SupportedOperations: %v", got.SupportedOperations)
	}
	if v, ok := got.ModalityPricingJSON["hd_1024x1024"].(float64); !ok || v != 80000 {
		t.Errorf("ModalityPricingJSON mutated or missing: %v", got.ModalityPricingJSON)
	}

	list, err := repo.ListGlobalModels(ctx)
	if err != nil {
		t.Fatalf("ListGlobalModels failed: %v", err)
	}
	found := false
	for _, m := range list {
		if m.ID == "openai/gpt-test-omni" {
			found = true
			if m.CacheWriteCostMicrosPer1M != 3125000 {
				t.Errorf("ListGlobalModels CacheWriteCostMicrosPer1M = %d, want 3125000", m.CacheWriteCostMicrosPer1M)
			}
		}
	}
	if !found {
		t.Errorf("expected openai/gpt-test-omni in ListGlobalModels")
	}
}

func TestMemoryRepository_GuardrailPolicyToxicityRoundTrip(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()

	pol := &domain.GuardrailPolicy{
		OrgID:                    "org_tox_mem_1",
		Mode:                     domain.GuardrailModeEnforce,
		ScanAllRoles:             true,
		EnablePromptInjection:    true,
		PromptInjectionAction:    domain.GuardrailActionBlock,
		EnablePIIDetection:       true,
		PIIAction:                domain.GuardrailActionRedact,
		EnableSecretDetection:    true,
		SecretAction:             domain.GuardrailActionAudit,
		BlockedKeywords:          []string{"banned_term"},
		RedactOutputPII:          true,
		EnableToxicityFilter:     true,
		ToxicityAction:           domain.GuardrailActionRedact,
		ToxicityThreshold:        "low",
		EnabledContentCategories: []string{"bias", "denied_insults"},
		ContentExceptions:        []string{"safe_context"},
	}

	if err := repo.SetGuardrailPolicy(ctx, pol); err != nil {
		t.Fatalf("SetGuardrailPolicy failed: %v", err)
	}

	got, err := repo.GetGuardrailPolicy(ctx, pol.OrgID)
	if err != nil {
		t.Fatalf("GetGuardrailPolicy failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil GuardrailPolicy")
	}
	if !got.EnableToxicityFilter {
		t.Errorf("EnableToxicityFilter = false, want true")
	}
	if got.ToxicityAction != domain.GuardrailActionRedact {
		t.Errorf("ToxicityAction = %q, want %q", got.ToxicityAction, domain.GuardrailActionRedact)
	}
	if got.ToxicityThreshold != "low" {
		t.Errorf("ToxicityThreshold = %q, want %q", got.ToxicityThreshold, "low")
	}
	if !reflect.DeepEqual(got.EnabledContentCategories, []string{"bias", "denied_insults"}) {
		t.Errorf("EnabledContentCategories = %#v, want [bias denied_insults]", got.EnabledContentCategories)
	}
	if !reflect.DeepEqual(got.ContentExceptions, []string{"safe_context"}) {
		t.Errorf("ContentExceptions = %#v, want [safe_context]", got.ContentExceptions)
	}
}

func TestMemoryRepository_ModelGroupAndDeploymentRoutingRoundTrip(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()

	mg := &domain.ModelGroup{
		ID:              "mg-rt-1",
		OrgID:           "org-rt-1",
		Alias:           "fast",
		RoutingStrategy: domain.StrategyFastestResponse,
		FallbackGroupIDs: []string{
			"mg-backup",
		},
		ContextWindowFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: "long-ctx", Overrides: map[string]any{"max_tokens": 4096}},
		},
		ContentPolicyFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: "safe-model"},
		},
		FallbackTargets: []domain.FallbackTarget{
			{GroupAliasOrID: "backup-model", Overrides: map[string]any{"temperature": 0.2}},
		},
		RetryPolicy: &domain.RetryPolicy{
			RateLimitRetries:   3,
			TimeoutRetries:     2,
			ServerErrorRetries: 1,
			DefaultRetries:     1,
		},
		CooldownPolicy: &domain.CooldownPolicy{
			AllowedFails:         map[string]int{"rate_limit": 5},
			FailureRateThreshold: 0.5,
			MinRequestsPerMinute: 10,
			MaxCooldownSeconds:   300,
		},
		IsActive: true,
	}
	if err := repo.CreateModelGroup(ctx, mg); err != nil {
		t.Fatalf("CreateModelGroup failed: %v", err)
	}

	// Mutate caller slices/maps/pointers to verify deep copy isolation.
	mg.ContextWindowFallbacks[0].Overrides["max_tokens"] = 1
	mg.RetryPolicy.RateLimitRetries = 99
	mg.CooldownPolicy.AllowedFails["rate_limit"] = 99

	gotMG, err := repo.GetModelGroupByAlias(ctx, "org-rt-1", "fast")
	if err != nil {
		t.Fatalf("GetModelGroupByAlias failed: %v", err)
	}
	if gotMG.RoutingStrategy != domain.StrategyFastestResponse {
		t.Fatalf("RoutingStrategy = %q, want %q", gotMG.RoutingStrategy, domain.StrategyFastestResponse)
	}
	if gotMG.ContextWindowFallbacks[0].Overrides["max_tokens"] != 4096 {
		t.Fatalf("ContextWindowFallbacks mutated: %+v", gotMG.ContextWindowFallbacks)
	}
	if len(gotMG.ContentPolicyFallbacks) != 1 || gotMG.ContentPolicyFallbacks[0].GroupAliasOrID != "safe-model" {
		t.Fatalf("ContentPolicyFallbacks mismatch: %+v", gotMG.ContentPolicyFallbacks)
	}
	if len(gotMG.FallbackTargets) != 1 || gotMG.FallbackTargets[0].Overrides["temperature"] != 0.2 {
		t.Fatalf("FallbackTargets mismatch: %+v", gotMG.FallbackTargets)
	}
	if gotMG.RetryPolicy == nil || gotMG.RetryPolicy.RateLimitRetries != 3 {
		t.Fatalf("RetryPolicy mismatch: %+v", gotMG.RetryPolicy)
	}
	if gotMG.CooldownPolicy == nil || gotMG.CooldownPolicy.AllowedFails["rate_limit"] != 5 || gotMG.CooldownPolicy.MaxCooldownSeconds != 300 {
		t.Fatalf("CooldownPolicy mismatch: %+v", gotMG.CooldownPolicy)
	}

	// Nil policies/slices round-trip safely.
	nilMG := &domain.ModelGroup{
		ID:       "mg-rt-nil",
		OrgID:    "org-rt-1",
		Alias:    "plain",
		IsActive: true,
	}
	if err := repo.CreateModelGroup(ctx, nilMG); err != nil {
		t.Fatalf("CreateModelGroup nilMG failed: %v", err)
	}
	gotNilMG, err := repo.GetModelGroupByID(ctx, "mg-rt-nil")
	if err != nil {
		t.Fatalf("GetModelGroupByID failed: %v", err)
	}
	if gotNilMG.RetryPolicy != nil || gotNilMG.CooldownPolicy != nil {
		t.Fatalf("expected nil RetryPolicy/CooldownPolicy, got %+v / %+v", gotNilMG.RetryPolicy, gotNilMG.CooldownPolicy)
	}

	dep := &domain.Deployment{
		ID:                "dep-rt-1",
		ModelGroupID:      mg.ID,
		GlobalModelID:     "openai/gpt-4.1",
		CredentialID:      "cred-1",
		DeploymentName:    "fast-1",
		Region:            "us-east",
		Priority:          2,
		Tags:              []string{"tier:fast", "region:us"},
		MaxBudgetMicros:   25000000,
		BudgetResetPeriod: "daily",
	}
	if err := repo.CreateDeployment(ctx, dep); err != nil {
		t.Fatalf("CreateDeployment failed: %v", err)
	}
	dep.Tags[0] = "mutated"

	deps, err := repo.ListDeploymentsByGroup(ctx, mg.ID)
	if err != nil || len(deps) != 1 {
		t.Fatalf("ListDeploymentsByGroup failed: len=%d err=%v", len(deps), err)
	}
	if deps[0].Priority != 2 || !reflect.DeepEqual(deps[0].Tags, []string{"tier:fast", "region:us"}) || deps[0].MaxBudgetMicros != 25000000 || deps[0].BudgetResetPeriod != "daily" {
		t.Fatalf("Deployment mismatch: %+v", deps[0])
	}

	// Empty BudgetResetPeriod and nil Tags remain empty/nil cleanly when omitted.
	depDefault := &domain.Deployment{
		ID:            "dep-rt-default",
		ModelGroupID:  mg.ID,
		GlobalModelID: "openai/gpt-4.1",
		CredentialID:  "cred-1",
	}
	if err := repo.CreateDeployment(ctx, depDefault); err != nil {
		t.Fatalf("CreateDeployment default failed: %v", err)
	}
	allDeps, err := repo.ListAllDeployments(ctx)
	if err != nil || len(allDeps) != 2 {
		t.Fatalf("ListAllDeployments failed: len=%d err=%v", len(allDeps), err)
	}
	var foundDefault bool
	for _, d := range allDeps {
		if d.ID == "dep-rt-default" {
			foundDefault = true
			if d.BudgetResetPeriod != "" || d.Tags != nil {
				t.Fatalf("expected empty BudgetResetPeriod and nil Tags, got period=%q tags=%#v", d.BudgetResetPeriod, d.Tags)
			}
		}
	}
	if !foundDefault {
		t.Fatalf("dep-rt-default not found in ListAllDeployments")
	}

	// Verify UpdateModelGroup, GetDeployment, UpdateDeployment, DeleteDeployment, DeleteModelGroup (cascade).
	mg.DropUnsupportedParams = true
	mg.DisableCooldowns = true
	mg.SaturationFallbacks = []domain.FallbackTarget{{GroupAliasOrID: "fallback-pool"}}
	if err := repo.UpdateModelGroup(ctx, mg); err != nil {
		t.Fatalf("UpdateModelGroup failed: %v", err)
	}
	gotUpdatedMG, err := repo.GetModelGroupByID(ctx, mg.ID)
	if err != nil {
		t.Fatalf("GetModelGroupByID after update failed: %v", err)
	}
	if !gotUpdatedMG.DropUnsupportedParams || !gotUpdatedMG.DisableCooldowns || len(gotUpdatedMG.SaturationFallbacks) != 1 || gotUpdatedMG.SaturationFallbacks[0].GroupAliasOrID != "fallback-pool" {
		t.Fatalf("unexpected updated ModelGroup fields: %+v", gotUpdatedMG)
	}

	gotDep, err := repo.GetDeployment(ctx, dep.ID)
	if err != nil {
		t.Fatalf("GetDeployment failed: %v", err)
	}
	gotDep.ITPMCapacity = 50000
	gotDep.OTPMCapacity = 10000
	gotDep.MaxParallelRequests = 12
	gotDep.Status = domain.DeploymentStatusDisabled
	if err := repo.UpdateDeployment(ctx, gotDep); err != nil {
		t.Fatalf("UpdateDeployment failed: %v", err)
	}
	gotUpdatedDep, err := repo.GetDeployment(ctx, dep.ID)
	if err != nil {
		t.Fatalf("GetDeployment after update failed: %v", err)
	}
	if gotUpdatedDep.ITPMCapacity != 50000 || gotUpdatedDep.OTPMCapacity != 10000 || gotUpdatedDep.MaxParallelRequests != 12 || gotUpdatedDep.Status != domain.DeploymentStatusDisabled {
		t.Fatalf("unexpected updated Deployment fields: %+v", gotUpdatedDep)
	}

	if err := repo.DeleteDeployment(ctx, depDefault.ID); err != nil {
		t.Fatalf("DeleteDeployment failed: %v", err)
	}
	if _, err := repo.GetDeployment(ctx, depDefault.ID); err == nil {
		t.Fatalf("expected error getting deleted deployment")
	}
	if err := repo.DeleteModelGroup(ctx, mg.ID); err != nil {
		t.Fatalf("DeleteModelGroup failed: %v", err)
	}
	if _, err := repo.GetDeployment(ctx, dep.ID); err == nil {
		t.Fatalf("expected cascade deletion of deployment when model group deleted")
	}
}
