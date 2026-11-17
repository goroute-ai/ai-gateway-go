package validation

import (
	"context"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestValidatorCapabilitiesContextAndParameters(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	val := NewValidator(repo)

	// 1. Invalid temperature (> 2.0)
	badTemp := 2.5
	err := val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:       "gpt-4.1-mini",
		Temperature: &badTemp,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, 10)
	if err == nil {
		t.Fatal("expected error for invalid temperature 2.5")
	}

	// 2. Vision request on non-vision model (`claude-3-5-haiku-latest` has SupportsVision: false in seed)
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model: "claude-3-5-haiku-latest",
		Messages: []domain.CanonicalMessage{
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/img.png"}},
				},
			},
		},
	}, 20)
	if err == nil {
		t.Fatal("expected capability_not_supported error for vision input on non-vision model")
	}

	// 3. Context window exceeded (`claude-3-5-haiku-latest` MaxInputTokens: 200000)
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:    "claude-3-5-haiku-latest",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, 250000)
	if err == nil {
		t.Fatal("expected context_length_exceeded error")
	}

	// 4. Max output tokens exceeded (`claude-3-5-haiku-latest` MaxOutputTokens: 8192)
	tooLargeMax := 16000
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:     "claude-3-5-haiku-latest",
		MaxTokens: &tooLargeMax,
		Messages:  []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, 50)
	if err == nil {
		t.Fatal("expected max_output_tokens_exceeded error")
	}
}

func TestValidatorTriStateCapabilities(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	val := NewValidator(repo)

	// Register a model with CapabilityUnknown across all capability dimensions
	unknownModel := &domain.GlobalModel{
		ID:             "groq/llama-unknown-caps",
		Provider:       domain.ProviderGroq,
		ModelName:      "llama-unknown-caps",
		MaxInputTokens: 32768,
		Capabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilityUnknown,
			Streaming: domain.CapabilityUnknown,
			Vision:    domain.CapabilityUnknown,
		},
		LifecycleStatus: domain.ModelStatusActive,
	}
	_ = repo.UpsertGlobalModel(ctx, unknownModel)

	// Register a model with CapabilityUnsupported for tools and vision
	unsupportedModel := &domain.GlobalModel{
		ID:             "custom/text-only-model",
		Provider:       domain.ProviderOpenAI,
		ModelName:      "text-only-model",
		MaxInputTokens: 8192,
		Capabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilityUnsupported,
			Streaming: domain.CapabilityUnsupported,
			Vision:    domain.CapabilityUnsupported,
		},
		LifecycleStatus: domain.ModelStatusActive,
	}
	_ = repo.UpsertGlobalModel(ctx, unsupportedModel)

	// 1. Model with CapabilityUnknown MUST pass validation for streaming, tools, and vision
	// to allow upstream provider invocation
	err := val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:  "groq/llama-unknown-caps",
		Stream: true,
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "get_weather"}},
		},
		Messages: []domain.CanonicalMessage{
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/test.png"}},
				},
			},
		},
	}, 100)
	if err != nil {
		t.Fatalf("expected request with unknown capabilities to PASS validation, but got error: %v", err)
	}

	// 2. Model with CapabilityUnsupported for Streaming MUST be rejected with HTTP 400
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:    "custom/text-only-model",
		Stream:   true,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "stream test"}},
	}, 10)
	if err == nil {
		t.Fatal("expected error for streaming on unsupported model")
	}
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.StatusCode != 400 || gwErr.Code != "capability_not_supported" {
		t.Fatalf("expected 400 capability_not_supported, got %+v", err)
	}

	// 3. Model with CapabilityUnsupported for Tools MUST be rejected with HTTP 400
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model: "custom/text-only-model",
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "search"}},
		},
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "tool test"}},
	}, 10)
	if err == nil {
		t.Fatal("expected error for tools on unsupported model")
	}
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.StatusCode != 400 || gwErr.Code != "capability_not_supported" {
		t.Fatalf("expected 400 capability_not_supported, got %+v", err)
	}

	// 4. Model with CapabilityUnsupported for Vision MUST be rejected with HTTP 400
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model: "custom/text-only-model",
		Messages: []domain.CanonicalMessage{
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/photo.jpg"}},
				},
			},
		},
	}, 10)
	if err == nil {
		t.Fatal("expected error for vision on unsupported model")
	}
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.StatusCode != 400 || gwErr.Code != "capability_not_supported" {
		t.Fatalf("expected 400 capability_not_supported, got %+v", err)
	}
}

func TestValidatorContextWindowFallbackHandoff(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	val := NewValidator(repo)

	orgID := "org-ctx-val"
	smallModel := &domain.GlobalModel{
		ID:              "openai/small-8k",
		Provider:        domain.ProviderOpenAI,
		ModelName:       "small-8k",
		MaxInputTokens:  8192,
		MaxOutputTokens: 4096,
		LifecycleStatus: domain.ModelStatusActive,
	}
	largeModel := &domain.GlobalModel{
		ID:              "anthropic/large-128k",
		Provider:        domain.ProviderAnthropic,
		ModelName:       "large-128k",
		MaxInputTokens:  128000,
		MaxOutputTokens: 8192,
		LifecycleStatus: domain.ModelStatusActive,
	}
	_ = repo.UpsertGlobalModel(ctx, smallModel)
	_ = repo.UpsertGlobalModel(ctx, largeModel)

	// 1. Group with only an 8k deployment and no fallbacks MUST reject 50k prompt.
	noFallbackGroup := &domain.ModelGroup{
		OrgID:           orgID,
		Alias:           "no-fallback-8k",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	if err := repo.CreateModelGroup(ctx, noFallbackGroup); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   noFallbackGroup.ID,
		GlobalModelID:  smallModel.ID,
		DeploymentName: "dep-small-only",
		Status:         domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	reqNoFB := &domain.CanonicalChatRequest{
		Model:    "no-fallback-8k",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "long prompt"}},
	}
	err := val.ValidateChatRequest(ctx, orgID, reqNoFB, 50000)
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.StatusCode != 400 || gwErr.Code != "context_length_exceeded" {
		t.Fatalf("expected 400 context_length_exceeded, got %+v", err)
	}

	// 2. Enabling allowDefaultFallbacks lets oversized prompt pass pre-flight validation.
	val.SetAllowDefaultFallbacks(true)
	if err := val.ValidateChatRequest(ctx, orgID, reqNoFB, 50000); err != nil {
		t.Fatalf("expected request to pass with allowDefaultFallbacks=true, got: %v", err)
	}
	val.SetAllowDefaultFallbacks(false)
	err = val.ValidateChatRequest(ctx, orgID, reqNoFB, 50000)
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.Code != "context_length_exceeded" {
		t.Fatalf("expected context_length_exceeded after disabling allowDefaultFallbacks, got %+v", err)
	}

	// 3. Group with ContextWindowFallbacks configured MUST pass pre-flight validation.
	ctxFBGroup := &domain.ModelGroup{
		OrgID:           orgID,
		Alias:           "ctx-fallback-group",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		ContextWindowFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: "large-group"},
		},
		IsActive: true,
	}
	if err := repo.CreateModelGroup(ctx, ctxFBGroup); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   ctxFBGroup.ID,
		GlobalModelID:  smallModel.ID,
		DeploymentName: "dep-small-ctx-fb",
		Status:         domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := val.ValidateChatRequest(ctx, orgID, &domain.CanonicalChatRequest{
		Model:    "ctx-fallback-group",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "long prompt"}},
	}, 50000); err != nil {
		t.Fatalf("expected request with ContextWindowFallbacks to pass validation, got: %v", err)
	}

	// 4. Group with a larger active deployment in the same group passes for 50k, rejects 200k.
	mixedGroup := &domain.ModelGroup{
		OrgID:           orgID,
		Alias:           "mixed-deployments",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	if err := repo.CreateModelGroup(ctx, mixedGroup); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   mixedGroup.ID,
		GlobalModelID:  smallModel.ID,
		DeploymentName: "dep-mixed-small",
		Status:         domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   mixedGroup.ID,
		GlobalModelID:  largeModel.ID,
		DeploymentName: "dep-mixed-large",
		Status:         domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	mixedReq := &domain.CanonicalChatRequest{
		Model:    "mixed-deployments",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "medium-long prompt"}},
	}
	if err := val.ValidateChatRequest(ctx, orgID, mixedReq, 50000); err != nil {
		t.Fatalf("expected 50k prompt to pass with 128k deployment in group, got: %v", err)
	}
	err = val.ValidateChatRequest(ctx, orgID, mixedReq, 200000)
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.Code != "context_length_exceeded" {
		t.Fatalf("expected 200k prompt to still fail with context_length_exceeded, got %+v", err)
	}

	// 5. Disabled larger deployment does NOT bypass context_length_exceeded.
	disabledLargeGroup := &domain.ModelGroup{
		OrgID:           orgID,
		Alias:           "disabled-large-dep",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	if err := repo.CreateModelGroup(ctx, disabledLargeGroup); err != nil {
		t.Fatal(err)
	}
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   disabledLargeGroup.ID,
		GlobalModelID:  smallModel.ID,
		DeploymentName: "dep-active-small",
		Status:         domain.DeploymentStatusActive,
	})
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   disabledLargeGroup.ID,
		GlobalModelID:  largeModel.ID,
		DeploymentName: "dep-disabled-large",
		Status:         domain.DeploymentStatusDisabled,
	})
	err = val.ValidateChatRequest(ctx, orgID, &domain.CanonicalChatRequest{
		Model:    "disabled-large-dep",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "long prompt"}},
	}, 50000)
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.Code != "context_length_exceeded" {
		t.Fatalf("expected disabled large deployment not to bypass context_length_exceeded, got %+v", err)
	}

	// 6. Regular FallbackTargets / FallbackGroupIDs: pass only when target group fits or has context fallbacks.
	largeTargetGroup := &domain.ModelGroup{
		OrgID:           orgID,
		Alias:           "large-target-group",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	if err := repo.CreateModelGroup(ctx, largeTargetGroup); err != nil {
		t.Fatal(err)
	}
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   largeTargetGroup.ID,
		GlobalModelID:  largeModel.ID,
		DeploymentName: "dep-target-large",
		Status:         domain.DeploymentStatusActive,
	})

	smallFallbackOnly := &domain.ModelGroup{
		OrgID:            orgID,
		Alias:            "small-fb-only",
		RoutingStrategy:  domain.StrategyWeightedShuffle,
		FallbackGroupIDs: []string{noFallbackGroup.ID},
		IsActive:         true,
	}
	if err := repo.CreateModelGroup(ctx, smallFallbackOnly); err != nil {
		t.Fatal(err)
	}
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   smallFallbackOnly.ID,
		GlobalModelID:  smallModel.ID,
		DeploymentName: "dep-small-fb-only",
		Status:         domain.DeploymentStatusActive,
	})
	err = val.ValidateChatRequest(ctx, orgID, &domain.CanonicalChatRequest{
		Model:    "small-fb-only",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "long prompt"}},
	}, 50000)
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.Code != "context_length_exceeded" {
		t.Fatalf("expected small-only regular fallback to fail with context_length_exceeded, got %+v", err)
	}

	largeFallbackTarget := &domain.ModelGroup{
		OrgID:           orgID,
		Alias:           "large-fb-target",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		FallbackTargets: []domain.FallbackTarget{{GroupAliasOrID: largeTargetGroup.Alias}},
		IsActive:        true,
	}
	if err := repo.CreateModelGroup(ctx, largeFallbackTarget); err != nil {
		t.Fatal(err)
	}
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   largeFallbackTarget.ID,
		GlobalModelID:  smallModel.ID,
		DeploymentName: "dep-large-fb-target",
		Status:         domain.DeploymentStatusActive,
	})
	if err := val.ValidateChatRequest(ctx, orgID, &domain.CanonicalChatRequest{
		Model:    "large-fb-target",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "long prompt"}},
	}, 50000); err != nil {
		t.Fatalf("expected request with large FallbackTarget group to pass validation, got: %v", err)
	}
}
