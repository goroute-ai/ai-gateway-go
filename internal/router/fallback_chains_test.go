package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestClassifyFailureCategory(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want FailureCategory
	}{
		{
			name: "nil error defaults to general",
			err:  nil,
			want: CategoryGeneral,
		},
		{
			name: "local guardrail_blocked is non-retryable",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "guardrail_blocked",
				Message:    "Request blocked by security guardrail",
			},
			want: CategoryNonRetryable,
		},
		{
			name: "local guardrail_blocked mentioning content_policy must never bypass",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "guardrail_blocked",
				Message:    "Blocked by local guardrail content_policy rule",
			},
			want: CategoryNonRetryable,
		},
		{
			name: "local guardrail ErrorTypePermission is non-retryable",
			err: &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "guardrail_blocked_keyword",
				Message:    "Blocked keyword",
			},
			want: CategoryNonRetryable,
		},
		{
			name: "local guardrail prompt injection code is non-retryable",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "guardrail_prompt_injection",
				Message:    "Prompt injection detected",
			},
			want: CategoryNonRetryable,
		},
		{
			name: "plain error mentioning guardrail_blocked is non-retryable",
			err:  errors.New("guardrail_blocked: pii detected"),
			want: CategoryNonRetryable,
		},
		{
			name: "explicit context_length_exceeded code",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "context_length_exceeded",
				Message:    "prompt too big",
			},
			want: CategoryContextWindow,
		},
		{
			name: "upstream 400 maximum context length",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "This model's maximum context length is 8192 tokens.", 0),
			want: CategoryContextWindow,
		},
		{
			name: "upstream 400 prompt is too long",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderAnthropic, http.StatusBadRequest, "prompt is too long: 210000 tokens > 200000 maximum", 0),
			want: CategoryContextWindow,
		},
		{
			name: "upstream 400 token limit",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderGemini, http.StatusBadRequest, "Input exceeds token limit for model", 0),
			want: CategoryContextWindow,
		},
		{
			name: "429 rate limit mentioning token limit stays general",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusTooManyRequests, "TPM token limit exceeded, try again later", 5),
			want: CategoryGeneral,
		},
		{
			name: "upstream content_policy refusal",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "Rejected by safety system: content_policy_violation", 0),
			want: CategoryContentPolicy,
		},
		{
			name: "upstream content_filter refusal",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderAzure, http.StatusBadRequest, "Prompt triggered content_filter", 0),
			want: CategoryContentPolicy,
		},
		{
			name: "upstream safety_blocked refusal",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderBedrock, http.StatusBadRequest, "safety_blocked by upstream", 0),
			want: CategoryContentPolicy,
		},
		{
			name: "upstream policy_violation refusal",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderVertex, http.StatusBadRequest, "policy_violation error", 0),
			want: CategoryContentPolicy,
		},
		{
			name: "upstream 401 auth failure",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusUnauthorized, "invalid api key", 0),
			want: CategoryAuth,
		},
		{
			name: "upstream 403 auth failure",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderAnthropic, http.StatusForbidden, "forbidden", 0),
			want: CategoryAuth,
		},
		{
			name: "explicit AuthFailure 403",
			err: &domain.GatewayError{
				StatusCode:  http.StatusForbidden,
				AuthFailure: true,
				Message:     "permission denied on key",
			},
			want: CategoryAuth,
		},
		{
			name: "non-retryable client schema error",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_temperature",
				Message:    "temperature must be between 0 and 2",
				Retryable:  false,
			},
			want: CategoryNonRetryable,
		},
		{
			name: "upstream 400 malformed tool schema",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "invalid JSON schema for function parameters", 0),
			want: CategoryNonRetryable,
		},
		{
			name: "429 rate limit is general",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusTooManyRequests, "rate limit exceeded", 2),
			want: CategoryGeneral,
		},
		{
			name: "503 unavailable is general",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusServiceUnavailable, "upstream overloaded", 0),
			want: CategoryGeneral,
		},
		{
			name: "404 model not found is general",
			err:  domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusNotFound, "model not found", 0),
			want: CategoryGeneral,
		},
		{
			name: "transport error is general",
			err:  errors.New("dial tcp: connection refused"),
			want: CategoryGeneral,
		},
		{
			name: "wrapped GatewayError preserves classification",
			err:  fmt.Errorf("attempt failed: %w", domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "context_length_exceeded", 0)),
			want: CategoryContextWindow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFailureCategory(tc.err); got != tc.want {
				t.Fatalf("classifyFailureCategory(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestBuildSpecializedFallbackChain_CategorySelectionAndFallback(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	ctxGroup := createFallbackTestGroup(t, repo, "org-1", "long-ctx")
	policyGroup := createFallbackTestGroup(t, repo, "org-1", "safe-policy")
	targetGroup := createFallbackTestGroup(t, repo, "org-1", "regular-target")
	legacyGroup := createFallbackTestGroup(t, repo, "org-1", "legacy-fb")
	defaultGroup := createFallbackTestGroup(t, repo, "org-1", "global-default")
	inactiveGroup := createFallbackTestGroup(t, repo, "org-1", "inactive-fb")
	inactiveGroup.IsActive = false
	_ = repo.CreateModelGroup(ctx, inactiveGroup)
	foreignGroup := createFallbackTestGroup(t, repo, "org-2", "foreign-fb")

	primary := &domain.ModelGroup{
		OrgID:           "org-1",
		Alias:           "primary",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
		ContextWindowFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: ctxGroup.Alias, Overrides: map[string]any{"max_tokens": 4096}},
		},
		ContentPolicyFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: policyGroup.ID, Overrides: map[string]any{"temperature": 0.2}},
		},
		FallbackTargets: []domain.FallbackTarget{
			{GroupAliasOrID: targetGroup.Alias, Overrides: map[string]any{"max_tokens": 1024}},
			{GroupAliasOrID: inactiveGroup.ID},
			{GroupAliasOrID: foreignGroup.ID},
			{GroupAliasOrID: "does-not-exist"},
		},
		FallbackGroupIDs: []string{targetGroup.ID, legacyGroup.ID},
	}
	if err := repo.CreateModelGroup(ctx, primary); err != nil {
		t.Fatal(err)
	}
	defaults := []domain.FallbackTarget{{GroupAliasOrID: defaultGroup.Alias, Overrides: map[string]any{"top_p": 0.9}}}

	// 1. CategoryNonRetryable yields no fallbacks.
	if hops := buildSpecializedFallbackChain(ctx, repo, primary, CategoryNonRetryable, defaults, 0, nil); len(hops) != 0 {
		t.Fatalf("expected 0 hops for CategoryNonRetryable, got %+v", hops)
	}

	// 2. CategoryContextWindow uses ContextWindowFallbacks only when present.
	ctxHops := buildSpecializedFallbackChain(ctx, repo, primary, CategoryContextWindow, defaults, 0, nil)
	if len(ctxHops) != 1 || ctxHops[0].Group.ID != ctxGroup.ID || ctxHops[0].Category != CategoryContextWindow {
		t.Fatalf("unexpected context window hops: %+v", ctxHops)
	}
	if ctxHops[0].Overrides["max_tokens"] != 4096 {
		t.Fatalf("expected max_tokens override 4096, got %+v", ctxHops[0].Overrides)
	}
	// Mutating returned overrides must not mutate stored ModelGroup.
	ctxHops[0].Overrides["max_tokens"] = 1
	if primary.ContextWindowFallbacks[0].Overrides["max_tokens"] != 4096 {
		t.Fatalf("primary overrides mutated: %+v", primary.ContextWindowFallbacks[0].Overrides)
	}

	// 3. CategoryContentPolicy uses ContentPolicyFallbacks only when present.
	policyHops := buildSpecializedFallbackChain(ctx, repo, primary, CategoryContentPolicy, defaults, 0, nil)
	if len(policyHops) != 1 || policyHops[0].Group.ID != policyGroup.ID || policyHops[0].Category != CategoryContentPolicy {
		t.Fatalf("unexpected content policy hops: %+v", policyHops)
	}
	if policyHops[0].Overrides["temperature"] != 0.2 {
		t.Fatalf("expected temperature override 0.2, got %+v", policyHops[0].Overrides)
	}

	// 4. CategoryGeneral uses FallbackTargets + deduplicated FallbackGroupIDs + defaultFallbacks, filtering inactive/foreign/missing.
	genHops := buildSpecializedFallbackChain(ctx, repo, primary, CategoryGeneral, defaults, 0, nil)
	wantIDs := []string{targetGroup.ID, legacyGroup.ID, defaultGroup.ID}
	if len(genHops) != len(wantIDs) {
		t.Fatalf("expected %d general hops, got %d: %+v", len(wantIDs), len(genHops), genHops)
	}
	for i, wantID := range wantIDs {
		if genHops[i].Group.ID != wantID {
			t.Fatalf("genHops[%d].Group.ID = %q, want %q", i, genHops[i].Group.ID, wantID)
		}
		if genHops[i].Category != CategoryGeneral {
			t.Fatalf("genHops[%d].Category = %q, want %q", i, genHops[i].Category, CategoryGeneral)
		}
	}
	if genHops[0].Overrides["max_tokens"] != 1024 {
		t.Fatalf("expected FallbackTarget override preserved over duplicate FallbackGroupIDs entry, got %+v", genHops[0].Overrides)
	}
	if genHops[2].Overrides["top_p"] != 0.9 {
		t.Fatalf("expected default fallback override preserved, got %+v", genHops[2].Overrides)
	}

	// 5. CategoryAuth uses regular fallbacks too.
	authHops := buildSpecializedFallbackChain(ctx, repo, primary, CategoryAuth, defaults, 0, nil)
	if len(authHops) != len(wantIDs) || authHops[0].Category != CategoryAuth {
		t.Fatalf("unexpected auth hops: %+v", authHops)
	}

	// 6. Specialized categories fall back to regular + defaultFallbacks when specialized slices are empty.
	barePrimary := createFallbackTestGroup(t, repo, "org-1", "bare-primary", legacyGroup.ID)
	ctxFallback := buildSpecializedFallbackChain(ctx, repo, barePrimary, CategoryContextWindow, defaults, 0, nil)
	if len(ctxFallback) != 2 || ctxFallback[0].Group.ID != legacyGroup.ID || ctxFallback[1].Group.ID != defaultGroup.ID {
		t.Fatalf("expected CategoryContextWindow to fall back to regular + defaultFallbacks, got %+v", ctxFallback)
	}
	policyFallback := buildSpecializedFallbackChain(ctx, repo, barePrimary, CategoryContentPolicy, defaults, 0, nil)
	if len(policyFallback) != 2 || policyFallback[0].Group.ID != legacyGroup.ID || policyFallback[1].Group.ID != defaultGroup.ID {
		t.Fatalf("expected CategoryContentPolicy to fall back to regular + defaultFallbacks, got %+v", policyFallback)
	}
}

func TestBuildSpecializedFallbackChain_CyclesVisitedAndMaxDepth(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	// Build a chain of 20 groups with a cycle back to primary and between A<->B.
	var groups []*domain.ModelGroup
	for i := 0; i < 20; i++ {
		g := createFallbackTestGroup(t, repo, "org-cycle", fmt.Sprintf("g-%d", i))
		groups = append(groups, g)
	}
	for i := 0; i < len(groups)-1; i++ {
		targets := []domain.FallbackTarget{{GroupAliasOrID: groups[i+1].ID}}
		if i > 0 {
			// Cycle edge back to primary and previous node.
			targets = append(targets,
				domain.FallbackTarget{GroupAliasOrID: groups[0].ID},
				domain.FallbackTarget{GroupAliasOrID: groups[i-1].ID},
			)
		}
		groups[i].FallbackTargets = targets
		if err := repo.CreateModelGroup(ctx, groups[i]); err != nil {
			t.Fatal(err)
		}
	}

	// Default maxDepth (0 -> 16).
	hopsDefault := buildSpecializedFallbackChain(ctx, repo, groups[0], CategoryGeneral, nil, 0, nil)
	if len(hopsDefault) != maxFallbackDepth {
		t.Fatalf("default maxDepth chain len = %d, want %d", len(hopsDefault), maxFallbackDepth)
	}
	for i, hop := range hopsDefault {
		wantID := groups[i+1].ID
		if hop.Group.ID != wantID {
			t.Fatalf("hopsDefault[%d] = %q, want %q", i, hop.Group.ID, wantID)
		}
	}

	// Custom maxDepth = 3.
	hopsBounded := buildSpecializedFallbackChain(ctx, repo, groups[0], CategoryGeneral, nil, 3, nil)
	if len(hopsBounded) != 3 {
		t.Fatalf("custom maxDepth=3 chain len = %d, want 3", len(hopsBounded))
	}

	// Pre-seeded visited prevents revisiting group[2] and its subtree.
	visited := map[string]struct{}{groups[2].ID: {}}
	hopsVisited := buildSpecializedFallbackChain(ctx, repo, groups[0], CategoryGeneral, nil, 0, visited)
	if len(hopsVisited) != 1 || hopsVisited[0].Group.ID != groups[1].ID {
		t.Fatalf("expected pre-seeded visited to stop at g-1, got %+v", hopsVisited)
	}
}

func TestApplyFallbackOverrides(t *testing.T) {
	if got := applyFallbackOverrides(nil, map[string]any{"max_tokens": 100}); got != nil {
		t.Fatalf("expected nil for nil request, got %+v", got)
	}

	origMax := 2048
	origTemp := 0.7
	origTopP := 0.95
	origReq := &domain.CanonicalChatRequest{
		Model:           "primary",
		MaxTokens:       &origMax,
		Temperature:     &origTemp,
		TopP:            &origTopP,
		ReasoningEffort: "medium",
		Stop:            []string{"STOP1", "STOP2"},
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}

	// Empty overrides still returns a shallow clone with detached pointers/slices.
	noOpClone := applyFallbackOverrides(origReq, nil)
	if noOpClone == origReq {
		t.Fatal("expected a new CanonicalChatRequest pointer")
	}
	*noOpClone.MaxTokens = 999
	*noOpClone.Temperature = 0.1
	*noOpClone.TopP = 0.2
	noOpClone.Stop[0] = "MUTATED"
	if *origReq.MaxTokens != 2048 || *origReq.Temperature != 0.7 || *origReq.TopP != 0.95 || origReq.Stop[0] != "STOP1" {
		t.Fatalf("original request mutated through no-op clone: %+v", origReq)
	}

	// Apply overrides (including JSON float64 / json.Number / zero temperature / []any stop).
	overridden := applyFallbackOverrides(origReq, map[string]any{
		"max_tokens":       float64(4096),
		"temperature":      0,
		"top_p":            json.Number("0.5"),
		"reasoning_effort": "high",
		"stop":             []any{"END", "\n\n"},
		"unknown_param":    "ignored",
	})
	if overridden == origReq {
		t.Fatal("expected distinct cloned pointer")
	}
	if overridden.MaxTokens == nil || *overridden.MaxTokens != 4096 {
		t.Fatalf("MaxTokens = %v, want 4096", overridden.MaxTokens)
	}
	if overridden.Temperature == nil || *overridden.Temperature != 0.0 {
		t.Fatalf("Temperature = %v, want 0.0", overridden.Temperature)
	}
	if overridden.TopP == nil || *overridden.TopP != 0.5 {
		t.Fatalf("TopP = %v, want 0.5", overridden.TopP)
	}
	if overridden.ReasoningEffort != "high" {
		t.Fatalf("ReasoningEffort = %q, want high", overridden.ReasoningEffort)
	}
	if !reflect.DeepEqual(overridden.Stop, []string{"END", "\n\n"}) {
		t.Fatalf("Stop = %v, want [END \\n\\n]", overridden.Stop)
	}

	// Original request must remain completely intact.
	if *origReq.MaxTokens != 2048 || *origReq.Temperature != 0.7 || *origReq.TopP != 0.95 ||
		origReq.ReasoningEffort != "medium" || !reflect.DeepEqual(origReq.Stop, []string{"STOP1", "STOP2"}) {
		t.Fatalf("original request was mutated: %+v", origReq)
	}

	// String stop value also supported.
	singleStop := applyFallbackOverrides(origReq, map[string]any{"stop": "DONE"})
	if !reflect.DeepEqual(singleStop.Stop, []string{"DONE"}) {
		t.Fatalf("single string stop = %v, want [DONE]", singleStop.Stop)
	}
}
