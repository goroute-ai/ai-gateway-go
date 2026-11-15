package guardrails_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/stretchr/testify/require"
)

type v2DriverFunc struct {
	name  string
	hooks []domain.GuardrailHook
	fn    func(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error)
}

func (d *v2DriverFunc) Name() string { return d.name }
func (d *v2DriverFunc) SupportedHooks() []domain.GuardrailHook {
	return d.hooks
}
func (d *v2DriverFunc) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	return d.fn(ctx, input)
}

func TestPipelineV2ExtensionsOverridesAndAntiBypassHTTP(t *testing.T) {
	lab := newGuardrailLab(t)
	ctx := context.Background()

	lab.gw.GuardrailPipeline().RegisterDriver("v2-wordcheck", func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		forbidden, _ := cfg.EffectiveConfig["forbidden"].(string)
		return &v2DriverFunc{
			name:  "v2-wordcheck",
			hooks: cfg.Definition.EventHooks,
			fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				joined := strings.Join(input.Texts, "\n")
				if forbidden != "" && strings.Contains(joined, forbidden) {
					if cfg.EffectiveAction == domain.GuardrailActionRedact {
						var modified []string
						for _, txt := range input.Texts {
							modified = append(modified, strings.ReplaceAll(txt, forbidden, "[REDACTED_TERM]"))
						}
						return &domain.GuardrailEvalResult{
							Decision:      domain.GuardrailDecisionModify,
							ModifiedTexts: modified,
							Violations: []domain.GuardrailViolation{{
								GuardrailName: cfg.Definition.Name,
								Message:       "redacted forbidden term",
							}},
						}, nil
					}
					return &domain.GuardrailEvalResult{
						Decision: domain.GuardrailDecisionBlock,
						Violations: []domain.GuardrailViolation{{
							GuardrailName: cfg.Definition.Name,
							Message:       "blocked forbidden term: " + forbidden,
						}},
					}, nil
				}
				return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
			},
		}, nil
	})

	// 1. Admin locked guardrail (blocks "locked-secret").
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-locked",
		OrgID:      lab.orgID,
		Name:       "locked-guard",
		Provider:   "v2-wordcheck",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  false,
		Precedence: 1,
		Config:     map[string]any{"action": "block", "forbidden": "locked-secret"},
		Status:     domain.GuardrailStatusActive,
	}))
	require.NoError(t, lab.repo.CreateGuardrailBinding(ctx, &domain.GuardrailBinding{
		ID:            "bind-locked",
		OrgID:         lab.orgID,
		GuardrailID:   "def-locked",
		GuardrailName: "locked-guard",
		TeamID:        lab.teamID,
		IsLocked:      true,
	}))

	// 2. Admin default_on guardrail (redacts "default-pii").
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-default-on",
		OrgID:      lab.orgID,
		Name:       "default-guard",
		Provider:   "v2-wordcheck",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		Precedence: 2,
		Config:     map[string]any{"action": "redact", "forbidden": "default-pii"},
		Status:     domain.GuardrailStatusActive,
	}))

	// 3. Opt-in guardrail (blocks "optin-secret" only when requested via goroute_extensions).
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-opt-in",
		OrgID:      lab.orgID,
		Name:       "optin-guard",
		Provider:   "v2-wordcheck",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  false,
		Precedence: 3,
		Config:     map[string]any{"action": "block", "forbidden": "optin-secret"},
		Status:     domain.GuardrailStatusActive,
	}))

	// Attempt to disable + downgrade locked-guard via goroute_extensions -> MUST still block!
	resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "contains locked-secret"}},
		"goroute_extensions": map[string]any{
			"guardrails": []map[string]any{
				{"name": "locked-guard", "enabled": false, "action": "audit"},
			},
		},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "locked guardrail must not be bypassed: %s", string(raw))
	require.Empty(t, lab.upstreamCalls(), "blocked request must not reach upstream")

	// Attempt to disable + downgrade default-guard via goroute_extensions -> MUST still redact!
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "my default-pii value"}},
		"goroute_extensions": map[string]any{
			"guardrails": []map[string]any{
				{"name": "default-guard", "enabled": false, "action": "audit"},
			},
		},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected redacted request to succeed: %s", string(raw))
	calls := lab.upstreamCalls()
	require.Len(t, calls, 1)
	require.Contains(t, calls[0].Body, "[REDACTED_TERM]")
	require.NotContains(t, calls[0].Body, "default-pii")

	// Without opt-in, "optin-secret" is allowed.
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "contains optin-secret"}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "opt-in guardrail inactive by default: %s", string(raw))

	// With goroute_extensions opt-in enabled, "optin-secret" blocks.
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "contains optin-secret"}},
		"goroute_extensions": map[string]any{
			"guardrails": []map[string]any{
				{"name": "optin-guard", "enabled": true},
			},
		},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "opt-in guardrail must block when enabled: %s", string(raw))

	// Embeddings also respects goroute_extensions opt-in guardrails.
	resp, raw = lab.doJSON(http.MethodPost, "/v1/embeddings", lab.authHeaders, map[string]any{
		"model": "emb-small",
		"input": "embed optin-secret text",
		"goroute_extensions": map[string]any{
			"guardrails": []map[string]any{
				{"name": "optin-guard", "enabled": true},
			},
		},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "embeddings must enforce goroute_extensions guardrails: %s", string(raw))
}

func TestPipelineV2DuringCallParallelBlockingSlowUpstreamHTTP(t *testing.T) {
	lab := newGuardrailLab(t)
	ctx := context.Background()

	var upstreamHits atomic.Int32
	var slowFinished atomic.Int32
	stopMock := make(chan struct{})
	slowUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		select {
		case <-r.Context().Done():
			return
		case <-stopMock:
			return
		case <-time.After(700 * time.Millisecond):
			slowFinished.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "chatcmpl-slow",
				"choices": []map[string]any{{
					"index":         0,
					"message":       map[string]any{"role": "assistant", "content": "too slow"},
					"finish_reason": "stop",
				}},
			})
		}
	}))
	t.Cleanup(func() {
		close(stopMock)
		slowUpstream.Close()
	})

	require.NoError(t, lab.repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                "openai/gpt-4o-mini-slow",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4o-mini-slow",
		DisplayName:       "Slow Mock",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
		Capabilities:      domain.ModelCapabilities{Streaming: domain.CapabilitySupported},
	}))

	var cred domain.ProviderCredential
	r, b := lab.doJSON(http.MethodPost, "/admin/v1/credentials", lab.adminHeaders, map[string]any{
		"org_id": lab.orgID, "provider": "openai", "name": "slow-openai",
		"base_url": slowUpstream.URL, "api_key": "sk-slow-mock",
	}, &cred)
	require.Equal(t, http.StatusCreated, r.StatusCode, string(b))

	var grp domain.ModelGroup
	r, b = lab.doJSON(http.MethodPost, "/admin/v1/model-groups", lab.adminHeaders, map[string]any{
		"org_id": lab.orgID, "alias": "slow-alias", "routing_strategy": "weighted-shuffle",
	}, &grp)
	require.Equal(t, http.StatusCreated, r.StatusCode, string(b))

	r, b = lab.doJSON(http.MethodPost, "/admin/v1/deployments", lab.adminHeaders, map[string]any{
		"model_group_id": grp.ID, "global_model_id": "openai/gpt-4o-mini-slow",
		"credential_id": cred.ID, "deployment_name": "slow-dep", "weight": 100,
	}, nil)
	require.Equal(t, http.StatusCreated, r.StatusCode, string(b))

	var slowKeyResp struct {
		Key string `json:"raw_key"`
	}
	r, b = lab.doJSON(http.MethodPost, "/admin/v1/keys", lab.adminHeaders, map[string]any{
		"org_id":         lab.orgID,
		"team_id":        lab.teamID,
		"name":           "slow-alias-key",
		"allowed_models": []string{"slow-alias"},
	}, &slowKeyResp)
	require.Equal(t, http.StatusCreated, r.StatusCode, string(b))
	slowHeaders := map[string]string{"Authorization": "Bearer " + slowKeyResp.Key}

	lab.gw.GuardrailPipeline().RegisterDriver("v2-during", func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		return &v2DriverFunc{
			name:  "v2-during",
			hooks: cfg.Definition.EventHooks,
			fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				time.Sleep(15 * time.Millisecond)
				if strings.Contains(strings.Join(input.Texts, "\n"), "trigger-during") {
					return &domain.GuardrailEvalResult{
						Decision: domain.GuardrailDecisionBlock,
						Violations: []domain.GuardrailViolation{{
							GuardrailName: cfg.Definition.Name,
							Message:       "parallel during_call block",
						}},
					}, nil
				}
				return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
			},
		}, nil
	})

	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-during-parallel",
		OrgID:      lab.orgID,
		Name:       "parallel-during",
		Provider:   "v2-during",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookDuringCall},
		DefaultOn:  true,
		Precedence: 1,
		Status:     domain.GuardrailStatusActive,
	}))

	// Non-streaming /v1/chat/completions must abort slow upstream early (<350ms vs 700ms).
	start := time.Now()
	resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", slowHeaders, map[string]any{
		"model":    "slow-alias",
		"messages": []map[string]any{{"role": "user", "content": "please trigger-during now"}},
	}, nil)
	elapsed := time.Since(start)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "chat during_call block: %s", string(raw))
	require.Contains(t, string(raw), "guardrail_blocked")
	require.Less(t, elapsed, 350*time.Millisecond, "during_call must cancel slow upstream early, took %v", elapsed)
	require.GreaterOrEqual(t, upstreamHits.Load(), int32(1), "expected slow upstream to start concurrently")
	require.Zero(t, slowFinished.Load(), "slow upstream must not finish before during_call aborts")

	// Streaming /v1/responses pre-chunk gate returns clean HTTP 400 JSON without emitting SSE headers.
	startResp := time.Now()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/responses", slowHeaders, map[string]any{
		"model":  "slow-alias",
		"input":  "trigger-during on responses stream",
		"stream": true,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "responses stream during_call block: %s", string(raw))
	require.Contains(t, resp.Header.Get("Content-Type"), "application/json")
	require.Contains(t, string(raw), "guardrail_blocked")
	require.Less(t, time.Since(startResp), 350*time.Millisecond)

	// Streaming /v1/messages pre-chunk gate returns clean HTTP 400 Anthropic error JSON.
	startMsg := time.Now()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/messages", slowHeaders, map[string]any{
		"model":      "slow-alias",
		"max_tokens": 64,
		"stream":     true,
		"messages":   []map[string]any{{"role": "user", "content": "trigger-during on messages stream"}},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "messages stream during_call block: %s", string(raw))
	require.Contains(t, resp.Header.Get("Content-Type"), "application/json")
	require.Equal(t, "block", resp.Header.Get("X-Gateway-Guardrail-Action"))
	require.Contains(t, string(raw), "parallel during_call block")
	require.Less(t, time.Since(startMsg), 350*time.Millisecond)
}

func TestPipelineV2ModifyMutationsAcrossChatResponsesMessagesHTTP(t *testing.T) {
	lab := newGuardrailLab(t, withNonStreamReply("raw-model-output"))
	ctx := context.Background()

	lab.gw.GuardrailPipeline().RegisterDriver("v2-mutator", func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		return &v2DriverFunc{
			name:  "v2-mutator",
			hooks: cfg.Definition.EventHooks,
			fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				if input.Hook == domain.GuardrailHookPreCall {
					msgs := make([]domain.CanonicalMessage, len(input.StructuredMessages))
					for i, m := range input.StructuredMessages {
						m.Content = strings.ReplaceAll(m.Content, "raw-prompt", "pre-mutated-prompt")
						for pi := range m.Parts {
							m.Parts[pi].Text = strings.ReplaceAll(m.Parts[pi].Text, "raw-prompt", "pre-mutated-prompt")
						}
						msgs[i] = m
					}
					return &domain.GuardrailEvalResult{
						Decision:         domain.GuardrailDecisionModify,
						ModifiedMessages: msgs,
					}, nil
				}
				return &domain.GuardrailEvalResult{
					Decision:      domain.GuardrailDecisionModify,
					ModifiedTexts: []string{"post-mutated-reply"},
				}, nil
			},
		}, nil
	})

	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-mod-pre",
		OrgID:      lab.orgID,
		Name:       "pre-mutator",
		Provider:   "v2-mutator",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		Precedence: 1,
		Status:     domain.GuardrailStatusActive,
	}))
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-mod-post",
		OrgID:      lab.orgID,
		Name:       "post-mutator",
		Provider:   "v2-mutator",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPostCall},
		DefaultOn:  true,
		Precedence: 2,
		Status:     domain.GuardrailStatusActive,
	}))

	// 1. /v1/chat/completions
	lab.clearUpstreamCalls()
	var chatOut map[string]any
	resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "raw-prompt"}},
	}, &chatOut)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.Contains(t, string(raw), "post-mutated-reply")
	require.NotContains(t, string(raw), "raw-model-output")
	require.Contains(t, lab.upstreamCalls()[0].Body, "pre-mutated-prompt")

	// 2. /v1/responses
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/responses", lab.authHeaders, map[string]any{
		"model": "fast",
		"input": "raw-prompt",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.Contains(t, string(raw), "post-mutated-reply")
	require.NotContains(t, string(raw), "raw-model-output")
	require.Contains(t, lab.upstreamCalls()[0].Body, "pre-mutated-prompt")

	// 3. /v1/messages
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/messages", lab.authHeaders, map[string]any{
		"model":      "fast",
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "raw-prompt"}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.Contains(t, string(raw), "post-mutated-reply")
	require.NotContains(t, string(raw), "raw-model-output")
	require.Contains(t, lab.upstreamCalls()[0].Body, "pre-mutated-prompt")
}

func TestPipelineV2ModeRuleLoggingOnlyAndLBFailoverHTTP(t *testing.T) {
	lab := newGuardrailLab(t)
	ctx := context.Background()

	var failedCalls, healthyCalls, shadowCalls atomic.Int32
	lab.gw.GuardrailPipeline().RegisterDriver("v2-lb", func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		mode, _ := cfg.EffectiveConfig["mode"].(string)
		return &v2DriverFunc{
			name:  "v2-lb",
			hooks: []domain.GuardrailHook{domain.GuardrailHookPreCall, domain.GuardrailHookLoggingOnly},
			fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				if input.Hook == domain.GuardrailHookLoggingOnly {
					shadowCalls.Add(1)
					return &domain.GuardrailEvalResult{
						Decision: domain.GuardrailDecisionBlock,
						Violations: []domain.GuardrailViolation{{
							GuardrailName: cfg.Definition.Name,
							Message:       "shadow violation must not block",
						}},
					}, nil
				}
				if mode == "fail" {
					failedCalls.Add(1)
					return nil, errors.New("instance down")
				}
				healthyCalls.Add(1)
				return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
			},
		}, nil
	})

	// Two definitions sharing Name "shared-guard": primary fails, secondary succeeds.
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:        "def-lb-fail",
		OrgID:     lab.orgID,
		Name:      "shared-guard",
		Provider:  "v2-lb",
		DefaultOn: true,
		Weight:    1000,
		ModeRule: &domain.GuardrailModeRule{
			Tags:    map[string][]domain.GuardrailHook{"shadow": {domain.GuardrailHookLoggingOnly}},
			Default: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		},
		Config: map[string]any{"mode": "fail"},
		Status: domain.GuardrailStatusActive,
	}))
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:        "def-lb-ok",
		OrgID:     lab.orgID,
		Name:      "shared-guard",
		Provider:  "v2-lb",
		DefaultOn: true,
		Weight:    1,
		ModeRule: &domain.GuardrailModeRule{
			Tags:    map[string][]domain.GuardrailHook{"shadow": {domain.GuardrailHookLoggingOnly}},
			Default: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		},
		Config: map[string]any{"mode": "ok"},
		Status: domain.GuardrailStatusActive,
	}))

	// Default tagless requests fail over cleanly from failing primary to healthy backup.
	for range 4 {
		resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
			"model":    "fast",
			"messages": []map[string]any{{"role": "user", "content": "hello"}},
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	}
	require.GreaterOrEqual(t, failedCalls.Load(), int32(1))
	require.Equal(t, int32(4), healthyCalls.Load())

	// Request tagged "shadow" runs via logging_only asynchronously and NEVER blocks despite returning Block.
	resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "shadow test"}},
		"goroute_extensions": map[string]any{
			"tags": []string{"shadow"},
		},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	lab.gw.GuardrailPipeline().WaitLoggingOnly(context.Background())
	require.Equal(t, int32(1), shadowCalls.Load())
}
