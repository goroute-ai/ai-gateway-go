package guardrails_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuardrailDefinitionsBindingsToolPoliciesCRUDAndSecretsRedaction(t *testing.T) {
	lab := newGuardrailLab(t)

	// 1. Create guardrail definition with Vault-encrypted secrets
	var created map[string]any
	resp, raw := lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/guardrail-definitions", lab.adminHeaders, map[string]any{
		"name":         "pii-and-secret-guard",
		"provider":     "local_content_filter",
		"event_hooks":  []string{"pre_call", "post_call"},
		"stream_scope": "both",
		"default_on":   false,
		"precedence":   10,
		"config": map[string]any{
			"action":           "redact",
			"categories":       []string{"pii", "secrets"},
			"blocked_keywords": []string{"top_secret_keyword"},
		},
		"secrets": map[string]any{
			"api_token": "super-secret-provider-token-999",
		},
		"guardrail_info": map[string]any{
			"usage_unit":           "request",
			"cost_per_call_micros": 100,
			"cost_per_unit_micros": 25,
		},
	}, &created)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create definition: %s", string(raw))
	defID, _ := created["id"].(string)
	require.NotEmpty(t, defID)
	assert.Equal(t, true, created["has_secrets"])
	assert.NotContains(t, string(raw), "super-secret-provider-token-999")
	assert.Nil(t, created["secrets"])

	// 2. GET single + GET list never leak secrets
	var fetched map[string]any
	resp, raw = lab.doJSON(http.MethodGet, "/admin/v1/guardrail-definitions/"+defID, lab.adminHeaders, nil, &fetched)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, true, fetched["has_secrets"])
	assert.NotContains(t, string(raw), "super-secret-provider-token-999")

	var listed struct {
		Data []map[string]any `json:"data"`
	}
	resp, raw = lab.doJSON(http.MethodGet, "/admin/v1/organizations/"+lab.orgID+"/guardrail-definitions", lab.adminHeaders, nil, &listed)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.Len(t, listed.Data, 1)
	assert.NotContains(t, string(raw), "super-secret-provider-token-999")

	// 3. PATCH & status transition workflow
	var patched map[string]any
	resp, raw = lab.doJSON(http.MethodPatch, "/admin/v1/guardrail-definitions/"+defID, lab.adminHeaders, map[string]any{
		"precedence": 5,
	}, &patched)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, float64(5), patched["precedence"])

	var statusUpdated map[string]any
	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/guardrail-definitions/"+defID+"/status", lab.adminHeaders, map[string]any{
		"status": "rejected",
	}, &statusUpdated)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, "rejected", statusUpdated["status"])

	// Reactivate via PUT
	var updated map[string]any
	resp, raw = lab.doJSON(http.MethodPut, "/admin/v1/guardrail-definitions/"+defID, lab.adminHeaders, map[string]any{
		"name":        "pii-and-secret-guard",
		"provider":    "local_content_filter",
		"event_hooks": []string{"pre_call", "post_call"},
		"status":      "active",
		"config": map[string]any{
			"action":     "redact",
			"categories": []string{"pii"},
		},
	}, &updated)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, "active", updated["status"])
	assert.Equal(t, true, updated["has_secrets"], "PUT without clear_secrets preserves encrypted secrets")

	// 4. Bindings CRUD
	var binding map[string]any
	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/guardrail-bindings", lab.adminHeaders, map[string]any{
		"org_id":       lab.orgID,
		"guardrail_id": defID,
		"team_id":      lab.teamID,
		"is_locked":    true,
	}, &binding)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))
	bindingID, _ := binding["id"].(string)
	require.NotEmpty(t, bindingID)

	var bindingsList struct {
		Data []map[string]any `json:"data"`
	}
	resp, raw = lab.doJSON(http.MethodGet, "/admin/v1/organizations/"+lab.orgID+"/guardrail-bindings", lab.adminHeaders, nil, &bindingsList)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.Len(t, bindingsList.Data, 1)

	resp, raw = lab.doJSON(http.MethodDelete, "/admin/v1/guardrail-bindings/"+bindingID, lab.adminHeaders, nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

	// 5. Tool Policies CRUD
	var tp map[string]any
	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/tool-policies", lab.adminHeaders, map[string]any{
		"team_id":       lab.teamID,
		"tool_name":     "shell_exec",
		"input_policy":  "blocked",
		"output_policy": "untrusted",
	}, &tp)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	tpID, _ := tp["id"].(string)
	require.NotEmpty(t, tpID)

	var tpList struct {
		Data []map[string]any `json:"data"`
	}
	resp, raw = lab.doJSON(http.MethodGet, "/admin/v1/organizations/"+lab.orgID+"/tool-policies", lab.adminHeaders, nil, &tpList)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.Len(t, tpList.Data, 1)

	resp, raw = lab.doJSON(http.MethodDelete, "/admin/v1/organizations/"+lab.orgID+"/tool-policies/"+tpID, lab.adminHeaders, nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

	// 6. Delete Guardrail Definition
	resp, raw = lab.doJSON(http.MethodDelete, "/admin/v1/guardrail-definitions/"+defID, lab.adminHeaders, nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

	resp, _ = lab.doJSON(http.MethodGet, "/admin/v1/guardrail-definitions/"+defID, lab.adminHeaders, nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestApplyGuardrailsEndpoint_AllowBlockModifyToolCallsRBACAndUsage(t *testing.T) {
	lab := newGuardrailLab(t)

	// Create second org to test strict cross-org tenant isolation
	var org2 domain.Organization
	resp, raw := lab.doJSON(http.MethodPost, "/admin/v1/organizations", lab.adminHeaders, map[string]any{
		"name": "Isolated Org 2",
		"slug": "isolated-org-2",
	}, &org2)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+org2.ID+"/guardrail-definitions", lab.adminHeaders, map[string]any{
		"name":        "org2-only-guard",
		"provider":    "local_content_filter",
		"event_hooks": []string{"pre_call"},
		"default_on":  true,
		"config": map[string]any{
			"action":     "block",
			"categories": []string{"pii"},
		},
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	// Create 3 guardrails in Org 1:
	// (a) pii-redactor (modify/redact, 50 micros per call + 10 micros per unit)
	// (b) keyword-blocker (block, default_on + locked, 100 micros per call)
	// (c) tool-policy-guard (tool_policy, blocks blocked tool calls)
	// (d) admin-only-guard (enabled_roles: ["org_admin"])
	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/guardrail-definitions", lab.adminHeaders, map[string]any{
		"name":        "pii-redactor",
		"provider":    "local_content_filter",
		"event_hooks": []string{"pre_call", "post_call"},
		"default_on":  false,
		"precedence":  1,
		"config": map[string]any{
			"action":     "redact",
			"categories": []string{"pii"},
		},
		"guardrail_info": map[string]any{
			"usage_unit":           "request",
			"cost_per_call_micros": 50,
			"cost_per_unit_micros": 10,
		},
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var blockerDef map[string]any
	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/guardrail-definitions", lab.adminHeaders, map[string]any{
		"name":        "keyword-blocker",
		"provider":    "local_content_filter",
		"event_hooks": []string{"pre_call"},
		"default_on":  true,
		"precedence":  2,
		"config": map[string]any{
			"action":           "block",
			"blocked_keywords": []string{"forbidden_launch_code"},
		},
		"guardrail_info": map[string]any{
			"usage_unit":           "request",
			"cost_per_call_micros": 100,
		},
	}, &blockerDef)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/guardrail-bindings", lab.adminHeaders, map[string]any{
		"org_id":       lab.orgID,
		"guardrail_id": blockerDef["id"],
		"team_id":      lab.teamID,
		"is_locked":    true,
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/tool-policies", lab.adminHeaders, map[string]any{
		"team_id":       lab.teamID,
		"tool_name":     "rm_rf_tool",
		"input_policy":  "blocked",
		"output_policy": "untrusted",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/guardrail-definitions", lab.adminHeaders, map[string]any{
		"name":        "tool-policy-guard",
		"provider":    "tool_policy",
		"event_hooks": []string{"pre_call", "post_call"},
		"default_on":  false,
		"precedence":  3,
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/guardrail-definitions", lab.adminHeaders, map[string]any{
		"name":          "admin-only-guard",
		"provider":      "local_content_filter",
		"event_hooks":   []string{"pre_call"},
		"enabled_roles": []string{"org_admin"},
		"config": map[string]any{
			"action":     "block",
			"categories": []string{"pii"},
		},
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	// Issue a developer virtual key with endpoint RBAC tested (one key missing /v1/guardrails/apply, one key with /v1/guardrails/apply)
	var restrictedKeyResp struct {
		Key string `json:"raw_key"`
	}
	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/keys", lab.adminHeaders, map[string]any{
		"org_id":            lab.orgID,
		"team_id":           lab.teamID,
		"name":              "no-apply-key",
		"role":              "developer",
		"allowed_endpoints": []string{"/v1/chat/completions"},
	}, &restrictedKeyResp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var devKeyResp struct {
		Key string `json:"raw_key"`
	}
	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/keys", lab.adminHeaders, map[string]any{
		"org_id":            lab.orgID,
		"team_id":           lab.teamID,
		"name":              "dev-apply-key",
		"role":              "developer",
		"allowed_endpoints": []string{"/v1/guardrails/apply"},
	}, &devKeyResp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	restrictedHeaders := map[string]string{"Authorization": "Bearer " + restrictedKeyResp.Key}
	devHeaders := map[string]string{"Authorization": "Bearer " + devKeyResp.Key}

	t.Run("endpoint_rbac_rejects_unpermitted_key", func(t *testing.T) {
		resp, _ := lab.doJSON(http.MethodPost, "/v1/guardrails/apply", restrictedHeaders, map[string]any{
			"text": "hello",
		}, nil)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("role_rbac_rejects_admin_only_guardrail", func(t *testing.T) {
		resp, _ := lab.doJSON(http.MethodPost, "/v1/guardrails/apply", devHeaders, map[string]any{
			"guardrail_name": "admin-only-guard",
			"text":           "hello",
		}, nil)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("cross_org_guardrail_not_accessible", func(t *testing.T) {
		resp, _ := lab.doJSON(http.MethodPost, "/v1/guardrails/apply", devHeaders, map[string]any{
			"guardrail_name": "org2-only-guard",
			"text":           "alice@example.com",
		}, nil)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("allow_clean_input", func(t *testing.T) {
		var out map[string]any
		resp, raw := lab.doJSON(http.MethodPost, "/v1/guardrails/apply", devHeaders, map[string]any{
			"guardrail_name": "pii-redactor",
			"input_type":     "request",
			"text":           "Explain clean architecture in Go.",
		}, &out)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
		assert.Equal(t, "allow", out["decision"])
		assert.Equal(t, false, out["blocked"])
	})

	t.Run("modify_redacts_pii", func(t *testing.T) {
		var out map[string]any
		resp, raw := lab.doJSON(http.MethodPost, "/v1/guardrails/apply", devHeaders, map[string]any{
			"guardrail_name": "pii-redactor",
			"input_type":     "request",
			"texts":          []string{"Send invoice to alice@example.com ASAP"},
		}, &out)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
		assert.Equal(t, "modify", out["decision"])
		assert.Equal(t, false, out["blocked"])
		assert.Equal(t, "redact", out["action"])
		modTexts, _ := out["modified_texts"].([]any)
		require.Len(t, modTexts, 1)
		assert.NotContains(t, modTexts[0].(string), "alice@example.com")
	})

	t.Run("locked_org_guardrail_cannot_be_bypassed_via_guardrail_name", func(t *testing.T) {
		var out map[string]any
		resp, raw := lab.doJSON(http.MethodPost, "/v1/guardrails/apply", devHeaders, map[string]any{
			"guardrail_name": "pii-redactor",
			"input_type":     "request",
			"text":           "Here is forbidden_launch_code please proceed",
		}, &out)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
		assert.Equal(t, "block", out["decision"])
		assert.Equal(t, true, out["blocked"])
	})

	t.Run("tool_calls_blocked_by_tool_policy", func(t *testing.T) {
		var out map[string]any
		resp, raw := lab.doJSON(http.MethodPost, "/v1/guardrails/apply", devHeaders, map[string]any{
			"guardrail_name": "tool-policy-guard",
			"input_type":     "response",
			"tool_calls": []map[string]any{{
				"id":   "call_1",
				"type": "function",
				"function": map[string]any{
					"name":      "rm_rf_tool",
					"arguments": `{"path":"/"}`,
				},
			}},
		}, &out)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
		assert.Equal(t, "block", out["decision"])
		assert.Equal(t, true, out["blocked"])
	})

	t.Run("usage_rollup_integer_cost_micros_and_prometheus_metrics", func(t *testing.T) {
		var usage storage.GuardrailUsageSummary
		resp, raw := lab.doJSON(http.MethodGet, "/admin/v1/organizations/"+lab.orgID+"/guardrail-usage", lab.adminHeaders, nil, &usage)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
		assert.Equal(t, lab.orgID, usage.OrgID)
		assert.GreaterOrEqual(t, usage.Totals.Evaluations, int64(4))
		assert.GreaterOrEqual(t, usage.Totals.Blocks, int64(2))
		assert.GreaterOrEqual(t, usage.Totals.Redactions, int64(1))
		// pii-redactor ran 3 times (clean, modify, and before keyword-blocker on bypass test) at 50 + 10*1 = 60 micros each,
		// plus keyword-blocker at 100 micros per call -> strictly positive integer micro-dollar sum.
		assert.Greater(t, usage.TotalCostMicros, int64(0))
		assert.Equal(t, usage.Totals.TotalCostMicros, usage.TotalCostMicros)
		assert.NotEmpty(t, usage.DailySeries)
		assert.NotEmpty(t, usage.TopTriggered)
		assert.NotEmpty(t, usage.UsageUnits)

		// Cross-org isolation on usage summary: org2 has zero evaluations
		var org2Usage storage.GuardrailUsageSummary
		resp, raw = lab.doJSON(http.MethodGet, "/admin/v1/organizations/"+org2.ID+"/guardrail-usage", lab.adminHeaders, nil, &org2Usage)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
		assert.Equal(t, int64(0), org2Usage.Totals.Evaluations)
		assert.Equal(t, int64(0), org2Usage.TotalCostMicros)

		// Verify Prometheus /metrics endpoint exposes guardrail metrics
		mReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		mReq.Header.Set("Authorization", lab.adminHeaders["Authorization"])
		mRec := httptest.NewRecorder()
		lab.gw.Handler().ServeHTTP(mRec, mReq)
		require.Equal(t, http.StatusOK, mRec.Code)
		metricsBody := mRec.Body.String()
		assert.Contains(t, metricsBody, `gateway_guardrail_evaluations_total{guardrail="pii-redactor"`)
		assert.Contains(t, metricsBody, `gateway_guardrail_errors_total{guardrail="pii-redactor"`)
		assert.Contains(t, metricsBody, `gateway_guardrail_duration_ms_bucket{guardrail="pii-redactor"`)
	})
}

func TestExpandedSimulate_OutputAndStreamingWindowAndToolCalls(t *testing.T) {
	lab := newGuardrailLab(t)

	resp, raw := lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/guardrail-definitions", lab.adminHeaders, map[string]any{
		"name":        "stream-pii-shield",
		"provider":    "local_content_filter",
		"event_hooks": []string{"pre_call", "during_call", "post_call"},
		"config": map[string]any{
			"action":     "redact",
			"categories": []string{"pii"},
		},
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	// Simulated output streaming chunk evaluation across chunk boundary!
	status, out := lab.simulate(t, map[string]any{
		"guardrail_name":    "stream-pii-shield",
		"direction":         "output",
		"texts":             []string{"Hello alice@example.com, welcome!"},
		"stream_chunk_size": 7,
	})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["allowed"])
	assert.Equal(t, true, out["redacted"])
	assert.Equal(t, "output", out["direction"])
	assert.GreaterOrEqual(t, out["stream_chunks_evaluated"], float64(4))
	redactedPrompt, _ := out["redacted_prompt"].(string)
	assert.NotContains(t, redactedPrompt, "alice@example.com")
	assert.Contains(t, redactedPrompt, "[REDACTED")

	// Dry-run simulate should NOT have recorded billing usage in guardrail-usage
	var usage storage.GuardrailUsageSummary
	resp, raw = lab.doJSON(http.MethodGet, "/admin/v1/organizations/"+lab.orgID+"/guardrail-usage", lab.adminHeaders, nil, &usage)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, int64(0), usage.Totals.Evaluations)
}

func TestYAMLStartupSeedingIdempotentAndVaultEncrypted(t *testing.T) {
	t.Setenv("SEEDED_GUARDRAIL_SECRET", "yaml-vault-secret-value-42")
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Auth.DefaultOrgID = "org_yaml_seed"
	cfg.Guardrails = config.GuardrailsConfig{
		Definitions: []config.GuardrailDefinitionConfig{
			{
				Name:        "yaml-pii-shield",
				Provider:    "local_content_filter",
				EventHooks:  []string{"pre_call", "post_call"},
				StreamScope: "both",
				DefaultOn:   true,
				Precedence:  5,
				Status:      "active",
				Config: map[string]any{
					"action":     "redact",
					"categories": []string{"pii"},
				},
				Secrets: map[string]any{
					"webhook_key": "os.environ/SEEDED_GUARDRAIL_SECRET",
				},
				GuardrailInfo: map[string]any{
					"usage_unit":           "request",
					"cost_per_call_micros": 75,
				},
				Bindings: []config.GuardrailBindingConfig{
					{
						TeamID:   "team_sec",
						IsLocked: true,
					},
				},
			},
		},
		ToolPolicies: []config.ToolPolicyConfig{
			{
				TeamID:       "team_sec",
				ToolName:     "bash_exec",
				InputPolicy:  "blocked",
				OutputPolicy: "untrusted",
			},
		},
	}

	// First server startup seeds definitions, bindings, tool policies, and encrypts secrets
	srv1, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	defer func() { srv1.Shutdown(context.Background()) }()

	defs, err := repo.ListGuardrailDefinitions(context.Background(), "org_yaml_seed", "", "")
	require.NoError(t, err)
	require.Len(t, defs, 1)
	assert.Equal(t, "yaml-pii-shield", defs[0].Name)
	assert.NotEmpty(t, defs[0].EncryptedSecrets)
	assert.NotContains(t, defs[0].EncryptedSecrets, "yaml-vault-secret-value-42")

	// Verify Vault secret is actually encrypted and readable by Admin API as redacted (has_secrets=true)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/guardrail-definitions/"+defs[0].ID, nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	rec := httptest.NewRecorder()
	srv1.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var dto map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &dto))
	assert.Equal(t, true, dto["has_secrets"])
	assert.NotContains(t, rec.Body.String(), "yaml-vault-secret-value-42")

	// Second server startup against same repo must be idempotent (no duplicates!)
	srv2, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	defer func() { srv2.Shutdown(context.Background()) }()

	defs2, err := repo.ListGuardrailDefinitions(context.Background(), "org_yaml_seed", "", "")
	require.NoError(t, err)
	require.Len(t, defs2, 1)

	bindings, err := repo.ListGuardrailBindings(context.Background(), storage.GuardrailBindingFilter{OrgID: "org_yaml_seed"})
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	assert.True(t, bindings[0].IsLocked)

	policies, err := repo.ListToolPolicies(context.Background(), storage.ToolPolicyFilter{OrgID: "org_yaml_seed"})
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "bash_exec", policies[0].ToolName)
	assert.Equal(t, storage.ToolTrustBlocked, policies[0].InputPolicy)

	// Confirm clean non-empty telemetry check for unused strings import safety
	assert.True(t, strings.HasPrefix(defs2[0].ID, "gr_"))
}
