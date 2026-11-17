package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAdminExtensions_NewReadAndSimulationEndpoints(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock upstream server for provider list models
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"object": "list",
			"data": [
				{"id": "gpt-4o", "object": "model"}
			]
		}`))
	}))
	defer upstreamSrv.Close()

	gw, err := server.New(cfg, repo, nil, upstreamSrv.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	// Setup initial test data
	org := &domain.Organization{ID: "org_test", Name: "Test Org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// 1. Test GET /admin/v1/users
	user := &domain.User{ID: "usr_1", OrgID: "org_test", Email: "alice@test.com", Role: domain.RoleDeveloper, IsActive: true}
	require.NoError(t, repo.CreateUser(ctx, user))

	req, _ := http.NewRequest(http.MethodGet, "/admin/v1/users?org_id=org_test", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var usersResp struct {
		Data []*domain.User `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &usersResp))
	require.Len(t, usersResp.Data, 1)
	assert.Equal(t, "usr_1", usersResp.Data[0].ID)
	assert.Equal(t, "alice@test.com", usersResp.Data[0].Email)

	// 2. Test GET /admin/v1/organizations/{orgID}/subscriptions
	sub := &domain.OrgProviderSubscription{OrgID: "org_test", Provider: domain.ProviderOpenAI, IsEnabled: true}
	require.NoError(t, repo.SetOrgProviderSubscription(ctx, sub))

	req, _ = http.NewRequest(http.MethodGet, "/admin/v1/organizations/org_test/subscriptions", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var subsResp struct {
		Data []*domain.OrgProviderSubscription `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &subsResp))
	require.Len(t, subsResp.Data, 1)
	assert.Equal(t, domain.ProviderOpenAI, subsResp.Data[0].Provider)

	// 3. Test GET /admin/v1/organizations/{orgID}/models
	pol := &domain.OrgModelPolicy{OrgID: "org_test", GlobalModelID: "openai/gpt-4o", IsEnabled: true}
	require.NoError(t, repo.SetOrgModelPolicy(ctx, pol))

	req, _ = http.NewRequest(http.MethodGet, "/admin/v1/organizations/org_test/models", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var polsResp struct {
		Data []*domain.OrgModelPolicy `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &polsResp))
	require.Len(t, polsResp.Data, 1)
	assert.Equal(t, "openai/gpt-4o", polsResp.Data[0].GlobalModelID)

	// 4. Test GET /admin/v1/deployments
	mg := &domain.ModelGroup{ID: "mg_fast", OrgID: "org_test", Alias: "fast", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))
	dep := &domain.Deployment{ID: "dep_1", ModelGroupID: "mg_fast", GlobalModelID: "openai/gpt-4o", Status: domain.DeploymentStatusActive}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	req, _ = http.NewRequest(http.MethodGet, "/admin/v1/deployments?model_group_id=mg_fast", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var depsResp struct {
		Data []*domain.Deployment `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &depsResp))
	require.Len(t, depsResp.Data, 1)
	assert.Equal(t, "dep_1", depsResp.Data[0].ID)

	// 5. Test POST /admin/v1/organizations/{orgID}/guardrails/simulate
	simPayload := map[string]any{
		"prompt": "Here is my secret sk-1234567890123456 and SSN 000-11-2222",
		"policy": map[string]any{
			"enable_secret_detection": true,
			"secret_action":           "redact",
			"enable_pii_detection":    true,
			"pii_action":              "redact",
		},
	}
	simBytes, _ := json.Marshal(simPayload)
	req, _ = http.NewRequest(http.MethodPost, "/admin/v1/organizations/org_test/guardrails/simulate", bytes.NewReader(simBytes))
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var simResp struct {
		Allowed        bool     `json:"allowed"`
		Violations     []string `json:"violations"`
		Redacted       bool     `json:"redacted"`
		RedactedPrompt string   `json:"redacted_prompt"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &simResp))
	assert.True(t, simResp.Allowed)
	assert.True(t, simResp.Redacted)
	assert.Contains(t, simResp.Violations, "secret_detected")
	assert.Contains(t, simResp.Violations, "pii_detected")
	assert.Contains(t, simResp.RedactedPrompt, "[REDACTED_SECRET]")
	assert.Contains(t, simResp.RedactedPrompt, "[REDACTED_SSN]")

	// 6. Test POST /admin/v1/credentials/validate (Preflight Validation)
	preflightPayload := map[string]any{
		"provider": "openai",
		"api_key":  "sk-test-key",
		"base_url": upstreamSrv.URL,
	}
	preflightBytes, _ := json.Marshal(preflightPayload)
	req, _ = http.NewRequest(http.MethodPost, "/admin/v1/credentials/validate", bytes.NewReader(preflightBytes))
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var preflightResp struct {
		Provider         string `json:"provider"`
		Valid            bool   `json:"valid"`
		ValidationStatus string `json:"validation_status"`
		DiscoveredModels int    `json:"discovered_models"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preflightResp))
	assert.Equal(t, "openai", preflightResp.Provider)
	assert.True(t, preflightResp.Valid)
	assert.Equal(t, "success", preflightResp.ValidationStatus)
	assert.Equal(t, 1, preflightResp.DiscoveredModels)
}

func TestAdminExtensions_OpenAPISchemaPayloadAlignment(t *testing.T) {
	// 1. Locate and parse docs/openapi/gateway.openapi.yaml
	possiblePaths := []string{
		filepath.Join("..", "..", "docs", "openapi", "gateway.openapi.yaml"),
		filepath.Join("docs", "openapi", "gateway.openapi.yaml"),
	}
	var openAPIBytes []byte
	var err error
	for _, p := range possiblePaths {
		if b, readErr := os.ReadFile(p); readErr == nil {
			openAPIBytes = b
			break
		}
	}
	require.NotEmpty(t, openAPIBytes, "failed to read gateway.openapi.yaml from expected locations")

	var openAPIDoc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type   string `yaml:"type"`
					Format string `yaml:"format"`
				} `yaml:"properties"`
				Required []string `yaml:"required"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	require.NoError(t, yaml.Unmarshal(openAPIBytes, &openAPIDoc))

	schemas := openAPIDoc.Components.Schemas
	require.Contains(t, schemas, "OrgProviderSubscription")
	require.Contains(t, schemas, "OrgModelPolicy")
	require.Contains(t, schemas, "AdminUser")
	require.Contains(t, schemas, "AdminDeployment")
	require.Contains(t, schemas, "AdminModelGroup")
	require.Contains(t, schemas, "GoRouteExtensions")
	require.Contains(t, schemas, "CredentialValidateResponse")

	// Helper to verify that every JSON key in the response payload matches the schema properties,
	// required-field presence, and primitive JSON value types.
	assertPayloadMatchesSchema := func(t *testing.T, schemaName string, payload map[string]any) {
		t.Helper()
		schema, ok := schemas[schemaName]
		require.True(t, ok, "schema %s missing from OpenAPI spec", schemaName)
		for key, val := range payload {
			prop, exists := schema.Properties[key]
			assert.True(t, exists, "handler returned key %q which is not defined in OpenAPI schema %s", key, schemaName)
			if exists && val != nil && prop.Type != "" {
				switch prop.Type {
				case "string":
					_, isStr := val.(string)
					assert.True(t, isStr, "expected property %q in schema %s to be string, got %T (%v)", key, schemaName, val, val)
				case "boolean":
					_, isBool := val.(bool)
					assert.True(t, isBool, "expected property %q in schema %s to be boolean, got %T (%v)", key, schemaName, val, val)
				case "integer", "number":
					_, isNum := val.(float64)
					assert.True(t, isNum, "expected property %q in schema %s to be number/integer, got %T (%v)", key, schemaName, val, val)
				case "array":
					_, isSlice := val.([]any)
					assert.True(t, isSlice, "expected property %q in schema %s to be array, got %T (%v)", key, schemaName, val, val)
				case "object":
					_, isMap := val.(map[string]any)
					assert.True(t, isMap, "expected property %q in schema %s to be object, got %T (%v)", key, schemaName, val, val)
				}
			}
		}
		for _, reqField := range schema.Required {
			val, exists := payload[reqField]
			assert.True(t, exists, "handler response missing required field %q defined in OpenAPI schema %s", reqField, schemaName)
			assert.NotNil(t, val, "required field %q in schema %s should not be nil", reqField, schemaName)
		}
	}

	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org_contract", Name: "Contract Test Org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Test 1: OrgProviderSubscription alignment
	sub := &domain.OrgProviderSubscription{
		OrgID:         "org_contract",
		Provider:      domain.ProviderAnthropic,
		IsEnabled:     true,
		AutoEnableNew: true,
	}
	require.NoError(t, repo.SetOrgProviderSubscription(ctx, sub))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/organizations/org_contract/subscriptions", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var subRespMap map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &subRespMap))
	dataSlice, ok := subRespMap["data"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, dataSlice)
	firstSub, ok := dataSlice[0].(map[string]any)
	require.True(t, ok)
	assertPayloadMatchesSchema(t, "OrgProviderSubscription", firstSub)

	// Test 2: OrgModelPolicy alignment
	pol := &domain.OrgModelPolicy{
		OrgID:         "org_contract",
		GlobalModelID: "anthropic/claude-3-5-sonnet",
		IsEnabled:     true,
		ApprovedBy:    "admin@test.com",
		ApprovedAt:    time.Now().UTC(),
	}
	require.NoError(t, repo.SetOrgModelPolicy(ctx, pol))

	req = httptest.NewRequest(http.MethodGet, "/admin/v1/organizations/org_contract/models", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var polRespMap map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &polRespMap))
	polDataSlice, ok := polRespMap["data"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, polDataSlice)
	firstPol, ok := polDataSlice[0].(map[string]any)
	require.True(t, ok)
	assertPayloadMatchesSchema(t, "OrgModelPolicy", firstPol)

	// Test 3: AdminUser alignment
	user := &domain.User{
		ID:        "usr_contract",
		OrgID:     "org_contract",
		Email:     "user@contract.io",
		Role:      domain.RoleDeveloper,
		IsActive:  true,
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.CreatedAt,
	}
	require.NoError(t, repo.CreateUser(ctx, user))

	req = httptest.NewRequest(http.MethodGet, "/admin/v1/users?org_id=org_contract", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var userRespMap map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &userRespMap))
	userDataSlice, ok := userRespMap["data"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, userDataSlice)
	firstUser, ok := userDataSlice[0].(map[string]any)
	require.True(t, ok)
	assertPayloadMatchesSchema(t, "AdminUser", firstUser)

	// Test 4: AdminDeployment & AdminModelGroup alignment (including v1.20 routing fields)
	mg := &domain.ModelGroup{
		ID:              "mg_contract",
		OrgID:           "org_contract",
		Alias:           "contract",
		Description:     "Contract group",
		RoutingStrategy: domain.StrategyFastestResponse,
		FallbackGroupIDs: []string{
			"mg_backup",
		},
		ContextWindowFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: "long-ctx", Overrides: map[string]any{"max_tokens": 8192}},
		},
		ContentPolicyFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: "safe-fallback"},
		},
		FallbackTargets: []domain.FallbackTarget{
			{GroupAliasOrID: "mg_backup"},
		},
		RetryPolicy: &domain.RetryPolicy{
			RateLimitRetries: 3,
			TimeoutRetries:   2,
			DefaultRetries:   1,
		},
		CooldownPolicy: &domain.CooldownPolicy{
			AllowedFails:         map[string]int{"429": 2},
			FailureRateThreshold: 0.25,
			MinRequestsPerMinute: 10,
			MaxCooldownSeconds:   120,
		},
		MaxRetries:       2,
		CooldownSeconds:  30,
		FailureThreshold: 3,
		IsActive:         true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))

	req = httptest.NewRequest(http.MethodGet, "/admin/v1/model-groups?org_id=org_contract", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var mgRespMap map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &mgRespMap))
	mgDataSlice, ok := mgRespMap["data"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, mgDataSlice)
	firstMG, ok := mgDataSlice[0].(map[string]any)
	require.True(t, ok)
	assertPayloadMatchesSchema(t, "AdminModelGroup", firstMG)

	dep := &domain.Deployment{
		ID:                "dep_contract",
		ModelGroupID:      "mg_contract",
		GlobalModelID:     "anthropic/claude-3-5-sonnet",
		Priority:          1,
		Tags:              []string{"tier:primary", "compliance:eu"},
		MaxBudgetMicros:   50_000_000,
		BudgetResetPeriod: "daily",
		Status:            domain.DeploymentStatusActive,
		DeploymentName:    "dep-us-east",
		Region:            "us-east-1",
		CreatedAt:         org.CreatedAt,
		UpdatedAt:         org.CreatedAt,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	req = httptest.NewRequest(http.MethodGet, "/admin/v1/deployments?model_group_id=mg_contract", nil)
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var depRespMap map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &depRespMap))
	depDataSlice, ok := depRespMap["data"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, depDataSlice)
	firstDep, ok := depDataSlice[0].(map[string]any)
	require.True(t, ok)
	assertPayloadMatchesSchema(t, "AdminDeployment", firstDep)

	// Test 5: CredentialValidateResponse alignment
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":"claude-3-5-sonnet"}]}`))
	}))
	defer upstreamSrv.Close()

	preflightPayload := map[string]any{
		"provider": "openai",
		"api_key":  "sk-test-preflight",
		"base_url": upstreamSrv.URL,
	}
	preflightBytes, _ := json.Marshal(preflightPayload)
	req = httptest.NewRequest(http.MethodPost, "/admin/v1/credentials/validate", bytes.NewReader(preflightBytes))
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var preflightMap map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preflightMap))
	assertPayloadMatchesSchema(t, "CredentialValidateResponse", preflightMap)
}

func TestAdminModelGroupAndDeployment_CreateListAndValidation(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"
	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org_v120", Name: "v120 Org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// 1. POST /admin/v1/model-groups with specialized fallbacks, policies, and legacy fallback_groups compat
	mgPayload := map[string]any{
		"org_id":           "org_v120",
		"alias":            "smart-fast",
		"routing_strategy": "fastest-response",
		"fallback_groups":  []string{"reasoning"},
		"context_window_fallbacks": []map[string]any{
			{"target": "long-context", "overrides": map[string]any{"max_tokens": 4096}},
		},
		"content_policy_fallbacks": []map[string]any{
			{"target": "safe-models"},
		},
		"retry_policy": map[string]any{
			"rate_limit_retries": 3,
			"timeout_retries":    2,
		},
		"cooldown_policy": map[string]any{
			"failure_rate_threshold":  0.3,
			"min_requests_per_minute": 5,
			"max_cooldown_seconds":    60,
		},
	}
	mgBytes, _ := json.Marshal(mgPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/model-groups", bytes.NewReader(mgBytes))
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var createdMG domain.ModelGroup
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createdMG))
	assert.Equal(t, domain.StrategyFastestResponse, createdMG.RoutingStrategy)
	assert.Equal(t, []string{"reasoning"}, createdMG.FallbackGroupIDs)
	require.Len(t, createdMG.ContextWindowFallbacks, 1)
	assert.Equal(t, "long-context", createdMG.ContextWindowFallbacks[0].GroupAliasOrID)
	require.Len(t, createdMG.ContentPolicyFallbacks, 1)
	assert.Equal(t, "safe-models", createdMG.ContentPolicyFallbacks[0].GroupAliasOrID)
	require.NotNil(t, createdMG.RetryPolicy)
	assert.Equal(t, 3, createdMG.RetryPolicy.RateLimitRetries)
	require.NotNil(t, createdMG.CooldownPolicy)
	assert.InDelta(t, 0.3, createdMG.CooldownPolicy.FailureRateThreshold, 1e-9)

	// 2. Reject invalid empty fallback target and invalid failure_rate_threshold
	badMGBytes, _ := json.Marshal(map[string]any{
		"org_id":                   "org_v120",
		"alias":                    "bad-mg",
		"context_window_fallbacks": []map[string]any{{"target": "  "}},
	})
	req = httptest.NewRequest(http.MethodPost, "/admin/v1/model-groups", bytes.NewReader(badMGBytes))
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// 3. POST /admin/v1/deployments with tags, max_budget_micros, budget_reset_period, priority
	depBytes, _ := json.Marshal(map[string]any{
		"model_group_id":      createdMG.ID,
		"global_model_id":     "openai/gpt-4.1",
		"deployment_name":     "eu-primary",
		"region":              "eu-west-1",
		"priority":            2,
		"weight":              80,
		"tags":                []string{" tier:fast ", "", "eu-gdpr"},
		"max_budget_micros":   15000000,
		"budget_reset_period": "daily",
	})
	req = httptest.NewRequest(http.MethodPost, "/admin/v1/deployments", bytes.NewReader(depBytes))
	req.Header.Set("Authorization", "Bearer admin_master_secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var createdDep domain.Deployment
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createdDep))
	assert.Equal(t, 2, createdDep.Priority)
	assert.Equal(t, []string{"tier:fast", "eu-gdpr"}, createdDep.Tags)
	assert.Equal(t, int64(15000000), createdDep.MaxBudgetMicros)
	assert.Equal(t, "daily", createdDep.BudgetResetPeriod)

	// 4. Reject negative max_budget_micros and invalid budget_reset_period
	for _, badDep := range []map[string]any{
		{"model_group_id": createdMG.ID, "global_model_id": "openai/gpt-4.1", "max_budget_micros": -100},
		{"model_group_id": createdMG.ID, "global_model_id": "openai/gpt-4.1", "budget_reset_period": "weekly"},
	} {
		b, _ := json.Marshal(badDep)
		req = httptest.NewRequest(http.MethodPost, "/admin/v1/deployments", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer admin_master_secret")
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	}
}
