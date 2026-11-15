package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestLivePostgresMigrationsAndGuardrailsApplyUsagePersistence(t *testing.T) {
	ctx := context.Background()
	pgDSN := getEnvOrDefault("GATEWAY_POSTGRES_DSN", "postgres://gateway:gateway@localhost:5432/aigateway?sslmode=disable")
	pool, err := storage.NewPostgresPool(ctx, pgDSN)
	if err != nil {
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, cannot connect to PostgreSQL: %v", err)
		}
		t.Skipf("skipping live guardrails e2e test: cannot connect to PostgreSQL: %v", err)
	}
	defer pool.Close()

	ts, _, pgRepo, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	// 1. Verify tables from migrations 0016-0019 exist in live PostgreSQL schema.
	for _, tbl := range []string{
		"guardrail_definitions",
		"guardrail_bindings",
		"tool_policies",
		"daily_guardrail_metrics",
		"daily_guardrail_usage_units",
		"spend_log_guardrails",
	} {
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, tbl).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %s: %v", tbl, err)
		}
		if !exists {
			t.Fatalf("expected PostgreSQL table %s from migrations 0016-0019 to exist", tbl)
		}
	}

	adminHeaders := map[string]string{
		"Authorization": "Bearer sk-gw-master-admin-e2e-test-key",
		"Content-Type":  "application/json",
	}
	doJSON := func(method, path string, headers map[string]string, body any, out any) int {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Fatalf("encode %s %s: %v", method, path, err)
			}
		}
		req, err := http.NewRequest(method, ts.URL+path, &buf)
		if err != nil {
			t.Fatalf("new request %s %s: %v", method, path, err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do %s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		if out != nil {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				t.Fatalf("decode %s %s: %v", method, path, err)
			}
		}
		return resp.StatusCode
	}

	// 2. Create Org, Team, and Virtual Key permitting /v1/guardrails/apply
	var org domain.Organization
	if code := doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Live Guardrails Org",
		"slug": "live-gr-" + time.Now().UTC().Format("150405.000"),
	}, &org); code != http.StatusCreated {
		t.Fatalf("create org status=%d", code)
	}

	var team domain.Team
	if code := doJSON(http.MethodPost, "/admin/v1/teams", adminHeaders, map[string]any{
		"org_id": org.ID,
		"name":   "Live Sec Team",
	}, &team); code != http.StatusCreated {
		t.Fatalf("create team status=%d", code)
	}

	var keyResp struct {
		ID  string `json:"id"`
		Key string `json:"raw_key"`
	}
	if code := doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":            org.ID,
		"team_id":           team.ID,
		"name":              "live-apply-key",
		"allowed_endpoints": []string{"/v1/guardrails/apply"},
	}, &keyResp); code != http.StatusCreated {
		t.Fatalf("create virtual key status=%d", code)
	}

	// 3. Create Guardrail Definition with Vault secret & micro-dollar pricing + Binding + Tool Policy
	var defOut map[string]any
	if code := doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/guardrail-definitions", adminHeaders, map[string]any{
		"name":        "live-pii-shield",
		"provider":    "local_content_filter",
		"event_hooks": []string{"pre_call"},
		"default_on":  true,
		"config": map[string]any{
			"action":     "redact",
			"categories": []string{"pii"},
		},
		"secrets": map[string]any{
			"api_key": "live-secret-987",
		},
		"guardrail_info": map[string]any{
			"usage_unit":           "request",
			"cost_per_call_micros": 120,
			"cost_per_unit_micros": 30,
		},
	}, &defOut); code != http.StatusCreated {
		t.Fatalf("create guardrail definition status=%d", code)
	}
	defID, _ := defOut["id"].(string)
	if defID == "" {
		t.Fatalf("missing guardrail definition id")
	}

	if code := doJSON(http.MethodPost, "/admin/v1/guardrail-bindings", adminHeaders, map[string]any{
		"org_id":       org.ID,
		"guardrail_id": defID,
		"team_id":      team.ID,
		"is_locked":    true,
	}, nil); code != http.StatusCreated {
		t.Fatalf("create binding status=%d", code)
	}

	if code := doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/tool-policies", adminHeaders, map[string]any{
		"team_id":       team.ID,
		"tool_name":     "shell_exec",
		"input_policy":  "blocked",
		"output_policy": "untrusted",
	}, nil); code != http.StatusOK {
		t.Fatalf("upsert tool policy status=%d", code)
	}

	// 4. Invoke POST /v1/guardrails/apply and verify PostgreSQL rollup persistence
	dpHeaders := map[string]string{
		"Authorization": "Bearer " + keyResp.Key,
		"Content-Type":  "application/json",
	}
	var applyOut map[string]any
	if code := doJSON(http.MethodPost, "/v1/guardrails/apply", dpHeaders, map[string]any{
		"guardrail_name": "live-pii-shield",
		"input_type":     "request",
		"text":           "Email alice@example.com for details",
	}, &applyOut); code != http.StatusOK {
		t.Fatalf("apply guardrails status=%d", code)
	}
	if applyOut["decision"] != "modify" {
		t.Fatalf("expected modify decision, got %v", applyOut["decision"])
	}

	var usage storage.GuardrailUsageSummary
	if code := doJSON(http.MethodGet, "/admin/v1/organizations/"+org.ID+"/guardrail-usage", adminHeaders, nil, &usage); code != http.StatusOK {
		t.Fatalf("get guardrail usage status=%d", code)
	}
	if usage.Totals.Evaluations != 1 || usage.Totals.Redactions != 1 || usage.TotalCostMicros != 150 {
		t.Fatalf("unexpected live usage summary: %+v", usage)
	}

	// 5. Verify RecordSpendLogGuardrail & ListSpendLogGuardrails directly on live PostgresRepository
	err = pgRepo.RecordSpendLogGuardrail(ctx, &storage.SpendLogGuardrail{
		OrgID:         org.ID,
		SpendLogID:    "spend_live_1",
		GuardrailID:   defID,
		GuardrailName: "live-pii-shield",
		Hook:          "pre_call",
		Decision:      "modify",
		Units:         1,
		CostMicros:    150,
	})
	if err != nil {
		t.Fatalf("RecordSpendLogGuardrail failed: %v", err)
	}
	attributions, err := pgRepo.ListSpendLogGuardrails(ctx, org.ID, "spend_live_1")
	if err != nil {
		t.Fatalf("ListSpendLogGuardrails failed: %v", err)
	}
	if len(attributions) != 1 || attributions[0].CostMicros != 150 {
		t.Fatalf("unexpected spend_log_guardrails rows: %+v", attributions)
	}
}
