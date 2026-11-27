package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestLivePostgresMigrationsAndGuardrailsPersistence(t *testing.T) {
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

	// 1. Verify active guardrail tables exist and deprecated tables were dropped by 0044.
	for _, tbl := range []string{"guardrail_policies", "guardrail_definitions"} {
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, tbl).Scan(&exists)
		if err != nil || !exists {
			t.Fatalf("expected PostgreSQL table %s to exist (exists=%v, err=%v)", tbl, exists, err)
		}
	}
	for _, dropped := range []string{
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
			)`, dropped).Scan(&exists)
		if err != nil || exists {
			t.Fatalf("expected deprecated table %s dropped by 0044 (exists=%v, err=%v)", dropped, exists, err)
		}
	}

	adminHeaders := map[string]string{
		"Authorization": "Bearer sk-gw-master-admin-live-e2e-key",
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

	// 2. Create Org & Built-in Guardrail Policy with blocked_patterns
	var org domain.Organization
	if code := doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Live Guardrails Org",
		"slug": "live-gr-" + time.Now().UTC().Format("150405.000"),
	}, &org); code != http.StatusCreated {
		t.Fatalf("create org status=%d", code)
	}

	var savedPol domain.GuardrailPolicy
	if code := doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/guardrails", adminHeaders, map[string]any{
		"mode":                 "enforce",
		"enable_pii_detection": true,
		"pii_action":           "redact",
		"blocked_patterns":     []string{`INTERNAL-\d{4}`},
	}, &savedPol); code != http.StatusOK {
		t.Fatalf("set guardrail policy status=%d", code)
	}
	if len(savedPol.BlockedPatterns) != 1 || savedPol.BlockedPatterns[0] != `INTERNAL-\d{4}` {
		t.Fatalf("unexpected persisted blocked_patterns: %+v", savedPol.BlockedPatterns)
	}

	// 3. Create External Guardrail Definition with Vault secret & run /test
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"modify","modified_texts":["Email [REDACTED_EMAIL] for details"]}`))
	}))
	defer webhookSrv.Close()

	var defOut map[string]any
	if code := doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/guardrail-definitions", adminHeaders, map[string]any{
		"name":        "live-http-guard",
		"provider":    "generic_http",
		"event_hooks": []string{"pre_call"},
		"enabled":     true,
		"config":      map[string]any{"url": webhookSrv.URL},
		"secrets":     map[string]any{"bearer_token": "live-secret-987"},
	}, &defOut); code != http.StatusCreated {
		t.Fatalf("create guardrail definition status=%d", code)
	}
	defID, _ := defOut["id"].(string)
	if defID == "" {
		t.Fatalf("missing guardrail definition id")
	}

	// Verify definition persisted in live PostgreSQL repository
	defs, err := pgRepo.ListGuardrailDefinitions(ctx, org.ID, true)
	if err != nil || len(defs) != 1 || defs[0].ID != defID || !defs[0].Enabled {
		t.Fatalf("unexpected live guardrail definitions: defs=%+v err=%v", defs, err)
	}

	// 4. Dry-run simulate built-in policy
	var simOut map[string]any
	if code := doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/guardrails/simulate", adminHeaders, map[string]any{
		"prompt": "Email alice@example.com for details",
	}, &simOut); code != http.StatusOK {
		t.Fatalf("simulate guardrails status=%d", code)
	}
	if simOut["redacted"] != true {
		t.Fatalf("expected redacted=true from simulate, got %+v", simOut)
	}
}
