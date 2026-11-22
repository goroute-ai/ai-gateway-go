package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func testGuardrailLivePostgresDSN() string {
	if v := os.Getenv("GATEWAY_POSTGRES_DSN"); v != "" {
		return v
	}
	return "postgres://gateway:gateway@localhost:15432/aigateway_test?sslmode=disable"
}

func boolPtr(v bool) *bool {
	return &v
}

func TestGoRouteExtensions_GuardrailsJSONRoundTrip(t *testing.T) {
	req := domain.CanonicalChatRequest{
		Model: "openai/gpt-4.1",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
		GoRouteExtensions: &domain.GoRouteExtensions{
			TaskID:    "task-123",
			ContextID: "ctx-456",
			Tags:      []string{"pii-strict", "finance"},
			Guardrails: []domain.GuardrailRequestOverride{
				{
					Name:    "pii-guard",
					Enabled: boolPtr(true),
					Action:  domain.GuardrailActionRedact,
					Config:  map[string]any{"mask": "[REDACTED]"},
				},
				{
					Name:    "legacy-filter",
					Enabled: boolPtr(false),
				},
			},
		},
	}

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal CanonicalChatRequest: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal wire map: %v", err)
	}
	extWire, ok := wire["goroute_extensions"].(map[string]any)
	if !ok {
		t.Fatalf("expected goroute_extensions object in JSON, got %T", wire["goroute_extensions"])
	}
	if extWire["task_id"] != "task-123" || extWire["context_id"] != "ctx-456" {
		t.Fatalf("existing wire fields altered: %+v", extWire)
	}

	var decoded domain.CanonicalChatRequest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal CanonicalChatRequest: %v", err)
	}
	if decoded.GoRouteExtensions == nil {
		t.Fatal("expected non-nil GoRouteExtensions")
	}
	if !reflect.DeepEqual(decoded.GoRouteExtensions, req.GoRouteExtensions) {
		t.Fatalf("GoRouteExtensions mismatch:\ngot:  %+v\nwant: %+v", decoded.GoRouteExtensions, req.GoRouteExtensions)
	}

	// Verify GuardrailEvalInput and GuardrailEvalResult JSON round-trip.
	evalIn := domain.GuardrailEvalInput{
		Direction:    domain.GuardrailDirectionInput,
		Hook:         domain.GuardrailHookPreCall,
		RequestID:    "req-1",
		TraceID:      "trace-1",
		OrgID:        "org-1",
		TeamID:       "team-1",
		VirtualKeyID: "vk-1",
		EndUserID:    "user-1",
		Model:        "gpt-4.1",
		Tags:         []string{"finance"},
		Texts:        []string{"hello"},
		StructuredMessages: []domain.CanonicalMessage{
			{Role: "user", Content: "hello"},
		},
		Images: []domain.ImageURL{{URL: "https://example.com/a.png", Detail: "low"}},
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "lookup"}},
		},
		ToolCalls: []domain.CanonicalToolCall{
			{ID: "tc-1", Type: "function", Function: domain.CanonicalFunctionCall{Name: "lookup", Arguments: "{}"}},
		},
		RequestHeaders: map[string]string{"X-Env": "prod"},
		Metadata:       map[string]any{"tier": "gold"},
	}
	inBytes, err := json.Marshal(evalIn)
	if err != nil {
		t.Fatalf("marshal GuardrailEvalInput: %v", err)
	}
	var evalInOut domain.GuardrailEvalInput
	if err := json.Unmarshal(inBytes, &evalInOut); err != nil {
		t.Fatalf("unmarshal GuardrailEvalInput: %v", err)
	}
	if !reflect.DeepEqual(evalInOut, evalIn) {
		t.Fatalf("GuardrailEvalInput round-trip mismatch:\ngot:  %+v\nwant: %+v", evalInOut, evalIn)
	}

	score := 0.95
	evalRes := domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionModify,
		ModifiedTexts:     []string{"[REDACTED]"},
		AppliedGuardrails: []string{"pii-guard"},
		UsageUnits:        12,
		Violations: []domain.GuardrailViolation{
			{
				GuardrailName: "pii-guard",
				Provider:      "local",
				Category:      "pii",
				Severity:      "high",
				Message:       "email redacted",
				Score:         &score,
				Action:        domain.GuardrailActionRedact,
				Decision:      domain.GuardrailDecisionModify,
			},
		},
	}
	resBytes, err := json.Marshal(evalRes)
	if err != nil {
		t.Fatalf("marshal GuardrailEvalResult: %v", err)
	}
	var evalResOut domain.GuardrailEvalResult
	if err := json.Unmarshal(resBytes, &evalResOut); err != nil {
		t.Fatalf("unmarshal GuardrailEvalResult: %v", err)
	}
	if !reflect.DeepEqual(evalResOut, evalRes) {
		t.Fatalf("GuardrailEvalResult round-trip mismatch:\ngot:  %+v\nwant: %+v", evalResOut, evalRes)
	}
}

func TestGuardrailRegistry_DefinitionAndBindingCRUDAndDeepCopy(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	defPrimary := &domain.GuardrailDefinition{
		OrgID:      "org-a",
		Name:       "pii-shield",
		Provider:   "presidio",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall, domain.GuardrailHookPostCall},
		StreamScopeByHook: domain.StreamScopeByHook{
			domain.GuardrailHookPostCall: domain.StreamScopeNonStreaming,
		},
		ModeRule: &domain.GuardrailModeRule{
			Tags: map[string][]domain.GuardrailHook{
				"audit-only": {domain.GuardrailHookLoggingOnly},
			},
			Default: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		},
		DefaultOn:        true,
		EnabledRoles:     []string{"developer", "service_account"},
		TimeoutMs:        1500,
		FailOpen:         false,
		Precedence:       10,
		Config:           map[string]any{"threshold": 0.8, "nested": map[string]any{"region": "us"}},
		EncryptedSecrets: "cipher-1",
		EncryptedDEK:     "dek-1",
		Status:           domain.GuardrailStatusActive,
		GuardrailInfo:    map[string]any{"owner": "secops"},
		Weight:           70,
	}
	if err := repo.CreateGuardrailDefinition(ctx, defPrimary); err != nil {
		t.Fatalf("CreateGuardrailDefinition primary: %v", err)
	}

	// Mutate caller inputs after create to verify repository deep copy.
	defPrimary.EventHooks[0] = domain.GuardrailHookLoggingOnly
	defPrimary.Config["threshold"] = 0.1
	defPrimary.Config["nested"].(map[string]any)["region"] = "eu"
	defPrimary.ModeRule.Tags["audit-only"][0] = domain.GuardrailHookPreMCPCall
	defPrimary.EnabledRoles[0] = "mutated"

	// Ensure EncryptedSecrets & EncryptedDEK are never serialized in JSON.
	defBytes, err := json.Marshal(defPrimary)
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	if strings.Contains(string(defBytes), "cipher-1") || strings.Contains(string(defBytes), "dek-1") {
		t.Fatalf("encrypted secret fields leaked in JSON: %s", string(defBytes))
	}

	got, err := repo.GetGuardrailDefinition(ctx, defPrimary.ID)
	if err != nil {
		t.Fatalf("GetGuardrailDefinition: %v", err)
	}
	if got.EventHooks[0] != domain.GuardrailHookPreCall {
		t.Fatalf("EventHooks mutated in storage: %v", got.EventHooks)
	}
	if got.Config["threshold"] != 0.8 || got.Config["nested"].(map[string]any)["region"] != "us" {
		t.Fatalf("Config mutated in storage: %v", got.Config)
	}
	if got.ModeRule.Tags["audit-only"][0] != domain.GuardrailHookLoggingOnly {
		t.Fatalf("ModeRule mutated in storage: %+v", got.ModeRule)
	}
	if got.EnabledRoles[0] != "developer" {
		t.Fatalf("EnabledRoles mutated in storage: %v", got.EnabledRoles)
	}
	if got.EffectiveStreamScope(domain.GuardrailHookPreCall) != domain.StreamScopeBoth {
		t.Fatalf("EffectiveStreamScope(pre_call) = %q, want both", got.EffectiveStreamScope(domain.GuardrailHookPreCall))
	}
	if got.EffectiveStreamScope(domain.GuardrailHookPostCall) != domain.StreamScopeNonStreaming {
		t.Fatalf("EffectiveStreamScope(post_call) = %q, want non_streaming", got.EffectiveStreamScope(domain.GuardrailHookPostCall))
	}

	// Second active definition sharing the same Name (for weighted load balancing) with lower precedence.
	defSecondary := &domain.GuardrailDefinition{
		OrgID:      "org-a",
		Name:       "pii-shield",
		Provider:   "presidio",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		Precedence: 5,
		Status:     domain.GuardrailStatusActive,
		Weight:     30,
	}
	if err := repo.CreateGuardrailDefinition(ctx, defSecondary); err != nil {
		t.Fatalf("CreateGuardrailDefinition secondary: %v", err)
	}

	// Pending-review definition should appear in ListGuardrailDefinitions, not in ListEffectiveGuardrailsForOrg.
	defPending := &domain.GuardrailDefinition{
		OrgID:      "org-a",
		Name:       "experimental-judge",
		Provider:   "llm_as_a_judge",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookDuringCall},
		Precedence: 20,
		Status:     domain.GuardrailStatusPendingReview,
	}
	if err := repo.CreateGuardrailDefinition(ctx, defPending); err != nil {
		t.Fatalf("CreateGuardrailDefinition pending: %v", err)
	}

	allOrgA, err := repo.ListGuardrailDefinitions(ctx, "org-a", "", "")
	if err != nil || len(allOrgA) != 3 {
		t.Fatalf("ListGuardrailDefinitions all = %d, err=%v", len(allOrgA), err)
	}
	if allOrgA[0].ID != defSecondary.ID || allOrgA[1].ID != defPrimary.ID {
		t.Fatalf("expected precedence order [secondary, primary], got [%s, %s]", allOrgA[0].ID, allOrgA[1].ID)
	}
	byName, err := repo.ListGuardrailDefinitions(ctx, "org-a", domain.GuardrailStatusActive, "pii-shield")
	if err != nil || len(byName) != 2 {
		t.Fatalf("ListGuardrailDefinitions by name = %d, err=%v", len(byName), err)
	}

	// Create bindings across different hierarchical scopes.
	bTeam := &domain.GuardrailBinding{
		OrgID:          "org-a",
		GuardrailID:    defPrimary.ID,
		TeamID:         "team-1",
		ParamOverrides: map[string]any{"threshold": 0.9},
		IsLocked:       true,
	}
	bKeyTag := &domain.GuardrailBinding{
		OrgID:        "org-a",
		GuardrailID:  defPrimary.ID,
		VirtualKeyID: "vk-1",
		ModelGroupID: "mg-1",
		EndUserID:    "eu-1",
		Tag:          "finance",
	}
	bPending := &domain.GuardrailBinding{
		OrgID:       "org-a",
		GuardrailID: defPending.ID,
		TeamID:      "team-1",
	}
	for _, b := range []*domain.GuardrailBinding{bTeam, bKeyTag, bPending} {
		if err := repo.CreateGuardrailBinding(ctx, b); err != nil {
			t.Fatalf("CreateGuardrailBinding: %v", err)
		}
	}
	if bTeam.GuardrailName != "pii-shield" {
		t.Fatalf("expected binding GuardrailName defaulted to pii-shield, got %q", bTeam.GuardrailName)
	}

	// Filter bindings by team, key, model_group, tag.
	gotTeamBindings, err := repo.ListGuardrailBindings(ctx, storage.GuardrailBindingFilter{
		OrgID:  "org-a",
		TeamID: "team-1",
	})
	if err != nil || len(gotTeamBindings) != 2 {
		t.Fatalf("ListGuardrailBindings by team = %d, err=%v", len(gotTeamBindings), err)
	}
	gotTagBindings, err := repo.ListGuardrailBindings(ctx, storage.GuardrailBindingFilter{
		OrgID:        "org-a",
		VirtualKeyID: "vk-1",
		ModelGroupID: "mg-1",
		EndUserID:    "eu-1",
		Tag:          "finance",
	})
	if err != nil || len(gotTagBindings) != 1 || gotTagBindings[0].ID != bKeyTag.ID {
		t.Fatalf("ListGuardrailBindings by key/model/user/tag = %+v, err=%v", gotTagBindings, err)
	}

	// Effective guardrails only include active definitions and bindings to active definitions.
	eff, err := repo.ListEffectiveGuardrailsForOrg(ctx, "org-a")
	if err != nil {
		t.Fatalf("ListEffectiveGuardrailsForOrg: %v", err)
	}
	if len(eff.Definitions) != 2 || len(eff.Bindings) != 2 {
		t.Fatalf("ListEffectiveGuardrailsForOrg got defs=%d bindings=%d, want 2 and 2", len(eff.Definitions), len(eff.Bindings))
	}

	// Update definition without secrets preserves existing encrypted secrets and propagates renamed guardrail_name.
	updatedDef := *got
	updatedDef.Name = "pii-shield-v2"
	updatedDef.EncryptedSecrets = ""
	updatedDef.EncryptedDEK = ""
	if err := repo.UpdateGuardrailDefinition(ctx, &updatedDef); err != nil {
		t.Fatalf("UpdateGuardrailDefinition: %v", err)
	}
	afterUpdate, err := repo.GetGuardrailDefinition(ctx, defPrimary.ID)
	if err != nil {
		t.Fatalf("GetGuardrailDefinition after update: %v", err)
	}
	if afterUpdate.Name != "pii-shield-v2" || afterUpdate.EncryptedSecrets != "cipher-1" || afterUpdate.EncryptedDEK != "dek-1" {
		t.Fatalf("unexpected definition after update: %+v", afterUpdate)
	}
	updatedBinding, err := repo.GetGuardrailBinding(ctx, bTeam.ID)
	if err != nil || updatedBinding.GuardrailName != "pii-shield-v2" {
		t.Fatalf("expected binding GuardrailName updated to pii-shield-v2, got %+v err=%v", updatedBinding, err)
	}

	// Update binding.
	updatedBinding.Tag = "hipaa"
	if err := repo.UpdateGuardrailBinding(ctx, updatedBinding); err != nil {
		t.Fatalf("UpdateGuardrailBinding: %v", err)
	}
	gotUpdatedBinding, err := repo.GetGuardrailBinding(ctx, bTeam.ID)
	if err != nil || gotUpdatedBinding.Tag != "hipaa" {
		t.Fatalf("GetGuardrailBinding after update: got %+v err=%v", gotUpdatedBinding, err)
	}

	// Delete definition cascades to its bindings.
	if err := repo.DeleteGuardrailDefinition(ctx, defPrimary.ID); err != nil {
		t.Fatalf("DeleteGuardrailDefinition: %v", err)
	}
	if _, err := repo.GetGuardrailDefinition(ctx, defPrimary.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for deleted definition, got %v", err)
	}
	if _, err := repo.GetGuardrailBinding(ctx, bTeam.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cascade-deleted binding, got %v", err)
	}

	// Delete remaining binding.
	if err := repo.DeleteGuardrailBinding(ctx, bPending.ID); err != nil {
		t.Fatalf("DeleteGuardrailBinding: %v", err)
	}
	if err := repo.DeleteGuardrailBinding(ctx, bPending.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second DeleteGuardrailBinding, got %v", err)
	}
}

func TestGuardrailRegistry_VaultDEKRotation(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}

	secretV1 := `{"api_key":"sk-guard-v1","webhook_secret":"wh-1"}`
	enc1, dek1, err := vault.EncryptString(secretV1)
	if err != nil {
		t.Fatalf("EncryptString v1: %v", err)
	}

	def := &domain.GuardrailDefinition{
		OrgID:            "org-vault",
		Name:             "lakera-guard",
		Provider:         "lakera",
		EventHooks:       []domain.GuardrailHook{domain.GuardrailHookPreCall},
		EncryptedSecrets: enc1,
		EncryptedDEK:     dek1,
		Status:           domain.GuardrailStatusActive,
	}
	if err := repo.CreateGuardrailDefinition(ctx, def); err != nil {
		t.Fatalf("CreateGuardrailDefinition: %v", err)
	}

	got1, err := repo.GetGuardrailDefinition(ctx, def.ID)
	if err != nil {
		t.Fatalf("GetGuardrailDefinition: %v", err)
	}
	plain1, err := vault.DecryptString(got1.EncryptedSecrets, got1.EncryptedDEK)
	if err != nil || plain1 != secretV1 {
		t.Fatalf("DecryptString v1 = %q, err=%v, want %q", plain1, err, secretV1)
	}

	// Rotate secret with fresh DEK.
	secretV2 := `{"api_key":"sk-guard-v2","webhook_secret":"wh-2"}`
	enc2, dek2, err := vault.EncryptString(secretV2)
	if err != nil {
		t.Fatalf("EncryptString v2: %v", err)
	}
	if dek2 == dek1 || enc2 == enc1 {
		t.Fatal("expected fresh DEK and ciphertext on rotation")
	}

	// Wrong org must fail with ErrNotFound and leave secret unchanged.
	if err := repo.RotateGuardrailSecrets(ctx, "org-other", def.ID, enc2, dek2); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong org rotation, got %v", err)
	}

	if err := repo.RotateGuardrailSecrets(ctx, "org-vault", def.ID, enc2, dek2); err != nil {
		t.Fatalf("RotateGuardrailSecrets: %v", err)
	}

	got2, err := repo.GetGuardrailDefinition(ctx, def.ID)
	if err != nil {
		t.Fatalf("GetGuardrailDefinition after rotation: %v", err)
	}
	if got2.EncryptedDEK != dek2 || got2.EncryptedSecrets != enc2 {
		t.Fatalf("rotated secret fields were not persisted")
	}
	plain2, err := vault.DecryptString(got2.EncryptedSecrets, got2.EncryptedDEK)
	if err != nil || plain2 != secretV2 {
		t.Fatalf("DecryptString v2 = %q, err=%v, want %q", plain2, err, secretV2)
	}
}

func TestGuardrailRegistry_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	defA := &domain.GuardrailDefinition{
		OrgID:      "org-a",
		Name:       "shared-name",
		Provider:   "local",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		Status:     domain.GuardrailStatusActive,
	}
	defB := &domain.GuardrailDefinition{
		OrgID:      "org-b",
		Name:       "shared-name",
		Provider:   "local",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPostCall},
		Status:     domain.GuardrailStatusActive,
	}
	if err := repo.CreateGuardrailDefinition(ctx, defA); err != nil {
		t.Fatalf("create defA: %v", err)
	}
	if err := repo.CreateGuardrailDefinition(ctx, defB); err != nil {
		t.Fatalf("create defB: %v", err)
	}

	// Cross-tenant binding must be rejected.
	crossBinding := &domain.GuardrailBinding{
		OrgID:       "org-b",
		GuardrailID: defA.ID,
		TeamID:      "team-b",
	}
	if err := repo.CreateGuardrailBinding(ctx, crossBinding); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant binding, got %v", err)
	}

	bindA := &domain.GuardrailBinding{OrgID: "org-a", GuardrailID: defA.ID, TeamID: "team-shared"}
	bindB := &domain.GuardrailBinding{OrgID: "org-b", GuardrailID: defB.ID, TeamID: "team-shared"}
	if err := repo.CreateGuardrailBinding(ctx, bindA); err != nil {
		t.Fatalf("create bindA: %v", err)
	}
	if err := repo.CreateGuardrailBinding(ctx, bindB); err != nil {
		t.Fatalf("create bindB: %v", err)
	}

	// Cross-tenant updates must fail.
	tamperedDef := *defA
	tamperedDef.OrgID = "org-b"
	if err := repo.UpdateGuardrailDefinition(ctx, &tamperedDef); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant definition update, got %v", err)
	}
	tamperedBind := *bindA
	tamperedBind.OrgID = "org-b"
	if err := repo.UpdateGuardrailBinding(ctx, &tamperedBind); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant binding update, got %v", err)
	}

	// Org A effective list contains only Org A records.
	effA, err := repo.ListEffectiveGuardrailsForOrg(ctx, "org-a")
	if err != nil {
		t.Fatalf("ListEffectiveGuardrailsForOrg org-a: %v", err)
	}
	if len(effA.Definitions) != 1 || effA.Definitions[0].ID != defA.ID {
		t.Fatalf("org-a effective definitions leaked or missing: %+v", effA.Definitions)
	}
	if len(effA.Bindings) != 1 || effA.Bindings[0].ID != bindA.ID {
		t.Fatalf("org-a effective bindings leaked or missing: %+v", effA.Bindings)
	}
}

func TestPostgres_GuardrailRegistryAndVaultRotationLive(t *testing.T) {
	ctx := context.Background()
	pool, err := storage.NewPostgresPool(ctx, testGuardrailLivePostgresDSN())
	if err != nil {
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, but PostgreSQL unreachable: %v", err)
		}
		t.Skipf("skipping live PostgreSQL guardrail registry test: %v", err)
	}
	defer pool.Close()

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := storage.RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir: %v", err)
	}

	repo, err := storage.NewPostgresRepository(ctx, pool)
	if err != nil {
		t.Fatalf("NewPostgresRepository: %v", err)
	}

	orgA := &domain.Organization{ID: "org-gr-pg-a", Name: "GR Org A", Slug: "gr-pg-a", IsActive: true}
	orgB := &domain.Organization{ID: "org-gr-pg-b", Name: "GR Org B", Slug: "gr-pg-b", IsActive: true}
	for _, org := range []*domain.Organization{orgA, orgB} {
		// Cleanup leftovers if running against an already-populated DB.
		_, _ = pool.Exec(ctx, `DELETE FROM guardrail_bindings WHERE org_id = $1`, org.ID)
		_, _ = pool.Exec(ctx, `DELETE FROM guardrail_definitions WHERE org_id = $1`, org.ID)
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID)
		if err := repo.CreateOrganization(ctx, org); err != nil {
			t.Fatalf("CreateOrganization %s: %v", org.ID, err)
		}
	}

	vault, err := auth.NewVault("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	enc1, dek1, err := vault.EncryptString(`{"token":"secret-v1"}`)
	if err != nil {
		t.Fatalf("EncryptString v1: %v", err)
	}

	defA1 := &domain.GuardrailDefinition{
		OrgID:       orgA.ID,
		Name:        "openai-mod-guard",
		Provider:    "openai_moderation",
		EventHooks:  []domain.GuardrailHook{domain.GuardrailHookPreCall, domain.GuardrailHookPostCall},
		StreamScope: domain.StreamScopeStreaming,
		StreamScopeByHook: domain.StreamScopeByHook{
			domain.GuardrailHookPostCall: domain.StreamScopeNonStreaming,
		},
		ModeRule: &domain.GuardrailModeRule{
			Tags:    map[string][]domain.GuardrailHook{"fast": {domain.GuardrailHookLoggingOnly}},
			Default: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		},
		DefaultOn:        true,
		EnabledRoles:     []string{"developer"},
		TimeoutMs:        2500,
		FailOpen:         true,
		Precedence:       1,
		Config:           map[string]any{"guardrail_id": "gr-123"},
		EncryptedSecrets: enc1,
		EncryptedDEK:     dek1,
		Status:           domain.GuardrailStatusActive,
		GuardrailInfo:    map[string]any{"version": "1"},
		Weight:           60,
	}
	defA2 := &domain.GuardrailDefinition{
		OrgID:      orgA.ID,
		Name:       "openai-mod-guard",
		Provider:   "openai_moderation",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		Precedence: 2,
		Status:     domain.GuardrailStatusActive,
		Weight:     40,
	}
	defAPending := &domain.GuardrailDefinition{
		OrgID:      orgA.ID,
		Name:       "pending-guard",
		Provider:   "local",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookDuringCall},
		Precedence: 3,
		Status:     domain.GuardrailStatusPendingReview,
	}
	defB := &domain.GuardrailDefinition{
		OrgID:      orgB.ID,
		Name:       "openai-mod-guard",
		Provider:   "openai_moderation",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		Status:     domain.GuardrailStatusActive,
	}
	for _, d := range []*domain.GuardrailDefinition{defA1, defA2, defAPending, defB} {
		if err := repo.CreateGuardrailDefinition(ctx, d); err != nil {
			t.Fatalf("CreateGuardrailDefinition %s: %v", d.Name, err)
		}
	}

	// Cross-tenant binding rejected in Postgres.
	if err := repo.CreateGuardrailBinding(ctx, &domain.GuardrailBinding{
		OrgID:       orgB.ID,
		GuardrailID: defA1.ID,
		TeamID:      "team-x",
	}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant Postgres binding, got %v", err)
	}

	b1 := &domain.GuardrailBinding{
		OrgID:          orgA.ID,
		GuardrailID:    defA1.ID,
		TeamID:         "team-alpha",
		VirtualKeyID:   "vk-alpha",
		ModelGroupID:   "mg-alpha",
		Tag:            "fast",
		ParamOverrides: map[string]any{"version": "2"},
		IsLocked:       true,
	}
	b2 := &domain.GuardrailBinding{
		OrgID:       orgA.ID,
		GuardrailID: defAPending.ID,
		TeamID:      "team-alpha",
	}
	if err := repo.CreateGuardrailBinding(ctx, b1); err != nil {
		t.Fatalf("CreateGuardrailBinding b1: %v", err)
	}
	if err := repo.CreateGuardrailBinding(ctx, b2); err != nil {
		t.Fatalf("CreateGuardrailBinding b2: %v", err)
	}

	// Vault DEK rotation in Postgres.
	enc2, dek2, err := vault.EncryptString(`{"token":"secret-v2"}`)
	if err != nil {
		t.Fatalf("EncryptString v2: %v", err)
	}
	if err := repo.RotateGuardrailSecrets(ctx, orgB.ID, defA1.ID, enc2, dek2); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant RotateGuardrailSecrets, got %v", err)
	}
	if err := repo.RotateGuardrailSecrets(ctx, orgA.ID, defA1.ID, enc2, dek2); err != nil {
		t.Fatalf("RotateGuardrailSecrets: %v", err)
	}

	// Read through a brand new PostgresRepository so reads come directly from PostgreSQL.
	freshRepo, err := storage.NewPostgresRepository(ctx, pool)
	if err != nil {
		t.Fatalf("NewPostgresRepository fresh: %v", err)
	}
	gotDef, err := freshRepo.GetGuardrailDefinition(ctx, defA1.ID)
	if err != nil {
		t.Fatalf("fresh GetGuardrailDefinition: %v", err)
	}
	plain, err := vault.DecryptString(gotDef.EncryptedSecrets, gotDef.EncryptedDEK)
	if err != nil || plain != `{"token":"secret-v2"}` {
		t.Fatalf("fresh DecryptString = %q err=%v", plain, err)
	}
	if gotDef.StreamScope != domain.StreamScopeStreaming ||
		gotDef.StreamScopeByHook[domain.GuardrailHookPostCall] != domain.StreamScopeNonStreaming ||
		gotDef.ModeRule == nil || len(gotDef.ModeRule.Tags["fast"]) != 1 ||
		!gotDef.DefaultOn || !gotDef.FailOpen || gotDef.Weight != 60 {
		t.Fatalf("fresh definition round-trip mismatch: %+v", gotDef)
	}

	eff, err := freshRepo.ListEffectiveGuardrailsForOrg(ctx, orgA.ID)
	if err != nil {
		t.Fatalf("fresh ListEffectiveGuardrailsForOrg: %v", err)
	}
	if len(eff.Definitions) != 2 || len(eff.Bindings) != 1 || eff.Bindings[0].ID != b1.ID {
		t.Fatalf("unexpected fresh effective guardrails: defs=%d bindings=%d", len(eff.Definitions), len(eff.Bindings))
	}

	filteredBindings, err := freshRepo.ListGuardrailBindings(ctx, storage.GuardrailBindingFilter{
		OrgID:        orgA.ID,
		TeamID:       "team-alpha",
		VirtualKeyID: "vk-alpha",
		Tag:          "fast",
	})
	if err != nil || len(filteredBindings) != 1 || filteredBindings[0].ID != b1.ID {
		t.Fatalf("fresh ListGuardrailBindings filtered = %+v err=%v", filteredBindings, err)
	}

	// Update definition without secrets preserves rotated secret and propagates renamed guardrail_name.
	gotDef.Name = "openai-mod-guard-renamed"
	gotDef.EncryptedSecrets = ""
	gotDef.EncryptedDEK = ""
	if err := freshRepo.UpdateGuardrailDefinition(ctx, gotDef); err != nil {
		t.Fatalf("UpdateGuardrailDefinition: %v", err)
	}
	gotB1, err := freshRepo.GetGuardrailBinding(ctx, b1.ID)
	if err != nil || gotB1.GuardrailName != "openai-mod-guard-renamed" {
		t.Fatalf("expected binding GuardrailName updated in Postgres, got %+v err=%v", gotB1, err)
	}
	gotDefAfter, err := freshRepo.GetGuardrailDefinition(ctx, defA1.ID)
	if err != nil || gotDefAfter.EncryptedSecrets != enc2 || gotDefAfter.EncryptedDEK != dek2 {
		t.Fatalf("expected rotated secrets preserved after UpdateGuardrailDefinition")
	}

	// Delete definition cascades to bindings in PostgreSQL.
	if err := freshRepo.DeleteGuardrailDefinition(ctx, defA1.ID); err != nil {
		t.Fatalf("DeleteGuardrailDefinition: %v", err)
	}
	if _, err := freshRepo.GetGuardrailBinding(ctx, b1.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cascade-deleted Postgres binding, got %v", err)
	}
}
