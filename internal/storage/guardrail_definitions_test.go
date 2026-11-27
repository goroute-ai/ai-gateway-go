// Guardrail definition and policy storage tests verify JSON round-trips,
// CRUD deep-copy safety, Vault DEK secret rotation, tenant isolation, and
// GuardrailPolicy.BlockedPatterns persistence.

package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestGuardrailEvalTypes_JSONRoundTrip(t *testing.T) {
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
		Images:         []domain.ImageURL{{URL: "https://example.com/a.png", Detail: "low"}},
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
		AppliedGuardrails: []string{"dlp-webhook"},
		Violations: []domain.GuardrailViolation{
			{
				GuardrailName: "dlp-webhook",
				Provider:      "generic_http",
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

func TestGuardrailDefinitions_CRUDDeepCopyAndSecretRotation(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	defPrimary := &domain.GuardrailDefinition{
		OrgID:            "org-a",
		Name:             "dlp-webhook",
		Provider:         "generic_http",
		EventHooks:       []domain.GuardrailHook{domain.GuardrailHookPreCall, domain.GuardrailHookPostCall},
		Enabled:          true,
		TimeoutMs:        1500,
		FailOpen:         false,
		Precedence:       10,
		Config:           map[string]any{"url": "https://guard.example.com/eval", "nested": map[string]any{"region": "us"}},
		EncryptedSecrets: "cipher-1",
		EncryptedDEK:     "dek-1",
	}
	if err := repo.CreateGuardrailDefinition(ctx, defPrimary); err != nil {
		t.Fatalf("CreateGuardrailDefinition primary: %v", err)
	}

	// Mutate caller inputs after create to verify deep copy.
	defPrimary.EventHooks[0] = domain.GuardrailHookLoggingOnly
	defPrimary.Config["url"] = "https://mutated.example.com"
	defPrimary.Config["nested"].(map[string]any)["region"] = "eu"

	// Ensure EncryptedSecrets & EncryptedDEK never serialize in JSON.
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
	if got.Config["url"] != "https://guard.example.com/eval" || got.Config["nested"].(map[string]any)["region"] != "us" {
		t.Fatalf("Config mutated in storage: %v", got.Config)
	}

	// Add a disabled definition and verify onlyEnabled filtering + precedence ordering.
	defDisabled := &domain.GuardrailDefinition{
		OrgID:      "org-a",
		Name:       "disabled-mod",
		Provider:   "openai_moderation",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		Enabled:    false,
		Precedence: 5,
	}
	if err := repo.CreateGuardrailDefinition(ctx, defDisabled); err != nil {
		t.Fatalf("CreateGuardrailDefinition disabled: %v", err)
	}

	allDefs, err := repo.ListGuardrailDefinitions(ctx, "org-a", false)
	if err != nil || len(allDefs) != 2 {
		t.Fatalf("ListGuardrailDefinitions(all) = %d, err=%v; want 2", len(allDefs), err)
	}
	if allDefs[0].Name != "disabled-mod" || allDefs[1].Name != "dlp-webhook" {
		t.Fatalf("expected precedence ordering, got %q then %q", allDefs[0].Name, allDefs[1].Name)
	}

	enabledDefs, err := repo.ListGuardrailDefinitions(ctx, "org-a", true)
	if err != nil || len(enabledDefs) != 1 || enabledDefs[0].Name != "dlp-webhook" {
		t.Fatalf("ListGuardrailDefinitions(enabled) = %+v, err=%v", enabledDefs, err)
	}

	// Update without secrets preserves existing Vault ciphertext.
	got.TimeoutMs = 2500
	got.EncryptedSecrets = ""
	got.EncryptedDEK = ""
	if err := repo.UpdateGuardrailDefinition(ctx, got); err != nil {
		t.Fatalf("UpdateGuardrailDefinition: %v", err)
	}
	afterUpdate, err := repo.GetGuardrailDefinition(ctx, got.ID)
	if err != nil {
		t.Fatalf("GetGuardrailDefinition after update: %v", err)
	}
	if afterUpdate.TimeoutMs != 2500 || afterUpdate.EncryptedSecrets != "cipher-1" || afterUpdate.EncryptedDEK != "dek-1" {
		t.Fatalf("unexpected state after update: %+v", afterUpdate)
	}

	// RotateGuardrailSecrets updates encrypted fields.
	if err := repo.RotateGuardrailSecrets(ctx, "org-a", got.ID, "cipher-2", "dek-2"); err != nil {
		t.Fatalf("RotateGuardrailSecrets: %v", err)
	}
	afterRotate, _ := repo.GetGuardrailDefinition(ctx, got.ID)
	if afterRotate.EncryptedSecrets != "cipher-2" || afterRotate.EncryptedDEK != "dek-2" {
		t.Fatalf("secret rotation did not persist: %+v", afterRotate)
	}

	// Delete removes definition cleanly.
	if err := repo.DeleteGuardrailDefinition(ctx, got.ID); err != nil {
		t.Fatalf("DeleteGuardrailDefinition: %v", err)
	}
	if _, err := repo.GetGuardrailDefinition(ctx, got.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestGuardrailPolicy_BlockedPatternsPersistence(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	pol := &domain.GuardrailPolicy{
		OrgID:                 "org-pol",
		Mode:                  domain.GuardrailModeEnforce,
		EnablePromptInjection: true,
		PromptInjectionAction: domain.GuardrailActionBlock,
		EnablePIIDetection:    true,
		PIIAction:             domain.GuardrailActionRedact,
		EnableSecretDetection: true,
		SecretAction:          domain.GuardrailActionBlock,
		BlockedKeywords:       []string{"secret-project"},
		BlockedPatterns:       []string{`(?i)codename-\d+`},
		RedactOutputPII:       true,
	}
	if err := repo.SetGuardrailPolicy(ctx, pol); err != nil {
		t.Fatalf("SetGuardrailPolicy: %v", err)
	}
	pol.BlockedPatterns[0] = "mutated"

	loaded, err := repo.GetGuardrailPolicy(ctx, "org-pol")
	if err != nil || loaded == nil {
		t.Fatalf("GetGuardrailPolicy: %v", err)
	}
	if len(loaded.BlockedPatterns) != 1 || loaded.BlockedPatterns[0] != `(?i)codename-\d+` {
		t.Fatalf("unexpected BlockedPatterns: %+v", loaded.BlockedPatterns)
	}
}
