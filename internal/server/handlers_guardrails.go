package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// telemeteredGuardrailDriver wraps any guardrails.Driver so every Evaluate call emits
// scrubbed OTEL `guardrail.evaluate` child spans and low-cardinality OTLP metrics.
type telemeteredGuardrailDriver struct {
	server *GatewayServer
	def    *domain.GuardrailDefinition
	inner  guardrails.Driver
}

func (d *telemeteredGuardrailDriver) Name() string {
	if d.inner != nil {
		return d.inner.Name()
	}
	if d.def != nil {
		return d.def.Name
	}
	return "unknown"
}

func (d *telemeteredGuardrailDriver) SupportedHooks() []domain.GuardrailHook {
	if d.inner == nil {
		return nil
	}
	return d.inner.SupportedHooks()
}

func (d *telemeteredGuardrailDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	gName := d.Name()
	if d.def != nil && strings.TrimSpace(d.def.Name) != "" {
		gName = d.def.Name
	}
	hookStr := string(domain.GuardrailHookPreCall)
	if input != nil && input.Hook != "" {
		hookStr = string(input.Hook)
	}

	spanCtx, span := observability.StartGuardrailEvaluateSpan(ctx, d.server.tracer, gName, hookStr)
	started := time.Now()
	res, err := d.inner.Evaluate(spanCtx, input)
	latencyMs := time.Since(started).Milliseconds()

	decision := string(domain.GuardrailDecisionAllow)
	isErr := err != nil
	var cats []string
	if res != nil {
		if res.Decision != "" {
			decision = string(res.Decision)
		}
		if res.ErrorMessage != "" && err == nil && res.Decision != domain.GuardrailDecisionBlock {
			isErr = true
		}
		for _, v := range res.Violations {
			if v.Category != "" {
				cats = append(cats, v.Category)
			} else if v.Rule != "" {
				cats = append(cats, v.Rule)
			}
		}
	}
	if isErr && len(cats) == 0 {
		cats = append(cats, "evaluation_error")
	}

	observability.FinishGuardrailEvaluateSpan(span, decision, cats, latencyMs, isErr)
	if d.server != nil && d.server.collector != nil {
		d.server.collector.RecordGuardrailEvaluation(observability.GuardrailObservation{
			GuardrailName: gName,
			Hook:          hookStr,
			Decision:      decision,
			LatencyMs:     latencyMs,
			IsError:       isErr,
		})
	}
	return res, err
}

func (s *GatewayServer) wrapGuardrailDriverLookup(base guardrails.DriverLookup) guardrails.DriverLookup {
	return func(ctx context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		drv, err := base(ctx, cfg)
		if err != nil || drv == nil {
			return drv, err
		}
		return &telemeteredGuardrailDriver{
			server: s,
			def:    cfg.Definition,
			inner:  drv,
		}, nil
	}
}

func (s *GatewayServer) recordGuardrailAuditHook(
	ctx context.Context,
	hook domain.GuardrailHook,
	prc guardrails.PipelineRequestContext,
	res *domain.GuardrailEvalResult,
) {
	if s == nil || res == nil || s.repo == nil || prc.OrgID == "" {
		return
	}
	_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:      prc.OrgID,
		ActorID:    prc.VirtualKeyID,
		Action:     "guardrail.evaluated",
		Resource:   string(hook),
		ResourceID: prc.RequestID,
		Details: map[string]any{
			"hook":          hook,
			"decision":      res.Decision,
			"error_message": res.ErrorMessage,
			"violations":    res.Violations,
			"trace_id":      prc.TraceID,
			"model":         prc.Model,
		},
	})
}

// --- Startup YAML Seeding ---

func (s *GatewayServer) seedGuardrailsFromConfig(ctx context.Context) error {
	if s == nil || s.repo == nil || len(s.cfg.Guardrails.Definitions) == 0 {
		return nil
	}

	defaultOrgID := strings.TrimSpace(s.cfg.Auth.DefaultOrgID)
	if defaultOrgID == "" {
		defaultOrgID = "org_default"
	}

	ensureOrg := func(orgID string) error {
		if _, err := s.repo.GetOrganization(ctx, orgID); err == nil {
			return nil
		}
		name := "Default Organization"
		slug := "default"
		if orgID != defaultOrgID {
			name = orgID
			slug = strings.ToLower(strings.ReplaceAll(orgID, "_", "-"))
		}
		return s.repo.CreateOrganization(ctx, &domain.Organization{
			ID:       orgID,
			Name:     name,
			Slug:     slug,
			IsActive: true,
		})
	}

	for _, defCfg := range s.cfg.Guardrails.Definitions {
		orgID := strings.TrimSpace(defCfg.OrgID)
		if orgID == "" {
			orgID = defaultOrgID
		}
		if err := ensureOrg(orgID); err != nil {
			return fmt.Errorf("ensure org %q for seeded guardrail %q: %w", orgID, defCfg.Name, err)
		}

		defID := strings.TrimSpace(defCfg.ID)
		if defID == "" {
			defID = deterministicSeedID("gr", orgID, defCfg.Name, defCfg.Provider)
		}

		enabled := true
		if defCfg.Enabled != nil {
			enabled = *defCfg.Enabled
		}

		hooks := make([]domain.GuardrailHook, 0, len(defCfg.EventHooks))
		for _, h := range defCfg.EventHooks {
			if trimmed := strings.TrimSpace(h); trimmed != "" {
				hooks = append(hooks, domain.GuardrailHook(trimmed))
			}
		}

		encSecrets, encDEK, err := s.encryptGuardrailSecretsMap(defCfg.Secrets, true)
		if err != nil {
			return fmt.Errorf("encrypt secrets for seeded guardrail %q: %w", defCfg.Name, err)
		}

		now := time.Now().UTC()
		def := &domain.GuardrailDefinition{
			ID:               defID,
			OrgID:            orgID,
			Name:             strings.TrimSpace(defCfg.Name),
			Provider:         strings.TrimSpace(defCfg.Provider),
			EventHooks:       hooks,
			Enabled:          enabled,
			TimeoutMs:        defCfg.TimeoutMs,
			FailOpen:         defCfg.FailOpen,
			Precedence:       defCfg.Precedence,
			Config:           cloneAnyMap(defCfg.Config),
			EncryptedSecrets: encSecrets,
			EncryptedDEK:     encDEK,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		existingDefs, err := s.repo.ListGuardrailDefinitions(ctx, orgID, false)
		if err != nil {
			return fmt.Errorf("list guardrails for seeding %q: %w", def.Name, err)
		}
		var matched *domain.GuardrailDefinition
		for _, ex := range existingDefs {
			if ex.ID == def.ID || (ex.Name == def.Name && ex.Provider == def.Provider) {
				matched = ex
				break
			}
		}
		if matched != nil {
			def.ID = matched.ID
			def.CreatedAt = matched.CreatedAt
			if def.EncryptedSecrets == "" {
				def.EncryptedSecrets = matched.EncryptedSecrets
				def.EncryptedDEK = matched.EncryptedDEK
			}
			if err := s.repo.UpdateGuardrailDefinition(ctx, def); err != nil {
				return fmt.Errorf("update seeded guardrail %q: %w", def.Name, err)
			}
		} else {
			if err := s.repo.CreateGuardrailDefinition(ctx, def); err != nil {
				return fmt.Errorf("create seeded guardrail %q: %w", def.Name, err)
			}
		}
	}
	return nil
}

func deterministicSeedID(prefix string, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return prefix + "_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func (s *GatewayServer) encryptGuardrailSecretsMap(secrets map[string]any, resolveEnv bool) (string, string, error) {
	if len(secrets) == 0 {
		return "", "", nil
	}
	if s.vault == nil {
		return "", "", errors.New("vault is not configured to encrypt guardrail secrets")
	}
	resolved := make(map[string]any, len(secrets))
	for k, v := range secrets {
		if resolveEnv {
			if strVal, ok := v.(string); ok {
				resolved[k] = config.ResolveEnvValue(strVal)
				continue
			}
		}
		resolved[k] = v
	}
	rawJSON, err := json.Marshal(resolved)
	if err != nil {
		return "", "", err
	}
	return s.vault.EncryptString(string(rawJSON))
}

func cloneAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// --- DTOs & Secret Redaction ---

type guardrailDefinitionDTO struct {
	ID         string                 `json:"id"`
	OrgID      string                 `json:"org_id"`
	Name       string                 `json:"name"`
	Provider   string                 `json:"provider"`
	EventHooks []domain.GuardrailHook `json:"event_hooks,omitempty"`
	Enabled    bool                   `json:"enabled"`
	TimeoutMs  int                    `json:"timeout_ms,omitempty"`
	FailOpen   bool                   `json:"fail_open"`
	Precedence int                    `json:"precedence"`
	Config     map[string]any         `json:"config,omitempty"`
	HasSecrets bool                   `json:"has_secrets"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

func toGuardrailDefinitionDTO(def *domain.GuardrailDefinition) guardrailDefinitionDTO {
	return guardrailDefinitionDTO{
		ID:         def.ID,
		OrgID:      def.OrgID,
		Name:       def.Name,
		Provider:   def.Provider,
		EventHooks: def.EventHooks,
		Enabled:    def.Enabled,
		TimeoutMs:  def.TimeoutMs,
		FailOpen:   def.FailOpen,
		Precedence: def.Precedence,
		Config:     def.Config,
		HasSecrets: strings.TrimSpace(def.EncryptedSecrets) != "",
		CreatedAt:  def.CreatedAt,
		UpdatedAt:  def.UpdatedAt,
	}
}

type guardrailDefinitionWriteRequest struct {
	ID         string                 `json:"id,omitempty"`
	Name       string                 `json:"name"`
	Provider   string                 `json:"provider"`
	EventHooks []domain.GuardrailHook `json:"event_hooks,omitempty"`
	Enabled    *bool                  `json:"enabled,omitempty"`
	TimeoutMs  int                    `json:"timeout_ms,omitempty"`
	FailOpen   bool                   `json:"fail_open"`
	Precedence int                    `json:"precedence"`
	Config     map[string]any         `json:"config,omitempty"`
	Secrets    map[string]any         `json:"secrets,omitempty"`
}

func (s *GatewayServer) validateGuardrailProvider(provider string) error {
	clean := strings.ToLower(strings.TrimSpace(provider))
	if clean == "" {
		return errors.New("provider is required")
	}
	reg := s.newGuardrailDriverRegistry()
	if !reg.Has(clean) {
		return fmt.Errorf("unsupported guardrail provider %q (supported: %s)", provider, strings.Join(reg.Providers(), ", "))
	}
	return nil
}

func (s *GatewayServer) handleAdminCreateGuardrailDefinition(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}
	var req guardrailDefinitionWriteRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	if req.Name == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: "name is required"})
		return
	}
	if err := s.validateGuardrailProvider(req.Provider); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	for _, h := range req.EventHooks {
		if !h.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: fmt.Sprintf("invalid event_hook %q", h)})
			return
		}
	}
	if len(req.EventHooks) == 0 {
		req.EventHooks = []domain.GuardrailHook{domain.GuardrailHookPreCall}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	encSecrets, encDEK, err := s.encryptGuardrailSecretsMap(req.Secrets, false)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Message: err.Error()})
		return
	}

	def := &domain.GuardrailDefinition{
		ID:               strings.TrimSpace(req.ID),
		OrgID:            orgID,
		Name:             req.Name,
		Provider:         req.Provider,
		EventHooks:       req.EventHooks,
		Enabled:          enabled,
		TimeoutMs:        req.TimeoutMs,
		FailOpen:         req.FailOpen,
		Precedence:       req.Precedence,
		Config:           req.Config,
		EncryptedSecrets: encSecrets,
		EncryptedDEK:     encDEK,
	}
	if def.ID == "" {
		def.ID = "gr_" + uuid.NewString()
	}
	if err := s.repo.CreateGuardrailDefinition(r.Context(), def); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	s.audit(r.Context(), orgID, "guardrail.definition.created", "guardrail_definition", def.ID, map[string]any{
		"name":     def.Name,
		"provider": def.Provider,
		"enabled":  def.Enabled,
	})
	writeJSON(w, http.StatusCreated, toGuardrailDefinitionDTO(def))
}

func (s *GatewayServer) handleAdminListGuardrailDefinitions(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	onlyEnabled := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("enabled")), "true")
	defs, err := s.repo.ListGuardrailDefinitions(r.Context(), orgID, onlyEnabled)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	out := make([]guardrailDefinitionDTO, 0, len(defs))
	for _, d := range defs {
		out = append(out, toGuardrailDefinitionDTO(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *GatewayServer) handleAdminGetGuardrailDefinition(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "guardrailID")
	def, err := s.repo.GetGuardrailDefinition(r.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNotFound) {
			status = http.StatusNotFound
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: status, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, def.OrgID, false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, toGuardrailDefinitionDTO(def))
}

func (s *GatewayServer) handleAdminUpdateGuardrailDefinition(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "guardrailID")
	existing, err := s.repo.GetGuardrailDefinition(r.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNotFound) {
			status = http.StatusNotFound
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: status, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	var req guardrailDefinitionWriteRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = existing.Name
	}
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		provider = existing.Provider
	}
	if err := s.validateGuardrailProvider(provider); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	hooks := req.EventHooks
	if len(hooks) == 0 {
		hooks = existing.EventHooks
	}
	for _, h := range hooks {
		if !h.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: fmt.Sprintf("invalid event_hook %q", h)})
			return
		}
	}
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	encSecrets, encDEK := existing.EncryptedSecrets, existing.EncryptedDEK
	if len(req.Secrets) > 0 {
		encSecrets, encDEK, err = s.encryptGuardrailSecretsMap(req.Secrets, false)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Message: err.Error()})
			return
		}
	}

	updated := &domain.GuardrailDefinition{
		ID:               existing.ID,
		OrgID:            existing.OrgID,
		Name:             name,
		Provider:         provider,
		EventHooks:       hooks,
		Enabled:          enabled,
		TimeoutMs:        req.TimeoutMs,
		FailOpen:         req.FailOpen,
		Precedence:       req.Precedence,
		Config:           req.Config,
		EncryptedSecrets: encSecrets,
		EncryptedDEK:     encDEK,
	}
	if err := s.repo.UpdateGuardrailDefinition(r.Context(), updated); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	s.audit(r.Context(), existing.OrgID, "guardrail.definition.updated", "guardrail_definition", updated.ID, map[string]any{
		"name":     updated.Name,
		"provider": updated.Provider,
		"enabled":  updated.Enabled,
	})
	writeJSON(w, http.StatusOK, toGuardrailDefinitionDTO(updated))
}

func (s *GatewayServer) handleAdminDeleteGuardrailDefinition(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "guardrailID")
	existing, err := s.repo.GetGuardrailDefinition(r.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNotFound) {
			status = http.StatusNotFound
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: status, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	if err := s.repo.DeleteGuardrailDefinition(r.Context(), id); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), existing.OrgID, "guardrail.definition.deleted", "guardrail_definition", id, map[string]any{
		"name": existing.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// --- Dry-Run Simulator ---

type guardrailSimulateRequest struct {
	Prompt    string                  `json:"prompt,omitempty"`
	Direction string                  `json:"direction,omitempty"` // "input" or "output"
	Policy    *domain.GuardrailPolicy `json:"policy,omitempty"`
}

func (s *GatewayServer) handleAdminSimulateGuardrails(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	var req guardrailSimulateRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}

	pol := req.Policy
	if pol == nil {
		loaded, err := s.repo.GetGuardrailPolicy(r.Context(), orgID)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		pol = loaded
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{OrgID: orgID}
	} else {
		cp := *pol
		cp.OrgID = orgID
		pol = &cp
	}
	if err := validateGuardrailPolicy(pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	isOutput := strings.EqualFold(strings.TrimSpace(req.Direction), domain.GuardrailDirectionOutput)
	var outcome *guardrails.CheckOutcome
	var evalErr error
	redactedText := req.Prompt

	if isOutput {
		probe := &domain.CanonicalChatResponse{
			Choices: []domain.CanonicalChoice{
				{Message: domain.CanonicalMessage{Role: "assistant", Content: req.Prompt}},
			},
		}
		outcome, evalErr = s.guardrails.EvaluateOutputWithPolicy(r.Context(), pol, probe)
		if len(probe.Choices) > 0 {
			redactedText = probe.Choices[0].Message.Content
		}
	} else {
		probe := &domain.CanonicalChatRequest{
			Messages: []domain.CanonicalMessage{
				{Role: "user", Content: req.Prompt},
			},
		}
		outcome, evalErr = s.guardrails.EvaluateInputWithPolicy(r.Context(), pol, probe)
		if len(probe.Messages) > 0 {
			redactedText = probe.Messages[0].Content
		}
	}

	decision := string(domain.GuardrailDecisionAllow)
	action := ""
	blocked := false
	redacted := false
	var violations []string
	var errMsg string

	if outcome != nil {
		violations = slices.Clone(outcome.Violations)
		redacted = outcome.Redacted
		action = string(outcome.AppliedAction)
		if redacted {
			decision = string(domain.GuardrailDecisionModify)
		} else if len(violations) > 0 {
			decision = string(domain.GuardrailDecisionFlag)
		}
	}
	if evalErr != nil {
		blocked = true
		decision = string(domain.GuardrailDecisionBlock)
		action = string(domain.GuardrailActionBlock)
		errMsg = evalErr.Error()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":         !blocked,
		"blocked":         blocked,
		"decision":        decision,
		"action":          action,
		"applied_action":  action,
		"redacted":        redacted,
		"redacted_text":   redactedText,
		"redacted_prompt": redactedText,
		"violations":      violations,
		"error_message":   errMsg,
		"effective_mode":  pol.EffectiveMode(),
	})
}
