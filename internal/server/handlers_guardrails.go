package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type guardrailDryRunCtxKey struct{}
type guardrailDriverTelemetryFlagKey struct{}

type guardrailTelemetryTracker struct {
	recorded bool
}

func withGuardrailDryRun(ctx context.Context) context.Context {
	return context.WithValue(ctx, guardrailDryRunCtxKey{}, true)
}

func isGuardrailDryRun(ctx context.Context) bool {
	v, _ := ctx.Value(guardrailDryRunCtxKey{}).(bool)
	return v
}

// telemeteredGuardrailDriver wraps any guardrails.Driver so every Evaluate call emits
// scrubbed OTEL `guardrail.evaluate` child spans, Prometheus/OTLP metrics, and
// integer micro-dollar daily usage rollups.
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
	if tracker, ok := ctx.Value(guardrailDriverTelemetryFlagKey{}).(*guardrailTelemetryTracker); ok && tracker != nil {
		tracker.recorded = true
	}

	gName := d.Name()
	gID := gName
	orgID := ""
	var info map[string]any
	if d.def != nil {
		if strings.TrimSpace(d.def.Name) != "" {
			gName = d.def.Name
		}
		if strings.TrimSpace(d.def.ID) != "" {
			gID = d.def.ID
		} else {
			gID = gName
		}
		orgID = d.def.OrgID
		info = d.def.GuardrailInfo
	}

	hookStr := ""
	teamID := ""
	vkID := ""
	charCount := int64(0)
	if input != nil {
		hookStr = string(input.Hook)
		if orgID == "" {
			orgID = input.OrgID
		}
		teamID = input.TeamID
		vkID = input.VirtualKeyID
		for _, t := range input.Texts {
			charCount += int64(len(t))
		}
		for _, m := range input.StructuredMessages {
			charCount += int64(len(m.Content))
		}
	}
	if hookStr == "" {
		hookStr = string(domain.GuardrailHookPreCall)
	}

	spanCtx, span := observability.StartGuardrailEvaluateSpan(ctx, d.server.tracer, gName, hookStr)
	started := time.Now()
	res, err := d.inner.Evaluate(spanCtx, input)
	latencyMs := time.Since(started).Milliseconds()

	decision := string(domain.GuardrailDecisionAllow)
	isErr := err != nil
	var cats []string
	var units int64
	if res != nil {
		if res.Decision != "" {
			decision = string(res.Decision)
		}
		if res.ErrorMessage != "" && err == nil {
			isErr = true
		}
		for _, v := range res.Violations {
			if v.Category != "" {
				cats = append(cats, v.Category)
			} else if v.Rule != "" {
				cats = append(cats, v.Rule)
			}
		}
		units = res.UsageUnits
	}
	if isErr && len(cats) == 0 {
		cats = append(cats, "evaluation_error")
	}

	observability.FinishGuardrailEvaluateSpan(span, decision, cats, latencyMs, isErr)
	d.server.recordGuardrailTelemetryAndUsage(
		ctx,
		orgID, gID, gName, teamID, vkID, hookStr,
		domain.GuardrailDecision(decision),
		info, units, charCount, latencyMs, isErr,
	)
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
	if s == nil || res == nil {
		return
	}
	if s.repo != nil && prc.OrgID != "" {
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
				"model_group":   prc.ModelGroupID,
			},
		})
	}
	// If drivers already emitted per-guardrail telemetry via telemeteredGuardrailDriver,
	// do not double-count; otherwise record fallback metrics/rollups for policy/pre-driver outcomes.
	if len(res.AppliedGuardrails) > 0 {
		return
	}
	if len(res.Violations) == 0 && res.ErrorMessage == "" {
		return
	}
	gName := "policy"
	gID := "policy"
	if len(res.Violations) > 0 && strings.TrimSpace(res.Violations[0].GuardrailName) != "" {
		gName = res.Violations[0].GuardrailName
		if res.Violations[0].GuardrailID != "" {
			gID = res.Violations[0].GuardrailID
		} else {
			gID = gName
		}
	}
	isErr := strings.TrimSpace(res.ErrorMessage) != ""
	s.recordGuardrailTelemetryAndUsage(
		ctx,
		prc.OrgID, gID, gName, prc.TeamID, prc.VirtualKeyID, string(hook),
		res.Decision, nil, res.UsageUnits, 0, 0, isErr,
	)
}

func (s *GatewayServer) recordGuardrailTelemetryAndUsage(
	ctx context.Context,
	orgID, guardrailID, guardrailName, teamID, virtualKeyID, hook string,
	decision domain.GuardrailDecision,
	guardrailInfo map[string]any,
	explicitUnits, charCount, latencyMs int64,
	isErr bool,
) {
	if s == nil {
		return
	}
	if s.collector != nil {
		s.collector.RecordGuardrailEvaluation(observability.GuardrailObservation{
			GuardrailName: guardrailName,
			Hook:          hook,
			Decision:      string(decision),
			LatencyMs:     latencyMs,
			IsError:       isErr,
		})
	}
	if isGuardrailDryRun(ctx) || orgID == "" {
		return
	}
	usageRepo, ok := s.repo.(storage.GuardrailUsageRepository)
	if !ok || usageRepo == nil {
		return
	}
	usageUnit, units, costMicros := computeGuardrailUsageAndCost(guardrailInfo, explicitUnits, charCount)
	_ = usageRepo.RecordGuardrailEvaluation(ctx, storage.GuardrailEvaluationRecord{
		OrgID:         orgID,
		GuardrailID:   guardrailID,
		GuardrailName: guardrailName,
		Date:          time.Now().UTC(),
		TeamID:        teamID,
		VirtualKeyID:  virtualKeyID,
		Hook:          hook,
		Decision:      decision,
		UsageUnit:     usageUnit,
		Units:         units,
		CostMicros:    costMicros,
		LatencyMs:     latencyMs,
		IsError:       isErr,
	})
}

// computeGuardrailUsageAndCost calculates usage units and integer micro-dollar cost
// strictly using int64 arithmetic without floating point operations.
func computeGuardrailUsageAndCost(info map[string]any, explicitUnits, charCount int64) (string, int64, int64) {
	usageUnit := "call"
	var perCallMicros int64
	var perUnitMicros int64
	if info != nil {
		if raw, ok := info["usage_unit"].(string); ok && strings.TrimSpace(raw) != "" {
			usageUnit = strings.TrimSpace(raw)
		}
		perCallMicros = parseInt64Value(info["cost_per_call_micros"])
		perUnitMicros = parseInt64Value(info["cost_per_unit_micros"])
	}
	units := explicitUnits
	if units <= 0 {
		switch strings.ToLower(usageUnit) {
		case "char", "chars", "character", "characters":
			if charCount > 0 {
				units = charCount
			} else {
				units = 1
			}
		default:
			units = 1
		}
	}
	costMicros := perCallMicros + (perUnitMicros * units)
	if costMicros < 0 {
		costMicros = 0
	}
	return usageUnit, units, costMicros
}

func parseInt64Value(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case uint64:
		if n > 1<<62 {
			return 0
		}
		return int64(n)
	case json.Number:
		if parsed, err := n.Int64(); err == nil {
			return parsed
		}
	case float64:
		// JSON decoding into map[string]any decodes integer literals as float64.
		if n >= 0 && n < float64(int64(1)<<53) {
			return int64(n)
		}
	case string:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64); err == nil {
			return parsed
		}
	}
	return 0
}

// --- Startup YAML Seeding ---

func (s *GatewayServer) seedGuardrailsFromConfig(ctx context.Context) error {
	if s == nil || s.repo == nil {
		return nil
	}
	if len(s.cfg.Guardrails.Definitions) == 0 && len(s.cfg.Guardrails.ToolPolicies) == 0 {
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
		status := domain.GuardrailStatusActive
		if st := strings.TrimSpace(defCfg.Status); st != "" {
			status = domain.GuardrailStatus(st)
		}

		hooks := make([]domain.GuardrailHook, 0, len(defCfg.EventHooks))
		for _, h := range defCfg.EventHooks {
			if trimmed := strings.TrimSpace(h); trimmed != "" {
				hooks = append(hooks, domain.GuardrailHook(trimmed))
			}
		}

		var modeRule *domain.GuardrailModeRule
		if defCfg.ModeRule != nil {
			mr := &domain.GuardrailModeRule{
				Tags: make(map[string][]domain.GuardrailHook, len(defCfg.ModeRule.Tags)),
			}
			for tag, tHooks := range defCfg.ModeRule.Tags {
				for _, h := range tHooks {
					mr.Tags[tag] = append(mr.Tags[tag], domain.GuardrailHook(h))
				}
			}
			for _, h := range defCfg.ModeRule.Default {
				mr.Default = append(mr.Default, domain.GuardrailHook(h))
			}
			modeRule = mr
		}

		weight := defCfg.Weight
		if weight <= 0 {
			weight = 1
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
			StreamScope:      domain.StreamScope(strings.TrimSpace(defCfg.StreamScope)),
			ModeRule:         modeRule,
			DefaultOn:        defCfg.DefaultOn,
			EnabledRoles:     append([]string(nil), defCfg.EnabledRoles...),
			TimeoutMs:        defCfg.TimeoutMs,
			FailOpen:         defCfg.FailOpen,
			Precedence:       defCfg.Precedence,
			Config:           cloneAnyMap(defCfg.Config),
			EncryptedSecrets: encSecrets,
			EncryptedDEK:     encDEK,
			Status:           status,
			GuardrailInfo:    cloneAnyMap(defCfg.GuardrailInfo),
			Weight:           weight,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		existingDefs, err := s.repo.ListGuardrailDefinitions(ctx, orgID, "", def.Name)
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

		existingBindings, _ := s.repo.ListGuardrailBindings(ctx, storage.GuardrailBindingFilter{
			OrgID:       orgID,
			GuardrailID: def.ID,
		})
		for _, bCfg := range defCfg.Bindings {
			bID := strings.TrimSpace(bCfg.ID)
			if bID == "" {
				bID = deterministicSeedID("grb", orgID, def.ID, bCfg.TeamID, bCfg.VirtualKeyID, bCfg.EndUserID, bCfg.ModelGroupID, bCfg.Tag)
			}
			already := false
			for _, eb := range existingBindings {
				if eb.ID == bID || (eb.TeamID == bCfg.TeamID && eb.VirtualKeyID == bCfg.VirtualKeyID &&
					eb.EndUserID == bCfg.EndUserID && eb.ModelGroupID == bCfg.ModelGroupID && eb.Tag == bCfg.Tag) {
					already = true
					break
				}
			}
			if already {
				continue
			}
			if err := s.repo.CreateGuardrailBinding(ctx, &domain.GuardrailBinding{
				ID:             bID,
				OrgID:          orgID,
				GuardrailID:    def.ID,
				GuardrailName:  def.Name,
				TeamID:         bCfg.TeamID,
				VirtualKeyID:   bCfg.VirtualKeyID,
				EndUserID:      bCfg.EndUserID,
				ModelGroupID:   bCfg.ModelGroupID,
				Tag:            bCfg.Tag,
				ParamOverrides: cloneAnyMap(bCfg.ParamOverrides),
				IsLocked:       bCfg.IsLocked,
				CreatedAt:      now,
				UpdatedAt:      now,
			}); err != nil {
				return fmt.Errorf("seed binding for guardrail %q: %w", def.Name, err)
			}
		}
	}

	if tpRepo, ok := s.repo.(storage.ToolPolicyRepository); ok && tpRepo != nil {
		for _, tpCfg := range s.cfg.Guardrails.ToolPolicies {
			orgID := strings.TrimSpace(tpCfg.OrgID)
			if orgID == "" {
				orgID = defaultOrgID
			}
			if err := ensureOrg(orgID); err != nil {
				return fmt.Errorf("ensure org %q for seeded tool policy %q: %w", orgID, tpCfg.ToolName, err)
			}
			tpID := strings.TrimSpace(tpCfg.ID)
			if tpID == "" {
				tpID = deterministicSeedID("tp", orgID, tpCfg.TeamID, tpCfg.VirtualKeyID, tpCfg.ToolName)
			}
			inPol := storage.ToolTrustLevel(strings.ToLower(strings.TrimSpace(tpCfg.InputPolicy)))
			if inPol == "" {
				inPol = storage.ToolTrustUntrusted
			}
			outPol := storage.ToolTrustLevel(strings.ToLower(strings.TrimSpace(tpCfg.OutputPolicy)))
			if outPol == "" {
				outPol = storage.ToolTrustUntrusted
			}
			if err := tpRepo.UpsertToolPolicy(ctx, &storage.ToolPolicy{
				ID:           tpID,
				OrgID:        orgID,
				TeamID:       strings.TrimSpace(tpCfg.TeamID),
				VirtualKeyID: strings.TrimSpace(tpCfg.VirtualKeyID),
				ToolName:     strings.TrimSpace(tpCfg.ToolName),
				InputPolicy:  inPol,
				OutputPolicy: outPol,
			}); err != nil {
				return fmt.Errorf("seed tool policy %q: %w", tpCfg.ToolName, err)
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
	ID                string                    `json:"id"`
	OrgID             string                    `json:"org_id"`
	Name              string                    `json:"name"`
	Provider          string                    `json:"provider"`
	EventHooks        []domain.GuardrailHook    `json:"event_hooks,omitempty"`
	StreamScope       domain.StreamScope        `json:"stream_scope,omitempty"`
	StreamScopeByHook domain.StreamScopeByHook  `json:"stream_scope_by_hook,omitempty"`
	ModeRule          *domain.GuardrailModeRule `json:"mode_rule,omitempty"`
	DefaultOn         bool                      `json:"default_on"`
	EnabledRoles      []string                  `json:"enabled_roles,omitempty"`
	TimeoutMs         int                       `json:"timeout_ms,omitempty"`
	FailOpen          bool                      `json:"fail_open"`
	Precedence        int                       `json:"precedence"`
	Config            map[string]any            `json:"config,omitempty"`
	HasSecrets        bool                      `json:"has_secrets"`
	Status            domain.GuardrailStatus    `json:"status"`
	GuardrailInfo     map[string]any            `json:"guardrail_info,omitempty"`
	Weight            int                       `json:"weight"`
	CreatedAt         time.Time                 `json:"created_at"`
	UpdatedAt         time.Time                 `json:"updated_at"`
}

func toGuardrailDefinitionDTO(def *domain.GuardrailDefinition) guardrailDefinitionDTO {
	return guardrailDefinitionDTO{
		ID:                def.ID,
		OrgID:             def.OrgID,
		Name:              def.Name,
		Provider:          def.Provider,
		EventHooks:        def.EventHooks,
		StreamScope:       def.StreamScope,
		StreamScopeByHook: def.StreamScopeByHook,
		ModeRule:          def.ModeRule,
		DefaultOn:         def.DefaultOn,
		EnabledRoles:      def.EnabledRoles,
		TimeoutMs:         def.TimeoutMs,
		FailOpen:          def.FailOpen,
		Precedence:        def.Precedence,
		Config:            def.Config,
		HasSecrets:        strings.TrimSpace(def.EncryptedSecrets) != "",
		Status:            def.Status,
		GuardrailInfo:     def.GuardrailInfo,
		Weight:            def.Weight,
		CreatedAt:         def.CreatedAt,
		UpdatedAt:         def.UpdatedAt,
	}
}

type guardrailDefinitionWriteRequest struct {
	ID                string                    `json:"id,omitempty"`
	Name              string                    `json:"name"`
	Provider          string                    `json:"provider"`
	EventHooks        []domain.GuardrailHook    `json:"event_hooks,omitempty"`
	StreamScope       domain.StreamScope        `json:"stream_scope,omitempty"`
	StreamScopeByHook domain.StreamScopeByHook  `json:"stream_scope_by_hook,omitempty"`
	ModeRule          *domain.GuardrailModeRule `json:"mode_rule,omitempty"`
	DefaultOn         bool                      `json:"default_on"`
	EnabledRoles      []string                  `json:"enabled_roles,omitempty"`
	TimeoutMs         int                       `json:"timeout_ms,omitempty"`
	FailOpen          bool                      `json:"fail_open"`
	Precedence        int                       `json:"precedence"`
	Config            map[string]any            `json:"config,omitempty"`
	Secrets           map[string]any            `json:"secrets,omitempty"`
	ClearSecrets      bool                      `json:"clear_secrets,omitempty"`
	Status            domain.GuardrailStatus    `json:"status,omitempty"`
	GuardrailInfo     map[string]any            `json:"guardrail_info,omitempty"`
	Weight            int                       `json:"weight,omitempty"`
}

// --- Control Plane Admin Handlers ---

func (s *GatewayServer) handleAdminCreateGuardrailDefinition(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}
	var req guardrailDefinitionWriteRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Provider) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "name and provider are required"})
		return
	}
	if req.TimeoutMs < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "timeout_ms cannot be negative"})
		return
	}
	status := req.Status
	if status == "" {
		status = domain.GuardrailStatusActive
	}
	if !status.IsValid() {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "invalid status"})
		return
	}
	if req.StreamScope != "" && !req.StreamScope.IsValid() {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "invalid stream_scope"})
		return
	}
	for _, h := range req.EventHooks {
		if !h.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: fmt.Sprintf("invalid event_hook %q", h)})
			return
		}
	}

	encSecrets, encDEK, err := s.encryptGuardrailSecretsMap(req.Secrets, false)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 500, Type: domain.ErrorTypeServer, Message: err.Error()})
		return
	}

	weight := req.Weight
	if weight <= 0 {
		weight = 1
	}
	defID := strings.TrimSpace(req.ID)
	if defID == "" {
		defID = "gr_" + uuid.NewString()
	}
	now := time.Now().UTC()
	def := &domain.GuardrailDefinition{
		ID:                defID,
		OrgID:             orgID,
		Name:              strings.TrimSpace(req.Name),
		Provider:          strings.TrimSpace(req.Provider),
		EventHooks:        req.EventHooks,
		StreamScope:       req.StreamScope,
		StreamScopeByHook: req.StreamScopeByHook,
		ModeRule:          req.ModeRule,
		DefaultOn:         req.DefaultOn,
		EnabledRoles:      req.EnabledRoles,
		TimeoutMs:         req.TimeoutMs,
		FailOpen:          req.FailOpen,
		Precedence:        req.Precedence,
		Config:            req.Config,
		EncryptedSecrets:  encSecrets,
		EncryptedDEK:      encDEK,
		Status:            status,
		GuardrailInfo:     req.GuardrailInfo,
		Weight:            weight,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.repo.CreateGuardrailDefinition(r.Context(), def); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	dto := toGuardrailDefinitionDTO(def)
	s.auditWithDiff(r.Context(), orgID, "guardrail_definition.created", "guardrail_definition", def.ID, map[string]any{
		"name":     def.Name,
		"provider": def.Provider,
		"status":   def.Status,
	}, nil, dto)
	writeJSON(w, http.StatusCreated, dto)
}

func (s *GatewayServer) handleAdminListGuardrailDefinitions(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	status := domain.GuardrailStatus(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && !status.IsValid() {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "invalid status filter"})
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	defs, err := s.repo.ListGuardrailDefinitions(r.Context(), orgID, status, name)
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
	guardrailID := chi.URLParam(r, "guardrailID")
	def, err := s.repo.GetGuardrailDefinition(r.Context(), guardrailID)
	if err != nil || def == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Code: "guardrail_not_found", Message: "Guardrail definition not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, def.OrgID, false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, toGuardrailDefinitionDTO(def))
}

func (s *GatewayServer) handleAdminUpdateGuardrailDefinition(w http.ResponseWriter, r *http.Request) {
	guardrailID := chi.URLParam(r, "guardrailID")
	existing, err := s.repo.GetGuardrailDefinition(r.Context(), guardrailID)
	if err != nil || existing == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Code: "guardrail_not_found", Message: "Guardrail definition not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	var req guardrailDefinitionWriteRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Provider) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "name and provider are required"})
		return
	}
	if req.TimeoutMs < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "timeout_ms cannot be negative"})
		return
	}
	status := req.Status
	if status == "" {
		status = existing.Status
	}
	if !status.IsValid() {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "invalid status"})
		return
	}

	encSecrets := existing.EncryptedSecrets
	encDEK := existing.EncryptedDEK
	if req.ClearSecrets {
		encSecrets = ""
		encDEK = ""
	} else if len(req.Secrets) > 0 {
		encSecrets, encDEK, err = s.encryptGuardrailSecretsMap(req.Secrets, false)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 500, Type: domain.ErrorTypeServer, Message: err.Error()})
			return
		}
	}

	weight := req.Weight
	if weight <= 0 {
		weight = existing.Weight
		if weight <= 0 {
			weight = 1
		}
	}

	updated := &domain.GuardrailDefinition{
		ID:                existing.ID,
		OrgID:             existing.OrgID,
		Name:              strings.TrimSpace(req.Name),
		Provider:          strings.TrimSpace(req.Provider),
		EventHooks:        req.EventHooks,
		StreamScope:       req.StreamScope,
		StreamScopeByHook: req.StreamScopeByHook,
		ModeRule:          req.ModeRule,
		DefaultOn:         req.DefaultOn,
		EnabledRoles:      req.EnabledRoles,
		TimeoutMs:         req.TimeoutMs,
		FailOpen:          req.FailOpen,
		Precedence:        req.Precedence,
		Config:            req.Config,
		EncryptedSecrets:  encSecrets,
		EncryptedDEK:      encDEK,
		Status:            status,
		GuardrailInfo:     req.GuardrailInfo,
		Weight:            weight,
		CreatedAt:         existing.CreatedAt,
		UpdatedAt:         time.Now().UTC(),
	}
	if err := s.repo.UpdateGuardrailDefinition(r.Context(), updated); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	dto := toGuardrailDefinitionDTO(updated)
	s.auditWithDiff(r.Context(), existing.OrgID, "guardrail_definition.updated", "guardrail_definition", updated.ID, map[string]any{
		"name":   updated.Name,
		"status": updated.Status,
	}, toGuardrailDefinitionDTO(existing), dto)
	writeJSON(w, http.StatusOK, dto)
}

func (s *GatewayServer) handleAdminPatchGuardrailDefinition(w http.ResponseWriter, r *http.Request) {
	guardrailID := chi.URLParam(r, "guardrailID")
	existing, err := s.repo.GetGuardrailDefinition(r.Context(), guardrailID)
	if err != nil || existing == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Code: "guardrail_not_found", Message: "Guardrail definition not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}

	var req struct {
		Name              *string                   `json:"name,omitempty"`
		Provider          *string                   `json:"provider,omitempty"`
		EventHooks        *[]domain.GuardrailHook   `json:"event_hooks,omitempty"`
		StreamScope       *domain.StreamScope       `json:"stream_scope,omitempty"`
		StreamScopeByHook *domain.StreamScopeByHook `json:"stream_scope_by_hook,omitempty"`
		ModeRule          *domain.GuardrailModeRule `json:"mode_rule,omitempty"`
		DefaultOn         *bool                     `json:"default_on,omitempty"`
		EnabledRoles      *[]string                 `json:"enabled_roles,omitempty"`
		TimeoutMs         *int                      `json:"timeout_ms,omitempty"`
		FailOpen          *bool                     `json:"fail_open,omitempty"`
		Precedence        *int                      `json:"precedence,omitempty"`
		Config            map[string]any            `json:"config,omitempty"`
		Secrets           map[string]any            `json:"secrets,omitempty"`
		ClearSecrets      bool                      `json:"clear_secrets,omitempty"`
		Status            *domain.GuardrailStatus   `json:"status,omitempty"`
		GuardrailInfo     map[string]any            `json:"guardrail_info,omitempty"`
		Weight            *int                      `json:"weight,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}

	cp := *existing
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "name cannot be empty"})
			return
		}
		cp.Name = strings.TrimSpace(*req.Name)
	}
	if req.Provider != nil {
		if strings.TrimSpace(*req.Provider) == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "provider cannot be empty"})
			return
		}
		cp.Provider = strings.TrimSpace(*req.Provider)
	}
	if req.EventHooks != nil {
		for _, h := range *req.EventHooks {
			if !h.IsValid() {
				domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: fmt.Sprintf("invalid event_hook %q", h)})
				return
			}
		}
		cp.EventHooks = *req.EventHooks
	}
	if req.StreamScope != nil {
		if *req.StreamScope != "" && !req.StreamScope.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "invalid stream_scope"})
			return
		}
		cp.StreamScope = *req.StreamScope
	}
	if req.StreamScopeByHook != nil {
		cp.StreamScopeByHook = *req.StreamScopeByHook
	}
	if req.ModeRule != nil {
		cp.ModeRule = req.ModeRule
	}
	if req.DefaultOn != nil {
		cp.DefaultOn = *req.DefaultOn
	}
	if req.EnabledRoles != nil {
		cp.EnabledRoles = *req.EnabledRoles
	}
	if req.TimeoutMs != nil {
		if *req.TimeoutMs < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "timeout_ms cannot be negative"})
			return
		}
		cp.TimeoutMs = *req.TimeoutMs
	}
	if req.FailOpen != nil {
		cp.FailOpen = *req.FailOpen
	}
	if req.Precedence != nil {
		cp.Precedence = *req.Precedence
	}
	if req.Config != nil {
		cp.Config = req.Config
	}
	if req.GuardrailInfo != nil {
		cp.GuardrailInfo = req.GuardrailInfo
	}
	if req.Weight != nil && *req.Weight > 0 {
		cp.Weight = *req.Weight
	}
	if req.Status != nil {
		if !req.Status.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "invalid status"})
			return
		}
		cp.Status = *req.Status
	}
	if req.ClearSecrets {
		cp.EncryptedSecrets = ""
		cp.EncryptedDEK = ""
	} else if len(req.Secrets) > 0 {
		encSecrets, encDEK, err := s.encryptGuardrailSecretsMap(req.Secrets, false)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 500, Type: domain.ErrorTypeServer, Message: err.Error()})
			return
		}
		cp.EncryptedSecrets = encSecrets
		cp.EncryptedDEK = encDEK
	}
	cp.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateGuardrailDefinition(r.Context(), &cp); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	dto := toGuardrailDefinitionDTO(&cp)
	s.auditWithDiff(r.Context(), existing.OrgID, "guardrail_definition.patched", "guardrail_definition", cp.ID, map[string]any{
		"name":   cp.Name,
		"status": cp.Status,
	}, toGuardrailDefinitionDTO(existing), dto)
	writeJSON(w, http.StatusOK, dto)
}

func (s *GatewayServer) handleAdminDeleteGuardrailDefinition(w http.ResponseWriter, r *http.Request) {
	guardrailID := chi.URLParam(r, "guardrailID")
	existing, err := s.repo.GetGuardrailDefinition(r.Context(), guardrailID)
	if err != nil || existing == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Code: "guardrail_not_found", Message: "Guardrail definition not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	if err := s.repo.DeleteGuardrailDefinition(r.Context(), guardrailID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "guardrail_definition.deleted", "guardrail_definition", guardrailID, map[string]any{
		"name": existing.Name,
	}, toGuardrailDefinitionDTO(existing), nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "deleted",
		"deleted": true,
		"id":      guardrailID,
	})
}

func (s *GatewayServer) handleAdminSetGuardrailDefinitionStatus(w http.ResponseWriter, r *http.Request) {
	guardrailID := chi.URLParam(r, "guardrailID")
	existing, err := s.repo.GetGuardrailDefinition(r.Context(), guardrailID)
	if err != nil || existing == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Code: "guardrail_not_found", Message: "Guardrail definition not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	var req struct {
		Status domain.GuardrailStatus `json:"status"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if !req.Status.IsValid() {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "status must be one of: active, pending_review, rejected"})
		return
	}
	cp := *existing
	cp.Status = req.Status
	cp.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpdateGuardrailDefinition(r.Context(), &cp); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	dto := toGuardrailDefinitionDTO(&cp)
	s.auditWithDiff(r.Context(), existing.OrgID, "guardrail_definition.status_updated", "guardrail_definition", cp.ID, map[string]any{
		"status": cp.Status,
	}, toGuardrailDefinitionDTO(existing), dto)
	writeJSON(w, http.StatusOK, dto)
}

func (s *GatewayServer) handleAdminCreateGuardrailBinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID             string         `json:"id,omitempty"`
		OrgID          string         `json:"org_id"`
		GuardrailID    string         `json:"guardrail_id"`
		GuardrailName  string         `json:"guardrail_name,omitempty"`
		TeamID         string         `json:"team_id,omitempty"`
		VirtualKeyID   string         `json:"virtual_key_id,omitempty"`
		EndUserID      string         `json:"end_user_id,omitempty"`
		ModelGroupID   string         `json:"model_group_id,omitempty"`
		Tag            string         `json:"tag,omitempty"`
		ParamOverrides map[string]any `json:"param_overrides,omitempty"`
		IsLocked       bool           `json:"is_locked"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	orgID := resolveScopedOrgID(r, req.OrgID)
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}
	if strings.TrimSpace(req.GuardrailID) == "" && strings.TrimSpace(req.GuardrailName) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "guardrail_id or guardrail_name is required"})
		return
	}
	guardrailName := strings.TrimSpace(req.GuardrailName)
	if req.GuardrailID != "" {
		def, err := s.repo.GetGuardrailDefinition(r.Context(), req.GuardrailID)
		if err != nil || def == nil || def.OrgID != orgID {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Code: "guardrail_not_found", Message: "Guardrail definition not found in organization"})
			return
		}
		if guardrailName == "" {
			guardrailName = def.Name
		}
	}

	bID := strings.TrimSpace(req.ID)
	if bID == "" {
		bID = "grb_" + uuid.NewString()
	}
	now := time.Now().UTC()
	binding := &domain.GuardrailBinding{
		ID:             bID,
		OrgID:          orgID,
		GuardrailID:    strings.TrimSpace(req.GuardrailID),
		GuardrailName:  guardrailName,
		TeamID:         strings.TrimSpace(req.TeamID),
		VirtualKeyID:   strings.TrimSpace(req.VirtualKeyID),
		EndUserID:      strings.TrimSpace(req.EndUserID),
		ModelGroupID:   strings.TrimSpace(req.ModelGroupID),
		Tag:            strings.TrimSpace(req.Tag),
		ParamOverrides: req.ParamOverrides,
		IsLocked:       req.IsLocked,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.repo.CreateGuardrailBinding(r.Context(), binding); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), orgID, "guardrail_binding.created", "guardrail_binding", binding.ID, map[string]any{
		"guardrail_id":   binding.GuardrailID,
		"guardrail_name": binding.GuardrailName,
		"is_locked":      binding.IsLocked,
	}, nil, binding)
	writeJSON(w, http.StatusCreated, binding)
}

func (s *GatewayServer) handleAdminListGuardrailBindings(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	q := r.URL.Query()
	bindings, err := s.repo.ListGuardrailBindings(r.Context(), storage.GuardrailBindingFilter{
		OrgID:         orgID,
		GuardrailID:   strings.TrimSpace(q.Get("guardrail_id")),
		GuardrailName: strings.TrimSpace(q.Get("guardrail_name")),
		TeamID:        strings.TrimSpace(q.Get("team_id")),
		VirtualKeyID:  strings.TrimSpace(q.Get("virtual_key_id")),
		EndUserID:     strings.TrimSpace(q.Get("end_user_id")),
		ModelGroupID:  strings.TrimSpace(q.Get("model_group_id")),
		Tag:           strings.TrimSpace(q.Get("tag")),
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": bindings})
}

func (s *GatewayServer) handleAdminDeleteGuardrailBinding(w http.ResponseWriter, r *http.Request) {
	bindingID := chi.URLParam(r, "bindingID")
	binding, err := s.repo.GetGuardrailBinding(r.Context(), bindingID)
	if err != nil || binding == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Code: "guardrail_binding_not_found", Message: "Guardrail binding not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, binding.OrgID, true); !ok {
		return
	}
	if err := s.repo.DeleteGuardrailBinding(r.Context(), bindingID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), binding.OrgID, "guardrail_binding.deleted", "guardrail_binding", bindingID, nil, binding, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "deleted",
		"deleted": true,
		"id":      bindingID,
	})
}

func (s *GatewayServer) handleAdminUpsertToolPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}
	tpRepo, ok := s.repo.(storage.ToolPolicyRepository)
	if !ok || tpRepo == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 500, Type: domain.ErrorTypeServer, Message: "tool policy repository unavailable"})
		return
	}
	var req struct {
		ID           string                 `json:"id,omitempty"`
		TeamID       string                 `json:"team_id,omitempty"`
		VirtualKeyID string                 `json:"virtual_key_id,omitempty"`
		ToolName     string                 `json:"tool_name"`
		InputPolicy  storage.ToolTrustLevel `json:"input_policy"`
		OutputPolicy storage.ToolTrustLevel `json:"output_policy"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if strings.TrimSpace(req.ToolName) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "tool_name is required"})
		return
	}
	if req.InputPolicy == "" {
		req.InputPolicy = storage.ToolTrustUntrusted
	}
	if req.OutputPolicy == "" {
		req.OutputPolicy = storage.ToolTrustUntrusted
	}
	if !req.InputPolicy.IsValidInput() {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "invalid input_policy (must be untrusted, trusted, or blocked)"})
		return
	}
	if !req.OutputPolicy.IsValidOutput() {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "invalid output_policy (must be untrusted or trusted)"})
		return
	}
	pol := &storage.ToolPolicy{
		ID:           strings.TrimSpace(req.ID),
		OrgID:        orgID,
		TeamID:       strings.TrimSpace(req.TeamID),
		VirtualKeyID: strings.TrimSpace(req.VirtualKeyID),
		ToolName:     strings.TrimSpace(req.ToolName),
		InputPolicy:  req.InputPolicy,
		OutputPolicy: req.OutputPolicy,
	}
	var beforePol *storage.ToolPolicy
	if pol.ID != "" {
		beforePol, _ = tpRepo.GetToolPolicy(r.Context(), orgID, pol.ID)
	} else if existingList, listErr := tpRepo.ListToolPolicies(r.Context(), storage.ToolPolicyFilter{
		OrgID:        orgID,
		TeamID:       pol.TeamID,
		VirtualKeyID: pol.VirtualKeyID,
		ToolName:     pol.ToolName,
	}); listErr == nil {
		for _, item := range existingList {
			if item != nil && item.TeamID == pol.TeamID && item.VirtualKeyID == pol.VirtualKeyID && item.ToolName == pol.ToolName {
				cp := *item
				beforePol = &cp
				break
			}
		}
	}
	if err := tpRepo.UpsertToolPolicy(r.Context(), pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), orgID, "tool_policy.upserted", "tool_policy", pol.ID, map[string]any{
		"tool_name":     pol.ToolName,
		"input_policy":  pol.InputPolicy,
		"output_policy": pol.OutputPolicy,
	}, beforePol, pol)
	writeJSON(w, http.StatusOK, pol)
}

func (s *GatewayServer) handleAdminListToolPolicies(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	tpRepo, ok := s.repo.(storage.ToolPolicyRepository)
	if !ok || tpRepo == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 500, Type: domain.ErrorTypeServer, Message: "tool policy repository unavailable"})
		return
	}
	q := r.URL.Query()
	policies, err := tpRepo.ListToolPolicies(r.Context(), storage.ToolPolicyFilter{
		OrgID:        orgID,
		TeamID:       strings.TrimSpace(q.Get("team_id")),
		VirtualKeyID: strings.TrimSpace(q.Get("virtual_key_id")),
		ToolName:     strings.TrimSpace(q.Get("tool_name")),
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": policies})
}

func (s *GatewayServer) handleAdminDeleteToolPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	policyID := chi.URLParam(r, "policyID")
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}
	tpRepo, ok := s.repo.(storage.ToolPolicyRepository)
	if !ok || tpRepo == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 500, Type: domain.ErrorTypeServer, Message: "tool policy repository unavailable"})
		return
	}
	beforePol, err := tpRepo.GetToolPolicy(r.Context(), orgID, policyID)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Code: "tool_policy_not_found", Message: "Tool policy not found"})
		return
	}
	if err := tpRepo.DeleteToolPolicy(r.Context(), orgID, policyID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), orgID, "tool_policy.deleted", "tool_policy", policyID, nil, beforePol, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "deleted",
		"deleted": true,
		"id":      policyID,
	})
}

func (s *GatewayServer) handleAdminGetGuardrailUsage(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	usageRepo, ok := s.repo.(storage.GuardrailUsageRepository)
	if !ok || usageRepo == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 500, Type: domain.ErrorTypeServer, Message: "guardrail usage repository unavailable"})
		return
	}
	q := r.URL.Query()
	var startDate, endDate time.Time
	if raw := strings.TrimSpace(q.Get("start_date")); raw != "" {
		parsed, err := time.Parse("2006-01-02", raw)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "start_date must be YYYY-MM-DD"})
			return
		}
		startDate = parsed
	}
	if raw := strings.TrimSpace(q.Get("end_date")); raw != "" {
		parsed, err := time.Parse("2006-01-02", raw)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "end_date must be YYYY-MM-DD"})
			return
		}
		endDate = parsed
	}
	topLimit := 10
	if raw := strings.TrimSpace(q.Get("top_limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			topLimit = n
		}
	}
	summary, err := usageRepo.GetGuardrailUsageSummary(r.Context(), storage.GuardrailUsageFilter{
		OrgID:        orgID,
		GuardrailID:  strings.TrimSpace(q.Get("guardrail_id")),
		TeamID:       strings.TrimSpace(q.Get("team_id")),
		VirtualKeyID: strings.TrimSpace(q.Get("virtual_key_id")),
		StartDate:    startDate,
		EndDate:      endDate,
		TopLimit:     topLimit,
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// --- Shared Guardrail Driver & Pipeline Evaluation Helper ---

func (s *GatewayServer) evaluateResolvedGuardrails(
	ctx context.Context,
	resolved []guardrails.ResolvedGuardrail,
	evalInput *domain.GuardrailEvalInput,
) (*domain.GuardrailEvalResult, error) {
	pipeline := s.GuardrailPipeline()
	combined := &domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionAllow,
		ModifiedTexts:     append([]string(nil), evalInput.Texts...),
		ModifiedMessages:  append([]domain.CanonicalMessage(nil), evalInput.StructuredMessages...),
		ModifiedToolCalls: append([]domain.CanonicalToolCall(nil), evalInput.ToolCalls...),
	}
	if len(resolved) == 0 {
		return combined, nil
	}

	curInput := *evalInput
	curInput.Texts = append([]string(nil), combined.ModifiedTexts...)
	curInput.StructuredMessages = append([]domain.CanonicalMessage(nil), combined.ModifiedMessages...)
	curInput.ToolCalls = append([]domain.CanonicalToolCall(nil), combined.ModifiedToolCalls...)

	lb := pipeline.RouterLB()
	driverRegistry := s.newGuardrailDriverRegistry()

	for _, rg := range resolved {
		res, _, err := lb.Execute(ctx, rg, func(candCtx context.Context, cand *guardrails.ResolvedCandidate) (*domain.GuardrailEvalResult, error) {
			if cand.TimeoutMs > 0 {
				var cancel context.CancelFunc
				candCtx, cancel = context.WithTimeout(candCtx, time.Duration(cand.TimeoutMs)*time.Millisecond)
				defer cancel()
			}
			var decSecrets map[string]any
			if s.vault != nil && cand.Definition != nil && strings.TrimSpace(cand.Definition.EncryptedSecrets) != "" {
				plain, decErr := s.vault.DecryptString(cand.Definition.EncryptedSecrets, cand.Definition.EncryptedDEK)
				if decErr != nil {
					return nil, fmt.Errorf("decrypt guardrail secrets for %q: %w", cand.Definition.Name, decErr)
				}
				_ = json.Unmarshal([]byte(plain), &decSecrets)
			}
			drv, drvErr := s.wrapGuardrailDriverLookup(driverRegistry.Build)(candCtx, guardrails.DriverConfig{
				Definition:       cand.Definition,
				EffectiveAction:  cand.EffectiveAction,
				EffectiveConfig:  cloneAnyMap(cand.EffectiveConfig),
				DecryptedSecrets: decSecrets,
			})
			if drvErr != nil {
				return nil, drvErr
			}
			if hooks := drv.SupportedHooks(); len(hooks) > 0 && curInput.Hook != "" {
				if !slices.Contains(hooks, curInput.Hook) {
					return &domain.GuardrailEvalResult{
						Decision:          domain.GuardrailDecisionAllow,
						AppliedGuardrails: []string{cand.Definition.Name},
					}, nil
				}
			}
			return drv.Evaluate(candCtx, &curInput)
		})
		if err != nil {
			if rg.FailOpen {
				combined.Violations = append(combined.Violations, domain.GuardrailViolation{
					GuardrailName: rg.Name,
					Severity:      "warning",
					Message:       err.Error(),
					Action:        domain.GuardrailActionAudit,
					Decision:      domain.GuardrailDecisionFlag,
				})
				if combined.Decision == domain.GuardrailDecisionAllow {
					combined.Decision = domain.GuardrailDecisionFlag
				}
				continue
			}
			combined.Decision = domain.GuardrailDecisionBlock
			combined.ErrorMessage = err.Error()
			combined.Violations = append(combined.Violations, domain.GuardrailViolation{
				GuardrailName: rg.Name,
				Severity:      "high",
				Message:       err.Error(),
				Action:        domain.GuardrailActionBlock,
				Decision:      domain.GuardrailDecisionBlock,
			})
			combined.AppliedGuardrails = append(combined.AppliedGuardrails, rg.Name)
			return combined, err
		}
		if res == nil {
			continue
		}
		combined.AppliedGuardrails = append(combined.AppliedGuardrails, rg.Name)
		combined.UsageUnits += res.UsageUnits
		combined.Violations = append(combined.Violations, res.Violations...)
		if len(res.ModifiedTexts) > 0 {
			combined.ModifiedTexts = res.ModifiedTexts
			curInput.Texts = append([]string(nil), res.ModifiedTexts...)
		}
		if len(res.ModifiedMessages) > 0 {
			combined.ModifiedMessages = res.ModifiedMessages
			curInput.StructuredMessages = append([]domain.CanonicalMessage(nil), res.ModifiedMessages...)
		}
		if len(res.ModifiedToolCalls) > 0 {
			combined.ModifiedToolCalls = res.ModifiedToolCalls
			curInput.ToolCalls = append([]domain.CanonicalToolCall(nil), res.ModifiedToolCalls...)
		}
		switch res.Decision {
		case domain.GuardrailDecisionBlock:
			combined.Decision = domain.GuardrailDecisionBlock
			if res.ErrorMessage != "" {
				combined.ErrorMessage = res.ErrorMessage
			}
			return combined, nil
		case domain.GuardrailDecisionModify:
			if combined.Decision != domain.GuardrailDecisionBlock {
				combined.Decision = domain.GuardrailDecisionModify
			}
		case domain.GuardrailDecisionFlag:
			if combined.Decision == domain.GuardrailDecisionAllow {
				combined.Decision = domain.GuardrailDecisionFlag
			}
		}
	}
	return combined, nil
}

func (s *GatewayServer) newGuardrailDriverRegistry() *drivers.Registry {
	opts := make([]drivers.RegistryOption, 0, 4)
	if s.netPolicy != nil {
		opts = append(opts, drivers.WithSSRFPolicy(s.netPolicy))
	}
	if tpRepo, ok := s.repo.(storage.ToolPolicyRepository); ok && tpRepo != nil {
		opts = append(opts, drivers.WithToolPolicyRepository(tpRepo))
	}
	if s.repo != nil {
		opts = append(opts, drivers.WithMCPServerRegistry(s.repo))
	}
	if s.reliability != nil {
		opts = append(opts, drivers.WithChatExecutor(drivers.ChatExecutorFunc(
			func(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
				resp, _, err := s.reliability.ExecuteChat(ctx, idCtx, req)
				return resp, err
			},
		)))
	}
	return drivers.NewRegistry(opts...)
}

// --- Expanded Admin Simulate Handler ---

func (s *GatewayServer) handleAdminSimulateGuardrailsExpanded(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	var req struct {
		Prompt          string                     `json:"prompt,omitempty"`
		Input           string                     `json:"input,omitempty"`
		Text            string                     `json:"text,omitempty"`
		Texts           []string                   `json:"texts,omitempty"`
		Messages        []domain.CanonicalMessage  `json:"messages,omitempty"`
		Tools           []domain.CanonicalTool     `json:"tools,omitempty"`
		ToolCalls       []domain.CanonicalToolCall `json:"tool_calls,omitempty"`
		Tags            []string                   `json:"tags,omitempty"`
		Direction       string                     `json:"direction,omitempty"`
		GuardrailName   string                     `json:"guardrail_name,omitempty"`
		StreamChunkSize int                        `json:"stream_chunk_size,omitempty"`
		Policy          *domain.GuardrailPolicy    `json:"policy,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}

	texts := append([]string(nil), req.Texts...)
	for _, single := range []string{req.Prompt, req.Input, req.Text} {
		if single != "" {
			texts = append(texts, single)
			break
		}
	}
	if len(texts) == 0 && len(req.Messages) == 0 && len(req.ToolCalls) == 0 && len(req.Tools) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "prompt, input, texts, messages, or tool_calls is required"})
		return
	}

	direction := strings.ToLower(strings.TrimSpace(req.Direction))
	if direction == "" {
		direction = domain.GuardrailDirectionInput
	}
	if direction != domain.GuardrailDirectionInput && direction != domain.GuardrailDirectionOutput {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "direction must be input or output"})
		return
	}
	hook := domain.GuardrailHookPreCall
	if direction == domain.GuardrailDirectionOutput {
		hook = domain.GuardrailHookPostCall
	}

	// Backward-compatible Layer-0 policy simulation when explicit policy or bare prompt-only payload is provided
	hasPipelineFields := strings.TrimSpace(req.GuardrailName) != "" ||
		req.StreamChunkSize > 0 ||
		len(req.ToolCalls) > 0 ||
		len(req.Tools) > 0 ||
		len(req.Texts) > 0 ||
		len(req.Messages) > 0 ||
		strings.TrimSpace(req.Direction) != "" ||
		strings.TrimSpace(req.Input) != ""

	var legacyViolations []string
	var legacyAction domain.GuardrailAction
	var legacyRedacted bool
	var legacyErr error
	redactedPrompt := ""
	if len(texts) > 0 {
		redactedPrompt = texts[0]
	}

	if req.Policy != nil || (!hasPipelineFields && strings.TrimSpace(req.Prompt) != "") {
		pol := req.Policy
		if pol == nil {
			var err error
			pol, err = s.repo.GetGuardrailPolicy(r.Context(), orgID)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			if pol == nil {
				pol = &domain.GuardrailPolicy{OrgID: orgID}
			}
		} else if pol.OrgID == "" {
			pol.OrgID = orgID
		}
		if len(texts) > 0 {
			canReq := &domain.CanonicalChatRequest{
				Messages: []domain.CanonicalMessage{{Role: "user", Content: texts[0]}},
			}
			outcome, evalErr := s.guardrails.EvaluateInputWithPolicy(r.Context(), pol, canReq)
			legacyViolations = outcome.Violations
			legacyAction = outcome.AppliedAction
			legacyRedacted = outcome.Redacted
			legacyErr = evalErr
			redactedPrompt = canReq.Messages[0].Content
			texts[0] = canReq.Messages[0].Content
		}
		if !hasPipelineFields {
			resp := map[string]any{
				"allowed":         legacyErr == nil,
				"applied_action":  legacyAction,
				"violations":      legacyViolations,
				"redacted":        legacyRedacted,
				"redacted_prompt": redactedPrompt,
			}
			if legacyErr != nil {
				resp["error_message"] = legacyErr.Error()
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	rc := guardrails.ResolveContext{
		OrgID:       orgID,
		Tags:        req.Tags,
		Hook:        hook,
		IsStreaming: req.StreamChunkSize > 0,
	}
	if strings.TrimSpace(req.GuardrailName) != "" {
		enabled := true
		rc.RequestOverrides = []domain.GuardrailRequestOverride{{
			Name:    strings.TrimSpace(req.GuardrailName),
			Enabled: &enabled,
		}}
	}

	eff, err := s.repo.ListEffectiveGuardrailsForOrg(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	resolved := guardrails.Resolve(eff, rc)
	if strings.TrimSpace(req.GuardrailName) != "" {
		filtered := resolved[:0]
		target := strings.ToLower(strings.TrimSpace(req.GuardrailName))
		for _, rg := range resolved {
			if strings.ToLower(rg.Name) == target {
				filtered = append(filtered, rg)
			}
		}
		resolved = filtered
	}

	dryCtx := withGuardrailDryRun(r.Context())
	if req.StreamChunkSize > 0 && len(texts) > 0 && len(resolved) > 0 {
		streamDrivers := make([]guardrails.Driver, 0, len(resolved))
		reg := s.newGuardrailDriverRegistry()
		for _, rg := range resolved {
			if len(rg.Candidates) == 0 {
				continue
			}
			cand := rg.Candidates[0]
			var decSecrets map[string]any
			if s.vault != nil && cand.Definition != nil && cand.Definition.EncryptedSecrets != "" {
				if plain, decErr := s.vault.DecryptString(cand.Definition.EncryptedSecrets, cand.Definition.EncryptedDEK); decErr == nil {
					_ = json.Unmarshal([]byte(plain), &decSecrets)
				}
			}
			if drv, drvErr := s.wrapGuardrailDriverLookup(reg.Build)(dryCtx, guardrails.DriverConfig{
				Definition:       cand.Definition,
				EffectiveAction:  cand.EffectiveAction,
				EffectiveConfig:  cloneAnyMap(cand.EffectiveConfig),
				DecryptedSecrets: decSecrets,
			}); drvErr == nil && drv != nil {
				streamDrivers = append(streamDrivers, drv)
			}
		}
		if swe := guardrails.NewStreamWindowEvaluator(guardrails.StreamWindowConfig{
			Unit:        guardrails.StreamWindowBytes,
			WindowSize:  req.StreamChunkSize * 2,
			OverlapSize: req.StreamChunkSize,
			InputTemplate: &domain.GuardrailEvalInput{
				Direction: direction,
				Hook:      hook,
				OrgID:     orgID,
				Tags:      req.Tags,
			},
		}, streamDrivers...); swe != nil {
			joined := strings.Join(texts, "\n")
			var rebuilt strings.Builder
			chunksEvaluated := 0
			for i := 0; i < len(joined); i += req.StreamChunkSize {
				end := i + req.StreamChunkSize
				if end > len(joined) {
					end = len(joined)
				}
				chunksEvaluated++
				safeChunk, _ := swe.Process(dryCtx, joined[i:end])
				rebuilt.WriteString(safeChunk)
			}
			tail, _ := swe.Flush(dryCtx)
			rebuilt.WriteString(tail)

			decision := domain.GuardrailDecisionAllow
			appliedAction := domain.GuardrailAction("allow")
			if swe.Blocked() {
				decision = domain.GuardrailDecisionBlock
				appliedAction = domain.GuardrailActionBlock
			} else if swe.Redacted() {
				decision = domain.GuardrailDecisionModify
				appliedAction = domain.GuardrailActionRedact
			} else if len(swe.EvalViolations()) > 0 {
				decision = domain.GuardrailDecisionFlag
				appliedAction = domain.GuardrailActionAudit
			}
			appliedNames := make([]string, 0, len(streamDrivers))
			for _, sd := range streamDrivers {
				appliedNames = append(appliedNames, sd.Name())
			}
			outText := rebuilt.String()
			writeJSON(w, http.StatusOK, map[string]any{
				"allowed":                 !swe.Blocked() && swe.Err() == nil,
				"blocked":                 swe.Blocked(),
				"decision":                decision,
				"action":                  appliedAction,
				"applied_action":          appliedAction,
				"redacted":                swe.Redacted(),
				"direction":               direction,
				"redacted_prompt":         outText,
				"texts":                   []string{outText},
				"modified_texts":          []string{outText},
				"violations":              swe.EvalViolations(),
				"applied_guardrails":      appliedNames,
				"stream_chunks_evaluated": chunksEvaluated,
			})
			return
		}
	}

	evalInput := &domain.GuardrailEvalInput{
		Direction:          direction,
		Hook:               hook,
		OrgID:              orgID,
		Tags:               req.Tags,
		Texts:              texts,
		StructuredMessages: req.Messages,
		Tools:              req.Tools,
		ToolCalls:          req.ToolCalls,
	}
	res, evalErr := s.evaluateResolvedGuardrails(dryCtx, resolved, evalInput)
	blocked := res.Decision == domain.GuardrailDecisionBlock || evalErr != nil
	redacted := res.Decision == domain.GuardrailDecisionModify || legacyRedacted
	appliedAction := domain.GuardrailAction("allow")
	if blocked {
		appliedAction = domain.GuardrailActionBlock
	} else if redacted {
		appliedAction = domain.GuardrailActionRedact
	} else if res.Decision == domain.GuardrailDecisionFlag {
		appliedAction = domain.GuardrailActionAudit
	}
	finalTexts := res.ModifiedTexts
	if len(finalTexts) == 0 {
		finalTexts = texts
	}
	if len(finalTexts) > 0 {
		redactedPrompt = finalTexts[0]
	}
	resp := map[string]any{
		"allowed":             !blocked,
		"blocked":             blocked,
		"decision":            res.Decision,
		"action":              appliedAction,
		"applied_action":      appliedAction,
		"redacted":            redacted,
		"direction":           direction,
		"redacted_prompt":     redactedPrompt,
		"texts":               finalTexts,
		"modified_texts":      res.ModifiedTexts,
		"modified_messages":   res.ModifiedMessages,
		"modified_tool_calls": res.ModifiedToolCalls,
		"violations":          res.Violations,
		"applied_guardrails":  res.AppliedGuardrails,
	}
	if evalErr != nil {
		resp["error_message"] = evalErr.Error()
	} else if res.ErrorMessage != "" {
		resp["error_message"] = res.ErrorMessage
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- Data Plane Endpoint: POST /v1/guardrails/apply ---

func (s *GatewayServer) handleApplyGuardrails(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "No identity context present on request",
		})
		return
	}

	var req struct {
		GuardrailName string                     `json:"guardrail_name,omitempty"`
		InputType     string                     `json:"input_type,omitempty"` // request|input|response|output
		Text          string                     `json:"text,omitempty"`
		Texts         []string                   `json:"texts,omitempty"`
		Messages      []domain.CanonicalMessage  `json:"messages,omitempty"`
		Tools         []domain.CanonicalTool     `json:"tools,omitempty"`
		ToolCalls     []domain.CanonicalToolCall `json:"tool_calls,omitempty"`
		Tags          []string                   `json:"tags,omitempty"`
		Metadata      map[string]any             `json:"metadata,omitempty"`
		Model         string                     `json:"model,omitempty"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	if err := dec.Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    err.Error(),
		})
		return
	}

	texts := append([]string(nil), req.Texts...)
	if req.Text != "" && len(texts) == 0 {
		texts = []string{req.Text}
	}
	if len(texts) == 0 && len(req.Messages) == 0 && len(req.ToolCalls) == 0 && len(req.Tools) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_input",
			Message:    "text, texts, messages, tools, or tool_calls is required",
		})
		return
	}

	direction := domain.GuardrailDirectionInput
	hook := domain.GuardrailHookPreCall
	switch strings.ToLower(strings.TrimSpace(req.InputType)) {
	case "", "request", "input":
		direction = domain.GuardrailDirectionInput
		hook = domain.GuardrailHookPreCall
	case "response", "output":
		direction = domain.GuardrailDirectionOutput
		hook = domain.GuardrailHookPostCall
	default:
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_input_type",
			Message:    "input_type must be request, input, response, or output",
		})
		return
	}

	// Sanitize inbound metadata and never trust caller-supplied internal origin markers.
	meta := cloneAnyMap(req.Metadata)
	drivers.StripInternalGuardrailOriginMetadata(meta)

	eff, err := s.repo.ListEffectiveGuardrailsForOrg(r.Context(), idCtx.OrgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	callerRoles := []string{}
	if role := strings.TrimSpace(string(idCtx.Role)); role != "" {
		callerRoles = append(callerRoles, role)
	}

	rc := guardrails.ResolveContext{
		OrgID:        idCtx.OrgID,
		TeamID:       idCtx.TeamID,
		VirtualKeyID: idCtx.VirtualKeyID,
		EndUserID:    idCtx.UserID,
		Model:        strings.TrimSpace(req.Model),
		CallerRoles:  callerRoles,
		Tags:         req.Tags,
		Hook:         hook,
	}

	requestedName := strings.TrimSpace(req.GuardrailName)
	if requestedName != "" {
		// Verify existence, active status, and role authorization in caller's own organization ONLY.
		var orgMatches []*domain.GuardrailDefinition
		for _, def := range eff.Definitions {
			if def != nil && strings.EqualFold(def.Name, requestedName) {
				orgMatches = append(orgMatches, def)
			}
		}
		if len(orgMatches) == 0 {
			// Also check non-active definitions in caller's org so pending/rejected returns 403 while cross-org returns 404.
			allInOrg, _ := s.repo.ListGuardrailDefinitions(r.Context(), idCtx.OrgID, "", requestedName)
			if len(allInOrg) > 0 {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "guardrail_not_active",
					Message:    fmt.Sprintf("Guardrail %q is not active", requestedName),
				})
				return
			}
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "guardrail_not_found",
				Message:    fmt.Sprintf("Guardrail %q not found", requestedName),
			})
			return
		}
		roleAllowed := false
		for _, def := range orgMatches {
			if len(def.EnabledRoles) == 0 || slices.ContainsFunc(def.EnabledRoles, func(er string) bool {
				er = strings.TrimSpace(er)
				return er == "*" || strings.EqualFold(er, string(idCtx.Role))
			}) {
				roleAllowed = true
				break
			}
		}
		if !roleAllowed {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "guardrail_role_forbidden",
				Message:    fmt.Sprintf("Caller role %q is not authorized to invoke guardrail %q", idCtx.Role, requestedName),
			})
			return
		}

		// Opt in the requested named guardrail while still enforcing all locked/default_on org rules (anti-bypass).
		enabled := true
		rc.RequestOverrides = []domain.GuardrailRequestOverride{{
			Name:    requestedName,
			Enabled: &enabled,
		}}
	}

	resolved := guardrails.Resolve(eff, rc)

	// If a specific guardrail_name was requested, ensure any locked/default_on guardrails stay enforced
	// alongside it, and any non-locked unrelated optional guardrails are excluded.
	if requestedName != "" {
		filtered := make([]guardrails.ResolvedGuardrail, 0, len(resolved))
		for _, rg := range resolved {
			if strings.EqualFold(rg.Name, requestedName) || rg.IsLocked || rg.DefaultOn {
				filtered = append(filtered, rg)
			}
		}
		resolved = filtered
	}

	started := time.Now()
	evalInput := &domain.GuardrailEvalInput{
		Direction:          direction,
		Hook:               hook,
		RequestID:          observability.TraceFromContext(r.Context()).TraceID,
		TraceID:            observability.TraceFromContext(r.Context()).TraceID,
		OrgID:              idCtx.OrgID,
		TeamID:             idCtx.TeamID,
		VirtualKeyID:       idCtx.VirtualKeyID,
		EndUserID:          idCtx.UserID,
		Model:              strings.TrimSpace(req.Model),
		Tags:               req.Tags,
		Texts:              texts,
		StructuredMessages: req.Messages,
		Tools:              req.Tools,
		ToolCalls:          req.ToolCalls,
		RequestHeaders:     sanitizeGuardrailHeaders(r),
		Metadata:           meta,
	}

	res, evalErr := s.evaluateResolvedGuardrails(r.Context(), resolved, evalInput)
	latencyMs := time.Since(started).Milliseconds()

	blocked := res.Decision == domain.GuardrailDecisionBlock || evalErr != nil
	action := domain.GuardrailAction("allow")
	if blocked {
		action = domain.GuardrailActionBlock
	} else if res.Decision == domain.GuardrailDecisionModify {
		action = domain.GuardrailActionRedact
	} else if res.Decision == domain.GuardrailDecisionFlag {
		action = domain.GuardrailActionAudit
	}

	effectiveTexts := res.ModifiedTexts
	if len(effectiveTexts) == 0 {
		effectiveTexts = texts
	}
	usageUnits := res.UsageUnits
	if usageUnits == 0 && len(res.AppliedGuardrails) > 0 {
		usageUnits = int64(len(res.AppliedGuardrails))
	}

	resp := map[string]any{
		"decision":            res.Decision,
		"action":              action,
		"blocked":             blocked,
		"texts":               effectiveTexts,
		"modified_texts":      res.ModifiedTexts,
		"modified_messages":   res.ModifiedMessages,
		"modified_tool_calls": res.ModifiedToolCalls,
		"violations":          res.Violations,
		"applied_guardrails":  res.AppliedGuardrails,
		"usage_units":         usageUnits,
		"latency_ms":          latencyMs,
	}
	if evalErr != nil {
		resp["error_message"] = evalErr.Error()
	} else if res.ErrorMessage != "" {
		resp["error_message"] = res.ErrorMessage
	}
	writeJSON(w, http.StatusOK, resp)
}
