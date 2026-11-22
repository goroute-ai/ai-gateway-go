package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func (s *GatewayServer) keyGovernanceRepo() (storage.KeyGovernanceRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	r, ok := s.repo.(storage.KeyGovernanceRepository)
	return r, ok && r != nil
}

func redactAuditSnapshot(v any) map[string]any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return redactAuditMap(m)
}

func redactAuditMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	for k, v := range m {
		lower := strings.ToLower(k)
		if lower == "raw_key" || lower == "key_hash" || lower == "key" ||
			lower == "master_key" || lower == "new_master_key" ||
			lower == "password" || lower == "password_hash" || lower == "password_sha1" ||
			lower == "auth_secret" || lower == "csrf_token" ||
			lower == "authorization" || lower == "x-api-key" || lower == "api_key" ||
			strings.HasPrefix(lower, "encrypted_") ||
			lower == "dek_nonce" || lower == "data_nonce" ||
			strings.HasPrefix(lower, "decrypted_") {
			m[k] = "[REDACTED]"
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			m[k] = redactAuditMap(sub)
		}
	}
	return m
}

func (s *GatewayServer) auditWithDiff(
	ctx context.Context,
	orgID, action, resource, resourceID string,
	details map[string]any,
	before, after any,
) {
	if s == nil || s.repo == nil {
		return
	}
	actorID := "master_admin"
	var impersonatedBy string
	if op := auth.OperatorFromContext(ctx); op != nil {
		if op.ActorID != "" {
			actorID = op.ActorID
		}
		impersonatedBy = op.ImpersonatedByActorID
	}
	if impersonatedBy != "" {
		enriched := make(map[string]any, len(details)+2)
		for k, v := range details {
			enriched[k] = v
		}
		enriched["actor_id"] = actorID
		enriched["impersonated_by"] = impersonatedBy
		details = enriched
	}
	_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:       orgID,
		ActorID:     actorID,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		Details:     details,
		BeforeValue: redactAuditSnapshot(before),
		AfterValue:  redactAuditSnapshot(after),
	})
}

func (s *GatewayServer) validateLifecycleWebhookURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return "", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_webhook_url",
			Message:    "lifecycle_webhook_url must be a valid URL with host",
		}
	}
	if s != nil && s.netPolicy != nil {
		if err := s.netPolicy.ValidateURL(parsed); err != nil {
			return "", &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "webhook_ssrf_blocked",
				Message:    fmt.Sprintf("lifecycle_webhook_url rejected by outbound network security policy: %v", err),
			}
		}
	} else if parsed.Scheme != "https" {
		return "", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_webhook_scheme",
			Message:    "lifecycle_webhook_url must use https",
		}
	}
	return parsed.String(), nil
}

// enforceGuaranteedThroughput checks that creating or updating a key does not oversubscribe
// parent Team or Organization RPM/TPM ceilings when enforce_guaranteed_throughput is active.
func (s *GatewayServer) enforceGuaranteedThroughput(
	ctx context.Context,
	w http.ResponseWriter,
	orgID, teamID, excludeKeyID string,
	reqRPM, reqTPM int,
) bool {
	if s == nil || s.repo == nil || orgID == "" {
		return true
	}
	if reqRPM <= 0 && reqTPM <= 0 {
		return true
	}

	org, err := s.repo.GetOrganization(ctx, orgID)
	var team *domain.Team
	if teamID != "" {
		team, _ = s.repo.GetTeam(ctx, teamID)
	}

	checkOrg := err == nil && org != nil && org.EnforceGuaranteedThroughput && (org.RPMLimit > 0 || org.TPMLimit > 0)
	checkTeam := team != nil && team.EnforceGuaranteedThroughput && (team.RPMLimit > 0 || team.TPMLimit > 0)
	if !checkOrg && !checkTeam {
		return true
	}

	govRepo, ok := s.keyGovernanceRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "governance_unsupported",
			Message:    "Configured storage repository does not support guaranteed throughput checks",
		})
		return false
	}

	if checkTeam {
		rpmSum, tpmSum, sumErr := govRepo.SumChildKeyThroughput(ctx, orgID, teamID, excludeKeyID)
		if sumErr != nil {
			domain.WriteHTTPError(w, sumErr)
			return false
		}
		if team.RPMLimit > 0 && reqRPM > 0 && rpmSum+reqRPM > team.RPMLimit {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "throughput_allocation_exceeded",
				Message:    fmt.Sprintf("team guaranteed throughput exceeded: allocated %d + requested %d > team rpm_limit %d", rpmSum, reqRPM, team.RPMLimit),
			})
			return false
		}
		if team.TPMLimit > 0 && reqTPM > 0 && tpmSum+reqTPM > team.TPMLimit {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "throughput_allocation_exceeded",
				Message:    fmt.Sprintf("team guaranteed throughput exceeded: allocated %d + requested %d > team tpm_limit %d", tpmSum, reqTPM, team.TPMLimit),
			})
			return false
		}
	}

	if checkOrg {
		rpmSum, tpmSum, sumErr := govRepo.SumChildKeyThroughput(ctx, orgID, "", excludeKeyID)
		if sumErr != nil {
			domain.WriteHTTPError(w, sumErr)
			return false
		}
		if org.RPMLimit > 0 && reqRPM > 0 && rpmSum+reqRPM > org.RPMLimit {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "throughput_allocation_exceeded",
				Message:    fmt.Sprintf("organization guaranteed throughput exceeded: allocated %d + requested %d > org rpm_limit %d", rpmSum, reqRPM, org.RPMLimit),
			})
			return false
		}
		if org.TPMLimit > 0 && reqTPM > 0 && tpmSum+reqTPM > org.TPMLimit {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "throughput_allocation_exceeded",
				Message:    fmt.Sprintf("organization guaranteed throughput exceeded: allocated %d + requested %d > org tpm_limit %d", tpmSum, reqTPM, org.TPMLimit),
			})
			return false
		}
	}

	return true
}

// checkFallbackModelQuota verifies per-model quota descriptors and remaining scope budget
// affordability on cross-provider fallback hops without double-counting top-level RPM/TPM
// or primary budget reservations already acquired on initial entry.
func (s *GatewayServer) checkFallbackModelQuota(ctx context.Context, idCtx *domain.IdentityContext, fallbackAlias string, estTokens int) error {
	if s == nil || idCtx == nil || strings.TrimSpace(fallbackAlias) == "" {
		return nil
	}
	now := s.nowUTC()
	effID := applyEffectiveTempBudgets(idCtx, now)
	var reqID string
	var maxOutput int
	if qState := requestQuotaStateFromContext(ctx); qState != nil {
		reqID = qState.SettlementRequestID
		maxOutput = qState.MaxOutputTokens
	}

	var descs []domain.RateLimitDescriptor
	if s.limiter != nil {
		var err error
		descs, err = s.buildExtendedQuotaDescriptors(ctx, effID, fallbackAlias, now)
		if err != nil {
			return err
		}
	}

	var nonModelBudgetDescs []domain.RateLimitDescriptor
	var modelDescs []domain.RateLimitDescriptor
	for _, d := range descs {
		switch d.ScopeType {
		case domain.QuotaScopeModelPerKey,
			domain.QuotaScopeModelPerTeam,
			domain.QuotaScopeModelPerProject,
			domain.QuotaScopeModelPerUser,
			domain.QuotaScopeModelPerOrg,
			domain.QuotaScopeModelPerEndUser:
			modelDescs = append(modelDescs, d)
		default:
			if d.MaxBudgetMicros > 0 {
				nonModelBudgetDescs = append(nonModelBudgetDescs, d)
			}
		}
	}

	// Enforce remaining scope budget affordability whenever caller has any configured budget.
	var fallbackCost int64
	if hasLegacyBudget(effID) || len(nonModelBudgetDescs) > 0 || descriptorsHaveBudget(modelDescs) {
		cost, estErr := s.tokenBudgetUpperBound(ctx, effID.OrgID, fallbackAlias, estTokens, maxOutput)
		if estErr != nil {
			return &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeBudgetExceeded,
				Code:       "budget_estimate_unavailable",
				Message:    fmt.Sprintf("A safe upper-bound cost could not be calculated for fallback model %q", fallbackAlias),
			}
		}
		fallbackCost = cost
		if s.limiter != nil {
			if hasLegacyBudget(effID) {
				if err := s.limiter.CheckBudgetReserve(ctx, effID, fallbackCost, reqID); err != nil {
					return &domain.GatewayError{
						StatusCode:    http.StatusTooManyRequests,
						Type:          domain.ErrorTypeBudgetExceeded,
						Code:          "fallback_budget_exceeded",
						Message:       fmt.Sprintf("Remaining budget cannot cover fallback model %q: %s", fallbackAlias, err.Error()),
						RetryAfterSec: 60,
					}
				}
			}
			if len(nonModelBudgetDescs) > 0 {
				if err := s.limiter.CheckDescriptorBudgetReserve(ctx, effID.OrgID, nonModelBudgetDescs, fallbackCost, reqID); err != nil {
					return &domain.GatewayError{
						StatusCode:    http.StatusTooManyRequests,
						Type:          domain.ErrorTypeBudgetExceeded,
						Code:          "fallback_budget_exceeded",
						Message:       fmt.Sprintf("Remaining scope budget cannot cover fallback model %q: %s", fallbackAlias, err.Error()),
						RetryAfterSec: 60,
					}
				}
			}
		}
	}

	if s.limiter == nil || len(modelDescs) == 0 {
		return nil
	}
	rel, _, err := s.limiter.AcquireDescriptorsWithMeta(ctx, effID.OrgID, uuid.NewString(), estTokens, 0, fallbackCost, modelDescs)
	if err != nil {
		return err
	}
	// Release immediately after preflight verification so fallback probing never leaks concurrency slots.
	rel(-1, -1, -1)
	return nil
}

// handleKeySelfInfo serves GET /v1/key/info so developers can inspect the active virtual key's
// metadata, limits, spend, expiry, and allowed models without control-plane privileges.
func (s *GatewayServer) handleKeySelfInfo(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil || idCtx.VirtualKeyID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "missing_identity",
			Message:    "Valid virtual key is required",
		})
		return
	}
	vk, err := s.repo.GetVirtualKeyByID(r.Context(), idCtx.VirtualKeyID)
	if err != nil || vk == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "virtual_key_not_found",
			Message:    "Virtual key not found",
		})
		return
	}
	safeCopy := *vk
	safeCopy.RawKey = ""
	safeCopy.KeyHash = ""
	writeJSON(w, http.StatusOK, &safeCopy)
}

// handleAdminUpdateOrg handles PUT /admin/v1/organizations/{orgID} to mutate organization policies.
func (s *GatewayServer) handleAdminUpdateOrg(w http.ResponseWriter, r *http.Request) {
	orgID := strings.TrimSpace(chi.URLParam(r, "orgID"))
	if orgID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_org_id",
			Message:    "orgID is required",
		})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}

	updRepo, ok := s.repo.(storage.OrganizationUpdateRepository)
	if !ok || updRepo == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "org_update_unsupported",
			Message:    "Configured storage repository does not support organization updates",
		})
		return
	}

	existing, err := s.repo.GetOrganization(r.Context(), orgID)
	if err != nil || existing == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "organization_not_found",
			Message:    "Organization not found",
		})
		return
	}

	var req struct {
		Name                        *string                       `json:"name,omitempty"`
		MaxBudgetMicros             *int64                        `json:"max_budget_micros,omitempty"`
		TempBudgetIncreaseMicros    *int64                        `json:"temp_budget_increase_micros,omitempty"`
		TempBudgetExpiresAt         *time.Time                    `json:"temp_budget_expires_at,omitempty"`
		SelfServeBudgetPolicy       *domain.SelfServeBudgetPolicy `json:"self_serve_budget_policy,omitempty"`
		SoftBudgetMicros            *int64                        `json:"soft_budget_micros,omitempty"`
		ThrottleOnBudgetExceeded    *bool                         `json:"throttle_on_budget_exceeded,omitempty"`
		BudgetFallbacks             map[string][]string           `json:"budget_fallbacks,omitempty"`
		BudgetResetPeriod           *domain.BudgetResetPeriod     `json:"budget_reset_period,omitempty"`
		RPMLimit                    *int                          `json:"rpm_limit,omitempty"`
		TPMLimit                    *int                          `json:"tpm_limit,omitempty"`
		MaxConcurrentRequests       *int                          `json:"max_concurrent_requests,omitempty"`
		BatchEnqueuedTokenLimit     *int64                        `json:"batch_enqueued_token_limit,omitempty"`
		MaxIterations               *int                          `json:"max_iterations,omitempty"`
		MaxBudgetPerSessionMicros   *int64                        `json:"max_budget_per_session_micros,omitempty"`
		EnforceGuaranteedThroughput *bool                         `json:"enforce_guaranteed_throughput,omitempty"`
		DeveloperSelfServeKeys      *bool                         `json:"developer_self_serve_keys,omitempty"`
		KeyExpiryAlertDays          []int                         `json:"key_expiry_alert_days,omitempty"`
		LifecycleWebhookURL         *string                       `json:"lifecycle_webhook_url,omitempty"`
		IsActive                    *bool                         `json:"is_active,omitempty"`
		Metadata                    map[string]string             `json:"metadata,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}

	updated := *existing
	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_org_name", Message: "Organization name cannot be empty"})
			return
		}
		updated.Name = trimmed
	}
	if req.MaxBudgetMicros != nil {
		if *req.MaxBudgetMicros < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_budget", Message: "max_budget_micros cannot be negative"})
			return
		}
		updated.MaxBudgetMicros = *req.MaxBudgetMicros
	}
	if req.TempBudgetIncreaseMicros != nil {
		if *req.TempBudgetIncreaseMicros < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_temp_budget", Message: "temp_budget_increase_micros cannot be negative"})
			return
		}
		updated.TempBudgetIncreaseMicros = *req.TempBudgetIncreaseMicros
	}
	if req.TempBudgetExpiresAt != nil {
		t := req.TempBudgetExpiresAt.UTC()
		updated.TempBudgetExpiresAt = &t
	}
	if req.SelfServeBudgetPolicy != nil {
		if *req.SelfServeBudgetPolicy != "" && !req.SelfServeBudgetPolicy.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_self_serve_budget_policy", Message: "self_serve_budget_policy must be disabled, lower_only, or ceiling"})
			return
		}
		updated.SelfServeBudgetPolicy = *req.SelfServeBudgetPolicy
	}
	if req.SoftBudgetMicros != nil {
		if *req.SoftBudgetMicros < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_soft_budget", Message: "soft_budget_micros cannot be negative"})
			return
		}
		updated.SoftBudgetMicros = *req.SoftBudgetMicros
	}
	if req.ThrottleOnBudgetExceeded != nil {
		updated.ThrottleOnBudgetExceeded = *req.ThrottleOnBudgetExceeded
	}
	if req.BudgetFallbacks != nil {
		updated.BudgetFallbacks = domain.CloneBudgetFallbacks(req.BudgetFallbacks)
	}
	if req.BudgetResetPeriod != nil {
		updated.BudgetResetPeriod = *req.BudgetResetPeriod
	}
	if req.RPMLimit != nil {
		if *req.RPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_rpm_limit", Message: "rpm_limit cannot be negative"})
			return
		}
		updated.RPMLimit = *req.RPMLimit
	}
	if req.TPMLimit != nil {
		if *req.TPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_tpm_limit", Message: "tpm_limit cannot be negative"})
			return
		}
		updated.TPMLimit = *req.TPMLimit
	}
	if req.MaxConcurrentRequests != nil {
		if *req.MaxConcurrentRequests < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_concurrency_limit", Message: "max_concurrent_requests cannot be negative"})
			return
		}
		updated.MaxConcurrentRequests = *req.MaxConcurrentRequests
	}
	if req.BatchEnqueuedTokenLimit != nil {
		updated.BatchEnqueuedTokenLimit = *req.BatchEnqueuedTokenLimit
	}
	if req.MaxIterations != nil {
		updated.MaxIterations = *req.MaxIterations
	}
	if req.MaxBudgetPerSessionMicros != nil {
		updated.MaxBudgetPerSessionMicros = *req.MaxBudgetPerSessionMicros
	}
	if req.EnforceGuaranteedThroughput != nil {
		updated.EnforceGuaranteedThroughput = *req.EnforceGuaranteedThroughput
	}
	if req.DeveloperSelfServeKeys != nil {
		updated.DeveloperSelfServeKeys = *req.DeveloperSelfServeKeys
	}
	if req.KeyExpiryAlertDays != nil {
		cleaned := make([]int, 0, len(req.KeyExpiryAlertDays))
		for _, d := range req.KeyExpiryAlertDays {
			if d > 0 && !slices.Contains(cleaned, d) {
				cleaned = append(cleaned, d)
			}
		}
		updated.KeyExpiryAlertDays = cleaned
	}
	if req.LifecycleWebhookURL != nil {
		cleanURL, wErr := s.validateLifecycleWebhookURL(*req.LifecycleWebhookURL)
		if wErr != nil {
			domain.WriteHTTPError(w, wErr)
			return
		}
		updated.LifecycleWebhookURL = cleanURL
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}
	if req.Metadata != nil {
		updated.Metadata = req.Metadata
	}

	if err := updRepo.UpdateOrganization(r.Context(), &updated); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateOrg(r.Context(), updated.ID)
	}
	saved, gErr := s.repo.GetOrganization(r.Context(), updated.ID)
	if gErr != nil || saved == nil {
		saved = &updated
	}
	s.auditWithDiff(r.Context(), saved.ID, "organization.updated", "organization", saved.ID, map[string]any{
		"name":                          saved.Name,
		"enforce_guaranteed_throughput": saved.EnforceGuaranteedThroughput,
		"developer_self_serve_keys":     saved.DeveloperSelfServeKeys,
	}, existing, saved)
	writeJSON(w, http.StatusOK, saved)
}

func (s *GatewayServer) handleAdminGetKey(w http.ResponseWriter, r *http.Request) {
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	vk, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || vk == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), false); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "virtual_key_not_found",
			Message:    "Virtual key not found",
		})
		return
	}
	if _, ok := s.authorizeTeamAdmin(w, r, vk.OrgID, vk.TeamID, false); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, vk.OrgID, nil) {
		return
	}
	safeCopy := *vk
	safeCopy.RawKey = ""
	safeCopy.KeyHash = ""
	writeJSON(w, http.StatusOK, &safeCopy)
}

func (s *GatewayServer) handleAdminBlockKey(w http.ResponseWriter, r *http.Request) {
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	vk, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || vk == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "virtual_key_not_found", Message: "Virtual key not found"})
		return
	}
	op, ok := s.authorizeTeamAdmin(w, r, vk.OrgID, vk.TeamID, true)
	if !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, vk.OrgID, nil) {
		return
	}
	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		_ = decodeAdminJSON(w, r, &req)
	}
	actorID := "master_admin"
	if op != nil && op.ActorID != "" {
		actorID = op.ActorID
	}
	if err := s.authSvc.RevokeKeyWithActor(r.Context(), keyID, actorID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	after, _ := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	s.auditWithDiff(r.Context(), vk.OrgID, "virtual_key.blocked", "virtual_key", keyID, map[string]any{
		"reason":     strings.TrimSpace(req.Reason),
		"blocked_by": actorID,
	}, vk, after)
	writeJSON(w, http.StatusOK, map[string]any{"status": "blocked", "id": keyID, "revoked_by": actorID})
}

func (s *GatewayServer) handleAdminUnblockKey(w http.ResponseWriter, r *http.Request) {
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	vk, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || vk == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "virtual_key_not_found", Message: "Virtual key not found"})
		return
	}
	if _, ok := s.authorizeTeamAdmin(w, r, vk.OrgID, vk.TeamID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, vk.OrgID, nil) {
		return
	}
	govRepo, ok := s.keyGovernanceRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotImplemented, Type: domain.ErrorTypeServer, Code: "governance_unsupported", Message: "Configured storage repository does not support key unblocking"})
		return
	}
	if err := govRepo.UnblockVirtualKey(r.Context(), keyID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateKeyID(r.Context(), keyID)
	}
	after, _ := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	s.auditWithDiff(r.Context(), vk.OrgID, "virtual_key.unblocked", "virtual_key", keyID, nil, vk, after)
	if after != nil {
		writeJSON(w, http.StatusOK, after)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "active", "id": keyID})
}

func (s *GatewayServer) handleAdminResetKeySpend(w http.ResponseWriter, r *http.Request) {
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	vk, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || vk == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "virtual_key_not_found", Message: "Virtual key not found"})
		return
	}
	if _, ok := s.authorizeTeamAdmin(w, r, vk.OrgID, vk.TeamID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, vk.OrgID, nil) {
		return
	}
	govRepo, ok := s.keyGovernanceRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotImplemented, Type: domain.ErrorTypeServer, Code: "governance_unsupported", Message: "Configured storage repository does not support spend reset"})
		return
	}
	if err := govRepo.ResetEntitySpend(r.Context(), storage.EntitySpendScopeKey, vk.OrgID, keyID, ""); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.limiter != nil {
		_ = s.limiter.ClearEntitySpend(r.Context(), storage.EntitySpendScopeKey, vk.OrgID, keyID, "")
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateKeyID(r.Context(), keyID)
	}
	after, _ := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	s.auditWithDiff(r.Context(), vk.OrgID, "virtual_key.spend_reset", "virtual_key", keyID, map[string]any{
		"previous_spent_micros": vk.SpentMicros,
	}, vk, after)
	writeJSON(w, http.StatusOK, map[string]any{"status": "reset", "id": keyID, "spent_micros": 0})
}

func (s *GatewayServer) handleAdminBulkUpdateKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID           string   `json:"org_id,omitempty"`
		KeyIDs          []string `json:"key_ids"`
		IsActive        *bool    `json:"is_active,omitempty"`
		MaxBudgetMicros *int64   `json:"max_budget_micros,omitempty"`
		RPMLimit        *int     `json:"rpm_limit,omitempty"`
		TPMLimit        *int     `json:"tpm_limit,omitempty"`
		AllowedModels   []string `json:"allowed_models,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	orgID := resolveScopedOrgID(r, req.OrgID)
	normalizedIDs := make([]string, 0, len(req.KeyIDs))
	seenIDs := make(map[string]struct{}, len(req.KeyIDs))
	for _, rawID := range req.KeyIDs {
		kid := strings.TrimSpace(rawID)
		if kid == "" {
			continue
		}
		if _, dup := seenIDs[kid]; dup {
			continue
		}
		seenIDs[kid] = struct{}{}
		normalizedIDs = append(normalizedIDs, kid)
	}
	if len(normalizedIDs) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "missing_key_ids", Message: "key_ids must contain at least one key ID"})
		return
	}
	if len(normalizedIDs) > 250 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "too_many_keys", Message: "bulk-update supports at most 250 keys per request"})
		return
	}
	if req.MaxBudgetMicros != nil && *req.MaxBudgetMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_budget", Message: "max_budget_micros cannot be negative"})
		return
	}
	if req.RPMLimit != nil && *req.RPMLimit < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_rpm_limit", Message: "rpm_limit cannot be negative"})
		return
	}
	if req.TPMLimit != nil && *req.TPMLimit < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_tpm_limit", Message: "tpm_limit cannot be negative"})
		return
	}

	govRepo, ok := s.keyGovernanceRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotImplemented, Type: domain.ErrorTypeServer, Code: "governance_unsupported", Message: "Configured storage repository does not support bulk key updates"})
		return
	}

	var firstOp *domain.OperatorContext
	targetOrg := orgID
	teamSet := make(map[string]struct{})
	beforeKeys := make([]*domain.VirtualKey, 0, len(normalizedIDs))
	var preDeprecatedHashes []string
	depLookup, _ := s.repo.(storage.DeprecatedKeyLookupRepository)
	for _, kid := range normalizedIDs {
		vk, err := s.repo.GetVirtualKeyByID(r.Context(), kid)
		if err != nil || vk == nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "virtual_key_not_found", Message: fmt.Sprintf("Virtual key %q not found", kid)})
			return
		}
		if targetOrg == "" {
			targetOrg = vk.OrgID
		} else if vk.OrgID != targetOrg {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypePermission, Code: "cross_org_access_denied", Message: "All keys in bulk-update must belong to the same organization"})
			return
		}
		op, authOK := s.authorizeTeamAdmin(w, r, vk.OrgID, vk.TeamID, true)
		if !authOK {
			return
		}
		firstOp = op
		if op != nil && op.Role == domain.OperatorRoleTeamAdmin && req.MaxBudgetMicros != nil && *req.MaxBudgetMicros > 0 {
			if !s.enforceSelfServeBudgetPolicy(r.Context(), w, op, vk.OrgID, vk.TeamID, vk.MaxBudgetMicros, *req.MaxBudgetMicros) {
				return
			}
		}
		beforeCopy := *vk
		beforeKeys = append(beforeKeys, &beforeCopy)
		if req.IsActive != nil && !*req.IsActive && depLookup != nil {
			if hashes, err := depLookup.ListDeprecatedVirtualKeyHashesByKeyID(r.Context(), vk.ID); err == nil {
				preDeprecatedHashes = append(preDeprecatedHashes, hashes...)
			}
		}
		if vk.TeamID != "" {
			teamSet[vk.TeamID] = struct{}{}
		}
	}

	actorID := "master_admin"
	if firstOp != nil && firstOp.ActorID != "" {
		actorID = firstOp.ActorID
	}
	patch := storage.VirtualKeyBulkPatch{
		IsActive:        req.IsActive,
		MaxBudgetMicros: req.MaxBudgetMicros,
		RPMLimit:        req.RPMLimit,
		TPMLimit:        req.TPMLimit,
		AllowedModels:   req.AllowedModels,
	}
	if req.IsActive != nil && !*req.IsActive {
		patch.RevokedBy = actorID
	}

	updatedKeys, err := govRepo.BulkUpdateVirtualKeys(r.Context(), targetOrg, normalizedIDs, patch)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		for _, h := range preDeprecatedHashes {
			if h != "" {
				s.authSvc.InvalidateKeyHash(r.Context(), h)
			}
		}
		for _, k := range updatedKeys {
			if k != nil {
				s.authSvc.InvalidateKeyID(r.Context(), k.ID)
			}
		}
		for tid := range teamSet {
			s.authSvc.InvalidateTeam(r.Context(), tid)
		}
	}
	s.auditWithDiff(r.Context(), targetOrg, "virtual_key.bulk_updated", "virtual_key", targetOrg, map[string]any{
		"key_ids":       normalizedIDs,
		"updated_count": len(updatedKeys),
	}, map[string]any{"keys": beforeKeys}, map[string]any{"patch": patch, "keys": updatedKeys, "updated_count": len(updatedKeys)})
	writeJSON(w, http.StatusOK, map[string]any{"data": updatedKeys, "updated": len(updatedKeys)})
}

func applyTeamMemberDefaults(team *domain.Team, m *domain.TeamMembership) {
	if team == nil || m == nil {
		return
	}
	if m.MaxBudgetMicros == 0 && team.DefaultMemberMaxBudgetMicros > 0 {
		m.MaxBudgetMicros = team.DefaultMemberMaxBudgetMicros
	}
	if m.RPMLimit == 0 && team.DefaultMemberRPMLimit > 0 {
		m.RPMLimit = team.DefaultMemberRPMLimit
	}
	if m.TPMLimit == 0 && team.DefaultMemberTPMLimit > 0 {
		m.TPMLimit = team.DefaultMemberTPMLimit
	}
	if len(m.AllowedModels) == 0 && len(team.DefaultMemberAllowedModels) > 0 {
		m.AllowedModels = slices.Clone(team.DefaultMemberAllowedModels)
	}
}

func (s *GatewayServer) handleAdminBulkTeamMembers(w http.ResponseWriter, r *http.Request) {
	teamID := strings.TrimSpace(chi.URLParam(r, "teamID"))
	pmRepo, ok := s.projectMembershipRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotImplemented, Type: domain.ErrorTypeServer, Code: "memberships_unsupported", Message: "Configured storage repository does not support team memberships"})
		return
	}
	team, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || team == nil {
		if _, authOK := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), teamID, true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "team_not_found", Message: "Team not found"})
		return
	}
	op, authOK := s.authorizeTeamAdmin(w, r, team.OrgID, team.ID, true)
	if !authOK {
		return
	}

	var req struct {
		OrgID         *string  `json:"org_id,omitempty"`
		RemoveUserIDs []string `json:"remove_user_ids,omitempty"`
		Members       []struct {
			UserID          string      `json:"user_id"`
			Role            domain.Role `json:"role,omitempty"`
			MaxBudgetMicros int64       `json:"max_budget_micros,omitempty"`
			RPMLimit        int         `json:"rpm_limit,omitempty"`
			TPMLimit        int         `json:"tpm_limit,omitempty"`
			AllowedModels   []string    `json:"allowed_models,omitempty"`
		} `json:"members,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if !verifyExplicitOrgMatch(w, r, team.OrgID, req.OrgID) {
		return
	}
	if len(req.Members) == 0 && len(req.RemoveUserIDs) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "missing_members", Message: "members or remove_user_ids must not be empty"})
		return
	}

	beforeMembers, _ := pmRepo.ListTeamMemberships(r.Context(), team.OrgID, team.ID, "")
	upserts := make([]*domain.TeamMembership, 0, len(req.Members))
	for _, entry := range req.Members {
		uid := strings.TrimSpace(entry.UserID)
		if uid == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "missing_user_id", Message: "every member entry requires user_id"})
			return
		}
		role := entry.Role
		if role == "" {
			role = domain.RoleDeveloper
		}
		if !isValidTenantRole(role) {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_role", Message: fmt.Sprintf("Unsupported role %q", role)})
			return
		}
		if role == domain.RolePlatformAdmin && op.Role != domain.OperatorRolePlatformAdmin {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypePermission, Code: "platform_admin_required", Message: "Only platform_admin can assign platform_admin role"})
			return
		}
		if op.Role == domain.OperatorRoleTeamAdmin && isPrivilegedOrgOrPlatformRole(role) {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypePermission, Code: "insufficient_permissions", Message: fmt.Sprintf("team_admin cannot assign organization-wide or platform role %q", role)})
			return
		}
		if entry.MaxBudgetMicros < 0 || entry.RPMLimit < 0 || entry.TPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_limits", Message: "member budgets and limits cannot be negative"})
			return
		}
		user, uErr := s.lookupUserByID(r.Context(), uid)
		if uErr != nil || user == nil || user.OrgID != team.OrgID {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_team_member", Message: fmt.Sprintf("User %q not found in team organization", uid)})
			return
		}
		m := &domain.TeamMembership{
			OrgID:           team.OrgID,
			TeamID:          team.ID,
			UserID:          uid,
			Role:            role,
			MaxBudgetMicros: entry.MaxBudgetMicros,
			RPMLimit:        entry.RPMLimit,
			TPMLimit:        entry.TPMLimit,
			AllowedModels:   entry.AllowedModels,
		}
		applyTeamMemberDefaults(team, m)
		upserts = append(upserts, m)
	}

	cleanedRemovals := make([]string, 0, len(req.RemoveUserIDs))
	for _, rawUID := range req.RemoveUserIDs {
		if uid := strings.TrimSpace(rawUID); uid != "" {
			cleanedRemovals = append(cleanedRemovals, uid)
		}
	}

	var results []*domain.TeamMembership
	var removed int
	if bulkRepo, ok := s.repo.(storage.TeamMembershipBulkSyncRepository); ok && bulkRepo != nil {
		results, removed, err = bulkRepo.BulkSyncTeamMemberships(r.Context(), team.OrgID, team.ID, upserts, cleanedRemovals)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	} else {
		results = make([]*domain.TeamMembership, 0, len(upserts))
		for _, m := range upserts {
			if err := pmRepo.UpsertTeamMembership(r.Context(), m); err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			results = append(results, m)
		}
		for _, uid := range cleanedRemovals {
			if delErr := pmRepo.DeleteTeamMembership(r.Context(), team.ID, uid); delErr == nil {
				removed++
			}
		}
	}

	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), team.ID)
	}
	afterMembers, _ := pmRepo.ListTeamMemberships(r.Context(), team.OrgID, team.ID, "")
	action := "team_membership.bulk_upserted"
	if removed > 0 {
		action = "team_membership.bulk_synced"
	}
	s.auditWithDiff(r.Context(), team.OrgID, action, "team", team.ID, map[string]any{
		"team_id": team.ID,
		"count":   len(results),
		"removed": removed,
	}, map[string]any{"memberships": beforeMembers}, map[string]any{"memberships": afterMembers})
	writeJSON(w, http.StatusOK, map[string]any{"data": results, "upserted": len(results), "removed": removed})
}

func (s *GatewayServer) handleAdminResetTeamMemberSpend(w http.ResponseWriter, r *http.Request) {
	teamID := strings.TrimSpace(chi.URLParam(r, "teamID"))
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	team, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || team == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), teamID, true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "team_not_found", Message: "Team not found"})
		return
	}
	if _, ok := s.authorizeTeamAdmin(w, r, team.OrgID, team.ID, true); !ok {
		return
	}
	govRepo, ok := s.keyGovernanceRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotImplemented, Type: domain.ErrorTypeServer, Code: "governance_unsupported", Message: "Configured storage repository does not support team member spend reset"})
		return
	}
	if err := govRepo.ResetEntitySpend(r.Context(), storage.EntitySpendScopeTeamMember, team.OrgID, team.ID, userID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.limiter != nil {
		_ = s.limiter.ClearEntitySpend(r.Context(), storage.EntitySpendScopeTeamMember, team.OrgID, team.ID, userID)
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), team.ID)
	}
	s.auditWithDiff(r.Context(), team.OrgID, "team_membership.spend_reset", "team_membership", team.ID+":"+userID, map[string]any{
		"team_id": team.ID,
		"user_id": userID,
	}, nil, map[string]any{"spent_micros": 0})
	writeJSON(w, http.StatusOK, map[string]any{"status": "reset", "team_id": team.ID, "user_id": userID, "spent_micros": 0})
}

func (s *GatewayServer) handleAdminRotateKEK(w http.ResponseWriter, r *http.Request) {
	op, ok := s.authorizeAdmin(w, r, "", true)
	if !ok {
		return
	}
	if op.Role != domain.OperatorRolePlatformAdmin {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "platform_admin_required",
			Message:    "Only platform_admin can rotate the master key encryption key (KEK)",
		})
		return
	}
	if s.vault == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "vault_unavailable", Message: "Encryption vault is not initialized"})
		return
	}

	var req struct {
		NewMasterKey string `json:"new_master_key"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	newVault, err := auth.NewVault(req.NewMasterKey)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_master_key", Message: err.Error()})
		return
	}

	var rotSummary storage.KEKRotationSummary
	if txRepo, ok := s.repo.(storage.KEKRotationRepository); ok && txRepo != nil {
		var txErr error
		rotSummary, txErr = txRepo.RotateKEKsTransactionally(r.Context(), func(batch storage.KEKRotationBatch) (storage.KEKRotationBatch, error) {
			var out storage.KEKRotationBatch
			for _, cred := range batch.Credentials {
				if cred == nil || len(cred.EncryptedDEK) == 0 {
					continue
				}
				rotated, rErr := s.vault.ReWrapCredential(cred, newVault)
				if rErr != nil {
					return out, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap credential %s: %v", cred.ID, rErr)}
				}
				out.Credentials = append(out.Credentials, rotated)
			}
			for _, srv := range batch.MCPServers {
				if srv == nil || strings.TrimSpace(srv.EncryptedAuthDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(srv.EncryptedAuthDEK, newVault)
				if rErr != nil {
					return out, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap MCP server %s DEK: %v", srv.ID, rErr)}
				}
				cp := *srv
				cp.EncryptedAuthDEK = newDEK
				out.MCPServers = append(out.MCPServers, &cp)
			}
			for _, ag := range batch.A2AAgents {
				if ag == nil || strings.TrimSpace(ag.EncryptedAuthDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(ag.EncryptedAuthDEK, newVault)
				if rErr != nil {
					return out, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap A2A agent %s DEK: %v", ag.ID, rErr)}
				}
				cp := *ag
				cp.EncryptedAuthDEK = newDEK
				out.A2AAgents = append(out.A2AAgents, &cp)
			}
			for _, pc := range batch.A2APushConfigs {
				if pc == nil || strings.TrimSpace(pc.EncryptedAuthDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(pc.EncryptedAuthDEK, newVault)
				if rErr != nil {
					return out, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap A2A push config %s DEK: %v", pc.ID, rErr)}
				}
				cp := *pc
				cp.EncryptedAuthDEK = newDEK
				out.A2APushConfigs = append(out.A2APushConfigs, &cp)
			}
			for _, gd := range batch.Guardrails {
				if gd == nil || strings.TrimSpace(gd.EncryptedDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(gd.EncryptedDEK, newVault)
				if rErr != nil {
					return out, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap guardrail definition %s DEK: %v", gd.ID, rErr)}
				}
				cp := *gd
				cp.EncryptedDEK = newDEK
				out.Guardrails = append(out.Guardrails, &cp)
			}
			for _, vk := range batch.StagedVirtualKeys {
				if vk == nil || strings.TrimSpace(vk.StagedKeyDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(vk.StagedKeyDEK, newVault)
				if rErr != nil {
					return out, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap virtual key %s staged DEK: %v", vk.ID, rErr)}
				}
				cp := *vk
				cp.StagedKeyDEK = newDEK
				out.StagedVirtualKeys = append(out.StagedVirtualKeys, &cp)
			}
			return out, nil
		})
		if txErr != nil {
			domain.WriteHTTPError(w, txErr)
			return
		}
	} else {
		orgs, err := s.repo.ListOrganizations(r.Context())
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		for _, org := range orgs {
			if org == nil {
				continue
			}
			creds, _ := s.repo.ListProviderCredentials(r.Context(), org.ID)
			for _, cred := range creds {
				if cred == nil || len(cred.EncryptedDEK) == 0 {
					continue
				}
				rotated, rErr := s.vault.ReWrapCredential(cred, newVault)
				if rErr != nil {
					domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap credential %s: %v", cred.ID, rErr)})
					return
				}
				if uErr := s.repo.UpdateProviderCredential(r.Context(), rotated); uErr != nil {
					domain.WriteHTTPError(w, uErr)
					return
				}
				rotSummary.CredentialsRewrapped++
			}
			servers, _ := s.repo.ListMCPServers(r.Context(), org.ID)
			for _, srv := range servers {
				if srv == nil || strings.TrimSpace(srv.EncryptedAuthDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(srv.EncryptedAuthDEK, newVault)
				if rErr != nil {
					domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap MCP server %s DEK: %v", srv.ID, rErr)})
					return
				}
				cp := *srv
				cp.EncryptedAuthDEK = newDEK
				if uErr := s.repo.UpdateMCPServer(r.Context(), &cp); uErr != nil {
					domain.WriteHTTPError(w, uErr)
					return
				}
				rotSummary.MCPServersRewrapped++
			}
			agents, _ := s.repo.ListA2AAgents(r.Context(), org.ID)
			for _, ag := range agents {
				if ag == nil || strings.TrimSpace(ag.EncryptedAuthDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(ag.EncryptedAuthDEK, newVault)
				if rErr != nil {
					domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap A2A agent %s DEK: %v", ag.ID, rErr)})
					return
				}
				cp := *ag
				cp.EncryptedAuthDEK = newDEK
				if uErr := s.repo.UpdateA2AAgent(r.Context(), &cp); uErr != nil {
					domain.WriteHTTPError(w, uErr)
					return
				}
				rotSummary.A2AAgentsRewrapped++
			}
			a2aTasks, _, _ := s.repo.ListA2ATasks(r.Context(), domain.A2ATaskListFilter{
				OrgID: org.ID,
				Limit: 10000,
			})
			for _, t := range a2aTasks {
				if t == nil {
					continue
				}
				pushCfgs, _, _ := s.repo.ListA2APushNotificationConfigs(r.Context(), t.ID, 1000, 0)
				for _, pc := range pushCfgs {
					if pc == nil || strings.TrimSpace(pc.EncryptedAuthDEK) == "" {
						continue
					}
					newDEK, rErr := s.vault.ReWrapString(pc.EncryptedAuthDEK, newVault)
					if rErr != nil {
						domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap A2A push config %s DEK: %v", pc.ID, rErr)})
						return
					}
					cp := *pc
					cp.EncryptedAuthDEK = newDEK
					if uErr := s.repo.SetA2APushNotificationConfig(r.Context(), &cp); uErr != nil {
						domain.WriteHTTPError(w, uErr)
						return
					}
					rotSummary.A2APushConfigsRewrapped++
				}
			}
			grDefs, _ := s.repo.ListGuardrailDefinitions(r.Context(), org.ID, "", "")
			for _, gd := range grDefs {
				if gd == nil || strings.TrimSpace(gd.EncryptedDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(gd.EncryptedDEK, newVault)
				if rErr != nil {
					domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap guardrail definition %s DEK: %v", gd.ID, rErr)})
					return
				}
				cp := *gd
				cp.EncryptedDEK = newDEK
				if uErr := s.repo.UpdateGuardrailDefinition(r.Context(), &cp); uErr != nil {
					domain.WriteHTTPError(w, uErr)
					return
				}
				rotSummary.GuardrailsRewrapped++
			}
			vks, _ := s.repo.ListVirtualKeys(r.Context(), org.ID)
			for _, vk := range vks {
				if vk == nil || strings.TrimSpace(vk.StagedKeyDEK) == "" {
					continue
				}
				newDEK, rErr := s.vault.ReWrapString(vk.StagedKeyDEK, newVault)
				if rErr != nil {
					domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_rewrap_failed", Message: fmt.Sprintf("re-wrap virtual key %s staged DEK: %v", vk.ID, rErr)})
					return
				}
				cp := *vk
				cp.StagedKeyDEK = newDEK
				if uErr := s.repo.UpdateVirtualKey(r.Context(), &cp); uErr != nil {
					domain.WriteHTTPError(w, uErr)
					return
				}
				rotSummary.StagedVirtualKeysRewrapped++
			}
		}
	}

	if err := s.vault.PromoteKEK(newVault); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "kek_promote_failed", Message: err.Error()})
		return
	}

	podID := ""
	if s.keyRotation != nil {
		podID = s.keyRotation.PodID()
	}
	if s.redisFabric != nil {
		s.redisFabric.PublishInvalidation(r.Context(), storage.InvalidationEvent{
			Type:     "vault_kek_rotated",
			EntityID: podID,
		})
	}

	summary := map[string]any{
		"credentials_rewrapped":         rotSummary.CredentialsRewrapped,
		"mcp_servers_rewrapped":         rotSummary.MCPServersRewrapped,
		"a2a_agents_rewrapped":          rotSummary.A2AAgentsRewrapped,
		"a2a_push_configs_rewrapped":    rotSummary.A2APushConfigsRewrapped,
		"guardrails_rewrapped":          rotSummary.GuardrailsRewrapped,
		"staged_virtual_keys_rewrapped": rotSummary.StagedVirtualKeysRewrapped,
		"source_pod":                    podID,
	}
	s.auditWithDiff(r.Context(), "", "security.kek_rotated", "vault", "master_kek", summary, nil, summary)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "rotated",
		"rewrapped":        summary,
		"multi_pod_notice": "Database DEKs rotated atomically and promoted locally; update master_encryption_key across peer gateway instances before restarting them.",
	})
}

// --- Governed Developer Self-Service Key Endpoints (/v1/self/keys) ---

func (s *GatewayServer) requireSelfServiceOrgEnabled(w http.ResponseWriter, r *http.Request) (*domain.User, *domain.Organization, bool) {
	user := auth.SelfServiceUserFromContext(r.Context())
	if user == nil || user.ID == "" || user.OrgID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "user_identity_required",
			Message:    "Authenticated user identity is required",
		})
		return nil, nil, false
	}
	org, err := s.repo.GetOrganization(r.Context(), user.OrgID)
	if err != nil || org == nil || !org.IsActive {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Organization not found or inactive",
		})
		return nil, nil, false
	}
	if !org.DeveloperSelfServeKeys {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "self_service_disabled",
			Message:    "Developer self-service key management is disabled for your organization",
		})
		return nil, nil, false
	}
	return user, org, true
}

func teamAllowsSelfServicePerm(team *domain.Team, perm string) bool {
	if team == nil || len(team.TeamMemberPermissions) == 0 {
		return true
	}
	for _, raw := range team.TeamMemberPermissions {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "none" || p == "keys:none" {
			return false
		}
		if p == "*" || p == "keys:*" || p == strings.ToLower(perm) {
			return true
		}
	}
	return false
}

func (s *GatewayServer) authorizeSelfServiceTeamPermission(ctx context.Context, w http.ResponseWriter, teamID, perm string) bool {
	if s == nil || s.repo == nil || strings.TrimSpace(teamID) == "" {
		return true
	}
	team, err := s.repo.GetTeam(ctx, teamID)
	if err != nil || team == nil {
		return true
	}
	if teamAllowsSelfServicePerm(team, perm) {
		return true
	}
	domain.WriteHTTPError(w, &domain.GatewayError{
		StatusCode: http.StatusForbidden,
		Type:       domain.ErrorTypePermission,
		Code:       "team_permission_denied",
		Message:    fmt.Sprintf("Team %q restricts self-service operation %q", team.ID, perm),
	})
	return false
}

func (s *GatewayServer) handleSelfListKeys(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.requireSelfServiceOrgEnabled(w, r)
	if !ok {
		return
	}
	keys, err := s.repo.ListVirtualKeys(r.Context(), user.OrgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	teamAllowed := make(map[string]bool)
	owned := make([]*domain.VirtualKey, 0)
	for _, k := range keys {
		if k != nil && k.UserID == user.ID {
			if k.TeamID != "" {
				allowed, seen := teamAllowed[k.TeamID]
				if !seen {
					team, tErr := s.repo.GetTeam(r.Context(), k.TeamID)
					allowed = tErr != nil || teamAllowsSelfServicePerm(team, "keys:read")
					teamAllowed[k.TeamID] = allowed
				}
				if !allowed {
					continue
				}
			}
			cp := *k
			cp.RawKey = ""
			cp.KeyHash = ""
			owned = append(owned, &cp)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": owned})
}

func (s *GatewayServer) handleSelfCreateKey(w http.ResponseWriter, r *http.Request) {
	user, org, ok := s.requireSelfServiceOrgEnabled(w, r)
	if !ok {
		return
	}
	var req struct {
		Name                string            `json:"name"`
		TeamID              string            `json:"team_id,omitempty"`
		KeyType             domain.KeyType    `json:"key_type,omitempty"`
		AllowedModels       []string          `json:"allowed_models,omitempty"`
		AllowedEndpoints    []string          `json:"allowed_endpoints,omitempty"`
		MaxBudgetMicros     int64             `json:"max_budget_micros,omitempty"`
		SoftBudgetMicros    int64             `json:"soft_budget_micros,omitempty"`
		RPMLimit            int               `json:"rpm_limit,omitempty"`
		TPMLimit            int               `json:"tpm_limit,omitempty"`
		RotationIntervalSec int64             `json:"rotation_interval_sec,omitempty"`
		ExpiresAt           *time.Time        `json:"expires_at,omitempty"`
		Tags                []string          `json:"tags,omitempty"`
		Metadata            map[string]string `json:"metadata,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_key_name", Message: "Key name is required"})
		return
	}
	if req.MaxBudgetMicros < 0 || req.SoftBudgetMicros < 0 || req.RPMLimit < 0 || req.TPMLimit < 0 || req.RotationIntervalSec < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_limits", Message: "Budgets, rate limits, and rotation interval cannot be negative"})
		return
	}
	keyType := req.KeyType
	if keyType == "" {
		keyType = domain.KeyTypeLLMAPI
	}
	if keyType != domain.KeyTypeLLMAPI && keyType != domain.KeyTypeReadOnly {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "key_type_not_allowed",
			Message:    "Self-service keys only permit key_type \"llm_api\" or \"read_only\"",
		})
		return
	}
	if hasDisallowedTeamAdminEndpoint(req.AllowedEndpoints) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    "Self-service keys cannot specify wildcard, /admin, or /scim allowed_endpoints",
		})
		return
	}

	teamID := strings.TrimSpace(req.TeamID)
	if teamID == "" {
		teamID = user.TeamID
	}
	if teamID != "" && !s.userBelongsToTeam(r.Context(), user.OrgID, teamID, user.ID) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_team_access_denied",
			Message:    "Self-service key cannot be bound to a team you do not belong to",
		})
		return
	}
	if teamID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "team_membership_required",
			Message:    "Self-service keys must belong to one of your active teams",
		})
		return
	}
	if !s.authorizeSelfServiceTeamPermission(r.Context(), w, teamID, "keys:create") {
		return
	}

	if org.SelfServeBudgetPolicy == domain.SelfServeBudgetDisabled {
		if req.MaxBudgetMicros != 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "self_serve_budget_disabled",
				Message:    "Self-service budget override is disabled by your organization",
			})
			return
		}
	} else if op := auth.OperatorFromContext(r.Context()); op != nil && req.MaxBudgetMicros > 0 {
		if !s.enforceSelfServeBudgetPolicy(r.Context(), w, op, user.OrgID, teamID, 0, req.MaxBudgetMicros) {
			return
		}
	}
	if !s.enforceGuaranteedThroughput(r.Context(), w, user.OrgID, teamID, "", req.RPMLimit, req.TPMLimit) {
		return
	}

	// Self-service keys strictly lock role to developer (or user's non-admin role) and forbid impersonation.
	lockedRole := user.Role
	if isPrivilegedOrgOrPlatformRole(lockedRole) {
		lockedRole = domain.RoleDeveloper
	}

	vk, err := s.authSvc.IssueVirtualKey(r.Context(), &domain.VirtualKey{
		OrgID:               user.OrgID,
		TeamID:              teamID,
		UserID:              user.ID,
		Name:                name,
		Role:                lockedRole,
		KeyType:             keyType,
		AllowedModels:       req.AllowedModels,
		AllowedEndpoints:    req.AllowedEndpoints,
		MaxBudgetMicros:     req.MaxBudgetMicros,
		SoftBudgetMicros:    req.SoftBudgetMicros,
		RPMLimit:            req.RPMLimit,
		TPMLimit:            req.TPMLimit,
		RotationIntervalSec: req.RotationIntervalSec,
		ExpiresAt:           req.ExpiresAt,
		CanImpersonate:      false,
		Tags:                req.Tags,
		Metadata:            req.Metadata,
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), vk.OrgID, "virtual_key.self_service_issued", "virtual_key", vk.ID, map[string]any{
		"user_id":  user.ID,
		"team_id":  teamID,
		"key_type": vk.KeyType,
	}, nil, vk)
	writeJSON(w, http.StatusCreated, vk)
}

func (s *GatewayServer) handleSelfRevokeKey(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.requireSelfServiceOrgEnabled(w, r)
	if !ok {
		return
	}
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	vk, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || vk == nil || vk.OrgID != user.OrgID || vk.UserID != user.ID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "virtual_key_not_found",
			Message:    "Self-service virtual key not found",
		})
		return
	}
	if !s.authorizeSelfServiceTeamPermission(r.Context(), w, vk.TeamID, "keys:revoke") {
		return
	}
	if err := s.authSvc.RevokeKeyWithActor(r.Context(), keyID, user.ID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	after, _ := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	s.auditWithDiff(r.Context(), vk.OrgID, "virtual_key.self_service_revoked", "virtual_key", keyID, map[string]any{"user_id": user.ID}, vk, after)
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "id": keyID})
}

func (s *GatewayServer) handleSelfRotateKey(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.requireSelfServiceOrgEnabled(w, r)
	if !ok {
		return
	}
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	vk, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || vk == nil || vk.OrgID != user.OrgID || vk.UserID != user.ID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "virtual_key_not_found",
			Message:    "Self-service virtual key not found",
		})
		return
	}
	if !s.authorizeSelfServiceTeamPermission(r.Context(), w, vk.TeamID, "keys:rotate") {
		return
	}
	var req struct {
		GracePeriodSec int64 `json:"grace_period_sec,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		_ = decodeAdminJSON(w, r, &req)
	}
	grace := time.Duration(req.GracePeriodSec) * time.Second
	if grace < 0 {
		grace = 0
	}
	rotated, err := s.authSvc.RotateVirtualKeyWithGrace(r.Context(), keyID, grace)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), vk.OrgID, "virtual_key.self_service_rotated", "virtual_key", keyID, map[string]any{"user_id": user.ID}, vk, rotated)
	writeJSON(w, http.StatusOK, rotated)
}

func parseNonNegativeIntQuery(r *http.Request, name string) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}
