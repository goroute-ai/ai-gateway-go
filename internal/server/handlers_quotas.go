package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func normalizeQuotaScopeType(raw domain.QuotaScopeType) domain.QuotaScopeType {
	norm := domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(raw))))
	switch norm {
	case "virtual_key":
		return domain.QuotaScopeKey
	case "model_per_virtual_key":
		return domain.QuotaScopeModelPerKey
	default:
		return norm
	}
}

func (s *GatewayServer) quotaPolicyRepo() (storage.QuotaPolicyRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	qRepo, ok := s.repo.(storage.QuotaPolicyRepository)
	return qRepo, ok && qRepo != nil
}

func (s *GatewayServer) budgetWindowRepo() (storage.BudgetWindowRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	bwRepo, ok := s.repo.(storage.BudgetWindowRepository)
	return bwRepo, ok && bwRepo != nil
}

func (s *GatewayServer) tempBudgetRepo() (storage.TempBudgetRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	tbRepo, ok := s.repo.(storage.TempBudgetRepository)
	return tbRepo, ok && tbRepo != nil
}

// handleAdminUpsertQuotaPolicy handles `PUT /admin/v1/quotas`.
func (s *GatewayServer) handleAdminUpsertQuotaPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                        string                   `json:"id,omitempty"`
		OrgID                     string                   `json:"org_id"`
		ScopeType                 domain.QuotaScopeType    `json:"scope_type"`
		ScopeID                   string                   `json:"scope_id"`
		ModelPattern              string                   `json:"model_pattern,omitempty"`
		RPMLimit                  int                      `json:"rpm_limit,omitempty"`
		RPDLimit                  int64                    `json:"rpd_limit,omitempty"`
		TPMLimit                  int                      `json:"tpm_limit,omitempty"`
		ITPMLimit                 int                      `json:"itpm_limit,omitempty"`
		OTPMLimit                 int                      `json:"otpm_limit,omitempty"`
		TPDLimit                  int64                    `json:"tpd_limit,omitempty"`
		MaxConcurrent             int                      `json:"max_concurrent,omitempty"`
		MaxBudgetMicros           int64                    `json:"max_budget_micros,omitempty"`
		MaxBudgetPerSessionMicros int64                    `json:"max_budget_per_session_micros,omitempty"`
		BudgetResetPeriod         domain.BudgetResetPeriod `json:"budget_reset_period,omitempty"`
		BudgetResetAt             *time.Time               `json:"budget_reset_at,omitempty"`
		MaxIterations             int                      `json:"max_iterations,omitempty"`
		WindowTTLSec              int                      `json:"window_ttl_sec,omitempty"`
		IsActive                  *bool                    `json:"is_active,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    err.Error(),
		})
		return
	}

	req.OrgID = resolveScopedOrgID(r, req.OrgID)
	if _, ok := s.authorizeAdmin(w, r, req.OrgID, true); !ok {
		return
	}

	qRepo, ok := s.quotaPolicyRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "quota_policies_unsupported",
			Message:    "Configured storage repository does not support quota policies",
		})
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	maxBudget := req.MaxBudgetMicros
	if maxBudget == 0 && req.MaxBudgetPerSessionMicros != 0 {
		maxBudget = req.MaxBudgetPerSessionMicros
	}
	if req.RPDLimit < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_quota_policy",
			Message:    "rpd_limit must be non-negative",
		})
		return
	}
	policy := &domain.QuotaPolicy{
		ID:                strings.TrimSpace(req.ID),
		OrgID:             req.OrgID,
		ScopeType:         normalizeQuotaScopeType(req.ScopeType),
		ScopeID:           req.ScopeID,
		ModelPattern:      req.ModelPattern,
		RPMLimit:          req.RPMLimit,
		RPDLimit:          req.RPDLimit,
		TPMLimit:          req.TPMLimit,
		ITPMLimit:         req.ITPMLimit,
		OTPMLimit:         req.OTPMLimit,
		TPDLimit:          req.TPDLimit,
		MaxConcurrent:     req.MaxConcurrent,
		MaxBudgetMicros:   maxBudget,
		BudgetResetPeriod: req.BudgetResetPeriod,
		BudgetResetAt:     req.BudgetResetAt,
		MaxIterations:     req.MaxIterations,
		WindowTTLSec:      req.WindowTTLSec,
		IsActive:          isActive,
	}
	if err := qRepo.UpsertQuotaPolicy(r.Context(), policy); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "quota_policy_conflict",
				Message:    err.Error(),
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_quota_policy",
			Message:    err.Error(),
		})
		return
	}

	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_quotas", policy.OrgID)
	}
	s.auditWithDiff(r.Context(), policy.OrgID, "quota_policy.upserted", "quota_policy", policy.ID, map[string]any{
		"scope_type":    policy.ScopeType,
		"scope_id":      policy.ScopeID,
		"model_pattern": policy.ModelPattern,
		"is_active":     policy.IsActive,
	}, nil, policy)
	writeJSON(w, http.StatusOK, policy)
}

// handleAdminListQuotaPolicies handles `GET /admin/v1/quotas`.
func (s *GatewayServer) handleAdminListQuotaPolicies(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	qRepo, ok := s.quotaPolicyRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "quota_policies_unsupported",
			Message:    "Configured storage repository does not support quota policies",
		})
		return
	}

	var scopeType domain.QuotaScopeType
	if rawScope := strings.TrimSpace(r.URL.Query().Get("scope_type")); rawScope != "" {
		scopeType = normalizeQuotaScopeType(domain.QuotaScopeType(rawScope))
		if !scopeType.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_scope_type",
				Message:    "Unsupported quota scope_type",
			})
			return
		}
	}

	activeOnly := false
	if rawActive := strings.TrimSpace(r.URL.Query().Get("active_only")); rawActive != "" {
		parsed, err := strconv.ParseBool(rawActive)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_active_only",
				Message:    "active_only must be a boolean",
			})
			return
		}
		activeOnly = parsed
	}

	list, err := qRepo.ListQuotaPolicies(r.Context(), storage.QuotaPolicyFilter{
		OrgID:        orgID,
		ScopeType:    scopeType,
		ScopeID:      strings.TrimSpace(r.URL.Query().Get("scope_id")),
		ModelPattern: strings.TrimSpace(r.URL.Query().Get("model_pattern")),
		ActiveOnly:   activeOnly,
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if list == nil {
		list = []*domain.QuotaPolicy{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list})
}

// handleAdminDeleteQuotaPolicy handles `DELETE /admin/v1/quotas/{policyID}`.
func (s *GatewayServer) handleAdminDeleteQuotaPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	policyID := strings.TrimSpace(chi.URLParam(r, "policyID"))
	if policyID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_policy_id",
			Message:    "policyID is required",
		})
		return
	}

	qRepo, ok := s.quotaPolicyRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "quota_policies_unsupported",
			Message:    "Configured storage repository does not support quota policies",
		})
		return
	}

	existing, err := qRepo.GetQuotaPolicy(r.Context(), policyID)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "quota_policy_not_found",
			Message:    "Quota policy not found",
		})
		return
	}

	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, true); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}

	if err := qRepo.DeleteQuotaPolicy(r.Context(), policyID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_quotas", existing.OrgID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "quota_policy.deleted", "quota_policy", policyID, map[string]any{
		"scope_type":    existing.ScopeType,
		"scope_id":      existing.ScopeID,
		"model_pattern": existing.ModelPattern,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": policyID})
}

// handleAdminUpsertBudgetWindow handles `PUT /admin/v1/budget-windows`.
func (s *GatewayServer) handleAdminUpsertBudgetWindow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID              string                  `json:"id,omitempty"`
		OrgID           string                  `json:"org_id"`
		ScopeType       domain.QuotaScopeType   `json:"scope_type"`
		ScopeID         string                  `json:"scope_id"`
		WindowType      domain.BudgetWindowType `json:"window_type"`
		MaxBudgetMicros int64                   `json:"max_budget_micros"`
		WindowResetAt   *time.Time              `json:"window_reset_at,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    err.Error(),
		})
		return
	}

	req.OrgID = resolveScopedOrgID(r, req.OrgID)
	if _, ok := s.authorizeAdmin(w, r, req.OrgID, true); !ok {
		return
	}

	bwRepo, ok := s.budgetWindowRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "budget_windows_unsupported",
			Message:    "Configured storage repository does not support budget windows",
		})
		return
	}

	limit := &domain.BudgetWindowLimit{
		ID:              strings.TrimSpace(req.ID),
		OrgID:           req.OrgID,
		ScopeType:       normalizeQuotaScopeType(req.ScopeType),
		ScopeID:         req.ScopeID,
		WindowType:      req.WindowType,
		MaxBudgetMicros: req.MaxBudgetMicros,
	}
	if req.WindowResetAt != nil {
		limit.WindowResetAt = req.WindowResetAt.UTC()
	}

	if err := bwRepo.UpsertBudgetWindowLimit(r.Context(), limit); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "budget_window_conflict",
				Message:    err.Error(),
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_budget_window",
			Message:    err.Error(),
		})
		return
	}

	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_bw", limit.OrgID)
	}
	s.auditWithDiff(r.Context(), limit.OrgID, "budget_window.upserted", "budget_window", limit.ID, map[string]any{
		"scope_type":        limit.ScopeType,
		"scope_id":          limit.ScopeID,
		"window_type":       limit.WindowType,
		"max_budget_micros": limit.MaxBudgetMicros,
	}, nil, limit)
	writeJSON(w, http.StatusOK, limit)
}

// handleAdminListBudgetWindows handles `GET /admin/v1/budget-windows`.
func (s *GatewayServer) handleAdminListBudgetWindows(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	bwRepo, ok := s.budgetWindowRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "budget_windows_unsupported",
			Message:    "Configured storage repository does not support budget windows",
		})
		return
	}

	var scopeType domain.QuotaScopeType
	if rawScope := strings.TrimSpace(r.URL.Query().Get("scope_type")); rawScope != "" {
		scopeType = normalizeQuotaScopeType(domain.QuotaScopeType(rawScope))
		if !scopeType.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_scope_type",
				Message:    "Unsupported budget window scope_type",
			})
			return
		}
	}

	var windowType domain.BudgetWindowType
	if rawWindow := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("window_type"))); rawWindow != "" {
		windowType = domain.BudgetWindowType(rawWindow)
		if !windowType.IsValid() {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_window_type",
				Message:    "window_type must be daily, weekly, monthly, or rolling_24h",
			})
			return
		}
	}

	list, err := bwRepo.ListBudgetWindowLimits(r.Context(), storage.BudgetWindowFilter{
		OrgID:      orgID,
		ScopeType:  scopeType,
		ScopeID:    strings.TrimSpace(r.URL.Query().Get("scope_id")),
		WindowType: windowType,
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if list == nil {
		list = []*domain.BudgetWindowLimit{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list})
}

// handleAdminSetKeyTempBudget handles `POST /admin/v1/keys/{keyID}/temp-budget`.
func (s *GatewayServer) handleAdminSetKeyTempBudget(w http.ResponseWriter, r *http.Request) {
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	if keyID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_key_id",
			Message:    "keyID is required",
		})
		return
	}

	existing, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
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

	op, ok := s.authorizeAdmin(w, r, existing.OrgID, true)
	if !ok {
		return
	}
	if !ensureOperatorCanMutateTargetRole(w, op, existing.Role, "virtual key") {
		return
	}

	var req struct {
		OrgID                    *string    `json:"org_id,omitempty"`
		TempBudgetIncreaseMicros *int64     `json:"temp_budget_increase_micros,omitempty"`
		IncreaseMicros           *int64     `json:"increase_micros,omitempty"`
		TempBudgetExpiresAt      *time.Time `json:"temp_budget_expires_at,omitempty"`
		ExpiresAt                *time.Time `json:"expires_at,omitempty"`
		TTLSeconds               *int64     `json:"ttl_seconds,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    err.Error(),
		})
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, req.OrgID) {
		return
	}

	var increaseMicros int64
	switch {
	case req.TempBudgetIncreaseMicros != nil:
		increaseMicros = *req.TempBudgetIncreaseMicros
	case req.IncreaseMicros != nil:
		increaseMicros = *req.IncreaseMicros
	default:
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_temp_budget_increase",
			Message:    "temp_budget_increase_micros is required",
		})
		return
	}
	if increaseMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_temp_budget",
			Message:    "temp_budget_increase_micros cannot be negative",
		})
		return
	}

	now := time.Now().UTC()
	var expiresAt *time.Time
	switch {
	case req.TempBudgetExpiresAt != nil:
		t := req.TempBudgetExpiresAt.UTC()
		expiresAt = &t
	case req.ExpiresAt != nil:
		t := req.ExpiresAt.UTC()
		expiresAt = &t
	case req.TTLSeconds != nil:
		if *req.TTLSeconds <= 0 && increaseMicros > 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_temp_budget_expiry",
				Message:    "ttl_seconds must be positive",
			})
			return
		}
		if *req.TTLSeconds > 0 {
			t := now.Add(time.Duration(*req.TTLSeconds) * time.Second)
			expiresAt = &t
		}
	}

	if increaseMicros == 0 {
		expiresAt = nil
	} else {
		if expiresAt == nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "missing_temp_budget_expiry",
				Message:    "temp_budget_expires_at or positive ttl_seconds is required when temp_budget_increase_micros > 0",
			})
			return
		}
		if !expiresAt.After(now) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_temp_budget_expiry",
				Message:    "temp_budget_expires_at must be in the future",
			})
			return
		}
	}

	if tbRepo, ok := s.tempBudgetRepo(); ok {
		if err := tbRepo.SetTempBudgetBoost(r.Context(), domain.QuotaScopeKey, existing.ID, increaseMicros, expiresAt); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	} else {
		updated := *existing
		updated.TempBudgetIncreaseMicros = increaseMicros
		updated.TempBudgetExpiresAt = expiresAt
		if err := s.repo.UpdateVirtualKey(r.Context(), &updated); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	}

	if s.authSvc != nil {
		s.authSvc.InvalidateKeyID(r.Context(), existing.ID)
	}

	saved, err := s.repo.GetVirtualKeyByID(r.Context(), existing.ID)
	if err != nil || saved == nil {
		saved = existing
		saved.TempBudgetIncreaseMicros = increaseMicros
		saved.TempBudgetExpiresAt = expiresAt
	}

	s.auditWithDiff(r.Context(), existing.OrgID, "virtual_key.temp_budget_updated", "virtual_key", existing.ID, map[string]any{
		"temp_budget_increase_micros": increaseMicros,
		"temp_budget_expires_at":      expiresAt,
	}, existing, saved)
	writeJSON(w, http.StatusOK, saved)
}
