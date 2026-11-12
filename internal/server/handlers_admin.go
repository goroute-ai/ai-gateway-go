package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *GatewayServer) audit(ctx context.Context, orgID, action, resource, resourceID string, details map[string]any) {
	_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:      orgID,
		ActorID:    "admin",
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
	})
}

// --- Organizations, Layer 2 Subscriptions, Layer 3 Model Policies & Security Guardrails ---

func (s *GatewayServer) handleAdminCreateOrg(w http.ResponseWriter, r *http.Request) {
	var org domain.Organization
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	org.IsActive = true
	if org.BudgetResetPeriod == "" {
		org.BudgetResetPeriod = domain.BudgetResetMonthly
	}
	if err := s.repo.CreateOrganization(r.Context(), &org); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), org.ID, "organization.created", "organization", org.ID, map[string]any{"name": org.Name})
	writeJSON(w, http.StatusCreated, org)
}

func (s *GatewayServer) handleAdminListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.repo.ListOrganizations(r.Context())
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": orgs})
}

func (s *GatewayServer) handleAdminSetOrgSubscription(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	var sub domain.OrgProviderSubscription
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	sub.OrgID = orgID
	if err := s.repo.SetOrgProviderSubscription(r.Context(), &sub); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), orgID, "organization.subscription.updated", "org_provider_subscription", string(sub.Provider), map[string]any{
		"provider":        sub.Provider,
		"is_enabled":      sub.IsEnabled,
		"auto_enable_new": sub.AutoEnableNew,
	})
	writeJSON(w, http.StatusOK, sub)
}

func (s *GatewayServer) handleAdminGetOrgSubscriptions(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	subs, err := s.repo.GetOrgProviderSubscriptions(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": subs})
}

func (s *GatewayServer) handleAdminSetOrgModelPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	var pol domain.OrgModelPolicy
	if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	pol.OrgID = orgID
	if err := s.repo.SetOrgModelPolicy(r.Context(), &pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), orgID, "organization.model_policy.updated", "org_model_policy", pol.GlobalModelID, map[string]any{
		"global_model_id": pol.GlobalModelID,
		"is_enabled":      pol.IsEnabled,
	})
	writeJSON(w, http.StatusOK, pol)
}

func (s *GatewayServer) handleAdminGetOrgModelPolicies(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	pols, err := s.repo.GetOrgModelPolicies(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": pols})
}

func (s *GatewayServer) handleAdminSetGuardrailPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	var pol domain.GuardrailPolicy
	if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	pol.OrgID = orgID
	if err := s.repo.SetGuardrailPolicy(r.Context(), &pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), orgID, "organization.guardrails.updated", "guardrail_policy", orgID, map[string]any{
		"enable_prompt_injection": pol.EnablePromptInjection,
		"prompt_injection_action": pol.PromptInjectionAction,
		"enable_pii_detection":    pol.EnablePIIDetection,
		"pii_action":              pol.PIIAction,
		"enable_secret_detection": pol.EnableSecretDetection,
		"secret_action":           pol.SecretAction,
		"redact_output_pii":       pol.RedactOutputPII,
	})
	writeJSON(w, http.StatusOK, pol)
}

func (s *GatewayServer) handleAdminGetGuardrailPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	pol, err := s.repo.GetGuardrailPolicy(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{OrgID: orgID}
	}
	writeJSON(w, http.StatusOK, pol)
}

func (s *GatewayServer) handleAdminSimulateGuardrails(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	var req struct {
		Prompt string                  `json:"prompt"`
		Policy *domain.GuardrailPolicy `json:"policy,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if strings.TrimSpace(req.Prompt) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "prompt is required"})
		return
	}

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

	canReq := &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: req.Prompt},
		},
	}

	outcome, evalErr := s.guardrails.EvaluateInputWithPolicy(r.Context(), pol, canReq)
	resp := map[string]any{
		"allowed":         evalErr == nil,
		"applied_action":  outcome.AppliedAction,
		"violations":      outcome.Violations,
		"redacted":        outcome.Redacted,
		"redacted_prompt": canReq.Messages[0].Content,
	}
	if evalErr != nil {
		resp["error_message"] = evalErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- Teams & Users ---

func (s *GatewayServer) handleAdminCreateTeam(w http.ResponseWriter, r *http.Request) {
	var team domain.Team
	if err := json.NewDecoder(r.Body).Decode(&team); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	team.IsActive = true
	if err := s.repo.CreateTeam(r.Context(), &team); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), team.OrgID, "team.created", "team", team.ID, map[string]any{"name": team.Name})
	writeJSON(w, http.StatusCreated, team)
}

func (s *GatewayServer) handleAdminListTeams(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	teams, err := s.repo.ListTeams(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": teams})
}

func (s *GatewayServer) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var user domain.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	user.IsActive = true
	if user.Role == "" {
		user.Role = domain.RoleDeveloper
	}
	if err := s.repo.CreateUser(r.Context(), &user); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), user.OrgID, "user.created", "user", user.ID, map[string]any{"email": user.Email, "role": user.Role})
	writeJSON(w, http.StatusCreated, user)
}

func (s *GatewayServer) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	users, err := s.repo.ListUsers(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": users})
}

// --- Virtual API Keys ---

func (s *GatewayServer) handleAdminIssueKey(w http.ResponseWriter, r *http.Request) {
	var req domain.VirtualKey
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	vk, err := s.authSvc.IssueVirtualKey(r.Context(), &req)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), vk.OrgID, "virtual_key.issued", "virtual_key", vk.ID, map[string]any{"key_prefix": vk.KeyPrefix, "name": vk.Name})
	writeJSON(w, http.StatusCreated, vk)
}

func (s *GatewayServer) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	keys, err := s.repo.ListVirtualKeys(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": keys})
}

func (s *GatewayServer) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	if err := s.authSvc.RevokeKey(r.Context(), keyID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), "", "virtual_key.revoked", "virtual_key", keyID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "id": keyID})
}

// --- Boundary 2 Provider Credentials Vault & Lifecycle ---

func (s *GatewayServer) handleAdminCreateCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID               string              `json:"org_id"`
		Provider            domain.ProviderType `json:"provider"`
		Name                string              `json:"name"`
		BaseURL             string              `json:"base_url"`
		AzureDeploymentName string              `json:"azure_deployment_name,omitempty"`
		APIVersion          string              `json:"api_version,omitempty"`
		APIKey              string              `json:"api_key"`
		Headers             map[string]string   `json:"headers,omitempty"`
		ExpiresAt           *time.Time          `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	cred := &domain.ProviderCredential{
		OrgID:               req.OrgID,
		Provider:            req.Provider,
		Name:                req.Name,
		BaseURL:             req.BaseURL,
		AzureDeploymentName: req.AzureDeploymentName,
		APIVersion:          req.APIVersion,
		Headers:             req.Headers,
		IsActive:            true,
		ExpiresAt:           req.ExpiresAt,
	}
	if err := s.vault.EncryptCredential(cred, req.APIKey); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if err := s.repo.CreateProviderCredential(r.Context(), cred); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), cred.OrgID, "credential.created", "provider_credential", cred.ID, map[string]any{
		"provider":    cred.Provider,
		"name":        cred.Name,
		"key_version": cred.KeyVersion,
	})
	writeJSON(w, http.StatusCreated, cred)
}

func (s *GatewayServer) handleAdminListCredentials(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	creds, err := s.repo.ListProviderCredentials(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": creds})
}

func (s *GatewayServer) handleAdminRotateCredential(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "credID")
	var req struct {
		NewAPIKey string     `json:"api_key"`
		BaseURL   string     `json:"base_url,omitempty"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	cred, err := s.repo.GetProviderCredential(r.Context(), credID)
	if err != nil || cred == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Message: "Credential not found"})
		return
	}
	if err := s.vault.RotateCredential(cred, req.NewAPIKey); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if req.ExpiresAt != nil {
		cred.ExpiresAt = req.ExpiresAt
	}
	if req.BaseURL != "" {
		cred.BaseURL = req.BaseURL
	}
	if err := s.repo.UpdateProviderCredential(r.Context(), cred); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), cred.OrgID, "credential.rotated", "provider_credential", cred.ID, map[string]any{
		"provider":    cred.Provider,
		"key_version": cred.KeyVersion,
	})
	writeJSON(w, http.StatusOK, cred)
}

func (s *GatewayServer) handleAdminValidateCredential(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "credID")
	cred, err := s.repo.GetProviderCredential(r.Context(), credID)
	if err != nil || cred == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Message: "Credential not found"})
		return
	}
	if cred.ExpiresAt != nil && time.Now().UTC().After(*cred.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":       cred.ID,
			"provider": cred.Provider,
			"valid":    false,
			"reason":   "credential_expired",
		})
		return
	}
	adp, err := s.reg.Get(cred.Provider)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	rawKey, err := s.vault.DecryptCredential(cred)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	credCopy := *cred
	credCopy.DecryptedAPIKey = rawKey
	start := time.Now()
	models, discErr := adp.ListModels(r.Context(), &credCopy)
	latencyMs := time.Since(start).Milliseconds()
	now := time.Now().UTC()
	cred.LastValidatedAt = &now
	_ = s.repo.UpdateProviderCredential(r.Context(), cred)

	valid := discErr == nil
	validationStatus := "success"
	errMsg := ""
	if discErr != nil {
		if gwErr, ok := discErr.(*domain.GatewayError); ok && gwErr.Code == "list_models_unsupported" {
			valid = true
			validationStatus = "unsupported_by_provider"
		} else {
			validationStatus = "failed"
			errMsg = discErr.Error()
		}
	}
	s.audit(r.Context(), cred.OrgID, "credential.validated", "provider_credential", cred.ID, map[string]any{
		"provider":          cred.Provider,
		"valid":             valid,
		"validation_status": validationStatus,
		"discovered_models": len(models),
		"latency_ms":        latencyMs,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                cred.ID,
		"provider":          cred.Provider,
		"valid":             valid,
		"validation_status": validationStatus,
		"discovered_models": len(models),
		"latency_ms":        latencyMs,
		"last_validated_at": now,
		"error":             errMsg,
	})
}

func (s *GatewayServer) handleAdminPreflightValidateCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider            domain.ProviderType `json:"provider"`
		APIKey              string              `json:"api_key"`
		BaseURL             string              `json:"base_url,omitempty"`
		AzureDeploymentName string              `json:"azure_deployment_name,omitempty"`
		APIVersion          string              `json:"api_version,omitempty"`
		Headers             map[string]string   `json:"headers,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if req.Provider == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "provider is required"})
		return
	}
	if req.APIKey == "" && req.Provider != domain.ProviderOllama {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "api_key is required"})
		return
	}

	adp, err := s.reg.Get(req.Provider)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	credCopy := domain.ProviderCredential{
		Provider:            req.Provider,
		DecryptedAPIKey:     req.APIKey,
		BaseURL:             req.BaseURL,
		AzureDeploymentName: req.AzureDeploymentName,
		APIVersion:          req.APIVersion,
		Headers:             req.Headers,
	}

	start := time.Now()
	models, discErr := adp.ListModels(r.Context(), &credCopy)
	latencyMs := time.Since(start).Milliseconds()

	valid := discErr == nil
	validationStatus := "success"
	errMsg := ""
	if discErr != nil {
		if gwErr, ok := discErr.(*domain.GatewayError); ok && gwErr.Code == "list_models_unsupported" {
			valid = true
			validationStatus = "unsupported_by_provider"
		} else {
			validationStatus = "failed"
			errMsg = discErr.Error()
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"provider":          req.Provider,
		"valid":             valid,
		"validation_status": validationStatus,
		"discovered_models": len(models),
		"latency_ms":        latencyMs,
		"error":             errMsg,
	})
}

// --- Layer 4 Model Groups & Deployments ---

func (s *GatewayServer) handleAdminCreateModelGroup(w http.ResponseWriter, r *http.Request) {
	var mg domain.ModelGroup
	if err := json.NewDecoder(r.Body).Decode(&mg); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	mg.IsActive = true
	if err := s.repo.CreateModelGroup(r.Context(), &mg); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), mg.OrgID, "model_group.created", "model_group", mg.ID, map[string]any{"alias": mg.Alias, "strategy": mg.RoutingStrategy})
	writeJSON(w, http.StatusCreated, mg)
}

func (s *GatewayServer) handleAdminListModelGroups(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	groups, err := s.repo.ListModelGroups(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": groups})
}

func (s *GatewayServer) handleAdminCreateDeployment(w http.ResponseWriter, r *http.Request) {
	var dep domain.Deployment
	if err := json.NewDecoder(r.Body).Decode(&dep); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	dep.Status = domain.DeploymentStatusActive
	if err := s.repo.CreateDeployment(r.Context(), &dep); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), "", "deployment.created", "deployment", dep.ID, map[string]any{
		"model_group_id":  dep.ModelGroupID,
		"global_model_id": dep.GlobalModelID,
		"priority":        dep.Priority,
		"weight":          dep.Weight,
	})
	writeJSON(w, http.StatusCreated, dep)
}

func (s *GatewayServer) handleAdminListDeployments(w http.ResponseWriter, r *http.Request) {
	groupID := r.URL.Query().Get("model_group_id")
	var deps []*domain.Deployment
	var err error
	if groupID != "" {
		deps, err = s.repo.ListDeploymentsByGroup(r.Context(), groupID)
	} else {
		deps, err = s.repo.ListAllDeployments(r.Context())
	}
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": deps})
}

// --- Layer 1 Global Catalogue, Automated Discovery & Versioned Pricing ---

func (s *GatewayServer) handleAdminListCatalogue(w http.ResponseWriter, r *http.Request) {
	models, err := s.repo.ListGlobalModels(r.Context())
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": models})
}

func (s *GatewayServer) handleAdminTriggerDiscoverySync(w http.ResponseWriter, r *http.Request) {
	report, err := s.discovery.SyncNow(r.Context())
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), "", "catalogue.discovery.synced", "catalogue", "global", map[string]any{
		"report": report,
	})
	writeJSON(w, http.StatusOK, report)
}

func (s *GatewayServer) handleAdminImportCatalogue(w http.ResponseWriter, r *http.Request) {
	targetProv := domain.ProviderType(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider"))))
	var models []*domain.GlobalModel
	if targetProv != "" {
		models = catalog.Search(targetProv, "")
	} else {
		models = catalog.All()
	}

	imported := 0
	for _, m := range models {
		if err := s.repo.UpsertGlobalModel(r.Context(), m); err == nil {
			imported++
		}
	}

	s.audit(r.Context(), "", "catalogue.import.completed", "catalogue", "global", map[string]any{
		"imported": imported,
		"provider": string(targetProv),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"imported": imported,
		"provider": string(targetProv),
		"total":    catalog.Count(),
	})
}

func (s *GatewayServer) handleAdminUpdateModelPricing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GlobalModelID              string               `json:"global_model_id"`
		InputCostMicrosPer1M       int64                `json:"input_cost_micros_per_1m"`
		OutputCostMicrosPer1M      int64                `json:"output_cost_micros_per_1m"`
		CachedInputCostMicrosPer1M int64                `json:"cached_input_cost_micros_per_1m"`
		ReasoningCostMicrosPer1M   int64                `json:"reasoning_cost_micros_per_1m"`
		PricingStatus              domain.PricingStatus `json:"pricing_status,omitempty"`
		PricingProvenanceSource    string               `json:"pricing_provenance_source,omitempty"`
		PricingEffectiveDate       string               `json:"pricing_effective_date,omitempty"`
		ChangedBy                  string               `json:"changed_by,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if req.ChangedBy == "" {
		req.ChangedBy = "admin"
	}
	if req.PricingStatus == "" {
		req.PricingStatus = domain.PricingStatusVerified
	}
	if req.PricingProvenanceSource == "" {
		req.PricingProvenanceSource = "admin-audit-" + time.Now().UTC().Format("2006-01-02")
	}
	if req.PricingEffectiveDate == "" {
		req.PricingEffectiveDate = time.Now().UTC().Format(time.RFC3339)
	}
	gm, err := s.repo.UpdateModelPricing(
		r.Context(), req.GlobalModelID, req.InputCostMicrosPer1M, req.OutputCostMicrosPer1M,
		req.CachedInputCostMicrosPer1M, req.ReasoningCostMicrosPer1M, req.PricingStatus,
		req.PricingProvenanceSource, req.PricingEffectiveDate, req.ChangedBy,
	)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Message: err.Error()})
		return
	}
	hist, _ := s.repo.ListModelPricingHistory(r.Context(), req.GlobalModelID)
	s.audit(r.Context(), "", "catalogue.pricing.updated", "global_model", gm.ID, map[string]any{
		"model_name":               gm.ModelName,
		"pricing_version":          gm.PricingVersion,
		"input_cost_micros_per_1m": gm.InputCostMicrosPer1M,
		"pricing_status":           gm.PricingStatus,
		"provenance_source":        gm.PricingProvenanceSource,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"model":   gm,
		"history": hist,
	})
}

func (s *GatewayServer) handleAdminListModelPricingHistory(w http.ResponseWriter, r *http.Request) {
	modelID := r.URL.Query().Get("global_model_id")
	hist, err := s.repo.ListModelPricingHistory(r.Context(), modelID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": hist})
}

// --- Observability, Active Deployment Health & Cache Invalidation ---

func (s *GatewayServer) handleAdminObservabilityMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.collector.Snapshot())
}

func (s *GatewayServer) handleAdminListDeploymentHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"data": s.healthMon.GetReports()})
}

func (s *GatewayServer) handleAdminProbeDeployments(w http.ResponseWriter, r *http.Request) {
	reports, err := s.healthMon.ProbeAllNow(r.Context())
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), "", "health.deployments.probed", "deployment_health", "all", map[string]any{
		"probed_count": len(reports),
	})
	writeJSON(w, http.StatusOK, map[string]any{"data": reports})
}

func (s *GatewayServer) handleAdminInvalidateCache(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID string `json:"org_id,omitempty"`
		Model string `json:"model,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	purged, nsVer, err := s.respCache.Invalidate(r.Context(), req.OrgID, req.Model)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "cache_invalidation_unavailable",
			Message:    "Response cache invalidation could not update shared state",
		})
		return
	}
	s.audit(r.Context(), req.OrgID, "cache.invalidated", "response_cache", "global", map[string]any{
		"org_id":            req.OrgID,
		"model":             req.Model,
		"purged_entries":    purged,
		"namespace_version": nsVer,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "invalidated",
		"purged_entries":    purged,
		"namespace_version": nsVer,
	})
}

// --- FinOps Analytics & Governance Audit Logs ---

func (s *GatewayServer) handleAdminSpendSummary(w http.ResponseWriter, r *http.Request) {
	_ = s.spendWorker.FlushNow(r.Context())
	orgID := r.URL.Query().Get("org_id")
	sum, err := s.repo.GetSpendSummary(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *GatewayServer) handleAdminSpendLogs(w http.ResponseWriter, r *http.Request) {
	_ = s.spendWorker.FlushNow(r.Context())
	orgID := r.URL.Query().Get("org_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	logs, err := s.repo.ListSpendLogs(r.Context(), orgID, limit)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": logs})
}

func (s *GatewayServer) handleAdminAuditLogs(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	logs, err := s.repo.ListAuditLogs(r.Context(), orgID, limit)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": logs})
}
