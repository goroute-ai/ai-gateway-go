package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func (s *GatewayServer) validateA2ASSRFURL(rawURL, fieldName string) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil
	}
	var u *url.URL
	var err error
	if strings.Contains(trimmed, "://") {
		u, err = url.Parse(trimmed)
	} else {
		u, err = url.Parse("http://" + trimmed)
	}
	if err != nil {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_url",
			Message:    fmt.Sprintf("invalid %s: %v", fieldName, err),
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "grpc":
		u.Scheme = "http"
	case "grpcs":
		u.Scheme = "https"
	}
	if s.netPolicy != nil {
		if err := s.netPolicy.ValidateURL(u); err != nil {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "ssrf_blocked",
				Message:    fmt.Sprintf("%s blocked by network security policy: %v", fieldName, err),
			}
		}
	}
	return nil
}

func validateA2AAgentConfig(
	protocolBinding string,
	visibilityMode string,
	authType string,
	agentCardJSON string,
	extCardJSON string,
) error {
	if protocolBinding != "" {
		switch protocolBinding {
		case domain.A2AProtocolBindingHTTPJSON, domain.A2AProtocolBindingJSONRPC, domain.A2AProtocolBindingGRPC:
		default:
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_protocol_binding",
				Message:    fmt.Sprintf("unsupported protocol_binding %q", protocolBinding),
			}
		}
	}
	if visibilityMode != "" {
		switch visibilityMode {
		case domain.TaskVisibilityKeyStrict, domain.TaskVisibilityUserStrict, domain.TaskVisibilityTeam, domain.TaskVisibilityOrgAdmin:
		default:
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_visibility_mode",
				Message:    fmt.Sprintf("unsupported task_visibility_mode %q", visibilityMode),
			}
		}
	}
	if authType != "" {
		switch authType {
		case "none", "static", "vault_jwt":
		default:
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_auth_type",
				Message:    fmt.Sprintf("unsupported auth_type %q", authType),
			}
		}
	}
	if trimmed := strings.TrimSpace(agentCardJSON); trimmed != "" {
		if err := a2aspec.ValidateSchema("AgentCard", []byte(trimmed)); err != nil {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_agent_card",
				Message:    fmt.Sprintf("agent_card_json failed OpenAPI AgentCard schema validation: %v", err),
			}
		}
	}
	if trimmed := strings.TrimSpace(extCardJSON); trimmed != "" {
		if err := a2aspec.ValidateSchema("AgentCard", []byte(trimmed)); err != nil {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_extended_agent_card",
				Message:    fmt.Sprintf("extended_agent_card_json failed OpenAPI AgentCard schema validation: %v", err),
			}
		}
	}
	return nil
}

// handleAdminCreateA2AAgent registers a new A2A agent definition.
func (s *GatewayServer) handleAdminCreateA2AAgent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OrgID                 string `json:"org_id"`
		Name                  string `json:"name"`
		Slug                  string `json:"slug"`
		EndpointURL           string `json:"endpoint_url"`
		AgentCardURL          string `json:"agent_card_url,omitempty"`
		AgentCardJSON         string `json:"agent_card_json,omitempty"`
		ExtendedAgentCardJSON string `json:"extended_agent_card_json,omitempty"`
		IsPublicCard          bool   `json:"is_public_card,omitempty"`
		ProtocolBinding       string `json:"protocol_binding,omitempty"`
		TaskVisibilityMode    string `json:"task_visibility_mode,omitempty"`
		AuthType              string `json:"auth_type,omitempty"`
		AuthHeaderName        string `json:"auth_header_name,omitempty"`
		AuthSecret            string `json:"auth_secret,omitempty"`
		MaxTaskIterations     int    `json:"max_task_iterations,omitempty"`
		MaxTaskBudgetMicros   int64  `json:"max_task_budget_micros,omitempty"`
	}

	if err := decodeAdminJSON(w, r, &input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    err.Error(),
		})
		return
	}

	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Slug) == "" || strings.TrimSpace(input.EndpointURL) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_required_fields",
			Message:    "name, slug, and endpoint_url are required",
		})
		return
	}

	if input.OrgID == "" {
		input.OrgID = resolveScopedOrgID(r, "")
	}
	if input.OrgID == "" {
		input.OrgID = s.cfg.Auth.DefaultOrgID
	}
	op, ok := s.authorizeAdmin(w, r, input.OrgID, true)
	if !ok {
		return
	}
	if gwErr := s.authorizeCustomBaseURL(op, input.EndpointURL); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	if gwErr := s.authorizeCustomBaseURL(op, input.AgentCardURL); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	if err := s.validateA2ASSRFURL(input.EndpointURL, "endpoint_url"); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if strings.TrimSpace(input.AgentCardURL) != "" {
		cleanCardURL, err := a2a.ValidateAndSanitizeCardURL(input.AgentCardURL, s.netPolicy)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_agent_card_url",
				Message:    err.Error(),
			})
			return
		}
		input.AgentCardURL = cleanCardURL
	}
	if input.ProtocolBinding == "" {
		input.ProtocolBinding = domain.A2AProtocolBindingHTTPJSON
	}
	if input.TaskVisibilityMode == "" {
		input.TaskVisibilityMode = domain.TaskVisibilityKeyStrict
	}
	if input.AuthType == "" {
		input.AuthType = "none"
	}
	if input.MaxTaskIterations <= 0 {
		input.MaxTaskIterations = 50
	}
	if err := validateA2AAgentConfig(input.ProtocolBinding, input.TaskVisibilityMode, input.AuthType, input.AgentCardJSON, input.ExtendedAgentCardJSON); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	now := time.Now().UTC()
	agent := &domain.A2AAgent{
		ID:                    "agent_" + uuid.NewString(),
		OrgID:                 input.OrgID,
		Name:                  strings.TrimSpace(input.Name),
		Slug:                  strings.TrimSpace(input.Slug),
		EndpointURL:           strings.TrimSpace(input.EndpointURL),
		AgentCardURL:          strings.TrimSpace(input.AgentCardURL),
		AgentCardJSON:         strings.TrimSpace(input.AgentCardJSON),
		ExtendedAgentCardJSON: strings.TrimSpace(input.ExtendedAgentCardJSON),
		IsPublicCard:          input.IsPublicCard,
		ProtocolBinding:       input.ProtocolBinding,
		TaskVisibilityMode:    input.TaskVisibilityMode,
		AuthType:              input.AuthType,
		AuthHeaderName:        strings.TrimSpace(input.AuthHeaderName),
		MaxTaskIterations:     input.MaxTaskIterations,
		MaxTaskBudgetMicros:   input.MaxTaskBudgetMicros,
		IsActive:              true,
		IsKilled:              false,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if strings.TrimSpace(input.AuthSecret) != "" {
		cipher, dek, err := s.vault.EncryptString(strings.TrimSpace(input.AuthSecret))
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "encryption_error",
				Message:    err.Error(),
			})
			return
		}
		agent.EncryptedAuthSecret = cipher
		agent.EncryptedAuthDEK = dek
	}

	if err := s.repo.CreateA2AAgent(r.Context(), agent); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "agent_slug_conflict",
				Message:    err.Error(),
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "created",
		"agent":  agent,
	})
}

// handleAdminListA2AAgents lists registered A2A agents for an organization.
func (s *GatewayServer) handleAdminListA2AAgents(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if orgID == "" {
		orgID = s.cfg.Auth.DefaultOrgID
	}
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	agents, err := s.repo.ListA2AAgents(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"agents": agents,
	})
}

// handleAdminGetA2AAgent gets an agent by ID.
func (s *GatewayServer) handleAdminGetA2AAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	agent, err := s.repo.GetA2AAgent(r.Context(), agentID)
	if err != nil || agent == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "agent_not_found",
			Message:    fmt.Sprintf("Agent %q not found", agentID),
		})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, agent.OrgID, false); !ok {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"agent": agent,
	})
}

// handleAdminUpdateA2AAgent updates mutable settings on an existing A2A agent definition.
func (s *GatewayServer) handleAdminUpdateA2AAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	existing, err := s.repo.GetA2AAgent(r.Context(), agentID)
	if err != nil || existing == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "agent_not_found",
			Message:    fmt.Sprintf("Agent %q not found", agentID),
		})
		return
	}
	op, ok := s.authorizeAdmin(w, r, existing.OrgID, true)
	if !ok {
		return
	}

	var input struct {
		Name                  *string `json:"name,omitempty"`
		EndpointURL           *string `json:"endpoint_url,omitempty"`
		AgentCardURL          *string `json:"agent_card_url,omitempty"`
		AgentCardJSON         *string `json:"agent_card_json,omitempty"`
		ExtendedAgentCardJSON *string `json:"extended_agent_card_json,omitempty"`
		IsPublicCard          *bool   `json:"is_public_card,omitempty"`
		ProtocolBinding       *string `json:"protocol_binding,omitempty"`
		TaskVisibilityMode    *string `json:"task_visibility_mode,omitempty"`
		AuthType              *string `json:"auth_type,omitempty"`
		AuthHeaderName        *string `json:"auth_header_name,omitempty"`
		AuthSecret            *string `json:"auth_secret,omitempty"`
		MaxTaskIterations     *int    `json:"max_task_iterations,omitempty"`
		MaxTaskBudgetMicros   *int64  `json:"max_task_budget_micros,omitempty"`
		IsActive              *bool   `json:"is_active,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    err.Error(),
		})
		return
	}

	updated := *existing
	if input.Name != nil {
		if strings.TrimSpace(*input.Name) == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_name",
				Message:    "name cannot be empty",
			})
			return
		}
		updated.Name = strings.TrimSpace(*input.Name)
	}
	if input.EndpointURL != nil {
		if gwErr := s.authorizeCustomBaseURL(op, *input.EndpointURL); gwErr != nil {
			domain.WriteHTTPError(w, gwErr)
			return
		}
		if err := s.validateA2ASSRFURL(*input.EndpointURL, "endpoint_url"); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		updated.EndpointURL = strings.TrimSpace(*input.EndpointURL)
	}
	if input.AgentCardURL != nil {
		if gwErr := s.authorizeCustomBaseURL(op, *input.AgentCardURL); gwErr != nil {
			domain.WriteHTTPError(w, gwErr)
			return
		}
		if strings.TrimSpace(*input.AgentCardURL) != "" {
			cleanCardURL, err := a2a.ValidateAndSanitizeCardURL(*input.AgentCardURL, s.netPolicy)
			if err != nil {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "invalid_agent_card_url",
					Message:    err.Error(),
				})
				return
			}
			updated.AgentCardURL = cleanCardURL
		} else {
			updated.AgentCardURL = ""
		}
	}
	if input.AgentCardJSON != nil {
		updated.AgentCardJSON = strings.TrimSpace(*input.AgentCardJSON)
	}
	if input.ExtendedAgentCardJSON != nil {
		updated.ExtendedAgentCardJSON = strings.TrimSpace(*input.ExtendedAgentCardJSON)
	}
	if input.IsPublicCard != nil {
		updated.IsPublicCard = *input.IsPublicCard
	}
	if input.ProtocolBinding != nil {
		updated.ProtocolBinding = strings.TrimSpace(*input.ProtocolBinding)
	}
	if input.TaskVisibilityMode != nil {
		updated.TaskVisibilityMode = strings.TrimSpace(*input.TaskVisibilityMode)
	}
	if input.AuthType != nil {
		updated.AuthType = strings.TrimSpace(*input.AuthType)
	}
	if input.AuthHeaderName != nil {
		updated.AuthHeaderName = strings.TrimSpace(*input.AuthHeaderName)
	}
	if input.MaxTaskIterations != nil && *input.MaxTaskIterations > 0 {
		updated.MaxTaskIterations = *input.MaxTaskIterations
	}
	if input.MaxTaskBudgetMicros != nil {
		updated.MaxTaskBudgetMicros = *input.MaxTaskBudgetMicros
	}
	if input.IsActive != nil {
		updated.IsActive = *input.IsActive
	}

	if err := validateA2AAgentConfig(
		updated.ProtocolBinding,
		updated.TaskVisibilityMode,
		updated.AuthType,
		updated.AgentCardJSON,
		updated.ExtendedAgentCardJSON,
	); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	if input.AuthSecret != nil && strings.TrimSpace(*input.AuthSecret) != "" {
		cipher, dek, err := s.vault.EncryptString(strings.TrimSpace(*input.AuthSecret))
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "encryption_error",
				Message:    err.Error(),
			})
			return
		}
		updated.EncryptedAuthSecret = cipher
		updated.EncryptedAuthDEK = dek
	}
	updated.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateA2AAgent(r.Context(), &updated); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "updated",
		"agent":  &updated,
	})
}

// handleAdminDeleteA2AAgent removes an A2A agent definition by ID.
func (s *GatewayServer) handleAdminDeleteA2AAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	agent, err := s.repo.GetA2AAgent(r.Context(), agentID)
	if err != nil || agent == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "agent_not_found",
			Message:    fmt.Sprintf("Agent %q not found", agentID),
		})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, agent.OrgID, true); !ok {
		return
	}

	if err := s.repo.DeleteA2AAgent(r.Context(), agentID); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "deleted",
		"id":     agentID,
	})
}

// handleAdminSyncA2AAgentCard fetches, validates, and persists an upstream AgentCard from agent_card_url.
func (s *GatewayServer) handleAdminSyncA2AAgentCard(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	agent, err := s.repo.GetA2AAgent(r.Context(), agentID)
	if err != nil || agent == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "agent_not_found",
			Message:    fmt.Sprintf("Agent %q not found", agentID),
		})
		return
	}
	op, ok := s.authorizeAdmin(w, r, agent.OrgID, true)
	if !ok {
		return
	}

	var opts struct {
		AgentCardURL string `json:"agent_card_url,omitempty"`
		JWKSURL      string `json:"jwks_url,omitempty"`
	}
	if r.Body != nil {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &opts); err != nil {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "invalid_json",
					Message:    err.Error(),
				})
				return
			}
		}
	}

	cardURL := strings.TrimSpace(opts.AgentCardURL)
	if cardURL == "" {
		cardURL = strings.TrimSpace(agent.AgentCardURL)
	}
	if cardURL == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_agent_card_url",
			Message:    "agent_card_url is required to sync upstream AgentCard",
		})
		return
	}
	if gwErr := s.authorizeCustomBaseURL(op, cardURL); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	if gwErr := s.authorizeCustomBaseURL(op, opts.JWKSURL); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	cleanCardURL, err := a2a.ValidateAndSanitizeCardURL(cardURL, s.netPolicy)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "ssrf_blocked",
			Message:    fmt.Sprintf("agent_card_url blocked: %v", err),
		})
		return
	}
	cleanJWKSURL := ""
	if strings.TrimSpace(opts.JWKSURL) != "" {
		cleanJWKSURL, err = a2a.ValidateAndSanitizeCardURL(opts.JWKSURL, s.netPolicy)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "ssrf_blocked",
				Message:    fmt.Sprintf("jwks_url blocked: %v", err),
			})
			return
		}
	}
	if s.a2aRouter == nil || s.a2aRouter.Verifier() == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "verifier_unavailable",
			Message:    "A2A card verifier is unavailable",
		})
		return
	}

	card, err := s.a2aRouter.Verifier().FetchAndVerifyCard(r.Context(), agent.Slug, cleanCardURL, cleanJWKSURL)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "card_sync_failed",
			Message:    err.Error(),
		})
		return
	}

	cardJSON, err := json.Marshal(card)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "marshal_error",
			Message:    err.Error(),
		})
		return
	}

	updated := *agent
	updated.AgentCardURL = cleanCardURL
	updated.AgentCardJSON = string(cardJSON)
	updated.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpdateA2AAgent(r.Context(), &updated); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "synced",
		"agent":  &updated,
	})
}

// handleAdminSetA2AKillSwitch activates or deactivates an emergency kill-switch for an agent.
func (s *GatewayServer) handleAdminSetA2AKillSwitch(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	var input struct {
		Killed bool `json:"killed"`
	}

	if err := decodeAdminJSON(w, r, &input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    err.Error(),
		})
		return
	}

	agent, err := s.repo.GetA2AAgent(r.Context(), agentID)
	if err != nil || agent == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "agent_not_found",
			Message:    fmt.Sprintf("Agent %q not found", agentID),
		})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, agent.OrgID, true); !ok {
		return
	}

	if err := s.repo.SetA2AAgentKillSwitch(r.Context(), agentID, input.Killed); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "updated",
		"agent_id": agentID,
		"killed":   input.Killed,
	})
}

// handleAdminSetA2APushConfig registers a push notification webhook for task updates.
func (s *GatewayServer) handleAdminSetA2APushConfig(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OrgID      string `json:"org_id,omitempty"`
		TaskID     string `json:"task_id"`
		TargetURL  string `json:"target_url"`
		Token      string `json:"token,omitempty"`
		AuthToken  string `json:"auth_token,omitempty"`
		AuthScheme string `json:"auth_scheme,omitempty"`
	}

	if err := decodeAdminJSON(w, r, &input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    err.Error(),
		})
		return
	}

	if strings.TrimSpace(input.TaskID) == "" || strings.TrimSpace(input.TargetURL) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_required_fields",
			Message:    "task_id and target_url are required",
		})
		return
	}
	if err := s.validateA2ASSRFURL(input.TargetURL, "target_url"); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	task, err := s.repo.GetA2ATask(r.Context(), input.TaskID)
	if err != nil || task == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "a2a_task_not_found",
			Message:    "A2A task not found",
		})
		return
	}
	targetOrgID := task.OrgID
	if targetOrgID == "" {
		targetOrgID = input.OrgID
	}
	if targetOrgID == "" {
		targetOrgID = s.cfg.Auth.DefaultOrgID
	}
	op, ok := s.authorizeAdmin(w, r, targetOrgID, true)
	if !ok {
		return
	}
	if gwErr := s.authorizeCustomBaseURL(op, input.TargetURL); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	cleanTargetURL, err := s.validateCredentialBaseURL(input.TargetURL)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_target_url",
			Message:    err.Error(),
		})
		return
	}
	input.TargetURL = cleanTargetURL

	now := time.Now().UTC()
	secretCred := strings.TrimSpace(input.AuthToken)
	if secretCred == "" {
		secretCred = strings.TrimSpace(input.Token)
	}
	var encCreds, encDEK string
	if secretCred != "" && s.vault != nil {
		cipher, dek, encErr := s.vault.EncryptString(secretCred)
		if encErr != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "vault_encryption_error",
				Message:    encErr.Error(),
			})
			return
		}
		encCreds = cipher
		encDEK = dek
	}

	cfg := &domain.A2APushNotificationConfig{
		ID:                 "push_cfg_" + uuid.NewString(),
		TaskID:             input.TaskID,
		Tenant:             targetOrgID,
		TargetURL:          strings.TrimSpace(input.TargetURL),
		Token:              strings.TrimSpace(input.Token),
		AuthScheme:         strings.TrimSpace(input.AuthScheme),
		EncryptedAuthCreds: encCreds,
		EncryptedAuthDEK:   encDEK,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := s.repo.SetA2APushNotificationConfig(r.Context(), cfg); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status":      "created",
		"push_config": cfg,
	})
}

// handleAdminListA2AOutboxEvents lists push notification outbox events scoped by org and status.
func (s *GatewayServer) handleAdminListA2AOutboxEvents(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if orgID == "" {
		orgID = s.cfg.Auth.DefaultOrgID
	}
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := 100
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	events, err := s.repo.ListA2AOutboxEvents(r.Context(), orgID, statusFilter, limit)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
	})
}

// handleAdminReplayA2AOutboxEvent re-queues a dead-lettered or failed push notification outbox event.
func (s *GatewayServer) handleAdminReplayA2AOutboxEvent(w http.ResponseWriter, r *http.Request) {
	eventID := chi.URLParam(r, "id")
	existing, err := s.repo.GetA2AOutboxEvent(r.Context(), eventID)
	if err != nil || existing == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "outbox_event_not_found",
			Message:    fmt.Sprintf("A2A outbox event %q not found", eventID),
		})
		return
	}

	targetOrgID := s.cfg.Auth.DefaultOrgID
	if task, tErr := s.repo.GetA2ATask(r.Context(), existing.TaskID); tErr == nil && task != nil && task.OrgID != "" {
		targetOrgID = task.OrgID
	}
	if _, ok := s.authorizeAdmin(w, r, targetOrgID, true); !ok {
		return
	}

	requeued, err := s.repo.ReplayA2AOutboxEvent(r.Context(), eventID)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "requeued",
		"event":  requeued,
	})
}
