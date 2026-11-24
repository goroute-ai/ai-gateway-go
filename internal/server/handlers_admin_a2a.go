package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// handleAdminCreateA2AAgent registers a new A2A agent definition.
func (s *GatewayServer) handleAdminCreateA2AAgent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OrgID               string `json:"org_id"`
		Name                string `json:"name"`
		Slug                string `json:"slug"`
		EndpointURL         string `json:"endpoint_url"`
		AgentCardURL        string `json:"agent_card_url,omitempty"`
		AgentCardJSON       string `json:"agent_card_json,omitempty"`
		TaskVisibilityMode  string `json:"task_visibility_mode,omitempty"` // "key_strict", "user_strict", "team", "org_admin"
		AuthType            string `json:"auth_type,omitempty"`
		AuthSecret          string `json:"auth_secret,omitempty"`
		MaxTaskIterations   int    `json:"max_task_iterations,omitempty"`
		MaxTaskBudgetMicros int64  `json:"max_task_budget_micros,omitempty"`
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

	if input.Name == "" || input.Slug == "" || input.EndpointURL == "" {
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
	if _, ok := s.authorizeAdmin(w, r, input.OrgID, true); !ok {
		return
	}
	if input.TaskVisibilityMode == "" {
		input.TaskVisibilityMode = domain.TaskVisibilityKeyStrict
	}
	if input.MaxTaskIterations <= 0 {
		input.MaxTaskIterations = 50
	}

	agent := &domain.A2AAgent{
		ID:                  "agent_" + uuid.NewString(),
		OrgID:               input.OrgID,
		Name:                input.Name,
		Slug:                input.Slug,
		EndpointURL:         input.EndpointURL,
		AgentCardURL:        input.AgentCardURL,
		AgentCardJSON:       input.AgentCardJSON,
		TaskVisibilityMode:  input.TaskVisibilityMode,
		AuthType:            input.AuthType,
		MaxTaskIterations:   input.MaxTaskIterations,
		MaxTaskBudgetMicros: input.MaxTaskBudgetMicros,
		IsActive:            true,
		IsKilled:            false,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}

	// Encrypt auth secret if provided
	if input.AuthSecret != "" {
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
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	s.auditWithDiff(r.Context(), agent.OrgID, "a2a_agent.created", "a2a_agent", agent.ID, map[string]any{
		"name":                 agent.Name,
		"slug":                 agent.Slug,
		"task_visibility_mode": agent.TaskVisibilityMode,
		"auth_type":            agent.AuthType,
	}, nil, agent)

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

	before := *agent
	if err := s.repo.SetA2AAgentKillSwitch(r.Context(), agentID, input.Killed); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}
	after := before
	after.IsKilled = input.Killed
	s.auditWithDiff(r.Context(), agent.OrgID, "a2a_agent.kill_switch_updated", "a2a_agent", agentID, map[string]any{
		"slug":   agent.Slug,
		"killed": input.Killed,
	}, &before, &after)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "updated",
		"agent_id": agentID,
		"killed":   input.Killed,
	})
}

// handleAdminSetA2APushConfig registers a push notification webhook for task updates.
func (s *GatewayServer) handleAdminSetA2APushConfig(w http.ResponseWriter, r *http.Request) {
	var input struct {
		TaskID    string `json:"task_id"`
		TargetURL string `json:"target_url"`
		AuthToken string `json:"auth_token,omitempty"`
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

	if input.TaskID == "" || input.TargetURL == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_required_fields",
			Message:    "task_id and target_url are required",
		})
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
		targetOrgID = s.cfg.Auth.DefaultOrgID
	}
	if _, ok := s.authorizeAdmin(w, r, targetOrgID, true); !ok {
		return
	}

	encryptedAuthToken := ""
	if trimmedToken := strings.TrimSpace(input.AuthToken); trimmedToken != "" {
		cipher, dek, err := s.vault.EncryptString(trimmedToken)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "vault_encryption_error",
				Message:    err.Error(),
			})
			return
		}
		encryptedAuthToken = "vault:" + cipher + ":" + dek
	}

	cfg := &domain.A2APushNotificationConfig{
		ID:        "push_cfg_" + uuid.NewString(),
		TaskID:    input.TaskID,
		TargetURL: input.TargetURL,
		AuthToken: encryptedAuthToken,
		CreatedAt: time.Now().UTC(),
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

	s.auditWithDiff(r.Context(), targetOrgID, "a2a_push_config.created", "a2a_push_config", cfg.ID, map[string]any{
		"task_id":    cfg.TaskID,
		"target_url": cfg.TargetURL,
	}, nil, cfg)

	writeJSON(w, http.StatusCreated, map[string]any{
		"status":      "created",
		"push_config": cfg,
	})
}
