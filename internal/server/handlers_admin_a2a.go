package server

import (
	"encoding/json"
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

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
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
		input.OrgID = s.cfg.Auth.DefaultOrgID
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

	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "created",
		"agent":  agent,
	})
}

// handleAdminListA2AAgents lists registered A2A agents for an organization.
func (s *GatewayServer) handleAdminListA2AAgents(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		orgID = s.cfg.Auth.DefaultOrgID
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

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    err.Error(),
		})
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
		TaskID    string `json:"task_id"`
		TargetURL string `json:"target_url"`
		AuthToken string `json:"auth_token,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
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

	cfg := &domain.A2APushNotificationConfig{
		ID:        "push_cfg_" + uuid.NewString(),
		TaskID:    input.TaskID,
		TargetURL: input.TargetURL,
		AuthToken: input.AuthToken,
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

	writeJSON(w, http.StatusCreated, map[string]any{
		"status":      "created",
		"push_config": cfg,
	})
}
