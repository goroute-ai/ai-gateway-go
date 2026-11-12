package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

// handleTokenize serves `POST /v1/tokenize` and `POST /tokenize`.
func (s *GatewayServer) handleTokenize(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Missing virtual key identity context",
		})
		return
	}

	var raw struct {
		Model    string                    `json:"model"`
		Prompt   any                       `json:"prompt,omitempty"`
		Messages []domain.CanonicalMessage `json:"messages,omitempty"`
		Tools    []domain.CanonicalTool    `json:"tools,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse tokenize request: " + err.Error(),
		})
		return
	}

	model := strings.TrimSpace(raw.Model)
	if model == "" {
		model = "auto"
	}

	if err := s.rbac.AuthorizeRequestedModel(idCtx, model); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	profile := ratelimit.ResolveTokenizerProfile(model)
	tokenCount := 0

	if len(raw.Messages) > 0 || len(raw.Tools) > 0 {
		chatReq := &domain.CanonicalChatRequest{
			Model:    model,
			Messages: raw.Messages,
			Tools:    raw.Tools,
		}
		tokenCount = ratelimit.EstimateRequestTokens(chatReq)
	} else {
		// Single text prompt
		promptText := ""
		switch v := raw.Prompt.(type) {
		case string:
			promptText = v
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					promptText += s + " "
				}
			}
		}
		tokenCount = ratelimit.EstimateTextTokens(promptText, profile)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"model":        model,
		"profile":      string(profile),
		"count":        tokenCount,
		"total_tokens": tokenCount,
	})
}

// handleAnthropicCountTokens serves `POST /anthropic/v1/messages/count_tokens` and `POST /v1/messages/count_tokens`.
func (s *GatewayServer) handleAnthropicCountTokens(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteAnthropicHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Missing virtual key identity context",
		})
		return
	}

	var payload anthropicMessagesPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		domain.WriteAnthropicHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse count_tokens request: " + err.Error(),
		})
		return
	}

	model := strings.TrimSpace(payload.Model)
	if model == "" {
		model = "claude-3-7-sonnet"
	}

	if err := s.rbac.AuthorizeRequestedModel(idCtx, model); err != nil {
		domain.WriteAnthropicHTTPError(w, err)
		return
	}

	chatReq := domain.CanonicalChatRequest{
		Model: model,
	}
	if payload.System != nil {
		sysText := parseAnthropicSystem(payload.System)
		if sysText != "" {
			chatReq.Messages = append(chatReq.Messages, domain.CanonicalMessage{
				Role:    "system",
				Content: sysText,
			})
		}
	}
	for _, m := range payload.Messages {
		chatReq.Messages = append(chatReq.Messages, parseAnthropicMessage(m)...)
	}
	for _, t := range payload.Tools {
		chatReq.Tools = append(chatReq.Tools, domain.CanonicalTool{
			Type: "function",
			Function: domain.CanonicalFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.InputSchema,
			},
		})
	}

	tokens := ratelimit.EstimateRequestTokens(&chatReq)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{
		"input_tokens": tokens,
	})
}
