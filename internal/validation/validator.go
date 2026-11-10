package validation

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

var validRoles = []string{"system", "developer", "user", "assistant", "tool"}

// Validator enforces schema, parameter bounds, model capabilities, and context-window limits
// prior to routing and load balancing.
type Validator struct {
	repo storage.Repository
}

func NewValidator(repo storage.Repository) *Validator {
	return &Validator{repo: repo}
}

// ValidateChatRequest validates request parameters, capabilities, and context-window constraints.
func (v *Validator) ValidateChatRequest(ctx context.Context, orgID string, req *domain.CanonicalChatRequest, estimatedPromptTokens int) error {
	if req == nil {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "empty_request",
			Message:    "ChatCompletion request cannot be nil",
		}
	}
	if len(req.Messages) == 0 {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_messages",
			Message:    "messages array cannot be empty",
		}
	}

	hasImageInput := false
	for i, m := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if !slices.Contains(validRoles, role) {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_message_role",
				Message:    fmt.Sprintf("messages[%d].role %q is invalid (allowed: system, developer, user, assistant, tool)", i, m.Role),
			}
		}
		for _, p := range m.Parts {
			if p.Type == "image_url" && p.ImageURL != nil && p.ImageURL.URL != "" {
				hasImageInput = true
			}
		}
	}

	if req.Temperature != nil && (*req.Temperature < 0.0 || *req.Temperature > 2.0) {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_temperature",
			Message:    fmt.Sprintf("temperature %.2f must be between 0.0 and 2.0", *req.Temperature),
		}
	}

	if req.TopP != nil && (*req.TopP < 0.0 || *req.TopP > 1.0) {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_top_p",
			Message:    fmt.Sprintf("top_p %.2f must be between 0.0 and 1.0", *req.TopP),
		}
	}

	if req.MaxTokens != nil && *req.MaxTokens <= 0 {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_max_tokens",
			Message:    "max_tokens must be greater than 0",
		}
	}

	// If the requested model is not a smart alias, resolve the target GlobalModel to verify capabilities & context limits
	requested := strings.TrimSpace(req.Model)
	if requested != "" && !slices.Contains(auth.SmartAliases, requested) && v.repo != nil {
		gm := v.resolveTargetGlobalModel(ctx, orgID, requested)
		if gm != nil {
			caps := gm.ResolveCapabilities()
			if req.Stream && caps.Streaming == domain.CapabilityUnsupported {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "capability_not_supported",
					Message:    fmt.Sprintf("Model %q does not support SSE streaming (stream: true)", gm.ModelName),
				}
			}
			if len(req.Tools) > 0 && caps.Tools == domain.CapabilityUnsupported {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "capability_not_supported",
					Message:    fmt.Sprintf("Model %q does not support function/tool calling", gm.ModelName),
				}
			}
			if hasImageInput && caps.Vision == domain.CapabilityUnsupported {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "capability_not_supported",
					Message:    fmt.Sprintf("Model %q does not support multimodal vision inputs", gm.ModelName),
				}
			}
			if gm.MaxInputTokens > 0 && estimatedPromptTokens > gm.MaxInputTokens {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "context_length_exceeded",
					Message:    fmt.Sprintf("Estimated prompt tokens (%d) exceed model %q maximum context window (%d tokens)", estimatedPromptTokens, gm.ModelName, gm.MaxInputTokens),
				}
			}
			if req.MaxTokens != nil && gm.MaxOutputTokens > 0 && *req.MaxTokens > gm.MaxOutputTokens {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "max_output_tokens_exceeded",
					Message:    fmt.Sprintf("Requested max_tokens (%d) exceeds model %q maximum output tokens (%d)", *req.MaxTokens, gm.ModelName, gm.MaxOutputTokens),
				}
			}
		}
	}

	return nil
}

func (v *Validator) resolveTargetGlobalModel(ctx context.Context, orgID, modelOrAlias string) *domain.GlobalModel {
	if mg, err := v.repo.GetModelGroupByAlias(ctx, orgID, modelOrAlias); err == nil && mg != nil {
		if deps, err := v.repo.ListDeploymentsByGroup(ctx, mg.ID); err == nil && len(deps) > 0 && deps[0].GlobalModel != nil {
			return deps[0].GlobalModel
		}
	}
	if gm, err := v.repo.GetGlobalModel(ctx, modelOrAlias); err == nil {
		return gm
	}
	return nil
}
