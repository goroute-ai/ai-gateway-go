package validation

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const maxFallbackLookupDepth = 16

var validRoles = []string{"system", "developer", "user", "assistant", "tool"}

// Validator enforces schema, parameter bounds, model capabilities, and context-window limits
// prior to routing and load balancing.
type Validator struct {
	repo                  storage.Repository
	allowDefaultFallbacks atomic.Bool
}

func NewValidator(repo storage.Repository) *Validator {
	return &Validator{repo: repo}
}

// SetAllowDefaultFallbacks configures whether pre-flight context-window validation
// permits oversized prompts when router-level default fallbacks are configured.
func (v *Validator) SetAllowDefaultFallbacks(allow bool) {
	if v == nil {
		return
	}
	v.allowDefaultFallbacks.Store(allow)
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
		mg, deps, gm := v.resolveTargetContext(ctx, orgID, requested)
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
			if req.ResponseFormat != nil && req.ResponseFormat.Type == "json_schema" && caps.StructuredOutputs == domain.CapabilityUnsupported {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "capability_not_supported",
					Message:    fmt.Sprintf("Model %q does not support structured outputs (json_schema)", gm.ModelName),
				}
			}
			if req.ReasoningEffort != "" && caps.Reasoning == domain.CapabilityUnsupported {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "capability_not_supported",
					Message:    fmt.Sprintf("Model %q does not support reasoning_effort", gm.ModelName),
				}
			}
			if gm.MaxInputTokens > 0 && estimatedPromptTokens > gm.MaxInputTokens && !v.canRouteLargerContext(ctx, mg, deps, estimatedPromptTokens) {
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

	for _, m := range req.Messages {
		for _, p := range m.Parts {
			if p.Type == "document" && p.Document != nil {
				switch strings.ToLower(strings.TrimSpace(p.Document.MimeType)) {
				case "application/pdf", "text/plain", "text/csv", "text/markdown", "text/html":
				default:
					return &domain.GatewayError{
						StatusCode: http.StatusBadRequest,
						Type:       domain.ErrorTypeInvalidRequest,
						Code:       "unsupported_document_mime_type",
						Message:    fmt.Sprintf("Document MIME type %q is not supported", p.Document.MimeType),
					}
				}
				if p.Document.Data != "" && base64.StdEncoding.DecodedLen(len(p.Document.Data)) > 25*1024*1024 {
					return &domain.GatewayError{
						StatusCode: http.StatusRequestEntityTooLarge,
						Type:       domain.ErrorTypeInvalidRequest,
						Code:       "document_too_large",
						Message:    "Document payload exceeds 25 MiB limit",
					}
				}
			}
		}
	}

	return nil
}

func (v *Validator) resolveTargetContext(ctx context.Context, orgID, modelOrAlias string) (*domain.ModelGroup, []*domain.Deployment, *domain.GlobalModel) {
	if mg, err := v.repo.GetModelGroupByAlias(ctx, orgID, modelOrAlias); err == nil && mg != nil {
		deps, err := v.repo.ListDeploymentsByGroup(ctx, mg.ID)
		if err == nil {
			var fallbackGM *domain.GlobalModel
			for _, d := range deps {
				if d == nil || d.GlobalModel == nil {
					continue
				}
				if d.Status != domain.DeploymentStatusDisabled {
					return mg, deps, d.GlobalModel
				}
				if fallbackGM == nil {
					fallbackGM = d.GlobalModel
				}
			}
			if fallbackGM != nil {
				return mg, deps, fallbackGM
			}
		}
		if gm, err := v.repo.GetGlobalModel(ctx, modelOrAlias); err == nil {
			return mg, deps, gm
		}
		return mg, deps, nil
	}
	if gm, err := v.repo.GetGlobalModel(ctx, modelOrAlias); err == nil {
		return nil, nil, gm
	}
	return nil, nil, nil
}

func (v *Validator) canRouteLargerContext(ctx context.Context, mg *domain.ModelGroup, deps []*domain.Deployment, estimatedPromptTokens int) bool {
	if v.allowDefaultFallbacks.Load() {
		return true
	}
	if mg == nil {
		return false
	}
	if len(mg.ContextWindowFallbacks) > 0 {
		return true
	}
	if anyDeploymentFits(deps, estimatedPromptTokens) {
		return true
	}
	return v.hasFittingFallbackGroup(ctx, mg, estimatedPromptTokens)
}

func anyDeploymentFits(deps []*domain.Deployment, estimatedPromptTokens int) bool {
	for _, d := range deps {
		if d == nil || d.GlobalModel == nil || d.Status == domain.DeploymentStatusDisabled {
			continue
		}
		if d.GlobalModel.MaxInputTokens >= estimatedPromptTokens {
			return true
		}
	}
	return false
}

func (v *Validator) hasFittingFallbackGroup(ctx context.Context, root *domain.ModelGroup, estimatedPromptTokens int) bool {
	if root == nil || v.repo == nil {
		return false
	}
	visited := map[string]struct{}{}
	if root.ID != "" {
		visited[root.ID] = struct{}{}
	}
	var walk func(current *domain.ModelGroup, depth int) bool
	walk = func(current *domain.ModelGroup, depth int) bool {
		if current == nil || depth >= maxFallbackLookupDepth {
			return false
		}
		refs := make([]string, 0, len(current.FallbackTargets)+len(current.FallbackGroupIDs))
		for _, t := range current.FallbackTargets {
			refs = append(refs, t.GroupAliasOrID)
		}
		refs = append(refs, current.FallbackGroupIDs...)
		for _, rawRef := range refs {
			ref := strings.TrimSpace(rawRef)
			if ref == "" {
				continue
			}
			fbGroup, err := v.repo.GetModelGroupByID(ctx, ref)
			if err != nil || fbGroup == nil {
				fbGroup, err = v.repo.GetModelGroupByAlias(ctx, root.OrgID, ref)
			}
			if err != nil || fbGroup == nil || !fbGroup.IsActive || fbGroup.OrgID != root.OrgID {
				continue
			}
			if _, seen := visited[fbGroup.ID]; seen {
				continue
			}
			visited[fbGroup.ID] = struct{}{}
			if len(fbGroup.ContextWindowFallbacks) > 0 {
				return true
			}
			if deps, err := v.repo.ListDeploymentsByGroup(ctx, fbGroup.ID); err == nil && anyDeploymentFits(deps, estimatedPromptTokens) {
				return true
			}
			if walk(fbGroup, depth+1) {
				return true
			}
		}
		return false
	}
	return walk(root, 0)
}
