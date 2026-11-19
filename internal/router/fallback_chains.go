package router

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"slices"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// FailureCategory classifies an execution error to select the appropriate specialized fallback chain.
type FailureCategory string

const (
	CategoryGeneral          FailureCategory = "general"
	CategoryContextWindow    FailureCategory = "context_window"
	CategoryContentPolicy    FailureCategory = "content_policy"
	CategoryAuth             FailureCategory = "auth"
	CategorySaturation       FailureCategory = "saturation"
	CategoryUnsupportedParam FailureCategory = "unsupported_param"
	CategoryNonRetryable     FailureCategory = "non_retryable"
)

// FallbackHop represents a resolved model group in a specialized fallback chain
// along with optional per-target request parameter overrides.
type FallbackHop struct {
	Group     *domain.ModelGroup
	Overrides map[string]any
	Category  FailureCategory
}

// classifyFailureCategory categorizes an attempt error for specialized fallback routing.
// Local guardrail blocks always classify as CategoryNonRetryable so fallback chains can never bypass them.
func classifyFailureCategory(err error) FailureCategory {
	return classifyFailureCategoryWithOptions(err, false)
}

func classifyFailureCategoryWithOptions(err error, fallbackOnUnsupportedParams bool) FailureCategory {
	if err == nil {
		return CategoryGeneral
	}

	var gwErr *domain.GatewayError
	hasGW := errors.As(err, &gwErr) && gwErr != nil

	var codeLower string
	var msgLower string
	if hasGW {
		codeLower = strings.ToLower(strings.TrimSpace(gwErr.Code))
		msgLower = strings.ToLower(gwErr.Message)
	}
	errLower := strings.ToLower(err.Error())

	if isLocalGuardrailError(gwErr, hasGW, codeLower, errLower) {
		return CategoryNonRetryable
	}

	if hasGW && (gwErr.AuthFailure ||
		gwErr.Type == domain.ErrorTypeAuthentication ||
		gwErr.StatusCode == http.StatusUnauthorized ||
		(gwErr.StatusCode == http.StatusForbidden && gwErr.Provider != "")) {
		return CategoryAuth
	}

	isRateLimit := hasGW && (gwErr.StatusCode == http.StatusTooManyRequests || gwErr.Type == domain.ErrorTypeRateLimit)
	if !isRateLimit && isContextWindowError(gwErr, hasGW, codeLower, msgLower, errLower) {
		return CategoryContextWindow
	}

	if isUpstreamContentPolicyError(codeLower, msgLower, errLower) {
		return CategoryContentPolicy
	}

	if fallbackOnUnsupportedParams && hasGW && isUnsupportedParamError(gwErr, codeLower, msgLower, errLower) {
		return CategoryUnsupportedParam
	}

	if hasGW && !gwErr.Retryable && isClientSchemaError(gwErr) {
		return CategoryNonRetryable
	}

	return CategoryGeneral
}

func isUnsupportedParamError(gwErr *domain.GatewayError, codeLower, msgLower, errLower string) bool {
	if gwErr == nil {
		return false
	}
	if gwErr.StatusCode != 0 &&
		gwErr.StatusCode != http.StatusBadRequest &&
		gwErr.StatusCode != http.StatusUnprocessableEntity &&
		gwErr.Type != domain.ErrorTypeInvalidRequest {
		return false
	}
	combined := codeLower + " " + msgLower + " " + errLower
	if strings.Contains(combined, "invalid json") ||
		strings.Contains(combined, "unexpected end of json") ||
		strings.Contains(combined, "cannot unmarshal") {
		return false
	}
	return strings.Contains(combined, "unsupported_parameter") ||
		strings.Contains(combined, "unsupported parameter") ||
		strings.Contains(combined, "unsupported_value") ||
		strings.Contains(combined, "unsupported value") ||
		strings.Contains(combined, "unknown parameter") ||
		strings.Contains(combined, "unrecognized request argument") ||
		strings.Contains(combined, "extra inputs are not permitted") ||
		strings.Contains(combined, "invalid_parameter") ||
		strings.Contains(combined, "does not support") ||
		strings.Contains(combined, "not supported by this model") ||
		strings.Contains(combined, "not supported with this model")
}

func isLocalGuardrailError(gwErr *domain.GatewayError, hasGW bool, codeLower, errLower string) bool {
	if hasGW {
		if codeLower == "guardrail_blocked" || strings.HasPrefix(codeLower, "guardrail_") {
			return true
		}
		if codeLower == "tool_hash_mismatch" || codeLower == "tool_poisoning_detected" {
			return true
		}
		if gwErr.Type == domain.ErrorTypePermission && !gwErr.AuthFailure {
			return true
		}
		return false
	}
	return strings.Contains(errLower, "guardrail_blocked")
}

func isContextWindowError(gwErr *domain.GatewayError, hasGW bool, codeLower, msgLower, errLower string) bool {
	if codeLower == "context_length_exceeded" {
		return true
	}
	if hasGW && gwErr.StatusCode != 0 &&
		gwErr.StatusCode != http.StatusBadRequest &&
		gwErr.StatusCode != http.StatusRequestEntityTooLarge &&
		gwErr.StatusCode != http.StatusUnprocessableEntity &&
		gwErr.Type != domain.ErrorTypeInvalidRequest {
		return false
	}
	combined := codeLower + " " + msgLower + " " + errLower
	return strings.Contains(combined, "context_length_exceeded") ||
		strings.Contains(combined, "maximum context length") ||
		strings.Contains(combined, "prompt is too long") ||
		strings.Contains(combined, "token limit")
}

func isUpstreamContentPolicyError(codeLower, msgLower, errLower string) bool {
	combined := codeLower + " " + msgLower + " " + errLower
	return strings.Contains(combined, "content_policy") ||
		strings.Contains(combined, "content_filter") ||
		strings.Contains(combined, "safety_blocked") ||
		strings.Contains(combined, "policy_violation")
}

func isClientSchemaError(gwErr *domain.GatewayError) bool {
	if gwErr.Type == domain.ErrorTypeInvalidRequest {
		return true
	}
	return (gwErr.StatusCode == http.StatusBadRequest || gwErr.StatusCode == http.StatusUnprocessableEntity) &&
		gwErr.Type != domain.ErrorTypeUpstream &&
		gwErr.Type != domain.ErrorTypeServer &&
		gwErr.Type != domain.ErrorTypeRateLimit
}

// buildSpecializedFallbackChain resolves the ordered fallback hops for primary under category,
// enforcing tenant isolation, active status, cycle prevention via visited, and maxDepth (default 16).
func buildSpecializedFallbackChain(
	ctx context.Context,
	repo storage.Repository,
	primary *domain.ModelGroup,
	category FailureCategory,
	defaultFallbacks []domain.FallbackTarget,
	maxDepth int,
	visited map[string]struct{},
) []FallbackHop {
	if primary == nil || repo == nil || category == CategoryNonRetryable {
		return nil
	}
	if maxDepth <= 0 {
		maxDepth = maxFallbackDepth
	}
	if visited == nil {
		visited = make(map[string]struct{})
	}
	if primaryKey := groupVisitKey(primary); primaryKey != "" {
		visited[primaryKey] = struct{}{}
	}

	var hops []FallbackHop
	var visit func(current *domain.ModelGroup, depth int)
	visit = func(current *domain.ModelGroup, depth int) {
		if current == nil || depth >= maxDepth {
			return
		}
		targets := selectFallbackTargets(current, category, defaultFallbacks, depth == 0)
		for _, target := range targets {
			targetRef := strings.TrimSpace(target.GroupAliasOrID)
			if targetRef == "" {
				continue
			}
			fbGroup, err := repo.GetModelGroupByID(ctx, targetRef)
			if err != nil || fbGroup == nil {
				fbGroup, err = repo.GetModelGroupByAlias(ctx, primary.OrgID, targetRef)
			}
			if err != nil || fbGroup == nil || !fbGroup.IsActive || fbGroup.OrgID != primary.OrgID {
				continue
			}
			key := groupVisitKey(fbGroup)
			if _, seen := visited[key]; seen {
				continue
			}
			visited[key] = struct{}{}
			hops = append(hops, FallbackHop{
				Group:     fbGroup,
				Overrides: cloneOverrideMap(target.Overrides),
				Category:  category,
			})
			visit(fbGroup, depth+1)
		}
	}

	visit(primary, 0)
	return hops
}

func groupVisitKey(mg *domain.ModelGroup) string {
	if mg == nil {
		return ""
	}
	if mg.ID != "" {
		return mg.ID
	}
	return mg.Alias
}

func selectFallbackTargets(
	group *domain.ModelGroup,
	category FailureCategory,
	defaultFallbacks []domain.FallbackTarget,
	isRoot bool,
) []domain.FallbackTarget {
	switch category {
	case CategoryContextWindow:
		if len(group.ContextWindowFallbacks) > 0 {
			return group.ContextWindowFallbacks
		}
	case CategoryContentPolicy:
		if len(group.ContentPolicyFallbacks) > 0 {
			return group.ContentPolicyFallbacks
		}
	case CategorySaturation:
		if len(group.SaturationFallbacks) > 0 {
			return group.SaturationFallbacks
		}
	}

	total := len(group.FallbackTargets) + len(group.FallbackGroupIDs)
	if isRoot {
		total += len(defaultFallbacks)
	}
	if total == 0 {
		return nil
	}

	targets := make([]domain.FallbackTarget, 0, total)
	targets = append(targets, group.FallbackTargets...)
	for _, id := range group.FallbackGroupIDs {
		targets = append(targets, domain.FallbackTarget{GroupAliasOrID: id})
	}
	if isRoot {
		targets = append(targets, defaultFallbacks...)
	}
	return targets
}

func cloneOverrideMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// applyFallbackOverrides returns a shallow clone of req with supported parameter overrides applied
// (max_tokens, temperature, top_p, reasoning_effort, stop) without mutating req.
func applyFallbackOverrides(req *domain.CanonicalChatRequest, overrides map[string]any) *domain.CanonicalChatRequest {
	if req == nil {
		return nil
	}
	cloned := *req
	if req.MaxTokens != nil {
		v := *req.MaxTokens
		cloned.MaxTokens = &v
	}
	if req.Temperature != nil {
		v := *req.Temperature
		cloned.Temperature = &v
	}
	if req.TopP != nil {
		v := *req.TopP
		cloned.TopP = &v
	}
	if req.Stop != nil {
		cloned.Stop = slices.Clone(req.Stop)
	}

	if len(overrides) == 0 {
		return &cloned
	}

	if raw, ok := overrides["max_tokens"]; ok && raw != nil {
		if v, ok := overrideInt(raw); ok {
			cloned.MaxTokens = &v
		}
	}
	if raw, ok := overrides["temperature"]; ok && raw != nil {
		if v, ok := overrideFloat64(raw); ok {
			cloned.Temperature = &v
		}
	}
	if raw, ok := overrides["top_p"]; ok && raw != nil {
		if v, ok := overrideFloat64(raw); ok {
			cloned.TopP = &v
		}
	}
	if raw, ok := overrides["reasoning_effort"]; ok && raw != nil {
		if s, ok := raw.(string); ok {
			cloned.ReasoningEffort = s
		}
	}
	if raw, ok := overrides["stop"]; ok && raw != nil {
		if stop, ok := overrideStringSlice(raw); ok {
			cloned.Stop = stop
		}
	}
	return &cloned
}

func overrideInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		if v <= math.MaxInt {
			return int(v), true
		}
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return int(v), true
		}
	case float32:
		f := float64(v)
		if !math.IsNaN(f) && !math.IsInf(f, 0) {
			return int(f), true
		}
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n), true
		}
		if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return int(f), true
		}
	case *int:
		if v != nil {
			return *v, true
		}
	}
	return 0, false
}

func overrideFloat64(raw any) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return v, true
		}
	case float32:
		f := float64(v)
		if !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case json.Number:
		if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	case *float64:
		if v != nil && !math.IsNaN(*v) && !math.IsInf(*v, 0) {
			return *v, true
		}
	}
	return 0, false
}

func overrideStringSlice(raw any) ([]string, bool) {
	switch v := raw.(type) {
	case []string:
		return slices.Clone(v), true
	case string:
		return []string{v}, true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}
