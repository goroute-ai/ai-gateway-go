package router

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

var openAIOnlyExtraParams = []string{
	"logprobs",
	"top_logprobs",
	"logit_bias",
	"service_tier",
	"store",
	"prediction",
	"audio",
	"modalities",
	"web_search_options",
	"frequency_penalty",
	"presence_penalty",
	"seed",
	"n",
}

type droppedParamsObserverKey struct{}

// WithDroppedParamsObserver attaches a callback invoked once a target deployment's
// unsupported parameters are stripped prior to upstream dispatch.
func WithDroppedParamsObserver(ctx context.Context, fn func([]string)) context.Context {
	if ctx == nil || fn == nil {
		return ctx
	}
	return context.WithValue(ctx, droppedParamsObserverKey{}, fn)
}

func notifyDroppedParams(ctx context.Context, params []string) {
	if ctx == nil {
		return
	}
	if fn, ok := ctx.Value(droppedParamsObserverKey{}).(func([]string)); ok && fn != nil {
		fn(params)
	}
}

func resolveDropUnsupportedParams(routerDefault bool, group *domain.ModelGroup, req *domain.CanonicalChatRequest) bool {
	drop := routerDefault || (group != nil && group.DropUnsupportedParams)
	if req != nil && req.GoRouteExtensions != nil && req.GoRouteExtensions.DropUnsupportedParams != nil {
		drop = *req.GoRouteExtensions.DropUnsupportedParams
	}
	return drop
}

func resolveEffectiveStrategy(group *domain.ModelGroup, req *domain.CanonicalChatRequest, allowOverride bool) domain.RoutingStrategy {
	if allowOverride && req != nil && req.GoRouteExtensions != nil {
		if raw := strings.TrimSpace(req.GoRouteExtensions.RoutingStrategy); raw != "" {
			candidate := domain.NormalizeRoutingStrategy(domain.RoutingStrategy(raw))
			if domain.IsValidRoutingStrategy(candidate) {
				return candidate
			}
		}
	}
	if group != nil && strings.TrimSpace(string(group.RoutingStrategy)) != "" {
		normalized := domain.NormalizeRoutingStrategy(group.RoutingStrategy)
		if domain.IsValidRoutingStrategy(normalized) {
			return normalized
		}
		return normalized
	}
	return domain.StrategyWeightedShuffle
}

func isOpenAIWireProvider(p domain.ProviderType) bool {
	return p != domain.ProviderAnthropic
}

func isReasoningSeriesModel(modelName string) bool {
	base := strings.ToLower(strings.TrimSpace(modelName))
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	return strings.HasPrefix(base, "o1") || strings.HasPrefix(base, "o3") || strings.HasPrefix(base, "o4")
}

// sanitizeRequestForDeployment returns a safe shallow clone of req adapted to dep's
// declared capabilities and model/provider parameter constraints when dropEnabled is true.
func sanitizeRequestForDeployment(req *domain.CanonicalChatRequest, dep *domain.Deployment, dropEnabled bool) (domain.CanonicalChatRequest, []string) {
	if req == nil {
		return domain.CanonicalChatRequest{}, nil
	}
	reqCopy := *req
	if !dropEnabled || dep == nil || dep.GlobalModel == nil {
		return reqCopy, nil
	}

	gm := dep.GlobalModel
	caps := gm.ResolveCapabilities()
	var dropped []string
	extraCloned := false
	stripExtra := func(k string) {
		if len(reqCopy.ExtraParams) == 0 {
			return
		}
		if _, ok := reqCopy.ExtraParams[k]; !ok {
			return
		}
		if !extraCloned {
			reqCopy.ExtraParams = maps.Clone(reqCopy.ExtraParams)
			extraCloned = true
		}
		delete(reqCopy.ExtraParams, k)
		dropped = append(dropped, k)
	}

	if caps.Tools == domain.CapabilityUnsupported {
		if len(reqCopy.Tools) > 0 {
			reqCopy.Tools = nil
			dropped = append(dropped, "tools")
		}
		if reqCopy.ToolChoice != nil {
			reqCopy.ToolChoice = nil
			dropped = append(dropped, "tool_choice")
		}
		stripExtra("parallel_tool_calls")
	}

	if caps.StructuredOutputs == domain.CapabilityUnsupported && reqCopy.ResponseFormat != nil {
		reqCopy.ResponseFormat = nil
		dropped = append(dropped, "response_format")
	}

	if caps.Reasoning == domain.CapabilityUnsupported {
		if strings.TrimSpace(reqCopy.ReasoningEffort) != "" {
			reqCopy.ReasoningEffort = ""
			dropped = append(dropped, "reasoning_effort")
		}
		stripExtra("thinking")
		stripExtra("thinking_budget")
	}

	if gm.MaxOutputTokens > 0 && reqCopy.MaxTokens != nil && *reqCopy.MaxTokens > gm.MaxOutputTokens {
		clamped := gm.MaxOutputTokens
		reqCopy.MaxTokens = &clamped
		dropped = append(dropped, "max_tokens")
	}

	if isReasoningSeriesModel(gm.ModelName) {
		if reqCopy.Temperature != nil {
			reqCopy.Temperature = nil
			dropped = append(dropped, "temperature")
		}
		if reqCopy.TopP != nil {
			reqCopy.TopP = nil
			dropped = append(dropped, "top_p")
		}
	}

	if !isOpenAIWireProvider(gm.Provider) && len(reqCopy.ExtraParams) > 0 {
		for _, k := range openAIOnlyExtraParams {
			stripExtra(k)
		}
	}

	if len(dropped) == 0 {
		return reqCopy, nil
	}
	slices.Sort(dropped)
	dropped = slices.Compact(dropped)
	return reqCopy, dropped
}

func formatRedactedFallbackError(groupAlias, depID string, err error) string {
	g := sanitizeHeaderToken(groupAlias, "-")
	d := sanitizeHeaderToken(depID, "-")
	status := 0
	code := "upstream_error"
	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) && gwErr != nil {
		status = gwErr.StatusCode
		if c := sanitizeHeaderToken(gwErr.Code, ""); c != "" {
			code = c
		} else if t := sanitizeHeaderToken(string(gwErr.Type), ""); t != "" {
			code = t
		}
	} else if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
			code = "timeout"
		} else if errors.Is(err, context.Canceled) {
			code = "canceled"
		}
	}
	if status > 0 {
		return fmt.Sprintf("%s/%s:%d:%s", g, d, status, code)
	}
	return fmt.Sprintf("%s/%s:%s", g, d, code)
}

func sanitizeHeaderToken(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= ' ' || c == ';' || c == ':' || c == '/' {
			b.WriteByte('_')
		} else if c < 0x7f {
			b.WriteByte(c)
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return fallback
	}
	return out
}
