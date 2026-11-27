package guardrails

import (
	"context"
	"slices"
	"sort"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// ResolveContext carries the tenant and lifecycle hook used to resolve active external guardrails.
type ResolveContext struct {
	OrgID string
	Hook  domain.GuardrailHook
}

// ResolvedGuardrail is a ready-to-execute external guardrail definition ordered by precedence.
type ResolvedGuardrail struct {
	Definition      *domain.GuardrailDefinition
	EffectiveConfig map[string]any
	TimeoutMs       int
	FailOpen        bool
	Precedence      int
}

// ResolveEffectiveGuardrails loads an organization's enabled guardrail definitions matching rc.Hook.
func ResolveEffectiveGuardrails(ctx context.Context, repo storage.Repository, rc ResolveContext) ([]ResolvedGuardrail, error) {
	if repo == nil || rc.OrgID == "" {
		return nil, nil
	}
	defs, err := repo.ListGuardrailDefinitions(ctx, rc.OrgID, true)
	if err != nil {
		return nil, err
	}
	return Resolve(defs, rc), nil
}

// Resolve filters and sorts enabled guardrail definitions matching rc.Hook.
func Resolve(defs []*domain.GuardrailDefinition, rc ResolveContext) []ResolvedGuardrail {
	if len(defs) == 0 {
		return nil
	}
	out := make([]ResolvedGuardrail, 0, len(defs))
	for _, def := range defs {
		if def == nil || !def.Enabled {
			continue
		}
		if rc.Hook != "" && !matchesHook(def, rc.Hook) {
			continue
		}
		out = append(out, ResolvedGuardrail{
			Definition:      def,
			EffectiveConfig: cloneConfigMap(def.Config),
			TimeoutMs:       def.TimeoutMs,
			FailOpen:        def.FailOpen,
			Precedence:      def.Precedence,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Precedence != out[j].Precedence {
			return out[i].Precedence < out[j].Precedence
		}
		if !out[i].Definition.CreatedAt.Equal(out[j].Definition.CreatedAt) {
			return out[i].Definition.CreatedAt.Before(out[j].Definition.CreatedAt)
		}
		return out[i].Definition.ID < out[j].Definition.ID
	})
	return out
}

func matchesHook(def *domain.GuardrailDefinition, hook domain.GuardrailHook) bool {
	if len(def.EventHooks) == 0 {
		return hook == domain.GuardrailHookPreCall
	}
	if slices.Contains(def.EventHooks, hook) {
		return true
	}
	// A guardrail configured with logging_only executes in shadow mode on pre_call / post_call.
	if slices.Contains(def.EventHooks, domain.GuardrailHookLoggingOnly) &&
		(hook == domain.GuardrailHookPreCall || hook == domain.GuardrailHookPostCall) {
		return true
	}
	return false
}

func isLoggingOnlyDefinition(def *domain.GuardrailDefinition, hook domain.GuardrailHook) bool {
	if def == nil {
		return false
	}
	if hook == domain.GuardrailHookLoggingOnly {
		return true
	}
	if len(def.EventHooks) == 0 {
		return false
	}
	return slices.Contains(def.EventHooks, domain.GuardrailHookLoggingOnly) && !slices.Contains(def.EventHooks, hook)
}

func cloneConfigMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = cloneConfigValue(v)
	}
	return dst
}

func cloneConfigValue(v any) any {
	switch tv := v.(type) {
	case map[string]any:
		return cloneConfigMap(tv)
	case []any:
		cp := make([]any, len(tv))
		for i, item := range tv {
			cp[i] = cloneConfigValue(item)
		}
		return cp
	case []string:
		return slices.Clone(tv)
	default:
		return v
	}
}
