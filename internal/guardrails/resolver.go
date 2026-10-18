package guardrails

import (
	"context"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// ResolveContext describes the runtime identity, routing, and request override context
// used to resolve which named guardrails apply to a specific lifecycle hook.
type ResolveContext struct {
	OrgID            string
	TeamID           string
	VirtualKeyID     string
	EndUserID        string
	Model            string
	ModelGroupID     string
	CallerRoles      []string
	Tags             []string
	RequestOverrides []domain.GuardrailRequestOverride
	Hook             domain.GuardrailHook
	IsStreaming      bool
}

// ResolvedCandidate is a single active GuardrailDefinition candidate within a logical
// named guardrail group, carrying its merged admin bindings and validated request overrides.
type ResolvedCandidate struct {
	Definition      *domain.GuardrailDefinition
	EffectiveAction domain.GuardrailAction
	EffectiveConfig map[string]any
	TimeoutMs       int
	FailOpen        bool
	Weight          int
	DefaultOn       bool
	IsLocked        bool
}

// ResolvedGuardrail represents a deterministic, precedence-ordered logical guardrail
// containing one or more active candidates (for weighted load balancing when sharing a Name).
type ResolvedGuardrail struct {
	Name            string
	Precedence      int
	DefaultOn       bool
	IsLocked        bool
	EffectiveAction domain.GuardrailAction
	EffectiveConfig map[string]any
	TimeoutMs       int
	FailOpen        bool
	Candidates      []*ResolvedCandidate
}

// ResolveEffectiveGuardrails loads an organization's active guardrail definitions and bindings
// from repo and resolves the ordered guardrails matching rc.
func ResolveEffectiveGuardrails(ctx context.Context, repo storage.Repository, rc ResolveContext) ([]ResolvedGuardrail, error) {
	if repo == nil || rc.OrgID == "" {
		return nil, nil
	}
	if rc.ModelGroupID == "" && rc.Model != "" {
		if mg, err := repo.GetModelGroupByAlias(ctx, rc.OrgID, rc.Model); err == nil && mg != nil {
			rc.ModelGroupID = mg.ID
		}
	}
	eff, err := repo.ListEffectiveGuardrailsForOrg(ctx, rc.OrgID)
	if err != nil {
		return nil, err
	}
	return Resolve(eff, rc), nil
}

// Resolve filters, merges hierarchical bindings, enforces anti-bypass locks, and orders
// active guardrail definitions for rc deterministically by Precedence (ascending), Name, and ID.
func Resolve(eff *storage.EffectiveGuardrails, rc ResolveContext) []ResolvedGuardrail {
	if eff == nil || len(eff.Definitions) == 0 {
		return nil
	}

	tagSet := make(map[string]struct{}, len(rc.Tags))
	for _, t := range rc.Tags {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" {
			tagSet[trimmed] = struct{}{}
		}
	}

	overrideByName := make(map[string]domain.GuardrailRequestOverride, len(rc.RequestOverrides))
	for _, ov := range rc.RequestOverrides {
		key := strings.ToLower(strings.TrimSpace(ov.Name))
		if key != "" {
			overrideByName[key] = ov
		}
	}

	// Step 1: Filter definitions by status, org, role, hook/mode_rule, and stream_scope,
	// and group eligible candidates by logical guardrail Name (falling back to ID).
	type groupAccumulator struct {
		name       string
		precedence int
		defaultOn  bool
		candidates []*domain.GuardrailDefinition
	}
	groups := make(map[string]*groupAccumulator)

	for _, def := range eff.Definitions {
		if def == nil || def.Status != domain.GuardrailStatusActive {
			continue
		}
		if rc.OrgID != "" && def.OrgID != "" && def.OrgID != rc.OrgID {
			continue
		}
		if !matchesEnabledRoles(def.EnabledRoles, rc.CallerRoles) {
			continue
		}
		if !matchesHook(def, tagSet, rc.Hook) {
			continue
		}
		if !matchesStreamScope(def.EffectiveStreamScope(rc.Hook), rc.IsStreaming) {
			continue
		}

		groupKey := strings.TrimSpace(def.Name)
		if groupKey == "" {
			groupKey = def.ID
		}
		acc, ok := groups[groupKey]
		if !ok {
			acc = &groupAccumulator{
				name:       groupKey,
				precedence: def.Precedence,
			}
			groups[groupKey] = acc
		}
		if def.Precedence < acc.precedence {
			acc.precedence = def.Precedence
		}
		if def.DefaultOn {
			acc.defaultOn = true
		}
		acc.candidates = append(acc.candidates, def)
	}

	if len(groups) == 0 {
		return nil
	}

	// Step 2: Evaluate hierarchical bindings + request overrides + anti-bypass per group.
	out := make([]ResolvedGuardrail, 0, len(groups))
	for _, acc := range groups {
		sort.Slice(acc.candidates, func(i, j int) bool {
			if acc.candidates[i].Precedence != acc.candidates[j].Precedence {
				return acc.candidates[i].Precedence < acc.candidates[j].Precedence
			}
			return acc.candidates[i].ID < acc.candidates[j].ID
		})

		ov, hasOverride := findRequestOverride(overrideByName, acc.name, acc.candidates)

		// Collect matching bindings per candidate and determine group-level lock/inclusion.
		groupHasBinding := false
		groupIsLocked := false
		candidateBindings := make([][]matchedBinding, len(acc.candidates))
		for idx, def := range acc.candidates {
			matched := matchBindingsForDef(eff.Bindings, def, rc, tagSet)
			candidateBindings[idx] = matched
			if len(matched) > 0 {
				groupHasBinding = true
				for _, mb := range matched {
					if mb.binding.IsLocked {
						groupIsLocked = true
					}
				}
			}
		}

		included := acc.defaultOn || groupHasBinding
		if hasOverride {
			if ov.Enabled != nil && !*ov.Enabled {
				// Anti-bypass: request overrides must never disable default_on or locked guardrails.
				if !acc.defaultOn && !groupIsLocked {
					included = false
				}
			} else {
				// Enabled == nil (action/config override) or Enabled == true opts the guardrail in.
				included = true
			}
		}
		if !included {
			continue
		}

		resolvedCandidates := make([]*ResolvedCandidate, 0, len(acc.candidates))
		for idx, def := range acc.candidates {
			cand := buildResolvedCandidate(def, candidateBindings[idx], acc.defaultOn, groupIsLocked, hasOverride, ov)
			resolvedCandidates = append(resolvedCandidates, cand)
		}

		primary := resolvedCandidates[0]
		out = append(out, ResolvedGuardrail{
			Name:            acc.name,
			Precedence:      acc.precedence,
			DefaultOn:       acc.defaultOn,
			IsLocked:        groupIsLocked,
			EffectiveAction: primary.EffectiveAction,
			EffectiveConfig: cloneConfigMap(primary.EffectiveConfig),
			TimeoutMs:       primary.TimeoutMs,
			FailOpen:        primary.FailOpen,
			Candidates:      resolvedCandidates,
		})
	}

	// Step 3: Deterministic ordering by Precedence ascending, then Name, then primary Definition ID.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Precedence != out[j].Precedence {
			return out[i].Precedence < out[j].Precedence
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		var idI, idJ string
		if len(out[i].Candidates) > 0 && out[i].Candidates[0].Definition != nil {
			idI = out[i].Candidates[0].Definition.ID
		}
		if len(out[j].Candidates) > 0 && out[j].Candidates[0].Definition != nil {
			idJ = out[j].Candidates[0].Definition.ID
		}
		return idI < idJ
	})

	return out
}

func matchesEnabledRoles(enabledRoles, callerRoles []string) bool {
	if len(enabledRoles) == 0 {
		return true
	}
	if len(callerRoles) == 0 {
		return false
	}
	for _, er := range enabledRoles {
		erNorm := strings.ToLower(strings.TrimSpace(er))
		if erNorm == "" {
			continue
		}
		if erNorm == "*" {
			return true
		}
		for _, cr := range callerRoles {
			if strings.EqualFold(strings.TrimSpace(cr), erNorm) {
				return true
			}
		}
	}
	return false
}

func matchesHook(def *domain.GuardrailDefinition, tagSet map[string]struct{}, hook domain.GuardrailHook) bool {
	if hook == "" {
		return true
	}
	effectiveHooks := resolveEffectiveHooks(def, tagSet)
	return slices.Contains(effectiveHooks, hook)
}

func resolveEffectiveHooks(def *domain.GuardrailDefinition, tagSet map[string]struct{}) []domain.GuardrailHook {
	if def.ModeRule != nil {
		if len(def.ModeRule.Tags) > 0 && len(tagSet) > 0 {
			var matched []domain.GuardrailHook
			tagMatched := false
			for tag := range tagSet {
				if hooks, ok := def.ModeRule.Tags[tag]; ok {
					tagMatched = true
					for _, h := range hooks {
						if !slices.Contains(matched, h) {
							matched = append(matched, h)
						}
					}
				}
			}
			if tagMatched {
				return matched
			}
		}
		if len(def.ModeRule.Default) > 0 {
			return def.ModeRule.Default
		}
	}
	return def.EventHooks
}

func matchesStreamScope(scope domain.StreamScope, isStreaming bool) bool {
	switch scope {
	case "", domain.StreamScopeBoth:
		return true
	case domain.StreamScopeStreaming:
		return isStreaming
	case domain.StreamScopeNonStreaming:
		return !isStreaming
	default:
		return true
	}
}

type matchedBinding struct {
	binding     *domain.GuardrailBinding
	specificity int
	exactID     bool
}

func matchBindingsForDef(bindings []*domain.GuardrailBinding, def *domain.GuardrailDefinition, rc ResolveContext, tagSet map[string]struct{}) []matchedBinding {
	if len(bindings) == 0 || def == nil {
		return nil
	}
	var out []matchedBinding
	for _, b := range bindings {
		if b == nil {
			continue
		}
		exactID := b.GuardrailID != "" && b.GuardrailID == def.ID
		nameMatch := b.GuardrailName != "" && b.GuardrailName == def.Name
		if !exactID && !nameMatch {
			continue
		}
		if b.OrgID != "" && rc.OrgID != "" && b.OrgID != rc.OrgID {
			continue
		}
		if b.TeamID != "" && b.TeamID != rc.TeamID {
			continue
		}
		if b.VirtualKeyID != "" && b.VirtualKeyID != rc.VirtualKeyID {
			continue
		}
		if b.EndUserID != "" && b.EndUserID != rc.EndUserID {
			continue
		}
		if b.ModelGroupID != "" {
			matchesMG := (rc.ModelGroupID != "" && b.ModelGroupID == rc.ModelGroupID) ||
				(rc.Model != "" && b.ModelGroupID == rc.Model)
			if !matchesMG {
				continue
			}
		}
		if b.Tag != "" {
			if _, ok := tagSet[strings.TrimSpace(b.Tag)]; !ok {
				continue
			}
		}

		// Hierarchical precedence: Org (0) < Team (1) < VirtualKey (2) < EndUser (4) < ModelGroup (8) < Tag (16).
		spec := 0
		if b.TeamID != "" {
			spec |= 1 << 0
		}
		if b.VirtualKeyID != "" {
			spec |= 1 << 1
		}
		if b.EndUserID != "" {
			spec |= 1 << 2
		}
		if b.ModelGroupID != "" {
			spec |= 1 << 3
		}
		if b.Tag != "" {
			spec |= 1 << 4
		}

		out = append(out, matchedBinding{
			binding:     b,
			specificity: spec,
			exactID:     exactID,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].specificity != out[j].specificity {
			return out[i].specificity < out[j].specificity
		}
		if out[i].exactID != out[j].exactID {
			return !out[i].exactID
		}
		if !out[i].binding.UpdatedAt.Equal(out[j].binding.UpdatedAt) {
			return out[i].binding.UpdatedAt.Before(out[j].binding.UpdatedAt)
		}
		return out[i].binding.ID < out[j].binding.ID
	})

	return out
}

func findRequestOverride(byName map[string]domain.GuardrailRequestOverride, groupName string, candidates []*domain.GuardrailDefinition) (domain.GuardrailRequestOverride, bool) {
	if len(byName) == 0 {
		return domain.GuardrailRequestOverride{}, false
	}
	if ov, ok := byName[strings.ToLower(strings.TrimSpace(groupName))]; ok {
		return ov, true
	}
	for _, c := range candidates {
		if c == nil {
			continue
		}
		if ov, ok := byName[strings.ToLower(strings.TrimSpace(c.ID))]; ok {
			return ov, true
		}
	}
	return domain.GuardrailRequestOverride{}, false
}

func buildResolvedCandidate(
	def *domain.GuardrailDefinition,
	bindings []matchedBinding,
	groupDefaultOn bool,
	groupIsLocked bool,
	hasOverride bool,
	ov domain.GuardrailRequestOverride,
) *ResolvedCandidate {
	cfg := cloneConfigMap(def.Config)
	if cfg == nil {
		cfg = make(map[string]any)
	}

	candLocked := groupIsLocked
	for _, mb := range bindings {
		if mb.binding.IsLocked {
			candLocked = true
		}
		mergeConfigMap(cfg, mb.binding.ParamOverrides)
	}

	// Capture admin-configured baseline before applying request overrides.
	adminConfigKeys := make(map[string]struct{}, len(cfg))
	for k := range cfg {
		adminConfigKeys[k] = struct{}{}
	}

	adminAction := extractActionFromConfig(cfg)
	adminMode, _ := cfg["mode"].(string)
	adminFailOpen := def.FailOpen
	if fo, ok := cfg["fail_open"].(bool); ok {
		adminFailOpen = fo
	}
	timeoutMs := def.TimeoutMs
	if tm, ok := intFromAny(cfg["timeout_ms"]); ok && tm > 0 {
		timeoutMs = tm
	}

	effectiveAction := adminAction
	effectiveFailOpen := adminFailOpen
	isProtected := def.DefaultOn || groupDefaultOn || candLocked

	if hasOverride {
		// Apply request Config overrides subject to anti-bypass rules.
		for k, v := range ov.Config {
			keyLower := strings.ToLower(strings.TrimSpace(k))
			if isProtected {
				if isBypassConfigKey(keyLower, v, adminFailOpen, adminMode, adminAction) {
					continue
				}
				if candLocked {
					// Locked bindings protect all admin-specified keys from client overwrite.
					if _, exists := adminConfigKeys[k]; exists {
						continue
					}
				}
			}
			cfg[k] = cloneAny(v)
		}

		// Re-evaluate action from request Config["action"] or explicit ov.Action.
		reqAction := ov.Action
		if reqAction == "" {
			reqAction = extractActionFromConfig(ov.Config)
		}
		if reqAction != "" {
			if isProtected {
				if canUpgradeAction(adminAction, adminMode, reqAction) {
					effectiveAction = reqAction
					cfg["action"] = string(reqAction)
				} else if adminAction != "" {
					cfg["action"] = string(adminAction)
				} else {
					delete(cfg, "action")
				}
			} else {
				effectiveAction = reqAction
				cfg["action"] = string(reqAction)
			}
		}

		if !isProtected {
			if fo, ok := cfg["fail_open"].(bool); ok {
				effectiveFailOpen = fo
			}
		}
	}

	weight := def.Weight
	if weight <= 0 {
		weight = 1
	}

	return &ResolvedCandidate{
		Definition:      def,
		EffectiveAction: effectiveAction,
		EffectiveConfig: cfg,
		TimeoutMs:       timeoutMs,
		FailOpen:        effectiveFailOpen,
		Weight:          weight,
		DefaultOn:       def.DefaultOn || groupDefaultOn,
		IsLocked:        candLocked,
	}
}

func isBypassConfigKey(keyLower string, val any, adminFailOpen bool, adminMode string, adminAction domain.GuardrailAction) bool {
	switch keyLower {
	case "enabled":
		if b, ok := val.(bool); ok && !b {
			return true
		}
	case "fail_open":
		if b, ok := val.(bool); ok && b && !adminFailOpen {
			return true
		}
	case "logging_only":
		if b, ok := val.(bool); ok && b && !strings.EqualFold(adminMode, string(domain.GuardrailModeLoggingOnly)) {
			return true
		}
	case "mode":
		if s, ok := val.(string); ok && strings.EqualFold(strings.TrimSpace(s), string(domain.GuardrailModeLoggingOnly)) &&
			!strings.EqualFold(adminMode, string(domain.GuardrailModeLoggingOnly)) {
			return true
		}
	case "action":
		if s, ok := val.(string); ok {
			return !canUpgradeAction(adminAction, adminMode, domain.GuardrailAction(strings.TrimSpace(s)))
		}
	}
	return false
}

func actionStrictness(action domain.GuardrailAction) int {
	switch domain.GuardrailAction(strings.ToLower(strings.TrimSpace(string(action)))) {
	case domain.GuardrailActionBlock:
		return 3
	case domain.GuardrailActionRedact, "modify":
		return 2
	case domain.GuardrailActionAudit, "flag":
		return 1
	default:
		return 0
	}
}

func canUpgradeAction(adminAction domain.GuardrailAction, adminMode string, reqAction domain.GuardrailAction) bool {
	reqRank := actionStrictness(reqAction)
	if reqRank == 0 {
		return false
	}
	baseAction := adminAction
	if baseAction == "" {
		if strings.EqualFold(strings.TrimSpace(adminMode), string(domain.GuardrailModeLoggingOnly)) {
			baseAction = domain.GuardrailActionAudit
		} else {
			baseAction = domain.GuardrailActionBlock
		}
	}
	return reqRank >= actionStrictness(baseAction)
}

func extractActionFromConfig(cfg map[string]any) domain.GuardrailAction {
	if len(cfg) == 0 {
		return ""
	}
	raw, ok := cfg["action"].(string)
	if !ok {
		return ""
	}
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch domain.GuardrailAction(trimmed) {
	case domain.GuardrailActionBlock, domain.GuardrailActionRedact, domain.GuardrailActionAudit:
		return domain.GuardrailAction(trimmed)
	case "modify":
		return domain.GuardrailActionRedact
	case "flag":
		return domain.GuardrailActionAudit
	default:
		return domain.GuardrailAction(trimmed)
	}
}

func mergeConfigMap(dst, src map[string]any) {
	if len(src) == 0 {
		return
	}
	for k, v := range src {
		if existingMap, ok := dst[k].(map[string]any); ok {
			if srcMap, ok := v.(map[string]any); ok {
				nested := cloneConfigMap(existingMap)
				mergeConfigMap(nested, srcMap)
				dst[k] = nested
				continue
			}
		}
		dst[k] = cloneAny(v)
	}
}

func cloneConfigMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = cloneAny(v)
	}
	return out
}

func cloneAny(v any) any {
	switch tv := v.(type) {
	case map[string]any:
		return cloneConfigMap(tv)
	case []any:
		out := make([]any, len(tv))
		for i, item := range tv {
			out[i] = cloneAny(item)
		}
		return out
	case []string:
		return slices.Clone(tv)
	case map[string]string:
		return maps.Clone(tv)
	default:
		return v
	}
}

func intFromAny(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}
