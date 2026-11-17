package router

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/health"
)

// RoutingContext carries per-request routing metadata and the mutable candidate slice
// passed through registered RoutingPlugins.
type RoutingContext struct {
	OrgID           string
	GroupAlias      string
	Request         *domain.CanonicalChatRequest
	Candidates      []*domain.Deployment
	EstimatedTokens int
}

// RoutingPlugin filters or reorders candidate deployments during Stage 2 filtering.
type RoutingPlugin interface {
	Name() string
	Filter(ctx context.Context, rc *RoutingContext) ([]*domain.Deployment, error)
}

// RoutingPluginFunc adapts a plain function into a RoutingPlugin.
type RoutingPluginFunc struct {
	PluginName string
	Fn         func(ctx context.Context, rc *RoutingContext) ([]*domain.Deployment, error)
}

// Name returns the configured plugin identifier.
func (f RoutingPluginFunc) Name() string {
	return f.PluginName
}

// Filter executes Fn against rc, or returns rc.Candidates unchanged when Fn is nil.
func (f RoutingPluginFunc) Filter(ctx context.Context, rc *RoutingContext) ([]*domain.Deployment, error) {
	if f.Fn == nil {
		if rc == nil {
			return nil, nil
		}
		return rc.Candidates, nil
	}
	return f.Fn(ctx, rc)
}

// BudgetCheckFn reports whether a deployment is within its configured spend budget
// for orgID. Returning false excludes the deployment from selection.
type BudgetCheckFn func(ctx context.Context, orgID string, dep *domain.Deployment) bool

// ContextWindowExhaustedError is returned when every otherwise-eligible deployment
// is pruned solely because EstimatedTokens exceeds GlobalModel.MaxInputTokens.
// It wraps a 400 context_length_exceeded *domain.GatewayError so callers can either
// trigger context-window fallbacks or surface the standard API error.
type ContextWindowExhaustedError struct {
	EstimatedTokens int
	MaxInputTokens  int
	GatewayErr      *domain.GatewayError
}

func newContextWindowExhaustedError(estTokens, maxTokens int) *ContextWindowExhaustedError {
	msg := fmt.Sprintf("Estimated input tokens (%d) exceed the maximum context window across all available deployments", estTokens)
	if maxTokens > 0 {
		msg = fmt.Sprintf("Estimated input tokens (%d) exceed maximum context window (%d tokens) across all available deployments", estTokens, maxTokens)
	}
	return &ContextWindowExhaustedError{
		EstimatedTokens: estTokens,
		MaxInputTokens:  maxTokens,
		GatewayErr: &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "context_length_exceeded",
			Message:    msg,
		},
	}
}

// Error returns the underlying GatewayError message.
func (e *ContextWindowExhaustedError) Error() string {
	if e == nil {
		return ""
	}
	if e.GatewayErr != nil {
		return e.GatewayErr.Error()
	}
	return fmt.Sprintf("[400:context_length_exceeded] estimated tokens %d exceed context window", e.EstimatedTokens)
}

// Unwrap exposes the underlying *domain.GatewayError for errors.As matching.
func (e *ContextWindowExhaustedError) Unwrap() error {
	if e == nil || e.GatewayErr == nil {
		return nil
	}
	return e.GatewayErr
}

// FilterPipeline applies ordered deployment eligibility checks and registered
// RoutingPlugins before load-balancer selection. Configuration methods should be
// called during initialization before concurrent FilterEligibleDeployments calls.
type FilterPipeline struct {
	healthMon   *health.Monitor
	lb          *LoadBalancer
	cfg         config.RouterConfig
	budgetCheck BudgetCheckFn
	tagMatchAll bool
	plugins     []RoutingPlugin
	now         func() time.Time
}

// NewFilterPipeline constructs a FilterPipeline with optional initial RoutingPlugins.
func NewFilterPipeline(healthMon *health.Monitor, lb *LoadBalancer, cfg config.RouterConfig, plugins ...RoutingPlugin) *FilterPipeline {
	var copied []RoutingPlugin
	for _, plugin := range plugins {
		if plugin != nil {
			copied = append(copied, plugin)
		}
	}
	return &FilterPipeline{
		healthMon: healthMon,
		lb:        lb,
		cfg:       cfg,
		plugins:   copied,
		now:       time.Now,
	}
}

// SetBudgetCheck configures an optional deployment/provider budget gate callback.
func (p *FilterPipeline) SetBudgetCheck(fn BudgetCheckFn) {
	if p != nil {
		p.budgetCheck = fn
	}
}

// SetTagMatchAll controls whether plain tags in GoRouteExtensions.Tags require
// all tags (true) or any tag (false, default).
func (p *FilterPipeline) SetTagMatchAll(matchAll bool) {
	if p != nil {
		p.tagMatchAll = matchAll
	}
}

// AddPlugin appends a non-nil RoutingPlugin to the end of the pipeline.
func (p *FilterPipeline) AddPlugin(plugin RoutingPlugin) {
	if p != nil && plugin != nil {
		p.plugins = append(p.plugins, plugin)
	}
}

// FilterContext runs FilterEligibleDeployments using the fields of rc.
func (p *FilterPipeline) FilterContext(ctx context.Context, rc *RoutingContext) ([]*domain.Deployment, error) {
	if rc == nil {
		return nil, nil
	}
	return p.FilterEligibleDeployments(ctx, rc.OrgID, rc.GroupAlias, rc.Request, rc.Candidates, rc.EstimatedTokens)
}

// FilterEligibleDeployments evaluates deployments through ordered filter stages:
//  1. Active deployment status, non-nil GlobalModel, and active/non-expired Credential
//  2. Active background health with staleness threshold (retaining all if all unhealthy)
//  3. Chat capabilities and context-window capacity (returning *ContextWindowExhaustedError if all fail context window alone)
//  4. Region affinity from GoRouteExtensions.AllowedRegion
//  5. Tag matching from GoRouteExtensions.Tags
//  6. Live RPM/TPM saturation gate via LoadBalancer signals (with non-strict safety fallback)
//  7. Optional budget gate callback
//  8. Registered RoutingPlugins in order
//
// When optional filters are inactive and all candidates pass, candidates is returned
// without heap allocations.
func (p *FilterPipeline) FilterEligibleDeployments(
	ctx context.Context,
	orgID string,
	groupAlias string,
	req *domain.CanonicalChatRequest,
	candidates []*domain.Deployment,
	estimatedTokens int,
) ([]*domain.Deployment, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	if estimatedTokens < 0 {
		estimatedTokens = 0
	}

	var (
		healthMon   *health.Monitor
		lb          *LoadBalancer
		cfg         config.RouterConfig
		budgetCheck BudgetCheckFn
		tagMatchAll bool
		plugins     []RoutingPlugin
		nowFn       = time.Now
	)
	if p != nil {
		healthMon = p.healthMon
		lb = p.lb
		cfg = p.cfg
		budgetCheck = p.budgetCheck
		tagMatchAll = p.tagMatchAll
		plugins = p.plugins
		if p.now != nil {
			nowFn = p.now
		}
	}

	// Stage 1: Deployment status, hydrated GlobalModel, and Credential lifecycle.
	var nowUTC time.Time
	for _, d := range candidates {
		if d != nil && d.Credential != nil && d.Credential.ExpiresAt != nil {
			nowUTC = nowFn().UTC()
			break
		}
	}
	var stage1 []*domain.Deployment
	for i, d := range candidates {
		if isBaseEligibleDeployment(d, nowUTC) {
			if stage1 != nil {
				stage1 = append(stage1, d)
			}
			continue
		}
		if stage1 == nil {
			stage1 = make([]*domain.Deployment, i, len(candidates)-1)
			copy(stage1, candidates[:i])
		}
	}
	if stage1 != nil {
		candidates = stage1
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	// Stage 2: Active health + staleness gate with all-unhealthy safety net.
	if healthMon != nil {
		var stage2 []*domain.Deployment
		for i, d := range candidates {
			if healthMon.IsHealthyWithMaxAge(d.ID, cfg.HealthStalenessThreshold) {
				if stage2 != nil {
					stage2 = append(stage2, d)
				}
				continue
			}
			if stage2 == nil {
				stage2 = make([]*domain.Deployment, i, len(candidates)-1)
				copy(stage2, candidates[:i])
			}
		}
		if stage2 != nil && len(stage2) > 0 {
			candidates = stage2
		}
		// If len(stage2) == 0, retain candidates so transient probe glitches do not blackhole the group.
	}

	// Stage 3: Chat capability & context window filter.
	needsStream, needsTools, needsVision, needsJSONSchema, needsReasoning := extractChatCapabilityNeeds(req)
	checkCaps := needsStream || needsTools || needsVision || needsJSONSchema || needsReasoning
	if checkCaps || estimatedTokens > 0 {
		var stage3 []*domain.Deployment
		capEligible := 0
		ctxPruned := 0
		maxSeenWindow := 0

		for i, d := range candidates {
			gm := d.GlobalModel
			capOK := !checkCaps || modelSupportsChatRequirements(gm, needsStream, needsTools, needsVision, needsJSONSchema, needsReasoning)
			if capOK {
				capEligible++
			}
			ctxOK := estimatedTokens == 0 || gm.MaxInputTokens <= 0 || estimatedTokens <= gm.MaxInputTokens
			if !ctxOK {
				ctxPruned++
				if gm.MaxInputTokens > maxSeenWindow {
					maxSeenWindow = gm.MaxInputTokens
				}
			}
			if capOK && ctxOK {
				if stage3 != nil {
					stage3 = append(stage3, d)
				}
				continue
			}
			if stage3 == nil {
				stage3 = make([]*domain.Deployment, i, len(candidates)-1)
				copy(stage3, candidates[:i])
			}
		}
		if stage3 != nil {
			if len(stage3) == 0 {
				if capEligible == len(candidates) && ctxPruned == len(candidates) {
					return nil, newContextWindowExhaustedError(estimatedTokens, maxSeenWindow)
				}
				return nil, nil
			}
			candidates = stage3
		}
	}

	// Stage 4: Region filter.
	var allowedRegion string
	var reqTags []string
	if req != nil && req.GoRouteExtensions != nil {
		allowedRegion = strings.TrimSpace(req.GoRouteExtensions.AllowedRegion)
		reqTags = req.GoRouteExtensions.Tags
	}
	if allowedRegion != "" {
		var stage4 []*domain.Deployment
		for i, d := range candidates {
			if strings.EqualFold(strings.TrimSpace(d.Region), allowedRegion) {
				if stage4 != nil {
					stage4 = append(stage4, d)
				}
				continue
			}
			if stage4 == nil {
				stage4 = make([]*domain.Deployment, i, len(candidates)-1)
				copy(stage4, candidates[:i])
			}
		}
		if stage4 != nil {
			candidates = stage4
		}
		if len(candidates) == 0 {
			return nil, nil
		}
	}

	// Stage 5: Tag filter.
	if len(reqTags) > 0 {
		var stage5 []*domain.Deployment
		for i, d := range candidates {
			if matchDeploymentTags(d.Tags, reqTags, tagMatchAll) {
				if stage5 != nil {
					stage5 = append(stage5, d)
				}
				continue
			}
			if stage5 == nil {
				stage5 = make([]*domain.Deployment, i, len(candidates)-1)
				copy(stage5, candidates[:i])
			}
		}
		if stage5 != nil {
			candidates = stage5
		}
		if len(candidates) == 0 {
			return nil, nil
		}
	}

	// Stage 6: Live RPM/TPM saturation gate across all routing strategies.
	if lb != nil && hasCapacityLimits(candidates) {
		candidates = filterByCapacity(lb, candidates, estimatedTokens, cfg.StrictCapacityFiltering, nowFn())
		if len(candidates) == 0 {
			return nil, nil
		}
	}

	// Stage 7: Optional budget gate.
	if budgetCheck != nil {
		var stage7 []*domain.Deployment
		for i, d := range candidates {
			if budgetCheck(ctx, orgID, d) {
				if stage7 != nil {
					stage7 = append(stage7, d)
				}
				continue
			}
			if stage7 == nil {
				stage7 = make([]*domain.Deployment, i, len(candidates)-1)
				copy(stage7, candidates[:i])
			}
		}
		if stage7 != nil {
			candidates = stage7
		}
		if len(candidates) == 0 {
			return nil, nil
		}
	}

	// Stage 8: Registered RoutingPlugins in registration order.
	if len(plugins) > 0 {
		rc := &RoutingContext{
			OrgID:           orgID,
			GroupAlias:      groupAlias,
			Request:         req,
			Candidates:      candidates,
			EstimatedTokens: estimatedTokens,
		}
		for _, plugin := range plugins {
			if plugin == nil {
				continue
			}
			next, err := plugin.Filter(ctx, rc)
			if err != nil {
				return nil, err
			}
			rc.Candidates = next
			candidates = next
			if len(candidates) == 0 {
				return nil, nil
			}
		}
	}

	return candidates, nil
}

func isBaseEligibleDeployment(d *domain.Deployment, nowUTC time.Time) bool {
	if d == nil || d.Status != domain.DeploymentStatusActive || d.GlobalModel == nil {
		return false
	}
	if d.Credential != nil {
		if !d.Credential.IsActive {
			return false
		}
		if d.Credential.ExpiresAt != nil && !nowUTC.Before(*d.Credential.ExpiresAt) {
			return false
		}
	}
	return true
}

func extractChatCapabilityNeeds(req *domain.CanonicalChatRequest) (stream, tools, vision, jsonSchema, reasoning bool) {
	if req == nil {
		return false, false, false, false, false
	}
	stream = req.Stream
	tools = len(req.Tools) > 0
	jsonSchema = req.ResponseFormat != nil && strings.EqualFold(strings.TrimSpace(req.ResponseFormat.Type), "json_schema")
	reasoning = strings.TrimSpace(req.ReasoningEffort) != ""
	for i := range req.Messages {
		parts := req.Messages[i].Parts
		for j := range parts {
			p := &parts[j]
			if ((p.Type == "image_url" || p.Type == "input_image") && (p.ImageURL == nil || p.ImageURL.URL != "")) ||
				(p.ImageURL != nil && p.ImageURL.URL != "") {
				vision = true
				return
			}
		}
	}
	return
}

func modelSupportsChatRequirements(gm *domain.GlobalModel, stream, tools, vision, jsonSchema, reasoning bool) bool {
	caps := gm.ResolveCapabilities()
	if stream && caps.Streaming == domain.CapabilityUnsupported {
		return false
	}
	if tools && caps.Tools == domain.CapabilityUnsupported {
		return false
	}
	if vision && caps.Vision == domain.CapabilityUnsupported {
		return false
	}
	if jsonSchema && caps.StructuredOutputs == domain.CapabilityUnsupported {
		return false
	}
	if reasoning && caps.Reasoning == domain.CapabilityUnsupported {
		return false
	}
	return true
}

// matchDeploymentTags evaluates deployment tags against requested tag filters.
// Supported syntax in reqTags:
//   - "eu"       plain tag (all required when matchAll is true; any when matchAll is false)
//   - "&gpu"     required tag (always required regardless of matchAll)
//   - "!legacy"  excluded tag (always rejected regardless of matchAll)
//   - "prefix*"  trailing wildcard prefix match (can combine with & or !)
func matchDeploymentTags(depTags, reqTags []string, matchAll bool) bool {
	if len(reqTags) == 0 {
		return true
	}
	hasPlain := false
	matchedPlain := false
	for _, raw := range reqTags {
		tag := strings.TrimSpace(raw)
		if tag == "" {
			continue
		}
		switch tag[0] {
		case '!':
			pat := strings.TrimSpace(tag[1:])
			if pat != "" && matchSingleTag(depTags, pat) {
				return false
			}
		case '&':
			pat := strings.TrimSpace(tag[1:])
			if pat != "" && !matchSingleTag(depTags, pat) {
				return false
			}
		default:
			hasPlain = true
			if matchAll {
				if !matchSingleTag(depTags, tag) {
					return false
				}
			} else if !matchedPlain && matchSingleTag(depTags, tag) {
				matchedPlain = true
			}
		}
	}
	if hasPlain && !matchAll && !matchedPlain {
		return false
	}
	return true
}

func matchSingleTag(depTags []string, pattern string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		for _, dt := range depTags {
			dt = strings.TrimSpace(dt)
			if len(dt) >= len(prefix) && strings.EqualFold(dt[:len(prefix)], prefix) {
				return true
			}
		}
		return false
	}
	for _, dt := range depTags {
		if strings.EqualFold(strings.TrimSpace(dt), pattern) {
			return true
		}
	}
	return false
}

func hasCapacityLimits(candidates []*domain.Deployment) bool {
	for _, d := range candidates {
		if d.RPMCapacity > 0 || d.TPMCapacity > 0 {
			return true
		}
	}
	return false
}

func filterByCapacity(lb *LoadBalancer, candidates []*domain.Deployment, estTokens int, strict bool, now time.Time) []*domain.Deployment {
	var signals map[string]deploymentTelemetry
	if lb.redis != nil && lb.redis.Client() != nil {
		shared, err := lb.readSharedSignals(candidates)
		if err != nil {
			lb.setSharedDegraded(true, "capacity_filter")
		} else {
			lb.setSharedDegraded(false, "capacity_filter")
			signals = shared
		}
	}

	if signals == nil {
		lb.mu.RLock()
		defer lb.mu.RUnlock()
	}

	var filtered []*domain.Deployment
	for i, d := range candidates {
		usedRPM, usedTPM := deploymentWindowUsage(lb, signals, d.ID, now)
		if !isCapacitySaturated(d, usedRPM, usedTPM, estTokens) {
			if filtered != nil {
				filtered = append(filtered, d)
			}
			continue
		}
		if filtered == nil {
			filtered = make([]*domain.Deployment, i, len(candidates)-1)
			copy(filtered, candidates[:i])
		}
	}

	if filtered == nil {
		return candidates
	}
	if len(filtered) == 0 && !strict {
		// Non-strict safety fallback: avoid blackholing the group when all deployments appear saturated.
		return candidates
	}
	return filtered
}

func deploymentWindowUsage(lb *LoadBalancer, signals map[string]deploymentTelemetry, depID string, now time.Time) (int, int) {
	if signals != nil {
		sig, ok := signals[depID]
		if !ok {
			return 0, 0
		}
		if sig.windowStart.IsZero() || now.Sub(sig.windowStart) < time.Minute {
			return sig.usedRPM, sig.usedTPM
		}
		return 0, 0
	}
	m, ok := lb.metrics[depID]
	if !ok || m == nil {
		return 0, 0
	}
	if m.windowStart.IsZero() || now.Sub(m.windowStart) < time.Minute {
		return m.usedRPM, m.usedTPM
	}
	return 0, 0
}

func isCapacitySaturated(d *domain.Deployment, usedRPM, usedTPM, estTokens int) bool {
	if d.RPMCapacity > 0 && usedRPM >= d.RPMCapacity {
		return true
	}
	if d.TPMCapacity > 0 && usedTPM+estTokens > d.TPMCapacity {
		return true
	}
	return false
}
