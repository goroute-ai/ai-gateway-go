package router

import (
	"context"
	"math"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// RouteDecision describes how Stage 1 Intelligent Router mapped a request's model field to a ModelGroup.
type RouteDecision struct {
	RequestedModel   string
	TargetGroupAlias string
	ComplexityScore  float64
	Reason           string
	ModelGroup       *domain.ModelGroup
}

// IntelligentRouter implements Stage 1 of the Two-Stage Routing Engine:
// resolving smart aliases (`auto`, `fast`, `reasoning`, `coding`) and explicit model names
// into concrete ModelGroups without calling an external LLM on the hot path.
type IntelligentRouter struct {
	repo storage.Repository
	cfg  config.RouterConfig
}

func NewIntelligentRouter(repo storage.Repository, cfg config.RouterConfig) *IntelligentRouter {
	if cfg.DefaultFastAlias == "" {
		cfg.DefaultFastAlias = "fast"
	}
	if cfg.DefaultReasoningAlias == "" {
		cfg.DefaultReasoningAlias = "reasoning"
	}
	if cfg.DefaultCodingAlias == "" {
		cfg.DefaultCodingAlias = "coding"
	}
	if cfg.ComplexityThreshold <= 0 {
		cfg.ComplexityThreshold = 0.40
	}
	if cfg.LongContextTokens <= 0 {
		cfg.LongContextTokens = 32000
	}
	return &IntelligentRouter{repo: repo, cfg: cfg}
}

// ResolveGroup determines the target ModelGroup for a chat completion request.
func (ir *IntelligentRouter) ResolveGroup(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (*RouteDecision, error) {
	requested := strings.TrimSpace(req.Model)
	if requested == "" {
		requested = "auto"
	}

	decision := &RouteDecision{
		RequestedModel:   requested,
		TargetGroupAlias: requested,
		Reason:           "explicit_model",
	}

	// If "auto" is requested, run the 3-Tier Intelligent Classification Cascade
	if requested == "auto" {
		alias, score, reason := ir.classifyPrompt(req)
		decision.TargetGroupAlias = alias
		decision.ComplexityScore = score
		decision.Reason = reason
	}

	// Lookup the resolved ModelGroup for the Organization
	mg, err := ir.repo.GetModelGroupByAlias(ctx, orgID, decision.TargetGroupAlias)
	if err == nil && mg != nil {
		decision.ModelGroup = mg
		return decision, nil
	}

	// Dynamic `provider/model` & Catalogue Resolution (wildcard behavior):
	// If the user requested "gemini/gemini-2.5-flash" or "gemini-2.5-flash" directly and the organization
	// has an active credential for that provider, resolve or auto-provision the ModelGroup on the fly.
	if requested != "auto" {
		if dynGroup := ir.resolveDynamicProviderModel(ctx, orgID, decision.TargetGroupAlias); dynGroup != nil {
			decision.ModelGroup = dynGroup
			decision.TargetGroupAlias = dynGroup.Alias
			decision.Reason = "dynamic_catalogue_model"
			return decision, nil
		}
	}

	// Fallback: if a specific smart alias group ("coding" or "reasoning") isn't configured yet,
	// try any active model group matching the requested model or the first active group in the org.
	groups, _ := ir.repo.ListModelGroups(ctx, orgID)
	for _, g := range groups {
		if g.IsActive && (g.Alias == requested || g.Alias == ir.cfg.DefaultFastAlias || g.Alias == ir.cfg.DefaultReasoningAlias) {
			decision.ModelGroup = g
			decision.TargetGroupAlias = g.Alias
			return decision, nil
		}
	}
	if len(groups) > 0 && groups[0].IsActive {
		decision.ModelGroup = groups[0]
		decision.TargetGroupAlias = groups[0].Alias
		return decision, nil
	}

	return nil, &domain.GatewayError{
		StatusCode: 404,
		Type:       domain.ErrorTypeNotFound,
		Code:       "model_group_not_found",
		Message:    "No active model group configured for model or alias: " + requested,
	}
}

// resolveDynamicProviderModel handles direct model requests (e.g. "gemini/gemini-2.5-flash"
// or "gemini-2.5-flash") by checking if the bare model group already exists or if the organization holds
// an active credential for that model's provider in the Global Model Catalogue.
func (ir *IntelligentRouter) resolveDynamicProviderModel(ctx context.Context, orgID, requested string) *domain.ModelGroup {
	prov, bareModel, globalModelID := config.ParseProviderModel(requested)
	if bareModel != "" && bareModel != requested {
		if mg, err := ir.repo.GetModelGroupByAlias(ctx, orgID, bareModel); err == nil && mg != nil {
			return mg
		}
	}
	if prov == "" || globalModelID == "" {
		return nil
	}
	gm, err := ir.repo.GetGlobalModel(ctx, globalModelID)
	if err != nil || gm == nil || gm.LifecycleStatus == domain.ModelStatusRetired {
		return nil
	}

	creds, err := ir.repo.ListProviderCredentials(ctx, orgID)
	if err != nil {
		return nil
	}
	var activeCred *domain.ProviderCredential
	for _, c := range creds {
		if c != nil && c.IsActive && c.Provider == prov {
			activeCred = c
			break
		}
	}
	if activeCred == nil {
		return nil
	}

	// Auto-create the ModelGroup & Deployment for this catalogued model so subsequent calls hit O(1) lookup
	mg := &domain.ModelGroup{
		OrgID:            orgID,
		Alias:            bareModel,
		RoutingStrategy:  domain.StrategyWeightedShuffle,
		MaxRetries:       ir.cfg.DefaultMaxRetries,
		CooldownSeconds:  int(ir.cfg.DefaultCooldown.Seconds()),
		FailureThreshold: ir.cfg.FailureThreshold,
		IsActive:         true,
	}
	if err := ir.repo.CreateModelGroup(ctx, mg); err != nil {
		if existing, err2 := ir.repo.GetModelGroupByAlias(ctx, orgID, bareModel); err2 == nil && existing != nil {
			return existing
		}
		return nil
	}
	_ = ir.repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   mg.ID,
		GlobalModelID:  globalModelID,
		CredentialID:   activeCred.ID,
		DeploymentName: bareModel + "-auto",
		Weight:         100,
		Status:         domain.DeploymentStatusActive,
	})
	return mg
}

// classifyPrompt executes Tier 1 (Deterministic Rules) and Tier 2 (Complexity Scorer) in < 0.2ms.
func (ir *IntelligentRouter) classifyPrompt(req *domain.CanonicalChatRequest) (targetAlias string, score float64, reason string) {
	// Tier 1: Deterministic Rules
	estTokens := ratelimit.EstimateRequestTokens(req)
	if estTokens >= ir.cfg.LongContextTokens || req.ReasoningEffort != "" {
		return ir.cfg.DefaultReasoningAlias, 0.95, "rule:long_context_or_explicit_reasoning"
	}

	var combinedText strings.Builder
	for _, m := range req.Messages {
		if m.Role == "user" {
			combinedText.WriteString(strings.ToLower(m.Content))
			combinedText.WriteByte(' ')
		}
	}
	text := combinedText.String()

	// Tier 2: Multi-Feature Prompt Complexity Scorer S in [0.0, 1.0]
	// Feature 1: Token length contribution
	lengthScore := math.Min(float64(estTokens)/1000.0, 1.0) * 0.25

	// Feature 2: Reasoning & analytical instruction density
	reasoningMarkers := []string{
		"step by step", "analyze", "architect", "prove", "theorem",
		"optimize", "trade-off", "design", "root cause", "debug",
		"concurrency", "distributed", "mathematical", "algorithm",
	}
	matchCount := 0
	for _, kw := range reasoningMarkers {
		if strings.Contains(text, kw) {
			matchCount++
		}
	}
	reasoningScore := math.Min(float64(matchCount)*0.22, 0.55)

	// Feature 3: Code block / technical syntax density
	codeScore := 0.0
	if strings.Contains(text, "```") || strings.Contains(text, "func ") || strings.Contains(text, "select ") || strings.Contains(text, "class ") {
		codeScore = 0.30
	}

	// Feature 4: Tool usage / Multi-turn depth
	turnScore := math.Min(float64(len(req.Messages))*0.03, 0.15)
	if len(req.Tools) > 0 {
		turnScore += 0.15
	}

	score = math.Min(lengthScore+reasoningScore+codeScore+turnScore, 1.0)
	if score >= ir.cfg.ComplexityThreshold {
		return ir.cfg.DefaultReasoningAlias, score, "heuristic:high_complexity"
	}
	return ir.cfg.DefaultFastAlias, score, "heuristic:fast_simple_task"
}

// CosineSimilarity computes the cosine similarity between two embedding vectors (used by Tier 3 Semantic Router).
func CosineSimilarity(a, b []float64) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}
