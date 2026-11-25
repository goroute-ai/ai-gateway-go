package router

import (
	"context"
	"math"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	catalog "github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/modelmgmt"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// RouteDecision describes how Stage 1 Intelligent Router mapped a request's model field to a ModelGroup.
type RouteDecision struct {
	RequestedModel   string
	TargetGroupAlias string
	ComplexityScore  float64
	Reason           string
	PreRouterName    string
	BanditBucket     TaskBucket
	ModelGroup       *domain.ModelGroup
}

const defaultRoutingL1CacheTTL = 10 * time.Second

type cachedOrgModelGroups struct {
	groups    []*domain.ModelGroup
	rev       uint64
	expiresAt time.Time
}

// IntelligentRouter implements Stage 1 of the Two-Stage Routing Engine:
// resolving smart aliases (`auto`, `router/*`, `fast`, `reasoning`, `coding`) and explicit model names
// into concrete ModelGroups without calling an external LLM on the hot path.
type IntelligentRouter struct {
	repo             storage.Repository
	cfg              config.RouterConfig
	providerCallable func(domain.ProviderType) bool

	mu             sync.RWMutex
	preRouters     *PreRouterRegistry
	bandit         *BanditPreRouter
	semantic       *SemanticPreRouter
	quality        *QualityPreRouter
	orgGroupsCache map[string]cachedOrgModelGroups
}

// NewIntelligentRouter initializes a Stage 1 IntelligentRouter with default alias fallbacks.
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

	ir := &IntelligentRouter{
		repo:             repo,
		cfg:              cfg,
		providerCallable: catalog.IsCallableProvider,
	}

	reg := NewPreRouterRegistry(cfg.PreRouterMode)
	reg.Register(NewHeuristicPreRouterWithRouter(ir))

	qual := NewQualityPreRouter(repo, cfg)
	reg.Register(qual)

	var bandit *BanditPreRouter
	if cfg.Bandit.Enabled {
		bandit = NewBanditPreRouter(cfg, nil, WithBanditRepository(repo))
		reg.Register(bandit)
	}

	ir.preRouters = reg
	ir.quality = qual
	ir.bandit = bandit
	return ir
}

// RegisterPreRouter registers a PreRouter implementation in the router's registry.
func (ir *IntelligentRouter) RegisterPreRouter(pr PreRouter) {
	if ir == nil || pr == nil {
		return
	}
	ir.mu.Lock()
	defer ir.mu.Unlock()
	if ir.preRouters == nil {
		ir.preRouters = NewPreRouterRegistry(ir.cfg.PreRouterMode)
	}
	ir.preRouters.Register(pr)
	switch typed := pr.(type) {
	case *SemanticPreRouter:
		ir.semantic = typed
	case *QualityPreRouter:
		ir.quality = typed
	case *BanditPreRouter:
		ir.bandit = typed
	}
}

// SetSemanticPreRouter attaches and registers a SemanticPreRouter instance.
func (ir *IntelligentRouter) SetSemanticPreRouter(s *SemanticPreRouter) {
	if ir == nil {
		return
	}
	ir.mu.Lock()
	defer ir.mu.Unlock()
	ir.semantic = s
	if s != nil {
		if ir.preRouters == nil {
			ir.preRouters = NewPreRouterRegistry(ir.cfg.PreRouterMode)
		}
		ir.preRouters.Register(s)
	}
}

// SetQualityPreRouter attaches and registers a QualityPreRouter instance.
func (ir *IntelligentRouter) SetQualityPreRouter(q *QualityPreRouter) {
	if ir == nil {
		return
	}
	ir.mu.Lock()
	defer ir.mu.Unlock()
	ir.quality = q
	if q != nil {
		if ir.preRouters == nil {
			ir.preRouters = NewPreRouterRegistry(ir.cfg.PreRouterMode)
		}
		ir.preRouters.Register(q)
	}
}

// SetBanditPreRouter attaches and registers a BanditPreRouter instance.
func (ir *IntelligentRouter) SetBanditPreRouter(b *BanditPreRouter) {
	if ir == nil {
		return
	}
	ir.mu.Lock()
	defer ir.mu.Unlock()
	ir.bandit = b
	if b != nil {
		if ir.preRouters == nil {
			ir.preRouters = NewPreRouterRegistry(ir.cfg.PreRouterMode)
		}
		ir.preRouters.Register(b)
	}
}

// PreRouters returns the PreRouterRegistry managed by this router.
func (ir *IntelligentRouter) PreRouters() *PreRouterRegistry {
	if ir == nil {
		return nil
	}
	ir.mu.RLock()
	defer ir.mu.RUnlock()
	return ir.preRouters
}

// Bandit returns the configured BanditPreRouter, if any.
func (ir *IntelligentRouter) Bandit() *BanditPreRouter {
	if ir == nil {
		return nil
	}
	ir.mu.RLock()
	defer ir.mu.RUnlock()
	return ir.bandit
}

// SetProviderCallable lets server wiring use the live adapter registry, including
// startup-configured custom profiles, when resolving direct provider/model routes.
func (ir *IntelligentRouter) SetProviderCallable(check func(domain.ProviderType) bool) {
	if check != nil {
		ir.providerCallable = check
	}
}

// ListActiveModelGroupsCached returns active model groups for orgID using short-TTL L1 caching
// invalidated on RoutingRevision bumps and explicit InvalidateCache events.
func (ir *IntelligentRouter) ListActiveModelGroupsCached(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	if ir == nil || ir.repo == nil {
		return nil, nil
	}
	now := time.Now()
	var curRev uint64
	if rp, ok := ir.repo.(storage.RoutingRevisionProvider); ok {
		curRev = rp.RoutingRevision()
	}

	ir.mu.RLock()
	if ir.orgGroupsCache != nil {
		if ent, ok := ir.orgGroupsCache[orgID]; ok && now.Before(ent.expiresAt) && (curRev == 0 || ent.rev == curRev) {
			ir.mu.RUnlock()
			return ent.groups, nil
		}
	}
	ir.mu.RUnlock()

	groups, err := ir.repo.ListModelGroups(ctx, orgID)
	if err != nil {
		return nil, err
	}
	active := make([]*domain.ModelGroup, 0, len(groups))
	for _, g := range groups {
		if g != nil && g.IsActive {
			active = append(active, g)
		}
	}

	ir.mu.Lock()
	if ir.orgGroupsCache == nil {
		ir.orgGroupsCache = make(map[string]cachedOrgModelGroups)
	}
	ir.orgGroupsCache[orgID] = cachedOrgModelGroups{
		groups:    active,
		rev:       curRev,
		expiresAt: now.Add(defaultRoutingL1CacheTTL),
	}
	ir.mu.Unlock()
	return active, nil
}

// InvalidateCache clears cached model groups/deployments across IntelligentRouter and QualityPreRouter.
func (ir *IntelligentRouter) InvalidateCache(ev storage.InvalidationEvent) {
	if ir == nil {
		return
	}
	ir.mu.Lock()
	if ev.OrgID != "" && ir.orgGroupsCache != nil {
		delete(ir.orgGroupsCache, ev.OrgID)
	} else {
		ir.orgGroupsCache = nil
	}
	qual := ir.quality
	ir.mu.Unlock()
	if qual != nil {
		qual.InvalidateCache(ev)
	}
}

// ResolveExplicitModel resolves a specific model name or alias for an organization,
// including dynamic provider/model catalogue resolution.
func (ir *IntelligentRouter) ResolveExplicitModel(ctx context.Context, orgID string, requested string) (*domain.ModelGroup, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "model_required",
			Message:    "Model parameter is required",
		}
	}

	// 1. Exact alias lookup
	mg, err := ir.repo.GetModelGroupByAlias(ctx, orgID, requested)
	if err == nil && mg != nil && mg.IsActive {
		return mg, nil
	}

	// 2. Dynamic provider/model resolution
	if dynGroup := ir.resolveDynamicProviderModel(ctx, orgID, requested); dynGroup != nil {
		return dynGroup, nil
	}

	// 3. Fallback scan of active groups
	groups, _ := ir.repo.ListModelGroups(ctx, orgID)
	for _, g := range groups {
		if g.IsActive && g.Alias == requested {
			return g, nil
		}
	}

	return nil, &domain.GatewayError{
		StatusCode: http.StatusNotFound,
		Type:       domain.ErrorTypeNotFound,
		Code:       "model_not_found",
		Message:    "No active model group configured for: " + requested,
	}
}

// ResolveGroup determines the target ModelGroup for a chat completion request.
func (ir *IntelligentRouter) ResolveGroup(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (*RouteDecision, error) {
	if req == nil {
		req = &domain.CanonicalChatRequest{Model: VirtualAliasAuto}
	}
	requested := strings.TrimSpace(req.Model)
	if requested == "" {
		requested = VirtualAliasAuto
	}

	decision := &RouteDecision{
		RequestedModel:   requested,
		TargetGroupAlias: requested,
		Reason:           "explicit_model",
	}

	reg := ir.PreRouters()
	isVirtualAlias := strings.EqualFold(requested, VirtualAliasAuto) || (reg != nil && reg.IsVirtualAlias(requested))
	if isVirtualAlias {
		alias, score, reason, prName := ir.routeViaPreRouter(ctx, orgID, requested, req, reg)
		decision.TargetGroupAlias = alias
		decision.ComplexityScore = score
		decision.Reason = reason
		decision.PreRouterName = prName
		if prName == PreRouterModeAdaptive {
			decision.BanditBucket = ClassifyTaskBucket(req, ir.cfg.LongContextTokens)
		}
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
	isSmartAlias := isVirtualAlias || slices.Contains(auth.SmartAliases, requested)
	if !isSmartAlias {
		if dynGroup := ir.resolveDynamicProviderModel(ctx, orgID, decision.TargetGroupAlias); dynGroup != nil {
			decision.ModelGroup = dynGroup
			decision.TargetGroupAlias = dynGroup.Alias
			decision.Reason = "dynamic_catalogue_model"
			return decision, nil
		}
	}

	// Fallback logic:
	// For explicit models, we check if there's any active group whose Alias matches requested.
	// If not, explicit model requests MUST fail immediately with 404 (NEVER fall through to groups[0] or default alias).
	groups, _ := ir.repo.ListModelGroups(ctx, orgID)
	for _, g := range groups {
		if g != nil && g.IsActive && (g.Alias == requested || g.Alias == decision.TargetGroupAlias) {
			decision.ModelGroup = g
			decision.TargetGroupAlias = g.Alias
			return decision, nil
		}
	}

	// Fallback to default fast/reasoning alias or first active group is STRICTLY reserved for smart aliases
	if isSmartAlias {
		for _, g := range groups {
			if g != nil && g.IsActive && (g.Alias == ir.cfg.DefaultFastAlias || g.Alias == ir.cfg.DefaultReasoningAlias) {
				decision.ModelGroup = g
				decision.TargetGroupAlias = g.Alias
				return decision, nil
			}
		}
		for _, g := range groups {
			if g != nil && g.IsActive {
				decision.ModelGroup = g
				decision.TargetGroupAlias = g.Alias
				return decision, nil
			}
		}
	}

	return nil, &domain.GatewayError{
		StatusCode: 404,
		Type:       domain.ErrorTypeNotFound,
		Code:       "model_group_not_found",
		Message:    "No active model group configured for model or alias: " + requested,
	}
}

func (ir *IntelligentRouter) routeViaPreRouter(
	ctx context.Context,
	orgID string,
	requested string,
	req *domain.CanonicalChatRequest,
	reg *PreRouterRegistry,
) (targetAlias string, score float64, reason string, prName string) {
	if reg != nil {
		if pr, ok := reg.ResolveAlias(requested); ok && pr != nil {
			alias, rsn, sc, err := pr.Route(ctx, orgID, req)
			if err == nil && strings.TrimSpace(alias) != "" {
				return strings.TrimSpace(alias), sc, rsn, pr.Name()
			}
		}
		if heur, ok := reg.Get(PreRouterModeHeuristic); ok && heur != nil {
			if alias, rsn, sc, err := heur.Route(ctx, orgID, req); err == nil && strings.TrimSpace(alias) != "" {
				return strings.TrimSpace(alias), sc, rsn, heur.Name()
			}
		}
	}
	alias, sc, rsn := ir.classifyPrompt(req)
	return alias, sc, rsn, PreRouterModeHeuristic
}

// resolveDynamicProviderModel handles direct model requests (e.g. "gemini/gemini-2.5-flash"
// or "gemini-2.5-flash") by validating Layer 2 Provider Subscriptions, Layer 3 Org Model Policies,
// and active tenant credentials before dynamically provisioning or referencing the route.
func (ir *IntelligentRouter) groupMatchesProvider(ctx context.Context, groupID string, prov domain.ProviderType) bool {
	deps, err := ir.repo.ListDeploymentsByGroup(ctx, groupID)
	if err != nil {
		return false
	}
	for _, d := range deps {
		if d != nil && d.GlobalModel != nil && d.GlobalModel.Provider == prov {
			return true
		}
	}
	return false
}

const maxDynamicModelNameLen = 128

func isValidDynamicModelSegment(seg string) bool {
	if seg == "" || strings.Contains(seg, "..") {
		return false
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 && !isAlphaNum {
			return false
		}
		if !isAlphaNum && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isBuiltInCatalogProvider(prov domain.ProviderType) bool {
	switch prov {
	case domain.ProviderOpenAI, domain.ProviderAnthropic, domain.ProviderGroq, domain.ProviderOpenRouter, domain.ProviderGemini:
		return true
	default:
		return false
	}
}

func isValidDynamicModelName(prov domain.ProviderType, bareModel string) bool {
	if bareModel == "*" {
		return true
	}
	if bareModel == "" || len(bareModel) > maxDynamicModelNameLen {
		return false
	}
	if prov == domain.ProviderOpenRouter || prov == domain.ProviderGroq {
		parts := strings.Split(bareModel, "/")
		if len(parts) > 3 {
			return false
		}
		for _, seg := range parts {
			if !isValidDynamicModelSegment(seg) {
				return false
			}
		}
		return true
	}
	return isValidDynamicModelSegment(bareModel)
}

func (ir *IntelligentRouter) resolveDynamicProviderModel(ctx context.Context, orgID, requested string) *domain.ModelGroup {
	prov, bareModel, globalModelID := config.ParseProviderModel(requested)
	if prov == "" || globalModelID == "" || !isValidDynamicModelName(prov, bareModel) {
		return nil
	}
	aliasKey := bareModel
	if strings.Contains(requested, "/") {
		if mg, err := ir.repo.GetModelGroupByAlias(ctx, orgID, globalModelID); err == nil && mg != nil {
			return mg
		}
	}
	if bareModel != "" && bareModel != requested {
		if mg, err := ir.repo.GetModelGroupByAlias(ctx, orgID, bareModel); err == nil && mg != nil {
			if ir.groupMatchesProvider(ctx, mg.ID, prov) {
				return mg
			}
			// bareModel alias is already claimed by another provider; use provider-qualified alias
			aliasKey = globalModelID
		}
	}

	// 1. Layer 2 Check: Org Provider Subscriptions (fail-closed if subscriptions are configured or repository fails)
	subs, err := ir.repo.GetOrgProviderSubscriptions(ctx, orgID)
	if err != nil {
		return nil // Fail closed on database/repository error
	}
	if len(subs) > 0 {
		hasSubscription := false
		for _, s := range subs {
			if s != nil && s.Provider == prov && s.IsEnabled {
				hasSubscription = true
				break
			}
		}
		if !hasSubscription {
			return nil
		}
	}

	// 2. Layer 3 Check: Org Model Policies (fail-closed if model is explicitly disabled or repository fails)
	pols, err := ir.repo.GetOrgModelPolicies(ctx, orgID)
	if err != nil {
		return nil // Fail closed on database/repository error
	}
	if len(pols) > 0 {
		for _, p := range pols {
			if p != nil && p.GlobalModelID == globalModelID && !p.IsEnabled {
				return nil
			}
		}
	}

	// 3. Active Tenant Credential Check (strict multi-tenant isolation; zero env var leakage)
	creds, err := ir.repo.ListProviderCredentials(ctx, orgID)
	if err != nil {
		return nil // Fail closed on database/repository error
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

	// 4. Verify the provider has a registered callable transport. A credential BaseURL
	// alone is not enough to safely infer the wire protocol or request adaptation.
	if ir.providerCallable == nil || !ir.providerCallable(prov) {
		return nil
	}

	// 5. Wildcard `<provider>/*` resolution + Model Lookup & Dynamic Catalogue Import
	if bareModel == "*" {
		chosen := ir.pickWildcardProviderModel(ctx, prov, pols)
		if chosen == nil {
			return nil
		}
		bareModel = chosen.ModelName
		globalModelID = chosen.ID
		aliasKey = chosen.ID
		if mg, err := ir.repo.GetModelGroupByAlias(ctx, orgID, globalModelID); err == nil && mg != nil {
			return mg
		}
	}

	gm, err := ir.repo.GetGlobalModel(ctx, globalModelID)
	if err != nil || gm == nil {
		var toImport *domain.GlobalModel
		if catModel, ok := catalog.LookupByProviderAndModel(prov, bareModel); ok && catModel != nil {
			catCopy := *catModel
			toImport = &catCopy
		} else if !isBuiltInCatalogProvider(prov) {
			// Startup-registered custom provider profiles have no built-in catalog entries.
			// Their models retain PricingStatusUnknown so pickWildcardProviderModel will never
			// select them for cross-tenant wildcard routing unless explicitly policy-enabled.
			toImport = modelmgmt.EnrichDiscoveredModel(domain.DiscoveredModel{
				Provider:    prov,
				ModelName:   bareModel,
				DisplayName: bareModel,
			}, true)
			toImport.SupportsInference = true
		} else {
			// Fail closed for built-in catalog providers: never synthesize or persist untrusted
			// data-plane model names into the shared cross-tenant global_models table.
			return nil
		}
		if toImport == nil || !toImport.SupportsInference {
			return nil // Refuse to dynamically provision non-inference models (e.g. image dimension pricing)
		}
		toImport.LifecycleStatus = domain.ModelStatusActive
		if err := ir.repo.UpsertGlobalModel(ctx, toImport); err == nil {
			gm = toImport
		}
	}

	if gm == nil || !gm.SupportsInference || (gm.LifecycleStatus != domain.ModelStatusActive && gm.LifecycleStatus != domain.ModelStatusPreview) {
		return nil
	}

	// 6. Auto-provision ModelGroup & Deployment for this tenant
	mg := &domain.ModelGroup{
		OrgID:            orgID,
		Alias:            aliasKey,
		RoutingStrategy:  domain.StrategyWeightedShuffle,
		MaxRetries:       ir.cfg.DefaultMaxRetries,
		CooldownSeconds:  int(ir.cfg.DefaultCooldown.Seconds()),
		FailureThreshold: ir.cfg.FailureThreshold,
		IsActive:         true,
	}
	if err := ir.repo.CreateModelGroup(ctx, mg); err != nil {
		if existing, err2 := ir.repo.GetModelGroupByAlias(ctx, orgID, aliasKey); err2 == nil && existing != nil {
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

func (ir *IntelligentRouter) pickWildcardProviderModel(
	ctx context.Context,
	prov domain.ProviderType,
	pols []*domain.OrgModelPolicy,
) *domain.GlobalModel {
	disabled := make(map[string]bool)
	enabledSet := make(map[string]bool)
	for _, p := range pols {
		if p == nil {
			continue
		}
		if !p.IsEnabled {
			disabled[p.GlobalModelID] = true
		} else {
			enabledSet[p.GlobalModelID] = true
		}
	}

	seen := make(map[string]*domain.GlobalModel)
	addCandidate := func(gm *domain.GlobalModel) {
		if gm == nil || gm.Provider != prov || gm.ModelName == "" || gm.ModelName == "*" {
			return
		}
		if disabled[gm.ID] {
			return
		}
		if gm.LifecycleStatus != "" && gm.LifecycleStatus != domain.ModelStatusActive && gm.LifecycleStatus != domain.ModelStatusPreview {
			return
		}
		if !gm.SupportsInference && (len(gm.SupportedOperations) == 0 || !gm.SupportsOperation(domain.OperationChat)) {
			return
		}
		if len(gm.SupportedOperations) > 0 && !gm.SupportsOperation(domain.OperationChat) {
			return
		}
		if _, exists := seen[gm.ID]; !exists {
			seen[gm.ID] = gm
		}
	}

	if ir.repo != nil {
		if repoModels, err := ir.repo.ListGlobalModels(ctx); err == nil {
			for _, gm := range repoModels {
				if gm == nil {
					continue
				}
				// Guard against unverified/unknown-pricing rogue rows hijacking cross-tenant
				// wildcard resolution unless explicitly enabled for this org or present in the trusted catalog.
				if !enabledSet[gm.ID] && domain.ResolvePricingStatus(gm) == domain.PricingStatusUnknown {
					if _, inCat := catalog.LookupByProviderAndModel(gm.Provider, gm.ModelName); !inCat {
						continue
					}
				}
				addCandidate(gm)
			}
		}
	}
	for _, gm := range catalog.All() {
		addCandidate(gm)
	}
	if len(seen) == 0 {
		return nil
	}

	candidates := make([]*domain.GlobalModel, 0, len(seen))
	for _, gm := range seen {
		candidates = append(candidates, gm)
	}
	sort.Slice(candidates, func(i, j int) bool {
		// Prefer explicitly policy-approved models first, then deterministic ID ordering.
		eI, eJ := enabledSet[candidates[i].ID], enabledSet[candidates[j].ID]
		if eI != eJ {
			return eI
		}
		return candidates[i].ID < candidates[j].ID
	})
	return candidates[0]
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
