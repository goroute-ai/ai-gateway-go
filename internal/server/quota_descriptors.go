package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type requestQuotaStateContextKey struct{}

type requestQuotaState struct {
	ProjectID             string
	EndUserID             string
	Tags                  []string
	TagCandidates         []string
	SessionID             string
	ModelAccessGroupIDs   []string
	MatchedQuotaPolicyIDs []string
	SettlementID          string
	SettlementRequestID   string
	SettlementAt          time.Time
}

func appendUniqueQuotaStr(dst []string, vals ...string) []string {
	for _, raw := range vals {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || slices.Contains(dst, trimmed) {
			continue
		}
		dst = append(dst, trimmed)
	}
	return dst
}

func appendCSVQuotaTags(dst []string, raw string) []string {
	for _, part := range strings.Split(raw, ",") {
		dst = appendUniqueQuotaStr(dst, part)
	}
	return dst
}

func extractMetadataTagParts(md map[string]string, explicit []string, candidates []string) ([]string, []string) {
	for k, v := range md {
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if key == "" || val == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "tags":
			explicit = appendCSVQuotaTags(explicit, val)
			candidates = appendCSVQuotaTags(candidates, val)
		case "tag":
			explicit = appendUniqueQuotaStr(explicit, val)
			candidates = appendUniqueQuotaStr(candidates, val)
		default:
			candidates = appendUniqueQuotaStr(candidates, key+":"+val)
		}
	}
	return explicit, candidates
}

// withRequestQuotaState extracts end-user, tag, and session quota attributes from the
// request headers, identity context, and parsed request payload, attaching them to ctx.
func withRequestQuotaState(
	ctx context.Context,
	r *http.Request,
	id *domain.IdentityContext,
	bodyUser string,
	bodyMetadata map[string]string,
	ext *domain.GoRouteExtensions,
) (context.Context, *requestQuotaState) {
	if ctx == nil {
		ctx = context.Background()
	}
	state := &requestQuotaState{
		EndUserID: strings.TrimSpace(bodyUser),
	}
	if id != nil && id.ProjectID != "" {
		state.ProjectID = id.ProjectID
	}
	if ext != nil {
		state.SessionID = strings.TrimSpace(ext.SessionID)
		state.Tags = appendUniqueQuotaStr(state.Tags, ext.Tags...)
	}
	if r != nil {
		if state.SessionID == "" {
			state.SessionID = strings.TrimSpace(r.Header.Get("X-Gateway-Session-Id"))
		}
		for _, raw := range r.Header.Values("X-Gateway-Tags") {
			state.Tags = appendCSVQuotaTags(state.Tags, raw)
		}
	}
	if id != nil {
		state.Tags = appendUniqueQuotaStr(state.Tags, id.KeyTags...)
	}
	state.TagCandidates = appendUniqueQuotaStr(state.TagCandidates, state.Tags...)
	state.Tags, state.TagCandidates = extractMetadataTagParts(bodyMetadata, state.Tags, state.TagCandidates)
	if id != nil {
		state.Tags, state.TagCandidates = extractMetadataTagParts(id.KeyMetadata, state.Tags, state.TagCandidates)
	}
	return context.WithValue(ctx, requestQuotaStateContextKey{}, state), state
}

func requestQuotaStateFromContext(ctx context.Context) *requestQuotaState {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(requestQuotaStateContextKey{}).(*requestQuotaState)
	return state
}

func enrichSpendEventFromContext(ctx context.Context, ev domain.SpendEvent) domain.SpendEvent {
	state := requestQuotaStateFromContext(ctx)
	if state == nil {
		return ev
	}
	if state.SettlementID != "" && ev.RequestID == state.SettlementRequestID {
		ev.ID = state.SettlementID
		if !state.SettlementAt.IsZero() {
			ev.CreatedAt = state.SettlementAt
		}
	}
	if ev.ProjectID == "" && state.ProjectID != "" {
		ev.ProjectID = state.ProjectID
	}
	if ev.EndUserID == "" && state.EndUserID != "" {
		ev.EndUserID = state.EndUserID
	}
	if len(ev.Tags) == 0 && len(state.Tags) > 0 {
		ev.Tags = slices.Clone(state.Tags)
	}
	if ev.SessionID == "" && state.SessionID != "" {
		ev.SessionID = state.SessionID
	}
	if len(ev.ModelAccessGroupIDs) == 0 && len(state.ModelAccessGroupIDs) > 0 {
		ev.ModelAccessGroupIDs = slices.Clone(state.ModelAccessGroupIDs)
	}
	if len(ev.MatchedQuotaPolicyIDs) == 0 && len(state.MatchedQuotaPolicyIDs) > 0 {
		ev.MatchedQuotaPolicyIDs = slices.Clone(state.MatchedQuotaPolicyIDs)
	}
	return ev
}

// applyEffectiveTempBudgets returns a shallow copy of id with active temporary
// budget boosts applied to key, team, user, and org limits when now < expires_at.
// Temporary boost fields are cleared on the copy so repeated calls are idempotent.
func applyEffectiveTempBudgets(id *domain.IdentityContext, now time.Time) *domain.IdentityContext {
	if id == nil {
		return nil
	}
	cp := *id
	cp.KeyMaxBudgetMicros = domain.EffectiveMaxBudgetMicros(id.KeyMaxBudgetMicros, id.KeyTempBudgetIncreaseMicros, id.KeyTempBudgetExpiresAt, now)
	cp.KeyTempBudgetIncreaseMicros = 0
	cp.KeyTempBudgetExpiresAt = nil
	cp.TeamMaxBudgetMicros = domain.EffectiveMaxBudgetMicros(id.TeamMaxBudgetMicros, id.TeamTempBudgetIncreaseMicros, id.TeamTempBudgetExpiresAt, now)
	cp.TeamTempBudgetIncreaseMicros = 0
	cp.TeamTempBudgetExpiresAt = nil
	cp.UserMaxBudgetMicros = domain.EffectiveMaxBudgetMicros(id.UserMaxBudgetMicros, id.UserTempBudgetIncreaseMicros, id.UserTempBudgetExpiresAt, now)
	cp.UserTempBudgetIncreaseMicros = 0
	cp.UserTempBudgetExpiresAt = nil
	cp.OrgMaxBudgetMicros = domain.EffectiveMaxBudgetMicros(id.OrgMaxBudgetMicros, id.OrgTempBudgetIncreaseMicros, id.OrgTempBudgetExpiresAt, now)
	cp.OrgTempBudgetIncreaseMicros = 0
	cp.OrgTempBudgetExpiresAt = nil
	return &cp
}

func teamMemberScopeID(teamID, userID string) string {
	teamID = strings.TrimSpace(teamID)
	userID = strings.TrimSpace(userID)
	if teamID == "" || userID == "" {
		return ""
	}
	return teamID + ":" + userID
}

func matchesQuotaScope(id *domain.IdentityContext, scopeType domain.QuotaScopeType, scopeID string) bool {
	if id == nil || scopeID == "" {
		return false
	}
	switch scopeType {
	case domain.QuotaScopeOrg, domain.QuotaScopeModelPerOrg:
		return id.OrgID != "" && scopeID == id.OrgID
	case domain.QuotaScopeTeam, domain.QuotaScopeModelPerTeam:
		return id.TeamID != "" && scopeID == id.TeamID
	case domain.QuotaScopeTeamMember:
		tmID := teamMemberScopeID(id.TeamID, id.UserID)
		return tmID != "" && scopeID == tmID
	case domain.QuotaScopeProject, domain.QuotaScopeModelPerProject:
		return id.ProjectID != "" && scopeID == id.ProjectID
	case domain.QuotaScopeUser, domain.QuotaScopeModelPerUser:
		return id.UserID != "" && scopeID == id.UserID
	case domain.QuotaScopeKey, domain.QuotaScopeModelPerKey:
		return id.VirtualKeyID != "" && scopeID == id.VirtualKeyID
	default:
		return false
	}
}

func matchesQuotaModelPattern(pattern, requestedModel string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return false
	}
	if auth.MatchesModelPattern(pattern, requestedModel) {
		return true
	}
	if !strings.Contains(pattern, "/") {
		_, bareModel, _ := config.ParseProviderModel(requestedModel)
		if bareModel != "" && auth.MatchesModelPattern(pattern, bareModel) {
			return true
		}
	}
	return false
}

// buildIdentityBaseDescriptors builds descriptors for the four legacy identity
// scopes (key, team, user, org) with active temporary budget boosts applied.
func buildIdentityBaseDescriptors(effID *domain.IdentityContext) []domain.RateLimitDescriptor {
	if effID == nil {
		return nil
	}
	candidates := []domain.RateLimitDescriptor{
		{
			ScopeType:        domain.QuotaScopeKey,
			ScopeID:          effID.VirtualKeyID,
			ModelPattern:     "*",
			RPMLimit:         effID.KeyRPMLimit,
			TPMLimit:         effID.KeyTPMLimit,
			MaxConcurrent:    effID.KeyMaxConcurrent,
			MaxBudgetMicros:  effID.KeyMaxBudgetMicros,
			SpentFloorMicros: effID.KeySpentMicros,
		},
		{
			ScopeType:        domain.QuotaScopeTeam,
			ScopeID:          effID.TeamID,
			ModelPattern:     "*",
			RPMLimit:         effID.TeamRPMLimit,
			TPMLimit:         effID.TeamTPMLimit,
			MaxConcurrent:    effID.TeamMaxConcurrent,
			MaxBudgetMicros:  effID.TeamMaxBudgetMicros,
			SpentFloorMicros: effID.TeamSpentMicros,
		},
		{
			ScopeType:        domain.QuotaScopeUser,
			ScopeID:          effID.UserID,
			ModelPattern:     "*",
			RPMLimit:         effID.UserRPMLimit,
			TPMLimit:         effID.UserTPMLimit,
			MaxConcurrent:    effID.UserMaxConcurrent,
			MaxBudgetMicros:  effID.UserMaxBudgetMicros,
			SpentFloorMicros: effID.UserSpentMicros,
		},
		{
			ScopeType:        domain.QuotaScopeOrg,
			ScopeID:          effID.OrgID,
			ModelPattern:     "*",
			RPMLimit:         effID.OrgRPMLimit,
			TPMLimit:         effID.OrgTPMLimit,
			MaxConcurrent:    effID.OrgMaxConcurrent,
			MaxBudgetMicros:  effID.OrgMaxBudgetMicros,
			SpentFloorMicros: effID.OrgSpentMicros,
		},
	}
	var out []domain.RateLimitDescriptor
	for _, d := range candidates {
		if d.ScopeID != "" && d.HasLimits() {
			out = append(out, d)
		}
	}
	return out
}

// buildExtendedQuotaDescriptors builds descriptors not covered by the legacy 4-scope
// limiter: team_member, project, end_user, tag, model_access_group, agent_session,
// active QuotaPolicy entries (including per-model ITPM/OTPM/TPD/RPM/TPM/concurrency/budget
// policies), and BudgetWindowLimit entries across daily/weekly/monthly/rolling_24h windows.
func (s *GatewayServer) buildExtendedQuotaDescriptors(ctx context.Context, effID *domain.IdentityContext, model string, now time.Time) ([]domain.RateLimitDescriptor, error) {
	if effID == nil {
		return nil, nil
	}
	var out []domain.RateLimitDescriptor
	state := requestQuotaStateFromContext(ctx)
	if state != nil {
		state.ModelAccessGroupIDs = nil
		state.MatchedQuotaPolicyIDs = nil
		if state.ProjectID == "" && effID.ProjectID != "" {
			state.ProjectID = effID.ProjectID
		}
	}

	if tmID := teamMemberScopeID(effID.TeamID, effID.UserID); tmID != "" {
		d := domain.RateLimitDescriptor{
			ScopeType:        domain.QuotaScopeTeamMember,
			ScopeID:          tmID,
			ModelPattern:     "*",
			RPMLimit:         effID.TeamMemberRPMLimit,
			TPMLimit:         effID.TeamMemberTPMLimit,
			MaxBudgetMicros:  effID.TeamMemberMaxBudgetMicros,
			SpentFloorMicros: effID.TeamMemberSpentMicros,
		}
		if d.HasLimits() {
			out = append(out, d)
		}
	}
	if effID.ProjectID != "" {
		d := domain.RateLimitDescriptor{
			ScopeType:        domain.QuotaScopeProject,
			ScopeID:          effID.ProjectID,
			ModelPattern:     "*",
			RPMLimit:         effID.ProjectRPMLimit,
			TPMLimit:         effID.ProjectTPMLimit,
			MaxBudgetMicros:  effID.ProjectMaxBudgetMicros,
			SpentFloorMicros: effID.ProjectSpentMicros,
		}
		if d.HasLimits() {
			out = append(out, d)
		}
	}

	if state != nil && state.SessionID != "" {
		maxIter := minPositiveInt(effID.KeyMaxIterations, effID.TeamMaxIterations, effID.OrgMaxIterations)
		maxSessBudget := minPositiveInt64(effID.KeyMaxBudgetPerSessionMicros, effID.TeamMaxBudgetPerSessionMicros, effID.OrgMaxBudgetPerSessionMicros)
		ttlSec := 0
		if s != nil && s.cfg != nil {
			if maxIter == 0 && s.cfg.RateLimit.DefaultAgentSessionMaxIterations > 0 {
				maxIter = s.cfg.RateLimit.DefaultAgentSessionMaxIterations
			}
			if maxSessBudget == 0 && s.cfg.RateLimit.DefaultAgentSessionMaxBudgetMicros > 0 {
				maxSessBudget = s.cfg.RateLimit.DefaultAgentSessionMaxBudgetMicros
			}
			ttlSec = s.cfg.RateLimit.DefaultAgentSessionTTLSec
		}
		sessDesc := domain.RateLimitDescriptor{
			ScopeType:       domain.QuotaScopeAgentSession,
			ScopeID:         state.SessionID,
			ModelPattern:    "*",
			MaxIterations:   maxIter,
			MaxBudgetMicros: maxSessBudget,
			WindowTTLSec:    ttlSec,
		}
		if sessDesc.HasLimits() {
			out = append(out, sessDesc)
		}
	}

	if s == nil || s.repo == nil || effID.OrgID == "" {
		return mergeExtendedDescriptors(out), nil
	}

	// EndUser auto-create / lookup strictly scoped by (org_id, end_user_id) via L1 cache when available.
	if state != nil && state.EndUserID != "" {
		var (
			eu  *domain.EndUser
			err error
		)
		if s.rbac != nil {
			eu, err = s.rbac.GetOrCreateCachedEndUser(ctx, effID.OrgID, state.EndUserID)
		} else if euRepo, ok := s.repo.(storage.EndUserRepository); ok && euRepo != nil {
			eu, err = euRepo.GetOrCreateEndUser(ctx, effID.OrgID, state.EndUserID)
		}
		if err != nil {
			return nil, err
		}
		if eu != nil {
			if !eu.IsActive {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "end_user_blocked",
					Message:    fmt.Sprintf("End user %q is blocked", eu.EndUserID),
				}
			}
			if len(eu.AllowedModels) > 0 && !matchesQuotaModelList(eu.AllowedModels, model) {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "end_user_model_restricted",
					Message:    fmt.Sprintf("End user %q is not authorized to use model %q", eu.EndUserID, model),
				}
			}
			if d := eu.ToDescriptor(); d.HasLimits() {
				out = append(out, d)
			}
		}
	}

	// Active Tag quotas within org_id via RBAC L1/L2 cache when available.
	if state != nil && len(state.TagCandidates) > 0 {
		var (
			tags []*domain.Tag
			err  error
		)
		if s.rbac != nil {
			tags, err = s.rbac.GetCachedTags(ctx, effID.OrgID)
		} else if tagRepo, ok := s.repo.(storage.TagRepository); ok && tagRepo != nil {
			tags, err = tagRepo.ListTags(ctx, storage.TagFilter{
				OrgID:      effID.OrgID,
				ActiveOnly: true,
			})
		}
		if err != nil {
			return nil, err
		}
		for _, t := range tags {
			if t == nil || !t.IsActive || t.OrgID != effID.OrgID {
				continue
			}
			if !slices.Contains(state.TagCandidates, t.Tag) {
				continue
			}
			state.Tags = appendUniqueQuotaStr(state.Tags, t.Tag)
			if len(t.AllowedModels) > 0 && !matchesQuotaModelList(t.AllowedModels, model) {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "tag_model_restricted",
					Message:    fmt.Sprintf("Tag %q is not authorized to use model %q", t.Tag, model),
				}
			}
			if d := t.ToDescriptor(); d.HasLimits() {
				out = append(out, d)
			}
		}
	}

	// Active ModelAccessGroup quotas & spend attribution within org_id via RBAC L1/L2 cache.
	var (
		magEval auth.ModelAccessGroupEvaluation
		err     error
	)
	if s.rbac != nil {
		magEval, err = s.rbac.EvaluateModelAccessGroupsWithCache(ctx, effID, model, effID.AccessGroups)
	} else {
		magEval, err = auth.EvaluateModelAccessGroups(ctx, s.repo, effID, model, effID.AccessGroups)
	}
	if err != nil {
		return nil, err
	}
	if len(magEval.MatchingGroups) > 0 {
		for _, g := range magEval.MatchingGroups {
			if g == nil {
				continue
			}
			if state != nil {
				state.ModelAccessGroupIDs = appendUniqueQuotaStr(state.ModelAccessGroupIDs, g.ID)
			}
			if d := g.ToDescriptor(); d.HasLimits() {
				out = append(out, d)
			}
		}
	}

	var policies []*domain.QuotaPolicy
	if s.rbac != nil {
		policies, err = s.rbac.GetCachedQuotaPolicies(ctx, effID.OrgID)
	} else if qRepo, ok := s.repo.(storage.QuotaPolicyRepository); ok && qRepo != nil {
		policies, err = qRepo.ListQuotaPolicies(ctx, storage.QuotaPolicyFilter{
			OrgID:      effID.OrgID,
			ActiveOnly: true,
		})
	}
	if err != nil {
		return nil, err
	}
	for _, qp := range policies {
		if qp == nil || !qp.IsActive {
			continue
		}
		if !matchesQuotaModelPattern(qp.ModelPattern, model) {
			continue
		}
		desc := qp.ToDescriptor()
		if !resolveScopeDescriptorID(effID, state, magEval.MatchingGroups, &desc) {
			continue
		}
		if desc.ScopeType == domain.QuotaScopeAgentSession && desc.WindowTTLSec <= 0 && s.cfg != nil && s.cfg.RateLimit.DefaultAgentSessionTTLSec > 0 {
			desc.WindowTTLSec = s.cfg.RateLimit.DefaultAgentSessionTTLSec
		}
		if state != nil && qp.ID != "" {
			state.MatchedQuotaPolicyIDs = appendUniqueQuotaStr(state.MatchedQuotaPolicyIDs, qp.ID)
		}
		if desc.HasLimits() {
			out = append(out, desc)
		}
	}

	var windows []*domain.BudgetWindowLimit
	if bwRepo, ok := s.repo.(storage.BudgetWindowRepository); ok && bwRepo != nil {
		_, hasRollingHistory := s.repo.(storage.RollingSpendHistoryRepository)
		windows, err = bwRepo.ListBudgetWindowLimits(ctx, storage.BudgetWindowFilter{
			OrgID: effID.OrgID, SkipRollingSpend: hasRollingHistory,
		})
	}
	if err != nil {
		return nil, err
	}
	for _, bw := range windows {
		if bw == nil || bw.MaxBudgetMicros <= 0 {
			continue
		}
		desc := bw.ToDescriptor()
		if !resolveScopeDescriptorID(effID, state, magEval.MatchingGroups, &desc) {
			continue
		}
		if bw.WindowType != domain.BudgetWindowRolling24h && !bw.WindowResetAt.IsZero() && !now.Before(bw.WindowResetAt) {
			// Periodic window has expired and is awaiting background reset.
			desc.SpentFloorMicros = 0
		}
		if desc.HasLimits() {
			out = append(out, desc)
		}
	}

	return mergeExtendedDescriptors(out), nil
}

func matchesQuotaModelList(allowed []string, model string) bool {
	for _, pat := range allowed {
		if matchesQuotaModelPattern(pat, model) {
			return true
		}
	}
	return false
}

func resolveScopeDescriptorID(
	effID *domain.IdentityContext,
	state *requestQuotaState,
	groups []*domain.ModelAccessGroup,
	desc *domain.RateLimitDescriptor,
) bool {
	if desc == nil {
		return false
	}
	switch desc.ScopeType {
	case domain.QuotaScopeEndUser, domain.QuotaScopeModelPerEndUser:
		if state == nil || state.EndUserID == "" {
			return false
		}
		if desc.ScopeID != "*" && desc.ScopeID != state.EndUserID {
			return false
		}
		desc.ScopeID = state.EndUserID
		return true
	case domain.QuotaScopeTag:
		if state == nil || !slices.Contains(state.TagCandidates, desc.ScopeID) {
			return false
		}
		state.Tags = appendUniqueQuotaStr(state.Tags, desc.ScopeID)
		return true
	case domain.QuotaScopeModelAccessGroup:
		for _, g := range groups {
			if g != nil && (desc.ScopeID == g.ID || desc.ScopeID == g.Name) {
				desc.ScopeID = g.ID
				if state != nil {
					state.ModelAccessGroupIDs = appendUniqueQuotaStr(state.ModelAccessGroupIDs, g.ID)
				}
				return true
			}
		}
		return false
	case domain.QuotaScopeAgentSession:
		if state == nil || state.SessionID == "" {
			return false
		}
		if desc.ScopeID != "*" && desc.ScopeID != state.SessionID {
			return false
		}
		desc.ScopeID = state.SessionID
		return true
	default:
		return matchesQuotaScope(effID, desc.ScopeType, desc.ScopeID)
	}
}

func minPositiveInt(vals ...int) int {
	best := 0
	for _, v := range vals {
		if v > 0 && (best == 0 || v < best) {
			best = v
		}
	}
	return best
}

func minPositiveInt64(vals ...int64) int64 {
	best := int64(0)
	for _, v := range vals {
		if v > 0 && (best == 0 || v < best) {
			best = v
		}
	}
	return best
}

type descriptorMergeKey struct {
	ScopeType    domain.QuotaScopeType
	ScopeID      string
	ModelPattern string
	WindowType   domain.BudgetWindowType
}

func mergeExtendedDescriptors(descriptors []domain.RateLimitDescriptor) []domain.RateLimitDescriptor {
	if len(descriptors) <= 1 {
		return descriptors
	}
	out := make([]domain.RateLimitDescriptor, 0, len(descriptors))
	indexByKey := make(map[descriptorMergeKey]int, len(descriptors))
	for _, d := range descriptors {
		if !d.HasLimits() {
			continue
		}
		if d.ModelPattern == "" {
			d.ModelPattern = "*"
		}
		key := descriptorMergeKey{
			ScopeType:    d.ScopeType,
			ScopeID:      d.ScopeID,
			ModelPattern: d.ModelPattern,
			WindowType:   d.WindowType,
		}
		if idx, exists := indexByKey[key]; exists {
			existing := &out[idx]
			existing.RPMLimit = minPositiveInt(existing.RPMLimit, d.RPMLimit)
			existing.TPMLimit = minPositiveInt(existing.TPMLimit, d.TPMLimit)
			existing.ITPMLimit = minPositiveInt(existing.ITPMLimit, d.ITPMLimit)
			existing.OTPMLimit = minPositiveInt(existing.OTPMLimit, d.OTPMLimit)
			existing.TPDLimit = minPositiveInt64(existing.TPDLimit, d.TPDLimit)
			existing.MaxConcurrent = minPositiveInt(existing.MaxConcurrent, d.MaxConcurrent)
			existing.MaxIterations = minPositiveInt(existing.MaxIterations, d.MaxIterations)
			existing.MaxBudgetMicros = minPositiveInt64(existing.MaxBudgetMicros, d.MaxBudgetMicros)
			if d.SpentFloorMicros > existing.SpentFloorMicros {
				existing.SpentFloorMicros = d.SpentFloorMicros
			}
			if d.WindowTTLSec > existing.WindowTTLSec {
				existing.WindowTTLSec = d.WindowTTLSec
			}
			continue
		}
		indexByKey[key] = len(out)
		out = append(out, d)
	}
	return out
}

// buildRequestQuotaDescriptors builds the full descriptor set across key, team,
// team_member, project, user, org, model-scoped policies, and multi-window budgets.
func (s *GatewayServer) buildRequestQuotaDescriptors(ctx context.Context, id *domain.IdentityContext, model string, now time.Time) ([]domain.RateLimitDescriptor, error) {
	if id == nil {
		return nil, nil
	}
	effID := applyEffectiveTempBudgets(id, now)
	base := buildIdentityBaseDescriptors(effID)
	ext, err := s.buildExtendedQuotaDescriptors(ctx, effID, model, now)
	if err != nil {
		return nil, err
	}
	if len(base) == 0 {
		return ext, nil
	}
	if len(ext) == 0 {
		return base, nil
	}
	all := make([]domain.RateLimitDescriptor, 0, len(base)+len(ext))
	all = append(all, base...)
	all = append(all, ext...)
	return all, nil
}

func descriptorsHaveBudget(descriptors []domain.RateLimitDescriptor) bool {
	for _, d := range descriptors {
		if d.MaxBudgetMicros > 0 {
			return true
		}
	}
	return false
}

func hasLegacyBudget(id *domain.IdentityContext) bool {
	return id != nil && (id.KeyMaxBudgetMicros > 0 || id.TeamMaxBudgetMicros > 0 || id.UserMaxBudgetMicros > 0 || id.OrgMaxBudgetMicros > 0)
}

func (s *GatewayServer) requestHasBudget(ctx context.Context, id *domain.IdentityContext, model string) bool {
	if identityHasBudget(id) {
		return true
	}
	if s == nil || id == nil {
		return false
	}
	ext, err := s.buildExtendedQuotaDescriptors(ctx, id, model, s.nowUTC())
	if err != nil {
		return false
	}
	return descriptorsHaveBudget(ext)
}

func (s *GatewayServer) incrementBudgetWindowSpendBestEffort(reqCtx context.Context, id *domain.IdentityContext, deltaMicros int64) {
	if s == nil || s.repo == nil || id == nil || id.OrgID == "" || deltaMicros <= 0 {
		return
	}
	state := requestQuotaStateFromContext(reqCtx)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if bwRepo, ok := s.repo.(storage.BudgetWindowRepository); ok && bwRepo != nil {
		_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeOrg, id.OrgID, deltaMicros)
		if id.TeamID != "" {
			_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeTeam, id.TeamID, deltaMicros)
		}
		if id.UserID != "" {
			_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeUser, id.UserID, deltaMicros)
		}
		if id.VirtualKeyID != "" {
			_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeKey, id.VirtualKeyID, deltaMicros)
		}
		if id.ProjectID != "" {
			_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeProject, id.ProjectID, deltaMicros)
		}
		if tmID := teamMemberScopeID(id.TeamID, id.UserID); tmID != "" {
			_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeTeamMember, tmID, deltaMicros)
		}
		if state != nil {
			if state.EndUserID != "" {
				_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeEndUser, state.EndUserID, deltaMicros)
			}
			for _, tag := range state.Tags {
				_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeTag, tag, deltaMicros)
			}
			for _, magID := range state.ModelAccessGroupIDs {
				_ = bwRepo.IncrementBudgetWindowSpend(ctx, id.OrgID, domain.QuotaScopeModelAccessGroup, magID, deltaMicros)
			}
		}
	}
	if state != nil {
		if state.EndUserID != "" {
			if euRepo, ok := s.repo.(storage.EndUserRepository); ok && euRepo != nil {
				_ = euRepo.IncrementEndUserSpend(ctx, id.OrgID, state.EndUserID, deltaMicros)
			}
		}
		if len(state.Tags) > 0 {
			if tagRepo, ok := s.repo.(storage.TagRepository); ok && tagRepo != nil {
				for _, tag := range state.Tags {
					_ = tagRepo.IncrementTagSpend(ctx, id.OrgID, tag, deltaMicros)
				}
			}
		}
		if len(state.ModelAccessGroupIDs) > 0 {
			if magRepo, ok := s.repo.(storage.ModelAccessGroupRepository); ok && magRepo != nil {
				for _, magID := range state.ModelAccessGroupIDs {
					_ = magRepo.IncrementModelAccessGroupSpend(ctx, magID, deltaMicros)
				}
			}
		}
	}
}
