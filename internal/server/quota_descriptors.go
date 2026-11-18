package server

import (
	"context"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

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
	matchTarget := func(target string) bool {
		if pattern == target {
			return true
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if prefix != "" && strings.HasPrefix(target, prefix) {
				return true
			}
		}
		return false
	}
	if matchTarget(requestedModel) {
		return true
	}
	if !strings.Contains(pattern, "/") {
		_, bareModel, _ := config.ParseProviderModel(requestedModel)
		if bareModel != "" && matchTarget(bareModel) {
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
// limiter: team_member, project, active QuotaPolicy entries (including per-model
// ITPM/OTPM/TPD/RPM/TPM/concurrency/budget policies), and BudgetWindowLimit entries
// across daily/weekly/monthly/rolling_24h windows.
func (s *GatewayServer) buildExtendedQuotaDescriptors(ctx context.Context, effID *domain.IdentityContext, model string, now time.Time) ([]domain.RateLimitDescriptor, error) {
	if effID == nil {
		return nil, nil
	}
	var out []domain.RateLimitDescriptor

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

	if s == nil || s.repo == nil || effID.OrgID == "" {
		return out, nil
	}

	if qRepo, ok := s.repo.(storage.QuotaPolicyRepository); ok && qRepo != nil {
		policies, err := qRepo.ListQuotaPolicies(ctx, storage.QuotaPolicyFilter{
			OrgID:      effID.OrgID,
			ActiveOnly: true,
		})
		if err != nil {
			return nil, err
		}
		for _, qp := range policies {
			if qp == nil || !qp.IsActive {
				continue
			}
			if !matchesQuotaScope(effID, qp.ScopeType, qp.ScopeID) {
				continue
			}
			if !matchesQuotaModelPattern(qp.ModelPattern, model) {
				continue
			}
			desc := qp.ToDescriptor()
			if desc.HasLimits() {
				out = append(out, desc)
			}
		}
	}

	if bwRepo, ok := s.repo.(storage.BudgetWindowRepository); ok && bwRepo != nil {
		windows, err := bwRepo.ListBudgetWindowLimits(ctx, storage.BudgetWindowFilter{
			OrgID: effID.OrgID,
		})
		if err != nil {
			return nil, err
		}
		for _, bw := range windows {
			if bw == nil || bw.MaxBudgetMicros <= 0 {
				continue
			}
			if !matchesQuotaScope(effID, bw.ScopeType, bw.ScopeID) {
				continue
			}
			desc := bw.ToDescriptor()
			if !bw.WindowResetAt.IsZero() && !now.Before(bw.WindowResetAt) {
				// Window has expired and is awaiting background reset.
				desc.SpentFloorMicros = 0
			}
			if desc.HasLimits() {
				out = append(out, desc)
			}
		}
	}

	return out, nil
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
	ext, err := s.buildExtendedQuotaDescriptors(ctx, id, model, time.Now().UTC())
	if err != nil {
		return false
	}
	return descriptorsHaveBudget(ext)
}

func (s *GatewayServer) incrementBudgetWindowSpendBestEffort(id *domain.IdentityContext, deltaMicros int64) {
	if s == nil || s.repo == nil || id == nil || id.OrgID == "" || deltaMicros <= 0 {
		return
	}
	bwRepo, ok := s.repo.(storage.BudgetWindowRepository)
	if !ok || bwRepo == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
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
}
