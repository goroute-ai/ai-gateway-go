package router

import (
	"cmp"
	"context"
	"log/slog"
	"slices"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
)

func normalizedPriority(d *domain.Deployment) int {
	if d == nil || d.Priority <= 0 {
		return 0
	}
	return d.Priority
}

var emptyPriorityTiers = [][]*domain.Deployment{}

// partitionByPriority groups deployments into tiers ordered by ascending normalized
// priority (values <= 0 normalize to 0, which is highest priority), preserving
// the original relative order within each tier.
//
// Empty, single-element, and uniform-priority inputs take a zero-alloc fast path
// that avoids copying, sorting, or heap-allocating tier slices.
func partitionByPriority(deployments []*domain.Deployment) [][]*domain.Deployment {
	if tiers := partitionByPriorityMultiIfNeeded(deployments); tiers != nil {
		return tiers
	}
	return [][]*domain.Deployment{deployments}
}

func partitionByPriorityMultiIfNeeded(deployments []*domain.Deployment) [][]*domain.Deployment {
	if len(deployments) == 0 {
		return emptyPriorityTiers
	}
	if len(deployments) == 1 {
		return nil
	}
	first := normalizedPriority(deployments[0])
	for _, d := range deployments[1:] {
		if normalizedPriority(d) != first {
			return partitionByPriorityMulti(deployments)
		}
	}
	return nil
}

func partitionByPriorityMulti(deployments []*domain.Deployment) [][]*domain.Deployment {
	sorted := make([]*domain.Deployment, len(deployments))
	copy(sorted, deployments)
	slices.SortStableFunc(sorted, func(a, b *domain.Deployment) int {
		return cmp.Compare(normalizedPriority(a), normalizedPriority(b))
	})

	var tiers [][]*domain.Deployment
	start := 0
	curPriority := normalizedPriority(sorted[0])
	for i := 1; i < len(sorted); i++ {
		p := normalizedPriority(sorted[i])
		if p != curPriority {
			tiers = append(tiers, sorted[start:i])
			start = i
			curPriority = p
		}
	}
	tiers = append(tiers, sorted[start:])
	return tiers
}

func maxAttemptsForGroup(group *domain.ModelGroup) int {
	if group == nil || group.MaxRetries < 0 {
		return 1
	}
	return group.MaxRetries + 1
}

func recordTierStepdown(ctx context.Context, meta *ExecutionMeta, group *domain.ModelGroup, tierIdx int) {
	if meta != nil {
		meta.TierStepdowns++
		meta.FallbackReason = "priority_tier_stepdown"
	}
	groupAlias := ""
	if group != nil {
		groupAlias = group.Alias
	}
	logger.WarnContext(ctx, "Priority tier stepdown activated",
		slog.String("component", "router"),
		slog.String("group_alias", groupAlias),
		slog.Int("tier_index", tierIdx),
	)
}
