package router

import (
	"context"
	"fmt"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestBuildGroupChainTraversesNestedFallbacksWithoutDuplicates(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	primary := createFallbackTestGroup(t, repo, "org-a", "primary")
	b := createFallbackTestGroup(t, repo, "org-a", "b")
	c := createFallbackTestGroup(t, repo, "org-a", "c")
	d := createFallbackTestGroup(t, repo, "org-a", "d")
	foreign := createFallbackTestGroup(t, repo, "org-b", "foreign")
	primary.FallbackGroupIDs = []string{b.ID, c.Alias, b.ID, "missing", foreign.ID}
	b.FallbackGroupIDs = []string{c.ID, primary.Alias}
	c.FallbackGroupIDs = []string{b.ID, d.ID}
	for _, group := range []*domain.ModelGroup{primary, b, c, d, foreign} {
		if err := repo.CreateModelGroup(ctx, group); err != nil {
			t.Fatal(err)
		}
	}

	rm := NewReliabilityManager(repo, nil, nil, nil, nil, nil, nil, config.RouterConfig{})
	chain := rm.buildGroupChain(ctx, primary)
	want := []string{primary.ID, b.ID, c.ID, d.ID}
	if len(chain) != len(want) {
		t.Fatalf("expected %d fallback groups, got %d", len(want), len(chain))
	}
	for i, group := range chain {
		if group.ID != want[i] {
			t.Fatalf("chain[%d] = %q, want %q", i, group.ID, want[i])
		}
	}
}

func TestBuildGroupChainEnforcesMaximumDepth(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	var child *domain.ModelGroup
	for i := maxFallbackDepth + 3; i >= 0; i-- {
		alias := fmt.Sprintf("group-%d", i)
		fallbacks := []string(nil)
		if child != nil {
			fallbacks = []string{child.ID}
		}
		child = createFallbackTestGroup(t, repo, "org-depth", alias, fallbacks...)
	}

	rm := NewReliabilityManager(repo, nil, nil, nil, nil, nil, nil, config.RouterConfig{})
	chain := rm.buildGroupChain(ctx, child)
	if got, want := len(chain), maxFallbackDepth+1; got != want {
		t.Fatalf("chain length = %d, want depth-bounded length %d", got, want)
	}
}

func createFallbackTestGroup(t *testing.T, repo *storage.MemoryRepository, orgID, alias string, fallbacks ...string) *domain.ModelGroup {
	t.Helper()
	group := &domain.ModelGroup{
		OrgID:            orgID,
		Alias:            alias,
		RoutingStrategy:  domain.StrategyWeightedShuffle,
		FallbackGroupIDs: fallbacks,
		IsActive:         true,
	}
	if err := repo.CreateModelGroup(context.Background(), group); err != nil {
		t.Fatal(err)
	}
	return group
}
