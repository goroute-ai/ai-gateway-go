package storage

import (
	"context"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestConfigurePostgresPoolRespectsDSNAndOptions(t *testing.T) {
	// Default fallback when neither DSN nor options specify pool sizing.
	cfg, err := configurePostgresPool("postgres://user:pass@localhost:5432/db?sslmode=disable", PostgresPoolOptions{})
	if err != nil {
		t.Fatalf("configurePostgresPool default: %v", err)
	}
	if cfg.MaxConns != 32 || cfg.MinConns != 4 {
		t.Fatalf("expected default MaxConns=32 MinConns=4, got MaxConns=%d MinConns=%d", cfg.MaxConns, cfg.MinConns)
	}

	// DSN pool_max_conns / pool_min_conns must not be overwritten.
	cfg, err = configurePostgresPool("postgres://user:pass@localhost:5432/db?sslmode=disable&pool_max_conns=64&pool_min_conns=8", PostgresPoolOptions{})
	if err != nil {
		t.Fatalf("configurePostgresPool dsn: %v", err)
	}
	if cfg.MaxConns != 64 || cfg.MinConns != 8 {
		t.Fatalf("expected DSN MaxConns=64 MinConns=8, got MaxConns=%d MinConns=%d", cfg.MaxConns, cfg.MinConns)
	}

	// Explicit options override DSN and defaults.
	cfg, err = configurePostgresPool("postgres://user:pass@localhost:5432/db?pool_max_conns=64", PostgresPoolOptions{
		MaxConns: 16,
		MinConns: 2,
	})
	if err != nil {
		t.Fatalf("configurePostgresPool options: %v", err)
	}
	if cfg.MaxConns != 16 || cfg.MinConns != 2 {
		t.Fatalf("expected explicit MaxConns=16 MinConns=2, got MaxConns=%d MinConns=%d", cfg.MaxConns, cfg.MinConns)
	}
}

func TestSortedSpendDeltasDeterministicOrder(t *testing.T) {
	deltas := sortedSpendDeltas(map[string]int64{
		"id-c": 30,
		"id-a": 10,
		"id-b": 20,
		"":     99,
		"id-0": 0,
	})
	if len(deltas) != 3 {
		t.Fatalf("expected 3 positive deltas, got %d", len(deltas))
	}
	want := []spendDelta{
		{id: "id-a", costMicros: 10},
		{id: "id-b", costMicros: 20},
		{id: "id-c", costMicros: 30},
	}
	for i := range want {
		if deltas[i] != want[i] {
			t.Fatalf("delta[%d] = %+v, want %+v", i, deltas[i], want[i])
		}
	}
}

func TestBudgetResetScheduleInitAndUserSpendSummary(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository()

	org := &domain.Organization{ID: "org-sched", Name: "Sched", Slug: "sched", BudgetResetPeriod: domain.BudgetResetDaily, IsActive: true}
	team := &domain.Team{ID: "team-sched", OrgID: org.ID, Name: "Team", BudgetResetPeriod: domain.BudgetResetMonthly, IsActive: true}
	user := &domain.User{ID: "user-sched", OrgID: org.ID, TeamID: team.ID, Email: "u@sched.io", Name: "User", Role: domain.RoleDeveloper, BudgetResetPeriod: domain.BudgetResetDaily, IsActive: true}
	vk := &domain.VirtualKey{ID: "vk-sched", OrgID: org.ID, TeamID: team.ID, UserID: user.ID, KeyHash: "h-sched", Name: "VK", BudgetResetPeriod: domain.BudgetResetNever, IsActive: true}

	for _, err := range []error{
		repo.CreateOrganization(ctx, org),
		repo.CreateTeam(ctx, team),
		repo.CreateUser(ctx, user),
		repo.CreateVirtualKey(ctx, vk),
	} {
		if err != nil {
			t.Fatalf("create entity: %v", err)
		}
	}

	if org.BudgetResetAt == nil || team.BudgetResetAt == nil || user.BudgetResetAt == nil {
		t.Fatalf("expected daily/monthly BudgetResetAt initialized: org=%v team=%v user=%v", org.BudgetResetAt, team.BudgetResetAt, user.BudgetResetAt)
	}
	if vk.BudgetResetAt != nil {
		t.Fatalf("expected never-reset key BudgetResetAt=nil, got %v", vk.BudgetResetAt)
	}

	if err := repo.RecordSpendBatch(ctx, []domain.SpendEvent{
		{ID: "sp-1", RequestID: "r-1", OrgID: org.ID, TeamID: team.ID, UserID: user.ID, VirtualKeyID: vk.ID, CostMicros: 125, Provider: domain.ProviderOpenAI, ResolvedModel: "gpt-4o", CreatedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("RecordSpendBatch: %v", err)
	}

	gotUser, err := repo.GetUser(ctx, user.ID)
	if err != nil || gotUser.SpentMicros != 125 {
		t.Fatalf("expected user spent_micros=125, got %+v err=%v", gotUser, err)
	}

	sum, err := repo.GetSpendSummary(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetSpendSummary: %v", err)
	}
	if sum.SpendByUser[user.ID] != 125 || sum.SpendByTeam[team.ID] != 125 || sum.SpendByVirtualKey[vk.ID] != 125 {
		t.Fatalf("unexpected SpendSummary breakdowns: %+v", sum)
	}
}
