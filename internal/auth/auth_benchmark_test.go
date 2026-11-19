package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func setupAuthBenchFixture(b *testing.B, withRedis bool) (*auth.Service, *auth.RBACEngine, string, func()) {
	b.Helper()
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	var rf *storage.RedisFabric
	var cleanup func()
	if withRedis {
		mr, err := miniredis.Run()
		if err != nil {
			b.Fatalf("miniredis run: %v", err)
		}
		rf = storage.NewRedisFabric(mr.Addr(), "", 0)
		cleanup = mr.Close
	} else {
		cleanup = func() {}
	}

	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-bench", Name: "Bench Org", IsActive: true}); err != nil {
		b.Fatal(err)
	}
	if err := repo.CreateTeam(ctx, &domain.Team{
		ID:            "team-bench",
		OrgID:         "org-bench",
		Name:          "Bench Team",
		AllowedModels: []string{"gpt-4*", "claude-*"},
		IsActive:      true,
	}); err != nil {
		b.Fatal(err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:       "user-bench",
		OrgID:    "org-bench",
		TeamID:   "team-bench",
		Email:    "bench@example.com",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}); err != nil {
		b.Fatal(err)
	}
	_ = repo.UpsertModelAccessGroup(ctx, &domain.ModelAccessGroup{
		ID:       "mag-bench",
		OrgID:    "org-bench",
		Name:     "bench-models",
		IsActive: true,
		Members: []*domain.ModelAccessGroupMember{
			{ID: "m1", OrgID: "org-bench", GroupID: "mag-bench", MemberType: domain.ModelAccessGroupMemberModel, MemberID: "gpt-4o-*"},
			{ID: "m2", OrgID: "org-bench", GroupID: "mag-bench", MemberType: domain.ModelAccessGroupMemberTeam, MemberID: "team-bench"},
		},
	})

	svc := auth.NewService(repo, rf, "bench-master-key-0123456789abcdef", time.Minute, time.Minute)
	rbac := auth.NewRBACEngine(repo)
	if rf != nil {
		rbac.SetRedis(rf)
	}
	vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:         "org-bench",
		TeamID:        "team-bench",
		UserID:        "user-bench",
		Name:          "bench-key",
		AllowedModels: []string{"gpt-4*"},
	})
	if err != nil {
		b.Fatal(err)
	}
	return svc, rbac, vk.RawKey, cleanup
}

func BenchmarkAuthenticateVirtualKey_L1Hit(b *testing.B) {
	svc, _, rawKey, cleanup := setupAuthBenchFixture(b, false)
	defer cleanup()

	ctx := context.Background()
	if _, err := svc.AuthenticateVirtualKey(ctx, rawKey); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.AuthenticateVirtualKey(ctx, rawKey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthenticateVirtualKey_RedisL2Hit(b *testing.B) {
	ctx := context.Background()
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatalf("miniredis run: %v", err)
	}
	defer mr.Close()

	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-l2", Name: "L2 Org", IsActive: true}); err != nil {
		b.Fatal(err)
	}
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	writerSvc := auth.NewService(repo, rf, "bench-master-key-0123456789abcdef", time.Minute, time.Minute)
	vk, err := writerSvc.IssueVirtualKey(ctx, &domain.VirtualKey{OrgID: "org-l2", Name: "l2-key"})
	if err != nil {
		b.Fatal(err)
	}
	// Warm L2 Redis cache via writerSvc.
	if _, err := writerSvc.AuthenticateVirtualKey(ctx, vk.RawKey); err != nil {
		b.Fatal(err)
	}

	// Reader service exercises L2 fetch path on a cold L1 entry when invalidated between iterations,
	// and measures warmed L1+epoch path after initial hit.
	readerSvc := auth.NewService(repo, rf, "bench-master-key-0123456789abcdef", time.Minute, time.Minute)
	if _, err := readerSvc.AuthenticateVirtualKey(ctx, vk.RawKey); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := readerSvc.AuthenticateVirtualKey(ctx, vk.RawKey); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthorizeRequestedModelWithEval(b *testing.B) {
	svc, rbac, rawKey, cleanup := setupAuthBenchFixture(b, false)
	defer cleanup()

	ctx := context.Background()
	idCtx, err := svc.AuthenticateVirtualKey(ctx, rawKey)
	if err != nil {
		b.Fatal(err)
	}
	// Warm cached model access group slice.
	if _, err := rbac.AuthorizeRequestedModelWithEval(idCtx, "gpt-4o-mini"); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rbac.AuthorizeRequestedModelWithEval(idCtx, "gpt-4o-mini"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatchesModelPattern(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !auth.MatchesModelPattern("anthropic/claude-3-*-sonnet-*", "anthropic/claude-3-5-sonnet-20241022") {
			b.Fatal("expected pattern match")
		}
	}
}
