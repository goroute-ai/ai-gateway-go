package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type slowBundleRepo struct {
	*storage.MemoryRepository
	calls       atomic.Int32
	onFirstRead func()
}

func (r *slowBundleRepo) GetVirtualKeyAuthBundleByHash(ctx context.Context, keyHash string, now time.Time) (*storage.VirtualKeyAuthBundle, error) {
	n := r.calls.Add(1)
	if n == 1 && r.onFirstRead != nil {
		r.onFirstRead()
	}
	return r.MemoryRepository.GetVirtualKeyAuthBundleByHash(ctx, keyHash, now)
}

func TestAuthenticateVirtualKey_SingleflightAndAntiStampedeLease(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryRepository()
	if err := mem.CreateOrganization(ctx, &domain.Organization{ID: "org-sf", Name: "SF", IsActive: true}); err != nil {
		t.Fatal(err)
	}

	// 1. Concurrent cold misses collapse into 1 DB bundle query.
	gate := make(chan struct{})
	repo := &slowBundleRepo{
		MemoryRepository: mem,
		onFirstRead: func() {
			<-gate
		},
	}
	svc := auth.NewService(repo, nil, "master-admin", time.Minute, time.Minute)
	vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org-sf",
		Name:  "sf-key",
	})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 12
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			idCtx, authErr := svc.AuthenticateVirtualKey(ctx, vk.RawKey)
			if authErr != nil {
				errs <- authErr
				return
			}
			if idCtx.VirtualKeyID != vk.ID {
				errs <- authErr
			}
		}()
	}
	time.Sleep(30 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent AuthenticateVirtualKey failed: %v", e)
	}
	if got := repo.calls.Load(); got != 1 {
		t.Fatalf("expected singleflight to collapse 12 cold misses into 1 DB call, got %d", got)
	}

	// 2. Concurrent invalidation during slow read prevents stale L1 cache write.
	svc2 := auth.NewService(repo, nil, "master-admin", time.Minute, time.Minute)
	repo.calls.Store(0)
	var gate2 sync.WaitGroup
	gate2.Add(1)
	repo.onFirstRead = func() {
		// Simulate an invalidation arriving while the DB read is in-flight
		svc2.InvalidateKeyHash(ctx, vk.KeyHash)
		gate2.Done()
	}
	if _, err := svc2.AuthenticateVirtualKey(ctx, vk.RawKey); err != nil {
		t.Fatalf("expected first lookup to succeed: %v", err)
	}
	gate2.Wait()
	// Because invalidation happened mid-read, L1 must NOT have been populated, so a second read hits DB again.
	if _, err := svc2.AuthenticateVirtualKey(ctx, vk.RawKey); err != nil {
		t.Fatalf("second lookup failed: %v", err)
	}
	if got := repo.calls.Load(); got != 2 {
		t.Fatalf("expected 2 DB calls when invalidation landed mid-read (cache lease protection), got %d", got)
	}
}

func TestMatchesModelPattern_WildcardGlobs(t *testing.T) {
	cases := []struct {
		pattern string
		target  string
		want    bool
	}{
		{"*", "openai/gpt-4.1", true},
		{"openai/*", "openai/gpt-4.1", true},
		{"bedrock/us.*", "bedrock/us.anthropic.claude-3-5-sonnet", true},
		{"bedrock/us.*", "bedrock/eu.anthropic.claude-3-5-sonnet", false},
		{"*-mini", "gpt-4.1-mini", true},
		{"*-mini", "gpt-4.1", false},
		{"openai/*gpt-4*", "openai/gpt-4o-mini", true},
		{"", "gpt-4.1", false},
		{"gpt-4.1", "gpt-4.1", true},
		{"gpt-4.1", "gpt-4.1-mini", false},
	}
	for _, tc := range cases {
		if got := auth.MatchesModelPattern(tc.pattern, tc.target); got != tc.want {
			t.Errorf("MatchesModelPattern(%q, %q) = %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

type rbacCountingRepo struct {
	*storage.MemoryRepository
	magListCalls atomic.Int32
	magMemCalls  atomic.Int32
	qpListCalls  atomic.Int32
	tagListCalls atomic.Int32
	bwListCalls  atomic.Int32
	endUserCalls atomic.Int32
}

func (r *rbacCountingRepo) ListModelAccessGroups(ctx context.Context, filter storage.ModelAccessGroupFilter) ([]*domain.ModelAccessGroup, error) {
	r.magListCalls.Add(1)
	return r.MemoryRepository.ListModelAccessGroups(ctx, filter)
}

func (r *rbacCountingRepo) ListModelAccessGroupMembersByOrg(ctx context.Context, orgID string) ([]*domain.ModelAccessGroupMember, error) {
	r.magMemCalls.Add(1)
	return r.MemoryRepository.ListModelAccessGroupMembersByOrg(ctx, orgID)
}

func (r *rbacCountingRepo) ListQuotaPolicies(ctx context.Context, filter storage.QuotaPolicyFilter) ([]*domain.QuotaPolicy, error) {
	r.qpListCalls.Add(1)
	return r.MemoryRepository.ListQuotaPolicies(ctx, filter)
}

func (r *rbacCountingRepo) ListTags(ctx context.Context, filter storage.TagFilter) ([]*domain.Tag, error) {
	r.tagListCalls.Add(1)
	return r.MemoryRepository.ListTags(ctx, filter)
}

func (r *rbacCountingRepo) ListBudgetWindowLimits(ctx context.Context, filter storage.BudgetWindowFilter) ([]*domain.BudgetWindowLimit, error) {
	r.bwListCalls.Add(1)
	return r.MemoryRepository.ListBudgetWindowLimits(ctx, filter)
}

func (r *rbacCountingRepo) GetOrCreateEndUser(ctx context.Context, orgID, endUserID string) (*domain.EndUser, error) {
	r.endUserCalls.Add(1)
	return r.MemoryRepository.GetOrCreateEndUser(ctx, orgID, endUserID)
}

func TestRBACEngine_PolicyCachesAndInvalidation(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer rf.Client().Close()

	repo := &rbacCountingRepo{MemoryRepository: storage.NewMemoryRepository()}
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org-cache", Name: "Cache Org", IsActive: true})
	_ = repo.UpsertModelAccessGroup(ctx, &domain.ModelAccessGroup{
		ID:       "mag-1",
		OrgID:    "org-cache",
		Name:     "frontier",
		IsActive: true,
	})
	_ = repo.AddModelAccessGroupMember(ctx, &domain.ModelAccessGroupMember{
		ID: "m1", GroupID: "mag-1", OrgID: "org-cache", MemberType: domain.ModelAccessGroupMemberModel, MemberID: "gpt-4.1",
	})
	_ = repo.AddModelAccessGroupMember(ctx, &domain.ModelAccessGroupMember{
		ID: "m2", GroupID: "mag-1", OrgID: "org-cache", MemberType: domain.ModelAccessGroupMemberKey, MemberID: "vk-1",
	})
	_ = repo.UpsertQuotaPolicy(ctx, &domain.QuotaPolicy{
		ID:        "qp-1",
		OrgID:     "org-cache",
		ScopeType: domain.QuotaScopeKey,
		ScopeID:   "vk-1",
		RPMLimit:  100,
		IsActive:  true,
	})
	_ = repo.UpsertTag(ctx, &domain.Tag{ID: "tag-1", OrgID: "org-cache", Tag: "prod"})
	_ = repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
		ID:              "bw-1",
		OrgID:           "org-cache",
		ScopeType:       domain.QuotaScopeKey,
		ScopeID:         "vk-1",
		WindowType:      domain.BudgetWindowDaily,
		MaxBudgetMicros: 1_000_000,
	})

	rbac := auth.NewRBACEngine(repo)
	rbac.SetRedis(rf)

	idCtx := &domain.IdentityContext{
		VirtualKeyID:     "vk-1",
		KeyPrefix:        "sk-gw-1",
		OrgID:            "org-cache",
		AllowedEndpoints: []string{"/v1/*"},
	}

	// Warm caches across 5 consecutive calls -> each repo method should be called only ONCE, and magMemCalls 0!
	for i := 0; i < 5; i++ {
		if _, err := rbac.AuthorizeRequestedModelWithEval(idCtx, "gpt-4.1"); err != nil {
			t.Fatalf("AuthorizeRequestedModelWithEval[%d]: %v", i, err)
		}
		if _, err := rbac.GetCachedQuotaPolicies(ctx, "org-cache"); err != nil {
			t.Fatal(err)
		}
		if _, err := rbac.GetCachedTags(ctx, "org-cache"); err != nil {
			t.Fatal(err)
		}
		if _, err := rbac.GetCachedBudgetWindowLimits(ctx, "org-cache"); err != nil {
			t.Fatal(err)
		}
		if _, err := rbac.GetOrCreateCachedEndUser(ctx, "org-cache", "user-ext-1"); err != nil {
			t.Fatal(err)
		}
	}

	if repo.magListCalls.Load() != 1 || repo.magMemCalls.Load() != 0 {
		t.Fatalf("MAG cache miss count unexpected: list=%d mem=%d", repo.magListCalls.Load(), repo.magMemCalls.Load())
	}
	if repo.qpListCalls.Load() != 1 || repo.tagListCalls.Load() != 1 || repo.bwListCalls.Load() != 1 || repo.endUserCalls.Load() != 1 {
		t.Fatalf("expected 1 repo call each for qp/tag/bw/eu, got qp=%d tag=%d bw=%d eu=%d",
			repo.qpListCalls.Load(), repo.tagListCalls.Load(), repo.bwListCalls.Load(), repo.endUserCalls.Load())
	}

	// Explicit scope invalidation evicts L1+L2 and forces refresh on next call.
	rbac.InvalidatePolicyScope(ctx, "rbac_quotas", "org-cache")
	if _, err := rbac.GetCachedQuotaPolicies(ctx, "org-cache"); err != nil {
		t.Fatal(err)
	}
	if repo.qpListCalls.Load() != 2 {
		t.Fatalf("expected qpListCalls=2 after invalidation, got %d", repo.qpListCalls.Load())
	}
}

func TestKeyExpiryAlertManager_IdempotentAlertsAndWebhook(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

	var received []auth.KeyExpiryAlertPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p auth.KeyExpiryAlertPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err == nil {
			received = append(received, p)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	pol, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}

	_ = repo.CreateOrganization(ctx, &domain.Organization{
		ID:                  "org-exp",
		Name:                "Expiry Org",
		IsActive:            true,
		KeyExpiryAlertDays:  []int{7, 1},
		LifecycleWebhookURL: srv.URL,
	})
	exp3d := now.Add(3 * 24 * time.Hour)
	_ = repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:        "vk-exp-1",
		OrgID:     "org-exp",
		Name:      "expiring-soon",
		KeyPrefix: "sk-gw-exp",
		KeyHash:   "hash-exp-1",
		ExpiresAt: &exp3d,
		IsActive:  true,
	})

	mgr := auth.NewKeyExpiryAlertManager(repo, nil, auth.KeyExpiryAlertConfig{
		NetworkPolicy: pol,
		Now:           func() time.Time { return now },
	})

	res1, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce #1: %v", err)
	}
	if res1.AlertsRecorded != 1 || res1.WebhooksSent != 1 || len(received) != 1 || received[0].ThresholdDays != 7 {
		t.Fatalf("unexpected RunOnce #1 result: %+v received=%+v", res1, received)
	}

	// Second sweep at same timestamp must NOT duplicate threshold 7 alert.
	res2, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce #2: %v", err)
	}
	if res2.AlertsRecorded != 0 || res2.WebhooksSent != 0 || len(received) != 1 {
		t.Fatalf("expected idempotent 0 alerts on RunOnce #2, got %+v", res2)
	}
}
