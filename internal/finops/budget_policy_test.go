package finops_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestSoftBudgetNotifier_AuditLogWebhookAndRedisCooldown(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	var mu sync.Mutex
	var received []finops.SoftBudgetAlert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var alert finops.SoftBudgetAlert
		if err := json.NewDecoder(r.Body).Decode(&alert); err == nil {
			mu.Lock()
			received = append(received, alert)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
		AllowedSchemes:       []string{"http", "https"},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	repo := storage.NewMemoryRepository()
	notifier := finops.NewSoftBudgetNotifier(repo, redisFabric, netPolicy, srv.URL, 120)

	// Below threshold -> no alert.
	if notifier.NotifyIfExceeded(ctx, finops.SoftBudgetAlert{
		Scope:            "key",
		EntityID:         "vk-1",
		OrgID:            "org-1",
		SoftBudgetMicros: 1000,
		MaxBudgetMicros:  2000,
		SpentMicros:      999,
		ResetPeriod:      "daily",
	}) {
		t.Fatal("expected alert below soft budget threshold not to trigger")
	}

	// Crosses threshold -> emits AuditLog + async webhook + Redis cooldown key.
	if !notifier.NotifyIfExceeded(ctx, finops.SoftBudgetAlert{
		Scope:            "key",
		EntityID:         "vk-1",
		OrgID:            "org-1",
		SoftBudgetMicros: 1000,
		MaxBudgetMicros:  2000,
		SpentMicros:      1250,
		ResetPeriod:      "daily",
	}) {
		t.Fatal("expected first soft budget crossing to trigger")
	}

	// Duplicate within cooldown for same (scope, entity, reset_period) -> suppressed.
	if notifier.NotifyIfExceeded(ctx, finops.SoftBudgetAlert{
		Scope:            "key",
		EntityID:         "vk-1",
		OrgID:            "org-1",
		SoftBudgetMicros: 1000,
		MaxBudgetMicros:  2000,
		SpentMicros:      1500,
		ResetPeriod:      "daily",
	}) {
		t.Fatal("expected duplicate alert within cooldown to be deduplicated")
	}

	// Different reset_period -> triggers independently.
	if !notifier.NotifyIfExceeded(ctx, finops.SoftBudgetAlert{
		Scope:            "key",
		EntityID:         "vk-1",
		OrgID:            "org-1",
		SoftBudgetMicros: 1000,
		MaxBudgetMicros:  2000,
		SpentMicros:      1500,
		ResetPeriod:      "monthly",
	}) {
		t.Fatal("expected alert for distinct reset_period to trigger")
	}

	if err := notifier.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	dedupKey := finops.SoftBudgetAlertKey("org-1", "key", "vk-1", "daily")
	if !mr.Exists(dedupKey) {
		t.Fatalf("expected Redis cooldown key %q to exist", dedupKey)
	}
	if ttl := mr.TTL(dedupKey); ttl <= 0 || ttl > 120*time.Second {
		t.Fatalf("unexpected TTL on cooldown key %q: %v", dedupKey, ttl)
	}

	logs, err := repo.ListAuditLogs(ctx, "org-1", 10)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 audit logs, got %d", len(logs))
	}
	if logs[0].Action != "budget.soft_limit_reached" || logs[0].Resource != "virtual_key" {
		t.Fatalf("unexpected audit log entry: %+v", logs[0])
	}

	mu.Lock()
	gotCount := len(received)
	mu.Unlock()
	if gotCount != 2 {
		t.Fatalf("expected 2 webhook deliveries, got %d", gotCount)
	}

	// ClearCooldown allows re-notification (e.g. after budget period reset).
	notifier.ClearCooldown(ctx, "org-1", "key", "vk-1", "daily")
	if !notifier.NotifyIfExceeded(ctx, finops.SoftBudgetAlert{
		Scope:            "key",
		EntityID:         "vk-1",
		OrgID:            "org-1",
		SoftBudgetMicros: 1000,
		MaxBudgetMicros:  2000,
		SpentMicros:      1100,
		ResetPeriod:      "daily",
	}) {
		t.Fatal("expected alert after ClearCooldown to trigger")
	}
	_ = notifier.Wait(ctx)
	mu.Lock()
	gotCount = len(received)
	mu.Unlock()
	if gotCount != 3 {
		t.Fatalf("expected 3 webhook deliveries after ClearCooldown, got %d", gotCount)
	}
}

func TestSoftBudgetNotifier_SSRFPolicyBlocksPrivateWebhook(t *testing.T) {
	ctx := context.Background()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Strict default policy forbids loopback/private IPs and insecure HTTP.
	strictPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	repo := storage.NewMemoryRepository()
	notifier := finops.NewSoftBudgetNotifier(repo, nil, strictPolicy, srv.URL, 60)

	if !notifier.NotifyIfExceeded(ctx, finops.SoftBudgetAlert{
		Scope:            "org",
		EntityID:         "org-ssrf",
		OrgID:            "org-ssrf",
		SoftBudgetMicros: 500,
		SpentMicros:      600,
		ResetPeriod:      "monthly",
	}) {
		t.Fatal("expected soft budget alert to trigger audit log")
	}
	_ = notifier.Wait(ctx)

	if hits != 0 {
		t.Fatalf("expected SSRF policy to block loopback webhook delivery, got %d hits", hits)
	}
	logs, err := repo.ListAuditLogs(ctx, "org-ssrf", 10)
	if err != nil || len(logs) != 1 {
		t.Fatalf("expected audit log to still be recorded, got logs=%+v err=%v", logs, err)
	}
}

func TestSoftBudgetNotifier_SpendWorkerPostSettlementTrigger(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	var mu sync.Mutex
	alertsByScope := make(map[string]finops.SoftBudgetAlert)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var alert finops.SoftBudgetAlert
		if err := json.NewDecoder(r.Body).Decode(&alert); err == nil {
			mu.Lock()
			alertsByScope[alert.Scope] = alert
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
		AllowedSchemes:       []string{"http", "https"},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	repo := storage.NewMemoryRepository()
	org := &domain.Organization{ID: "org-sw-sb", Name: "Org", Slug: "org-sw-sb", SoftBudgetMicros: 500, MaxBudgetMicros: 2000, IsActive: true}
	team := &domain.Team{ID: "team-sw-sb", OrgID: org.ID, Name: "Team", SoftBudgetMicros: 400, MaxBudgetMicros: 1500, IsActive: true}
	user := &domain.User{ID: "user-sw-sb", OrgID: org.ID, TeamID: team.ID, Email: "u@sw.test", SoftBudgetMicros: 1000, MaxBudgetMicros: 2000, IsActive: true}
	vk := &domain.VirtualKey{ID: "vk-sw-sb", OrgID: org.ID, TeamID: team.ID, UserID: user.ID, KeyHash: "hash-sw-sb", SoftBudgetMicros: 300, MaxBudgetMicros: 1000, IsActive: true}
	_ = repo.CreateOrganization(ctx, org)
	_ = repo.CreateTeam(ctx, team)
	_ = repo.CreateUser(ctx, user)
	_ = repo.CreateVirtualKey(ctx, vk)

	notifier := finops.NewSoftBudgetNotifier(repo, redisFabric, netPolicy, srv.URL, 60)
	sw := finops.NewSpendWorker(repo, nil, config.FinOpsConfig{BatchSize: 10})
	sw.SetSoftBudgetNotifier(notifier)

	if err := sw.Record(ctx, domain.SpendEvent{
		ID:           "ev-sb-1",
		RequestID:    "req-sb-1",
		OrgID:        org.ID,
		TeamID:       team.ID,
		UserID:       user.ID,
		VirtualKeyID: vk.ID,
		CostMicros:   600,
		StatusCode:   200,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := sw.FlushNow(ctx); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}
	_ = notifier.Wait(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(alertsByScope) != 3 {
		t.Fatalf("expected 3 alerts (org, team, key), got %d: %+v", len(alertsByScope), alertsByScope)
	}
	if _, ok := alertsByScope["user"]; ok {
		t.Fatal("user soft budget (1000) was not exceeded by 600 spend")
	}
}

func TestApplyBudgetThrottle_ScalesRPMAndTPMAcrossScopes(t *testing.T) {
	if got, throttled := finops.ApplyBudgetThrottle(nil, 0.1); got != nil || throttled {
		t.Fatalf("expected (nil, false) for nil idCtx")
	}

	base := &domain.IdentityContext{
		VirtualKeyID:                 "vk-1",
		OrgID:                        "org-1",
		KeyRPMLimit:                  100,
		KeyTPMLimit:                  10_000,
		KeyMaxBudgetMicros:           1000,
		KeySpentMicros:               1000,
		KeyThrottleOnBudgetExceeded:  true,
		TeamRPMLimit:                 5,
		TeamTPMLimit:                 0, // unlimited stays unlimited
		TeamMaxBudgetMicros:          500,
		TeamSpentMicros:              600,
		TeamThrottleOnBudgetExceeded: true,
		UserRPMLimit:                 50,
		UserMaxBudgetMicros:          500,
		UserSpentMicros:              500,
		UserThrottleOnBudgetExceeded: false, // hard-block remains
		OrgRPMLimit:                  200,
		OrgTPMLimit:                  20_000,
		OrgMaxBudgetMicros:           5000,
		OrgSpentMicros:               4000, // below budget
		OrgThrottleOnBudgetExceeded:  true,
	}

	eff, throttled := finops.ApplyBudgetThrottle(base, 0.1)
	if !throttled {
		t.Fatal("expected throttled=true")
	}
	if eff == base {
		t.Fatal("expected ApplyBudgetThrottle to clone IdentityContext")
	}
	// Original must remain unmutated.
	if base.KeyMaxBudgetMicros != 1000 || base.KeyRPMLimit != 100 {
		t.Fatalf("original IdentityContext was mutated: %+v", base)
	}
	// Key scope throttled by 0.1 and budget cleared for limiter.
	if eff.KeyMaxBudgetMicros != 0 || eff.KeyRPMLimit != 10 || eff.KeyTPMLimit != 1000 {
		t.Fatalf("unexpected throttled key limits: maxB=%d rpm=%d tpm=%d", eff.KeyMaxBudgetMicros, eff.KeyRPMLimit, eff.KeyTPMLimit)
	}
	// Team RPM=5 * 0.1 = 0 -> floored to 1; Team TPM=0 remains 0.
	if eff.TeamMaxBudgetMicros != 0 || eff.TeamRPMLimit != 1 || eff.TeamTPMLimit != 0 {
		t.Fatalf("unexpected throttled team limits: maxB=%d rpm=%d tpm=%d", eff.TeamMaxBudgetMicros, eff.TeamRPMLimit, eff.TeamTPMLimit)
	}
	// User has ThrottleOnBudgetExceeded=false -> remains hard-blocked.
	if eff.UserMaxBudgetMicros != 500 || eff.UserRPMLimit != 50 {
		t.Fatalf("expected user scope not to throttle: maxB=%d rpm=%d", eff.UserMaxBudgetMicros, eff.UserRPMLimit)
	}
	// Org is below budget -> remains intact.
	if eff.OrgMaxBudgetMicros != 5000 || eff.OrgRPMLimit != 200 || eff.OrgTPMLimit != 20_000 {
		t.Fatalf("expected org scope below budget not to throttle: %+v", eff)
	}
}

func TestResolveBudgetFallbackModel_PrecedenceAndFirstWithinBudget(t *testing.T) {
	ctx := context.Background()
	idCtx := &domain.IdentityContext{
		KeyBudgetFallbacks: map[string][]string{
			"gpt-4.1": {"gpt-4.1", "key-over", "key-ok"},
		},
		TeamBudgetFallbacks: map[string][]string{
			"gpt-4.1": {"key-over", "team-ok"},
		},
		UserBudgetFallbacks: map[string][]string{
			"gpt-4.1": {"user-ok"},
		},
		OrgBudgetFallbacks: map[string][]string{
			"gpt-4.1": {"org-ok"},
		},
	}

	var checked []string
	model, ok := finops.ResolveBudgetFallbackModel(ctx, idCtx, "gpt-4.1", func(_ context.Context, candidate string) error {
		checked = append(checked, candidate)
		if candidate == "key-ok" || candidate == "team-ok" {
			return nil
		}
		return errors.New("budget exceeded")
	})
	if !ok || model != "key-ok" {
		t.Fatalf("got (%q, %v), want (%q, true)", model, ok, "key-ok")
	}
	if len(checked) != 2 || checked[0] != "key-over" || checked[1] != "key-ok" {
		t.Fatalf("expected self-skip and Key precedence order, checked=%v", checked)
	}

	// Fall through Key -> Team -> User -> Org when higher scopes are over budget.
	checked = nil
	model, ok = finops.ResolveBudgetFallbackModel(ctx, idCtx, "gpt-4.1", func(_ context.Context, candidate string) error {
		checked = append(checked, candidate)
		if candidate == "user-ok" {
			return nil
		}
		return errors.New("over budget")
	})
	if !ok || model != "user-ok" {
		t.Fatalf("got (%q, %v), want (%q, true)", model, ok, "user-ok")
	}
	// key-over should be checked only once (deduplicated across Key and Team).
	wantChecked := []string{"key-over", "key-ok", "team-ok", "user-ok"}
	if len(checked) != len(wantChecked) {
		t.Fatalf("checked = %v, want %v", checked, wantChecked)
	}
	for i := range wantChecked {
		if checked[i] != wantChecked[i] {
			t.Fatalf("checked[%d] = %q, want %q (all=%v)", i, checked[i], wantChecked[i], checked)
		}
	}

	// No match returns ("", false).
	if m, ok := finops.ResolveBudgetFallbackModel(ctx, idCtx, "unknown-model", func(context.Context, string) error { return nil }); ok || m != "" {
		t.Fatalf("expected (\"\", false) for unmapped model, got (%q, %v)", m, ok)
	}
}
