package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
)

func TestBudgetWindowRepository_CRUDIncrementAndReset(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		new  func() interface {
			Repository
			BudgetWindowRepository
			BudgetWindowResetRepository
		}
	}{
		{
			name: "MemoryRepository",
			new: func() interface {
				Repository
				BudgetWindowRepository
				BudgetWindowResetRepository
			} {
				return NewMemoryRepository()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := tc.new()

			// Validation rejects invalid window_type, scope_type, missing org_id, negative max.
			if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-1",
				WindowType:      domain.BudgetWindowType("hourly"),
				MaxBudgetMicros: 1000,
			}); err == nil {
				t.Fatal("expected error for invalid window_type")
			}
			if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeType("bad"),
				ScopeID:         "vk-1",
				WindowType:      domain.BudgetWindowDaily,
				MaxBudgetMicros: 1000,
			}); err == nil {
				t.Fatal("expected error for invalid scope_type")
			}
			if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-1",
				WindowType:      domain.BudgetWindowDaily,
				MaxBudgetMicros: -5,
			}); err == nil {
				t.Fatal("expected error for negative max_budget_micros")
			}

			// Seed org/team/user/key/project so RecordSpendBatch can exercise all scopes.
			if err := repo.CreateOrganization(ctx, &domain.Organization{
				ID:       "org-w1",
				Name:     "Window Org",
				Slug:     "window-org",
				IsActive: true,
			}); err != nil {
				t.Fatalf("CreateOrganization: %v", err)
			}
			if err := repo.CreateTeam(ctx, &domain.Team{
				ID:       "team-w1",
				OrgID:    "org-w1",
				Name:     "Window Team",
				IsActive: true,
			}); err != nil {
				t.Fatalf("CreateTeam: %v", err)
			}
			if err := repo.CreateUser(ctx, &domain.User{
				ID:       "user-w1",
				OrgID:    "org-w1",
				TeamID:   "team-w1",
				Email:    "w@org.example",
				Name:     "Window User",
				Role:     domain.RoleDeveloper,
				IsActive: true,
			}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if err := repo.CreateVirtualKey(ctx, &domain.VirtualKey{
				ID:        "vk-1",
				KeyPrefix: "sk-gw-w1",
				KeyHash:   "hash-w1",
				Name:      "key-w1",
				OrgID:     "org-w1",
				TeamID:    "team-w1",
				ProjectID: "proj-w1",
				UserID:    "user-w1",
				Role:      domain.RoleDeveloper,
				IsActive:  true,
			}); err != nil {
				t.Fatalf("CreateVirtualKey: %v", err)
			}

			now := time.Now().UTC()
			expiredAt := now.Add(-1 * time.Hour)
			futureAt := now.Add(48 * time.Hour)

			// Upsert simultaneous daily, weekly, monthly, and rolling_24h windows on vk-1.
			daily := &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-1",
				WindowType:      domain.BudgetWindowDaily,
				MaxBudgetMicros: 500_000,
				WindowResetAt:   expiredAt,
			}
			weekly := &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-1",
				WindowType:      domain.BudgetWindowWeekly,
				MaxBudgetMicros: 2_000_000,
				WindowResetAt:   futureAt,
			}
			monthly := &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-1",
				WindowType:      domain.BudgetWindowMonthly,
				MaxBudgetMicros: 5_000_000,
			}
			rolling := &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-1",
				WindowType:      domain.BudgetWindowRolling24h,
				MaxBudgetMicros: 750_000,
				WindowResetAt:   expiredAt,
			}
			for _, w := range []*domain.BudgetWindowLimit{daily, weekly, monthly, rolling} {
				if err := repo.UpsertBudgetWindowLimit(ctx, w); err != nil {
					t.Fatalf("UpsertBudgetWindowLimit(%s): %v", w.WindowType, err)
				}
				if w.ID == "" || w.WindowResetAt.IsZero() {
					t.Fatalf("expected ID and WindowResetAt populated for %s: %+v", w.WindowType, w)
				}
			}

			// Duplicate ID with different tuple returns ErrConflict.
			if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
				ID:              daily.ID,
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeTeam,
				ScopeID:         "team-w1",
				WindowType:      domain.BudgetWindowDaily,
				MaxBudgetMicros: 100,
			}); !errors.Is(err, ErrConflict) {
				t.Fatalf("expected ErrConflict for duplicate ID with different tuple, got %v", err)
			}

			// Add team_member and project windows to verify RecordSpendBatch updates them too.
			if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeTeamMember,
				ScopeID:         "team-w1:user-w1",
				WindowType:      domain.BudgetWindowDaily,
				MaxBudgetMicros: 1_000_000,
			}); err != nil {
				t.Fatalf("UpsertBudgetWindowLimit team_member: %v", err)
			}
			if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeProject,
				ScopeID:         "proj-w1",
				WindowType:      domain.BudgetWindowDaily,
				MaxBudgetMicros: 1_500_000,
			}); err != nil {
				t.Fatalf("UpsertBudgetWindowLimit project: %v", err)
			}

			// IncrementBudgetWindowSpend updates all windows for (org-w1, key, vk-1) simultaneously.
			if err := repo.IncrementBudgetWindowSpend(ctx, "org-w1", domain.QuotaScopeKey, "vk-1", 120_000); err != nil {
				t.Fatalf("IncrementBudgetWindowSpend: %v", err)
			}
			if err := repo.IncrementBudgetWindowSpend(ctx, "org-w1", domain.QuotaScopeKey, "vk-1", -1); err == nil {
				t.Fatal("expected error for negative IncrementBudgetWindowSpend")
			}

			// RecordSpendBatch also increments matching budget windows.
			if err := repo.RecordSpendBatch(ctx, []domain.SpendEvent{
				{
					ID:            "sp-bw-1",
					RequestID:     "req-bw-1",
					OrgID:         "org-w1",
					TeamID:        "team-w1",
					UserID:        "user-w1",
					VirtualKeyID:  "vk-1",
					Endpoint:      "/v1/chat/completions",
					ResolvedModel: "gpt-4.1",
					Provider:      domain.ProviderOpenAI,
					CostMicros:    30_000,
					CreatedAt:     now,
				},
			}); err != nil {
				t.Fatalf("RecordSpendBatch: %v", err)
			}

			keyWindows, err := repo.ListBudgetWindowLimits(ctx, BudgetWindowFilter{
				OrgID:     "org-w1",
				ScopeType: domain.QuotaScopeKey,
				ScopeID:   "vk-1",
			})
			if err != nil || len(keyWindows) != 4 {
				t.Fatalf("ListBudgetWindowLimits key len=%d err=%v, want 4", len(keyWindows), err)
			}
			for _, w := range keyWindows {
				if w.SpentMicros != 150_000 {
					t.Fatalf("window %s SpentMicros=%d, want 150000", w.WindowType, w.SpentMicros)
				}
				desc := w.ToDescriptor()
				if desc.WindowType != w.WindowType || desc.SpentFloorMicros != 150_000 || desc.MaxBudgetMicros != w.MaxBudgetMicros {
					t.Fatalf("unexpected compiled descriptor for %s: %+v", w.WindowType, desc)
				}
			}

			// Verify team_member and project windows received 30,000 from RecordSpendBatch.
			tmWindows, err := repo.ListBudgetWindowLimits(ctx, BudgetWindowFilter{
				OrgID:     "org-w1",
				ScopeType: domain.QuotaScopeTeamMember,
				ScopeID:   "team-w1:user-w1",
			})
			if err != nil || len(tmWindows) != 1 || tmWindows[0].SpentMicros != 30_000 {
				t.Fatalf("team_member window = %+v (err=%v), want spent=30000", tmWindows, err)
			}
			projWindows, err := repo.ListBudgetWindowLimits(ctx, BudgetWindowFilter{
				OrgID:     "org-w1",
				ScopeType: domain.QuotaScopeProject,
				ScopeID:   "proj-w1",
			})
			if err != nil || len(projWindows) != 1 || projWindows[0].SpentMicros != 30_000 {
				t.Fatalf("project window = %+v (err=%v), want spent=30000", projWindows, err)
			}

			// Upserting existing tuple updates max_budget_micros while preserving ID and spent_micros.
			origDailyID := daily.ID
			if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
				OrgID:           "org-w1",
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-1",
				WindowType:      domain.BudgetWindowDaily,
				MaxBudgetMicros: 600_000,
			}); err != nil {
				t.Fatalf("UpsertBudgetWindowLimit update: %v", err)
			}
			dailyAfter, err := repo.ListBudgetWindowLimits(ctx, BudgetWindowFilter{
				OrgID:      "org-w1",
				ScopeType:  domain.QuotaScopeKey,
				ScopeID:    "vk-1",
				WindowType: domain.BudgetWindowDaily,
			})
			if err != nil || len(dailyAfter) != 1 || dailyAfter[0].ID != origDailyID || dailyAfter[0].SpentMicros != 150_000 || dailyAfter[0].MaxBudgetMicros != 600_000 {
				t.Fatalf("unexpected daily window after upsert update: %+v (err=%v)", dailyAfter, err)
			}

			// ResetExpiredBudgetWindowsWithResults resets only periodic expired windows (daily), leaving rolling_24h intact.
			resetList, err := repo.ResetExpiredBudgetWindowsWithResults(ctx, now)
			if err != nil {
				t.Fatalf("ResetExpiredBudgetWindowsWithResults: %v", err)
			}
			if len(resetList) != 1 || resetList[0].WindowType != domain.BudgetWindowDaily {
				t.Fatalf("expected 1 periodic expired window reset (daily), got %d: %+v", len(resetList), resetList)
			}
			for _, rw := range resetList {
				if rw.SpentMicros != 0 {
					t.Fatalf("expected reset window %s spent=0, got %d", rw.WindowType, rw.SpentMicros)
				}
				if !rw.WindowResetAt.After(now) {
					t.Fatalf("expected reset window %s WindowResetAt > now, got %v", rw.WindowType, rw.WindowResetAt)
				}
			}
			rollingAfterReset, err := repo.ListBudgetWindowLimits(ctx, BudgetWindowFilter{
				OrgID:      "org-w1",
				ScopeType:  domain.QuotaScopeKey,
				ScopeID:    "vk-1",
				WindowType: domain.BudgetWindowRolling24h,
			})
			if err != nil || len(rollingAfterReset) != 1 || rollingAfterReset[0].SpentMicros != 150_000 {
				t.Fatalf("expected rolling_24h window to survive periodic reset with spent=150000, got %+v (err=%v)", rollingAfterReset, err)
			}

			// Weekly and monthly windows were not expired and must still retain SpentMicros=150_000.
			weeklyAfter, _ := repo.ListBudgetWindowLimits(ctx, BudgetWindowFilter{
				OrgID:      "org-w1",
				ScopeType:  domain.QuotaScopeKey,
				ScopeID:    "vk-1",
				WindowType: domain.BudgetWindowWeekly,
			})
			if len(weeklyAfter) != 1 || weeklyAfter[0].SpentMicros != 150_000 {
				t.Fatalf("expected non-expired weekly window to keep spent=150000, got %+v", weeklyAfter)
			}
		})
	}
}

func TestBudgetWindowRepository_PostgresNilPoolFallback(t *testing.T) {
	ctx := context.Background()
	repo := &PostgresRepository{mem: NewMemoryRepository()}
	now := time.Now().UTC()

	if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
		OrgID:           "org-pg",
		ScopeType:       domain.QuotaScopeKey,
		ScopeID:         "vk-pg",
		WindowType:      domain.BudgetWindowDaily,
		MaxBudgetMicros: 500_000,
		WindowResetAt:   now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("UpsertBudgetWindowLimit: %v", err)
	}
	if err := repo.IncrementBudgetWindowSpend(ctx, "org-pg", domain.QuotaScopeKey, "vk-pg", 42_000); err != nil {
		t.Fatalf("IncrementBudgetWindowSpend: %v", err)
	}
	listed, err := repo.ListBudgetWindowLimits(ctx, BudgetWindowFilter{
		OrgID:     "org-pg",
		ScopeType: domain.QuotaScopeKey,
		ScopeID:   "vk-pg",
	})
	if err != nil || len(listed) != 1 || listed[0].SpentMicros != 42_000 {
		t.Fatalf("ListBudgetWindowLimits = %+v (err=%v), want spent=42000", listed, err)
	}
	resets, err := repo.ResetExpiredBudgetWindowsWithResults(ctx, now)
	if err != nil || len(resets) != 1 || resets[0].SpentMicros != 0 {
		t.Fatalf("ResetExpiredBudgetWindowsWithResults = %+v (err=%v)", resets, err)
	}
}

func TestTempBudgetRepository_PersistenceAndScanners(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository()
	now := time.Now().UTC().Truncate(time.Second)
	future := now.Add(30 * time.Minute)
	past := now.Add(-5 * time.Minute)

	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:                    "org-tb",
		Name:                  "Temp Org",
		Slug:                  "temp-org",
		MaxBudgetMicros:       1_000_000,
		SelfServeBudgetPolicy: domain.SelfServeBudgetCeiling,
		IsActive:              true,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.CreateTeam(ctx, &domain.Team{
		ID:              "team-tb",
		OrgID:           "org-tb",
		Name:            "Temp Team",
		MaxBudgetMicros: 500_000,
		IsActive:        true,
	}); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:              "user-tb",
		OrgID:           "org-tb",
		TeamID:          "team-tb",
		Email:           "tb@org.example",
		Name:            "Temp User",
		Role:            domain.RoleDeveloper,
		MaxBudgetMicros: 250_000,
		IsActive:        true,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:              "vk-tb",
		KeyPrefix:       "sk-gw-tb",
		KeyHash:         "hash-tb",
		Name:            "Temp Key",
		OrgID:           "org-tb",
		TeamID:          "team-tb",
		UserID:          "user-tb",
		MaxBudgetMicros: 100_000,
		IsActive:        true,
	}); err != nil {
		t.Fatalf("CreateVirtualKey: %v", err)
	}

	// SetTempBudgetBoost works across key, team, user, org.
	if err := repo.SetTempBudgetBoost(ctx, domain.QuotaScopeKey, "vk-tb", 50_000, &future); err != nil {
		t.Fatalf("SetTempBudgetBoost key: %v", err)
	}
	if err := repo.SetTempBudgetBoost(ctx, domain.QuotaScopeTeam, "team-tb", 100_000, &future); err != nil {
		t.Fatalf("SetTempBudgetBoost team: %v", err)
	}
	if err := repo.SetTempBudgetBoost(ctx, domain.QuotaScopeUser, "user-tb", 25_000, &past); err != nil {
		t.Fatalf("SetTempBudgetBoost user: %v", err)
	}
	if err := repo.SetTempBudgetBoost(ctx, domain.QuotaScopeOrg, "org-tb", 200_000, &future); err != nil {
		t.Fatalf("SetTempBudgetBoost org: %v", err)
	}

	vk, err := repo.GetVirtualKeyByID(ctx, "vk-tb")
	if err != nil || vk.TempBudgetIncreaseMicros != 50_000 || vk.TempBudgetExpiresAt == nil || !vk.TempBudgetExpiresAt.Equal(future) {
		t.Fatalf("unexpected vk temp budget: %+v err=%v", vk, err)
	}
	if got := domain.EffectiveMaxBudgetMicros(vk.MaxBudgetMicros, vk.TempBudgetIncreaseMicros, vk.TempBudgetExpiresAt, now); got != 150_000 {
		t.Fatalf("EffectiveMaxBudgetMicros active = %d, want 150000", got)
	}
	if got := domain.EffectiveMaxBudgetMicros(vk.MaxBudgetMicros, vk.TempBudgetIncreaseMicros, vk.TempBudgetExpiresAt, future); got != 100_000 {
		t.Fatalf("EffectiveMaxBudgetMicros at exact expiry = %d, want 100000", got)
	}
	if got := domain.EffectiveMaxBudgetMicros(0, 50_000, &future, now); got != 0 {
		t.Fatalf("EffectiveMaxBudgetMicros unlimited base = %d, want 0", got)
	}

	usr, err := repo.GetUser(ctx, "user-tb")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got := domain.EffectiveMaxBudgetMicros(usr.MaxBudgetMicros, usr.TempBudgetIncreaseMicros, usr.TempBudgetExpiresAt, now); got != 250_000 {
		t.Fatalf("expired user boost should return base 250000, got %d", got)
	}

	org, err := repo.GetOrganization(ctx, "org-tb")
	if err != nil || org.SelfServeBudgetPolicy != domain.SelfServeBudgetCeiling || org.TempBudgetIncreaseMicros != 200_000 {
		t.Fatalf("unexpected org: %+v err=%v", org, err)
	}

	// Error cases.
	if err := repo.SetTempBudgetBoost(ctx, domain.QuotaScopeKey, "missing", 10, &future); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := repo.SetTempBudgetBoost(ctx, domain.QuotaScopeKey, "vk-tb", -1, &future); err == nil {
		t.Fatal("expected error for negative increase")
	}
	if err := repo.SetTempBudgetBoost(ctx, domain.QuotaScopeProject, "proj-1", 10, &future); err == nil {
		t.Fatal("expected error for unsupported scope")
	}

	// Verify scanOrganization and scanUser column counts/mappings match select cols.
	orgRow := &fakeTeamScanner{
		values: []any{
			"org-scan", "Scan Org", "scan-org", int64(5000), int64(1000), &future, "lower_only",
			int64(0), false, []byte("{}"), int64(250), "monthly", nil, 10, 100, 5, int64(0), 0, int64(0),
			true, false, []int32{7, 1}, "https://hooks.example.com/keys", true,
		},
	}
	scannedOrg, err := scanOrganization(orgRow)
	if err != nil {
		t.Fatalf("scanOrganization: %v", err)
	}
	if scannedOrg.SelfServeBudgetPolicy != domain.SelfServeBudgetLowerOnly || scannedOrg.TempBudgetIncreaseMicros != 1000 {
		t.Fatalf("unexpected scannedOrg: %+v", scannedOrg)
	}

	userRow := &fakeTeamScanner{
		values: []any{
			"usr-scan", "org-scan", "team-scan", "u@scan.example", "Scan User", "developer", "", "sub-1", "scim-1", true,
			int64(2000), int64(500), &future, int64(0), false, []byte("{}"), int64(100), "daily", nil,
			20, 200, 3, int64(0), true, now, now,
		},
	}
	scannedUser, err := scanUser(userRow)
	if err != nil {
		t.Fatalf("scanUser: %v", err)
	}
	if scannedUser.SCIMExternalID != "scim-1" || !scannedUser.SCIMActive || scannedUser.TempBudgetIncreaseMicros != 500 || scannedUser.TempBudgetExpiresAt == nil || !scannedUser.TempBudgetExpiresAt.Equal(future) {
		t.Fatalf("unexpected scannedUser: %+v", scannedUser)
	}

	bwRow := &fakeTeamScanner{
		values: []any{
			"bw-1", "org-scan", "key", "vk-1", "rolling_24h", int64(1000), int64(200), future, int64(50), &future, now, now,
		},
	}
	scannedBW, err := scanBudgetWindowLimit(bwRow)
	if err != nil {
		t.Fatalf("scanBudgetWindowLimit: %v", err)
	}
	if scannedBW.WindowType != domain.BudgetWindowRolling24h || scannedBW.MaxBudgetMicros != 1000 || scannedBW.SpentMicros != 200 || scannedBW.RollingHoldMicros != 50 {
		t.Fatalf("unexpected scannedBW: %+v", scannedBW)
	}
	if _, err := scanBudgetWindowLimit(&fakeTeamScanner{err: pgx.ErrNoRows}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows, got %v", err)
	}
}

func TestRecordSpendBatch_ProjectMemberPinnedPolicyAndRolling24h(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository()
	now := time.Now().UTC()

	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-attr", Name: "Org Attr", Slug: "org-attr", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.CreateTeam(ctx, &domain.Team{ID: "team-attr", OrgID: "org-attr", Name: "Team Attr", IsActive: true}); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{ID: "usr-attr", OrgID: "org-attr", TeamID: "team-attr", Email: "attr@example.com", Name: "Attr User", Role: domain.RoleDeveloper, IsActive: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := repo.UpsertTeamMembership(ctx, &domain.TeamMembership{ID: "tm-attr", OrgID: "org-attr", TeamID: "team-attr", UserID: "usr-attr", Role: domain.RoleDeveloper}); err != nil {
		t.Fatalf("UpsertTeamMembership: %v", err)
	}
	if err := repo.CreateProject(ctx, &domain.Project{ID: "proj-attr", OrgID: "org-attr", TeamID: "team-attr", Name: "Proj Attr", IsActive: true}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if err := repo.CreateVirtualKey(ctx, &domain.VirtualKey{ID: "vk-attr", KeyPrefix: "sk-gw-attr", KeyHash: "hash-attr", Name: "VK Attr", OrgID: "org-attr", TeamID: "team-attr", ProjectID: "proj-attr", UserID: "usr-attr", Role: domain.RoleDeveloper, IsActive: true}); err != nil {
		t.Fatalf("CreateVirtualKey: %v", err)
	}
	if err := repo.UpsertQuotaPolicy(ctx, &domain.QuotaPolicy{ID: "qp-pinned", OrgID: "org-attr", ScopeType: domain.QuotaScopeModelPerProject, ScopeID: "proj-attr", ModelPattern: "gpt-4.1", MaxBudgetMicros: 100_000, IsActive: true}); err != nil {
		t.Fatalf("UpsertQuotaPolicy pinned: %v", err)
	}
	if err := repo.UpsertQuotaPolicy(ctx, &domain.QuotaPolicy{ID: "qp-later", OrgID: "org-attr", ScopeType: domain.QuotaScopeModelPerTeam, ScopeID: "team-attr", ModelPattern: "*", MaxBudgetMicros: 200_000, IsActive: true}); err != nil {
		t.Fatalf("UpsertQuotaPolicy later: %v", err)
	}
	if err := repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{OrgID: "org-attr", ScopeType: domain.QuotaScopeProject, ScopeID: "proj-attr", WindowType: domain.BudgetWindowRolling24h, MaxBudgetMicros: 50_000}); err != nil {
		t.Fatalf("UpsertBudgetWindowLimit rolling: %v", err)
	}

	events := []domain.SpendEvent{
		{
			ID:                    "sp-old",
			RequestID:             "req-old",
			OrgID:                 "org-attr",
			TeamID:                "team-attr",
			UserID:                "usr-attr",
			VirtualKeyID:          "vk-attr",
			ProjectID:             "proj-attr",
			MatchedQuotaPolicyIDs: []string{"qp-pinned", "qp-pinned"},
			ResolvedModel:         "gpt-4.1",
			Provider:              domain.ProviderOpenAI,
			CostMicros:            12_000,
			CreatedAt:             now.Add(-25 * time.Hour),
		},
		{
			ID:                    "sp-recent",
			RequestID:             "req-recent",
			OrgID:                 "org-attr",
			TeamID:                "team-attr",
			UserID:                "usr-attr",
			VirtualKeyID:          "vk-attr",
			ProjectID:             "proj-attr",
			MatchedQuotaPolicyIDs: []string{"qp-pinned"},
			ResolvedModel:         "gpt-4.1",
			Provider:              domain.ProviderOpenAI,
			CostMicros:            18_000,
			CreatedAt:             now.Add(-2 * time.Hour),
		},
	}
	if err := repo.RecordSpendBatch(ctx, events); err != nil {
		t.Fatalf("RecordSpendBatch initial: %v", err)
	}
	// Outbox replay with identical IDs must be strictly idempotent.
	if err := repo.RecordSpendBatch(ctx, events); err != nil {
		t.Fatalf("RecordSpendBatch replay: %v", err)
	}

	proj, err := repo.GetProject(ctx, "proj-attr")
	if err != nil || proj.SpentMicros != 30_000 {
		t.Fatalf("Project SpentMicros = %d (err=%v), want 30000", proj.SpentMicros, err)
	}
	tm, err := repo.GetTeamMembership(ctx, "team-attr", "usr-attr")
	if err != nil || tm.SpentMicros != 30_000 {
		t.Fatalf("TeamMembership SpentMicros = %d (err=%v), want 30000", tm.SpentMicros, err)
	}
	qpPinned, err := repo.GetQuotaPolicy(ctx, "qp-pinned")
	if err != nil || qpPinned.SpentMicros != 30_000 {
		t.Fatalf("Pinned QuotaPolicy SpentMicros = %d (err=%v), want 30000", qpPinned.SpentMicros, err)
	}
	qpLater, err := repo.GetQuotaPolicy(ctx, "qp-later")
	if err != nil || qpLater.SpentMicros != 0 {
		t.Fatalf("Unpinned QuotaPolicy SpentMicros = %d (err=%v), want 0", qpLater.SpentMicros, err)
	}

	bws, err := repo.ListBudgetWindowLimits(ctx, BudgetWindowFilter{OrgID: "org-attr", ScopeType: domain.QuotaScopeProject, ScopeID: "proj-attr", WindowType: domain.BudgetWindowRolling24h})
	if err != nil || len(bws) != 1 || bws[0].SpentMicros != 18_000 {
		t.Fatalf("Rolling 24h window SpentMicros = %+v (err=%v), want 18000 (excluding >24h spend)", bws, err)
	}

	// Verify ListRollingWindowHistory returns exact millisecond entries and active migration hold only before expiry.
	hist, err := repo.ListRollingWindowHistory(ctx, "org-attr", domain.QuotaScopeProject, "proj-attr", now)
	if err != nil || len(hist) != 1 || hist[0].ID != "db:sp-recent" || hist[0].AmountMicros != 18_000 {
		t.Fatalf("ListRollingWindowHistory = %+v (err=%v), want single sp-recent entry", hist, err)
	}
	if err := repo.IncrementBudgetWindowSpend(ctx, "org-attr", domain.QuotaScopeProject, "proj-attr", 5_000); err != nil {
		t.Fatalf("IncrementBudgetWindowSpend hold: %v", err)
	}
	histWithHold, err := repo.ListRollingWindowHistory(ctx, "org-attr", domain.QuotaScopeProject, "proj-attr", now)
	if err != nil || len(histWithHold) != 2 || histWithHold[1].AmountMicros != 5_000 {
		t.Fatalf("ListRollingWindowHistory with hold = %+v (err=%v)", histWithHold, err)
	}
	histAfterHoldExp, err := repo.ListRollingWindowHistory(ctx, "org-attr", domain.QuotaScopeProject, "proj-attr", now.Add(25*time.Hour))
	if err != nil || len(histAfterHoldExp) != 0 {
		t.Fatalf("expected all history and hold expired after +25h, got %+v (err=%v)", histAfterHoldExp, err)
	}
}
