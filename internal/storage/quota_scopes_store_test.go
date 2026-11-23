package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
)

func TestQuotaScopesRepositories_MemoryAndPostgresNilParity(t *testing.T) {
	ctx := context.Background()

	runSuite := func(t *testing.T, name string, mem *MemoryRepository, euRepo EndUserRepository, tagRepo TagRepository, magRepo ModelAccessGroupRepository) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			// 1. EndUserRepository: GetOrCreate scoped by (org_id, end_user_id), Upsert preserves SpentMicros.
			euA, err := euRepo.GetOrCreateEndUser(ctx, "org_1", "alice")
			if err != nil {
				t.Fatalf("GetOrCreateEndUser org_1/alice: %v", err)
			}
			euA2, err := euRepo.GetOrCreateEndUser(ctx, "org_1", "alice")
			if err != nil {
				t.Fatalf("GetOrCreateEndUser repeat: %v", err)
			}
			if euA.ID != euA2.ID {
				t.Fatalf("expected same EndUser ID on repeat lookup, got %q vs %q", euA.ID, euA2.ID)
			}
			euOtherOrg, err := euRepo.GetOrCreateEndUser(ctx, "org_2", "alice")
			if err != nil {
				t.Fatalf("GetOrCreateEndUser org_2/alice: %v", err)
			}
			if euOtherOrg.ID == euA.ID {
				t.Fatalf("expected distinct EndUser across orgs, got identical ID %q", euA.ID)
			}

			if err := euRepo.IncrementEndUserSpend(ctx, "org_1", "alice", 250_000); err != nil {
				t.Fatalf("IncrementEndUserSpend: %v", err)
			}
			err = euRepo.UpsertEndUser(ctx, &domain.EndUser{
				OrgID:           "org_1",
				EndUserID:       "alice",
				Alias:           "Alice",
				MaxBudgetMicros: 1_000_000,
				RPMLimit:        30,
				ITPMLimit:       5000,
				OTPMLimit:       2000,
				TPDLimit:        50000,
				IsActive:        true,
			})
			if err != nil {
				t.Fatalf("UpsertEndUser: %v", err)
			}
			gotEU, err := euRepo.GetEndUserByExternalID(ctx, "org_1", "alice")
			if err != nil {
				t.Fatalf("GetEndUserByExternalID: %v", err)
			}
			if gotEU.ID != euA.ID || gotEU.SpentMicros != 250_000 || gotEU.RPMLimit != 30 || gotEU.ITPMLimit != 5000 {
				t.Fatalf("unexpected EndUser after upsert: %+v", gotEU)
			}
			listedEU, err := euRepo.ListEndUsers(ctx, EndUserFilter{OrgID: "org_1"})
			if err != nil || len(listedEU) != 1 {
				t.Fatalf("ListEndUsers org_1 = %d (err=%v), want 1", len(listedEU), err)
			}

			// 2. TagRepository: CRUD + IncrementTagSpend + org isolation.
			tagObj := &domain.Tag{
				OrgID:           "org_1",
				Tag:             "prod",
				Description:     "Production traffic",
				MaxBudgetMicros: 2_000_000,
				RPMLimit:        100,
				TPMLimit:        50_000,
				ITPMLimit:       30_000,
				OTPMLimit:       20_000,
				TPDLimit:        500_000,
				IsActive:        true,
			}
			if err := tagRepo.UpsertTag(ctx, tagObj); err != nil {
				t.Fatalf("UpsertTag: %v", err)
			}
			if err := tagRepo.IncrementTagSpend(ctx, "org_1", "prod", 120_000); err != nil {
				t.Fatalf("IncrementTagSpend: %v", err)
			}
			gotTag, err := tagRepo.GetTagByName(ctx, "org_1", "prod")
			if err != nil || gotTag.SpentMicros != 120_000 || gotTag.RPMLimit != 100 {
				t.Fatalf("GetTagByName = %+v (err=%v)", gotTag, err)
			}
			if _, err := tagRepo.GetTagByName(ctx, "org_2", "prod"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected ErrNotFound for org_2 tag lookup, got %v", err)
			}

			// 3. ModelAccessGroupRepository: groups + members + spend + cascade delete.
			grp := &domain.ModelAccessGroup{
				OrgID:           "org_1",
				Name:            "frontier-pool",
				Description:     "Frontier models",
				MaxBudgetMicros: 5_000_000,
				RPMLimit:        40,
				IsActive:        true,
			}
			if err := magRepo.UpsertModelAccessGroup(ctx, grp); err != nil {
				t.Fatalf("UpsertModelAccessGroup: %v", err)
			}
			mModel := &domain.ModelAccessGroupMember{
				OrgID:      "org_1",
				GroupID:    grp.ID,
				MemberType: domain.ModelAccessGroupMemberModel,
				MemberID:   "gpt-4.1",
			}
			mKey := &domain.ModelAccessGroupMember{
				OrgID:      "org_1",
				GroupID:    grp.ID,
				MemberType: domain.ModelAccessGroupMemberKey,
				MemberID:   "vk-1",
			}
			if err := magRepo.AddModelAccessGroupMember(ctx, mModel); err != nil {
				t.Fatalf("AddModelAccessGroupMember model: %v", err)
			}
			if err := magRepo.AddModelAccessGroupMember(ctx, mKey); err != nil {
				t.Fatalf("AddModelAccessGroupMember key: %v", err)
			}
			if err := magRepo.IncrementModelAccessGroupSpend(ctx, grp.ID, 75_000); err != nil {
				t.Fatalf("IncrementModelAccessGroupSpend: %v", err)
			}
			gotGrp, err := magRepo.GetModelAccessGroup(ctx, grp.ID)
			if err != nil || gotGrp.SpentMicros != 75_000 || len(gotGrp.Members) != 2 {
				t.Fatalf("GetModelAccessGroup = %+v (err=%v)", gotGrp, err)
			}

			// 4. RecordSpendBatch attributes spend to end_users, tags, model_access_groups.
			if err := mem.RecordSpendBatch(ctx, []domain.SpendEvent{
				{
					ID:                  "sp-quota-scope-1",
					RequestID:           "req-1",
					OrgID:               "org_1",
					VirtualKeyID:        "vk-1",
					EndUserID:           "alice",
					Tags:                []string{"prod"},
					ModelAccessGroupIDs: []string{grp.ID},
					SessionID:           "sess-1",
					CostMicros:          50_000,
				},
			}); err != nil {
				t.Fatalf("RecordSpendBatch: %v", err)
			}
			gotEU, _ = euRepo.GetEndUser(ctx, euA.ID)
			if gotEU.SpentMicros != 300_000 {
				t.Fatalf("EndUser SpentMicros after RecordSpendBatch = %d, want 300000", gotEU.SpentMicros)
			}
			gotTag, _ = tagRepo.GetTag(ctx, tagObj.ID)
			if gotTag.SpentMicros != 170_000 {
				t.Fatalf("Tag SpentMicros after RecordSpendBatch = %d, want 170000", gotTag.SpentMicros)
			}
			gotGrp, _ = magRepo.GetModelAccessGroup(ctx, grp.ID)
			if gotGrp.SpentMicros != 125_000 {
				t.Fatalf("ModelAccessGroup SpentMicros after RecordSpendBatch = %d, want 125000", gotGrp.SpentMicros)
			}

			// 5. Removal & cascade delete.
			if err := magRepo.RemoveModelAccessGroupMemberByTuple(ctx, grp.ID, domain.ModelAccessGroupMemberKey, "vk-1"); err != nil {
				t.Fatalf("RemoveModelAccessGroupMemberByTuple: %v", err)
			}
			membersAfter, _ := magRepo.ListModelAccessGroupMembers(ctx, grp.ID)
			if len(membersAfter) != 1 {
				t.Fatalf("expected 1 member after remove, got %d", len(membersAfter))
			}
			if err := magRepo.DeleteModelAccessGroup(ctx, grp.ID); err != nil {
				t.Fatalf("DeleteModelAccessGroup: %v", err)
			}
			if membersAfterDel, _ := magRepo.ListModelAccessGroupMembers(ctx, grp.ID); len(membersAfterDel) != 0 {
				t.Fatalf("expected 0 members after group delete, got %d", len(membersAfterDel))
			}
			if err := tagRepo.DeleteTag(ctx, tagObj.ID); err != nil {
				t.Fatalf("DeleteTag: %v", err)
			}
			if err := euRepo.DeleteEndUser(ctx, euA.ID); err != nil {
				t.Fatalf("DeleteEndUser: %v", err)
			}
		})
	}

	memRepo := NewMemoryRepository()
	runSuite(t, "MemoryRepository", memRepo, memRepo, memRepo, memRepo)

	pgNilMem := NewMemoryRepository()
	pgNil := &PostgresRepository{mem: pgNilMem}
	runSuite(t, "PostgresRepository_NilPool", pgNilMem, pgNil, pgNil, pgNil)
}

func TestScanQuotaScopeEntities_ColumnAlignment(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	euRow := &fakeTeamScanner{
		values: []any{
			"eu-1", "org-1", "alice", "Alice", int64(5000), int64(100), "monthly", nil,
			10, 1000, 600, 400, int64(2000), 3, []string{"gpt-4.1"}, true, []byte(`{"tier":"pro"}`), now, now,
		},
	}
	eu, err := scanEndUser(euRow)
	if err != nil {
		t.Fatalf("scanEndUser: %v", err)
	}
	if eu.EndUserID != "alice" || eu.ITPMLimit != 600 || eu.Metadata["tier"] != "pro" {
		t.Fatalf("unexpected scanned EndUser: %+v", eu)
	}

	tagRow := &fakeTeamScanner{
		values: []any{
			"tag-1", "org-1", "prod", "Prod traffic", int64(9000), int64(300), "daily", nil,
			20, 2000, 1000, 1000, int64(5000), 4, []string{}, true, []byte(`{}`), now, now,
		},
	}
	tg, err := scanTag(tagRow)
	if err != nil {
		t.Fatalf("scanTag: %v", err)
	}
	if tg.Tag != "prod" || tg.RPMLimit != 20 || tg.TPDLimit != 5000 {
		t.Fatalf("unexpected scanned Tag: %+v", tg)
	}

	magRow := &fakeTeamScanner{
		values: []any{
			"mag-1", "org-1", "frontier", "Frontier group", int64(10_000), int64(500), "monthly", nil,
			30, 3000, 1500, 1500, int64(9000), 2, []string{"github"}, []string{"github:get_issue"}, []string{"agent-1"}, true, []byte(`{"owner":"ml"}`), now, now,
		},
	}
	mag, err := scanModelAccessGroup(magRow)
	if err != nil {
		t.Fatalf("scanModelAccessGroup: %v", err)
	}
	if mag.Name != "frontier" || mag.Metadata["owner"] != "ml" {
		t.Fatalf("unexpected scanned ModelAccessGroup: %+v", mag)
	}

	memRow := &fakeTeamScanner{
		values: []any{"mem-1", "org-1", "mag-1", "model", "gpt-4.1", now},
	}
	mem, err := scanModelAccessGroupMember(memRow)
	if err != nil {
		t.Fatalf("scanModelAccessGroupMember: %v", err)
	}
	if mem.MemberType != domain.ModelAccessGroupMemberModel || mem.MemberID != "gpt-4.1" {
		t.Fatalf("unexpected scanned ModelAccessGroupMember: %+v", mem)
	}
	if _, err := scanEndUser(&fakeTeamScanner{err: pgx.ErrNoRows}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows, got %v", err)
	}
}
