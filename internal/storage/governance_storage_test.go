package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestGovernanceStorage_MemoryAndPostgresFallback(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		repo interface {
			Repository
			VirtualKeyBundleLookup
			OrganizationUpdateRepository
			KeyGovernanceRepository
			KeyRotationRepository
			DeprecatedKeyRevocationRepository
			ProjectAndMembershipRepository
			TeamMembershipBulkSyncRepository
			KEKRotationRepository
		}
	}{
		{name: "MemoryRepository", repo: NewMemoryRepository()},
		{name: "PostgresPoolNilFallback", repo: &PostgresRepository{mem: NewMemoryRepository()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.repo
			now := time.Now().UTC()

			org := &domain.Organization{
				ID:                          "org-gov",
				Name:                        "Gov Org",
				Slug:                        "gov-org",
				EnforceGuaranteedThroughput: true,
				DeveloperSelfServeKeys:      true,
				KeyExpiryAlertDays:          []int{7, 3, 1},
				LifecycleWebhookURL:         "https://hooks.example.com/lifecycle",
				IsActive:                    true,
			}
			if err := r.CreateOrganization(ctx, org); err != nil {
				t.Fatalf("CreateOrganization: %v", err)
			}
			org.EnforceGuaranteedThroughput = false
			org.LifecycleWebhookURL = "https://hooks.example.com/v2"
			if err := r.UpdateOrganization(ctx, org); err != nil {
				t.Fatalf("UpdateOrganization: %v", err)
			}
			gotOrg, err := r.GetOrganization(ctx, org.ID)
			if err != nil || gotOrg.EnforceGuaranteedThroughput || gotOrg.LifecycleWebhookURL != "https://hooks.example.com/v2" || !gotOrg.DeveloperSelfServeKeys {
				t.Fatalf("GetOrganization mismatch: got=%+v err=%v", gotOrg, err)
			}

			team := &domain.Team{
				ID:                           "team-gov",
				OrgID:                        org.ID,
				Name:                         "Core Team",
				DefaultMemberMaxBudgetMicros: 5_000_000,
				DefaultMemberRPMLimit:        50,
				DefaultMemberTPMLimit:        50_000,
				DefaultMemberAllowedModels:   []string{"openai/*"},
				TeamMemberPermissions:        []string{"keys:create", "keys:revoke"},
				IsActive:                     true,
			}
			if err := r.CreateTeam(ctx, team); err != nil {
				t.Fatalf("CreateTeam: %v", err)
			}

			usr := &domain.User{
				ID:       "usr-gov",
				OrgID:    org.ID,
				TeamID:   team.ID,
				Email:    "dev@gov.example",
				Name:     "Dev",
				Role:     domain.RoleDeveloper,
				IsActive: true,
			}
			if err := r.CreateUser(ctx, usr); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}

			expFuture := now.Add(48 * time.Hour)
			expPast := now.Add(-1 * time.Hour)

			vk1 := &domain.VirtualKey{
				ID:              "vk-gov-1",
				OrgID:           org.ID,
				TeamID:          team.ID,
				UserID:          usr.ID,
				Name:            "alpha-key",
				KeyPrefix:       "sk-gw-alpha",
				KeyHash:         "hash-alpha-active",
				RPMLimit:        30,
				TPMLimit:        10_000,
				MaxBudgetMicros: 2_000_000,
				SpentMicros:     500_000,
				ExpiresAt:       &expFuture,
				IsActive:        true,
			}
			vk2 := &domain.VirtualKey{
				ID:        "vk-gov-2",
				OrgID:     org.ID,
				TeamID:    team.ID,
				Name:      "beta-expired",
				KeyPrefix: "sk-gw-beta",
				KeyHash:   "hash-beta",
				RPMLimit:  20,
				TPMLimit:  5_000,
				ExpiresAt: &expPast,
				IsActive:  true,
			}
			vk3 := &domain.VirtualKey{
				ID:        "vk-gov-3",
				OrgID:     org.ID,
				TeamID:    team.ID,
				Name:      "gamma-revoked",
				KeyPrefix: "sk-gw-gamma",
				KeyHash:   "hash-gamma",
				RPMLimit:  100,
				IsActive:  true,
			}
			for _, k := range []*domain.VirtualKey{vk1, vk2, vk3} {
				if err := r.CreateVirtualKey(ctx, k); err != nil {
					t.Fatalf("CreateVirtualKey(%s): %v", k.ID, err)
				}
			}

			if err := r.RevokeVirtualKeyWithActor(ctx, vk3.ID, "admin-1"); err != nil {
				t.Fatalf("RevokeVirtualKeyWithActor: %v", err)
			}

			// Single-call bundle for active key
			bundle, err := r.GetVirtualKeyAuthBundleByHash(ctx, "hash-alpha-active", now)
			if err != nil {
				t.Fatalf("GetVirtualKeyAuthBundleByHash active: %v", err)
			}
			if bundle.Deprecated || bundle.Key == nil || bundle.Org == nil || bundle.Team == nil || bundle.User == nil {
				t.Fatalf("unexpected bundle: %+v", bundle)
			}

			// Single-call bundle for deprecated hash during grace period
			if err := r.AddDeprecatedVirtualKeyHash(ctx, "hash-alpha-old", vk1.ID, now.Add(15*time.Minute)); err != nil {
				t.Fatalf("AddDeprecatedVirtualKeyHash: %v", err)
			}
			depBundle, err := r.GetVirtualKeyAuthBundleByHash(ctx, "hash-alpha-old", now)
			if err != nil || !depBundle.Deprecated || depBundle.Key.ID != vk1.ID {
				t.Fatalf("GetVirtualKeyAuthBundleByHash deprecated: got=%+v err=%v", depBundle, err)
			}

			// Filter + pagination
			activeKeys, activeTotal, err := r.ListVirtualKeysFiltered(ctx, VirtualKeyFilter{OrgID: org.ID, Status: "active"})
			if err != nil || activeTotal != 1 || len(activeKeys) != 1 || activeKeys[0].ID != vk1.ID {
				t.Fatalf("filter active: total=%d keys=%+v err=%v", activeTotal, activeKeys, err)
			}
			revokedKeys, revokedTotal, err := r.ListVirtualKeysFiltered(ctx, VirtualKeyFilter{OrgID: org.ID, Status: "revoked"})
			if err != nil || revokedTotal != 1 || revokedKeys[0].ID != vk3.ID || revokedKeys[0].RevokedBy != "admin-1" {
				t.Fatalf("filter revoked: total=%d keys=%+v err=%v", revokedTotal, revokedKeys, err)
			}
			expiredKeys, expTotal, err := r.ListVirtualKeysFiltered(ctx, VirtualKeyFilter{OrgID: org.ID, Status: "expired"})
			if err != nil || expTotal != 1 || expiredKeys[0].ID != vk2.ID {
				t.Fatalf("filter expired: total=%d keys=%+v err=%v", expTotal, expiredKeys, err)
			}

			// Unblock + throughput sum (revoked vk3 omitted before unblock, included after)
			rpmSum, tpmSum, err := r.SumChildKeyThroughput(ctx, org.ID, team.ID, "")
			if err != nil || rpmSum != 50 || tpmSum != 15_000 {
				t.Fatalf("SumChildKeyThroughput before unblock: rpm=%d tpm=%d err=%v", rpmSum, tpmSum, err)
			}
			if err := r.UnblockVirtualKey(ctx, vk3.ID); err != nil {
				t.Fatalf("UnblockVirtualKey: %v", err)
			}
			rpmSum2, _, err := r.SumChildKeyThroughput(ctx, org.ID, team.ID, vk3.ID)
			if err != nil || rpmSum2 != 50 {
				t.Fatalf("SumChildKeyThroughput excluding vk3: rpm=%d err=%v", rpmSum2, err)
			}

			// Expiry alerts & rotation metadata
			expiring, err := r.ListVirtualKeysExpiringBefore(ctx, now.Add(72*time.Hour), 10)
			if err != nil || len(expiring) != 1 || expiring[0].ID != vk1.ID {
				t.Fatalf("ListVirtualKeysExpiringBefore: %+v err=%v", expiring, err)
			}
			if err := r.MarkVirtualKeyExpiryAlertSent(ctx, vk1.ID, 7); err != nil {
				t.Fatalf("MarkVirtualKeyExpiryAlertSent: %v", err)
			}
			if err := r.MarkVirtualKeyRotated(ctx, vk1.ID, now); err != nil {
				t.Fatalf("MarkVirtualKeyRotated: %v", err)
			}
			gotVK1, _ := r.GetVirtualKeyByID(ctx, vk1.ID)
			if gotVK1.RotationCount != 1 || gotVK1.LastRotatedAt == nil || len(gotVK1.ExpiryAlertSentDays) != 1 {
				t.Fatalf("expected updated rotation/expiry alert state, got %+v", gotVK1)
			}

			// Reset spend & bulk update
			if err := r.ResetEntitySpend(ctx, EntitySpendScopeKey, org.ID, vk1.ID, ""); err != nil {
				t.Fatalf("ResetEntitySpend: %v", err)
			}
			gotVK1After, _ := r.GetVirtualKeyByID(ctx, vk1.ID)
			if gotVK1After.SpentMicros != 0 {
				t.Fatalf("expected SpentMicros=0 after reset, got %d", gotVK1After.SpentMicros)
			}

			newRPM := 99
			inactive := false
			bulkRes, err := r.BulkUpdateVirtualKeys(ctx, org.ID, []string{vk1.ID, vk3.ID}, VirtualKeyBulkPatch{
				RPMLimit:  &newRPM,
				IsActive:  &inactive,
				RevokedBy: "bulk-op",
			})
			if err != nil || len(bulkRes) != 2 || bulkRes[0].RPMLimit != 99 || bulkRes[0].IsActive || bulkRes[0].RevokedBy != "bulk-op" {
				t.Fatalf("BulkUpdateVirtualKeys: %+v err=%v", bulkRes, err)
			}

			// Audit before/after values
			if err := r.RecordAuditLog(ctx, &domain.AuditLog{
				OrgID:       org.ID,
				ActorID:     "admin-1",
				Action:      "virtual_key.updated",
				Resource:    "virtual_key",
				ResourceID:  vk1.ID,
				BeforeValue: map[string]any{"rpm_limit": 30},
				AfterValue:  map[string]any{"rpm_limit": 99},
			}); err != nil {
				t.Fatalf("RecordAuditLog: %v", err)
			}
			logs, err := r.ListAuditLogs(ctx, org.ID, 10)
			if err != nil || len(logs) == 0 || logs[0].BeforeValue["rpm_limit"] != 30 || logs[0].AfterValue["rpm_limit"] != 99 {
				t.Fatalf("ListAuditLogs diff mismatch: %+v err=%v", logs, err)
			}

			// BulkSyncTeamMemberships: add/update + remove in one call
			if _, _, err := r.BulkSyncTeamMemberships(ctx, org.ID, team.ID, []*domain.TeamMembership{
				{UserID: "usr_bulk_1", Role: domain.RoleDeveloper, MaxBudgetMicros: 50_000},
				{UserID: "usr_bulk_2", Role: domain.RoleDeveloper, MaxBudgetMicros: 60_000},
			}, nil); err != nil {
				t.Fatalf("BulkSyncTeamMemberships upsert: %v", err)
			}
			upserted2, removed2, err := r.BulkSyncTeamMemberships(ctx, org.ID, team.ID, []*domain.TeamMembership{
				{UserID: "usr_bulk_1", Role: domain.RoleTeamAdmin, MaxBudgetMicros: 75_000},
			}, []string{"usr_bulk_2"})
			if err != nil || len(upserted2) != 1 || removed2 != 1 {
				t.Fatalf("BulkSyncTeamMemberships remove: upserted=%d removed=%d err=%v", len(upserted2), removed2, err)
			}
			remaining, err := r.ListTeamMemberships(ctx, org.ID, team.ID, "")
			if err != nil || len(remaining) != 1 || remaining[0].UserID != "usr_bulk_1" || remaining[0].Role != domain.RoleTeamAdmin {
				t.Fatalf("unexpected remaining memberships: %+v err=%v", remaining, err)
			}

			// RotateKEKsTransactionally: rollback leaves state untouched; commit updates all DEKs + staged virtual keys atomically
			if err := r.CreateProviderCredential(ctx, &domain.ProviderCredential{
				ID: "cred_kek_1", OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "kek-cred",
				EncryptedAPIKey: []byte("cipher"), DataNonce: []byte("nonce1234567"),
				EncryptedDEK: []byte("old-dek"), DEKNonce: []byte("oldnonce1234"),
				KeyVersion: 1, IsActive: true,
			}); err != nil {
				t.Fatalf("CreateProviderCredential: %v", err)
			}
			if err := r.CreateVirtualKey(ctx, &domain.VirtualKey{
				ID:            "vk_kek_staged_1",
				OrgID:         org.ID,
				Name:          "staged-kek-key",
				KeyPrefix:     "sk-gw-stk",
				KeyHash:       "hash-staged-kek-active",
				StagedKeyHash: "hash-staged-kek-next",
				StagedKeyDEK:  "old-staged-dek-hex",
				IsActive:      true,
			}); err != nil {
				t.Fatalf("CreateVirtualKey(staged): %v", err)
			}
			_, rbErr := r.RotateKEKsTransactionally(ctx, func(batch KEKRotationBatch) (KEKRotationBatch, error) {
				return KEKRotationBatch{}, fmt.Errorf("injected rewrap failure")
			})
			if rbErr == nil {
				t.Fatal("expected injected rewrap error")
			}
			credAfterRB, _ := r.GetProviderCredential(ctx, "cred_kek_1")
			if string(credAfterRB.EncryptedDEK) != "old-dek" {
				t.Fatalf("expected DEK unchanged after rollback, got %q", string(credAfterRB.EncryptedDEK))
			}
			vkAfterRB, _ := r.GetVirtualKeyByID(ctx, "vk_kek_staged_1")
			if vkAfterRB.StagedKeyDEK != "old-staged-dek-hex" {
				t.Fatalf("expected StagedKeyDEK unchanged after rollback, got %q", vkAfterRB.StagedKeyDEK)
			}

			rotSum, rotErr := r.RotateKEKsTransactionally(ctx, func(batch KEKRotationBatch) (KEKRotationBatch, error) {
				var out KEKRotationBatch
				for _, c := range batch.Credentials {
					cp := *c
					cp.EncryptedDEK = []byte("new-dek")
					cp.KeyVersion++
					out.Credentials = append(out.Credentials, &cp)
				}
				for _, vk := range batch.StagedVirtualKeys {
					cp := *vk
					cp.StagedKeyDEK = "new-staged-dek-hex"
					out.StagedVirtualKeys = append(out.StagedVirtualKeys, &cp)
				}
				return out, nil
			})
			if rotErr != nil || rotSum.CredentialsRewrapped == 0 || rotSum.StagedVirtualKeysRewrapped != 1 {
				t.Fatalf("RotateKEKsTransactionally commit failed: %+v err=%v", rotSum, rotErr)
			}
			credAfterCommit, _ := r.GetProviderCredential(ctx, "cred_kek_1")
			if string(credAfterCommit.EncryptedDEK) != "new-dek" {
				t.Fatalf("expected DEK updated after commit, got %q", string(credAfterCommit.EncryptedDEK))
			}
			vkAfterCommit, _ := r.GetVirtualKeyByID(ctx, "vk_kek_staged_1")
			if vkAfterCommit.StagedKeyDEK != "new-staged-dek-hex" {
				t.Fatalf("expected StagedKeyDEK updated after commit, got %q", vkAfterCommit.StagedKeyDEK)
			}
		})
	}
}
