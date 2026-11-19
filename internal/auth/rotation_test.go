package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestApplyKeyTypePreset(t *testing.T) {
	t.Run("llm_api preset sets data-plane inference routes and non-admin role", func(t *testing.T) {
		vk := &domain.VirtualKey{
			KeyType: domain.KeyTypeLLMAPI,
			Role:    domain.RoleOrgAdmin,
		}
		auth.ApplyKeyTypePreset(vk)
		if vk.KeyType != domain.KeyTypeLLMAPI {
			t.Fatalf("KeyType = %q, want %q", vk.KeyType, domain.KeyTypeLLMAPI)
		}
		if vk.Role != domain.RoleServiceAccount {
			t.Fatalf("Role = %q, want %q", vk.Role, domain.RoleServiceAccount)
		}
		if !slices.Equal(vk.AllowedEndpoints, domain.DefaultAllowedEndpoints) {
			t.Fatalf("AllowedEndpoints = %v, want %v", vk.AllowedEndpoints, domain.DefaultAllowedEndpoints)
		}

		// Preserves narrower explicit data-plane subset
		narrow := &domain.VirtualKey{
			KeyType:          domain.KeyTypeLLMAPI,
			AllowedEndpoints: []string{"/v1/chat/completions"},
		}
		auth.ApplyKeyTypePreset(narrow)
		if !slices.Equal(narrow.AllowedEndpoints, []string{"/v1/chat/completions"}) {
			t.Fatalf("expected narrow llm_api endpoints preserved, got %v", narrow.AllowedEndpoints)
		}

		// Replaces admin endpoints if previously set
		wasAdmin := &domain.VirtualKey{
			KeyType:          domain.KeyTypeLLMAPI,
			AllowedEndpoints: []string{"/admin/v1/*"},
		}
		auth.ApplyKeyTypePreset(wasAdmin)
		if !slices.Equal(wasAdmin.AllowedEndpoints, domain.DefaultAllowedEndpoints) {
			t.Fatalf("expected admin endpoints replaced for llm_api, got %v", wasAdmin.AllowedEndpoints)
		}
	})

	t.Run("management preset restricts to /admin/v1/* and ensures operator role", func(t *testing.T) {
		vk := &domain.VirtualKey{
			KeyType:          domain.KeyTypeManagement,
			AllowedEndpoints: []string{"/v1/chat/completions"},
		}
		auth.ApplyKeyTypePreset(vk)
		if vk.KeyType != domain.KeyTypeManagement {
			t.Fatalf("KeyType = %q, want %q", vk.KeyType, domain.KeyTypeManagement)
		}
		if vk.Role != domain.RoleOrgAdmin {
			t.Fatalf("Role = %q, want %q", vk.Role, domain.RoleOrgAdmin)
		}
		if !slices.Equal(vk.AllowedEndpoints, []string{"/admin/v1/*"}) {
			t.Fatalf("AllowedEndpoints = %v, want [/admin/v1/*]", vk.AllowedEndpoints)
		}

		// Preserves explicit platform_admin role
		plat := &domain.VirtualKey{
			KeyType: domain.KeyTypeManagement,
			Role:    domain.RolePlatformAdmin,
		}
		auth.ApplyKeyTypePreset(plat)
		if plat.Role != domain.RolePlatformAdmin {
			t.Fatalf("expected platform_admin role preserved, got %q", plat.Role)
		}
	})

	t.Run("read_only preset restricts to GET/info routes and viewer/org_viewer role", func(t *testing.T) {
		vk := &domain.VirtualKey{
			KeyType:          domain.KeyTypeReadOnly,
			Role:             domain.RoleOrgAdmin,
			AllowedEndpoints: []string{"*"},
		}
		auth.ApplyKeyTypePreset(vk)
		if vk.Role != domain.RoleOrgViewer {
			t.Fatalf("Role = %q, want %q", vk.Role, domain.RoleOrgViewer)
		}
		if !slices.Equal(vk.AllowedEndpoints, auth.ReadOnlyAllowedEndpoints) {
			t.Fatalf("AllowedEndpoints = %v, want %v", vk.AllowedEndpoints, auth.ReadOnlyAllowedEndpoints)
		}

		// Keeps RoleViewer if explicitly chosen
		viewer := &domain.VirtualKey{
			KeyType:          domain.KeyTypeReadOnly,
			Role:             domain.RoleViewer,
			AllowedEndpoints: []string{"/v1/models"},
		}
		auth.ApplyKeyTypePreset(viewer)
		if viewer.Role != domain.RoleViewer {
			t.Fatalf("expected RoleViewer preserved, got %q", viewer.Role)
		}
		if !slices.Equal(viewer.AllowedEndpoints, []string{"/v1/models"}) {
			t.Fatalf("expected narrow read-only endpoint preserved, got %v", viewer.AllowedEndpoints)
		}
	})

	t.Run("service_account preset sets RoleServiceAccount and clears UserID", func(t *testing.T) {
		vk := &domain.VirtualKey{
			KeyType: domain.KeyTypeServiceAccount,
			Role:    domain.RoleDeveloper,
			UserID:  "usr_human_123",
		}
		auth.ApplyKeyTypePreset(vk)
		if vk.Role != domain.RoleServiceAccount {
			t.Fatalf("Role = %q, want %q", vk.Role, domain.RoleServiceAccount)
		}
		if vk.UserID != "" {
			t.Fatalf("expected UserID cleared for service_account, got %q", vk.UserID)
		}
	})

	t.Run("default preset normalizes empty key_type and preserves caller fields", func(t *testing.T) {
		vk := &domain.VirtualKey{
			Role:             domain.RoleDeveloper,
			UserID:           "usr_1",
			AllowedEndpoints: []string{"/v1/embeddings"},
		}
		auth.ApplyKeyTypePreset(vk)
		if vk.KeyType != domain.KeyTypeDefault {
			t.Fatalf("KeyType = %q, want %q", vk.KeyType, domain.KeyTypeDefault)
		}
		if vk.Role != domain.RoleDeveloper || vk.UserID != "usr_1" || !slices.Equal(vk.AllowedEndpoints, []string{"/v1/embeddings"}) {
			t.Fatalf("default preset should preserve fields, got %+v", vk)
		}
	})

	t.Run("IsValidKeyType validates supported values", func(t *testing.T) {
		for _, valid := range []domain.KeyType{"", domain.KeyTypeDefault, domain.KeyTypeLLMAPI, domain.KeyTypeManagement, domain.KeyTypeReadOnly, domain.KeyTypeServiceAccount} {
			if !auth.IsValidKeyType(valid) {
				t.Fatalf("expected %q to be valid", valid)
			}
		}
		if auth.IsValidKeyType("super_admin") {
			t.Fatal("expected unknown key_type to be invalid")
		}
	})
}

func TestRotateVirtualKeyWithGrace_DualActiveHeadersExpiryAndRevocation(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = redisFabric.Client().Close() }()

	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org_rot", Name: "Rot Org", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	var clockMu sync.RWMutex
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	getNow := func() time.Time {
		clockMu.RLock()
		defer clockMu.RUnlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	svc1 := auth.NewService(repo, redisFabric, "master-secret", 30*time.Second, 5*time.Minute)
	svc2 := auth.NewService(repo, redisFabric, "master-secret", 30*time.Second, 5*time.Minute)
	svc1.SetNowFunc(getNow)
	svc2.SetNowFunc(getNow)
	svc1.StartInvalidationListener(ctx)
	svc2.StartInvalidationListener(ctx)
	defer svc1.StopInvalidationListener()
	defer svc2.StopInvalidationListener()

	// Issue key with 1h scheduled rotation interval
	issued, err := svc1.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:               "org_rot",
		Name:                "grace-key",
		KeyType:             domain.KeyTypeLLMAPI,
		RotationIntervalSec: 3600,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}
	oldRawKey := issued.RawKey
	expectedFirstRot := getNow().Add(3600 * time.Second)
	if issued.KeyRotationAt == nil || !issued.KeyRotationAt.Equal(expectedFirstRot) {
		t.Fatalf("expected initial KeyRotationAt=%v, got %v", expectedFirstRot, issued.KeyRotationAt)
	}

	// Warm both pods' L1 and L2 caches with oldRawKey before rotation
	if id, err := svc1.AuthenticateVirtualKey(ctx, oldRawKey); err != nil || id.DeprecatedKeyRevokeAt != nil {
		t.Fatalf("pre-rotation svc1 auth: id=%+v err=%v", id, err)
	}
	if id, err := svc2.AuthenticateVirtualKey(ctx, oldRawKey); err != nil || id.DeprecatedKeyRevokeAt != nil {
		t.Fatalf("pre-rotation svc2 auth: id=%+v err=%v", id, err)
	}

	// Advance 5 minutes, then rotate with 10 minute grace period
	advance(5 * time.Minute)
	grace := 10 * time.Minute
	expectedRevokeAt := getNow().Add(grace)
	expectedNextRot := getNow().Add(3600 * time.Second)

	rotated, err := svc1.RotateVirtualKeyWithGrace(ctx, issued.ID, grace)
	if err != nil {
		t.Fatalf("RotateVirtualKeyWithGrace: %v", err)
	}
	newRawKey := rotated.RawKey
	if newRawKey == "" || newRawKey == oldRawKey {
		t.Fatalf("expected distinct rotated RawKey, got %q", newRawKey)
	}
	if rotated.KeyRotationAt == nil || !rotated.KeyRotationAt.Equal(expectedNextRot) {
		t.Fatalf("expected advanced KeyRotationAt=%v, got %v", expectedNextRot, rotated.KeyRotationAt)
	}

	// Negative grace period rejected
	if _, err := svc1.RotateVirtualKeyWithGrace(ctx, issued.ID, -1*time.Second); err == nil {
		t.Fatal("expected error for negative grace period")
	}

	// On svc1: old key still works during grace window and carries DeprecatedKeyRevokeAt
	depID1, err := svc1.AuthenticateVirtualKey(ctx, oldRawKey)
	if err != nil {
		t.Fatalf("expected old key to authenticate during grace window on svc1: %v", err)
	}
	if depID1.DeprecatedKeyRevokeAt == nil || !depID1.DeprecatedKeyRevokeAt.Equal(expectedRevokeAt) {
		t.Fatalf("expected DeprecatedKeyRevokeAt=%v, got %v", expectedRevokeAt, depID1.DeprecatedKeyRevokeAt)
	}

	// On svc2: wait briefly for Pub/Sub invalidation so stale non-deprecated entry is replaced with deprecated metadata
	deadline := time.Now().Add(500 * time.Millisecond)
	var depID2 *domain.IdentityContext
	for time.Now().Before(deadline) {
		depID2, err = svc2.AuthenticateVirtualKey(ctx, oldRawKey)
		if err == nil && depID2 != nil && depID2.DeprecatedKeyRevokeAt != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || depID2 == nil || depID2.DeprecatedKeyRevokeAt == nil || !depID2.DeprecatedKeyRevokeAt.Equal(expectedRevokeAt) {
		t.Fatalf("expected svc2 to observe DeprecatedKeyRevokeAt=%v, got id=%+v err=%v", expectedRevokeAt, depID2, err)
	}

	// Verify DataPlaneMiddleware emits X-Gateway-Key-Deprecated and X-Gateway-Key-Revoke-At for old key,
	// and omits them for the new primary key.
	rbac := auth.NewRBACEngine(repo)
	mw := auth.DataPlaneMiddleware(svc1, rbac)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqOld := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	reqOld.Header.Set("Authorization", "Bearer "+oldRawKey)
	recOld := httptest.NewRecorder()
	mw.ServeHTTP(recOld, reqOld)
	if recOld.Code != http.StatusOK {
		t.Fatalf("old key status = %d, want 200 (%s)", recOld.Code, recOld.Body.String())
	}
	if recOld.Header().Get(auth.HeaderKeyDeprecated) != "true" {
		t.Fatalf("X-Gateway-Key-Deprecated = %q, want \"true\"", recOld.Header().Get(auth.HeaderKeyDeprecated))
	}
	if recOld.Header().Get(auth.HeaderKeyRevokeAt) != expectedRevokeAt.Format(time.RFC3339) {
		t.Fatalf("X-Gateway-Key-Revoke-At = %q, want %q", recOld.Header().Get(auth.HeaderKeyRevokeAt), expectedRevokeAt.Format(time.RFC3339))
	}

	reqNew := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	reqNew.Header.Set("Authorization", "Bearer "+newRawKey)
	recNew := httptest.NewRecorder()
	mw.ServeHTTP(recNew, reqNew)
	if recNew.Code != http.StatusOK {
		t.Fatalf("new key status = %d, want 200 (%s)", recNew.Code, recNew.Body.String())
	}
	if recNew.Header().Get(auth.HeaderKeyDeprecated) != "" || recNew.Header().Get(auth.HeaderKeyRevokeAt) != "" {
		t.Fatalf("expected no deprecation headers for new key, got deprecated=%q revoke_at=%q",
			recNew.Header().Get(auth.HeaderKeyDeprecated), recNew.Header().Get(auth.HeaderKeyRevokeAt))
	}

	// Advance clock to exact revoke_at: old key must fail immediately (even when cached in L1/L2)
	advance(grace)
	if _, err := svc1.AuthenticateVirtualKey(ctx, oldRawKey); err == nil {
		t.Fatal("expected old key to be rejected once clock reaches revoke_at")
	}
	if _, err := svc2.AuthenticateVirtualKey(ctx, oldRawKey); err == nil {
		t.Fatal("expected old key to be rejected on svc2 once clock reaches revoke_at")
	}
	// New key continues working
	if id, err := svc1.AuthenticateVirtualKey(ctx, newRawKey); err != nil || id.DeprecatedKeyRevokeAt != nil {
		t.Fatalf("expected new key to remain valid after old key expiry: id=%+v err=%v", id, err)
	}

	// Explicit RevokeKey immediately invalidates both primary AND any active deprecated grace hash
	rotated2, err := svc1.RotateVirtualKeyWithGrace(ctx, issued.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("second RotateVirtualKeyWithGrace: %v", err)
	}
	// Warm L1/L2 for deprecated hash (newRawKey) and primary hash (rotated2.RawKey)
	if _, err := svc1.AuthenticateVirtualKey(ctx, newRawKey); err != nil {
		t.Fatalf("expected previous key to authenticate during second grace period: %v", err)
	}
	if _, err := svc1.AuthenticateVirtualKey(ctx, rotated2.RawKey); err != nil {
		t.Fatalf("expected latest key to authenticate: %v", err)
	}
	if err := svc1.RevokeKey(ctx, issued.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := svc1.AuthenticateVirtualKey(ctx, rotated2.RawKey); err == nil {
		t.Fatal("expected primary key rejected after RevokeKey")
	}
	if _, err := svc1.AuthenticateVirtualKey(ctx, newRawKey); err == nil {
		t.Fatal("expected deprecated grace key rejected immediately after RevokeKey")
	}
}

func TestKeyRotationManager_DistributedRedisLockAndAutoRotation(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = redisFabric.Client().Close() }()

	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org_auto", Name: "Auto Org", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	var clockMu sync.RWMutex
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	getNow := func() time.Time {
		clockMu.RLock()
		defer clockMu.RUnlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	svc := auth.NewService(repo, redisFabric, "master-secret", 30*time.Second, 5*time.Minute)
	svc.SetMasterEncryptionKey("rotation-test-master-encryption-key-0123456789")
	svc.SetNowFunc(getNow)

	dueAt := getNow().Add(-10 * time.Second)
	futureAt := getNow().Add(30 * time.Minute)

	dueKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:               "org_auto",
		Name:                "auto-due-key",
		KeyType:             domain.KeyTypeLLMAPI,
		RotationIntervalSec: 600,
		KeyRotationAt:       &dueAt,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey(due): %v", err)
	}
	oldDueRawKey := dueKey.RawKey
	oldDueHash := dueKey.KeyHash

	futureKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:               "org_auto",
		Name:                "auto-future-key",
		KeyType:             domain.KeyTypeLLMAPI,
		RotationIntervalSec: 600,
		KeyRotationAt:       &futureAt,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey(future): %v", err)
	}

	// Seed an already-expired deprecated hash so RunOnce purges it
	staleHash := strings.Repeat("c", 64)
	if err := repo.AddDeprecatedVirtualKeyHash(ctx, staleHash, futureKey.ID, getNow().Add(-5*time.Second)); err != nil {
		t.Fatalf("AddDeprecatedVirtualKeyHash(stale): %v", err)
	}

	grace := 5 * time.Minute
	var delivered []string
	mgr := auth.NewKeyRotationManager(svc, repo, redisFabric, auth.KeyRotationConfig{
		Deliver: func(_ context.Context, _, _, raw string) error {
			delivered = append(delivered, raw)
			return nil
		},
		PollInterval: 50 * time.Millisecond,
		GracePeriod:  grace,
		LockTTL:      55 * time.Second,
		PodID:        "pod-alpha",
		Now:          getNow,
	})

	// 1. Contention test: another pod already holds gw:lock:key_rotation
	if err := mr.Set(auth.KeyRotationLockKey, "pod-beta"); err != nil {
		t.Fatalf("mr.Set lock: %v", err)
	}
	resContended, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce under contention returned error: %v", err)
	}
	if resContended.LockAcquired || resContended.RotatedKeys != 0 {
		t.Fatalf("expected skipped sweep when lock held by another pod, got %+v", resContended)
	}
	// Lua release must NOT have touched pod-beta's lock!
	lockVal, err := mr.Get(auth.KeyRotationLockKey)
	if err != nil || lockVal != "pod-beta" {
		t.Fatalf("expected pod-beta lock untouched, got val=%q err=%v", lockVal, err)
	}

	// 2. Clear lock -> pod-alpha acquires lock, purges stale hash, rotates dueKey, records audit log, and releases lock
	mr.Del(auth.KeyRotationLockKey)

	res, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.LockAcquired || res.RotatedKeys != 1 || len(res.RotatedKeyIDs) != 1 || res.RotatedKeyIDs[0] != dueKey.ID {
		t.Fatalf("unexpected RunOnce result: %+v", res)
	}
	if res.PurgedHashes != 1 {
		t.Fatalf("PurgedHashes = %d, want 1", res.PurgedHashes)
	}
	if mr.Exists(auth.KeyRotationLockKey) {
		t.Fatal("expected Redis distributed lock to be released by Lua script after RunOnce")
	}

	// Verify dueKey hash changed & KeyRotationAt advanced, while futureKey is untouched
	updatedDue, err := repo.GetVirtualKeyByID(ctx, dueKey.ID)
	if err != nil {
		t.Fatalf("GetVirtualKeyByID(due): %v", err)
	}
	if updatedDue.KeyHash == oldDueHash {
		t.Fatal("expected dueKey KeyHash to change after auto-rotation")
	}
	expectedNextRot := getNow().Add(600 * time.Second)
	if updatedDue.KeyRotationAt == nil || !updatedDue.KeyRotationAt.Equal(expectedNextRot) {
		t.Fatalf("expected updated KeyRotationAt=%v, got %v", expectedNextRot, updatedDue.KeyRotationAt)
	}

	updatedFuture, err := repo.GetVirtualKeyByID(ctx, futureKey.ID)
	if err != nil {
		t.Fatalf("GetVirtualKeyByID(future): %v", err)
	}
	if updatedFuture.KeyHash != futureKey.KeyHash {
		t.Fatal("expected futureKey to remain untouched")
	}

	// Old dueKey remains usable during 5m grace period with deprecation metadata
	depID, err := svc.AuthenticateVirtualKey(ctx, oldDueRawKey)
	if err != nil {
		t.Fatalf("expected old dueKey to work during auto-rotation grace period: %v", err)
	}
	expectedRevoke := getNow().Add(grace)
	if depID.DeprecatedKeyRevokeAt == nil || !depID.DeprecatedKeyRevokeAt.Equal(expectedRevoke) {
		t.Fatalf("DeprecatedKeyRevokeAt = %v, want %v", depID.DeprecatedKeyRevokeAt, expectedRevoke)
	}

	// Audit log recorded without leaking any raw key material
	logs, err := repo.ListAuditLogs(ctx, "org_auto", 20)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	var foundAudit *domain.AuditLog
	for _, l := range logs {
		if l.Action == "virtual_key.auto_rotated" && l.ResourceID == dueKey.ID {
			foundAudit = l
			break
		}
	}
	if foundAudit == nil {
		t.Fatalf("expected virtual_key.auto_rotated audit log, got %+v", logs)
	}
	if foundAudit.ActorID != "key-rotation-worker" {
		t.Fatalf("ActorID = %q, want key-rotation-worker", foundAudit.ActorID)
	}
	for k, v := range foundAudit.Details {
		if str, ok := v.(string); ok && len(str) > 20 && strings.HasPrefix(str, "sk-gw-") {
			t.Fatalf("audit detail %q must never contain raw secret: %q", k, str)
		}
	}

	// 3. Advance past grace period: old key rejected and next sweep purges expired deprecated hash
	advance(grace + time.Second)
	if _, err := svc.AuthenticateVirtualKey(ctx, oldDueRawKey); err == nil {
		t.Fatal("expected old dueKey rejected after grace period elapsed")
	}
	resPurge, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce(purge): %v", err)
	}
	if !resPurge.LockAcquired || resPurge.PurgedHashes != 1 || resPurge.RotatedKeys != 0 {
		t.Fatalf("expected 1 purged hash and 0 rotations, got %+v", resPurge)
	}

	// 4. Advance past next rotation interval and verify background Start/Stop loop rotates automatically
	advance(600 * time.Second)
	hashBeforeLoop := updatedDue.KeyHash
	bgCtx, bgCancel := context.WithCancel(ctx)
	defer bgCancel()
	mgr.Start(bgCtx)

	waitDeadline := time.Now().Add(2 * time.Second)
	rotatedInBG := false
	for time.Now().Before(waitDeadline) {
		k, err := repo.GetVirtualKeyByID(ctx, dueKey.ID)
		if err == nil && k != nil && k.KeyHash != hashBeforeLoop {
			rotatedInBG = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	mgr.Stop()
	mgr.Stop() // idempotent stop
	if !rotatedInBG {
		t.Fatal("expected KeyRotationManager background loop to auto-rotate due key")
	}
	if len(delivered) < 2 {
		t.Fatalf("expected at least 2 delivered replacements, got %d", len(delivered))
	}
}

func TestKeyRotationManager_StagedReuseAcrossDeliveryRetriesAndNoDelivery(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org_stage", Name: "Stage Org", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	svc := auth.NewService(repo, nil, "master-secret", 30*time.Second, 5*time.Minute)
	svc.SetMasterEncryptionKey("staging-master-encryption-key-0123456789abcdef")
	svc.SetNowFunc(func() time.Time { return now })

	dueAt := now.Add(-1 * time.Minute)
	vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:               "org_stage",
		Name:                "scheduled-staged-key",
		KeyType:             domain.KeyTypeLLMAPI,
		RotationIntervalSec: 3600,
		KeyRotationAt:       &dueAt,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}
	origRaw := vk.RawKey
	origHash := vk.KeyHash

	// 1. Without a delivery channel, scheduled auto-rotation leaves due keys active.
	noDeliverMgr := auth.NewKeyRotationManager(svc, repo, nil, auth.KeyRotationConfig{
		GracePeriod: 10 * time.Minute,
		Now:         func() time.Time { return now },
	})
	noDelRes, err := noDeliverMgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce(nil deliver): %v", err)
	}
	if noDelRes.RotatedKeys != 0 {
		t.Fatalf("expected 0 scheduled rotations when delivery is unconfigured, got %d", noDelRes.RotatedKeys)
	}
	stillActive, _ := repo.GetVirtualKeyByID(ctx, vk.ID)
	if stillActive.KeyHash != origHash || stillActive.StagedKeyHash != "" {
		t.Fatalf("expected active key unchanged and nothing staged without delivery")
	}

	// Manual rotation still works even when scheduled delivery is unconfigured.
	manualKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_stage",
		Name:  "manual-key",
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey(manual): %v", err)
	}
	if rotatedManual, err := svc.RotateVirtualKeyWithGrace(ctx, manualKey.ID, 5*time.Minute); err != nil || rotatedManual.RawKey == "" || rotatedManual.RawKey == manualKey.RawKey {
		t.Fatalf("expected manual rotation without delivery channel to succeed, got %+v err=%v", rotatedManual, err)
	}

	// 2. Transient delivery failures persist an encrypted staged key and reuse the exact
	// same replacement across retries before promoting and starting grace on 2xx ACK.
	var delivered []string
	var failDelivery = true
	mgr := auth.NewKeyRotationManager(svc, repo, nil, auth.KeyRotationConfig{
		Deliver: func(_ context.Context, orgID, keyID, replacement string) error {
			delivered = append(delivered, replacement)
			if failDelivery {
				return errors.New("delivery webhook returned 503")
			}
			return nil
		},
		GracePeriod: 15 * time.Minute,
		Now:         func() time.Time { return now },
	})

	// Attempt 1 fails -> staged key stored encrypted, old key remains active without grace deprecation.
	res1, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce attempt 1: %v", err)
	}
	if res1.RotatedKeys != 0 || res1.Errors != 1 {
		t.Fatalf("expected 0 rotations and 1 error on failed delivery, got %+v", res1)
	}
	staged1, err := repo.GetVirtualKeyByID(ctx, vk.ID)
	if err != nil {
		t.Fatalf("GetVirtualKeyByID after attempt 1: %v", err)
	}
	if staged1.KeyHash != origHash {
		t.Fatal("expected active key hash unchanged before delivery ACK")
	}
	if staged1.StagedKeyHash == "" || staged1.StagedEncryptedRawKey == "" || staged1.StagedKeyDEK == "" || staged1.StagedCreatedAt == nil {
		t.Fatalf("expected encrypted staged replacement fields populated, got %+v", staged1)
	}
	if strings.Contains(staged1.StagedEncryptedRawKey, "sk-gw-") {
		t.Fatal("staged replacement ciphertext must not contain plaintext key")
	}
	idOrig1, err := svc.AuthenticateVirtualKey(ctx, origRaw)
	if err != nil || idOrig1.DeprecatedKeyRevokeAt != nil {
		t.Fatalf("expected original key active with no grace period before delivery ACK, got %+v err=%v", idOrig1, err)
	}

	// Attempt 2 fails -> must reuse the EXACT same staged replacement string without re-minting.
	res2, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce attempt 2: %v", err)
	}
	if res2.RotatedKeys != 0 || res2.Errors != 1 || len(delivered) != 2 || delivered[0] != delivered[1] {
		t.Fatalf("expected retry delivery to reuse exact staged replacement, res=%+v delivered=%v", res2, delivered)
	}

	// Attempt 3 succeeds (delivery ACK) -> delivers same replacement, promotes to primary,
	// clears staged fields, and starts old key grace period.
	failDelivery = false
	res3, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce attempt 3: %v", err)
	}
	if res3.RotatedKeys != 1 || len(delivered) != 3 || delivered[2] != delivered[0] {
		t.Fatalf("expected promotion on ACK with same replacement, res=%+v delivered=%v", res3, delivered)
	}
	promoted, err := repo.GetVirtualKeyByID(ctx, vk.ID)
	if err != nil {
		t.Fatalf("GetVirtualKeyByID after ACK: %v", err)
	}
	if promoted.KeyHash != auth.HashKey(delivered[0]) {
		t.Fatal("expected promoted KeyHash to match staged replacement")
	}
	if promoted.StagedKeyHash != "" || promoted.StagedEncryptedRawKey != "" || promoted.StagedKeyDEK != "" || promoted.StagedCreatedAt != nil {
		t.Fatalf("expected staged fields cleared after promotion, got %+v", promoted)
	}
	if _, err := svc.AuthenticateVirtualKey(ctx, delivered[0]); err != nil {
		t.Fatalf("expected promoted replacement key to authenticate: %v", err)
	}
	idGrace, err := svc.AuthenticateVirtualKey(ctx, origRaw)
	if err != nil || idGrace.DeprecatedKeyRevokeAt == nil || !idGrace.DeprecatedKeyRevokeAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("expected old key deprecated with grace period starting at ACK, got %+v err=%v", idGrace, err)
	}
}

func TestKeyRotationManager_AutoRotatedWebhookAndSecretSink(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	var mu sync.Mutex
	var webhookPayloads []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		mu.Lock()
		webhookPayloads = append(webhookPayloads, payload)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:                  "org-rot-hook",
		Name:                "Rot Hook Org",
		IsActive:            true,
		LifecycleWebhookURL: srv.URL,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	svc := auth.NewService(repo, nil, "master-key-rot-webhook-0123456789", time.Minute, time.Minute)
	svc.SetNowFunc(func() time.Time { return now })

	past := now.Add(-time.Minute)
	vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:               "org-rot-hook",
		Name:                "auto-rot-webhook-key",
		RotationIntervalSec: 3600,
		KeyRotationAt:       &past,
	})
	if err != nil {
		t.Fatal(err)
	}

	var delivered []auth.KeyRotatedSecretEvent
	mgr := auth.NewKeyRotationManager(svc, repo, nil, auth.KeyRotationConfig{
		PollInterval: time.Minute,
		GracePeriod:  30 * time.Minute,
		HTTPClient:   srv.Client(),
		SecretSink: auth.KeySecretSinkFunc(func(_ context.Context, ev auth.KeyRotatedSecretEvent) error {
			delivered = append(delivered, ev)
			return nil
		}),
		Now: func() time.Time { return now },
	})

	res, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.RotatedKeys != 1 || res.WebhooksSent != 1 || res.Errors != 0 {
		t.Fatalf("unexpected sweep result: %+v", res)
	}
	if len(delivered) != 1 || delivered[0].VirtualKeyID != vk.ID || !strings.HasPrefix(delivered[0].RawKey, "sk-gw-") {
		t.Fatalf("expected SecretSink to receive newly minted raw key, got %+v", delivered)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(webhookPayloads) != 1 {
		t.Fatalf("expected 1 auto-rotation webhook payload, got %d", len(webhookPayloads))
	}
	if webhookPayloads[0]["event"] != "virtual_key.auto_rotated" {
		t.Fatalf("unexpected event: %v", webhookPayloads[0]["event"])
	}
	if _, leaked := webhookPayloads[0]["raw_key"]; leaked {
		t.Fatalf("webhook payload must never expose raw_key")
	}
	if errors.Is(context.Canceled, nil) {
		t.Fatal("unreachable")
	}
}

func TestUpdateVirtualKey_And_SetSecretSink_GraceCacheConsistency(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)

	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org-grace-upd",
		Name:     "Grace Update Org",
		Slug:     "grace-upd",
		IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)
	svc := auth.NewService(repo, rf, "test-master-admin-key", time.Minute, 5*time.Minute)
	svc.SetNowFunc(func() time.Time { return now })

	issued, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:         "org-grace-upd",
		Name:          "grace-cache-key",
		AllowedModels: []string{"gpt-4o"},
	})
	if err != nil {
		t.Fatal(err)
	}
	oldRawKey := issued.RawKey

	rotated, err := svc.RotateVirtualKeyWithGrace(ctx, issued.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Warm L1 + Redis L2 for the deprecated grace key
	idOld, err := svc.AuthenticateVirtualKey(ctx, oldRawKey)
	if err != nil {
		t.Fatalf("AuthenticateVirtualKey(old grace key): %v", err)
	}
	if !slices.Equal(idOld.KeyAllowedModels, []string{"gpt-4o"}) {
		t.Fatalf("unexpected initial AllowedModels: %v", idOld.KeyAllowedModels)
	}

	// Non-deactivating UpdateVirtualKey must evict warm deprecated grace cache without deleting the grace window
	updated := *rotated
	updated.RawKey = ""
	updated.AllowedModels = []string{"claude-sonnet-4"}
	if err := svc.UpdateVirtualKey(ctx, &updated); err != nil {
		t.Fatalf("UpdateVirtualKey(models): %v", err)
	}
	idAfterUpdate, err := svc.AuthenticateVirtualKey(ctx, oldRawKey)
	if err != nil {
		t.Fatalf("expected old grace key to stay active with refreshed policy: %v", err)
	}
	if !slices.Equal(idAfterUpdate.KeyAllowedModels, []string{"claude-sonnet-4"}) {
		t.Fatalf("expected stale deprecated grace cache to refresh to [claude-sonnet-4], got %v", idAfterUpdate.KeyAllowedModels)
	}

	// SetSecretSink dynamically updates KeySecretSink and receives rotated raw key
	var sinkEvents []auth.KeyRotatedSecretEvent
	past := now.Add(-time.Minute)
	updated.RotationIntervalSec = 3600
	updated.KeyRotationAt = &past
	if err := svc.UpdateVirtualKey(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	mgr := auth.NewKeyRotationManager(svc, repo, nil, auth.KeyRotationConfig{
		PollInterval: time.Minute,
		GracePeriod:  time.Hour,
		Now:          func() time.Time { return now },
	})
	mgr.SetSecretSink(auth.KeySecretSinkFunc(func(_ context.Context, ev auth.KeyRotatedSecretEvent) error {
		sinkEvents = append(sinkEvents, ev)
		return nil
	}))
	res, err := mgr.RunOnce(ctx)
	if err != nil || res.RotatedKeys != 1 || len(sinkEvents) != 1 || !strings.HasPrefix(sinkEvents[0].RawKey, "sk-gw-") {
		t.Fatalf("expected SetSecretSink delivery after RunOnce, res=%+v events=%+v err=%v", res, sinkEvents, err)
	}

	// Deactivating via UpdateVirtualKey immediately clears & evicts both primary and deprecated grace hashes
	disabled := *rotated
	disabled.RawKey = ""
	disabled.IsActive = false
	if err := svc.UpdateVirtualKey(ctx, &disabled); err != nil {
		t.Fatalf("UpdateVirtualKey(disable): %v", err)
	}
	if _, err := svc.AuthenticateVirtualKey(ctx, oldRawKey); err == nil {
		t.Fatalf("expected old grace key to fail immediately after UpdateVirtualKey(IsActive=false)")
	}
}

func TestKeyRotationManager_SecretSinkRetryPreservesStagedKey(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org-sink-retry",
		Name:     "Sink Retry Org",
		Slug:     "sink-retry",
		IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)
	svc := auth.NewService(repo, nil, "test-master-admin-key", time.Minute, 5*time.Minute)
	svc.SetNowFunc(func() time.Time { return now })
	vault, err := auth.NewVault(strings.Repeat("v", 32))
	if err != nil {
		t.Fatal(err)
	}
	svc.SetVault(vault)

	past := now.Add(-time.Minute)
	issued, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:               "org-sink-retry",
		Name:                "sink-retry-key",
		RotationIntervalSec: 3600,
		KeyRotationAt:       &past,
	})
	if err != nil {
		t.Fatal(err)
	}

	var attempts int
	var delivered []auth.KeyRotatedSecretEvent
	mgr := auth.NewKeyRotationManager(svc, repo, nil, auth.KeyRotationConfig{
		PollInterval: time.Minute,
		GracePeriod:  time.Hour,
		Now:          func() time.Time { return now },
		SecretSink: auth.KeySecretSinkFunc(func(_ context.Context, ev auth.KeyRotatedSecretEvent) error {
			attempts++
			if attempts <= 2 {
				return errors.New("transient secret manager outage")
			}
			delivered = append(delivered, ev)
			return nil
		}),
	})

	// First sweep fails delivery -> staged encrypted key must stay persisted and record one failure audit entry.
	res1, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce #1 unexpected error: %v", err)
	}
	if res1.Errors != 1 || res1.RotatedKeys != 0 {
		t.Fatalf("expected Errors=1 RotatedKeys=0 on transient failure, got %+v", res1)
	}
	vkStaged, err := repo.GetVirtualKeyByID(ctx, issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if vkStaged.StagedKeyHash == "" || vkStaged.StagedKeyDEK == "" {
		t.Fatalf("expected StagedKeyHash & StagedKeyDEK preserved after transient SecretSink error")
	}
	if vkStaged.KeyHash != issued.KeyHash {
		t.Fatalf("expected active KeyHash unchanged after transient SecretSink error")
	}
	deliveries1, failures1 := mgr.DeliveryStats()
	if deliveries1 != 0 || failures1 != 1 {
		t.Fatalf("DeliveryStats after failure #1 = (%d, %d), want (0, 1)", deliveries1, failures1)
	}
	logs1, err := repo.ListAuditLogs(ctx, "org-sink-retry", 20)
	if err != nil {
		t.Fatal(err)
	}
	countAction := func(logs []*domain.AuditLog, action string) int {
		n := 0
		for _, l := range logs {
			if l != nil && l.Action == action {
				n++
			}
		}
		return n
	}
	if got := countAction(logs1, "virtual_key.auto_rotation_failed"); got != 1 {
		t.Fatalf("expected 1 virtual_key.auto_rotation_failed audit log after RunOnce #1, got %d", got)
	}

	// Second sweep fails again on already-staged key -> must NOT duplicate failed audit log entry.
	res2Fail, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce #2 unexpected error: %v", err)
	}
	if res2Fail.Errors != 1 || res2Fail.RotatedKeys != 0 {
		t.Fatalf("expected Errors=1 RotatedKeys=0 on RunOnce #2 failure, got %+v", res2Fail)
	}
	logs2, err := repo.ListAuditLogs(ctx, "org-sink-retry", 20)
	if err != nil {
		t.Fatal(err)
	}
	if got := countAction(logs2, "virtual_key.auto_rotation_failed"); got != 1 {
		t.Fatalf("expected throttled 1 virtual_key.auto_rotation_failed audit log after RunOnce #2, got %d", got)
	}

	// Third sweep retries exact same staged key hash and promotes it cleanly.
	res3, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce #3 unexpected error: %v", err)
	}
	if res3.Errors != 0 || res3.RotatedKeys != 1 || len(delivered) != 1 {
		t.Fatalf("expected recovery on RunOnce #3, got res=%+v delivered=%d", res3, len(delivered))
	}
	if auth.HashKey(delivered[0].RawKey) != vkStaged.StagedKeyHash {
		t.Fatalf("expected retry delivery for staged hash %q, got %q", vkStaged.StagedKeyHash, auth.HashKey(delivered[0].RawKey))
	}
	vkPromoted, err := repo.GetVirtualKeyByID(ctx, issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if vkPromoted.KeyHash != vkStaged.StagedKeyHash || vkPromoted.StagedKeyHash != "" || vkPromoted.StagedKeyDEK != "" {
		t.Fatalf("expected staged key promoted and cleared, got hash=%q staged=%q dek=%q", vkPromoted.KeyHash, vkPromoted.StagedKeyHash, vkPromoted.StagedKeyDEK)
	}
	deliveries3, failures3 := mgr.DeliveryStats()
	if deliveries3 != 1 || failures3 != 2 {
		t.Fatalf("DeliveryStats after retry = (%d, %d), want (1, 2)", deliveries3, failures3)
	}
	logs3, err := repo.ListAuditLogs(ctx, "org-sink-retry", 20)
	if err != nil {
		t.Fatal(err)
	}
	if got := countAction(logs3, "virtual_key.auto_rotated"); got != 1 {
		t.Fatalf("expected 1 virtual_key.auto_rotated audit log after promotion, got %d", got)
	}
}
