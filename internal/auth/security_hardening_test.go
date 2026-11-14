package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func signTestRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims *auth.JWTClaims) string {
	t.Helper()
	hdrBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	clmBytes, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(clmBytes)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign rs256: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestJWTVerifier_SingleflightAndBackoff(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	nEnc := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	eEnc := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes())

	var fetches atomic.Int32
	var failMode atomic.Bool
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if failMode.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		time.Sleep(30 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "k1",
					"use": "sig",
					"alg": "RS256",
					"n":   nEnc,
					"e":   eEnc,
				},
			},
		})
	}))
	defer jwksSrv.Close()

	// 1. When JWKS fails (!cacheValid), backoff prevents immediate retry storm.
	failMode.Store(true)
	vFail := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:      "https://idp.example.com",
		Audience:    "ai-gateway",
		OIDCJWKSURL: jwksSrv.URL,
		HTTPClient:  jwksSrv.Client(),
	})
	tok := signTestRS256(t, privKey, "k1", &auth.JWTClaims{
		Subject:   "user-1",
		Issuer:    "https://idp.example.com",
		Audience:  auth.AudienceClaim{"ai-gateway"},
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if _, err := vFail.Verify(t.Context(), tok); err == nil {
		t.Fatal("expected Verify to fail when JWKS returns 500")
	}
	if _, err := vFail.Verify(t.Context(), tok); err == nil {
		t.Fatal("expected second Verify to fail under backoff")
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch under backoff when !cacheValid, got %d", got)
	}

	// 2. Concurrent Verify calls coalesce into a single JWKS fetch via singleflight.
	fetches.Store(0)
	failMode.Store(false)
	vSF := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:      "https://idp.example.com",
		Audience:    "ai-gateway",
		OIDCJWKSURL: jwksSrv.URL,
		HTTPClient:  jwksSrv.Client(),
	})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := vSF.Verify(t.Context(), tok)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Verify failed: %v", err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("expected singleflight to coalesce 8 concurrent Verify calls into 1 fetch, got %d", got)
	}
}

func TestJWTVerifier_AlgMismatchRejected(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	nEnc := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	eEnc := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes())

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "k1",
					"use": "sig",
					"alg": "ES256", // Mismatched alg vs RS256 token
					"n":   nEnc,
					"e":   eEnc,
				},
			},
		})
	}))
	defer jwksSrv.Close()

	v := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:      "https://idp.example.com",
		Audience:    "ai-gateway",
		OIDCJWKSURL: jwksSrv.URL,
		HTTPClient:  jwksSrv.Client(),
	})
	tok := signTestRS256(t, privKey, "k1", &auth.JWTClaims{
		Subject:   "user-1",
		Issuer:    "https://idp.example.com",
		Audience:  auth.AudienceClaim{"ai-gateway"},
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if _, err := v.Verify(t.Context(), tok); err == nil {
		t.Fatal("expected Verify to reject token when JWK alg != token header alg")
	}
}

func TestIssueAndAuthenticateVirtualKey_Hardening(t *testing.T) {
	ctx := t.Context()
	repo := storage.NewMemoryRepository()
	orgA := &domain.Organization{ID: "org-a", Name: "Org A", Slug: "org-a", IsActive: true}
	orgB := &domain.Organization{ID: "org-b", Name: "Org B", Slug: "org-b", IsActive: true}
	_ = repo.CreateOrganization(ctx, orgA)
	_ = repo.CreateOrganization(ctx, orgB)

	teamB := &domain.Team{ID: "team-b", OrgID: orgB.ID, Name: "Team B", IsActive: true}
	_ = repo.CreateTeam(ctx, teamB)
	userB := &domain.User{ID: "user-b", OrgID: orgB.ID, Email: "b@example.com", Role: domain.RoleDeveloper, IsActive: true}
	_ = repo.CreateUser(ctx, userB)
	userAInactive := &domain.User{ID: "user-a-inactive", OrgID: orgA.ID, Email: "inactive@example.com", Role: domain.RoleDeveloper, IsActive: false}
	_ = repo.CreateUser(ctx, userAInactive)

	svc := auth.NewService(repo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)

	// Default AllowedEndpoints should be ["*"]
	vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{OrgID: orgA.ID, Name: "default-ep"})
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}
	if len(vk.AllowedEndpoints) != 1 || vk.AllowedEndpoints[0] != "*" {
		t.Fatalf("expected default AllowedEndpoints [*], got %v", vk.AllowedEndpoints)
	}

	// Cross-org TeamID must fail closed
	if _, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{OrgID: orgA.ID, TeamID: teamB.ID, Name: "bad-team"}); err == nil {
		t.Fatal("expected cross-org TeamID to be rejected")
	}

	// Cross-org UserID must fail closed
	if _, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{OrgID: orgA.ID, UserID: userB.ID, Name: "bad-user"}); err == nil {
		t.Fatal("expected cross-org UserID to be rejected")
	}

	// Inactive user key must fail closed on AuthenticateVirtualKey
	vkInactiveUser, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{OrgID: orgA.ID, UserID: userAInactive.ID, Name: "inactive-user-key"})
	if err != nil {
		t.Fatalf("issue inactive user key: %v", err)
	}
	if _, err := svc.AuthenticateVirtualKey(ctx, vkInactiveUser.RawKey); err == nil {
		t.Fatal("expected inactive user virtual key to be rejected")
	}

	// Cross-org team on persisted key must fail closed on AuthenticateVirtualKey
	rawMismatch := "sk-gw-mismatch-team-key-123456"
	_ = repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:        "vk-team-mismatch",
		OrgID:     orgA.ID,
		TeamID:    teamB.ID,
		KeyPrefix: "sk-gw-mism",
		KeyHash:   auth.HashKey(rawMismatch),
		IsActive:  true,
	})
	if _, err := svc.AuthenticateVirtualKey(ctx, rawMismatch); err == nil {
		t.Fatal("expected team_org_mismatch to be rejected")
	}

	// MasterKeyDataPlane caches identity in L1
	svc.SetAllowMasterKeyDataPlane(true)
	id1, err := svc.AuthenticateVirtualKey(ctx, "sk-gw-master-admin-secret-key")
	if err != nil || id1.VirtualKeyID != "vk_master_admin" {
		t.Fatalf("expected master key data plane auth to succeed, got %v", err)
	}
	id2, err := svc.AuthenticateVirtualKey(ctx, "sk-gw-master-admin-secret-key")
	if err != nil || id2 != id1 {
		t.Fatalf("expected L1 cached master key identity pointer reuse")
	}
}

func TestInvalidateOrg_EvictsL1AndL2Epoch(t *testing.T) {
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer rf.Client().Close()

	ctx := t.Context()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{ID: "org-inv", Name: "Org Inv", Slug: "org-inv", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	svc1 := auth.NewService(repo, rf, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
	svc2 := auth.NewService(repo, rf, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)

	vk, err := svc1.IssueVirtualKey(ctx, &domain.VirtualKey{OrgID: org.ID, Name: "k1"})
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}
	if _, err := svc1.AuthenticateVirtualKey(ctx, vk.RawKey); err != nil {
		t.Fatalf("auth svc1: %v", err)
	}

	// Deactivate org in DB and invalidate via svc1
	org.IsActive = false
	_ = repo.CreateOrganization(ctx, org)
	svc1.InvalidateOrg(ctx, org.ID)

	// svc2 has empty L1, reads L2 Redis, sees bumped org epoch, falls back to DB and rejects!
	if _, err := svc2.AuthenticateVirtualKey(ctx, vk.RawKey); err == nil {
		t.Fatal("expected svc2 to reject key after InvalidateOrg bumped L2 epoch")
	}
}

type countingPolicyRepo struct {
	storage.Repository
	subCalls atomic.Int32
	polCalls atomic.Int32
}

func (r *countingPolicyRepo) GetOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error) {
	r.subCalls.Add(1)
	return r.Repository.GetOrgProviderSubscriptions(ctx, orgID)
}

func (r *countingPolicyRepo) GetOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error) {
	r.polCalls.Add(1)
	return r.Repository.GetOrgModelPolicies(ctx, orgID)
}

func TestRBACEngine_FailClosedAndCaching(t *testing.T) {
	ctx := t.Context()
	mem := storage.NewMemoryRepository()
	repo := &countingPolicyRepo{Repository: mem}
	rbac := auth.NewRBACEngine(repo)

	if err := rbac.AuthorizeEndpoint(&domain.IdentityContext{KeyPrefix: "k"}, "/v1/chat/completions"); err == nil {
		t.Fatal("expected AuthorizeEndpoint to fail closed when AllowedEndpoints is empty")
	}
	if err := rbac.AuthorizeRequestedModel(nil, "gpt-4.1"); err == nil {
		t.Fatal("expected AuthorizeRequestedModel to fail closed when idCtx is nil")
	}

	gm, _ := mem.GetGlobalModel(ctx, "openai/gpt-4.1")
	dep := &domain.Deployment{GlobalModel: gm}
	if err := rbac.AuthorizeDeployment(ctx, "org-cache", dep); err != nil {
		t.Fatalf("first AuthorizeDeployment: %v", err)
	}
	if err := rbac.AuthorizeDeployment(ctx, "org-cache", dep); err != nil {
		t.Fatalf("second AuthorizeDeployment: %v", err)
	}
	if repo.subCalls.Load() != 1 || repo.polCalls.Load() != 1 {
		t.Fatalf("expected 1 repo call each due to L1 cache, got subs=%d pols=%d", repo.subCalls.Load(), repo.polCalls.Load())
	}

	rbac.InvalidateOrgPolicies(ctx, "org-cache")
	if err := rbac.AuthorizeDeployment(ctx, "org-cache", dep); err != nil {
		t.Fatalf("third AuthorizeDeployment after invalidation: %v", err)
	}
	if repo.subCalls.Load() != 2 || repo.polCalls.Load() != 2 {
		t.Fatalf("expected 2 repo calls after InvalidateOrgPolicies, got subs=%d pols=%d", repo.subCalls.Load(), repo.polCalls.Load())
	}
}
