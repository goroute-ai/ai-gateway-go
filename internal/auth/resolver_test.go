package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func signRS256JWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdrBytes, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	})
	if err != nil {
		t.Fatalf("marshal jwt header: %v", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal jwt payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign rs256: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func startOIDCTestProvider(t *testing.T, kid string, priv *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   srv.URL,
				"jwks_uri": srv.URL + "/jwks.json",
			})
		case "/jwks.json":
			pub := &priv.PublicKey
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"use": "sig",
						"alg": "RS256",
						"kid": kid,
						"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAuthResolver_FailClosedWhenDataPlaneJWTDisabled(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true})

	svc := auth.NewService(repo, nil, "sk-gw-master-admin-secret", time.Minute, time.Minute)
	vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		Name:  "dev-key",
		OrgID: "org_a",
		Role:  domain.RoleDeveloper,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	idp := newTestOIDCIssuer(t)
	verifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:        idp.Issuer(),
		Audience:      "ai-gateway",
		OIDCJWKSURL:   idp.JWKSURL(),
		AutoRegister:  true,
		DefaultOrgID:  "org_a",
		NetworkPolicy: idp.NetworkPolicy(),
	})

	resolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               repo,
		JWTVerifier:        verifier,
		EnableDataPlaneJWT: false,
		DefaultOrgID:       "org_a",
	})
	svc.SetDataPlaneResolver(resolver)

	jwtTok := idp.SignClaims(&auth.JWTClaims{
		Subject:   "user-sub-1",
		Issuer:    idp.Issuer(),
		Audience:  auth.AudienceClaim{"ai-gateway"},
		Email:     "alice@example.com",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+jwtTok)
	if _, err := resolver.ResolveRequest(ctx, req); err == nil {
		t.Fatal("expected JWT bearer token to be rejected when EnableDataPlaneJWT=false")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "invalid_api_key" {
			t.Fatalf("expected 401 invalid_api_key, got %v", err)
		}
	}

	// DataPlaneMiddleware must also fail closed when EnableDataPlaneJWT=false
	rbac := auth.NewRBACEngine(repo)
	mw := auth.DataPlaneMiddleware(svc, rbac)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected DataPlaneMiddleware 401 when EnableDataPlaneJWT=false, got %d", rec.Code)
	}

	// Virtual Key still succeeds and receives Principal
	vkReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	vkReq.Header.Set("Authorization", "Bearer "+vk.RawKey)
	idCtx, err := resolver.ResolveRequest(ctx, vkReq)
	if err != nil {
		t.Fatalf("expected virtual key to authenticate: %v", err)
	}
	if idCtx.VirtualKeyID != vk.ID || idCtx.Principal == nil || idCtx.Principal.AuthMethod != "virtual_key" {
		t.Fatalf("unexpected identity/principal for virtual key: %+v", idCtx)
	}
}

func TestAuthResolver_JWTKeyMappingAndEmailDomainDeny(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{
		ID:              "org_a",
		Name:            "Org A",
		Slug:            "org-a",
		MaxBudgetMicros: 50_000_000,
		RPMLimit:        500,
		IsActive:        true,
	})
	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:            "team_ml",
		OrgID:         "org_a",
		Name:          "ML Team",
		AllowedModels: []string{"openai/gpt-4.1"},
		RPMLimit:      120,
		IsActive:      true,
	})

	svc := auth.NewService(repo, nil, "sk-gw-master-admin-secret", time.Minute, time.Minute)
	mappedKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		Name:            "ml-mapped-key",
		OrgID:           "org_a",
		TeamID:          "team_ml",
		Role:            domain.RoleServiceAccount,
		AllowedModels:   []string{"openai/gpt-4.1"},
		MaxBudgetMicros: 10_000_000,
		RPMLimit:        60,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	oidcSrv := startOIDCTestProvider(t, "kid-1", rsaPriv)

	if err := repo.CreateJWTKeyMapping(ctx, &domain.JWTKeyMapping{
		OrgID:        "org_a",
		Issuer:       oidcSrv.URL,
		ClaimName:    "groups",
		ClaimValue:   "ml-platform",
		VirtualKeyID: mappedKey.ID,
	}); err != nil {
		t.Fatalf("CreateJWTKeyMapping: %v", err)
	}

	netPol, _ := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	verifier := auth.NewMultiIssuerJWTVerifier(auth.MultiIssuerConfig{
		NetworkPolicy: netPol,
		Issuers: []auth.OIDCIssuerConfig{
			{
				Issuer:              oidcSrv.URL,
				Audience:            "ai-gateway",
				AllowedEmailDomains: []string{"allowed.example"},
				AutoRegister:        true,
				DefaultOrgID:        "org_a",
			},
		},
	})

	resolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               repo,
		JWTVerifier:        verifier,
		EnableDataPlaneJWT: true,
		DefaultOrgID:       "org_a",
	})

	// 1. Mapped claim resolves to mapped VirtualKey with Principal attached
	mappedTok := signRS256JWT(t, rsaPriv, "kid-1", map[string]any{
		"iss":            oidcSrv.URL,
		"sub":            "oidc-alice",
		"aud":            "ai-gateway",
		"email":          "alice@allowed.example",
		"email_verified": true,
		"groups":         []string{"devs", "ml-platform"},
		"exp":            time.Now().UTC().Add(10 * time.Minute).Unix(),
	})

	for _, path := range []string{"/v1/chat/completions", "/mcp", "/a2a/v1/agents/coder/"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+mappedTok)
		idCtx, err := resolver.ResolveRequest(ctx, req)
		if err != nil {
			t.Fatalf("ResolveRequest(%s): %v", path, err)
		}
		if idCtx.VirtualKeyID != mappedKey.ID || idCtx.TeamID != "team_ml" || idCtx.KeyRPMLimit != 60 {
			t.Fatalf("expected mapped virtual key context on %s, got %+v", path, idCtx)
		}
		if idCtx.Principal == nil || idCtx.Principal.AuthMethod != "jwt" || idCtx.Principal.PrincipalType != "virtual_key" ||
			idCtx.Principal.Issuer != oidcSrv.URL || idCtx.Principal.Subject != "oidc-alice" || idCtx.Principal.Email != "alice@allowed.example" {
			t.Fatalf("unexpected principal: %+v", idCtx.Principal)
		}
	}

	// 2. Non-Bearer header (x-api-key) must NOT accept a JWT
	xAPIReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	xAPIReq.Header.Set("x-api-key", mappedTok)
	if _, err := resolver.ResolveRequest(ctx, xAPIReq); err == nil {
		t.Fatal("expected JWT in x-api-key header to be rejected")
	}

	// 3. Disallowed email domain is denied and must NOT trigger JIT provisioning
	deniedTok := signRS256JWT(t, rsaPriv, "kid-1", map[string]any{
		"iss":   oidcSrv.URL,
		"sub":   "oidc-mallory",
		"aud":   "ai-gateway",
		"email": "mallory@evil.example",
		"exp":   time.Now().UTC().Add(10 * time.Minute).Unix(),
	})
	deniedReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	deniedReq.Header.Set("Authorization", "Bearer "+deniedTok)
	if _, err := resolver.ResolveRequest(ctx, deniedReq); err == nil {
		t.Fatal("expected disallowed email domain to fail")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "invalid_token" {
			t.Fatalf("expected 401 invalid_token, got %v", err)
		}
	}
	if _, err := repo.GetUserByOrgAndOIDCSubject(ctx, "org_a", "oidc-mallory"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected denied email domain user not to be JIT provisioned, got err=%v", err)
	}
}

func TestAuthResolver_JITProvisioningAndConcurrentRaceRecovery(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{
		ID:                    "org_jit",
		Name:                  "JIT Org",
		Slug:                  "jit-org",
		MaxBudgetMicros:       100_000_000,
		RPMLimit:              1000,
		TPMLimit:              500_000,
		MaxConcurrentRequests: 50,
		IsActive:              true,
	})
	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:                    "team_eng",
		OrgID:                 "org_jit",
		Name:                  "Engineering",
		AllowedModels:         []string{"openai/gpt-4.1", "anthropic/claude-sonnet-4"},
		MaxBudgetMicros:       25_000_000,
		RPMLimit:              200,
		TPMLimit:              100_000,
		MaxConcurrentRequests: 10,
		IsActive:              true,
	})

	idp := newTestOIDCIssuer(t)
	verifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:        idp.Issuer(),
		Audience:      "ai-gateway",
		OIDCJWKSURL:   idp.JWKSURL(),
		AutoRegister:  true,
		DefaultOrgID:  "org_jit",
		DefaultTeamID: "team_eng",
		DefaultRole:   "developer",
		NetworkPolicy: idp.NetworkPolicy(),
	})
	svc := auth.NewService(repo, nil, "sk-gw-master-admin-secret", time.Minute, time.Minute)
	resolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               repo,
		JWTVerifier:        verifier,
		EnableDataPlaneJWT: true,
		DefaultOrgID:       "org_jit",
	})

	tok := idp.SignClaims(&auth.JWTClaims{
		Subject:   "race-sub-42",
		Issuer:    idp.Issuer(),
		Audience:  auth.AudienceClaim{"ai-gateway"},
		Email:     "racer@jit.example",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})

	const workers = 24
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	ids := make(chan string, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			idCtx, resolveErr := resolver.ResolveRequest(ctx, req)
			if resolveErr != nil {
				errs <- resolveErr
				return
			}
			if idCtx.OrgID != "org_jit" || idCtx.TeamID != "team_eng" || idCtx.TeamRPMLimit != 200 || idCtx.OrgMaxBudgetMicros != 100_000_000 {
				errs <- fmt.Errorf("unexpected frozen IdentityContext: %+v", idCtx)
				return
			}
			if len(idCtx.TeamAllowedModels) != 2 || idCtx.Principal == nil || idCtx.Principal.AuthMethod != "jwt" || idCtx.Principal.PrincipalType != "user" {
				errs <- fmt.Errorf("missing team models or principal: %+v", idCtx)
				return
			}
			ids <- idCtx.UserID
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)

	for e := range errs {
		t.Fatalf("concurrent JIT ResolveRequest failed: %v", e)
	}

	users, err := repo.ListUsers(ctx, "org_jit")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected exactly 1 JIT user created under concurrency, got %d", len(users))
	}
	expectedUserID := users[0].ID
	for gotID := range ids {
		if gotID != expectedUserID {
			t.Fatalf("expected all concurrent requests to resolve user %q, got %q", expectedUserID, gotID)
		}
	}

	// Verify AutoRegister=false rejects unknown user
	noJITVerifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:        idp.Issuer(),
		Audience:      "ai-gateway",
		OIDCJWKSURL:   idp.JWKSURL(),
		AutoRegister:  false,
		DefaultOrgID:  "org_jit",
		NetworkPolicy: idp.NetworkPolicy(),
	})
	noJITResolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               repo,
		JWTVerifier:        noJITVerifier,
		EnableDataPlaneJWT: true,
		DefaultOrgID:       "org_jit",
	})
	unknownTok := idp.SignClaims(&auth.JWTClaims{
		Subject:   "unknown-sub-99",
		Issuer:    idp.Issuer(),
		Audience:  auth.AudienceClaim{"ai-gateway"},
		Email:     "unknown@jit.example",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+unknownTok)
	if _, err := noJITResolver.ResolveRequest(ctx, req); err == nil {
		t.Fatal("expected unknown user to fail when AutoRegister=false")
	}
}

func TestAuthResolver_OpaqueIntrospectionViaOIDCDiscovery(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{
		ID:              "org_ent",
		Name:            "Enterprise Org",
		Slug:            "ent-org",
		MaxBudgetMicros: 80_000_000,
		RPMLimit:        300,
		IsActive:        true,
	})
	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:            "team_core",
		OrgID:         "org_ent",
		Name:          "Core",
		AllowedModels: []string{"openai/gpt-4.1-mini"},
		RPMLimit:      90,
		IsActive:      true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:              "usr_bob",
		OrgID:           "org_ent",
		TeamID:          "team_core",
		Email:           "bob@ent.example",
		Name:            "Bob",
		Role:            domain.RoleDeveloper,
		OIDCSubject:     "sub-bob",
		MaxBudgetMicros: 5_000_000,
		RPMLimit:        40,
		IsActive:        true,
	})

	var introspectCalls atomic.Int32
	var introspectSrvURL string
	introspectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 introspectSrvURL,
				"jwks_uri":               introspectSrvURL + "/certs",
				"authorization_endpoint": introspectSrvURL + "/auth",
				"token_endpoint":         introspectSrvURL + "/token",
				"introspection_endpoint": introspectSrvURL + "/introspect",
			})
			return
		}
		introspectCalls.Add(1)
		_ = r.ParseForm()
		tok := r.FormValue("token")
		if tok == "opaque-valid-bob" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "sub-bob",
				"email":  "bob@ent.example",
				"org_id": "org_ent",
				"iss":    introspectSrvURL,
				"exp":    time.Now().UTC().Add(5 * time.Minute).Unix(),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
	}))
	defer introspectSrv.Close()
	introspectSrvURL = introspectSrv.URL

	netPol, _ := network.NewPolicy(config.OutboundSSRFConfig{
		AllowLoopbackHTTP: true,
	})
	introspector := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
		Issuer:        introspectSrv.URL,
		ClientID:      "gw-client",
		ClientSecret:  "gw-secret",
		Mode:          auth.IntrospectionModeIntrospect,
		NetworkPolicy: netPol,
	})

	svc := auth.NewService(repo, nil, "sk-gw-master-admin-secret", time.Minute, time.Minute)
	resolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               repo,
		Introspector:       introspector,
		EnableDataPlaneJWT: false,
		DefaultOrgID:       "org_ent",
	})
	svc.SetDataPlaneResolver(resolver)

	// 1. Opaque Bearer token introspection resolved via OIDC Discovery
	opaqueReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	opaqueReq.Header.Set("Authorization", "Bearer opaque-valid-bob")
	idCtx, err := resolver.ResolveRequest(ctx, opaqueReq)
	if err != nil {
		t.Fatalf("opaque introspection ResolveRequest: %v", err)
	}
	if idCtx.UserID != "usr_bob" || idCtx.TeamID != "team_core" || idCtx.UserRPMLimit != 40 || idCtx.TeamRPMLimit != 90 {
		t.Fatalf("unexpected opaque introspected IdentityContext: %+v", idCtx)
	}
	if idCtx.Principal == nil || idCtx.Principal.AuthMethod != "introspection" || idCtx.Principal.Subject != "sub-bob" {
		t.Fatalf("unexpected introspection principal: %+v", idCtx.Principal)
	}

	// Inactive opaque token rejected
	badOpaqueReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	badOpaqueReq.Header.Set("Authorization", "Bearer opaque-revoked")
	if _, err := resolver.ResolveRequest(ctx, badOpaqueReq); err == nil {
		t.Fatal("expected inactive opaque token to fail")
	}
}

type simulatedConflictRaceRepo struct {
	*storage.MemoryRepository
	preCreated *domain.User
	raced      atomic.Bool
}

func (r *simulatedConflictRaceRepo) GetUserByOIDCIdentity(ctx context.Context, orgID, issuer, subject string) (*domain.User, error) {
	if !r.raced.Load() {
		return nil, storage.ErrNotFound
	}
	return r.MemoryRepository.GetUserByOIDCIdentity(ctx, orgID, issuer, subject)
}

func (r *simulatedConflictRaceRepo) GetUserByOrgAndOIDCSubject(ctx context.Context, orgID, subject string) (*domain.User, error) {
	// Simulate initial read miss before another replica inserts concurrently.
	if !r.raced.Load() {
		return nil, storage.ErrNotFound
	}
	return r.MemoryRepository.GetUserByOrgAndOIDCSubject(ctx, orgID, subject)
}

func (r *simulatedConflictRaceRepo) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	if !r.raced.Load() {
		return nil, storage.ErrNotFound
	}
	return r.MemoryRepository.GetUserByEmail(ctx, email)
}

func (r *simulatedConflictRaceRepo) GetOrCreateUserByOIDCSubject(ctx context.Context, user *domain.User) (*domain.User, bool, error) {
	if r.raced.CompareAndSwap(false, true) {
		// Simulate another pod inserting first, causing ON CONFLICT DO NOTHING -> re-read.
		_, _, _ = r.MemoryRepository.GetOrCreateUserByOIDCSubject(ctx, r.preCreated)
	}
	return r.MemoryRepository.GetOrCreateUserByOIDCSubject(ctx, user)
}

func TestAuthResolver_JITSimulatedDBConflictReReadRecovery(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryRepository()
	_ = mem.CreateOrganization(ctx, &domain.Organization{ID: "org_r", Name: "Org R", Slug: "org-r", IsActive: true})

	idp := newTestOIDCIssuer(t)
	raceRepo := &simulatedConflictRaceRepo{
		MemoryRepository: mem,
		preCreated: &domain.User{
			ID:                "usr_winner",
			OrgID:             "org_r",
			Email:             "winner@org-r.example",
			Name:              "Winner",
			Role:              domain.RoleDeveloper,
			OIDCIssuer:        idp.Issuer(),
			OIDCSubject:       "sub-race-winner",
			MaxBudgetMicros:   123456,
			BudgetResetPeriod: domain.BudgetResetMonthly,
			IsActive:          true,
		},
	}

	verifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:        idp.Issuer(),
		Audience:      "ai-gateway",
		OIDCJWKSURL:   idp.JWKSURL(),
		AutoRegister:  true,
		DefaultOrgID:  "org_r",
		NetworkPolicy: idp.NetworkPolicy(),
	})
	svc := auth.NewService(raceRepo, nil, "sk-gw-master-admin-secret", time.Minute, time.Minute)
	resolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               raceRepo,
		JWTVerifier:        verifier,
		EnableDataPlaneJWT: true,
		DefaultOrgID:       "org_r",
	})

	tok := idp.SignClaims(&auth.JWTClaims{
		Subject:   "sub-race-winner",
		Issuer:    idp.Issuer(),
		Audience:  auth.AudienceClaim{"ai-gateway"},
		Email:     "winner@org-r.example",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	idCtx, err := resolver.ResolveRequest(ctx, req)
	if err != nil {
		t.Fatalf("expected JIT conflict recovery to succeed, got %v", err)
	}
	if idCtx.UserID != "usr_winner" || idCtx.UserMaxBudgetMicros != 123456 {
		t.Fatalf("expected re-read winner user usr_winner with budget 123456, got %+v", idCtx)
	}
}

func TestAuthResolver_OIDCIssuerIsolationLegacyAndNoEmailLink(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryRepository()
	_ = mem.CreateOrganization(ctx, &domain.Organization{ID: "org_m", Name: "Org M", Slug: "org-m", IsActive: true})

	idpA := newTestOIDCIssuer(t)
	idpB := newTestOIDCIssuer(t)

	_ = mem.CreateUser(ctx, &domain.User{
		ID:          "usr_a",
		OrgID:       "org_m",
		Email:       "user-a@org-m.example",
		Name:        "User A",
		Role:        domain.RoleDeveloper,
		OIDCIssuer:  idpA.Issuer(),
		OIDCSubject: "same-sub",
		IsActive:    true,
	})
	_ = mem.CreateUser(ctx, &domain.User{
		ID:          "usr_b",
		OrgID:       "org_m",
		Email:       "user-b@org-m.example",
		Name:        "User B",
		Role:        domain.RoleDeveloper,
		OIDCIssuer:  idpB.Issuer(),
		OIDCSubject: "same-sub",
		IsActive:    true,
	})
	_ = mem.CreateUser(ctx, &domain.User{
		ID:       "usr_email",
		OrgID:    "org_m",
		Email:    "emailonly@org-m.example",
		Name:     "Email Only",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	})
	_ = mem.CreateUser(ctx, &domain.User{
		ID:          "usr_legacy",
		OrgID:       "org_m",
		Email:       "legacy@org-m.example",
		Name:        "Legacy Unbound",
		Role:        domain.RoleDeveloper,
		OIDCSubject: "legacy-sub",
		IsActive:    true,
	})

	multiVerifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuers: []auth.OIDCIssuerConfig{
			{
				Issuer:        idpA.Issuer(),
				Audience:      "ai-gateway",
				JWKSURL:       idpA.JWKSURL(),
				AutoRegister:  false,
				DefaultOrgID:  "org_m",
				NetworkPolicy: idpA.NetworkPolicy(),
			},
			{
				Issuer:        idpB.Issuer(),
				Audience:      "ai-gateway",
				JWKSURL:       idpB.JWKSURL(),
				AutoRegister:  false,
				DefaultOrgID:  "org_m",
				NetworkPolicy: idpB.NetworkPolicy(),
			},
		},
	})
	svc := auth.NewService(mem, nil, "sk-gw-master-admin-secret", time.Minute, time.Minute)
	multiResolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               mem,
		JWTVerifier:        multiVerifier,
		EnableDataPlaneJWT: true,
		DefaultOrgID:       "org_m",
	})

	tokA := idpA.SignClaims(&auth.JWTClaims{
		Subject:   "same-sub",
		Issuer:    idpA.Issuer(),
		Audience:  auth.AudienceClaim{"ai-gateway"},
		Email:     "user-a@org-m.example",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	reqA := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	reqA.Header.Set("Authorization", "Bearer "+tokA)
	ctxA, err := multiResolver.ResolveRequest(ctx, reqA)
	if err != nil || ctxA.UserID != "usr_a" {
		t.Fatalf("expected usr_a from issuer A, got %+v err=%v", ctxA, err)
	}

	tokB := idpB.SignClaims(&auth.JWTClaims{
		Subject:   "same-sub",
		Issuer:    idpB.Issuer(),
		Audience:  auth.AudienceClaim{"ai-gateway"},
		Email:     "user-b@org-m.example",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	reqB := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	reqB.Header.Set("Authorization", "Bearer "+tokB)
	ctxB, err := multiResolver.ResolveRequest(ctx, reqB)
	if err != nil || ctxB.UserID != "usr_b" {
		t.Fatalf("expected usr_b from issuer B, got %+v err=%v", ctxB, err)
	}

	// Email match alone must not auto-link.
	tokEmail := idpA.SignClaims(&auth.JWTClaims{
		Subject:   "unlinked-sub",
		Issuer:    idpA.Issuer(),
		Audience:  auth.AudienceClaim{"ai-gateway"},
		Email:     "emailonly@org-m.example",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	reqEmail := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	reqEmail.Header.Set("Authorization", "Bearer "+tokEmail)
	if _, err := multiResolver.ResolveRequest(ctx, reqEmail); err == nil {
		t.Fatal("expected rejection when email matches unbound user without (issuer, sub)")
	}

	// Multi-issuer refuses unbound legacy subject.
	tokLegacy := idpA.SignClaims(&auth.JWTClaims{
		Subject:   "legacy-sub",
		Issuer:    idpA.Issuer(),
		Audience:  auth.AudienceClaim{"ai-gateway"},
		Email:     "legacy@org-m.example",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	reqLegacy := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	reqLegacy.Header.Set("Authorization", "Bearer "+tokLegacy)
	if _, err := multiResolver.ResolveRequest(ctx, reqLegacy); err == nil {
		t.Fatal("expected multi-issuer resolver to refuse unbound legacy subject")
	}

	// Single-issuer resolver allows unambiguous legacy subject.
	singleVerifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:        idpA.Issuer(),
		Audience:      "ai-gateway",
		OIDCJWKSURL:   idpA.JWKSURL(),
		AutoRegister:  false,
		DefaultOrgID:  "org_m",
		NetworkPolicy: idpA.NetworkPolicy(),
	})
	singleResolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               mem,
		JWTVerifier:        singleVerifier,
		EnableDataPlaneJWT: true,
		DefaultOrgID:       "org_m",
	})
	ctxSingleLegacy, err := singleResolver.ResolveRequest(ctx, reqLegacy)
	if err != nil || ctxSingleLegacy.UserID != "usr_legacy" {
		t.Fatalf("expected unambiguous single-issuer resolver to accept usr_legacy, got %+v err=%v", ctxSingleLegacy, err)
	}
}
