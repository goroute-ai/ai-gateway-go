package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestMasterKeyDataPlaneDisabledByDefault(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org_default",
		Name:     "Default Org",
		Slug:     "default",
		IsActive: true,
	}); err != nil {
		t.Fatalf("create org: %v", err)
	}

	svc := auth.NewService(repo, nil, "sk-gw-master-secret-key", time.Minute, time.Minute)

	// Default: allowMasterKeyDataPlane == false -> 401 invalid_api_key
	_, err := svc.AuthenticateVirtualKey(ctx, "sk-gw-master-secret-key")
	if err == nil {
		t.Fatalf("expected error when master key used on data plane by default")
	}
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "invalid_api_key" {
		t.Fatalf("expected 401 invalid_api_key, got %v", err)
	}

	// Explicitly enabled -> synthesizes vk_master_admin
	svc.SetAllowMasterKeyDataPlane(true)
	idCtx, err := svc.AuthenticateVirtualKey(ctx, "sk-gw-master-secret-key")
	if err != nil {
		t.Fatalf("expected master key to succeed when allowMasterKeyDataPlane=true: %v", err)
	}
	if idCtx.VirtualKeyID != "vk_master_admin" || idCtx.OrgID != "org_default" {
		t.Fatalf("unexpected identity context: %+v", idCtx)
	}
}

func TestJWTVerifier_HS256(t *testing.T) {
	ctx := context.Background()
	secret := "super-secret-hmac-key-for-testing"
	verifier := auth.NewJWTVerifier(auth.JWTConfig{
		Secret:   secret,
		Issuer:   "https://auth.example.com",
		Audience: "ai-gateway",
	})

	now := time.Now().UTC()
	tok, err := auth.SignHS256(secret, &auth.JWTClaims{
		Subject:   "oidc-sub-123",
		Issuer:    "https://auth.example.com",
		Audience:  auth.AudienceClaim{"ai-gateway"},
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
	})
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	claims, err := verifier.Verify(ctx, tok)
	if err != nil {
		t.Fatalf("verify valid hs256 jwt: %v", err)
	}
	if claims.Subject != "oidc-sub-123" {
		t.Fatalf("expected sub oidc-sub-123, got %q", claims.Subject)
	}

	// Expired token
	expiredTok, _ := auth.SignHS256(secret, &auth.JWTClaims{
		Subject:   "oidc-sub-123",
		Issuer:    "https://auth.example.com",
		Audience:  auth.AudienceClaim{"ai-gateway"},
		ExpiresAt: now.Add(-1 * time.Minute).Unix(),
	})
	if _, err := verifier.Verify(ctx, expiredTok); err == nil {
		t.Fatalf("expected expired jwt to fail")
	}

	// Wrong issuer
	wrongIssTok, _ := auth.SignHS256(secret, &auth.JWTClaims{
		Subject:   "oidc-sub-123",
		Issuer:    "https://evil.example.com",
		Audience:  auth.AudienceClaim{"ai-gateway"},
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if _, err := verifier.Verify(ctx, wrongIssTok); err == nil {
		t.Fatalf("expected wrong issuer jwt to fail")
	}

	// Wrong audience
	wrongAudTok, _ := auth.SignHS256(secret, &auth.JWTClaims{
		Subject:   "oidc-sub-123",
		Issuer:    "https://auth.example.com",
		Audience:  auth.AudienceClaim{"other-aud"},
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if _, err := verifier.Verify(ctx, wrongAudTok); err == nil {
		t.Fatalf("expected wrong audience jwt to fail")
	}

	// Wrong signature
	wrongSigTok, _ := auth.SignHS256("wrong-secret", &auth.JWTClaims{
		Subject:   "oidc-sub-123",
		Issuer:    "https://auth.example.com",
		Audience:  auth.AudienceClaim{"ai-gateway"},
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if _, err := verifier.Verify(ctx, wrongSigTok); err == nil {
		t.Fatalf("expected wrong signature jwt to fail")
	}
}

func TestJWTVerifier_OIDCJWKS_RS256AndES256(t *testing.T) {
	ctx := context.Background()

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "rsa-key-1",
					"use": "sig",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(rsaPriv.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.PublicKey.E)).Bytes()),
				},
				{
					"kty": "EC",
					"kid": "ec-key-1",
					"use": "sig",
					"alg": "ES256",
					"crv": "P-256",
					"x":   base64.RawURLEncoding.EncodeToString(ecPriv.PublicKey.X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(ecPriv.PublicKey.Y.Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer jwksSrv.Close()

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("new network policy: %v", err)
	}

	verifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:        "https://idp.example.com",
		Audience:      "gateway-admin",
		OIDCJWKSURL:   jwksSrv.URL,
		NetworkPolicy: netPolicy,
	})

	now := time.Now().UTC()
	claimsJSON, _ := json.Marshal(auth.JWTClaims{
		Subject:   "user-oidc-42",
		Issuer:    "https://idp.example.com",
		Audience:  auth.AudienceClaim{"gateway-admin"},
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})

	// Sign RS256 token
	rsaHdrJSON, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "rsa-key-1", "typ": "JWT"})
	rsaInput := base64.RawURLEncoding.EncodeToString(rsaHdrJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	rsaSum := sha256.Sum256([]byte(rsaInput))
	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaPriv, 0x05 /* crypto.SHA256 */, rsaSum[:])
	if err != nil {
		t.Fatalf("sign rs256: %v", err)
	}
	rsaTok := rsaInput + "." + base64.RawURLEncoding.EncodeToString(rsaSig)

	gotRSA, err := verifier.Verify(ctx, rsaTok)
	if err != nil {
		t.Fatalf("verify rs256 jwt: %v", err)
	}
	if gotRSA.Subject != "user-oidc-42" {
		t.Fatalf("expected user-oidc-42, got %q", gotRSA.Subject)
	}

	// Sign ES256 token (RFC 7515 raw r || s 64-byte signature)
	ecHdrJSON, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "ec-key-1", "typ": "JWT"})
	ecInput := base64.RawURLEncoding.EncodeToString(ecHdrJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	ecSum := sha256.Sum256([]byte(ecInput))
	rInt, sInt, err := ecdsa.Sign(rand.Reader, ecPriv, ecSum[:])
	if err != nil {
		t.Fatalf("sign es256: %v", err)
	}
	ecSig := make([]byte, 64)
	rBytes := rInt.Bytes()
	sBytes := sInt.Bytes()
	copy(ecSig[32-len(rBytes):32], rBytes)
	copy(ecSig[64-len(sBytes):64], sBytes)
	ecTok := ecInput + "." + base64.RawURLEncoding.EncodeToString(ecSig)

	gotEC, err := verifier.Verify(ctx, ecTok)
	if err != nil {
		t.Fatalf("verify es256 jwt: %v", err)
	}
	if gotEC.Subject != "user-oidc-42" {
		t.Fatalf("expected user-oidc-42, got %q", gotEC.Subject)
	}
}

func TestAuthenticateOperatorAndAuthorizeAdminAction(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true})
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true})

	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_org_admin_a",
		OrgID:       "org_a",
		Email:       "admin@orga.io",
		Name:        "Admin A",
		Role:        domain.RoleOrgAdmin,
		OIDCSubject: "sub-admin-a",
		IsActive:    true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_viewer_a",
		OrgID:       "org_a",
		Email:       "viewer@orga.io",
		Name:        "Viewer A",
		Role:        domain.RoleViewer,
		OIDCSubject: "sub-viewer-a",
		IsActive:    true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_dev_a",
		OrgID:       "org_a",
		Email:       "dev@orga.io",
		Name:        "Dev A",
		Role:        domain.RoleDeveloper,
		OIDCSubject: "sub-dev-a",
		IsActive:    true,
	})

	svc := auth.NewService(repo, nil, "sk-gw-master-admin-test", time.Minute, time.Minute)
	jwtSecret := "operator-jwt-secret-key"
	svc.SetJWTVerifier(auth.NewJWTVerifier(auth.JWTConfig{Secret: jwtSecret}))

	// 1. MasterAdminKey -> platform_admin
	opMaster, err := svc.AuthenticateOperator(ctx, "sk-gw-master-admin-test")
	if err != nil {
		t.Fatalf("master key operator auth failed: %v", err)
	}
	if opMaster.Role != domain.OperatorRolePlatformAdmin || opMaster.AuthMethod != "master_key" {
		t.Fatalf("unexpected master operator: %+v", opMaster)
	}
	if err := auth.AuthorizeAdminAction(opMaster, "org_b", true); err != nil {
		t.Fatalf("platform_admin should write to any org: %v", err)
	}
	if err := auth.AuthorizeAdminAction(opMaster, "", true); err != nil {
		t.Fatalf("platform_admin should write globally: %v", err)
	}

	// 2. Admin VirtualKey (org_admin) vs Developer VirtualKey (denied)
	adminVK, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a",
		Name:  "Org A Admin Key",
		Role:  domain.RoleOrgAdmin,
	})
	if err != nil {
		t.Fatalf("issue admin vk: %v", err)
	}
	opVK, err := svc.AuthenticateOperator(ctx, adminVK.RawKey)
	if err != nil {
		t.Fatalf("admin vk operator auth failed: %v", err)
	}
	if opVK.Role != domain.OperatorRoleOrgAdmin || opVK.OrgID != "org_a" || opVK.AuthMethod != "virtual_key" {
		t.Fatalf("unexpected vk operator: %+v", opVK)
	}
	if err := auth.AuthorizeAdminAction(opVK, "org_a", true); err != nil {
		t.Fatalf("org_admin should write in own org: %v", err)
	}
	if err := auth.AuthorizeAdminAction(opVK, "org_b", false); err == nil {
		t.Fatalf("org_admin should be denied cross-org read")
	}
	if err := auth.AuthorizeAdminAction(opVK, "", true); err == nil {
		t.Fatalf("org_admin should be denied global write")
	}

	devVK, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a",
		Name:  "Org A Dev Key",
		Role:  domain.RoleDeveloper,
	})
	if err != nil {
		t.Fatalf("issue dev vk: %v", err)
	}
	if _, err := svc.AuthenticateOperator(ctx, devVK.RawKey); err == nil {
		t.Fatalf("developer virtual key should be rejected on control plane")
	}

	// 3. Inbound JWT -> org_viewer
	viewerTok, _ := auth.SignHS256(jwtSecret, &auth.JWTClaims{
		Subject:   "sub-viewer-a",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	opViewer, err := svc.AuthenticateOperator(ctx, viewerTok)
	if err != nil {
		t.Fatalf("viewer jwt operator auth failed: %v", err)
	}
	if opViewer.ActorID != "usr_viewer_a" || opViewer.Role != domain.OperatorRoleOrgViewer || opViewer.OrgID != "org_a" || opViewer.AuthMethod != "jwt" {
		t.Fatalf("unexpected viewer operator: %+v", opViewer)
	}
	if err := auth.AuthorizeAdminAction(opViewer, "org_a", false); err != nil {
		t.Fatalf("org_viewer should read own org: %v", err)
	}
	if err := auth.AuthorizeAdminAction(opViewer, "org_a", true); err == nil {
		t.Fatalf("org_viewer should be denied write in own org")
	}
	if err := auth.AuthorizeAdminAction(opViewer, "org_b", false); err == nil {
		t.Fatalf("org_viewer should be denied cross-org read")
	}

	// Developer JWT should be rejected on control plane
	devTok, _ := auth.SignHS256(jwtSecret, &auth.JWTClaims{
		Subject:   "sub-dev-a",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	if _, err := svc.AuthenticateOperator(ctx, devTok); err == nil {
		t.Fatalf("developer jwt should be rejected on control plane")
	}
}
