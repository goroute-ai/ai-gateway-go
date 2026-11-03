package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestOIDC_DiscoveryEmptyIssuerRejectedAndRFC8414SuffixFallback(t *testing.T) {
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	client := network.NewHTTPClient(netPolicy)

	t.Run("empty issuer in discovery document is rejected per OIDC Discovery 1.0 §4.3", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   "",
				"jwks_uri": "https://example.com/jwks",
			})
		}))
		defer srv.Close()

		_, err := auth.FetchOIDCDiscoveryMetadata(context.Background(), client, srv.URL+"/.well-known/openid-configuration", srv.URL, false)
		if err == nil {
			t.Fatal("expected empty discovery issuer to fail validation")
		}
	})

	t.Run("RFC 8414 suffix fallback works when path-inserted returns 404", func(t *testing.T) {
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/tenant/alpha/.well-known/oauth-authorization-server" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer":                 srvURL + "/tenant/alpha",
					"authorization_endpoint": srvURL + "/tenant/alpha/auth",
					"token_endpoint":         srvURL + "/tenant/alpha/token",
					"jwks_uri":               srvURL + "/tenant/alpha/jwks",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		srvURL = srv.URL

		issuer := srv.URL + "/tenant/alpha"
		doc, err := auth.FetchOIDCDiscoveryMetadata(context.Background(), client, issuer+"/.well-known/openid-configuration", issuer, true)
		if err != nil {
			t.Fatalf("expected RFC 8414 suffix fallback to succeed, got: %v", err)
		}
		if doc.JWKSURI != issuer+"/jwks" {
			t.Fatalf("unexpected jwks_uri: %q", doc.JWKSURI)
		}
	})
}

func TestOIDC_RSAKeyMinimum2048BitsRejected(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(1024): %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "weak-1024",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(weakKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(weakKey.E)).Bytes()),
			}},
		})
	}))
	defer srv.Close()

	netPolicy, _ := network.NewPolicy(config.OutboundSSRFConfig{AllowLoopbackHTTP: true})
	v := auth.NewOIDCVerifier(auth.OIDCIssuerConfig{
		Issuer:        srv.URL,
		Audience:      "gw",
		JWKSURL:       srv.URL + "/jwks",
		NetworkPolicy: netPolicy,
	})
	tok := signRS256JWT(t, weakKey, "weak-1024", map[string]any{
		"iss": srv.URL,
		"sub": "alice",
		"aud": "gw",
		"exp": time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected 1024-bit RSA JWK to be rejected per RFC 7518 §3.3")
	}
}

func TestSSO_EdDSAATHash_StrictAZP_AndClientSecretBasic(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	accessToken := "eddsa-access-token-12345"
	sum512 := sha512.Sum512([]byte(accessToken))
	validEdDSAATHash := base64.RawURLEncoding.EncodeToString(sum512[:len(sum512)/2])

	var (
		idpURL       string
		claimsMode   string
		sawBasicAuth bool
	)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/ed/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                idpURL + "/realms/ed",
				"authorization_endpoint":                idpURL + "/realms/ed/auth",
				"token_endpoint":                        idpURL + "/realms/ed/token",
				"jwks_uri":                              idpURL + "/realms/ed/certs",
				"code_challenge_methods_supported":      []string{"S256"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
			})
		case "/realms/ed/certs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{{
					"kty": "OKP",
					"crv": "Ed25519",
					"kid": "ed-1",
					"use": "sig",
					"alg": "EdDSA",
					"x":   base64.RawURLEncoding.EncodeToString(edPub),
				}},
			})
		case "/realms/ed/token":
			u, p, ok := r.BasicAuth()
			sawBasicAuth = ok && u == "gw-ed" && p == "ed-secret"
			_ = r.ParseForm()
			now := time.Now().UTC()
			payload := map[string]any{
				"iss":            idpURL + "/realms/ed",
				"sub":            "ed-user-1",
				"aud":            "gw-ed",
				"nonce":          r.FormValue("code"),
				"email":          "ed@goroute.local",
				"email_verified": true,
				"at_hash":        validEdDSAATHash,
				"iat":            now.Unix(),
				"exp":            now.Add(5 * time.Minute).Unix(),
			}
			switch claimsMode {
			case "multi_aud_missing_azp":
				payload["aud"] = []string{"gw-ed", "other-app"}
			case "single_aud_wrong_azp":
				payload["aud"] = "gw-ed"
				payload["azp"] = "other-client"
			}
			idTok := signJWTWithHeader(t,
				map[string]string{"alg": "EdDSA", "kid": "ed-1", "typ": "JWT"},
				payload,
				func(in string) []byte { return ed25519.Sign(edPriv, []byte(in)) },
			)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_type":   "Bearer",
				"access_token": accessToken,
				"id_token":     idTok,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer idp.Close()
	idpURL = idp.URL

	netPolicy, _ := network.NewPolicy(config.OutboundSSRFConfig{AllowLoopbackHTTP: true})
	mgr, err := auth.NewSSOProviderManager([]auth.SSOProviderConfig{{
		ID:                  "ed-idp",
		Type:                "oidc",
		ClientID:            "gw-ed",
		ClientSecret:        "ed-secret",
		Issuer:              idp.URL + "/realms/ed",
		AllowedEmailDomains: []string{"goroute.local"},
	}}, netPolicy)
	if err != nil {
		t.Fatalf("NewSSOProviderManager: %v", err)
	}

	// 1. EdDSA at_hash + client_secret_basic succeeds
	claims, err := mgr.ExchangeAndVerify(context.Background(), "ed-idp", "nonce-1", "http://localhost:8080/cb", "verifier-1", "nonce-1")
	if err != nil {
		t.Fatalf("expected EdDSA at_hash + client_secret_basic to succeed, got: %v", err)
	}
	if !sawBasicAuth {
		t.Fatal("expected client_secret_basic Authorization header when IdP only advertises client_secret_basic")
	}
	if claims.Subject != "ed-user-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// 2. Multi-audience without azp must be rejected (OIDC Core §3.1.3.7)
	claimsMode = "multi_aud_missing_azp"
	if _, err := mgr.ExchangeAndVerify(context.Background(), "ed-idp", "nonce-2", "http://localhost:8080/cb", "verifier-2", "nonce-2"); err == nil {
		t.Fatal("expected multi-audience ID token without azp to fail")
	}

	// 3. Single-audience with mismatched azp must be rejected (OIDC Core §3.1.3.7)
	claimsMode = "single_aud_wrong_azp"
	if _, err := mgr.ExchangeAndVerify(context.Background(), "ed-idp", "nonce-3", "http://localhost:8080/cb", "verifier-3", "nonce-3"); err == nil {
		t.Fatal("expected single-audience ID token with wrong azp to fail")
	}
}

func TestSession_VaultEncryptedIDTokenHint_SCIMAndDeletedUserFailClosed(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_1", Name: "Org 1", Slug: "org-1", IsActive: true})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:         "u_admin",
		OrgID:      "org_1",
		Email:      "admin@org1.local",
		Name:       "Admin",
		Role:       domain.RoleOrgAdmin,
		IsActive:   true,
		SCIMActive: true,
	})

	vault, err := auth.NewVault("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff")
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	sm := auth.NewSessionManager(repo, nil, []byte("session-secret-key-0123456789abcdef"), time.Hour)
	sm.SetVault(vault)

	svc := auth.NewService(repo, nil, "master-key-0123456789", 15*time.Second, time.Minute)
	svc.SetSessionManager(sm)

	issued, err := sm.IssueSessionWithOIDC(ctx, "u_admin", "org_1", "", "keycloak", "eyJ.raw-id-token.sig", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSessionWithOIDC: %v", err)
	}

	// Verify id_token_hint is stored encrypted and decrypts properly
	storedSess, err := repo.GetOperatorSession(ctx, issued.Session.ID)
	if err != nil {
		t.Fatalf("GetOperatorSession: %v", err)
	}
	if storedSess.EncryptedIDToken == "" || strings.Contains(storedSess.EncryptedIDToken, "raw-id-token") {
		t.Fatalf("expected encrypted id_token at rest, got %q", storedSess.EncryptedIDToken)
	}
	if got := sm.DecryptIDTokenHint(storedSess); got != "eyJ.raw-id-token.sig" {
		t.Fatalf("DecryptIDTokenHint = %q, want raw id token", got)
	}

	// SCIM deprovisioning must immediately reject active operator sessions
	u, _ := repo.GetUser(ctx, "u_admin")
	u.SCIMActive = false
	_ = repo.UpdateUser(ctx, u)
	if _, err := svc.AuthenticateOperatorWithSource(ctx, auth.ExtractedCredentials{
		Token:  issued.Token,
		Source: auth.CredentialSourceCookie,
	}); err == nil {
		t.Fatal("expected SCIM-deprovisioned user session to be rejected")
	}

	// RevokeSession wipes encrypted id_token
	if err := sm.RevokeSession(ctx, issued.Session.ID, issued.ExpiresAt); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	revokedSess, err := repo.GetOperatorSession(ctx, issued.Session.ID)
	if err != nil || revokedSess == nil {
		t.Fatalf("GetOperatorSession after revoke: %v", err)
	}
	if revokedSess.EncryptedIDToken != "" || revokedSess.EncryptedIDTokenDEK != "" {
		t.Fatal("expected RevokeSession to wipe encrypted id_token fields")
	}

	// Deleted user must fail closed (never fall back to stale JWT claims)
	u.SCIMActive = true
	_ = repo.UpdateUser(ctx, u)
	issued2, err := sm.IssueSessionWithOIDC(ctx, "u_admin", "org_1", "", "keycloak", "eyJ.second.sig", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSessionWithOIDC #2: %v", err)
	}
	_ = repo.DeleteUser(ctx, "u_admin")
	if _, err := svc.AuthenticateOperatorWithSource(ctx, auth.ExtractedCredentials{
		Token:  issued2.Token,
		Source: auth.CredentialSourceCookie,
	}); err == nil {
		t.Fatal("expected deleted user session to fail closed")
	}
}

func TestIntrospector_IssuerAudienceValidation_AndBoundedL1Cache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tok := r.FormValue("token")
		w.Header().Set("Content-Type", "application/json")
		switch tok {
		case "wrong-iss":
			_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1", "iss": "https://other.idp", "aud": "gw"})
		case "wrong-aud":
			_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1", "iss": "https://expected.idp", "aud": "other-client"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "u-" + tok,
				"iss":    "https://expected.idp",
				"aud":    "gw",
				"exp":    time.Now().UTC().Add(5 * time.Minute).Unix(),
			})
		}
	}))
	defer srv.Close()

	netPolicy, _ := network.NewPolicy(config.OutboundSSRFConfig{AllowLoopbackHTTP: true})
	introspector := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
		TokenInfoEndpoint: srv.URL + "/introspect",
		Issuer:            "https://expected.idp",
		Audience:          "gw",
		Mode:              auth.IntrospectionModeIntrospect,
		MaxL1Entries:      8,
		NetworkPolicy:     netPolicy,
	})

	if _, err := introspector.Introspect(context.Background(), "wrong-iss"); err == nil {
		t.Fatal("expected mismatched issuer in introspection response to fail")
	}
	if _, err := introspector.Introspect(context.Background(), "wrong-aud"); err == nil {
		t.Fatal("expected mismatched audience in introspection response to fail")
	}
	for i := 0; i < 20; i++ {
		res, err := introspector.Introspect(context.Background(), fmt.Sprintf("tok-%d", i))
		if err != nil || !res.Active {
			t.Fatalf("expected valid introspection for tok-%d, got %v / %+v", i, err, res)
		}
	}
}
