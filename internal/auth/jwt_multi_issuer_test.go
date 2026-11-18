package auth_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func signJWTWithHeader(t *testing.T, hdr map[string]string, claims map[string]any, signer func(signingInput string) []byte) string {
	t.Helper()
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := signer(signingInput)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func rsaJWK(kid, alg string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": alg,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(kid, alg, crv string, pub *ecdsa.PublicKey, coordSize int) map[string]any {
	xBytes := make([]byte, coordSize)
	yBytes := make([]byte, coordSize)
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	copy(xBytes[coordSize-len(xb):], xb)
	copy(yBytes[coordSize-len(yb):], yb)
	return map[string]any{
		"kty": "EC",
		"kid": kid,
		"use": "sig",
		"alg": alg,
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

func ed25519JWK(kid string, pub ed25519.PublicKey) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"kid": kid,
		"use": "sig",
		"alg": "EdDSA",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

func signECDSARaw(t *testing.T, priv *ecdsa.PrivateKey, digest []byte, coordSize int) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("sign ecdsa: %v", err)
	}
	sig := make([]byte, coordSize*2)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig[coordSize-len(rb):coordSize], rb)
	copy(sig[coordSize*2-len(sb):coordSize*2], sb)
	return sig
}

func allowLocalNetworkPolicy(t *testing.T) *network.Policy {
	t.Helper()
	p, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("new network policy: %v", err)
	}
	return p
}

func TestJWTVerifier_MultiIssuerRoutingAndDiscovery(t *testing.T) {
	ctx := context.Background()
	netPolicy := allowLocalNetworkPolicy(t)

	rsaPrivA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key A: %v", err)
	}
	_, edPrivB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key B: %v", err)
	}
	edPubB := edPrivB.Public().(ed25519.PublicKey)

	var srvAURL string
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   srvAURL,
				"jwks_uri": srvAURL + "/keys",
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{rsaJWK("kid-a", "RS256", &rsaPrivA.PublicKey)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srvA.Close()
	srvAURL = srvA.URL

	var srvBURL string
	var discBCalls atomic.Int32
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/custom-oidc/discovery":
			discBCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   "https://idp-b.example.com",
				"jwks_uri": srvBURL + "/jwks.json",
			})
		case "/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{ed25519JWK("kid-b", edPubB)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srvB.Close()
	srvBURL = srvB.URL

	// Also verify network.Policy SSRF enforcement blocks private loopback when AllowPrivateNetworks=false.
	strictPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
	})
	if err != nil {
		t.Fatalf("new strict policy: %v", err)
	}
	blockedVerifier := auth.NewMultiIssuerJWTVerifier(auth.MultiIssuerConfig{
		Issuers: []auth.OIDCIssuerConfig{
			{
				Issuer:         srvAURL,
				Audience:       "gw-a",
				NetworkPolicy:  strictPolicy,
				RetryBaseDelay: time.Millisecond,
			},
		},
	})
	exp := time.Now().UTC().Add(5 * time.Minute).Unix()
	tokA := signJWTWithHeader(t,
		map[string]string{"alg": "RS256", "kid": "kid-a", "typ": "JWT"},
		map[string]any{"sub": "alice", "iss": srvAURL, "aud": "gw-a", "exp": exp},
		func(in string) []byte {
			sum := sha256.Sum256([]byte(in))
			sig, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivA, crypto.SHA256, sum[:])
			if err != nil {
				t.Fatalf("sign rs256: %v", err)
			}
			return sig
		},
	)
	if _, err := blockedVerifier.Verify(ctx, tokA); err == nil {
		t.Fatal("expected strict network.Policy to block loopback discovery/JWKS fetch")
	}

	// Build multi-issuer verifier using network.NewHTTPClient(netPolicy) (HTTPClient nil).
	verifier := auth.NewMultiIssuerJWTVerifier(auth.MultiIssuerConfig{
		NetworkPolicy: netPolicy,
		Issuers: []auth.OIDCIssuerConfig{
			{
				// Auto-derives <srvAURL>/.well-known/openid-configuration
				Issuer:   srvAURL,
				Audience: "gw-a",
			},
			{
				Issuer:       "https://idp-b.example.com",
				Audience:     "gw-b",
				DiscoveryURL: srvBURL + "/custom-oidc/discovery",
			},
		},
	})
	if !verifier.Enabled() {
		t.Fatal("expected multi-issuer verifier to be enabled")
	}

	claimsA, err := verifier.Verify(ctx, tokA)
	if err != nil {
		t.Fatalf("verify token A via auto-derived discovery: %v", err)
	}
	if claimsA.Subject != "alice" || claimsA.Issuer != srvAURL {
		t.Fatalf("unexpected claims A: %+v", claimsA)
	}

	tokB := signJWTWithHeader(t,
		map[string]string{"alg": "EdDSA", "kid": "kid-b", "typ": "JWT"},
		map[string]any{"sub": "bob", "iss": "https://idp-b.example.com", "aud": "gw-b", "exp": exp},
		func(in string) []byte {
			return ed25519.Sign(edPrivB, []byte(in))
		},
	)
	claimsB, err := verifier.Verify(ctx, tokB)
	if err != nil {
		t.Fatalf("verify token B via explicit discovery_url: %v", err)
	}
	if claimsB.Subject != "bob" || claimsB.Issuer != "https://idp-b.example.com" {
		t.Fatalf("unexpected claims B: %+v", claimsB)
	}
	if discBCalls.Load() != 1 {
		t.Fatalf("expected 1 discovery call for issuer B, got %d", discBCalls.Load())
	}

	// Cross-issuer forgery attempt (claiming issuer B while signed with issuer A's key) must fail.
	forged := signJWTWithHeader(t,
		map[string]string{"alg": "RS256", "kid": "kid-a", "typ": "JWT"},
		map[string]any{"sub": "eve", "iss": "https://idp-b.example.com", "aud": "gw-b", "exp": exp},
		func(in string) []byte {
			sum := sha256.Sum256([]byte(in))
			sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaPrivA, crypto.SHA256, sum[:])
			return sig
		},
	)
	if _, err := verifier.Verify(ctx, forged); err == nil {
		t.Fatal("expected cross-issuer token to fail")
	}

	// Unknown issuer must fail.
	unknownIss := signJWTWithHeader(t,
		map[string]string{"alg": "RS256", "kid": "kid-a", "typ": "JWT"},
		map[string]any{"sub": "eve", "iss": "https://unknown.example.com", "aud": "gw-a", "exp": exp},
		func(in string) []byte {
			sum := sha256.Sum256([]byte(in))
			sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaPrivA, crypto.SHA256, sum[:])
			return sig
		},
	)
	if _, err := verifier.Verify(ctx, unknownIss); err == nil {
		t.Fatal("expected unknown issuer to fail")
	}
}

func TestJWTVerifier_ExpandedAlgorithmsAndSecurityGuards(t *testing.T) {
	ctx := context.Background()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	ec256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p256 key: %v", err)
	}
	ec384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384 key: %v", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	edPub := edPriv.Public().(ed25519.PublicKey)

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				rsaJWK("k-rs256", "RS256", &rsaPriv.PublicKey),
				rsaJWK("k-rs384", "RS384", &rsaPriv.PublicKey),
				rsaJWK("k-rs512", "RS512", &rsaPriv.PublicKey),
				rsaJWK("k-ps256", "PS256", &rsaPriv.PublicKey),
				ecJWK("k-es256", "ES256", "P-256", &ec256Priv.PublicKey, 32),
				ecJWK("k-es384", "ES384", "P-384", &ec384Priv.PublicKey, 48),
				ed25519JWK("k-eddsa", edPub),
			},
		})
	}))
	defer jwksSrv.Close()

	verifier := auth.NewMultiIssuerJWTVerifier(auth.MultiIssuerConfig{
		Issuers: []auth.OIDCIssuerConfig{
			{
				Issuer:     "https://idp.example.com",
				Audience:   "gateway",
				JWKSURL:    jwksSrv.URL,
				HTTPClient: jwksSrv.Client(),
			},
		},
	})

	exp := time.Now().UTC().Add(5 * time.Minute).Unix()
	baseClaims := map[string]any{
		"sub": "user-alg-test",
		"iss": "https://idp.example.com",
		"aud": "gateway",
		"exp": exp,
	}

	cases := []struct {
		name string
		alg  string
		kid  string
		sign func(string) []byte
	}{
		{
			name: "RS256",
			alg:  "RS256",
			kid:  "k-rs256",
			sign: func(in string) []byte {
				d := sha256.Sum256([]byte(in))
				sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, d[:])
				return sig
			},
		},
		{
			name: "RS384",
			alg:  "RS384",
			kid:  "k-rs384",
			sign: func(in string) []byte {
				d := sha512.Sum384([]byte(in))
				sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA384, d[:])
				return sig
			},
		},
		{
			name: "RS512",
			alg:  "RS512",
			kid:  "k-rs512",
			sign: func(in string) []byte {
				d := sha512.Sum512([]byte(in))
				sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA512, d[:])
				return sig
			},
		},
		{
			name: "PS256",
			alg:  "PS256",
			kid:  "k-ps256",
			sign: func(in string) []byte {
				d := sha256.Sum256([]byte(in))
				sig, _ := rsa.SignPSS(rand.Reader, rsaPriv, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
				return sig
			},
		},
		{
			name: "ES256",
			alg:  "ES256",
			kid:  "k-es256",
			sign: func(in string) []byte {
				d := sha256.Sum256([]byte(in))
				return signECDSARaw(t, ec256Priv, d[:], 32)
			},
		},
		{
			name: "ES384",
			alg:  "ES384",
			kid:  "k-es384",
			sign: func(in string) []byte {
				d := sha512.Sum384([]byte(in))
				return signECDSARaw(t, ec384Priv, d[:], 48)
			},
		},
		{
			name: "EdDSA",
			alg:  "EdDSA",
			kid:  "k-eddsa",
			sign: func(in string) []byte {
				return ed25519.Sign(edPriv, []byte(in))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := signJWTWithHeader(t, map[string]string{
				"alg": tc.alg,
				"kid": tc.kid,
				"typ": "JWT",
			}, baseClaims, tc.sign)
			got, err := verifier.Verify(ctx, tok)
			if err != nil {
				t.Fatalf("verify %s failed: %v", tc.name, err)
			}
			if got.Subject != "user-alg-test" {
				t.Fatalf("unexpected sub %q", got.Subject)
			}
		})
	}

	// Reject alg: "none"
	algNoneTok := signJWTWithHeader(t, map[string]string{"alg": "none", "typ": "JWT"}, baseClaims, func(string) []byte {
		return nil
	})
	if _, err := verifier.Verify(ctx, algNoneTok); err == nil {
		t.Fatal("expected alg: none to be rejected")
	}

	// Reject typ: "oauth-id-jag+jwt" even with a valid cryptographic signature
	jagTok := signJWTWithHeader(t, map[string]string{
		"alg": "EdDSA",
		"kid": "k-eddsa",
		"typ": "oauth-id-jag+jwt",
	}, baseClaims, func(in string) []byte {
		return ed25519.Sign(edPriv, []byte(in))
	})
	if _, err := verifier.Verify(ctx, jagTok); err == nil {
		t.Fatal("expected typ: oauth-id-jag+jwt to be rejected as direct bearer token")
	}

	// Verify AuthenticateOperator rejects oauth-id-jag+jwt with HTTP 401
	repo := storage.NewMemoryRepository()
	svc := auth.NewService(repo, nil, "sk-gw-master-secret", time.Minute, time.Minute)
	svc.SetJWTVerifier(verifier)
	_, opErr := svc.AuthenticateOperator(ctx, jagTok)
	var gwErr *domain.GatewayError
	if !errors.As(opErr, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 GatewayError for oauth-id-jag+jwt, got %v", opErr)
	}

	// Verify per-issuer Algorithms allowlist rejects disallowed algorithm
	restrictedVerifier := auth.NewMultiIssuerJWTVerifier(auth.MultiIssuerConfig{
		Issuers: []auth.OIDCIssuerConfig{
			{
				Issuer:     "https://idp.example.com",
				Audience:   "gateway",
				JWKSURL:    jwksSrv.URL,
				Algorithms: []string{"EdDSA"},
				HTTPClient: jwksSrv.Client(),
			},
		},
	})
	rs256Tok := signJWTWithHeader(t, map[string]string{"alg": "RS256", "kid": "k-rs256", "typ": "JWT"}, baseClaims, func(in string) []byte {
		d := sha256.Sum256([]byte(in))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, d[:])
		return sig
	})
	if _, err := restrictedVerifier.Verify(ctx, rs256Tok); err == nil {
		t.Fatal("expected RS256 to be rejected when issuer allowlist is [EdDSA]")
	}
}

func TestJWTVerifier_RetryBackoffCooldownAndStaleJWKSFallback(t *testing.T) {
	ctx := context.Background()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	edPub := edPriv.Public().(ed25519.PublicKey)

	var (
		mu        sync.Mutex
		now       = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
		failNext  int32
		always500 atomic.Bool
		attempts  atomic.Int32
	)
	nowFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if always500.Load() || (failNext > 0 && n <= failNext) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{ed25519JWK("k1", edPub)},
		})
	}))
	defer jwksSrv.Close()

	// 1. Transient failure recovers on 3rd attempt (retry/backoff = 3 attempts).
	failNext = 2
	vRetry := auth.NewMultiIssuerJWTVerifier(auth.MultiIssuerConfig{
		Now:                 nowFn,
		RetryBaseDelay:      time.Millisecond,
		CacheTTL:            5 * time.Minute,
		StaleCacheTTL:       24 * time.Hour,
		UnreachableCooldown: 30 * time.Second,
		Issuers: []auth.OIDCIssuerConfig{
			{
				Issuer:     "https://idp.example.com",
				Audience:   "gateway",
				JWKSURL:    jwksSrv.URL,
				HTTPClient: jwksSrv.Client(),
			},
		},
	})

	signTok := func(kid string) string {
		return signJWTWithHeader(t,
			map[string]string{"alg": "EdDSA", "kid": kid, "typ": "JWT"},
			map[string]any{
				"sub": "user-1",
				"iss": "https://idp.example.com",
				"aud": "gateway",
				"exp": nowFn().Add(48 * time.Hour).Unix(),
			},
			func(in string) []byte { return ed25519.Sign(edPriv, []byte(in)) },
		)
	}

	if _, err := vRetry.Verify(ctx, signTok("k1")); err != nil {
		t.Fatalf("expected Verify to succeed on 3rd retry attempt, got: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected 3 JWKS fetch attempts for 2 transient 503s, got %d", got)
	}

	// 2. Stale-JWKS grace cache: advance past cacheTTL (6m) while JWKS is down (500/503).
	always500.Store(true)
	attempts.Store(0)
	advance(6 * time.Minute)

	// Matching kid ("k1") must succeed via stale-JWKS grace cache after 3 retry attempts.
	if _, err := vRetry.Verify(ctx, signTok("k1")); err != nil {
		t.Fatalf("expected Verify to fall back to stale-JWKS grace cache, got: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected 3 refresh attempts before falling back to stale cache, got %d", got)
	}

	// Subsequent call within 30s unreachable cooldown must NOT hit JWKS server and still serve "k1" from stale cache.
	advance(10 * time.Second)
	if _, err := vRetry.Verify(ctx, signTok("k1")); err != nil {
		t.Fatalf("expected stale cache hit during 30s cooldown, got: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected 0 extra fetches during 30s cooldown, got total %d", got)
	}

	// Unknown kid during outage must still be rejected.
	if _, err := vRetry.Verify(ctx, signTok("unknown-kid")); err == nil {
		t.Fatal("expected unknown kid to fail even when stale cache is active")
	}

	// 3. Past staleCacheTTL (24h), stale-JWKS grace cache expires and fails closed.
	advance(24 * time.Hour)
	if _, err := vRetry.Verify(ctx, signTok("k1")); err == nil {
		t.Fatal("expected Verify to fail closed after 24h staleCacheTTL expires")
	}
	if got := attempts.Load(); got != 6 {
		t.Fatalf("expected 3 more refresh attempts after 30s cooldown elapsed, got total %d", got)
	}

	// 4. Recovery after 30s cooldown when endpoint comes back healthy.
	always500.Store(false)
	advance(31 * time.Second)
	if _, err := vRetry.Verify(ctx, signTok("k1")); err != nil {
		t.Fatalf("expected Verify to recover after cooldown when JWKS recovers: %v", err)
	}
}

func TestJWTVerifier_ClaimMappingsAndAllowedEmailDomains(t *testing.T) {
	ctx := context.Background()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	edPub := edPriv.Public().(ed25519.PublicKey)

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{ed25519JWK("k1", edPub)},
		})
	}))
	defer jwksSrv.Close()

	verifier := auth.NewMultiIssuerJWTVerifier(auth.MultiIssuerConfig{
		Issuers: []auth.OIDCIssuerConfig{
			{
				Issuer:              "https://idp.acme.com",
				Audience:            "ai-gateway",
				JWKSURL:             jwksSrv.URL,
				HTTPClient:          jwksSrv.Client(),
				AllowedEmailDomains: []string{"acme.com", "@partner.org"},
				ClaimMapping: auth.OIDCClaimMapping{
					UserID:  "custom.uid",
					Email:   "mail",
					OrgID:   "https://acme.com/org_id",
					TeamIDs: "groups",
					Role:    "realm_access.roles",
					EndUser: "actor.end_user",
				},
				DefaultOrgID:  "org_fallback",
				DefaultTeamID: "team_fallback",
				DefaultRole:   "viewer",
			},
		},
	})

	exp := time.Now().UTC().Add(5 * time.Minute).Unix()
	sign := func(claims map[string]any) string {
		return signJWTWithHeader(t,
			map[string]string{"alg": "EdDSA", "kid": "k1", "typ": "JWT"},
			claims,
			func(in string) []byte { return ed25519.Sign(edPriv, []byte(in)) },
		)
	}

	// Valid mapped claims + allowed domain
	tokOK := sign(map[string]any{
		"sub":                     "ignored-sub",
		"iss":                     "https://idp.acme.com",
		"aud":                     "ai-gateway",
		"exp":                     exp,
		"mail":                    "Alice@Acme.com",
		"https://acme.com/org_id": "org_acme_1",
		"groups":                  []string{"team_ml", "team_platform"},
		"realm_access":            map[string]any{"roles": []string{"org_admin", "developer"}},
		"custom":                  map[string]any{"uid": "user_mapped_99"},
		"actor":                   map[string]any{"end_user": "end_usr_42"},
	})
	claims, err := verifier.Verify(ctx, tokOK)
	if err != nil {
		t.Fatalf("verify valid mapped claims failed: %v", err)
	}
	if claims.Subject != "user_mapped_99" {
		t.Fatalf("Subject = %q, want user_mapped_99", claims.Subject)
	}
	if claims.Email != "Alice@Acme.com" {
		t.Fatalf("Email = %q, want Alice@Acme.com", claims.Email)
	}
	if claims.OrgID != "org_acme_1" {
		t.Fatalf("OrgID = %q, want org_acme_1", claims.OrgID)
	}
	if !reflect.DeepEqual(claims.TeamIDs, []string{"team_ml", "team_platform"}) {
		t.Fatalf("TeamIDs = %v, want [team_ml team_platform]", claims.TeamIDs)
	}
	if claims.Role != "org_admin" {
		t.Fatalf("Role = %q, want org_admin", claims.Role)
	}
	if claims.EndUserID != "end_usr_42" {
		t.Fatalf("EndUserID = %q, want end_usr_42", claims.EndUserID)
	}
	if claims.RawClaims["mail"] != "Alice@Acme.com" {
		t.Fatalf("expected RawClaims to retain full payload claims")
	}

	// Fallback defaults when optional org/team/role claims are absent
	tokDefaults := sign(map[string]any{
		"sub":  "sub-2",
		"iss":  "https://idp.acme.com",
		"aud":  "ai-gateway",
		"exp":  exp,
		"mail": "bob@partner.org",
	})
	claimsDef, err := verifier.Verify(ctx, tokDefaults)
	if err != nil {
		t.Fatalf("verify token with fallback defaults failed: %v", err)
	}
	if claimsDef.OrgID != "org_fallback" || !reflect.DeepEqual(claimsDef.TeamIDs, []string{"team_fallback"}) || claimsDef.Role != "viewer" {
		t.Fatalf("unexpected fallback claims: %+v", claimsDef)
	}

	// Disallowed email domain
	tokBadDomain := sign(map[string]any{
		"sub":  "sub-3",
		"iss":  "https://idp.acme.com",
		"aud":  "ai-gateway",
		"exp":  exp,
		"mail": "eve@evil.com",
	})
	if _, err := verifier.Verify(ctx, tokBadDomain); err == nil {
		t.Fatal("expected disallowed email domain to be rejected")
	}

	// Missing email when allowed_email_domains is configured
	tokNoEmail := sign(map[string]any{
		"sub": "sub-4",
		"iss": "https://idp.acme.com",
		"aud": "ai-gateway",
		"exp": exp,
	})
	if _, err := verifier.Verify(ctx, tokNoEmail); err == nil {
		t.Fatal("expected missing email to be rejected when allowed_email_domains is configured")
	}
}
