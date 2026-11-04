package upstream_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestSigV4Strategy_SignHTTP(t *testing.T) {
	ctx := context.Background()
	fixedTime := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

	strat, err := upstream.NewSigV4Strategy(upstream.SigV4Config{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr1EXAMPLETOKEN",
		Region:          "us-east-1",
		Service:         "bedrock",
		TimeProvider:    func() time.Time { return fixedTime },
	})
	if err != nil {
		t.Fatalf("new sigv4 strategy: %v", err)
	}

	if strat.Type() != "aws_sigv4" {
		t.Fatalf("expected type aws_sigv4, got %s", strat.Type())
	}

	bodyContent := `{"prompt": "Analyze systems architecture"}`
	req, err := http.NewRequest(http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-v2/invoke", strings.NewReader(bodyContent))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	authCtx := &upstream.UpstreamAuthContext{
		CallingOrgID: "org_prod_aws",
	}

	if err := strat.Apply(ctx, req, authCtx); err != nil {
		t.Fatalf("apply sigv4: %v", err)
	}

	authHdr := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHdr, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261108/us-east-1/bedrock/aws4_request") {
		t.Fatalf("unexpected Authorization header: %s", authHdr)
	}

	dateHdr := req.Header.Get("X-Amz-Date")
	if dateHdr != "20261108T120000Z" {
		t.Fatalf("expected 20261108T120000Z, got %s", dateHdr)
	}

	secTok := req.Header.Get("X-Amz-Security-Token")
	if secTok != "AQoDYXdzEJr1EXAMPLETOKEN" {
		t.Fatalf("expected session token header, got %s", secTok)
	}

	shaHdr := req.Header.Get("X-Amz-Content-Sha256")
	if shaHdr == "" {
		t.Fatalf("expected X-Amz-Content-Sha256 to be populated")
	}

	// Verify request body is still readable after signing
	readBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body after signing: %v", err)
	}
	if string(readBody) != bodyContent {
		t.Fatalf("expected body %q, got %q", bodyContent, string(readBody))
	}
}

func TestSigV4Strategy_ValidationFailures(t *testing.T) {
	_, err := upstream.NewSigV4Strategy(upstream.SigV4Config{
		AccessKeyID: "",
	})
	if err == nil {
		t.Fatalf("expected error for empty access key")
	}

	strat, _ := upstream.NewSigV4Strategy(upstream.SigV4Config{
		AccessKeyID:     "KEY",
		SecretAccessKey: "SECRET",
		Region:          "us-east-1",
		Service:         "bedrock",
	})
	if err := strat.Apply(context.Background(), nil, nil); err == nil {
		t.Fatalf("expected error for nil request")
	}
}

func TestCIMDResolverAndPKCE(t *testing.T) {
	ctx := context.Background()

	var fetchCount atomic.Int32
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  "https://gateway.example.com/oauth/client.json",
			"client_name":                "GoRoute AI Gateway",
			"redirect_uris":              []string{"https://gateway.example.com/oauth/callback"},
			"token_endpoint_auth_method": "private_key_jwt",
			"scope":                      "mcp:tools:read mcp:tools:call",
		})
	}))
	defer mockSrv.Close()

	netPolicy := &network.Policy{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	}

	resolver := upstream.NewCIMDResolver(netPolicy, 10*time.Minute, true)

	doc, err := resolver.Resolve(ctx, mockSrv.URL)
	if err != nil {
		t.Fatalf("resolve cimd: %v", err)
	}

	if doc.ClientName != "GoRoute AI Gateway" {
		t.Fatalf("unexpected client name: %s", doc.ClientName)
	}
	if len(doc.RedirectURIs) != 1 || doc.RedirectURIs[0] != "https://gateway.example.com/oauth/callback" {
		t.Fatalf("unexpected redirect uris: %v", doc.RedirectURIs)
	}

	// Second resolve should hit cache
	doc2, err := resolver.Resolve(ctx, mockSrv.URL)
	if err != nil {
		t.Fatalf("resolve cimd cached: %v", err)
	}
	if doc2.ClientName != doc.ClientName {
		t.Fatalf("cached doc mismatch")
	}
	if fetchCount.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream fetch, got %d", fetchCount.Load())
	}

	// Insecure rejection test
	secureResolver := upstream.NewCIMDResolver(netPolicy, 10*time.Minute, false)
	_, err = secureResolver.Resolve(ctx, "http://insecure.example.com/client.json")
	if err == nil || !strings.Contains(err.Error(), "insecure http scheme not allowed") {
		t.Fatalf("expected error for insecure http: %v", err)
	}

	// PKCE Test
	pkce, err := upstream.GeneratePKCE()
	if err != nil {
		t.Fatalf("generate pkce: %v", err)
	}
	if len(pkce.CodeVerifier) < 43 || len(pkce.CodeVerifier) > 128 {
		t.Fatalf("invalid code verifier length: %d", len(pkce.CodeVerifier))
	}
	if !upstream.ValidatePKCE(pkce.CodeVerifier, pkce.CodeChallenge, pkce.CodeChallengeMethod) {
		t.Fatalf("pkce validation failed for matching verifier and challenge")
	}
	if upstream.ValidatePKCE("tampered_verifier_123456789012345678901234567890123", pkce.CodeChallenge, "S256") {
		t.Fatalf("pkce validation should fail for tampered verifier")
	}
	if upstream.ValidatePKCE(pkce.CodeVerifier, pkce.CodeChallenge, "plain") {
		t.Fatalf("pkce validation should fail for non-S256 method")
	}
}

func TestRFC9207AndRFC8707(t *testing.T) {
	// RFC 9207 Issuer Validation
	expectedIss := "https://auth.company.internal/oauth2/v1"
	if err := upstream.ValidateRFC9207Issuer(expectedIss, expectedIss); err != nil {
		t.Fatalf("expected exact match to pass: %v", err)
	}

	// Character-for-character mismatch test (no normalization allowed)
	if err := upstream.ValidateRFC9207Issuer(expectedIss, expectedIss+"/"); err == nil {
		t.Fatalf("expected trailing slash mismatch to fail RFC 9207")
	}
	if err := upstream.ValidateRFC9207Issuer(expectedIss, "HTTPS://auth.company.internal/oauth2/v1"); err == nil {
		t.Fatalf("expected case mismatch to fail RFC 9207")
	}
	if err := upstream.ValidateRFC9207Issuer(expectedIss, ""); err == nil {
		t.Fatalf("expected empty issuer to fail RFC 9207")
	}

	// RFC 8707 Resource Indicators
	validURI := "https://mcp.internal.net/api/v1"
	if err := upstream.ValidateRFC8707ResourceURI(validURI); err != nil {
		t.Fatalf("expected valid absolute URI to pass: %v", err)
	}

	// Relative URI must fail
	if err := upstream.ValidateRFC8707ResourceURI("/api/v1"); err == nil {
		t.Fatalf("expected relative URI to fail RFC 8707")
	}
	// URI with fragment must fail
	if err := upstream.ValidateRFC8707ResourceURI("https://mcp.internal.net/api#section1"); err == nil {
		t.Fatalf("expected URI with fragment to fail RFC 8707")
	}

	vals := url.Values{}
	if err := upstream.ApplyRFC8707Resources(vals, []string{validURI, "https://mcp.internal.net/api/v2"}); err != nil {
		t.Fatalf("apply resources: %v", err)
	}
	if len(vals["resource"]) != 2 {
		t.Fatalf("expected 2 resource parameters, got: %v", vals["resource"])
	}
}

func TestTokenExchangeStrategy(t *testing.T) {
	ctx := context.Background()

	var tokenCallCount atomic.Int32
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCallCount.Add(1)
		_ = r.ParseForm()

		if r.FormValue("grant_type") != upstream.GrantTypeTokenExchange {
			t.Errorf("unexpected grant_type: %s", r.FormValue("grant_type"))
		}
		if r.FormValue("subject_token") != "caller-initial-jwt-token" {
			t.Errorf("unexpected subject_token: %s", r.FormValue("subject_token"))
		}
		if r.FormValue("resource") != "https://upstream.internal.net/mcp" {
			t.Errorf("unexpected resource: %s", r.FormValue("resource"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-upstream-token-xyz",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer mockAS.Close()

	netPolicy := &network.Policy{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	}

	strat, err := upstream.NewTokenExchangeStrategy(upstream.TokenExchangeConfig{
		TokenEndpoint: mockAS.URL,
		ClientID:      "gateway-client",
		ClientSecret:  "gateway-secret",
		Resource:      "https://upstream.internal.net/mcp",
		Audience:      "mcp-target-aud",
		NetPolicy:     netPolicy,
	})
	if err != nil {
		t.Fatalf("new token exchange strategy: %v", err)
	}

	if strat.Type() != "rfc8693_token_exchange" {
		t.Fatalf("unexpected type: %s", strat.Type())
	}

	req, _ := http.NewRequest(http.MethodGet, "https://upstream.internal.net/mcp/tools", nil)
	authCtx := &upstream.UpstreamAuthContext{
		DelegatedToken: "caller-initial-jwt-token",
	}

	if err := strat.Apply(ctx, req, authCtx); err != nil {
		t.Fatalf("apply token exchange: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer exchanged-upstream-token-xyz" {
		t.Fatalf("unexpected Authorization header: %s", req.Header.Get("Authorization"))
	}

	// Second apply should hit cache
	req2, _ := http.NewRequest(http.MethodGet, "https://upstream.internal.net/mcp/tools", nil)
	if err := strat.Apply(ctx, req2, authCtx); err != nil {
		t.Fatalf("apply token exchange cached: %v", err)
	}
	if req2.Header.Get("Authorization") != "Bearer exchanged-upstream-token-xyz" {
		t.Fatalf("unexpected cached Authorization header")
	}

	if tokenCallCount.Load() != 1 {
		t.Fatalf("expected 1 call to AS, got %d", tokenCallCount.Load())
	}
}

func TestOktaIDJAGStrategy(t *testing.T) {
	ctx := context.Background()

	var oktaCallCount atomic.Int32
	mockOkta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oktaCallCount.Add(1)
		_ = r.ParseForm()

		if r.FormValue("grant_type") != upstream.GrantTypeJWTBearer {
			t.Errorf("unexpected grant_type: %s", r.FormValue("grant_type"))
		}
		assertion := r.FormValue("assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Errorf("expected 3 parts in assertion JWT, got %d", len(parts))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "okta-issued-bearer-token-12345",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer mockOkta.Close()

	netPolicy := &network.Policy{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	}

	strat, err := upstream.NewOktaIDJAGStrategy(upstream.OktaIDJAGConfig{
		TokenEndpoint: mockOkta.URL,
		ClientID:      "0oa1234567890abcdef",
		Audience:      "https://company.okta.com/oauth2/v1/token",
		SigningKey:    "super-secret-hmac-key-for-okta-assertion",
		Scopes:        []string{"offline_access", "read:data"},
		NetPolicy:     netPolicy,
	})
	if err != nil {
		t.Fatalf("new okta strategy: %v", err)
	}

	if strat.Type() != "okta_id_jag" {
		t.Fatalf("unexpected type: %s", strat.Type())
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.company.internal/resource", nil)
	authCtx := &upstream.UpstreamAuthContext{
		CallingUserID: "usr_alice_123",
	}

	if err := strat.Apply(ctx, req, authCtx); err != nil {
		t.Fatalf("apply okta id jag: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer okta-issued-bearer-token-12345" {
		t.Fatalf("unexpected Authorization header: %s", req.Header.Get("Authorization"))
	}

	// Second apply should hit cache
	req2, _ := http.NewRequest(http.MethodPost, "https://api.company.internal/resource", nil)
	if err := strat.Apply(ctx, req2, authCtx); err != nil {
		t.Fatalf("apply okta cached: %v", err)
	}
	if req2.Header.Get("Authorization") != "Bearer okta-issued-bearer-token-12345" {
		t.Fatalf("unexpected cached Authorization header")
	}

	if oktaCallCount.Load() != 1 {
		t.Fatalf("expected 1 call to Okta, got %d", oktaCallCount.Load())
	}
}
