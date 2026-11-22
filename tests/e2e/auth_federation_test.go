package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func TestE2E_Auth_CredentialExtractionAndConflictRejection(t *testing.T) {
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.CustomAPIKeyHeader = "X-Corp-Gateway-Key"
	})

	ctx := context.Background()
	org := cluster.createOrg("CredExtractor Org")
	modelAlias := cluster.uniqueID("ext-chat")
	cluster.seedOpenAIModel(ctx, org.ID, modelAlias, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	// Also register Anthropic route and MCP server so all three ingress planes are verified.
	_ = cluster.pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    "anthropic/claude-sonnet-4-5",
		Provider:              domain.ProviderAnthropic,
		ModelName:             "claude-sonnet-4-5",
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  3_000_000,
		OutputCostMicrosPer1M: 15_000_000,
		MaxOutputTokens:       4096,
		SupportedOperations:   []domain.OperationType{domain.OperationChat},
	})
	var antCred, antGrp map[string]any
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/credentials", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "provider": "anthropic", "name": cluster.uniqueID("ant-cred"),
		"api_key": "sk-ant-mock", "base_url": upstream.AnthropicBaseURL(),
	}, &antCred)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/model-groups", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "alias": "claude-sonnet-4-5", "routing_strategy": "weighted_shuffle",
	}, &antGrp)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/deployments", cluster.adminHdrs, map[string]any{
		"model_group_id": antGrp["id"], "global_model_id": "anthropic/claude-sonnet-4-5",
		"credential_id": antCred["id"], "deployment_name": cluster.uniqueID("ant-dep"), "weight": 1,
	}, nil)

	mcpSlug := cluster.uniqueID("mcp-ext")
	var mcpCreated struct {
		Server domain.MCPServer `json:"server"`
	}
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/admin/v1/mcp/servers", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": "Ext MCP", "slug": mcpSlug,
		"protocol_version": "2026-07-28", "transport_type": "streamable_http",
		"endpoint_url": upstream.MCPEndpointURL(), "auth_type": "none",
	}, &mcpCreated)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create mcp server (%d): %s", resp.StatusCode, raw)
	}
	resp, raw = cluster.c1.doJSON(http.MethodPost, "/admin/v1/mcp/servers/"+mcpCreated.Server.ID+"/sync", cluster.adminHdrs, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sync mcp tools (%d): %s", resp.StatusCode, raw)
	}

	vkA := cluster.issueKey(map[string]any{
		"org_id":              org.ID,
		"name":                cluster.uniqueID("vk-a"),
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	})
	vkB := cluster.issueKey(map[string]any{
		"org_id":              org.ID,
		"name":                cluster.uniqueID("vk-b"),
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	})

	chatBody := map[string]any{
		"model":    modelAlias,
		"messages": []map[string]string{{"role": "user", "content": "hello"}},
	}

	basicCred := base64.StdEncoding.EncodeToString([]byte("user:" + vkA.RawKey))
	sigV4Header := "AWS4-HMAC-SHA256 Credential=" + vkA.RawKey + "/20261119/us-east-1/execute-api/aws4_request, SignedHeaders=host, Signature=deadbeef"

	cases := []struct {
		name    string
		path    string
		body    any
		headers map[string]string
		useC2   bool
	}{
		{name: "Bearer", path: "/v1/chat/completions", body: chatBody, headers: map[string]string{"Authorization": "Bearer " + vkA.RawKey}},
		{name: "x-api-key", path: "/v1/messages", body: map[string]any{"model": "claude-sonnet-4-5", "max_tokens": 32, "messages": []map[string]string{{"role": "user", "content": "hi"}}}, headers: map[string]string{"x-api-key": vkA.RawKey}},
		{name: "api-key", path: "/v1/chat/completions", body: chatBody, headers: map[string]string{"api-key": vkA.RawKey}, useC2: true},
		{name: "x-goog-api-key", path: "/v1/chat/completions", body: chatBody, headers: map[string]string{"x-goog-api-key": vkA.RawKey}},
		{name: "CustomHeaderOverride", path: "/v1/chat/completions", body: chatBody, headers: map[string]string{"X-Corp-Gateway-Key": vkA.RawKey, "Authorization": "Bearer " + vkB.RawKey}},
		{name: "HTTPBasic", path: "/v1/chat/completions", body: chatBody, headers: map[string]string{"Authorization": "Basic " + basicCred}, useC2: true},
		{name: "AWSSigV4", path: "/v1/chat/completions", body: chatBody, headers: map[string]string{"Authorization": sigV4Header}},
		{name: "MCPWithCustomHeader", path: "/mcp/" + mcpSlug, body: map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "echo_tool", "arguments": map[string]string{"msg": "ok"}}}, headers: map[string]string{"X-Corp-Gateway-Key": vkA.RawKey}, useC2: true},
		{name: "IdenticalMultipleSources", path: "/v1/chat/completions", body: chatBody, headers: map[string]string{"Authorization": "Bearer " + vkA.RawKey, "x-api-key": vkA.RawKey}},
	}
	for _, tc := range cases {
		client := cluster.c1
		if tc.useC2 {
			client = cluster.c2
		}
		r, b := client.doJSON(http.MethodPost, tc.path, tc.headers, tc.body, nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s (%s) failed: status=%d body=%s", tc.name, tc.path, r.StatusCode, string(b))
		}
	}

	callsBeforeConflict := upstream.ChatCalls("")
	conflictPairs := []struct {
		name    string
		headers map[string]string
	}{
		{"BearerVsXAPIKey", map[string]string{"Authorization": "Bearer " + vkA.RawKey, "x-api-key": vkB.RawKey}},
		{"BearerVsAPIKey", map[string]string{"Authorization": "Bearer " + vkA.RawKey, "api-key": vkB.RawKey}},
		{"BasicVsGoogKey", map[string]string{"Authorization": "Basic " + basicCred, "x-goog-api-key": vkB.RawKey}},
		{"SigV4VsXAPIKey", map[string]string{"Authorization": sigV4Header, "x-api-key": vkB.RawKey}},
	}
	for _, cp := range conflictPairs {
		r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", cp.headers, chatBody, nil)
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "ambiguous_gateway_credentials") {
			t.Fatalf("%s expected 400 ambiguous_gateway_credentials, got %d: %s", cp.name, r.StatusCode, string(b))
		}
	}
	if upstream.ChatCalls("") != callsBeforeConflict {
		t.Fatalf("expected 0 upstream calls for conflicting credentials, got +%d", upstream.ChatCalls("")-callsBeforeConflict)
	}
}

func TestE2E_Auth_MultiIssuerOIDCDiscoveryAlgorithmsAndStaleJWKS(t *testing.T) {
	idp := newMockEnterpriseIdentityProvider(t)
	upstream := newMockDeterministicLLMUpstream(t)

	var orgID string
	hsIssuer := "https://hs256.goroute.local"
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.EnableDataPlaneJWT = true
		cfg.Auth.JWTIssuer = hsIssuer
		cfg.Auth.JWTAudience = "goroute-e2e"
		cfg.Auth.JWTSecret = idp.HSSecret()
		cfg.Auth.OIDCIssuers = []config.OIDCIssuerConfig{
			{
				Issuer:       idp.IssuerA(),
				Audience:     "goroute-e2e",
				DiscoveryURL: idp.IssuerA() + "/.well-known/openid-configuration",
				Algorithms:   []string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA"},
				AutoRegister: true,
				DefaultRole:  "developer",
			},
			{
				Issuer:       idp.IssuerB(),
				Audience:     "goroute-e2e",
				DiscoveryURL: idp.IssuerB() + "/.well-known/openid-configuration",
				Algorithms:   []string{"RS256"},
				AutoRegister: true,
				DefaultRole:  "developer",
			},
		}
	})

	ctx := context.Background()
	org := cluster.createOrg("OIDC Org")
	orgID = org.ID
	modelAlias := cluster.uniqueID("oidc-model")
	cluster.seedOpenAIModel(ctx, orgID, modelAlias, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	// Legacy default HS256 verifier has AutoRegister=false by default, so pre-register the HS256 user.
	if err := cluster.pgRepo.CreateUser(ctx, &domain.User{
		ID:          cluster.uniqueID("usr-hs256"),
		OrgID:       orgID,
		Email:       fmt.Sprintf("sub-issb-hs256-%s@alg.test", cluster.runTag),
		Name:        "HS256 User",
		Role:        domain.RoleDeveloper,
		OIDCIssuer:  hsIssuer,
		OIDCSubject: "sub-issb-hs256",
		IsActive:    true,
		SCIMActive:  true,
	}); err != nil {
		t.Fatalf("CreateUser(hs256): %v", err)
	}

	exp := time.Now().UTC().Add(10 * time.Minute).Unix()
	algCases := []struct {
		alg string
		iss string
		kid string
		sub string
	}{
		{"RS256", idp.IssuerA(), "kid-a-1", "sub-rs256"},
		{"RS384", idp.IssuerA(), "kid-a-rs384", "sub-rs384"},
		{"RS512", idp.IssuerA(), "kid-a-rs512", "sub-rs512"},
		{"PS256", idp.IssuerA(), "kid-a-ps256", "sub-ps256"},
		{"ES256", idp.IssuerA(), "kid-a-es256", "sub-es256"},
		{"ES384", idp.IssuerA(), "kid-a-es384", "sub-es384"},
		{"EdDSA", idp.IssuerA(), "kid-a-eddsa", "sub-eddsa"},
		{"RS256", idp.IssuerB(), "kid-b-1", "sub-issb-rs256"},
		{"HS256", hsIssuer, "", "sub-issb-hs256"},
	}
	chatReq := map[string]any{
		"model":    modelAlias,
		"messages": []map[string]string{{"role": "user", "content": "alg check"}},
	}
	for _, tc := range algCases {
		tok := idp.SignJWT(tc.alg, tc.kid, "JWT", map[string]any{
			"iss": tc.iss, "sub": tc.sub, "aud": "goroute-e2e", "org_id": orgID,
			"email": fmt.Sprintf("%s-%s@alg.test", tc.sub, cluster.runTag), "exp": exp,
		})
		// Warm IssuerA JWKS only on node1 (keeping node2 cold for kid rotation refresh check);
		// run IssuerB cases on node2.
		client := cluster.c1
		if tc.iss == idp.IssuerB() || tc.iss == hsIssuer {
			client = cluster.c2
		}
		r, b := client.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tok}, chatReq, nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s on %s failed (%d): %s", tc.alg, tc.iss, r.StatusCode, string(b))
		}
	}

	// Reject oauth-id-jag+jwt typ and unknown issuer.
	jagTok := idp.SignJWT("RS256", "kid-a-1", "oauth-id-jag+jwt", map[string]any{
		"iss": idp.IssuerA(), "sub": "sub-jag", "aud": "goroute-e2e", "org_id": orgID, "exp": exp,
	})
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + jagTok}, chatReq, nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for oauth-id-jag+jwt, got %d: %s", r.StatusCode, string(b))
	}
	badIssTok := idp.SignJWT("RS256", "kid-a-1", "JWT", map[string]any{
		"iss": "https://untrusted.example.invalid", "sub": "sub-x", "aud": "goroute-e2e", "org_id": orgID, "exp": exp,
	})
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + badIssTok}, chatReq, nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for untrusted issuer, got %d: %s", r.StatusCode, string(b))
	}

	// Key rotation refreshes JWKS on node2 (cold IssuerA verifier) cleanly.
	idp.RotateKeyA("kid-a-rot-2")
	rotTok := idp.SignJWT("RS256", "kid-a-rot-2", "JWT", map[string]any{
		"iss": idp.IssuerA(), "sub": "sub-rot-2", "aud": "goroute-e2e", "org_id": orgID,
		"email": "rot2-" + cluster.runTag + "@alg.test", "exp": exp,
	})
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + rotTok}, chatReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("rotated kid inference on node2 failed (%d): %s", r.StatusCode, string(b))
	}

	// JWKS outage falls back cleanly to cached/stale JWKS across both nodes without disruption.
	idp.SetJWKSOutage(true)
	cachedTok := idp.SignJWT("RS256", "kid-a-1", "JWT", map[string]any{
		"iss": idp.IssuerA(), "sub": "sub-rs256", "aud": "goroute-e2e", "org_id": orgID,
		"email": fmt.Sprintf("sub-rs256-%s@alg.test", cluster.runTag), "exp": exp,
	})
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + cachedTok}, chatReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("expected cached/stale-JWKS fallback on node1 to succeed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + rotTok}, chatReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("expected cached/stale-JWKS fallback on node2 to succeed (%d): %s", r.StatusCode, string(b))
	}
}

func TestE2E_Auth_DataPlaneOIDC_IssuerBinding_ClaimMapping_JIT(t *testing.T) {
	idp := newMockEnterpriseIdentityProvider(t)
	upstream := newMockDeterministicLLMUpstream(t)

	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.EnableDataPlaneJWT = true
		cfg.Auth.OIDCIssuers = []config.OIDCIssuerConfig{
			{
				Issuer:       idp.IssuerA(),
				Audience:     "goroute-dp",
				DiscoveryURL: idp.IssuerA() + "/.well-known/openid-configuration",
				Algorithms:   []string{"RS256"},
				AutoRegister: true,
				DefaultRole:  "developer",
			},
			{
				Issuer:       idp.IssuerB(),
				Audience:     "goroute-dp",
				DiscoveryURL: idp.IssuerB() + "/.well-known/openid-configuration",
				Algorithms:   []string{"RS256"},
				AutoRegister: true,
				DefaultRole:  "developer",
			},
		}
	})

	ctx := context.Background()
	org := cluster.createOrg("OIDC Binding Org")
	allowedModel := cluster.uniqueID("oidc-allowed")
	blockedModel := cluster.uniqueID("oidc-blocked")
	cluster.seedOpenAIModel(ctx, org.ID, allowedModel, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)
	cluster.seedOpenAIModel(ctx, org.ID, blockedModel, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	// Register MCP & A2A to verify Data Plane OIDC works across /v1/*, /mcp/*, and /a2a/*.
	mcpSlug := cluster.uniqueID("oidc-mcp")
	var mcpCreated struct {
		Server domain.MCPServer `json:"server"`
	}
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/mcp/servers", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": "OIDC MCP", "slug": mcpSlug,
		"protocol_version": "2026-07-28", "transport_type": "streamable_http",
		"endpoint_url": upstream.MCPEndpointURL(), "auth_type": "none",
	}, &mcpCreated)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/mcp/servers/"+mcpCreated.Server.ID+"/sync", cluster.adminHdrs, nil, nil)

	a2aSlug := cluster.uniqueID("oidc-a2a")
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/a2a/agents", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": "OIDC Agent", "slug": a2aSlug,
		"endpoint_url": upstream.A2AEndpointURL(), "visibility_mode": "org_admin", "is_active": true,
	}, nil)

	exp := time.Now().UTC().Add(10 * time.Minute).Unix()

	// 1. Same sub across issuer-a and issuer-b binds independently by (org_id, issuer, subject).
	emailA := fmt.Sprintf("alice-a-%s@issuer-a.test", cluster.runTag)
	emailB := fmt.Sprintf("alice-b-%s@issuer-b.test", cluster.runTag)
	tokIssA := idp.SignJWT("RS256", "kid-a-1", "JWT", map[string]any{
		"iss": idp.IssuerA(), "sub": "shared-sub", "aud": "goroute-dp", "org_id": org.ID, "email": emailA, "exp": exp,
	})
	tokIssB := idp.SignJWT("RS256", "kid-b-1", "JWT", map[string]any{
		"iss": idp.IssuerB(), "sub": "shared-sub", "aud": "goroute-dp", "org_id": org.ID, "email": emailB, "exp": exp,
	})

	chatAllowed := map[string]any{
		"model":    allowedModel,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tokIssA}, chatAllowed, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("issuer-a chat failed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tokIssB}, chatAllowed, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("issuer-b chat failed (%d): %s", r.StatusCode, string(b))
	}

	var countSharedSub int
	if err := cluster.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE org_id = $1 AND oidc_subject = 'shared-sub'`, org.ID).Scan(&countSharedSub); err != nil {
		t.Fatalf("count shared-sub users: %v", err)
	}
	if countSharedSub != 2 {
		t.Fatalf("expected 2 issuer-isolated users for same subject across issuers, got %d", countSharedSub)
	}

	// Verify Data Plane JWT across /mcp and /a2a as well.
	if r, b := cluster.c1.doJSON(http.MethodPost, "/mcp/"+mcpSlug, map[string]string{"Authorization": "Bearer " + tokIssA}, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "echo_tool", "arguments": map[string]string{"msg": "jwt"}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("OIDC JWT on /mcp failed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/a2a/v1/agents/"+a2aSlug, map[string]string{"Authorization": "Bearer " + tokIssA}, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tasks/send", "params": map[string]any{"message": map[string]any{"messageId": "m1", "role": "ROLE_USER", "parts": []map[string]any{{"text": "hi"}}}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("OIDC JWT on /a2a failed (%d): %s", r.StatusCode, string(b))
	}

	// 2. Claim-to-key mapping inherits virtual key allowlist & budgets.
	mappedVK := cluster.issueKey(map[string]any{
		"org_id":         org.ID,
		"name":           cluster.uniqueID("jwt-mapped"),
		"allowed_models": []string{allowedModel},
	})
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/admin/v1/jwt-mappings", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "issuer": idp.IssuerA(), "claim_name": "groups", "claim_value": "ml-prod", "virtual_key_id": mappedVK.ID,
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create jwt mapping (%d): %s", resp.StatusCode, string(raw))
	}
	mappedTok := idp.SignJWT("RS256", "kid-a-1", "JWT", map[string]any{
		"iss": idp.IssuerA(), "sub": "mapped-sub-" + cluster.runTag, "aud": "goroute-dp",
		"email": "mapped-" + cluster.runTag + "@issuer-a.test", "groups": []string{"ml-prod"}, "exp": exp,
	})
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + mappedTok}, chatAllowed, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("mapped JWT allowed model failed on node2 (%d): %s", r.StatusCode, string(b))
	}
	chatBlocked := map[string]any{
		"model":    blockedModel,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + mappedTok}, chatBlocked, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for mapped JWT on disallowed model, got %d: %s", r.StatusCode, string(b))
	}

	// 3. No automatic email linking: a different issuer+subject carrying existing user's email must not hijack emailA.
	hijackTok := idp.SignJWT("RS256", "kid-b-1", "JWT", map[string]any{
		"iss": idp.IssuerB(), "sub": "hijack-sub-" + cluster.runTag, "aud": "goroute-dp", "org_id": org.ID, "email": emailA, "exp": exp,
	})
	if r, _ := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + hijackTok}, chatAllowed, nil); r.StatusCode == http.StatusOK {
		// Verify existing user row belonging to issuer-a was never overwritten or hijacked.
		var gotIss, gotSub string
		if err := cluster.pool.QueryRow(ctx, `SELECT oidc_issuer, oidc_subject FROM users WHERE org_id = $1 AND email = $2`, org.ID, emailA).Scan(&gotIss, &gotSub); err != nil {
			t.Fatalf("query emailA user: %v", err)
		}
		if gotIss != idp.IssuerA() || gotSub != "shared-sub" {
			t.Fatalf("emailA user was overwritten to issuer=%q sub=%q", gotIss, gotSub)
		}
	}

	// 4. Legacy subject-only binding: fails under multi-issuer ambiguity, succeeds under unambiguous single issuer.
	legacySub := "legacy-sub-" + cluster.runTag
	if _, err := cluster.pool.Exec(ctx, `
		INSERT INTO users (id, org_id, email, name, role, oidc_issuer, oidc_subject, is_active, scim_active)
		VALUES ($1, $2, $3, 'Legacy User', 'developer', '', $4, TRUE, TRUE)
	`, cluster.uniqueID("usr-leg"), org.ID, "legacy-"+cluster.runTag+"@corp.test", legacySub); err != nil {
		t.Fatalf("insert legacy subject-only user: %v", err)
	}
	legacyTokA := idp.SignJWT("RS256", "kid-a-1", "JWT", map[string]any{
		"iss": idp.IssuerA(), "sub": legacySub, "aud": "goroute-dp", "org_id": org.ID, "email": "diff-" + cluster.runTag + "@corp.test", "exp": exp,
	})
	// On multi-issuer cluster, AutoRegister tries to create a new user with diff email rather than adopting legacy subject-only row.
	// Spin a second cluster with AutoRegister=false + single unambiguous issuer vs multi-issuer to verify exact fail-closed behavior.
	multiNoReg := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.EnableDataPlaneJWT = true
		cfg.Auth.OIDCIssuers = []config.OIDCIssuerConfig{
			{Issuer: idp.IssuerA(), Audience: "goroute-dp", DiscoveryURL: idp.IssuerA() + "/.well-known/openid-configuration", Algorithms: []string{"RS256"}, AutoRegister: false},
			{Issuer: idp.IssuerB(), Audience: "goroute-dp", DiscoveryURL: idp.IssuerB() + "/.well-known/openid-configuration", Algorithms: []string{"RS256"}, AutoRegister: false},
		}
	})
	if r, b := multiNoReg.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + legacyTokA}, chatAllowed, nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for ambiguous legacy subject under multi-issuer AutoRegister=false, got %d: %s", r.StatusCode, string(b))
	}

	singleCluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.EnableDataPlaneJWT = true
		cfg.Auth.OIDCIssuers = []config.OIDCIssuerConfig{
			{Issuer: idp.IssuerA(), Audience: "goroute-dp", DiscoveryURL: idp.IssuerA() + "/.well-known/openid-configuration", Algorithms: []string{"RS256"}, AutoRegister: false},
		}
	})
	if r, b := singleCluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + legacyTokA}, chatAllowed, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("expected legacy subject-only user to resolve cleanly under unambiguous single issuer, got %d: %s", r.StatusCode, string(b))
	}
}

func TestE2E_Auth_RFC7662IntrospectionUserInfoAndCache(t *testing.T) {
	idp := newMockEnterpriseIdentityProvider(t)
	upstream := newMockDeterministicLLMUpstream(t)

	orgIDContainer := ""
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.Introspection = config.IntrospectionConfig{
			TokenInfoEndpoint: idp.IntrospectURL(),
			ClientID:          "gw-client",
			ClientSecret:      "gw-secret",
			Mode:              "introspect",
			CacheTTL:          60 * time.Second,
			AutoRegister:      true,
			DefaultRole:       "developer",
		}
	})

	ctx := context.Background()
	org := cluster.createOrg("Introspect Org")
	orgIDContainer = org.ID
	modelAlias := cluster.uniqueID("intro-chat")
	cluster.seedOpenAIModel(ctx, orgIDContainer, modelAlias, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	opaqueGood := "opaque-tok-active-" + cluster.runTag
	opaqueBad := "opaque-tok-inactive-" + cluster.runTag
	idp.SetIntrospectToken(opaqueGood, true, map[string]any{
		"sub": "intro-sub-" + cluster.runTag, "email": "intro-" + cluster.runTag + "@corp.test", "org_id": orgIDContainer,
	})
	idp.SetIntrospectToken(opaqueBad, false, nil)

	chatBody := map[string]any{"model": modelAlias, "messages": []map[string]string{{"role": "user", "content": "hi"}}}

	// Node 1 hits /introspect once, populates L1 and Redis L2 cache.
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + opaqueGood}, chatBody, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("node1 introspect failed (%d): %s", r.StatusCode, string(b))
	}
	if calls := idp.IntrospectCalls(); calls != 1 {
		t.Fatalf("expected IntrospectCalls == 1 after cold request, got %d", calls)
	}

	// Repeat on node 1 (L1) and node 2 (Redis L2 SHA-256 cache): 0 additional /introspect calls.
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + opaqueGood}, chatBody, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("node1 cached introspect failed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + opaqueGood}, chatBody, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("node2 L2 cached introspect failed (%d): %s", r.StatusCode, string(b))
	}
	if calls := idp.IntrospectCalls(); calls != 1 {
		t.Fatalf("expected IntrospectCalls to stay 1 across L1 and node2 L2 caches, got %d", calls)
	}

	// Inactive token rejected with 401.
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + opaqueBad}, chatBody, nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for inactive introspected token, got %d: %s", r.StatusCode, string(b))
	}

	// Verify UserInfo mode against /userinfo endpoint.
	uiCluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.Introspection = config.IntrospectionConfig{
			TokenInfoEndpoint: idp.UserInfoURL(),
			Mode:              "userinfo",
			CacheTTL:          30 * time.Second,
			AutoRegister:      true,
			DefaultRole:       "developer",
		}
	})
	uiTok := "opaque-userinfo-" + cluster.runTag
	idp.SetUserInfoToken(uiTok, map[string]any{
		"sub": "ui-sub-" + cluster.runTag, "email": "ui-" + cluster.runTag + "@corp.test", "org_id": orgIDContainer,
	})
	if r, b := uiCluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + uiTok}, chatBody, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("userinfo mode failed (%d): %s", r.StatusCode, string(b))
	}
}

func TestE2E_Auth_CIDRProxyAuthAndEmbeddedSDKCustomAuthenticator(t *testing.T) {
	upstream := newMockDeterministicLLMUpstream(t)
	trustedCluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.ProxyAuth = config.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"127.0.0.0/8", "::1/128"},
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
			AutoRegister:      true,
			DefaultRole:       "developer",
		}
		cfg.Security.Network.InboundCaller.TrustedProxyCIDRs = []string{"127.0.0.0/8", "::1/128"}
	})

	ctx := context.Background()
	org := trustedCluster.createOrg("Proxy & SDK Org")
	allowedModel := trustedCluster.uniqueID("proxy-allowed")
	blockedModel := trustedCluster.uniqueID("proxy-blocked")
	trustedCluster.seedOpenAIModel(ctx, org.ID, allowedModel, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)
	trustedCluster.seedOpenAIModel(ctx, org.ID, blockedModel, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	// 1. Trusted CIDR proxy headers succeed across both nodes.
	proxyHdrs := map[string]string{
		"X-Auth-Request-User":  "proxy-usr-" + trustedCluster.runTag,
		"X-Auth-Request-Email": "proxy-" + trustedCluster.runTag + "@corp.test",
		"X-Auth-Request-Org":   org.ID,
	}
	chatReq := map[string]any{"model": allowedModel, "messages": []map[string]string{{"role": "user", "content": "proxy"}}}
	if r, b := trustedCluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", proxyHdrs, chatReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("trusted proxy auth failed (%d): %s", r.StatusCode, string(b))
	}

	// Untrusted proxy CIDR rejects identical headers with 401.
	untrustedCluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.ProxyAuth = config.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.250.0.0/24"},
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
			AutoRegister:      true,
		}
	})
	if r, b := untrustedCluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", proxyHdrs, chatReq, nil); r.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "untrusted_proxy") {
		t.Fatalf("expected 403 untrusted_proxy from untrusted proxy peer CIDR, got %d: %s", r.StatusCode, string(b))
	}

	// 2. Embedded Go SDK WithCustomAuthenticator wired through live Postgres + Redis HTTP entry point.
	for _, k := range []string{
		"GATEWAY_JWT_SECRET", "GATEWAY_JWT_ISSUER", "GATEWAY_JWT_AUDIENCE",
		"GATEWAY_OIDC_JWKS_URL", "GATEWAY_MASTER_ADMIN_KEY", "GATEWAY_MASTER_ENCRYPTION_KEY",
	} {
		t.Setenv(k, "")
	}
	vk := trustedCluster.issueKey(map[string]any{
		"org_id":         org.ID,
		"name":           trustedCluster.uniqueID("sdk-vk"),
		"allowed_models": []string{allowedModel},
		"rpm_limit":      2,
	})

	cfgPath := filepath.Join(t.TempDir(), "sdk-e2e.yaml")
	cfgYAML := fmt.Sprintf(`server:
  environment: test
discovery:
  enabled: false
storage:
  mode: postgres
  postgres_dsn: %q
  redis_addr: %q
auth:
  master_admin_key: %q
  master_encryption_key: %q
  default_org_id: %q
finops:
  flush_interval: 25ms
  batch_size: 1
`, liveE2EPostgresDSN(), liveE2ERedisAddr(), e2eMasterAdminKey, e2eMasterEncryptionKey, org.ID)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write temp sdk yaml: %v", err)
	}

	// CustomAuthModeAuto: X-Custom-Partner maps to IdentityContext (or VirtualKey); missing header falls back to standard Bearer vk.
	sdkAuto, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithConfigFile(cfgPath),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithCustomAuthenticator(gateway.CustomAuthModeAuto, gateway.CustomAuthenticatorFunc(func(_ context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			if r.Header.Get("X-Custom-Partner") == "partner-direct" {
				return &gateway.AuthDecision{
					RunPostChecks: true,
					Identity: &domain.IdentityContext{
						OrgID:            org.ID,
						VirtualKeyID:     vk.ID,
						KeyPrefix:        "custom",
						Role:             domain.RoleDeveloper,
						KeyAllowedModels: []string{allowedModel},
						KeyRPMLimit:      2,
						AllowedEndpoints: []string{"*"},
					},
				}, nil
			}
			return nil, nil // abstain -> fall back to standard Bearer auth
		})),
	)
	if err != nil {
		t.Fatalf("gateway.New(Auto): %v", err)
	}
	defer sdkAuto.Close()

	httpClient := &http.Client{Timeout: 5 * time.Second}
	postSDK := func(baseURL string, hdrs map[string]string, model string) int {
		b, _ := json.Marshal(map[string]any{"model": model, "messages": []map[string]string{{"role": "user", "content": "sdk"}}})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("sdk HTTP post: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := postSDK(sdkAuto.BaseURL(), map[string]string{"X-Custom-Partner": "partner-direct"}, allowedModel); code != http.StatusOK {
		t.Fatalf("embedded SDK custom identity allowed model got %d, want 200", code)
	}
	if code := postSDK(sdkAuto.BaseURL(), map[string]string{"X-Custom-Partner": "partner-direct"}, blockedModel); code != http.StatusForbidden {
		t.Fatalf("embedded SDK custom identity blocked model got %d, want 403", code)
	}
	// Fallback to standard virtual key consumes remaining RPM=2 quota, then 3rd hits 429.
	if code := postSDK(sdkAuto.BaseURL(), map[string]string{"Authorization": "Bearer " + vk.RawKey}, allowedModel); code != http.StatusOK {
		t.Fatalf("embedded SDK Auto fallback got %d, want 200", code)
	}
	if code := postSDK(sdkAuto.BaseURL(), map[string]string{"Authorization": "Bearer " + vk.RawKey}, allowedModel); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 RPM exhaustion on embedded SDK, got %d", code)
	}

	// CustomAuthModeOn fails closed when custom authenticator abstains (even with valid Bearer header).
	sdkOn, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithConfigFile(cfgPath),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithCustomAuthenticator(gateway.CustomAuthModeOn, gateway.CustomAuthenticatorFunc(func(_ context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			if r.Header.Get("X-Custom-Only") == "yes" {
				return &gateway.AuthDecision{VirtualKey: vk.RawKey}, nil
			}
			return nil, nil
		})),
	)
	if err != nil {
		t.Fatalf("gateway.New(On): %v", err)
	}
	defer sdkOn.Close()

	if code := postSDK(sdkOn.BaseURL(), map[string]string{"Authorization": "Bearer " + vk.RawKey}, allowedModel); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when CustomAuthModeOn abstains, got %d", code)
	}
}
