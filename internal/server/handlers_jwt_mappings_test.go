package server_test

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func signTestRS256JWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdrBytes, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	payloadBytes, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func startServerOIDCTestProvider(t *testing.T, kid string, priv *rsa.PrivateKey) *httptest.Server {
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

func doJSONRequest(t *testing.T, baseURL, method, path, token string, body any, extraHeaders map[string]string) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request body: %v", err)
		}
	}
	req, err := http.NewRequest(method, baseURL+path, &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAdminJWTMappingsCRUD_RBACAndCrossOrgIsolation(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true})
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true})

	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_admin_a",
		OrgID:       "org_a",
		Email:       "admin@orga.example",
		Name:        "Org A Admin",
		Role:        domain.RoleOrgAdmin,
		OIDCSubject: "sub-admin-a",
		IsActive:    true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_viewer_a",
		OrgID:       "org_a",
		Email:       "viewer@orga.example",
		Name:        "Org A Viewer",
		Role:        domain.RoleOrgViewer,
		OIDCSubject: "sub-viewer-a",
		IsActive:    true,
	})

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-jwt-mappings-test"
	cfg.Auth.JWTSecret = "admin-jwt-mappings-secret"
	cfg.Auth.JWTIssuer = "https://admin-idp.example"
	cfg.Auth.JWTAudience = "ai-gateway"
	cfg.Auth.DefaultOrgID = "org_a"

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	vkA, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		Name:  "key-a",
		OrgID: "org_a",
		Role:  domain.RoleDeveloper,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey A: %v", err)
	}
	vkB, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		Name:  "key-b",
		OrgID: "org_b",
		Role:  domain.RoleDeveloper,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey B: %v", err)
	}

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	exp := time.Now().UTC().Add(10 * time.Minute).Unix()
	adminAJWT, _ := auth.SignHS256(cfg.Auth.JWTSecret, &auth.JWTClaims{
		Subject:   "sub-admin-a",
		Issuer:    cfg.Auth.JWTIssuer,
		Audience:  auth.AudienceClaim{cfg.Auth.JWTAudience},
		ExpiresAt: exp,
	})
	viewerAJWT, _ := auth.SignHS256(cfg.Auth.JWTSecret, &auth.JWTClaims{
		Subject:   "sub-viewer-a",
		Issuer:    cfg.Auth.JWTIssuer,
		Audience:  auth.AudienceClaim{cfg.Auth.JWTAudience},
		ExpiresAt: exp,
	})

	// 1. Unauthenticated request is rejected (401)
	status, _ := doJSONRequest(t, ts.URL, http.MethodGet, "/admin/v1/jwt-mappings", "", nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated GET /admin/v1/jwt-mappings, got %d", status)
	}

	// 2. org_viewer cannot create (403)
	status, _ = doJSONRequest(t, ts.URL, http.MethodPost, "/admin/v1/jwt-mappings", viewerAJWT, map[string]any{
		"org_id":         "org_a",
		"issuer":         "https://idp.example",
		"claim_name":     "groups",
		"claim_value":    "eng",
		"virtual_key_id": vkA.ID,
	}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for org_viewer POST /admin/v1/jwt-mappings, got %d", status)
	}

	// 3. org_admin of org_a cannot create mapping for org_b or cross-org virtual_key_id (403)
	status, _ = doJSONRequest(t, ts.URL, http.MethodPost, "/admin/v1/jwt-mappings", adminAJWT, map[string]any{
		"org_id":         "org_b",
		"issuer":         "https://idp.example",
		"claim_name":     "groups",
		"claim_value":    "eng-b",
		"virtual_key_id": vkB.ID,
	}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-org POST, got %d", status)
	}

	status, _ = doJSONRequest(t, ts.URL, http.MethodPost, "/admin/v1/jwt-mappings", adminAJWT, map[string]any{
		"org_id":         "org_a",
		"issuer":         "https://idp.example",
		"claim_name":     "groups",
		"claim_value":    "cross-key",
		"virtual_key_id": vkB.ID,
	}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 when binding org_a mapping to org_b virtual key, got %d", status)
	}

	// 4. org_admin of org_a creates mapping cleanly (201)
	status, createdA := doJSONRequest(t, ts.URL, http.MethodPost, "/admin/v1/jwt-mappings", adminAJWT, map[string]any{
		"issuer":         "https://idp.example",
		"claim_name":     "groups",
		"claim_value":    "ml-platform",
		"virtual_key_id": vkA.ID,
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("expected 201 creating mapping in org_a, got %d (%v)", status, createdA)
	}
	mappingAID, _ := createdA["id"].(string)
	if mappingAID == "" || createdA["org_id"] != "org_a" {
		t.Fatalf("unexpected created mapping: %v", createdA)
	}

	// Duplicate (issuer, claim_name, claim_value) fails with 409 Conflict
	status, _ = doJSONRequest(t, ts.URL, http.MethodPost, "/admin/v1/jwt-mappings", adminAJWT, map[string]any{
		"issuer":         "https://idp.example",
		"claim_name":     "groups",
		"claim_value":    "ml-platform",
		"virtual_key_id": vkA.ID,
	}, nil)
	if status != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate JWT key mapping, got %d", status)
	}

	// platform_admin creates mapping for org_b
	status, createdB := doJSONRequest(t, ts.URL, http.MethodPost, "/admin/v1/jwt-mappings", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":         "org_b",
		"issuer":         "https://idp.example",
		"claim_name":     "sub",
		"claim_value":    "svc-b",
		"virtual_key_id": vkB.ID,
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("expected 201 for platform_admin creating org_b mapping, got %d (%v)", status, createdB)
	}
	mappingBID, _ := createdB["id"].(string)

	// 5. org_viewer can list org_a mappings, sees only org_a (1 item), cannot list org_b
	status, listOut := doJSONRequest(t, ts.URL, http.MethodGet, "/admin/v1/jwt-mappings", viewerAJWT, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for org_viewer GET /admin/v1/jwt-mappings, got %d", status)
	}
	items, _ := listOut["data"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected org_a viewer to see 1 mapping, got %d (%v)", len(items), listOut)
	}

	status, _ = doJSONRequest(t, ts.URL, http.MethodGet, "/admin/v1/jwt-mappings?org_id=org_b", adminAJWT, nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 when org_a admin queries org_b mappings, got %d", status)
	}

	// platform_admin sees both mappings
	status, allOut := doJSONRequest(t, ts.URL, http.MethodGet, "/admin/v1/jwt-mappings", cfg.Auth.MasterAdminKey, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for platform_admin GET /admin/v1/jwt-mappings, got %d", status)
	}
	if allItems, _ := allOut["data"].([]any); len(allItems) != 2 {
		t.Fatalf("expected platform_admin to see 2 mappings, got %d", len(allItems))
	}

	// 6. org_admin of org_a cannot delete org_b's mapping (403)
	status, _ = doJSONRequest(t, ts.URL, http.MethodDelete, "/admin/v1/jwt-mappings/"+mappingBID, adminAJWT, nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 deleting org_b mapping as org_a admin, got %d", status)
	}

	// org_viewer cannot delete org_a's mapping (403)
	status, _ = doJSONRequest(t, ts.URL, http.MethodDelete, "/admin/v1/jwt-mappings/"+mappingAID, viewerAJWT, nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 deleting mapping as org_viewer, got %d", status)
	}

	// org_admin of org_a deletes org_a mapping (200)
	status, delOut := doJSONRequest(t, ts.URL, http.MethodDelete, "/admin/v1/jwt-mappings/"+mappingAID, adminAJWT, nil, nil)
	if status != http.StatusOK || delOut["status"] != "deleted" || delOut["id"] != mappingAID {
		t.Fatalf("expected 200 deleted status, got %d (%v)", status, delOut)
	}

	// Audit logs recorded created and deleted events
	logs, err := repo.ListAuditLogs(ctx, "org_a", 20)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	var sawCreated, sawDeleted bool
	for _, l := range logs {
		if l.Action == "jwt_mapping.created" && l.ResourceID == mappingAID {
			sawCreated = true
		}
		if l.Action == "jwt_mapping.deleted" && l.ResourceID == mappingAID {
			sawDeleted = true
		}
	}
	if !sawCreated || !sawDeleted {
		t.Fatalf("expected jwt_mapping.created and jwt_mapping.deleted audit logs (created=%v deleted=%v)", sawCreated, sawDeleted)
	}
}

func TestGatewayServer_DataPlaneOIDCMappingJITAndCustomHeader(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true})
	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:            "team_a",
		OrgID:         "org_a",
		Name:          "Team A",
		AllowedModels: []string{"openai/gpt-4.1"},
		IsActive:      true,
	})
	_ = repo.CreateMCPServer(ctx, &domain.MCPServer{
		ID:            "srv_a",
		OrgID:         "org_a",
		Name:          "Docs",
		Slug:          "docs",
		TransportType: domain.MCPTransportStreamableHTTP,
		EndpointURL:   "https://mcp.orga.example/mcp",
		IsActive:      true,
	})

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	oidcSrv := startServerOIDCTestProvider(t, "kid-srv", rsaPriv)

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-dataplane-oidc"
	cfg.Auth.EnableDataPlaneJWT = true
	cfg.Auth.CustomAPIKeyHeader = "X-Enterprise-Key"
	cfg.Auth.DefaultOrgID = "org_a"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.MCP.Enabled = true
	cfg.Auth.OIDCIssuers = []config.OIDCIssuerConfig{
		{
			Issuer:              oidcSrv.URL,
			Audience:            "ai-gateway",
			AllowedEmailDomains: []string{"orga.example"},
			AutoRegister:        true,
			DefaultOrgID:        "org_a",
			DefaultTeamID:       "team_a",
			DefaultRole:         "developer",
		},
	}

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	vk, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		Name:              "oidc-mapped-key",
		OrgID:             "org_a",
		TeamID:            "team_a",
		Role:              domain.RoleDeveloper,
		AllowedEndpoints:  []string{"/v1/*"}, // intentionally excludes /mcp
		AllowedMCPServers: []string{},
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	// Create JWT key mapping via Control Plane HTTP API
	status, _ := doJSONRequest(t, ts.URL, http.MethodPost, "/admin/v1/jwt-mappings", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":         "org_a",
		"issuer":         oidcSrv.URL,
		"claim_name":     "department",
		"claim_value":    "platform",
		"virtual_key_id": vk.ID,
	}, nil)
	if status != http.StatusCreated {
		t.Fatalf("expected 201 creating jwt mapping, got %d", status)
	}

	// 1. CustomAPIKeyHeader works on /v1/models
	status, _ = doJSONRequest(t, ts.URL, http.MethodGet, "/v1/models", "", nil, map[string]string{
		"X-Enterprise-Key": vk.RawKey,
	})
	if status != http.StatusOK {
		t.Fatalf("expected 200 on /v1/models via CustomAPIKeyHeader, got %d", status)
	}

	// 2. Mapped OIDC JWT works on /v1/models and respects mapped VirtualKey's AllowedEndpoints (/mcp returns 403)
	mappedJWT := signTestRS256JWT(t, rsaPriv, "kid-srv", map[string]any{
		"iss":        oidcSrv.URL,
		"sub":        "alice-sub",
		"aud":        "ai-gateway",
		"email":      "alice@orga.example",
		"department": "platform",
		"exp":        time.Now().UTC().Add(10 * time.Minute).Unix(),
	})
	status, _ = doJSONRequest(t, ts.URL, http.MethodGet, "/v1/models", mappedJWT, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 on /v1/models with mapped OIDC JWT, got %d", status)
	}
	status, _ = doJSONRequest(t, ts.URL, http.MethodPost, "/mcp", mappedJWT, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 on /mcp due to mapped key AllowedEndpoints, got %d", status)
	}

	// 3. Unmapped OIDC JWT triggers JIT user provisioning and succeeds on /v1/models and /mcp
	jitJWT := signTestRS256JWT(t, rsaPriv, "kid-srv", map[string]any{
		"iss":   oidcSrv.URL,
		"sub":   "bob-jit-sub",
		"aud":   "ai-gateway",
		"email": "bob@orga.example",
		"name":  "Bob JIT",
		"exp":   time.Now().UTC().Add(10 * time.Minute).Unix(),
	})
	status, _ = doJSONRequest(t, ts.URL, http.MethodGet, "/v1/models", jitJWT, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 on /v1/models with JIT OIDC JWT, got %d", status)
	}
	jitUser, err := repo.GetUserByOrgAndOIDCSubject(ctx, "org_a", "bob-jit-sub")
	if err != nil || jitUser == nil || jitUser.Email != "bob@orga.example" || jitUser.TeamID != "team_a" {
		t.Fatalf("expected JIT provisioned user in org_a/team_a, got user=%+v err=%v", jitUser, err)
	}

	// 4. Denied email domain returns 401
	badDomainJWT := signTestRS256JWT(t, rsaPriv, "kid-srv", map[string]any{
		"iss":   oidcSrv.URL,
		"sub":   "eve-sub",
		"aud":   "ai-gateway",
		"email": "eve@outsider.example",
		"exp":   time.Now().UTC().Add(10 * time.Minute).Unix(),
	})
	status, _ = doJSONRequest(t, ts.URL, http.MethodGet, "/v1/models", badDomainJWT, nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for disallowed email domain, got %d", status)
	}
}

func TestGatewayServer_DataPlaneDefaultsIntrospectionAndProxyAuth(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_x", Name: "Org X", Slug: "org-x", IsActive: true})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_x1",
		OrgID:       "org_x",
		Email:       "x1@orgx.example",
		Name:        "User X1",
		Role:        domain.RoleDeveloper,
		OIDCSubject: "sub-x1",
		IsActive:    true,
	})

	introspectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.FormValue("token") == "opaque-x1-token" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "sub-x1",
				"org_id": "org_x",
				"email":  "x1@orgx.example",
				"exp":    time.Now().UTC().Add(5 * time.Minute).Unix(),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
	}))
	defer introspectSrv.Close()

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-introspect-proxy"
	cfg.Auth.JWTSecret = "dataplane-disabled-secret"
	cfg.Auth.JWTIssuer = "https://idp.orgx.example"
	cfg.Auth.JWTAudience = "ai-gateway"
	cfg.Auth.DefaultOrgID = "org_x"
	// EnableDataPlaneJWT intentionally left false (fail-closed default)
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Auth.Introspection = config.IntrospectionConfig{
		TokenInfoEndpoint: introspectSrv.URL + "/introspect",
		ClientID:          "gw",
		ClientSecret:      "secret",
		Mode:              "introspect",
	}
	cfg.Auth.ProxyAuth = config.ProxyAuthConfig{
		Enabled:           true,
		TrustedProxyCIDRs: []string{"127.0.0.0/8", "::1/128"},
		HeaderMapping:     auth.DefaultProxyHeaderMapping(),
	}

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	// 1. EnableDataPlaneJWT=false rejects valid JWT on /v1/models
	jwtTok, _ := auth.SignHS256(cfg.Auth.JWTSecret, &auth.JWTClaims{
		Subject:   "sub-x1",
		Issuer:    cfg.Auth.JWTIssuer,
		Audience:  auth.AudienceClaim{cfg.Auth.JWTAudience},
		OrgID:     "org_x",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	status, _ := doJSONRequest(t, ts.URL, http.MethodGet, "/v1/models", jwtTok, nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 on /v1/models when EnableDataPlaneJWT=false, got %d", status)
	}

	// 2. Opaque Bearer token succeeds via Introspection
	status, _ = doJSONRequest(t, ts.URL, http.MethodGet, "/v1/models", "opaque-x1-token", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 on /v1/models with opaque introspection token, got %d", status)
	}

	// 3. Trusted reverse proxy headers succeed on /v1/models
	status, _ = doJSONRequest(t, ts.URL, http.MethodGet, "/v1/models", "", nil, map[string]string{
		"X-Auth-Request-Email": "x1@orgx.example",
		"X-Auth-Request-Org":   "org_x",
	})
	if status != http.StatusOK {
		t.Fatalf("expected 200 on /v1/models with trusted proxy headers, got %d", status)
	}
}
