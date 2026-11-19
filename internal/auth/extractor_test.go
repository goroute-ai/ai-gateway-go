package auth_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestExtractCredentials_PrecedenceAndOverrides(t *testing.T) {
	t.Run("Nil request returns empty without error", func(t *testing.T) {
		cred, err := auth.ExtractCredentials(nil, auth.ExtractorOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred != (auth.ExtractedCredentials{}) {
			t.Fatalf("expected empty ExtractedCredentials, got %+v", cred)
		}
	})

	t.Run("CustomHeaderName has highest precedence over x-goroute-api-key and conflicting primary headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("X-My-Gateway-Key", "  sk-gw-custom  ")
		req.Header.Set("x-goroute-api-key", "sk-gw-default-override")
		req.Header.Set("Authorization", "Bearer upstream-openai-key")
		req.Header.Set("x-api-key", "upstream-anthropic-key")

		cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{
			CustomHeaderName: " X-My-Gateway-Key ",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Token != "sk-gw-custom" || cred.Source != auth.CredentialSourceCustomHeader {
			t.Fatalf("got %+v, want token=sk-gw-custom source=%q", cred, auth.CredentialSourceCustomHeader)
		}
	})

	t.Run("x-goroute-api-key overrides conflicting primary headers when CustomHeaderName is absent or unset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("x-goroute-api-key", "  sk-gw-override  ")
		req.Header.Set("Authorization", "Bearer upstream-openai-key")
		req.Header.Set("x-goog-api-key", "upstream-gemini-key")

		cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{
			CustomHeaderName: "X-My-Gateway-Key",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Token != "sk-gw-override" || cred.Source != auth.CredentialSourceGatewayHeader {
			t.Fatalf("got %+v, want token=sk-gw-override source=%q", cred, auth.CredentialSourceGatewayHeader)
		}
	})

	t.Run("Whitespace-only override headers fall through to primary headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("X-My-Gateway-Key", "   ")
		req.Header.Set("x-goroute-api-key", "\t")
		req.Header.Set("Authorization", "Bearer sk-gw-bearer")

		cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{
			CustomHeaderName: "X-My-Gateway-Key",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Token != "sk-gw-bearer" || cred.Source != auth.CredentialSourceBearer {
			t.Fatalf("got %+v, want token=sk-gw-bearer source=%q", cred, auth.CredentialSourceBearer)
		}
	})
}

func TestExtractCredentials_AuthorizationFormats(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantToken  string
		wantSource auth.CredentialSource
	}{
		{
			name:       "Bearer standard",
			authHeader: "Bearer sk-gw-bearer-1",
			wantToken:  "sk-gw-bearer-1",
			wantSource: auth.CredentialSourceBearer,
		},
		{
			name:       "Bearer lowercase scheme with extra whitespace",
			authHeader: "  bearer   sk-gw-bearer-2  ",
			wantToken:  "sk-gw-bearer-2",
			wantSource: auth.CredentialSourceBearer,
		},
		{
			name:       "Bearer uppercase scheme with tab separator",
			authHeader: "BEARER\tsk-gw-bearer-3",
			wantToken:  "sk-gw-bearer-3",
			wantSource: auth.CredentialSourceBearer,
		},
		{
			name:       "Bearer with empty token is ignored",
			authHeader: "Bearer   ",
			wantToken:  "",
			wantSource: auth.CredentialSourceNone,
		},
		{
			name:       "Basic user:secret selects secret",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("apiuser:sk-gw-basic-secret")),
			wantToken:  "sk-gw-basic-secret",
			wantSource: auth.CredentialSourceBasic,
		},
		{
			name:       "Basic :secret selects secret",
			authHeader: "basic " + base64.StdEncoding.EncodeToString([]byte(":sk-gw-basic-only-secret")),
			wantToken:  "sk-gw-basic-only-secret",
			wantSource: auth.CredentialSourceBasic,
		},
		{
			name:       "Basic user: with empty secret falls back to user",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("sk-gw-basic-user:")),
			wantToken:  "sk-gw-basic-user",
			wantSource: auth.CredentialSourceBasic,
		},
		{
			name:       "Basic without colon uses decoded value",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("sk-gw-basic-raw")),
			wantToken:  "sk-gw-basic-raw",
			wantSource: auth.CredentialSourceBasic,
		},
		{
			name:       "Basic unpadded base64 with colon in secret",
			authHeader: "Basic " + base64.RawStdEncoding.EncodeToString([]byte("user:sk-gw:part1:part2")),
			wantToken:  "sk-gw:part1:part2",
			wantSource: auth.CredentialSourceBasic,
		},
		{
			name:       "Basic invalid base64 is ignored",
			authHeader: "Basic !!!not-valid-base64!!!",
			wantToken:  "",
			wantSource: auth.CredentialSourceNone,
		},
		{
			name:       "Basic empty colon is ignored",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte(":")),
			wantToken:  "",
			wantSource: auth.CredentialSourceNone,
		},
		{
			name:       "SigV4 standard Credential extraction",
			authHeader: "AWS4-HMAC-SHA256 Credential=sk-gw-sigv4-1/20261118/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef",
			wantToken:  "sk-gw-sigv4-1",
			wantSource: auth.CredentialSourceSigV4,
		},
		{
			name:       "SigV4 strips optional Bearer prefix in Credential",
			authHeader: "AWS4-HMAC-SHA256 Credential=Bearer sk-gw-sigv4-bearer/20261118/us-east-1/bedrock/aws4_request, SignedHeaders=host, Signature=abcdef",
			wantToken:  "sk-gw-sigv4-bearer",
			wantSource: auth.CredentialSourceSigV4,
		},
		{
			name:       "SigV4 strips case-insensitive bearer prefix when Credential is not first param",
			authHeader: "aws4-hmac-sha256 SignedHeaders=host, Credential=bearer sk-gw-sigv4-reordered/20261118/us-west-2/bedrock/aws4_request, Signature=1234",
			wantToken:  "sk-gw-sigv4-reordered",
			wantSource: auth.CredentialSourceSigV4,
		},
		{
			name:       "SigV4 Credential without slash",
			authHeader: "AWS4-HMAC-SHA256 Credential=sk-gw-sigv4-noslash",
			wantToken:  "sk-gw-sigv4-noslash",
			wantSource: auth.CredentialSourceSigV4,
		},
		{
			name:       "SigV4 empty Credential token is ignored",
			authHeader: "AWS4-HMAC-SHA256 Credential=/20261118/us-east-1/bedrock/aws4_request, Signature=1234",
			wantToken:  "",
			wantSource: auth.CredentialSourceNone,
		},
		{
			name:       "SigV4 empty Bearer token is ignored",
			authHeader: "AWS4-HMAC-SHA256 Credential=Bearer /20261118/us-east-1/bedrock/aws4_request",
			wantToken:  "",
			wantSource: auth.CredentialSourceNone,
		},
		{
			name:       "Unknown scheme is ignored",
			authHeader: "Digest username=\"alice\", realm=\"gw\"",
			wantToken:  "",
			wantSource: auth.CredentialSourceNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Header.Set("Authorization", tt.authHeader)

			cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cred.Token != tt.wantToken || cred.Source != tt.wantSource {
				t.Fatalf("got %+v, want token=%q source=%q", cred, tt.wantToken, tt.wantSource)
			}
		})
	}
}

func TestExtractCredentials_ProviderNativeHeaders(t *testing.T) {
	headers := []struct {
		name  string
		value string
	}{
		{name: "x-api-key", value: "sk-gw-anthropic-style"},
		{name: "x-goog-api-key", value: "sk-gw-gemini-style"},
		{name: "api-key", value: "sk-gw-azure-style"},
		{name: "Ocp-Apim-Subscription-Key", value: "sk-gw-azure-apim-style"},
	}

	for _, tc := range headers {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Header.Set(tc.name, "  "+tc.value+"  ")

			cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cred.Token != tc.value || cred.Source != auth.CredentialSourceHeaderKey {
				t.Fatalf("got %+v, want token=%q source=%q", cred, tc.value, auth.CredentialSourceHeaderKey)
			}
		})
	}
}

func TestExtractCredentials_GeminiQueryKey(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		wantToken  string
		wantSource auth.CredentialSource
	}{
		{
			name:       "generateContent suffix",
			method:     http.MethodPost,
			target:     "/v1/models/gemini-2.5-flash:generateContent?key=sk-gw-gem-1",
			wantToken:  "sk-gw-gem-1",
			wantSource: auth.CredentialSourceQuery,
		},
		{
			name:       "streamGenerateContent suffix",
			method:     http.MethodPost,
			target:     "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key=sk-gw-gem-2",
			wantToken:  "sk-gw-gem-2",
			wantSource: auth.CredentialSourceQuery,
		},
		{
			name:       "countTokens suffix",
			method:     http.MethodPost,
			target:     "/v1/models/gemini-2.5-pro:countTokens?key=sk-gw-gem-3",
			wantToken:  "sk-gw-gem-3",
			wantSource: auth.CredentialSourceQuery,
		},
		{
			name:       "v1beta prefix",
			method:     http.MethodGet,
			target:     "/v1beta/models?key=sk-gw-gem-4",
			wantToken:  "sk-gw-gem-4",
			wantSource: auth.CredentialSourceQuery,
		},
		{
			name:       "nested v1beta route",
			method:     http.MethodGet,
			target:     "/gemini/v1beta/models/gemini-2.5-flash?key=sk-gw-gem-5",
			wantToken:  "sk-gw-gem-5",
			wantSource: auth.CredentialSourceQuery,
		},
		{
			name:       "query key ignored on non-Gemini chat endpoint",
			method:     http.MethodPost,
			target:     "/v1/chat/completions?key=sk-gw-should-ignore",
			wantToken:  "",
			wantSource: auth.CredentialSourceNone,
		},
		{
			name:       "query key ignored on non-Gemini models endpoint",
			method:     http.MethodGet,
			target:     "/v1/models?key=sk-gw-should-ignore",
			wantToken:  "",
			wantSource: auth.CredentialSourceNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cred.Token != tt.wantToken || cred.Source != tt.wantSource {
				t.Fatalf("got %+v, want token=%q source=%q", cred, tt.wantToken, tt.wantSource)
			}
		})
	}

	t.Run("Conflicting Gemini header and query key are rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-2.5-flash:generateContent?key=query-key", nil)
		req.Header.Set("x-goog-api-key", "header-key")

		_, err := auth.ExtractCredentials(req, auth.ExtractorOptions{})
		var gatewayErr *domain.GatewayError
		if !errors.As(err, &gatewayErr) || gatewayErr.Code != "ambiguous_gateway_credentials" {
			t.Fatalf("expected ambiguous credentials error, got %v", err)
		}
	})

	t.Run("Custom override header wins over conflicting query and headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-2.5-flash:generateContent?key=query-key", nil)
		req.Header.Set("x-goog-api-key", "header-key")
		req.Header.Set("X-Proxy-API-Key", "override-key")

		cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{CustomHeaderName: "X-Proxy-API-Key"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Token != "override-key" || cred.Source != auth.CredentialSourceCustomHeader {
			t.Fatalf("got %+v, want override-key with custom_header source", cred)
		}
	})

	t.Run("Conflicting WebSocket subprotocol and query credentials are rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/realtime?api_key=sk-gw-query", nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Protocol", "realtime, openai-insecure-api-key.sk-gw-proto")

		_, err := auth.ExtractCredentials(req, auth.ExtractorOptions{})
		var gatewayErr *domain.GatewayError
		if !errors.As(err, &gatewayErr) || gatewayErr.Code != "ambiguous_gateway_credentials" {
			t.Fatalf("expected ambiguous credentials error, got %v", err)
		}
	})
}

func TestExtractCredentials_AmbiguityGuard(t *testing.T) {
	conflicts := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "Bearer vs x-api-key",
			headers: map[string]string{
				"Authorization": "Bearer sk-gw-a",
				"x-api-key":     "sk-gw-b",
			},
		},
		{
			name: "Bearer vs x-goog-api-key",
			headers: map[string]string{
				"Authorization":  "Bearer sk-gw-a",
				"x-goog-api-key": "sk-gw-b",
			},
		},
		{
			name: "Bearer vs api-key",
			headers: map[string]string{
				"Authorization": "Bearer sk-gw-a",
				"api-key":       "sk-gw-b",
			},
		},
		{
			name: "Bearer vs Ocp-Apim-Subscription-Key",
			headers: map[string]string{
				"Authorization":             "Bearer sk-gw-a",
				"Ocp-Apim-Subscription-Key": "sk-gw-b",
			},
		},
		{
			name: "Basic vs x-api-key",
			headers: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("u:sk-gw-a")),
				"x-api-key":     "sk-gw-b",
			},
		},
		{
			name: "SigV4 vs api-key",
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=sk-gw-a/20261118/us-east-1/bedrock/aws4_request",
				"api-key":       "sk-gw-b",
			},
		},
		{
			name: "x-api-key vs x-goog-api-key",
			headers: map[string]string{
				"x-api-key":      "sk-gw-a",
				"x-goog-api-key": "sk-gw-b",
			},
		},
		{
			name: "api-key vs Ocp-Apim-Subscription-Key",
			headers: map[string]string{
				"api-key":                   "sk-gw-a",
				"Ocp-Apim-Subscription-Key": "sk-gw-b",
			},
		},
	}

	for _, tc := range conflicts {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{})
			if err == nil {
				t.Fatalf("expected ambiguous_gateway_credentials error, got %+v", cred)
			}
			gwErr, ok := err.(*domain.GatewayError)
			if !ok || gwErr.StatusCode != http.StatusBadRequest || gwErr.Code != "ambiguous_gateway_credentials" {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}

	t.Run("Identical values across Authorization and multiple provider headers succeed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer sk-gw-same")
		req.Header.Set("x-api-key", "sk-gw-same")
		req.Header.Set("x-goog-api-key", "sk-gw-same")

		cred, err := auth.ExtractCredentials(req, auth.ExtractorOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Token != "sk-gw-same" || cred.Source != auth.CredentialSourceBearer {
			t.Fatalf("got %+v, want token=sk-gw-same source=%q", cred, auth.CredentialSourceBearer)
		}
	})
}

func TestMiddlewares_CustomAPIKeyHeaderAndSources(t *testing.T) {
	ctx := t.Context()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org_ext", Name: "Extractor Org", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:          "usr_ext_admin",
		OrgID:       "org_ext",
		Email:       "admin@ext.io",
		Name:        "Ext Admin",
		Role:        domain.RoleOrgAdmin,
		OIDCSubject: "sub-ext-admin",
		IsActive:    true,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	svc := auth.NewService(repo, nil, "sk-gw-master-ext-secret", time.Minute, time.Minute)
	svc.SetCustomAPIKeyHeader("X-Custom-Gateway-Key")
	jwtSecret := "ext-jwt-secret"
	svc.SetJWTVerifier(auth.NewJWTVerifier(auth.JWTConfig{Secret: jwtSecret}))

	devVK, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_ext",
		Name:  "Dev Key",
		Role:  domain.RoleDeveloper,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey(dev): %v", err)
	}

	adminVK, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_ext",
		Name:  "Admin Key",
		Role:  domain.RoleOrgAdmin,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey(admin): %v", err)
	}

	jwtTok, err := auth.SignHS256(jwtSecret, &auth.JWTClaims{
		Subject:   "sub-ext-admin",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("SignHS256: %v", err)
	}

	rbac := auth.NewRBACEngine(repo)
	dpMW := auth.DataPlaneMiddleware(svc, rbac)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.IdentityFromContext(r.Context()) == nil {
			http.Error(w, "missing identity", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("DataPlaneMiddleware accepts custom header overriding conflicting primary headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("X-Custom-Gateway-Key", devVK.RawKey)
		req.Header.Set("Authorization", "Bearer invalid-upstream-a")
		req.Header.Set("x-api-key", "invalid-upstream-b")
		rec := httptest.NewRecorder()
		dpMW.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("DataPlaneMiddleware accepts Basic, SigV4, provider headers, and Gemini query key", func(t *testing.T) {
		cases := []struct {
			name   string
			target string
			header [2]string
		}{
			{
				name:   "Basic",
				target: "/v1/chat/completions",
				header: [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("client:"+devVK.RawKey))},
			},
			{
				name:   "SigV4",
				target: "/v1/chat/completions",
				header: [2]string{"Authorization", "AWS4-HMAC-SHA256 Credential=Bearer " + devVK.RawKey + "/20261118/us-east-1/bedrock/aws4_request, SignedHeaders=host"},
			},
			{
				name:   "x-goog-api-key",
				target: "/v1beta/models/gemini-2.5-flash:generateContent",
				header: [2]string{"x-goog-api-key", devVK.RawKey},
			},
			{
				name:   "api-key",
				target: "/v1/chat/completions",
				header: [2]string{"api-key", devVK.RawKey},
			},
			{
				name:   "Ocp-Apim-Subscription-Key",
				target: "/v1/chat/completions",
				header: [2]string{"Ocp-Apim-Subscription-Key", devVK.RawKey},
			},
			{
				name:   "Gemini query key",
				target: "/v1beta/models/gemini-2.5-flash:generateContent?key=" + devVK.RawKey,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, tc.target, nil)
				if tc.header[0] != "" {
					req.Header.Set(tc.header[0], tc.header[1])
				}
				rec := httptest.NewRecorder()
				dpMW.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
				}
			})
		}
	})

	t.Run("DataPlaneMiddleware returns 400 on conflicting primary headers without override", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+devVK.RawKey)
		req.Header.Set("x-goog-api-key", "sk-gw-different")
		rec := httptest.NewRecorder()
		dpMW.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	admMW := auth.AdminControlPlaneMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.OperatorFromContext(r.Context()) == nil {
			http.Error(w, "missing operator", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("AdminControlPlaneMiddleware accepts admin VK via custom header and rejects JWT outside Bearer", func(t *testing.T) {
		reqOK := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
		reqOK.Header.Set("X-Custom-Gateway-Key", adminVK.RawKey)
		recOK := httptest.NewRecorder()
		admMW.ServeHTTP(recOK, reqOK)
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200 for admin VK in custom header, got %d (%s)", recOK.Code, recOK.Body.String())
		}

		reqJWTCustom := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
		reqJWTCustom.Header.Set("X-Custom-Gateway-Key", jwtTok)
		recJWTCustom := httptest.NewRecorder()
		admMW.ServeHTTP(recJWTCustom, reqJWTCustom)
		if recJWTCustom.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for JWT in custom header, got %d (%s)", recJWTCustom.Code, recJWTCustom.Body.String())
		}
	})
}
