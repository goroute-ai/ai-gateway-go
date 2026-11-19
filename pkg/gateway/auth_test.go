package gateway_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func TestCustomAuthModeParsing(t *testing.T) {
	cases := []struct {
		raw     string
		want    gateway.CustomAuthMode
		wantErr bool
	}{
		{raw: "", want: gateway.CustomAuthModeOff},
		{raw: "off", want: gateway.CustomAuthModeOff},
		{raw: " ON ", want: gateway.CustomAuthModeOn},
		{raw: "Auto", want: gateway.CustomAuthModeAuto},
		{raw: "invalid", wantErr: true},
	}

	for _, tc := range cases {
		got, err := gateway.ParseCustomAuthMode(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseCustomAuthMode(%q): expected error, got %q", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseCustomAuthMode(%q) unexpected error: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("ParseCustomAuthMode(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		if !got.Valid() {
			t.Fatalf("expected mode %q to be valid", got)
		}
	}

	if gateway.CustomAuthMode("bogus").Valid() {
		t.Fatal("expected bogus mode to be invalid")
	}
}

func TestEvaluateCustomAuth_OffMode(t *testing.T) {
	called := false
	auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
		called = true
		return nil, &domain.GatewayError{StatusCode: http.StatusUnauthorized, Code: "should_not_run"}
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	for _, mode := range []gateway.CustomAuthMode{gateway.CustomAuthModeOff, ""} {
		decision, err := gateway.EvaluateCustomAuth(context.Background(), req, mode, auth)
		if err != nil {
			t.Fatalf("mode=%q: unexpected error: %v", mode, err)
		}
		if decision != nil {
			t.Fatalf("mode=%q: expected nil decision (standard auth fallback), got %+v", mode, decision)
		}
		if called {
			t.Fatalf("mode=%q: authenticator should not be called when disabled", mode)
		}
	}
}

func TestEvaluateCustomAuth_OnMode(t *testing.T) {
	t.Run("direct IdentityContext with RunPostChecks", func(t *testing.T) {
		type ctxKey string
		const key ctxKey = "trace"
		var seenTrace string

		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			seenTrace, _ = ctx.Value(key).(string)
			return &gateway.AuthDecision{
				Identity: &domain.IdentityContext{
					OrgID:  "org_1",
					UserID: "usr_1",
					Role:   domain.RoleDeveloper,
				},
				RunPostChecks: true,
			}, nil
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		ctx := context.WithValue(context.Background(), key, "trace-123")
		decision, err := gateway.EvaluateCustomAuth(ctx, req, gateway.CustomAuthModeOn, auth)
		if err != nil {
			t.Fatalf("EvaluateCustomAuth failed: %v", err)
		}
		if seenTrace != "trace-123" {
			t.Fatalf("expected context value trace-123, got %q", seenTrace)
		}
		if decision == nil || decision.Identity == nil || decision.Identity.OrgID != "org_1" || !decision.RunPostChecks {
			t.Fatalf("unexpected AuthDecision: %+v", decision)
		}
	})

	t.Run("virtual key decision trims whitespace", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return &gateway.AuthDecision{
				VirtualKey:    "  sk-gw-custom-mapped-key  ",
				RunPostChecks: false,
			}, nil
		})

		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		decision, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeOn, auth)
		if err != nil {
			t.Fatalf("EvaluateCustomAuth failed: %v", err)
		}
		if decision.VirtualKey != "sk-gw-custom-mapped-key" || decision.RunPostChecks {
			t.Fatalf("unexpected AuthDecision: %+v", decision)
		}
	})

	t.Run("nil authenticator fails closed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		_, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeOn, nil)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "custom_auth_unavailable" {
			t.Fatalf("expected 401 custom_auth_unavailable, got %v", err)
		}
	})

	t.Run("nil decision abstention fails closed", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return nil, nil
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		_, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeOn, auth)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "custom_auth_rejected" {
			t.Fatalf("expected 401 custom_auth_rejected, got %v", err)
		}
	})

	t.Run("non-GatewayError fails closed", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return nil, errors.New("upstream auth backend unreachable")
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		_, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeOn, auth)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "custom_auth_failed" {
			t.Fatalf("expected 401 custom_auth_failed, got %v", err)
		}
	})

	t.Run("GatewayError is preserved", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "tenant_suspended",
				Message:    "Tenant access suspended",
			}
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		_, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeOn, auth)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "tenant_suspended" {
			t.Fatalf("expected 403 tenant_suspended, got %v", err)
		}
	})

	t.Run("empty or ambiguous AuthDecision fails closed", func(t *testing.T) {
		emptyAuth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return &gateway.AuthDecision{}, nil
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		_, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeOn, emptyAuth)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "invalid_custom_auth_decision" {
			t.Fatalf("expected invalid_custom_auth_decision, got %v", err)
		}

		ambiguousAuth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return &gateway.AuthDecision{
				Identity:   &domain.IdentityContext{OrgID: "org_1"},
				VirtualKey: "sk-gw-123",
			}, nil
		})
		_, err = gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeOn, ambiguousAuth)
		if !errors.As(err, &gwErr) || gwErr.Code != "ambiguous_custom_auth_decision" {
			t.Fatalf("expected ambiguous_custom_auth_decision, got %v", err)
		}
	})
}

func TestEvaluateCustomAuth_AutoMode(t *testing.T) {
	t.Run("succeeds when custom authenticator returns decision", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return &gateway.AuthDecision{
				Identity:      &domain.IdentityContext{OrgID: "org_auto", UserID: "usr_auto"},
				RunPostChecks: true,
			}, nil
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		decision, err := gateway.EvaluateCustomAuth(nil, req, gateway.CustomAuthModeAuto, auth)
		if err != nil {
			t.Fatalf("EvaluateCustomAuth failed: %v", err)
		}
		if decision == nil || decision.Identity == nil || decision.Identity.OrgID != "org_auto" {
			t.Fatalf("unexpected AuthDecision: %+v", decision)
		}
	})

	t.Run("falls back to standard auth when authenticator is nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		decision, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeAuto, nil)
		if err != nil || decision != nil {
			t.Fatalf("expected (nil, nil) fallback, got (%+v, %v)", decision, err)
		}
	})

	t.Run("falls back to standard auth when authenticator abstains with nil decision", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return nil, nil
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		decision, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeAuto, auth)
		if err != nil || decision != nil {
			t.Fatalf("expected (nil, nil) fallback on abstention, got (%+v, %v)", decision, err)
		}
	})

	t.Run("falls back to standard auth on non-GatewayError", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return nil, errors.New("not a custom token")
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		decision, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeAuto, auth)
		if err != nil || decision != nil {
			t.Fatalf("expected (nil, nil) fallback on non-GatewayError, got (%+v, %v)", decision, err)
		}
	})

	t.Run("fails closed on GatewayError", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return nil, fmt.Errorf("auth failure: %w", &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_custom_token",
				Message:    "Custom token signature invalid",
			})
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		decision, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeAuto, auth)
		if decision != nil {
			t.Fatalf("expected nil decision on GatewayError, got %+v", decision)
		}
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "invalid_custom_token" {
			t.Fatalf("expected 401 invalid_custom_token, got %v", err)
		}
	})

	t.Run("fails closed on malformed non-nil decision even in auto mode", func(t *testing.T) {
		auth := gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			return &gateway.AuthDecision{}, nil
		})
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		_, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthModeAuto, auth)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "invalid_custom_auth_decision" {
			t.Fatalf("expected invalid_custom_auth_decision, got %v", err)
		}
	})
}

func TestEvaluateCustomAuth_InvalidInputs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	_, err := gateway.EvaluateCustomAuth(context.Background(), req, gateway.CustomAuthMode("unknown"), nil)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_custom_auth_mode" {
		t.Fatalf("expected invalid_custom_auth_mode, got %v", err)
	}

	_, err = gateway.EvaluateCustomAuth(context.Background(), nil, gateway.CustomAuthModeOn, nil)
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_request" {
		t.Fatalf("expected invalid_request for nil http.Request, got %v", err)
	}
}

func TestWithCustomAuthenticator_EmbeddedHTTP(t *testing.T) {
	mockGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"custom-auth-ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8}}`)
	}))
	defer mockGemini.Close()

	t.Run("rejects remote gateway combination", func(t *testing.T) {
		_, err := gateway.New(
			gateway.WithRemote("https://gateway.example.com", "sk-gw-remote"),
			gateway.WithCustomAuthenticator(gateway.CustomAuthModeOn, gateway.CustomAuthenticatorFunc(func(context.Context, *http.Request) (*gateway.AuthDecision, error) {
				return nil, nil
			})),
		)
		if err == nil {
			t.Fatal("expected WithRemote + WithCustomAuthenticator to fail")
		}
	})

	t.Run("on mode enforces RunPostChecks, VirtualKey, and active org", func(t *testing.T) {
		var mode string
		gw, err := gateway.New(
			gateway.WithSilentLogs(),
			gateway.WithAllowPrivateNetworks(),
			gateway.WithModelList(gateway.ModelEntry{
				ModelName: "fast",
				Model:     "gemini/gemini-2.5-flash",
				APIKey:    "dummy-gemini-key",
				APIBase:   mockGemini.URL,
			}),
			gateway.WithCustomAuthenticator(gateway.CustomAuthModeOn, gateway.CustomAuthenticatorFunc(func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
				switch r.Header.Get("X-Test-Scenario") {
				case "post-checks-deny":
					return &gateway.AuthDecision{
						Identity: &domain.IdentityContext{
							OrgID:            "org_default",
							KeyPrefix:        "sk-cust-1",
							Role:             domain.RoleDeveloper,
							KeyAllowedModels: []string{"other-model"},
						},
						RunPostChecks: true,
					}, nil
				case "skip-inline-checks":
					return &gateway.AuthDecision{
						Identity: &domain.IdentityContext{
							OrgID:            "org_default",
							KeyPrefix:        "sk-cust-2",
							Role:             domain.RoleDeveloper,
							KeyAllowedModels: []string{"other-model"},
						},
						RunPostChecks: false,
					}, nil
				case "inactive-org":
					return &gateway.AuthDecision{
						Identity: &domain.IdentityContext{
							OrgID: "missing_org",
							Role:  domain.RoleDeveloper,
						},
						RunPostChecks: true,
					}, nil
				case "bad-vk":
					return &gateway.AuthDecision{VirtualKey: "not-a-gateway-key"}, nil
				default:
					return &gateway.AuthDecision{
						VirtualKey: mode,
					}, nil
				}
			})),
		)
		if err != nil {
			t.Fatalf("gateway.New failed: %v", err)
		}
		defer gw.Close()
		mode = issuedKeyRaw(t, gw)

		ctx := context.Background()
		reqPost := func(scenario string) *http.Response {
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.BaseURL()+"/v1/chat/completions", bytes.NewBufferString(`{"model":"fast","messages":[{"role":"user","content":"hi"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Test-Scenario", scenario)
			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			return resp
		}

		// RunPostChecks=true enforces KeyAllowedModels -> 403
		r1 := reqPost("post-checks-deny")
		r1.Body.Close()
		if r1.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 when RunPostChecks enforces KeyAllowedModels, got %d", r1.StatusCode)
		}

		// RunPostChecks=false ignores inline KeyAllowedModels -> 200
		r2 := reqPost("skip-inline-checks")
		b2, _ := io.ReadAll(r2.Body)
		r2.Body.Close()
		if r2.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 when RunPostChecks=false on active org, got %d: %s", r2.StatusCode, string(b2))
		}

		// Inactive/missing org is still rejected -> 403
		r3 := reqPost("inactive-org")
		r3.Body.Close()
		if r3.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for missing/inactive org, got %d", r3.StatusCode)
		}

		// Invalid VirtualKey prefix rejected -> 401
		r4 := reqPost("bad-vk")
		r4.Body.Close()
		if r4.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for non-sk-gw VirtualKey, got %d", r4.StatusCode)
		}

		// Valid VirtualKey resolves via standard virtual key auth -> 200
		r5 := reqPost("valid-vk")
		r5.Body.Close()
		if r5.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 when VirtualKey resolves through AuthService, got %d", r5.StatusCode)
		}
	})

	t.Run("auto mode abstains to standard virtual key auth", func(t *testing.T) {
		gw, err := gateway.New(
			gateway.WithSilentLogs(),
			gateway.WithAllowPrivateNetworks(),
			gateway.WithModelList(gateway.ModelEntry{
				ModelName: "fast",
				Model:     "gemini/gemini-2.5-flash",
				APIKey:    "dummy-gemini-key",
				APIBase:   mockGemini.URL,
			}),
			gateway.WithCustomAuthenticator(gateway.CustomAuthModeAuto, gateway.CustomAuthenticatorFunc(func(context.Context, *http.Request) (*gateway.AuthDecision, error) {
				return nil, nil
			})),
		)
		if err != nil {
			t.Fatalf("gateway.New failed: %v", err)
		}
		defer gw.Close()
		res, err := gw.Chat(context.Background(), "fast", "hello")
		if err != nil || res.Content != "custom-auth-ok" {
			t.Fatalf("expected fallback to default virtual key to succeed, got res=%+v err=%v", res, err)
		}
	})
}

func issuedKeyRaw(t *testing.T, gw *gateway.Client) string {
	t.Helper()
	vk, err := gw.IssueVirtualKey(context.Background(), domain.VirtualKey{
		OrgID:         "org_default",
		Name:          "custom-auth-vk",
		Role:          domain.RoleDeveloper,
		AllowedModels: []string{"fast"},
	})
	if err != nil || vk == nil || vk.RawKey == "" {
		t.Fatalf("IssueVirtualKey failed: vk=%+v err=%v", vk, err)
	}
	return vk.RawKey
}

func TestWithKeyRotationSecretSink(t *testing.T) {
	sink := gateway.KeySecretSinkFunc(func(_ context.Context, _ gateway.KeyRotatedSecretEvent) error {
		return nil
	})
	client, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithKeyRotationSecretSink(sink),
	)
	if err != nil {
		t.Fatalf("gateway.New(WithKeyRotationSecretSink): %v", err)
	}
	defer client.Close()
	client.SetKeyRotationSecretSink(sink)
}
