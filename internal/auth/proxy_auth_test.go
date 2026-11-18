package auth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestProxyAuthenticator_TrustedCIDRsAndIdentityExtraction(t *testing.T) {
	pa, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
		Enabled:           true,
		TrustedProxyCIDRs: []string{"10.0.0.0/8", "fd00::/8"},
		HeaderMapping:     auth.DefaultProxyHeaderMapping(),
	})
	if err != nil {
		t.Fatalf("NewProxyAuthenticator failed: %v", err)
	}
	if !pa.Enabled() {
		t.Fatal("expected Enabled() to be true")
	}

	t.Run("trusted IPv4 socket extracts identity headers and ignores unmapped privilege headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.RemoteAddr = "10.24.8.15:54321"
		req.Header.Set("X-Auth-Request-User", "  usr_alice  ")
		req.Header.Set("X-Auth-Request-Email", "alice@example.com")
		req.Header.Set("X-Auth-Request-Team", "team_eng")
		req.Header.Set("X-Auth-Request-Org", "org_acme")
		// Attempted privilege injection headers not in allowlist must be ignored.
		req.Header.Set("X-Role", "platform_admin")
		req.Header.Set("X-Budget", "999999999")
		req.Header.Set("X-RPM", "100000")
		req.Header.Set("X-TPM", "10000000")
		req.Header.Set("X-Permissions", "*")
		req.Header.Set("X-Allowed-Models", "*")

		id, err := pa.Authenticate(req)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}
		if id.UserID != "usr_alice" || id.UserEmail != "alice@example.com" || id.TeamID != "team_eng" || id.OrgID != "org_acme" {
			t.Fatalf("unexpected ProxyIdentity: %+v", id)
		}
		if id.SourceIP != "10.24.8.15" {
			t.Fatalf("expected SourceIP 10.24.8.15, got %q", id.SourceIP)
		}
	})

	t.Run("trusted IPv6 socket", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.RemoteAddr = "[fd00:1::42]:443"
		req.Header.Set("x-auth-request-user", "usr_v6")

		id, err := pa.Authenticate(req)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}
		if id.UserID != "usr_v6" || id.SourceIP != "fd00:1::42" {
			t.Fatalf("unexpected ProxyIdentity for IPv6: %+v", id)
		}
	})

	t.Run("trusted IPv4-mapped IPv6 socket matches IPv4 CIDR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.RemoteAddr = "[::ffff:10.1.2.3]:8080"
		req.Header.Set("X-Auth-Request-Email", "mapped@example.com")

		id, err := pa.Authenticate(req)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}
		if id.UserEmail != "mapped@example.com" || id.SourceIP != "10.1.2.3" {
			t.Fatalf("unexpected ProxyIdentity for IPv4-mapped IPv6: %+v", id)
		}
	})

	t.Run("untrusted RemoteAddr rejected even when X-Forwarded-For spoofs trusted IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.RemoteAddr = "203.0.113.99:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-IP", "10.0.0.1")
		req.Header.Set("Forwarded", "for=10.0.0.1")
		req.Header.Set("X-Auth-Request-User", "spoofed-admin")

		id, err := pa.Authenticate(req)
		if id != nil {
			t.Fatalf("expected nil identity for untrusted caller, got %+v", id)
		}
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) {
			t.Fatalf("expected *domain.GatewayError, got %T (%v)", err, err)
		}
		if gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "untrusted_proxy" {
			t.Fatalf("expected 403 untrusted_proxy, got %d %s", gwErr.StatusCode, gwErr.Code)
		}
	})
}

func TestProxyAuthenticator_FailClosedCases(t *testing.T) {
	t.Run("empty TrustedProxyCIDRs fails closed", func(t *testing.T) {
		pa, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: nil,
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
		})
		if err != nil {
			t.Fatalf("NewProxyAuthenticator failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.RemoteAddr = "127.0.0.1:8080"
		req.Header.Set("X-Auth-Request-User", "usr_local")

		_, err = pa.Authenticate(req)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "untrusted_proxy" {
			t.Fatalf("expected 403 untrusted_proxy fail-closed, got %v", err)
		}
		if pa.IsTrustedSource("127.0.0.1:8080") {
			t.Fatal("expected IsTrustedSource to return false when TrustedProxyCIDRs is empty")
		}
	})

	t.Run("disabled config fails closed", func(t *testing.T) {
		pa, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           false,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
		})
		if err != nil {
			t.Fatalf("NewProxyAuthenticator failed: %v", err)
		}
		if pa.Enabled() {
			t.Fatal("expected Enabled() to be false")
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		req.Header.Set("X-Auth-Request-User", "usr_1")

		_, err = pa.Authenticate(req)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "proxy_auth_disabled" {
			t.Fatalf("expected 401 proxy_auth_disabled, got %v", err)
		}
	})

	t.Run("missing identity headers from trusted proxy fails closed", func(t *testing.T) {
		pa, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
		})
		if err != nil {
			t.Fatalf("NewProxyAuthenticator failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.RemoteAddr = "10.0.0.5:1234"

		_, err = pa.Authenticate(req)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != "missing_proxy_identity" {
			t.Fatalf("expected 401 missing_proxy_identity, got %v", err)
		}
	})

	t.Run("invalid or empty RemoteAddr fails closed", func(t *testing.T) {
		pa, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
		})
		if err != nil {
			t.Fatalf("NewProxyAuthenticator failed: %v", err)
		}

		for _, addr := range []string{"", "not-an-ip", "999.999.999.999:80"} {
			req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			req.RemoteAddr = addr
			req.Header.Set("X-Auth-Request-User", "usr_1")
			_, err := pa.Authenticate(req)
			var gwErr *domain.GatewayError
			if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden {
				t.Fatalf("expected 403 for RemoteAddr=%q, got %v", addr, err)
			}
		}
	})

	t.Run("nil request fails closed", func(t *testing.T) {
		pa, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
		})
		if err != nil {
			t.Fatalf("NewProxyAuthenticator failed: %v", err)
		}
		if _, err := pa.Authenticate(nil); err == nil {
			t.Fatal("expected error for nil request")
		}
	})

	t.Run("conflicting duplicate proxy header values fail closed", func(t *testing.T) {
		pa, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
		})
		if err != nil {
			t.Fatalf("NewProxyAuthenticator failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.RemoteAddr = "10.0.0.2:443"
		req.Header.Add("X-Auth-Request-User", "alice")
		req.Header.Add("X-Auth-Request-User", "bob")

		_, err = pa.Authenticate(req)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusBadRequest || gwErr.Code != "ambiguous_proxy_headers" {
			t.Fatalf("expected 400 ambiguous_proxy_headers, got %v", err)
		}
	})

	t.Run("control characters in proxy header fail closed", func(t *testing.T) {
		pa, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
		})
		if err != nil {
			t.Fatalf("NewProxyAuthenticator failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.RemoteAddr = "10.0.0.2:443"
		req.Header["X-Auth-Request-User"] = []string{"alice\r\nX-Injected: true"}

		_, err = pa.Authenticate(req)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusBadRequest || gwErr.Code != "invalid_proxy_header" {
			t.Fatalf("expected 400 invalid_proxy_header, got %v", err)
		}
	})
}

func TestProxyAuthConfig_StrictAllowlistAndValidation(t *testing.T) {
	disallowedTargets := []string{
		"role",
		"budget",
		"max_budget_micros",
		"rpm",
		"tpm",
		"permissions",
		"allowed_models",
		"allowed_endpoints",
		"is_admin",
		"",
	}

	for _, target := range disallowedTargets {
		cfg := auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			HeaderMapping: map[string]string{
				"X-Auth-Request-User": "user_id",
				"X-Custom-Claim":      target,
			},
		}
		if _, err := auth.NewProxyAuthenticator(cfg); err == nil {
			t.Fatalf("expected NewProxyAuthenticator to reject privileged/disallowed target %q", target)
		}
		if auth.IsAllowedProxyAttribute(target) {
			t.Fatalf("expected IsAllowedProxyAttribute(%q) == false", target)
		}
	}

	for _, allowed := range []string{"user_id", "user_email", "team_id", "org_id", " USER_ID ", "Org_Id"} {
		if !auth.IsAllowedProxyAttribute(allowed) {
			t.Fatalf("expected IsAllowedProxyAttribute(%q) == true", allowed)
		}
	}

	t.Run("malformed CIDR rejected", func(t *testing.T) {
		_, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.1"}, // missing prefix length
			HeaderMapping:     auth.DefaultProxyHeaderMapping(),
		})
		if err == nil {
			t.Fatal("expected error for non-CIDR entry")
		}
	})

	t.Run("conflicting canonical header mapping rejected", func(t *testing.T) {
		_, err := auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
			HeaderMapping: map[string]string{
				"x-proxy-user": "user_id",
				"X-Proxy-User": "org_id",
			},
		})
		if err == nil {
			t.Fatal("expected error for conflicting canonical header mappings")
		}
	})

	t.Run("ExtractProxyIdentity helper works end-to-end", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.RemoteAddr = "192.168.10.5:9000"
		req.Header.Set("X-Proxy-User", "usr_helper")

		id, err := auth.ExtractProxyIdentity(req, auth.ProxyAuthConfig{
			Enabled:           true,
			TrustedProxyCIDRs: []string{"192.168.10.0/24"},
			HeaderMapping:     map[string]string{"X-Proxy-User": "user_id"},
		})
		if err != nil {
			t.Fatalf("ExtractProxyIdentity failed: %v", err)
		}
		if id.UserID != "usr_helper" {
			t.Fatalf("expected usr_helper, got %q", id.UserID)
		}
	})
}
