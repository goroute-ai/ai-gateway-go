package azure

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestAzureManagedIdentity_DisabledByDefault(t *testing.T) {
	ts := NewManagedIdentityTokenSource(ManagedIdentityConfig{})
	if _, err := ts.GetToken(context.Background()); !errors.Is(err, ErrAmbientIAMDisabled) {
		t.Fatalf("expected ErrAmbientIAMDisabled when disabled, got %v", err)
	}

	strat := &AzureAuthStrategy{}
	req, _ := http.NewRequest(http.MethodPost, "https://my-resource.openai.azure.com/openai/v1/chat/completions", nil)
	if err := strat.ApplyAuth(req, &domain.ProviderCredential{DecryptedAPIKey: ""}); err == nil {
		t.Fatal("expected AzureAuthStrategy to reject empty API key when AllowAmbientCloudIAM is false")
	}
	if err := strat.ApplyAuth(req, &domain.ProviderCredential{DecryptedAPIKey: "managed_identity"}); err == nil {
		t.Fatal("expected AzureAuthStrategy to reject managed_identity sentinel when AllowAmbientCloudIAM is false")
	}
}

func TestAzureManagedIdentity_IdentityEndpointRetryAndCache(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if r.Header.Get("X-IDENTITY-HEADER") != "secret-identity-hdr" {
			t.Fatalf("missing X-IDENTITY-HEADER, got %q", r.Header.Get("X-IDENTITY-HEADER"))
		}
		q := r.URL.Query()
		if q.Get("api-version") != "2019-08-01" {
			t.Fatalf("unexpected api-version: %q", q.Get("api-version"))
		}
		if q.Get("client_id") != "mi-client-123" {
			t.Fatalf("unexpected client_id: %q", q.Get("client_id"))
		}
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("transient unavailable"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "azure-msi-bearer-token",
			"expires_in":   "3600",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	t.Setenv("IDENTITY_ENDPOINT", srv.URL+"/msi/token")
	t.Setenv("IDENTITY_HEADER", "secret-identity-hdr")
	t.Setenv("AZURE_CLIENT_ID", "mi-client-123")

	ts := NewManagedIdentityTokenSource(ManagedIdentityConfig{
		AllowAmbientCloudIAM: true,
		MaxRetries:           3,
		RetryBaseDelay:       5 * time.Millisecond,
	})

	strat := &AzureAuthStrategy{
		AllowAmbientCloudIAM: true,
		ManagedIdentity:      ts,
	}

	req1, _ := http.NewRequest(http.MethodPost, "https://my-resource.openai.azure.com/openai/v1/chat/completions", nil)
	if err := strat.ApplyAuth(req1, &domain.ProviderCredential{DecryptedAPIKey: "managed_identity"}); err != nil {
		t.Fatalf("ApplyAuth 1 failed: %v", err)
	}
	if req1.Header.Get("Authorization") != "Bearer azure-msi-bearer-token" {
		t.Fatalf("unexpected Authorization header: %q", req1.Header.Get("Authorization"))
	}

	// Second call hits L1 cache without calling MSI endpoint again.
	req2, _ := http.NewRequest(http.MethodPost, "https://my-resource.openai.azure.com/openai/v1/chat/completions", nil)
	if err := strat.ApplyAuth(req2, &domain.ProviderCredential{DecryptedAPIKey: ""}); err != nil {
		t.Fatalf("ApplyAuth 2 failed: %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected 2 total HTTP attempts (1 retry + 1 success, then cached), got %d", attempts.Load())
	}
}

func TestAzureManagedIdentity_LegacyMSIEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Secret") != "legacy-msi-secret" {
			t.Fatalf("missing Secret header, got %q", r.Header.Get("Secret"))
		}
		if r.URL.Query().Get("api-version") != "2017-09-01" {
			t.Fatalf("unexpected api-version: %q", r.URL.Query().Get("api-version"))
		}
		expOn := time.Now().UTC().Add(30 * time.Minute).Unix()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "legacy-msi-token",
			"expires_on":   expOn,
		})
	}))
	defer srv.Close()

	t.Setenv("IDENTITY_ENDPOINT", "")
	t.Setenv("IDENTITY_HEADER", "")
	t.Setenv("MSI_ENDPOINT", srv.URL)
	t.Setenv("MSI_SECRET", "legacy-msi-secret")

	ts := NewManagedIdentityTokenSource(ManagedIdentityConfig{
		AllowAmbientCloudIAM: true,
	})
	tok, err := ts.GetToken(context.Background())
	if err != nil {
		t.Fatalf("legacy MSI GetToken failed: %v", err)
	}
	if tok != "legacy-msi-token" {
		t.Fatalf("unexpected token: %q", tok)
	}
}
