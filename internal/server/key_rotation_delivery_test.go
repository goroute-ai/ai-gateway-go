package server_test

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestKeyRotationDelivery_RejectsInsecureOrIncompleteConfig(t *testing.T) {
	baseCfg := func() *config.Config {
		c := config.Default()
		c.Server.Environment = "test"
		c.Discovery.Enabled = false
		return c
	}

	cases := []struct {
		name  string
		url   string
		token string
	}{
		{
			name:  "rejects plain http delivery url",
			url:   "http://vault.internal.example/hooks/rotate",
			token: "delivery-bearer-token",
		},
		{
			name:  "rejects delivery url with embedded credentials",
			url:   "https://user:pass@vault.internal.example/hooks/rotate",
			token: "delivery-bearer-token",
		},
		{
			name:  "rejects delivery url with query string",
			url:   "https://vault.internal.example/hooks/rotate?token=x",
			token: "delivery-bearer-token",
		},
		{
			name:  "rejects missing bearer token",
			url:   "https://vault.internal.example/hooks/rotate",
			token: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg()
			cfg.Auth.KeyRotationDeliveryURL = tc.url
			cfg.Auth.KeyRotationDeliveryToken = tc.token
			if _, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil); err == nil {
				t.Fatalf("expected server.New error for %s", tc.name)
			}
		})
	}

	// Unconfigured delivery URL succeeds cleanly.
	okCfg := baseCfg()
	if srv, err := server.New(okCfg, storage.NewMemoryRepository(), nil, nil); err != nil {
		t.Fatalf("expected server.New without delivery URL to succeed, got %v", err)
	} else {
		srv.Shutdown(t.Context())
	}
}
