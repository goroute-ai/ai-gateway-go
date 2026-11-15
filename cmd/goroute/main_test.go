package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGorouteCLI_LoginAndWhoami(t *testing.T) {
	var pollCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/cli/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"login_id":         "login-123",
				"user_code":        "ABCD-1234",
				"verification_url": "https://gw.example.com/ui/cli?login_id=login-123",
				"expires_in":       60,
				"interval":         1,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/auth/cli/poll/login-123":
			if pollCount.Add(1) == 1 {
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":   "pending",
					"interval": 1,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     "completed",
				"login_id":   "login-123",
				"api_key":    "sk-gw-test-secret-key",
				"key_id":     "vk-cli-1",
				"key_prefix": "sk-gw-test",
				"org_id":     "org-demo",
				"team_id":    "team-eng",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/auth/me":
			if r.Header.Get("Authorization") != "Bearer sk-gw-test-secret-key" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"operator": map[string]any{"actor_id": "u-1", "role": "org_admin", "org_id": "org-demo"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfgDir := t.TempDir()
	t.Setenv("GOROUTE_CONFIG_DIR", cfgDir)
	t.Setenv("GOROUTE_URL", "")
	t.Setenv("GOROUTE_API_KEY", "")

	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"login", "--gateway", srv.URL, "--no-open"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("login failed: %v (stderr=%s)", err, stderr.String())
	}
	// Secret must NOT leak to stdout unless --print-key is passed.
	if strings.Contains(stdout.String(), "sk-gw-test-secret-key") {
		t.Fatalf("API key leaked to stdout without --print-key")
	}

	credPath := filepath.Join(cfgDir, "credentials.json")
	info, err := os.Stat(credPath)
	if err != nil {
		t.Fatalf("credentials file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials file mode = %o, want 0600", perm)
	}

	stdout.Reset()
	if err := run(context.Background(), []string{"whoami"}, &stdout, &stderr); err != nil {
		t.Fatalf("whoami failed: %v", err)
	}
	if !strings.Contains(stdout.String(), `"org_admin"`) {
		t.Fatalf("unexpected whoami output: %s", stdout.String())
	}
}
