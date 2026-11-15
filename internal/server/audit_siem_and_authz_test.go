package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestAuditLogFilteredPagination_AndSIEMSink(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	base := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

	for i, rec := range []*domain.AuditLog{
		{ID: "aud-1", OrgID: "org-1", ActorID: "alice", Action: "key.created", Resource: "virtual_key", ResourceID: "vk-1", CreatedAt: base},
		{ID: "aud-2", OrgID: "org-1", ActorID: "bob", Action: "team.updated", Resource: "team", ResourceID: "t-1", CreatedAt: base.Add(1 * time.Second)},
		{ID: "aud-3", OrgID: "org-1", ActorID: "alice", Action: "key.revoked", Resource: "virtual_key", ResourceID: "vk-1", CreatedAt: base.Add(2 * time.Second)},
		{ID: "aud-4", OrgID: "org-2", ActorID: "alice", Action: "key.created", Resource: "virtual_key", ResourceID: "vk-2", CreatedAt: base.Add(3 * time.Second)},
	} {
		if err := repo.RecordAuditLog(ctx, rec); err != nil {
			t.Fatalf("RecordAuditLog[%d]: %v", i, err)
		}
	}

	page1, cursor1, err := repo.ListAuditLogsFiltered(ctx, domain.AuditLogFilter{
		OrgID: "org-1",
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 || page1[0].ID != "aud-3" || page1[1].ID != "aud-2" || cursor1 == "" {
		t.Fatalf("unexpected page1: len=%d cursor=%q ids=%+v", len(page1), cursor1, page1)
	}

	page2, cursor2, err := repo.ListAuditLogsFiltered(ctx, domain.AuditLogFilter{
		OrgID:  "org-1",
		Limit:  2,
		Cursor: cursor1,
	})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 1 || page2[0].ID != "aud-1" || cursor2 != "" {
		t.Fatalf("unexpected page2: len=%d cursor=%q ids=%+v", len(page2), cursor2, page2)
	}

	filtered, _, err := repo.ListAuditLogsFiltered(ctx, domain.AuditLogFilter{
		OrgID:   "org-1",
		ActorID: "alice",
		Action:  "key.revoked",
	})
	if err != nil || len(filtered) != 1 || filtered[0].ID != "aud-3" {
		t.Fatalf("unexpected filtered audit logs: %+v err=%v", filtered, err)
	}

	// Test signed async SIEM sink delivery
	var receivedEvents atomic.Int32
	const secret = "siem-secret-123"
	siemSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if r.Header.Get("X-GoRoute-Signature-256") != want {
			http.Error(w, "invalid hmac", http.StatusUnauthorized)
			return
		}
		var payload struct {
			Events []*domain.AuditLog `json:"events"`
		}
		_ = json.Unmarshal(body, &payload)
		receivedEvents.Add(int32(len(payload.Events)))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer siemSrv.Close()

	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowLoopbackHTTP:    true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	sink := NewAuditSIEMSink(AuditSIEMSinkConfig{
		URL:           siemSrv.URL,
		Secret:        secret,
		BatchSize:     2,
		FlushInterval: 50 * time.Millisecond,
		Timeout:       2 * time.Second,
	}, pol)
	sink.Enqueue(&domain.AuditLog{ID: "e1", OrgID: "org-1", Action: "key.created"})
	sink.Enqueue(&domain.AuditLog{ID: "e2", OrgID: "org-1", Action: "key.revoked"})
	sink.Close(context.Background())

	delivered, failed, dropped := sink.Stats()
	if delivered != 2 || failed != 0 || dropped != 0 || receivedEvents.Load() != 2 {
		t.Fatalf("unexpected SIEM stats: delivered=%d failed=%d dropped=%d received=%d",
			delivered, failed, dropped, receivedEvents.Load())
	}
}

func TestCustomAuthorizer_AllInferenceEndpointsAndAdminConfigRedaction(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org_default", Name: "Default", Slug: "default", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-test-key-123456"
	cfg.Auth.ExternalAuthorizer = config.ExternalAuthorizerConfig{
		Enabled:    false,
		Mode:       "webhook",
		URL:        "https://policy.internal.example/authz",
		Timeout:    500 * time.Millisecond,
		FailMode:   "closed",
		AuthHeader: "Bearer super-secret-policy-token",
		HMACSecret: "super-secret-hmac-key",
	}
	cfg.Audit.SIEMWebhook = config.AuditSIEMWebhookConfig{
		Enabled:       false,
		URL:           "https://siem.internal.example/events",
		Secret:        "super-secret-siem-key",
		AuthHeader:    "Bearer super-secret-siem-bearer",
		BatchSize:     25,
		FlushInterval: 2 * time.Second,
		Timeout:       3 * time.Second,
		MaxQueueSize:  1024,
	}

	srv, err := New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer srv.Shutdown(ctx)

	vk, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:         "org_default",
		Name:          "authz-test-key",
		AllowedModels: []string{"*"},
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	var deniedPaths []string
	srv.SetCustomAuthorizer(auth.AuthorizerFunc(func(_ context.Context, req *auth.AuthzRequest) (*auth.AuthzDecision, error) {
		if req.Action == auth.AuthzActionInference {
			deniedPaths = append(deniedPaths, req.HTTPPath)
			return &auth.AuthzDecision{
				Allow:     false,
				Reason:    "denied by custom policy",
				ErrorCode: "custom_policy_blocked",
			}, nil
		}
		return &auth.AuthzDecision{Allow: true}, nil
	}))

	cases := []struct {
		path string
		body string
	}{
		{"/v1/chat/completions", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`},
		{"/v1/responses", `{"model":"gpt-4o-mini","input":"hi"}`},
		{"/v1/messages", `{"model":"claude-3-5-haiku-latest","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`},
		{"/v1/embeddings", `{"model":"text-embedding-3-small","input":"hello"}`},
		{"/v1/completions", `{"model":"gpt-4o-mini","prompt":"hello"}`},
		{"/v1/moderations", `{"model":"omni-moderation-latest","input":"hello"}`},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("Authorization", "Bearer "+vk.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s expected 403, got %d: %s", tc.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "denied by custom policy") {
			t.Fatalf("%s expected custom denial message, got %s", tc.path, rec.Body.String())
		}
	}
	if len(deniedPaths) != len(cases) {
		t.Fatalf("expected %d custom authorizer evaluations, got %d (%v)", len(cases), len(deniedPaths), deniedPaths)
	}

	// Verify /admin/v1/config redacts external_authorizer and audit.siem_webhook secrets.
	cfgReq := httptest.NewRequest(http.MethodGet, "/admin/v1/config", nil)
	cfgReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	cfgRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(cfgRec, cfgReq)
	if cfgRec.Code != http.StatusOK {
		t.Fatalf("/admin/v1/config status=%d body=%s", cfgRec.Code, cfgRec.Body.String())
	}
	bodyStr := cfgRec.Body.String()
	for _, secret := range []string{"super-secret-policy-token", "super-secret-hmac-key", "super-secret-siem-key", "super-secret-siem-bearer"} {
		if strings.Contains(bodyStr, secret) {
			t.Fatalf("/admin/v1/config leaked raw secret %q", secret)
		}
	}
	if !strings.Contains(bodyStr, `"external_authorizer"`) || !strings.Contains(bodyStr, `"siem_webhook"`) {
		t.Fatalf("/admin/v1/config missing external_authorizer or siem_webhook sections: %s", bodyStr)
	}
}
