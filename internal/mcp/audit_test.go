package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestHub_AuditLogs_ToolCallAndRBACDenial(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      "1",
			Result: map[string]any{
				"content": []map[string]any{{"type": "text", "text": "ok"}},
			},
		})
	}))
	defer upstream.Close()

	_ = repo.CreateMCPServer(ctx, &domain.MCPServer{
		ID:            "srv-audit-1",
		OrgID:         "org-audit",
		Slug:          "github",
		Name:          "GitHub",
		TransportType: domain.MCPTransportStreamableHTTP,
		EndpointURL:   upstream.URL,
		AuthType:      domain.MCPAuthNone,
		IsActive:      true,
	})
	_ = repo.UpsertMCPTools(ctx, "srv-audit-1", "org-audit", []*domain.MCPTool{
		{
			ID:       "tool-audit-1",
			ServerID: "srv-audit-1",
			Name:     "list_repos",
			IsActive: true,
		},
	})

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	rbac := auth.NewRBACEngine(repo)
	hub := NewHub(repo, nil, rbac, NewTransportDispatcher(netPolicy, nil, false), NewAuthResolver(nil, netPolicy))

	allowedCtx := &domain.IdentityContext{
		OrgID:                 "org-audit",
		VirtualKeyID:          "vk-allowed",
		KeyAllowedMCPServers:  []string{"github"},
		TeamAllowedMCPServers: []string{"github"},
	}
	resp, err := hub.CallTool(ctx, allowedCtx, ToolCallInput{
		ServerSlug: "github",
		ToolName:   "list_repos",
	}, CallMetadata{RequestID: "req-1"})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if resp == nil || len(resp.Content) == 0 {
		t.Fatalf("expected non-empty tool response")
	}

	deniedCtx := &domain.IdentityContext{
		OrgID:                "org-audit",
		VirtualKeyID:         "vk-denied",
		KeyAllowedMCPServers: []string{"other"},
	}
	if _, err := hub.CallTool(ctx, deniedCtx, ToolCallInput{
		ServerSlug: "github",
		ToolName:   "list_repos",
	}, CallMetadata{RequestID: "req-2"}); err == nil {
		t.Fatal("expected RBAC denial error")
	}

	logs, err := repo.ListAuditLogs(ctx, "org-audit", 10)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	var sawToolCall, sawDenied bool
	for _, l := range logs {
		if l.Action == "mcp.tool.call" && l.ResourceID == "github/list_repos" && l.ActorID == "vk-allowed" {
			sawToolCall = true
		}
		if l.Action == "mcp.rbac.denied" && l.ResourceID == "github" && l.ActorID == "vk-denied" {
			sawDenied = true
		}
	}
	if !sawToolCall {
		t.Fatalf("expected mcp.tool.call audit log, got %+v", logs)
	}
	if !sawDenied {
		t.Fatalf("expected mcp.rbac.denied audit log, got %+v", logs)
	}
}

func TestHub_AuditLogs_NilRepoSafe(t *testing.T) {
	hub := NewHub(nil, nil, auth.NewRBACEngine(nil), nil, nil)
	hub.recordAudit(context.Background(), &domain.IdentityContext{OrgID: "org-1", VirtualKeyID: "vk-1"}, "mcp.tool.call", "mcp_tool", "s/t", nil)
}
