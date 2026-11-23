package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestRouterService_AuditLogs_DispatchAndRBACDenial(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	rbac := auth.NewRBACEngine(repo)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respObj := a2aspec.NewSendMessageResponseMessage(&a2aspec.Message{
			MessageId: "msg_up_1",
			Role:      a2aspec.ROLEAGENT,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("done")},
		})
		outJSON, _ := json.Marshal(respObj)
		w.Header().Set("Content-Type", MediaTypeA2AJSON)
		_, _ = w.Write(outJSON)
	}))
	defer upstream.Close()

	if err := repo.CreateA2AAgent(ctx, &domain.A2AAgent{
		ID:                 "agent_audit_1",
		OrgID:              "org-audit",
		Name:               "Audit Agent",
		Slug:               "audit-agent",
		EndpointURL:        upstream.URL,
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateA2AAgent: %v", err)
	}

	router := NewRouterService(repo, nil, rbac, netPolicy, nil, nil, nil)

	allowedCtx := &domain.IdentityContext{
		OrgID:               "org-audit",
		VirtualKeyID:        "vk-allowed",
		KeyAllowedA2AAgents: []string{"audit-agent"},
	}
	sendReq := &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "msg_1",
			Role:      a2aspec.ROLEUSER,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("hello")},
		},
	}
	if _, err := router.SendMessage(ctx, allowedCtx, "audit-agent", sendReq); err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	deniedCtx := &domain.IdentityContext{
		OrgID:               "org-audit",
		VirtualKeyID:        "vk-denied",
		KeyAllowedA2AAgents: []string{"other-agent"},
	}
	if _, err := router.SendMessage(ctx, deniedCtx, "audit-agent", sendReq); err == nil {
		t.Fatal("expected RBAC denial on SendMessage")
	}
	if _, err := router.GetTask(ctx, deniedCtx, "audit-agent", "task_1", nil); err == nil {
		t.Fatal("expected RBAC denial on GetTask")
	}
	if _, err := router.ListTasks(ctx, deniedCtx, "audit-agent", &a2aspec.ListTasksRequest{}); err == nil {
		t.Fatal("expected RBAC denial on ListTasks")
	}
	if _, err := router.CancelTask(ctx, deniedCtx, "audit-agent", "task_1"); err == nil {
		t.Fatal("expected RBAC denial on CancelTask")
	}

	logs, err := repo.ListAuditLogs(ctx, "org-audit", 20)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	var dispatchCount, deniedCount int
	for _, l := range logs {
		if l.Action == "a2a.task.dispatch" && l.ActorID == "vk-allowed" {
			dispatchCount++
		}
		if l.Action == "a2a.rbac.denied" && l.ResourceID == "audit-agent" && l.ActorID == "vk-denied" {
			deniedCount++
		}
	}
	if dispatchCount != 1 {
		t.Fatalf("expected 1 a2a.task.dispatch audit log, got %d (%+v)", dispatchCount, logs)
	}
	if deniedCount != 4 {
		t.Fatalf("expected 4 a2a.rbac.denied audit logs, got %d (%+v)", deniedCount, logs)
	}
}

func TestRouterService_AuditLogs_NilRepoSafe(t *testing.T) {
	router := NewRouterService(nil, nil, auth.NewRBACEngine(nil), nil, nil, nil, nil)
	deniedCtx := &domain.IdentityContext{
		OrgID:               "org-1",
		VirtualKeyID:        "vk-1",
		KeyAllowedA2AAgents: []string{"other"},
	}
	if _, err := router.SendMessage(context.Background(), deniedCtx, "audit-agent", &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "m1",
			Role:      a2aspec.ROLEUSER,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("hi")},
		},
	}); err == nil {
		t.Fatal("expected RBAC error")
	}
	if _, err := router.GetTask(context.Background(), deniedCtx, "audit-agent", "t1", nil); err == nil {
		t.Fatal("expected RBAC error")
	}
}
