package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestOutboxWorker_PersistsAttemptCountAndNextAttemptAt(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)

	failingSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failingSrv.Close()

	ev := &domain.A2AOutboxEvent{
		ID:            "outbox_persist_1",
		TaskID:        "task_p1",
		EventType:     "status",
		TargetURL:     failingSrv.URL,
		PayloadJSON:   `{}`,
		Status:        domain.OutboxStatusPending,
		AttemptCount:  0,
		NextAttemptAt: time.Now().UTC().Add(-time.Second),
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2AOutboxEvent(ctx, ev))

	before := time.Now().UTC()
	worker := NewOutboxWorker(repo, nil, netPolicy, 5, 10*time.Millisecond)
	worker.ProcessPendingEvents(ctx)

	stored, err := repo.GetA2AOutboxEvent(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, stored.AttemptCount)
	assert.True(t, stored.NextAttemptAt.After(before), "NextAttemptAt must be persisted into the future on retry")
}

func TestGRPCServer_DeleteTaskPushNotificationConfig_VisibilityAndDelete(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_pd", Name: "org_pd", IsActive: true}))
	agent := &domain.A2AAgent{
		ID:                 "agent_push_del",
		OrgID:              "org_pd",
		Slug:               "push-del-agent",
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	authSvc := auth.NewService(repo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
	ownerRawKey := "sk-gw-owner-secret-key-1"
	otherRawKey := "sk-gw-other-secret-key-2"
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:               "vk_owner",
		OrgID:            "org_pd",
		KeyHash:          auth.HashKey(ownerRawKey),
		KeyPrefix:        "sk-gw-owner",
		AllowedEndpoints: []string{"*"},
		AllowedA2AAgents: []string{"*"},
		IsActive:         true,
	}))
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:               "vk_other",
		OrgID:            "org_pd",
		KeyHash:          auth.HashKey(otherRawKey),
		KeyPrefix:        "sk-gw-other",
		AllowedEndpoints: []string{"*"},
		AllowedA2AAgents: []string{"*"},
		IsActive:         true,
	}))

	task := &domain.A2ATask{
		ID:           "task_pd_1",
		AgentID:      agent.ID,
		OrgID:        "org_pd",
		VirtualKeyID: "vk_owner",
		State:        domain.A2ATaskStateWorking,
	}
	require.NoError(t, repo.CreateA2ATask(ctx, task))
	require.NoError(t, repo.SetA2APushNotificationConfig(ctx, &domain.A2APushNotificationConfig{
		ID:        "cfg_1",
		TaskID:    task.ID,
		TargetURL: "https://example.com/hook",
	}))

	router := NewRouterService(repo, vault, rbac, netPolicy, nil, nil, nil)
	grpcSrv := NewGRPCServer(router, authSvc, rbac)

	// Other key must be denied (NotFound)
	otherCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+otherRawKey))
	_, err = grpcSrv.DeleteTaskPushNotificationConfig(otherCtx, &pb.DeleteTaskPushNotificationConfigRequest{TaskId: task.ID, Id: "cfg_1"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	// Owner key succeeds and deletes config directly from repository (fixes H5)
	ownerCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+ownerRawKey))
	_, err = grpcSrv.DeleteTaskPushNotificationConfig(ownerCtx, &pb.DeleteTaskPushNotificationConfigRequest{TaskId: task.ID, Id: "cfg_1"})
	require.NoError(t, err)

	_, getErr := repo.GetA2APushNotificationConfig(ctx, task.ID, "cfg_1")
	require.Error(t, getErr)
}

func TestRouterService_NilIdentityAndNonDoubleCountedCostIncrement(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)

	mockAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Also test C3: upstream returns a Task with INPUT_REQUIRED and nil Status details
		resp := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
			Id: "up_task_cost",
			Status: a2aspec.TaskStatus{
				State: a2aspec.TASKSTATEINPUTREQUIRED,
			},
		})
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", MediaTypeA2AJSON)
		_, _ = w.Write(b)
	}))
	defer mockAgent.Close()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_cost", Name: "org_cost", IsActive: true}))
	agent := &domain.A2AAgent{
		ID:                 "agent_cost",
		OrgID:              "org_cost",
		Slug:               "cost-agent",
		EndpointURL:        mockAgent.URL,
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	router := NewRouterService(repo, vault, rbac, netPolicy, nil, nil, nil)

	// Nil identity fails closed without panic
	_, err = router.SendMessage(ctx, nil, "cost-agent", &a2aspec.SendMessageRequest{})
	require.Error(t, err)
	_, err = router.GetTask(ctx, nil, "cost-agent", "t1", nil)
	require.Error(t, err)
	_, err = router.ListTasks(ctx, nil, "cost-agent", &a2aspec.ListTasksRequest{})
	require.Error(t, err)
	_, err = router.CancelTask(ctx, nil, "cost-agent", "t1")
	require.Error(t, err)

	idCtx := &domain.IdentityContext{OrgID: "org_cost", VirtualKeyID: "vk_cost"}
	turn1Resp, err := router.SendMessage(ctx, idCtx, "cost-agent", &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{MessageId: "m1", Role: a2aspec.ROLEUSER, Parts: []a2aspec.Part{a2aspec.NewTextPart("turn 1")}},
	})
	require.NoError(t, err)
	taskID := turn1Resp.Task.Id

	// C5 check: two turns at 100 micros MUST sum to 200 (not 300 from triangular double counting!)
	_, err = router.SendMessage(ctx, idCtx, "cost-agent", &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{MessageId: "m2", Role: a2aspec.ROLEUSER, TaskId: &taskID, Parts: []a2aspec.Part{a2aspec.NewTextPart("turn 2")}},
	})
	require.NoError(t, err)

	stored, err := repo.GetA2ATask(ctx, taskID)
	require.NoError(t, err)
	assert.Equal(t, int64(200), stored.TotalCostMicros)
}

func TestStreamSubscriber_ClosesOnTerminalTaskState(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	rbac := auth.NewRBACEngine(repo)

	require.NoError(t, repo.CreateA2AAgent(ctx, &domain.A2AAgent{
		ID:                 "agent_1",
		OrgID:              "org_sse",
		Name:               "Agent 1",
		Slug:               "a",
		EndpointURL:        "https://example.com",
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}))

	task := &domain.A2ATask{
		ID:           "task_term_sse",
		AgentID:      "agent_1",
		OrgID:        "org_sse",
		VirtualKeyID: "vk_sse",
		State:        domain.A2ATaskStateCompleted,
	}
	require.NoError(t, repo.CreateA2ATask(ctx, task))
	_, err := repo.AppendA2ATaskEvent(ctx, task.ID, "status", `{"statusUpdate":{"taskId":"task_term_sse","contextId":"c1","status":{"state":"TASK_STATE_COMPLETED"}}}`)
	require.NoError(t, err)

	sub := NewStreamSubscriber(repo, rbac, nil, 64)
	req := httptest.NewRequest(http.MethodGet, "/a2a/v1/agents/a/tasks/"+task.ID+":subscribe", nil)
	req.Header.Set("Last-Event-ID", "0")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		// Replay historical events (Last-Event-ID=0 < LastEventSeq=1) and close cleanly
		sub.SubscribeTaskStream(rec, req, &domain.IdentityContext{
			OrgID:               "org_sse",
			VirtualKeyID:        "vk_sse",
			KeyAllowedA2AAgents: []string{"*"},
		}, "a", task.ID)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("SSE stream did not close on terminal task state")
	}
	assert.Contains(t, rec.Body.String(), "TASK_STATE_COMPLETED")
}

func TestValidateAndSanitizeCardURL(t *testing.T) {
	strictPol, err := network.NewPolicy(config.OutboundSSRFConfig{})
	require.NoError(t, err)
	localPol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		rawURL  string
		policy  *network.Policy
		wantURL string
		wantErr bool
	}{
		{
			name:    "valid https card URL under strict policy",
			rawURL:  "https://Agents.Example.COM/.well-known/agent-card.json?v=1",
			policy:  strictPol,
			wantURL: "https://agents.example.com/.well-known/agent-card.json?v=1",
		},
		{
			name:    "rejects private IP under default nil policy",
			rawURL:  "https://127.0.0.1/.well-known/agent-card.json",
			policy:  nil,
			wantErr: true,
		},
		{
			name:    "rejects cloud metadata under permissive local policy",
			rawURL:  "http://169.254.169.254/latest/meta-data",
			policy:  localPol,
			wantErr: true,
		},
		{
			name:    "rejects insecure http under strict policy",
			rawURL:  "http://agents.example.com/.well-known/agent-card.json",
			policy:  strictPol,
			wantErr: true,
		},
		{
			name:    "rejects non-http scheme",
			rawURL:  "file:///etc/passwd",
			policy:  localPol,
			wantErr: true,
		},
		{
			name:    "rejects embedded userinfo",
			rawURL:  "https://user:pass@agents.example.com/.well-known/agent-card.json",
			policy:  strictPol,
			wantErr: true,
		},
		{
			name:    "rejects trailing-dot hostname",
			rawURL:  "https://agents.example.com./.well-known/agent-card.json",
			policy:  strictPol,
			wantErr: true,
		},
		{
			name:    "rejects path traversal",
			rawURL:  "https://agents.example.com/a/../secret",
			policy:  strictPol,
			wantErr: true,
		},
		{
			name:    "rejects control characters and backslashes",
			rawURL:  "https://agents.example.com/\\bad\r\n",
			policy:  strictPol,
			wantErr: true,
		},
		{
			name:    "allows loopback http when policy explicitly permits",
			rawURL:  "http://127.0.0.1:8080/.well-known/jwks.json",
			policy:  localPol,
			wantURL: "http://127.0.0.1:8080/.well-known/jwks.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateAndSanitizeCardURL(tc.rawURL, tc.policy)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantURL, got)
		})
	}
}
