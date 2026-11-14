package a2a

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
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
	"google.golang.org/protobuf/encoding/protojson"
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
	worker := NewOutboxWorker(repo, netPolicy, 5, 10*time.Millisecond)
	worker.ProcessPendingEvents(ctx)

	stored, err := repo.GetA2AOutboxEvent(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, stored.AttemptCount)
	assert.True(t, stored.NextAttemptAt.After(before), "NextAttemptAt must be persisted into the future on retry")
}

type pushConfigDeletingRepo struct {
	storage.Repository
	deleted map[string]bool
}

func (r *pushConfigDeletingRepo) DeleteA2APushNotificationConfig(ctx context.Context, taskID string) error {
	if !r.deleted[taskID] {
		cfg, err := r.Repository.GetA2APushNotificationConfig(ctx, taskID)
		if err != nil || cfg == nil {
			return fmt.Errorf("not found")
		}
		r.deleted[taskID] = true
		return nil
	}
	return fmt.Errorf("already deleted")
}

func TestGRPCServer_DeleteTaskPushNotificationConfig_VisibilityAndDelete(t *testing.T) {
	ctx := context.Background()
	baseRepo := storage.NewMemoryRepository()
	repo := &pushConfigDeletingRepo{Repository: baseRepo, deleted: make(map[string]bool)}
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org_pd",
		Name:     "org_pd",
		IsActive: true,
	}))
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
	_, err = grpcSrv.DeleteTaskPushNotificationConfig(otherCtx, &pb.DeleteTaskPushNotificationConfigRequest{TaskId: task.ID})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	// Owner key succeeds and deletes config
	ownerCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+ownerRawKey))
	_, err = grpcSrv.DeleteTaskPushNotificationConfig(ownerCtx, &pb.DeleteTaskPushNotificationConfigRequest{TaskId: task.ID})
	require.NoError(t, err)
	assert.True(t, repo.deleted[task.ID])
}

func TestRouterService_NilIdentityAndCostIncrement(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)

	mockAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Message{
				Message: &pb.Message{
					MessageId: "m1",
					Role:      pb.Role_ROLE_AGENT,
					Parts:     []*pb.Part{{Content: &pb.Part_Text{Text: "done"}}},
				},
			},
		}
		b, _ := protojson.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	defer mockAgent.Close()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org_pd",
		Name:     "org_pd",
		IsActive: true,
	}))
	agent := &domain.A2AAgent{
		ID:          "agent_cost",
		OrgID:       "org_cost",
		Slug:        "cost-agent",
		EndpointURL: mockAgent.URL,
		IsActive:    true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	router := NewRouterService(repo, vault, rbac, netPolicy, nil, nil, nil)

	// Nil identity fails closed without panic
	_, err = router.SendMessage(ctx, nil, "cost-agent", &pb.SendMessageRequest{Message: &pb.Message{}})
	require.Error(t, err)
	_, err = router.GetTask(ctx, nil, "cost-agent", "t1")
	require.Error(t, err)
	_, err = router.ListTasks(ctx, nil, "cost-agent", &pb.ListTasksRequest{})
	require.Error(t, err)
	_, err = router.CancelTask(ctx, nil, "cost-agent", "t1")
	require.Error(t, err)

	// Valid call increments TotalCostMicros
	idCtx := &domain.IdentityContext{OrgID: "org_cost", VirtualKeyID: "vk_cost"}
	_, err = router.SendMessage(ctx, idCtx, "cost-agent", &pb.SendMessageRequest{
		Message: &pb.Message{Parts: []*pb.Part{{Content: &pb.Part_Text{Text: "hi"}}}},
	})
	require.NoError(t, err)

	tasks, err := repo.ListA2ATasks(ctx, agent.ID, "vk_cost", 10)
	require.NoError(t, err)
	require.Len(t, tasks, 1)
	assert.Greater(t, tasks[0].TotalCostMicros, int64(0))
}

func TestStreamSubscriber_ClosesOnTerminalTaskState(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	task := &domain.A2ATask{
		ID:           "task_term_sse",
		AgentID:      "agent_1",
		OrgID:        "org_sse",
		VirtualKeyID: "vk_sse",
		State:        domain.A2ATaskStateCompleted,
	}
	require.NoError(t, repo.CreateA2ATask(ctx, task))
	_, err := repo.AppendA2ATaskEvent(ctx, task.ID, "status", `{"state":"completed"}`)
	require.NoError(t, err)

	sub := NewStreamSubscriber(repo, nil)
	req := httptest.NewRequest(http.MethodGet, "/a2a/v1/agents/a/tasks/"+task.ID+":subscribe", nil)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		sub.SubscribeTaskStream(rec, req, &domain.IdentityContext{OrgID: "org_sse", VirtualKeyID: "vk_sse"}, "a", task.ID, domain.TaskVisibilityKeyStrict)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("SSE stream did not close on terminal task state")
	}
	assert.Contains(t, rec.Body.String(), "completed")
}
