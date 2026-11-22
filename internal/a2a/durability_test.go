package a2a

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 1. Transactional Outbox Retries, Vault Webhook Auth & Dead-Letter Queue
func TestOutboxWorkerRetriesAndDeadLetterQueue(t *testing.T) {
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	var seenAuth, seenNotifToken string
	var deliveryAttempts int32
	mockTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenNotifToken = r.Header.Get("X-A2A-Notification-Token")
		if r.URL.Path == "/always-fail" {
			http.Error(w, "permanent failure", http.StatusInternalServerError)
			return
		}
		att := atomic.AddInt32(&deliveryAttempts, 1)
		if att < 3 {
			http.Error(w, "transient error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer mockTarget.Close()

	cipherHex, dekHex, err := vault.EncryptString("webhook-secret-999")
	require.NoError(t, err)
	require.NoError(t, repo.SetA2APushNotificationConfig(context.Background(), &domain.A2APushNotificationConfig{
		ID:                 "push_cfg_auth_1",
		TaskID:             "task_100",
		TargetURL:          mockTarget.URL,
		Token:              "notif-tok-123",
		AuthScheme:         "Bearer",
		EncryptedAuthCreds: cipherHex,
		EncryptedAuthDEK:   dekHex,
	}))

	ev := &domain.A2AOutboxEvent{
		ID:            "outbox_test_001",
		TaskID:        "task_100",
		PushConfigID:  "push_cfg_auth_1",
		EventType:     "status",
		TargetURL:     mockTarget.URL,
		PayloadJSON:   `{"statusUpdate":{"taskId":"task_100","contextId":"ctx_100","status":{"state":"TASK_STATE_WORKING"}}}`,
		Status:        domain.OutboxStatusPending,
		AttemptCount:  0,
		NextAttemptAt: time.Now().UTC().Add(-time.Second),
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2AOutboxEvent(context.Background(), ev))

	worker := NewOutboxWorker(repo, vault, netPolicy, 5, 10*time.Millisecond)

	// Attempt 1 fails -> pending, attempt=1
	worker.ProcessPendingEvents(context.Background())
	stored, err := repo.GetA2AOutboxEvent(context.Background(), ev.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.OutboxStatusPending, stored.Status)
	assert.Equal(t, 1, stored.AttemptCount)
	assert.Equal(t, "Bearer webhook-secret-999", seenAuth, "H1: Vault webhook secret must be sent")
	assert.Equal(t, "notif-tok-123", seenNotifToken, "X-A2A-Notification-Token must be sent")

	// Attempt 2 fails -> pending, attempt=2
	stored.NextAttemptAt = time.Now().UTC().Add(-time.Second)
	_ = repo.UpdateA2AOutboxEvent(context.Background(), stored)
	worker.ProcessPendingEvents(context.Background())
	stored, err = repo.GetA2AOutboxEvent(context.Background(), ev.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.OutboxStatusPending, stored.Status)
	assert.Equal(t, 2, stored.AttemptCount)

	// Attempt 3 succeeds -> sent
	stored.NextAttemptAt = time.Now().UTC().Add(-time.Second)
	_ = repo.UpdateA2AOutboxEvent(context.Background(), stored)
	worker.ProcessPendingEvents(context.Background())
	stored, err = repo.GetA2AOutboxEvent(context.Background(), ev.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.OutboxStatusSent, stored.Status)

	// Dead-Letter Queue Test
	deadEv := &domain.A2AOutboxEvent{
		ID:            "outbox_dead_002",
		TaskID:        "task_101",
		EventType:     "status",
		TargetURL:     mockTarget.URL + "/always-fail",
		PayloadJSON:   `{"statusUpdate":{"taskId":"task_101","contextId":"ctx_101","status":{"state":"TASK_STATE_FAILED"}}}`,
		Status:        domain.OutboxStatusPending,
		AttemptCount:  2,
		NextAttemptAt: time.Now().UTC().Add(-time.Second),
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2AOutboxEvent(context.Background(), deadEv))

	workerDLQ := NewOutboxWorker(repo, vault, netPolicy, 3, 10*time.Millisecond)
	workerDLQ.ProcessPendingEvents(context.Background())

	deadStored, err := repo.GetA2AOutboxEvent(context.Background(), deadEv.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.OutboxStatusDeadLetter, deadStored.Status)
	assert.Contains(t, deadStored.LastError, "500")
}

// 2. Stream Subscriber Subscribe-First Pattern & Historical Backfill Deduplication
func TestStreamSubscriberSubscribeFirstAndDeduplication(t *testing.T) {
	repo := storage.NewMemoryRepository()
	rbac := auth.NewRBACEngine(repo)
	subscriber := NewStreamSubscriber(repo, rbac, nil, 128)

	ctx := context.Background()
	agent := &domain.A2AAgent{
		ID:                 "agent_test",
		OrgID:              "org_default",
		Name:               "Agent Test",
		Slug:               "agent-test",
		EndpointURL:        "https://agent.test.internal/a2a",
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	taskID := "task_stream_001"
	task := &domain.A2ATask{
		ID:               taskID,
		AgentID:          agent.ID,
		OrgID:            "org_default",
		VirtualKeyID:     "vk_owner",
		UserID:           "usr_owner",
		State:            domain.A2ATaskStateWorking,
		LastEventSeq:     0,
		InputMessageJSON: `{"parts":[{"text":"init"}]}`,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2ATask(ctx, task))

	ev1, err := repo.AppendA2ATaskEvent(ctx, taskID, "status", `{"statusUpdate":{"taskId":"task_stream_001","contextId":"c1","status":{"state":"TASK_STATE_SUBMITTED"}}}`)
	require.NoError(t, err)
	ev2, err := repo.AppendA2ATaskEvent(ctx, taskID, "status", `{"statusUpdate":{"taskId":"task_stream_001","contextId":"c1","status":{"state":"TASK_STATE_WORKING"}}}`)
	require.NoError(t, err)
	require.Equal(t, int64(1), ev1.EventSeq)
	require.Equal(t, int64(2), ev2.EventSeq)

	idCtxOwner := &domain.IdentityContext{
		OrgID:               "org_default",
		VirtualKeyID:        "vk_owner",
		UserID:              "usr_owner",
		KeyAllowedA2AAgents: []string{"*"},
	}

	rec := httptest.NewRecorder()
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	defer cancel()

	httpReq := httptest.NewRequest(http.MethodGet, "/a2a/v1/agents/agent-test/tasks/"+taskID+":subscribe", nil).WithContext(reqCtx)
	subscriber.SubscribeTaskStream(rec, httpReq, idCtxOwner, "agent-test", taskID)

	respBody := rec.Body.String()
	assert.Contains(t, respBody, "id: 1")
	assert.Contains(t, respBody, `"TASK_STATE_SUBMITTED"`)
	assert.Contains(t, respBody, "id: 2")
	assert.Contains(t, respBody, `"TASK_STATE_WORKING"`)

	// Visibility Isolation: Stranger receives 404
	idCtxStranger := &domain.IdentityContext{
		OrgID:               "org_other",
		VirtualKeyID:        "vk_stranger",
		UserID:              "usr_stranger",
		KeyAllowedA2AAgents: []string{"*"},
	}
	recStranger := httptest.NewRecorder()
	reqStranger := httptest.NewRequest(http.MethodGet, "/a2a/v1/agents/agent-test/tasks/"+taskID+":subscribe", nil).WithContext(ctx)
	subscriber.SubscribeTaskStream(recStranger, reqStranger, idCtxStranger, "agent-test", taskID)
	assert.Equal(t, http.StatusNotFound, recStranger.Code)
}

// 3. Stream Publisher Background Sync
func TestStreamPublisherBackgroundSync(t *testing.T) {
	repo := storage.NewMemoryRepository()
	publisher := NewStreamPublisher(repo, nil, 20*time.Millisecond)

	ctx := context.Background()
	taskID := "task_pub_sync"

	require.NoError(t, repo.CreateA2ATask(ctx, &domain.A2ATask{
		ID:        taskID,
		AgentID:   "agent_pub",
		OrgID:     "org_pub",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	_, err := repo.AppendA2ATaskEvent(ctx, taskID, "status", `{"statusUpdate":{"taskId":"task_pub_sync","contextId":"c","status":{"state":"TASK_STATE_SUBMITTED"}}}`)
	require.NoError(t, err)

	pubs, err := repo.ClaimPendingA2AStreamPublications(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pubs, 1)

	require.NoError(t, publisher.PublishPending(ctx))

	pubsAfter, err := repo.ClaimPendingA2AStreamPublications(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, pubsAfter)
}

// 4. Budget & Iteration Cap Enforcement
func TestTaskBudgetAndIterationCapEnforcement(t *testing.T) {
	repo := storage.NewMemoryRepository()
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)

	router := NewRouterService(repo, nil, nil, netPolicy, nil, nil, nil)
	ctx := context.Background()

	agent := &domain.A2AAgent{
		ID:                  "agent_capped",
		OrgID:               "org_test",
		Slug:                "capped-agent",
		EndpointURL:         "https://upstream.agent.internal/a2a",
		TaskVisibilityMode:  domain.TaskVisibilityKeyStrict,
		MaxTaskBudgetMicros: 5000,
		MaxTaskIterations:   3,
		IsActive:            true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	idCtx := &domain.IdentityContext{OrgID: "org_test", VirtualKeyID: "vk_test", UserID: "usr_test"}

	taskBudgetHit := &domain.A2ATask{
		ID:              "task_budget_exceeded",
		AgentID:         agent.ID,
		OrgID:           agent.OrgID,
		VirtualKeyID:    idCtx.VirtualKeyID,
		UserID:          idCtx.UserID,
		State:           domain.A2ATaskStateWorking,
		TotalCostMicros: 6000,
		LastEventSeq:    1,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2ATask(ctx, taskBudgetHit))

	_, err = router.SendMessage(ctx, idCtx, agent.Slug, &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "m1",
			Role:      a2aspec.ROLEUSER,
			TaskId:    &taskBudgetHit.ID,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("continuation request")},
		},
	})
	require.Error(t, err)
	var a2aErr *A2AError
	require.ErrorAs(t, err, &a2aErr)
	assert.Equal(t, CodeBudgetExceeded, a2aErr.JSONRPCCode)

	taskIterHit := &domain.A2ATask{
		ID:              "task_iter_exceeded",
		AgentID:         agent.ID,
		OrgID:           agent.OrgID,
		VirtualKeyID:    idCtx.VirtualKeyID,
		UserID:          idCtx.UserID,
		State:           domain.A2ATaskStateWorking,
		TotalCostMicros: 1000,
		LastEventSeq:    3,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2ATask(ctx, taskIterHit))

	_, err = router.SendMessage(ctx, idCtx, agent.Slug, &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "m2",
			Role:      a2aspec.ROLEUSER,
			TaskId:    &taskIterHit.ID,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("another step")},
		},
	})
	require.Error(t, err)
	require.ErrorAs(t, err, &a2aErr)
	assert.Equal(t, CodeBudgetExceeded, a2aErr.JSONRPCCode)
}
