package a2a

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 1. Transactional Outbox Retries & Dead-Letter Queue
func TestOutboxWorkerRetriesAndDeadLetterQueue(t *testing.T) {
	repo := storage.NewMemoryRepository()
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	var deliveryAttempts int32
	mockTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/always-fail" {
			http.Error(w, "permanent failure", http.StatusInternalServerError)
			return
		}
		att := atomic.AddInt32(&deliveryAttempts, 1)
		if att < 3 {
			// Fail first 2 attempts
			http.Error(w, "transient error", http.StatusInternalServerError)
			return
		}
		// Succeed on 3rd attempt
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer mockTarget.Close()

	// Create outbox event
	ev := &domain.A2AOutboxEvent{
		ID:            "outbox_test_001",
		TaskID:        "task_100",
		EventType:     "status",
		TargetURL:     mockTarget.URL,
		PayloadJSON:   `{"task_id":"task_100","state":"working"}`,
		Status:        domain.OutboxStatusPending,
		AttemptCount:  0,
		NextAttemptAt: time.Now().UTC().Add(-time.Second),
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2AOutboxEvent(context.Background(), ev))

	worker := NewOutboxWorker(repo, netPolicy, 5, 10*time.Millisecond)

	// Step 1: First attempt fails -> pending, attempt=1
	worker.ProcessPendingEvents(context.Background())
	stored, err := repo.GetA2AOutboxEvent(context.Background(), ev.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.OutboxStatusPending, stored.Status)
	assert.Equal(t, 1, stored.AttemptCount)

	// Step 2: Second attempt fails -> pending, attempt=2
	// Force NextAttemptAt to past
	stored.NextAttemptAt = time.Now().UTC().Add(-time.Second)
	_ = repo.UpdateA2AOutboxEvent(context.Background(), stored)
	worker.ProcessPendingEvents(context.Background())
	stored, err = repo.GetA2AOutboxEvent(context.Background(), ev.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.OutboxStatusPending, stored.Status)
	assert.Equal(t, 2, stored.AttemptCount)

	// Step 3: Third attempt succeeds -> sent
	stored.NextAttemptAt = time.Now().UTC().Add(-time.Second)
	_ = repo.UpdateA2AOutboxEvent(context.Background(), stored)
	worker.ProcessPendingEvents(context.Background())
	stored, err = repo.GetA2AOutboxEvent(context.Background(), ev.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.OutboxStatusSent, stored.Status)

	// Dead-Letter Queue Test (MaxRetries exceeded)
	deadEv := &domain.A2AOutboxEvent{
		ID:            "outbox_dead_002",
		TaskID:        "task_101",
		EventType:     "status",
		TargetURL:     mockTarget.URL + "/always-fail",
		PayloadJSON:   `{"task_id":"task_101","state":"failed"}`,
		Status:        domain.OutboxStatusPending,
		AttemptCount:  2, // already at 2, maxRetries is 3
		NextAttemptAt: time.Now().UTC().Add(-time.Second),
		CreatedAt:     time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2AOutboxEvent(context.Background(), deadEv))

	workerDLQ := NewOutboxWorker(repo, netPolicy, 3, 10*time.Millisecond)
	workerDLQ.ProcessPendingEvents(context.Background())

	deadStored, err := repo.GetA2AOutboxEvent(context.Background(), deadEv.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.OutboxStatusDeadLetter, deadStored.Status, "Exceeding max retries must move outbox event to dead_letter (DLQ)")
}

// 2. Stream Subscriber Subscribe-First Pattern & Historical Backfill Deduplication
func TestStreamSubscriberSubscribeFirstAndDeduplication(t *testing.T) {
	repo := storage.NewMemoryRepository()
	subscriber := NewStreamSubscriber(repo, nil)

	ctx := context.Background()
	taskID := "task_stream_001"

	// Create task
	task := &domain.A2ATask{
		ID:               taskID,
		AgentID:          "agent_test",
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

	// Pre-seed 2 historical events
	ev1, err := repo.AppendA2ATaskEvent(ctx, taskID, "status", `{"state":"submitted"}`)
	require.NoError(t, err)
	ev2, err := repo.AppendA2ATaskEvent(ctx, taskID, "status", `{"state":"working"}`)
	require.NoError(t, err)
	require.Equal(t, int64(1), ev1.EventSeq)
	require.Equal(t, int64(2), ev2.EventSeq)

	// Setup authorized Identity
	idCtxOwner := &domain.IdentityContext{
		OrgID:        "org_default",
		VirtualKeyID: "vk_owner",
		UserID:       "usr_owner",
	}

	// Capture SSE response with timeout
	rec := httptest.NewRecorder()
	reqCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	httpReq := httptest.NewRequest(http.MethodGet, "/tasks/"+taskID+":subscribe", nil).WithContext(reqCtx)
	subscriber.SubscribeTaskStream(rec, httpReq, idCtxOwner, "agent-test", taskID, domain.TaskVisibilityKeyStrict)

	respBody := rec.Body.String()
	assert.Contains(t, respBody, ": connected")
	assert.Contains(t, respBody, "id: 1")
	assert.Contains(t, respBody, `"state":"submitted"`)
	assert.Contains(t, respBody, "id: 2")
	assert.Contains(t, respBody, `"state":"working"`)

	// Test Visibility Isolation: Unauthorized caller receives 404
	idCtxStranger := &domain.IdentityContext{
		OrgID:        "org_other",
		VirtualKeyID: "vk_stranger",
		UserID:       "usr_stranger",
	}
	recStranger := httptest.NewRecorder()
	reqStranger := httptest.NewRequest(http.MethodGet, "/tasks/"+taskID+":subscribe", nil).WithContext(ctx)
	subscriber.SubscribeTaskStream(recStranger, reqStranger, idCtxStranger, "agent-test", taskID, domain.TaskVisibilityKeyStrict)
	assert.Equal(t, http.StatusNotFound, recStranger.Code, "Stranger must be rejected with 404 per visibility isolation")
}

// 3. Stream Publisher Background Sync
func TestStreamPublisherBackgroundSync(t *testing.T) {
	repo := storage.NewMemoryRepository()
	publisher := NewStreamPublisher(repo, nil, 20*time.Millisecond)

	ctx := context.Background()
	taskID := "task_pub_sync"

	// Create task first
	task := &domain.A2ATask{
		ID:        taskID,
		AgentID:   "agent_pub",
		OrgID:     "org_pub",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2ATask(ctx, task))

	_, err := repo.AppendA2ATaskEvent(ctx, taskID, "status", `{"state":"submitted"}`)
	require.NoError(t, err)

	// Verify pending publication exists
	pubs, err := repo.ClaimPendingA2AStreamPublications(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pubs, 1)

	// Run publisher sync
	err = publisher.PublishPending(ctx)
	require.NoError(t, err)

	// Verify publication is completed
	pubsAfter, err := repo.ClaimPendingA2AStreamPublications(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, pubsAfter, "Publication should no longer be pending after publish")
}

// 4. Budget & Iteration Cap Enforcement
func TestTaskBudgetAndIterationCapEnforcement(t *testing.T) {
	repo := storage.NewMemoryRepository()
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	router := NewRouterService(repo, nil, nil, netPolicy, nil, nil, nil)
	ctx := context.Background()

	// Register agent with budget and iteration caps
	agent := &domain.A2AAgent{
		ID:                  "agent_capped",
		OrgID:               "org_test",
		Slug:                "capped-agent",
		EndpointURL:         "https://upstream.agent.internal/a2a",
		TaskVisibilityMode:  domain.TaskVisibilityKeyStrict,
		MaxTaskBudgetMicros: 5000, // $0.005 limit
		MaxTaskIterations:   3,    // 3 events max
		IsActive:            true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	idCtx := &domain.IdentityContext{
		OrgID:        "org_test",
		VirtualKeyID: "vk_test",
		UserID:       "usr_test",
	}

	// Create task that already hit budget cap
	taskBudgetHit := &domain.A2ATask{
		ID:               "task_budget_exceeded",
		AgentID:          agent.ID,
		OrgID:            agent.OrgID,
		VirtualKeyID:     idCtx.VirtualKeyID,
		UserID:           idCtx.UserID,
		State:            domain.A2ATaskStateWorking,
		TotalCostMicros:  6000, // exceeds 5000
		LastEventSeq:     1,
		InputMessageJSON: `{"parts":[{"text":"hello"}]}`,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2ATask(ctx, taskBudgetHit))

	req := &pb.SendMessageRequest{
		Message: &pb.Message{
			TaskId: taskBudgetHit.ID,
			Parts:  []*pb.Part{{Content: &pb.Part_Text{Text: "continuation request"}}},
		},
	}
	_, err = router.SendMessage(ctx, idCtx, agent.Slug, req)
	require.Error(t, err)
	var a2aErr *A2AError
	require.ErrorAs(t, err, &a2aErr)
	assert.Equal(t, CodeBudgetExceeded, a2aErr.Code, "Must return CodeBudgetExceeded (-32000) when cost exceeds budget")

	// Create task that hit iteration cap
	taskIterHit := &domain.A2ATask{
		ID:               "task_iter_exceeded",
		AgentID:          agent.ID,
		OrgID:            agent.OrgID,
		VirtualKeyID:     idCtx.VirtualKeyID,
		UserID:           idCtx.UserID,
		State:            domain.A2ATaskStateWorking,
		TotalCostMicros:  1000,
		LastEventSeq:     3, // reached cap of 3
		InputMessageJSON: `{"parts":[{"text":"hello"}]}`,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2ATask(ctx, taskIterHit))

	reqIter := &pb.SendMessageRequest{
		Message: &pb.Message{
			TaskId: taskIterHit.ID,
			Parts:  []*pb.Part{{Content: &pb.Part_Text{Text: "another step"}}},
		},
	}
	_, err = router.SendMessage(ctx, idCtx, agent.Slug, reqIter)
	require.Error(t, err)
	require.ErrorAs(t, err, &a2aErr)
	assert.Equal(t, CodeBudgetExceeded, a2aErr.Code, "Must return CodeBudgetExceeded (-32000) when iterations cap is hit")
}
