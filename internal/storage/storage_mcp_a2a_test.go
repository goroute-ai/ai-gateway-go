package storage_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestMCPStorageCRUD(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	org := &domain.Organization{Name: "Acme MCP", Slug: "acme-mcp", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	srv := &domain.MCPServer{
		OrgID:           org.ID,
		Name:            "GitHub MCP Server",
		Slug:            "github",
		ProtocolVersion: domain.MCPProtocolVersion2026,
		TransportType:   domain.MCPTransportStreamableHTTP,
		EndpointURL:     "https://mcp.github.internal/sse",
		AuthType:        "static",
		StaticHeaders: map[string]string{
			"X-GitHub-Version": "2026-01-01",
		},
		IsActive: true,
	}

	if err := repo.CreateMCPServer(ctx, srv); err != nil {
		t.Fatalf("create server: %v", err)
	}

	gotSrv, err := repo.GetMCPServerBySlug(ctx, org.ID, "github")
	if err != nil || gotSrv.ID != srv.ID {
		t.Fatalf("get server by slug: got %+v, err: %v", gotSrv, err)
	}
	if gotSrv.ConfigVersion != 1 {
		t.Fatalf("expected initial config_version 1, got %d", gotSrv.ConfigVersion)
	}

	// Update server -> config_version increments
	srv.Name = "GitHub MCP Server v2"
	if err := repo.UpdateMCPServer(ctx, srv); err != nil {
		t.Fatalf("update server: %v", err)
	}
	updated, _ := repo.GetMCPServer(ctx, srv.ID)
	if updated.ConfigVersion != 2 {
		t.Fatalf("expected config_version 2 after update, got %d", updated.ConfigVersion)
	}

	// Tools
	tools := []*domain.MCPTool{
		{
			Name:              "search_repos",
			Description:       "Search GitHub repositories",
			ToolDefHash:       "hash_search_repos_123",
			CostPerCallMicros: 50,
			IsActive:          true,
		},
		{
			Name:              "create_issue",
			Description:       "Create a GitHub issue",
			ToolDefHash:       "hash_create_issue_456",
			CostPerCallMicros: 100,
			IsActive:          true,
		},
	}
	if err := repo.UpsertMCPTools(ctx, srv.ID, org.ID, tools); err != nil {
		t.Fatalf("upsert tools: %v", err)
	}

	listedTools, err := repo.ListMCPTools(ctx, srv.ID)
	if err != nil || len(listedTools) != 2 {
		t.Fatalf("expected 2 tools, got %d (err: %v)", len(listedTools), err)
	}

	// Toolsets
	toolset := &domain.MCPToolset{
		OrgID:    org.ID,
		Name:     "Core Developer Tools",
		Slug:     "core-dev",
		ToolIDs:  []string{tools[0].ID, tools[1].ID},
		IsActive: true,
	}
	if err := repo.CreateMCPToolset(ctx, toolset); err != nil {
		t.Fatalf("create toolset: %v", err)
	}
	gotTS, err := repo.GetMCPToolsetBySlug(ctx, org.ID, "core-dev")
	if err != nil || len(gotTS.ToolIDs) != 2 {
		t.Fatalf("get toolset: got %+v (err: %v)", gotTS, err)
	}

	// User Credentials
	ucred := &domain.MCPUserCredential{
		ServerID:       srv.ID,
		UserID:         "user_alice",
		OrgID:          org.ID,
		EncryptedToken: "enc_token_xyz",
		EncryptedDEK:   "enc_dek_xyz",
	}
	if err := repo.SetMCPUserCredential(ctx, ucred); err != nil {
		t.Fatalf("set user credential: %v", err)
	}
	gotCred, err := repo.GetMCPUserCredential(ctx, srv.ID, "user_alice")
	if err != nil || gotCred.EncryptedToken != "enc_token_xyz" {
		t.Fatalf("get user cred: got %+v, err: %v", gotCred, err)
	}
}

func TestA2AStorageCRUDAndSequenceMonotonicity(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	org := &domain.Organization{Name: "Acme A2A", Slug: "acme-a2a", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	agent := &domain.A2AAgent{
		OrgID:              org.ID,
		Name:               "Weather Agent",
		Slug:               "weather",
		EndpointURL:        "https://agent.weather.internal/a2a",
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}
	if err := repo.CreateA2AAgent(ctx, agent); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	gotAgent, err := repo.GetA2AAgentBySlug(ctx, org.ID, "weather")
	if err != nil || gotAgent.Slug != "weather" {
		t.Fatalf("get agent by slug: %+v, err: %v", gotAgent, err)
	}

	// Kill Switch
	if err := repo.SetA2AAgentKillSwitch(ctx, agent.ID, true); err != nil {
		t.Fatalf("set kill switch: %v", err)
	}
	killedAgent, _ := repo.GetA2AAgent(ctx, agent.ID)
	if !killedAgent.IsKilled {
		t.Fatalf("expected agent to be killed")
	}

	// Create Task
	task := &domain.A2ATask{
		AgentID:          agent.ID,
		OrgID:            org.ID,
		VirtualKeyID:     "vk_123",
		State:            domain.A2ATaskStateSubmitted,
		InputMessageJSON: `{"text":"Check weather in SF"}`,
	}
	if err := repo.CreateA2ATask(ctx, task); err != nil {
		t.Fatalf("create task: %v", err)
	}

	// Register Push Config
	pushCfg := &domain.A2APushNotificationConfig{
		TaskID:    task.ID,
		TargetURL: "https://subscriber.client/webhook",
		AuthToken: "webhook_secret",
	}
	if err := repo.SetA2APushNotificationConfig(ctx, pushCfg); err != nil {
		t.Fatalf("set push config: %v", err)
	}

	// Test Concurrent AppendTaskEvent with strict sequence monotonicity
	const concurrentEvents = 20
	var wg sync.WaitGroup
	wg.Add(concurrentEvents)

	for i := 0; i < concurrentEvents; i++ {
		go func(idx int) {
			defer wg.Done()
			payload := fmt.Sprintf(`{"status":"processing_%d"}`, idx)
			_, err := repo.AppendA2ATaskEvent(ctx, task.ID, "status", payload)
			if err != nil {
				t.Errorf("append event error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Verify task LastEventSeq is exactly 20
	updatedTask, err := repo.GetA2ATask(ctx, task.ID)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if updatedTask.LastEventSeq != int64(concurrentEvents) {
		t.Fatalf("expected LastEventSeq == %d, got %d", concurrentEvents, updatedTask.LastEventSeq)
	}

	// Verify all events exist and sequences 1..20 are strictly monotonic with zero gaps
	events, err := repo.ListA2ATaskEvents(ctx, task.ID, 0, 100)
	if err != nil || len(events) != concurrentEvents {
		t.Fatalf("expected %d events, got %d (err: %v)", concurrentEvents, len(events), err)
	}
	seenSeqs := make(map[int64]bool)
	for _, e := range events {
		if seenSeqs[e.EventSeq] {
			t.Fatalf("duplicate sequence number %d detected!", e.EventSeq)
		}
		seenSeqs[e.EventSeq] = true
	}
	for s := int64(1); s <= int64(concurrentEvents); s++ {
		if !seenSeqs[s] {
			t.Fatalf("missing sequence number %d!", s)
		}
	}

	// Verify Stream Publications Queue
	pubs, err := repo.ClaimPendingA2AStreamPublications(ctx, 100)
	if err != nil || len(pubs) != concurrentEvents {
		t.Fatalf("expected %d stream publications, got %d (err: %v)", concurrentEvents, len(pubs), err)
	}
	for _, p := range pubs {
		if err := repo.MarkA2AStreamPublicationSuccess(ctx, p.ID); err != nil {
			t.Fatalf("mark publication success: %v", err)
		}
	}
	// After marking success, pending claims should be 0
	pubsAfter, _ := repo.ClaimPendingA2AStreamPublications(ctx, 100)
	if len(pubsAfter) != 0 {
		t.Fatalf("expected 0 pending publications, got %d", len(pubsAfter))
	}

	// Verify Outbox Events Queue (because push config was registered)
	outboxEvents, err := repo.ClaimPendingA2AOutboxEvents(ctx, 100)
	if err != nil || len(outboxEvents) != concurrentEvents {
		t.Fatalf("expected %d outbox events, got %d (err: %v)", concurrentEvents, len(outboxEvents), err)
	}
	for _, o := range outboxEvents {
		if err := repo.UpdateA2AOutboxEventStatus(ctx, o.ID, domain.OutboxStatusSent); err != nil {
			t.Fatalf("update outbox status: %v", err)
		}
	}
	outboxAfter, _ := repo.ClaimPendingA2AOutboxEvents(ctx, 100)
	if len(outboxAfter) != 0 {
		t.Fatalf("expected 0 pending outbox events, got %d", len(outboxAfter))
	}
}
