package storage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// -----------------------------------------------------------------------------
// MCP: Servers, Tools, Toolsets & BYOK Credentials
// -----------------------------------------------------------------------------

func (r *MemoryRepository) CreateMCPServer(ctx context.Context, server *domain.MCPServer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if server.ID == "" {
		server.ID = uuid.NewString()
	}
	if server.CreatedAt.IsZero() {
		server.CreatedAt = time.Now().UTC()
	}
	server.UpdatedAt = server.CreatedAt
	if server.ConfigVersion <= 0 {
		server.ConfigVersion = 1
	}
	cp := *server
	r.mcpServers[server.ID] = &cp
	return nil
}

func (r *MemoryRepository) UpdateMCPServer(ctx context.Context, server *domain.MCPServer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.mcpServers[server.ID]
	if !ok {
		return fmt.Errorf("mcp server %s not found", server.ID)
	}
	server.ConfigVersion = existing.ConfigVersion + 1
	server.UpdatedAt = time.Now().UTC()
	cp := *server
	r.mcpServers[server.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetMCPServer(ctx context.Context, id string) (*domain.MCPServer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.mcpServers[id]
	if !ok {
		return nil, fmt.Errorf("mcp server %s not found", id)
	}
	cp := *s
	return &cp, nil
}

func (r *MemoryRepository) GetMCPServerBySlug(ctx context.Context, orgID, slug string) (*domain.MCPServer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.mcpServers {
		if (orgID == "" || s.OrgID == orgID) && s.Slug == slug {
			cp := *s
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("mcp server with slug %q not found", slug)
}

func (r *MemoryRepository) ListMCPServers(ctx context.Context, orgID string) ([]*domain.MCPServer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.MCPServer
	for _, s := range r.mcpServers {
		if orgID == "" || s.OrgID == orgID {
			cp := *s
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *MemoryRepository) DeleteMCPServer(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.mcpServers, id)
	for tid, tool := range r.mcpTools {
		if tool.ServerID == id {
			delete(r.mcpTools, tid)
		}
	}
	return nil
}

func (r *MemoryRepository) UpsertMCPTools(ctx context.Context, serverID, orgID string, tools []*domain.MCPTool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	for _, t := range tools {
		if t.ID == "" {
			t.ID = uuid.NewString()
		}
		t.ServerID = serverID
		t.OrgID = orgID
		if t.CreatedAt.IsZero() {
			t.CreatedAt = now
		}
		t.UpdatedAt = now
		cp := *t
		r.mcpTools[t.ID] = &cp
	}
	return nil
}

func (r *MemoryRepository) ListMCPTools(ctx context.Context, serverID string) ([]*domain.MCPTool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.MCPTool
	for _, t := range r.mcpTools {
		if t.ServerID == serverID && t.IsActive {
			cp := *t
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *MemoryRepository) GetMCPTool(ctx context.Context, id string) (*domain.MCPTool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.mcpTools[id]
	if !ok {
		return nil, fmt.Errorf("mcp tool %s not found", id)
	}
	cp := *t
	return &cp, nil
}

func (r *MemoryRepository) CreateMCPToolset(ctx context.Context, toolset *domain.MCPToolset) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if toolset.ID == "" {
		toolset.ID = uuid.NewString()
	}
	if toolset.CreatedAt.IsZero() {
		toolset.CreatedAt = time.Now().UTC()
	}
	toolset.UpdatedAt = toolset.CreatedAt
	cp := *toolset
	r.mcpToolsets[toolset.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetMCPToolsetBySlug(ctx context.Context, orgID, slug string) (*domain.MCPToolset, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ts := range r.mcpToolsets {
		if (orgID == "" || ts.OrgID == orgID) && ts.Slug == slug {
			cp := *ts
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("mcp toolset %q not found", slug)
}

func (r *MemoryRepository) ListMCPToolsets(ctx context.Context, orgID string) ([]*domain.MCPToolset, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.MCPToolset
	for _, ts := range r.mcpToolsets {
		if orgID == "" || ts.OrgID == orgID {
			cp := *ts
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *MemoryRepository) SetMCPUserCredential(ctx context.Context, cred *domain.MCPUserCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cred.ID == "" {
		cred.ID = uuid.NewString()
	}
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = time.Now().UTC()
	}
	cred.UpdatedAt = time.Now().UTC()
	cp := *cred
	r.mcpUserCreds[cred.ServerID+":"+cred.UserID] = &cp
	return nil
}

func (r *MemoryRepository) GetMCPUserCredential(ctx context.Context, serverID, userID string) (*domain.MCPUserCredential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.mcpUserCreds[serverID+":"+userID]
	if !ok {
		return nil, fmt.Errorf("credential for server %s user %s not found", serverID, userID)
	}
	cp := *c
	return &cp, nil
}

// GetMCPRuntimeSettings returns the active gateway-wide MCP protocol specification settings.
func (r *MemoryRepository) GetMCPRuntimeSettings(ctx context.Context) (*domain.MCPRuntimeSettings, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.mcpRuntimeSetting == nil {
		return &domain.MCPRuntimeSettings{
			ActiveProtocolVersion: domain.MCPProtocolVersion20260728,
			UpdatedBy:             "system",
		}, nil
	}
	cp := *r.mcpRuntimeSetting
	return &cp, nil
}

// UpdateMCPRuntimeSettings updates the gateway-wide MCP protocol specification settings.
func (r *MemoryRepository) UpdateMCPRuntimeSettings(ctx context.Context, settings *domain.MCPRuntimeSettings) error {
	if settings == nil {
		return fmt.Errorf("mcp runtime settings cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *settings
	if cp.UpdatedAt.IsZero() {
		cp.UpdatedAt = time.Now().UTC()
	}
	r.mcpRuntimeSetting = &cp
	return nil
}

// -----------------------------------------------------------------------------
// A2A: Agents, Tasks, Events, Publications & Outbox
// -----------------------------------------------------------------------------

func (r *MemoryRepository) CreateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if agent.ID == "" {
		agent.ID = uuid.NewString()
	}
	if agent.TaskVisibilityMode == "" {
		agent.TaskVisibilityMode = domain.TaskVisibilityKeyStrict
	}
	if agent.MaxTaskIterations <= 0 {
		agent.MaxTaskIterations = 50
	}
	if agent.CreatedAt.IsZero() {
		agent.CreatedAt = time.Now().UTC()
	}
	agent.UpdatedAt = agent.CreatedAt
	cp := *agent
	r.a2aAgents[agent.ID] = &cp
	return nil
}

func (r *MemoryRepository) UpdateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.a2aAgents[agent.ID]; !ok {
		return fmt.Errorf("a2a agent %s not found", agent.ID)
	}
	agent.UpdatedAt = time.Now().UTC()
	cp := *agent
	r.a2aAgents[agent.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetA2AAgent(ctx context.Context, id string) (*domain.A2AAgent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.a2aAgents[id]
	if !ok {
		return nil, fmt.Errorf("a2a agent %s not found", id)
	}
	cp := *a
	return &cp, nil
}

func (r *MemoryRepository) GetA2AAgentBySlug(ctx context.Context, orgID, slug string) (*domain.A2AAgent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.a2aAgents {
		if (orgID == "" || a.OrgID == orgID) && a.Slug == slug {
			cp := *a
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("a2a agent %q not found", slug)
}

func (r *MemoryRepository) ListA2AAgents(ctx context.Context, orgID string) ([]*domain.A2AAgent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.A2AAgent
	for _, a := range r.a2aAgents {
		if orgID == "" || a.OrgID == orgID {
			cp := *a
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *MemoryRepository) SetA2AAgentKillSwitch(ctx context.Context, id string, killed bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.a2aAgents[id]
	if !ok {
		return fmt.Errorf("a2a agent %s not found", id)
	}
	a.IsKilled = killed
	a.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) CreateA2ATask(ctx context.Context, task *domain.A2ATask) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if task.ID == "" {
		task.ID = uuid.NewString()
	}
	if task.State == "" {
		task.State = domain.A2ATaskStateSubmitted
	}
	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now().UTC()
	}
	task.UpdatedAt = task.CreatedAt
	cp := *task
	r.a2aTasks[task.ID] = &cp
	return nil
}

func (r *MemoryRepository) UpdateA2ATaskState(ctx context.Context, taskID, state string, outputJSON string, costMicros int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.a2aTasks[taskID]
	if !ok {
		return fmt.Errorf("a2a task %s not found", taskID)
	}
	t.State = state
	if outputJSON != "" {
		t.OutputMessageJSON = outputJSON
	}
	if costMicros > 0 {
		t.TotalCostMicros += costMicros
	}
	t.UpdatedAt = time.Now().UTC()
	if state == domain.A2ATaskStateCompleted || state == domain.A2ATaskStateFailed || state == domain.A2ATaskStateCanceled {
		now := time.Now().UTC()
		t.CompletedAt = &now
	}
	return nil
}

func (r *MemoryRepository) GetA2ATask(ctx context.Context, id string) (*domain.A2ATask, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.a2aTasks[id]
	if !ok {
		return nil, fmt.Errorf("a2a task %s not found", id)
	}
	cp := *t
	return &cp, nil
}

func (r *MemoryRepository) ListA2ATasks(ctx context.Context, agentID, virtualKeyID string, limit int) ([]*domain.A2ATask, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	var out []*domain.A2ATask
	for _, t := range r.a2aTasks {
		if (agentID == "" || t.AgentID == agentID) && (virtualKeyID == "" || t.VirtualKeyID == virtualKeyID) {
			cp := *t
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *MemoryRepository) AppendA2ATaskEvent(ctx context.Context, taskID, eventType, payloadJSON string) (*domain.A2ATaskEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	task, ok := r.a2aTasks[taskID]
	if !ok {
		return nil, fmt.Errorf("a2a task %s not found", taskID)
	}

	// Strictly monotonic sequence increment
	task.LastEventSeq++
	task.UpdatedAt = time.Now().UTC()

	event := &domain.A2ATaskEvent{
		ID:          uuid.NewString(),
		TaskID:      taskID,
		EventSeq:    task.LastEventSeq,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
		CreatedAt:   time.Now().UTC(),
	}

	r.a2aTaskEvents[taskID] = append(r.a2aTaskEvents[taskID], event)

	// Insert into stream publications queue for Redis broadcast
	pub := &domain.A2AStreamPublication{
		ID:            uuid.NewString(),
		TaskID:        taskID,
		EventSeq:      task.LastEventSeq,
		PayloadJSON:   payloadJSON,
		Published:     false,
		NextAttemptAt: time.Now().UTC(),
		CreatedAt:     time.Now().UTC(),
	}
	r.a2aStreamPubs = append(r.a2aStreamPubs, pub)

	// If push notification config is registered, enqueue outbox event
	if pushCfg, exists := r.a2aPushConfigs[taskID]; exists {
		outbox := &domain.A2AOutboxEvent{
			ID:            uuid.NewString(),
			TaskID:        taskID,
			EventType:     eventType,
			TargetURL:     pushCfg.TargetURL,
			PayloadJSON:   payloadJSON,
			Status:        domain.OutboxStatusPending,
			NextAttemptAt: time.Now().UTC(),
			CreatedAt:     time.Now().UTC(),
		}
		r.a2aOutbox = append(r.a2aOutbox, outbox)
	}

	cp := *event
	return &cp, nil
}

func (r *MemoryRepository) ListA2ATaskEvents(ctx context.Context, taskID string, afterSeq int64, limit int) ([]*domain.A2ATaskEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	events := r.a2aTaskEvents[taskID]
	var out []*domain.A2ATaskEvent
	for _, e := range events {
		if e.EventSeq > afterSeq {
			cp := *e
			out = append(out, &cp)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (r *MemoryRepository) ClaimPendingA2AStreamPublications(ctx context.Context, batchSize int) ([]*domain.A2AStreamPublication, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if batchSize <= 0 {
		batchSize = 50
	}
	now := time.Now().UTC()
	var out []*domain.A2AStreamPublication
	for _, p := range r.a2aStreamPubs {
		if !p.Published && !now.Before(p.NextAttemptAt) {
			p.AttemptCount++
			p.NextAttemptAt = now.Add(5 * time.Second)
			cp := *p
			out = append(out, &cp)
			if len(out) >= batchSize {
				break
			}
		}
	}
	return out, nil
}

func (r *MemoryRepository) MarkA2AStreamPublicationSuccess(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.a2aStreamPubs {
		if p.ID == id {
			p.Published = true
			return nil
		}
	}
	return nil
}

func (r *MemoryRepository) CreateA2AOutboxEvent(ctx context.Context, event *domain.A2AOutboxEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.Status == "" {
		event.Status = domain.OutboxStatusPending
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	cp := *event
	r.a2aOutbox = append(r.a2aOutbox, &cp)
	return nil
}

func (r *MemoryRepository) ClaimPendingA2AOutboxEvents(ctx context.Context, batchSize int) ([]*domain.A2AOutboxEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if batchSize <= 0 {
		batchSize = 25
	}
	now := time.Now().UTC()
	var out []*domain.A2AOutboxEvent
	for _, o := range r.a2aOutbox {
		if o.Status == domain.OutboxStatusPending && !now.Before(o.NextAttemptAt) {
			o.AttemptCount++
			o.NextAttemptAt = now.Add(10 * time.Second)
			cp := *o
			out = append(out, &cp)
			if len(out) >= batchSize {
				break
			}
		}
	}
	return out, nil
}

func (r *MemoryRepository) UpdateA2AOutboxEvent(ctx context.Context, ev *domain.A2AOutboxEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, o := range r.a2aOutbox {
		if o.ID == ev.ID {
			cp := *ev
			r.a2aOutbox[i] = &cp
			return nil
		}
	}
	return fmt.Errorf("outbox event %s not found", ev.ID)
}

func (r *MemoryRepository) UpdateA2AOutboxEventStatus(ctx context.Context, id, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.a2aOutbox {
		if o.ID == id {
			o.Status = status
			return nil
		}
	}
	return nil
}

func (r *MemoryRepository) GetA2AOutboxEvent(ctx context.Context, id string) (*domain.A2AOutboxEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, o := range r.a2aOutbox {
		if o.ID == id {
			cp := *o
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("outbox event %s not found", id)
}

func (r *MemoryRepository) SetA2APushNotificationConfig(ctx context.Context, cfg *domain.A2APushNotificationConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cfg.ID == "" {
		cfg.ID = uuid.NewString()
	}
	if cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = time.Now().UTC()
	}
	cp := *cfg
	r.a2aPushConfigs[cfg.TaskID] = &cp
	return nil
}

func (r *MemoryRepository) GetA2APushNotificationConfig(ctx context.Context, taskID string) (*domain.A2APushNotificationConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.a2aPushConfigs[taskID]
	if !ok {
		return nil, fmt.Errorf("push notification config for task %s not found", taskID)
	}
	cp := *c
	return &cp, nil
}

// Files Management

func (r *MemoryRepository) CreateFile(ctx context.Context, file *domain.CanonicalFile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if file.ID == "" {
		file.ID = uuid.NewString()
	}
	if file.CreatedAt.IsZero() {
		file.CreatedAt = time.Now().UTC()
	}
	cp := *file
	r.files[file.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetFile(ctx context.Context, orgID, fileID string) (*domain.CanonicalFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.files[fileID]
	if !ok || (orgID != "" && f.OrgID != orgID) {
		return nil, fmt.Errorf("file %s not found", fileID)
	}
	cp := *f
	return &cp, nil
}

func (r *MemoryRepository) ListFiles(ctx context.Context, orgID string, purpose string) ([]*domain.CanonicalFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.CanonicalFile
	for _, f := range r.files {
		if (orgID == "" || f.OrgID == orgID) && (purpose == "" || f.Purpose == purpose) {
			cp := *f
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (r *MemoryRepository) DeleteFile(ctx context.Context, orgID, fileID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.files[fileID]
	if !ok || (orgID != "" && f.OrgID != orgID) {
		return fmt.Errorf("file %s not found", fileID)
	}
	delete(r.files, fileID)
	return nil
}

// Batches Management

func (r *MemoryRepository) CreateBatch(ctx context.Context, batch *domain.CanonicalBatch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if batch.ID == "" {
		batch.ID = uuid.NewString()
	}
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = time.Now().UTC()
	}
	cp := *batch
	r.batches[batch.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetBatch(ctx context.Context, orgID, batchID string) (*domain.CanonicalBatch, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.batches[batchID]
	if !ok || (orgID != "" && b.OrgID != orgID) {
		return nil, fmt.Errorf("batch %s not found", batchID)
	}
	cp := *b
	return &cp, nil
}

func (r *MemoryRepository) ListBatches(ctx context.Context, orgID string, limit int) ([]*domain.CanonicalBatch, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	var out []*domain.CanonicalBatch
	for _, b := range r.batches {
		if orgID == "" || b.OrgID == orgID {
			cp := *b
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *MemoryRepository) UpdateBatchStatus(ctx context.Context, batchID string, status string, outputFileID string, counts domain.BatchCounts, completedAt *time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.batches[batchID]
	if !ok {
		return fmt.Errorf("batch %s not found", batchID)
	}
	b.Status = status
	if outputFileID != "" {
		b.OutputFileID = outputFileID
	}
	b.RequestCounts = counts
	b.CompletedAt = completedAt
	return nil
}
