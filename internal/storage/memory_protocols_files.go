package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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

func isTerminalA2ADomainState(state string) bool {
	switch state {
	case domain.A2ATaskStateCompleted, domain.A2ATaskStateFailed, domain.A2ATaskStateCanceled, domain.A2ATaskStateRejected:
		return true
	default:
		return false
	}
}

func buildA2AStreamEnvelope(seq int64, eventType, taskState, payloadJSON string) string {
	trimmed := strings.TrimSpace(payloadJSON)
	var raw json.RawMessage
	if json.Valid([]byte(trimmed)) {
		raw = json.RawMessage(trimmed)
	} else {
		b, _ := json.Marshal(payloadJSON)
		raw = b
	}
	env := struct {
		EventSeq       int64           `json:"event_seq"`
		EventType      string          `json:"event_type"`
		State          string          `json:"state"`
		StreamResponse json.RawMessage `json:"stream_response"`
	}{
		EventSeq:       seq,
		EventType:      eventType,
		State:          taskState,
		StreamResponse: raw,
	}
	b, _ := json.Marshal(env)
	return string(b)
}

func cloneA2ATask(t *domain.A2ATask) *domain.A2ATask {
	if t == nil {
		return nil
	}
	cp := *t
	if t.CompletedAt != nil {
		ct := *t.CompletedAt
		cp.CompletedAt = &ct
	}
	if t.StatusTimestamp != nil {
		st := *t.StatusTimestamp
		cp.StatusTimestamp = &st
	}
	return &cp
}

func (r *MemoryRepository) CreateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.a2aAgents {
		if existing.OrgID == agent.OrgID && existing.Slug == agent.Slug {
			return fmt.Errorf("a2a agent slug %q already exists in org %q", agent.Slug, agent.OrgID)
		}
	}
	if agent.ID == "" {
		agent.ID = uuid.NewString()
	}
	if agent.TaskVisibilityMode == "" {
		agent.TaskVisibilityMode = domain.TaskVisibilityKeyStrict
	}
	if agent.ProtocolBinding == "" {
		agent.ProtocolBinding = domain.A2AProtocolBindingHTTPJSON
	}
	if agent.AuthType == "" {
		agent.AuthType = "none"
	}
	if agent.AuthHeaderName == "" {
		agent.AuthHeaderName = "Authorization"
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
	for _, existing := range r.a2aAgents {
		if existing.ID != agent.ID && existing.OrgID == agent.OrgID && existing.Slug == agent.Slug {
			return fmt.Errorf("a2a agent slug %q already exists in org %q", agent.Slug, agent.OrgID)
		}
	}
	agent.UpdatedAt = time.Now().UTC()
	cp := *agent
	r.a2aAgents[agent.ID] = &cp
	return nil
}

func (r *MemoryRepository) DeleteA2AAgent(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.a2aAgents[id]; !ok {
		return fmt.Errorf("a2a agent %s not found", id)
	}
	delete(r.a2aAgents, id)
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
	out := make([]*domain.A2AAgent, 0)
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
	r.a2aTasks[task.ID] = cloneA2ATask(task)
	return nil
}

func (r *MemoryRepository) UpdateA2ATask(ctx context.Context, task *domain.A2ATask, costDeltaMicros int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if task == nil || task.ID == "" {
		return fmt.Errorf("a2a task is required")
	}
	t, ok := r.a2aTasks[task.ID]
	if !ok {
		return fmt.Errorf("a2a task %s not found", task.ID)
	}
	if task.State != "" {
		t.State = task.State
	}
	if task.ContextID != "" {
		t.ContextID = task.ContextID
	}
	if task.ClientTaskID != "" {
		t.ClientTaskID = task.ClientTaskID
	}
	if task.OutputMessageJSON != "" {
		t.OutputMessageJSON = task.OutputMessageJSON
	}
	if task.StatusMessageJSON != "" {
		t.StatusMessageJSON = task.StatusMessageJSON
	}
	if task.StatusTimestamp != nil {
		st := *task.StatusTimestamp
		t.StatusTimestamp = &st
	}
	if task.HistoryJSON != "" {
		t.HistoryJSON = task.HistoryJSON
	}
	if task.ArtifactsJSON != "" {
		t.ArtifactsJSON = task.ArtifactsJSON
	}
	if task.MetadataJSON != "" {
		t.MetadataJSON = task.MetadataJSON
	}
	if costDeltaMicros > 0 {
		t.TotalCostMicros += costDeltaMicros
	}
	t.UpdatedAt = time.Now().UTC()
	if task.CompletedAt != nil {
		ct := *task.CompletedAt
		t.CompletedAt = &ct
	} else if isTerminalA2ADomainState(t.State) && t.CompletedAt == nil {
		now := time.Now().UTC()
		t.CompletedAt = &now
	}
	task.TotalCostMicros = t.TotalCostMicros
	task.UpdatedAt = t.UpdatedAt
	if t.CompletedAt != nil {
		ct := *t.CompletedAt
		task.CompletedAt = &ct
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
	return cloneA2ATask(t), nil
}

func (r *MemoryRepository) ListA2ATasks(ctx context.Context, filter domain.A2ATaskListFilter) ([]*domain.A2ATask, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	matched := make([]*domain.A2ATask, 0)
	for _, t := range r.a2aTasks {
		if filter.AgentID != "" && t.AgentID != filter.AgentID {
			continue
		}
		if filter.OrgID != "" && t.OrgID != filter.OrgID {
			continue
		}
		if filter.VirtualKeyID != "" && t.VirtualKeyID != filter.VirtualKeyID {
			continue
		}
		if filter.ContextID != "" && t.ContextID != filter.ContextID {
			continue
		}
		if filter.State != "" && t.State != filter.State {
			continue
		}
		if filter.UpdatedAfter != nil && !t.UpdatedAt.After(*filter.UpdatedAfter) {
			continue
		}
		matched = append(matched, cloneA2ATask(t))
	}
	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].UpdatedAt.Equal(matched[j].UpdatedAt) {
			return matched[i].UpdatedAt.After(matched[j].UpdatedAt)
		}
		return matched[i].ID > matched[j].ID
	})
	total := len(matched)
	offset := max(filter.Offset, 0)
	if offset >= total {
		return []*domain.A2ATask{}, total, nil
	}
	matched = matched[offset:]
	limit := filter.Limit
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, total, nil
}

func (r *MemoryRepository) AppendA2ATaskEvent(ctx context.Context, taskID, eventType, payloadJSON string) (*domain.A2ATaskEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	task, ok := r.a2aTasks[taskID]
	if !ok {
		return nil, fmt.Errorf("a2a task %s not found", taskID)
	}

	task.LastEventSeq++
	now := time.Now().UTC()
	task.UpdatedAt = now

	event := &domain.A2ATaskEvent{
		ID:          uuid.NewString(),
		TaskID:      taskID,
		EventSeq:    task.LastEventSeq,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
		CreatedAt:   now,
	}

	r.a2aTaskEvents[taskID] = append(r.a2aTaskEvents[taskID], event)

	envelopeJSON := buildA2AStreamEnvelope(task.LastEventSeq, eventType, task.State, payloadJSON)
	pub := &domain.A2AStreamPublication{
		ID:            uuid.NewString(),
		TaskID:        taskID,
		EventSeq:      task.LastEventSeq,
		PayloadJSON:   envelopeJSON,
		Published:     false,
		NextAttemptAt: now,
		CreatedAt:     now,
	}
	r.a2aStreamPubs = append(r.a2aStreamPubs, pub)

	// Enqueue one outbox event per registered push notification config for this task
	for _, pushCfg := range r.a2aPushConfigs {
		if pushCfg == nil || pushCfg.TaskID != taskID || pushCfg.TargetURL == "" {
			continue
		}
		outbox := &domain.A2AOutboxEvent{
			ID:            uuid.NewString(),
			TaskID:        taskID,
			PushConfigID:  pushCfg.ID,
			EventType:     eventType,
			TargetURL:     pushCfg.TargetURL,
			PayloadJSON:   payloadJSON,
			Status:        domain.OutboxStatusPending,
			NextAttemptAt: now,
			CreatedAt:     now,
			UpdatedAt:     now,
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
	out := make([]*domain.A2ATaskEvent, 0)
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
	out := make([]*domain.A2AStreamPublication, 0)
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
	event.UpdatedAt = event.CreatedAt
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
	out := make([]*domain.A2AOutboxEvent, 0)
	for _, o := range r.a2aOutbox {
		if o.Status == domain.OutboxStatusPending && !now.Before(o.NextAttemptAt) {
			o.AttemptCount++
			o.NextAttemptAt = now.Add(10 * time.Second)
			o.UpdatedAt = now
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
			cp.UpdatedAt = time.Now().UTC()
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
			o.UpdatedAt = time.Now().UTC()
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

func (r *MemoryRepository) ListA2AOutboxEvents(ctx context.Context, orgID, status string, limit int) ([]*domain.A2AOutboxEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	out := make([]*domain.A2AOutboxEvent, 0)
	for _, o := range r.a2aOutbox {
		if status != "" && o.Status != status {
			continue
		}
		if orgID != "" {
			t, ok := r.a2aTasks[o.TaskID]
			if !ok || t.OrgID != orgID {
				continue
			}
		}
		cp := *o
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *MemoryRepository) ReplayA2AOutboxEvent(ctx context.Context, id string) (*domain.A2AOutboxEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	for _, o := range r.a2aOutbox {
		if o.ID == id {
			o.Status = domain.OutboxStatusPending
			o.AttemptCount = 0
			o.LastError = ""
			o.NextAttemptAt = now
			o.UpdatedAt = now
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
		cfg.ID = "push_cfg_" + uuid.NewString()
	}
	now := time.Now().UTC()
	if cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = now
	}
	cfg.UpdatedAt = now
	cp := *cfg
	r.a2aPushConfigs[cfg.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetA2APushNotificationConfig(ctx context.Context, taskID, configID string) (*domain.A2APushNotificationConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if configID != "" {
		c, ok := r.a2aPushConfigs[configID]
		if !ok || (taskID != "" && c.TaskID != taskID) {
			return nil, fmt.Errorf("push notification config %s for task %s not found", configID, taskID)
		}
		cp := *c
		return &cp, nil
	}
	var latest *domain.A2APushNotificationConfig
	for _, c := range r.a2aPushConfigs {
		if c.TaskID == taskID {
			if latest == nil || c.CreatedAt.After(latest.CreatedAt) {
				latest = c
			}
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("push notification config for task %s not found", taskID)
	}
	cp := *latest
	return &cp, nil
}

func (r *MemoryRepository) ListA2APushNotificationConfigs(ctx context.Context, taskID string, limit, offset int) ([]*domain.A2APushNotificationConfig, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.A2APushNotificationConfig, 0)
	for _, c := range r.a2aPushConfigs {
		if c.TaskID == taskID {
			cp := *c
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	total := len(out)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*domain.A2APushNotificationConfig{}, total, nil
	}
	out = out[offset:]
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, total, nil
}

func (r *MemoryRepository) DeleteA2APushNotificationConfig(ctx context.Context, taskID, configID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if configID != "" {
		c, ok := r.a2aPushConfigs[configID]
		if !ok || (taskID != "" && c.TaskID != taskID) {
			return fmt.Errorf("push notification config %s for task %s not found", configID, taskID)
		}
		delete(r.a2aPushConfigs, configID)
		return nil
	}
	deleted := 0
	for id, c := range r.a2aPushConfigs {
		if c.TaskID == taskID {
			delete(r.a2aPushConfigs, id)
			deleted++
		}
	}
	if deleted == 0 {
		return fmt.Errorf("push notification config for task %s not found", taskID)
	}
	return nil
}

func (r *MemoryRepository) PruneExpiredA2ARecords(ctx context.Context, pubBefore, outboxBefore, taskBefore time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var total int64

	if !pubBefore.IsZero() {
		cut := pubBefore.UTC()
		kept := make([]*domain.A2AStreamPublication, 0, len(r.a2aStreamPubs))
		for _, p := range r.a2aStreamPubs {
			if p.Published && p.CreatedAt.Before(cut) {
				total++
				continue
			}
			kept = append(kept, p)
		}
		r.a2aStreamPubs = kept
	}

	if !outboxBefore.IsZero() {
		cut := outboxBefore.UTC()
		kept := make([]*domain.A2AOutboxEvent, 0, len(r.a2aOutbox))
		for _, e := range r.a2aOutbox {
			if (e.Status == domain.OutboxStatusSent || e.Status == domain.OutboxStatusDeadLetter) && e.UpdatedAt.Before(cut) {
				total++
				continue
			}
			kept = append(kept, e)
		}
		r.a2aOutbox = kept
	}

	if !taskBefore.IsZero() {
		cut := taskBefore.UTC()
		prunedTasks := make(map[string]struct{})
		for id, t := range r.a2aTasks {
			if domain.IsTerminalA2ATaskState(t.State) && t.UpdatedAt.Before(cut) {
				delete(r.a2aTasks, id)
				delete(r.a2aTaskEvents, id)
				prunedTasks[id] = struct{}{}
				total++
			}
		}
		if len(prunedTasks) > 0 {
			for cfgID, cfg := range r.a2aPushConfigs {
				if _, ok := prunedTasks[cfg.TaskID]; ok {
					delete(r.a2aPushConfigs, cfgID)
				}
			}
			keptPubs := make([]*domain.A2AStreamPublication, 0, len(r.a2aStreamPubs))
			for _, p := range r.a2aStreamPubs {
				if _, ok := prunedTasks[p.TaskID]; ok {
					continue
				}
				keptPubs = append(keptPubs, p)
			}
			r.a2aStreamPubs = keptPubs

			keptOutbox := make([]*domain.A2AOutboxEvent, 0, len(r.a2aOutbox))
			for _, e := range r.a2aOutbox {
				if _, ok := prunedTasks[e.TaskID]; ok {
					continue
				}
				keptOutbox = append(keptOutbox, e)
			}
			r.a2aOutbox = keptOutbox
		}
	}

	return total, nil
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
