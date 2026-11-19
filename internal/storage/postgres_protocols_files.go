package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
)

// -----------------------------------------------------------------------------
// MCP: Servers, Tools, Toolsets & BYOK Credentials
// -----------------------------------------------------------------------------

func (p *PostgresRepository) CreateMCPServer(ctx context.Context, server *domain.MCPServer) error {
	if server.ID == "" {
		server.ID = uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.CreateMCPServer(ctx, server)
	}
	headersJSON, _ := json.Marshal(server.StaticHeaders)
	const q = `
		INSERT INTO mcp_servers (
			id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
			config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
			static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
			pinned_tool_hash, rpm_limit, is_active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	if _, err := p.pool.Exec(ctx, q,
		server.ID, server.OrgID, server.Name, server.Slug, server.ProtocolVersion, server.TransportType, server.EndpointURL,
		server.ConfigVersion, server.AuthType, server.EncryptedAuthSecret, server.EncryptedAuthDEK,
		headersJSON, server.OAuth2Endpoint, server.OAuth2ClientID, server.OAuth2Scopes,
		server.PinnedToolHash, server.RPMLimit, server.IsActive,
	); err != nil {
		return err
	}
	return p.mem.CreateMCPServer(ctx, server)
}

func (p *PostgresRepository) UpdateMCPServer(ctx context.Context, server *domain.MCPServer) error {
	if p.pool == nil {
		return p.mem.UpdateMCPServer(ctx, server)
	}
	headersJSON, _ := json.Marshal(server.StaticHeaders)
	const q = `
		UPDATE mcp_servers SET
			name = $2, slug = $3, protocol_version = $4, transport_type = $5, endpoint_url = $6,
			config_version = config_version + 1, auth_type = $7, encrypted_auth_secret = $8, encrypted_auth_dek = $9,
			static_headers = $10, oauth2_endpoint = $11, oauth2_client_id = $12, oauth2_scopes = $13,
			pinned_tool_hash = $14, rpm_limit = $15, is_active = $16, updated_at = NOW()
		WHERE id = $1 RETURNING config_version`
	var newVersion int64
	if err := p.pool.QueryRow(ctx, q,
		server.ID, server.Name, server.Slug, server.ProtocolVersion, server.TransportType, server.EndpointURL,
		server.AuthType, server.EncryptedAuthSecret, server.EncryptedAuthDEK,
		headersJSON, server.OAuth2Endpoint, server.OAuth2ClientID, server.OAuth2Scopes,
		server.PinnedToolHash, server.RPMLimit, server.IsActive,
	).Scan(&newVersion); err != nil {
		return err
	}
	server.ConfigVersion = newVersion
	if err := p.mem.UpdateMCPServer(ctx, server); err != nil {
		_ = p.mem.CreateMCPServer(ctx, server)
	}
	return nil
}

func (p *PostgresRepository) GetMCPServer(ctx context.Context, id string) (*domain.MCPServer, error) {
	if p.pool == nil {
		return p.mem.GetMCPServer(ctx, id)
	}
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, rpm_limit, is_active, created_at, updated_at
		FROM mcp_servers WHERE id = $1`
	var s domain.MCPServer
	var headersJSON []byte
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
		&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
		&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
		&s.PinnedToolHash, &s.RPMLimit, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("mcp server %s not found: %w", id, err)
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
	}
	_ = p.mem.CreateMCPServer(ctx, &s)
	return &s, nil
}

func (p *PostgresRepository) GetMCPServerBySlug(ctx context.Context, orgID, slug string) (*domain.MCPServer, error) {
	if p.pool == nil {
		return p.mem.GetMCPServerBySlug(ctx, orgID, slug)
	}
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, rpm_limit, is_active, created_at, updated_at
		FROM mcp_servers WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var s domain.MCPServer
	var headersJSON []byte
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(
		&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
		&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
		&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
		&s.PinnedToolHash, &s.RPMLimit, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("mcp server %q not found: %w", slug, err)
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
	}
	_ = p.mem.CreateMCPServer(ctx, &s)
	return &s, nil
}

func (p *PostgresRepository) ListMCPServers(ctx context.Context, orgID string) ([]*domain.MCPServer, error) {
	if p.pool == nil {
		return p.mem.ListMCPServers(ctx, orgID)
	}
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, rpm_limit, is_active, created_at, updated_at
		FROM mcp_servers WHERE org_id = $1 OR $1 = '' ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListMCPServers(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.MCPServer
	for rows.Next() {
		var s domain.MCPServer
		var headersJSON []byte
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
			&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
			&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
			&s.PinnedToolHash, &s.RPMLimit, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
		); err == nil {
			if len(headersJSON) > 0 {
				_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
			}
			out = append(out, &s)
		}
	}
	return out, nil
}

func (p *PostgresRepository) DeleteMCPServer(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM mcp_servers WHERE id = $1`, id)
	_ = p.mem.DeleteMCPServer(ctx, id)
	return err
}

func (p *PostgresRepository) UpsertMCPTools(ctx context.Context, serverID, orgID string, tools []*domain.MCPTool) error {
	if len(tools) == 0 {
		return p.mem.UpsertMCPTools(ctx, serverID, orgID, tools)
	}
	const q = `
		INSERT INTO mcp_tools (id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (server_id, name) DO UPDATE SET
			description = EXCLUDED.description,
			input_schema = EXCLUDED.input_schema,
			tool_def_hash = EXCLUDED.tool_def_hash,
			cost_per_call_micros = EXCLUDED.cost_per_call_micros,
			is_active = EXCLUDED.is_active,
			updated_at = NOW()`
	batch := &pgx.Batch{}
	for _, t := range tools {
		if t.ID == "" {
			t.ID = uuid.NewString()
		}
		schemaJSON, _ := json.Marshal(t.InputSchema)
		batch.Queue(q, t.ID, serverID, orgID, t.Name, t.Description, schemaJSON, t.ToolDefHash, t.CostPerCallMicros, t.IsActive)
	}
	br := p.pool.SendBatch(ctx, batch)
	for range tools {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	if err := br.Close(); err != nil {
		return err
	}
	return p.mem.UpsertMCPTools(ctx, serverID, orgID, tools)
}

func (p *PostgresRepository) ListMCPTools(ctx context.Context, serverID string) ([]*domain.MCPTool, error) {
	const q = `SELECT id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, created_at, updated_at FROM mcp_tools WHERE server_id = $1 AND is_active = TRUE ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, serverID)
	if err != nil {
		return p.mem.ListMCPTools(ctx, serverID)
	}
	defer rows.Close()

	var out []*domain.MCPTool
	for rows.Next() {
		var t domain.MCPTool
		var schemaJSON []byte
		if err := rows.Scan(&t.ID, &t.ServerID, &t.OrgID, &t.Name, &t.Description, &schemaJSON, &t.ToolDefHash, &t.CostPerCallMicros, &t.IsActive, &t.CreatedAt, &t.UpdatedAt); err == nil {
			if len(schemaJSON) > 0 {
				_ = json.Unmarshal(schemaJSON, &t.InputSchema)
			}
			out = append(out, &t)
		}
	}
	return out, nil
}

func (p *PostgresRepository) GetMCPTool(ctx context.Context, id string) (*domain.MCPTool, error) {
	if p.pool == nil {
		return p.mem.GetMCPTool(ctx, id)
	}
	const q = `SELECT id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, created_at, updated_at FROM mcp_tools WHERE id = $1`
	var t domain.MCPTool
	var schemaJSON []byte
	if err := p.pool.QueryRow(ctx, q, id).Scan(&t.ID, &t.ServerID, &t.OrgID, &t.Name, &t.Description, &schemaJSON, &t.ToolDefHash, &t.CostPerCallMicros, &t.IsActive, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, fmt.Errorf("mcp tool %s not found: %w", id, err)
	}
	if len(schemaJSON) > 0 {
		_ = json.Unmarshal(schemaJSON, &t.InputSchema)
	}
	return &t, nil
}

func (p *PostgresRepository) CreateMCPToolset(ctx context.Context, toolset *domain.MCPToolset) error {
	if toolset.ID == "" {
		toolset.ID = uuid.NewString()
	}
	toolIDs := toolset.ToolIDs
	if toolIDs == nil {
		toolIDs = []string{}
	}
	const q = `INSERT INTO mcp_toolsets (id, org_id, name, slug, tool_ids, is_active) VALUES ($1,$2,$3,$4,$5,$6)`
	if _, err := p.pool.Exec(ctx, q, toolset.ID, toolset.OrgID, toolset.Name, toolset.Slug, toolIDs, toolset.IsActive); err != nil {
		return err
	}
	return p.mem.CreateMCPToolset(ctx, toolset)
}

func (p *PostgresRepository) GetMCPToolsetBySlug(ctx context.Context, orgID, slug string) (*domain.MCPToolset, error) {
	if ts, err := p.mem.GetMCPToolsetBySlug(ctx, orgID, slug); err == nil && ts != nil {
		return ts, nil
	}
	const q = `SELECT id, org_id, name, slug, tool_ids, is_active, created_at, updated_at FROM mcp_toolsets WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var ts domain.MCPToolset
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(&ts.ID, &ts.OrgID, &ts.Name, &ts.Slug, &ts.ToolIDs, &ts.IsActive, &ts.CreatedAt, &ts.UpdatedAt); err != nil {
		return nil, fmt.Errorf("mcp toolset %q not found: %w", slug, err)
	}
	_ = p.mem.CreateMCPToolset(ctx, &ts)
	return &ts, nil
}

func (p *PostgresRepository) ListMCPToolsets(ctx context.Context, orgID string) ([]*domain.MCPToolset, error) {
	const q = `SELECT id, org_id, name, slug, tool_ids, is_active, created_at, updated_at FROM mcp_toolsets WHERE org_id = $1 OR $1 = ''`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListMCPToolsets(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.MCPToolset
	for rows.Next() {
		var ts domain.MCPToolset
		if err := rows.Scan(&ts.ID, &ts.OrgID, &ts.Name, &ts.Slug, &ts.ToolIDs, &ts.IsActive, &ts.CreatedAt, &ts.UpdatedAt); err == nil {
			out = append(out, &ts)
		}
	}
	return out, nil
}

func (p *PostgresRepository) SetMCPUserCredential(ctx context.Context, cred *domain.MCPUserCredential) error {
	if cred.ID == "" {
		cred.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO mcp_user_credentials (id, server_id, user_id, org_id, encrypted_token, encrypted_dek, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (server_id, user_id) DO UPDATE SET
			encrypted_token = EXCLUDED.encrypted_token,
			encrypted_dek = EXCLUDED.encrypted_dek,
			updated_at = NOW()`
	if _, err := p.pool.Exec(ctx, q, cred.ID, cred.ServerID, cred.UserID, cred.OrgID, cred.EncryptedToken, cred.EncryptedDEK); err != nil {
		return err
	}
	return p.mem.SetMCPUserCredential(ctx, cred)
}

func (p *PostgresRepository) GetMCPUserCredential(ctx context.Context, serverID, userID string) (*domain.MCPUserCredential, error) {
	if c, err := p.mem.GetMCPUserCredential(ctx, serverID, userID); err == nil && c != nil {
		return c, nil
	}
	const q = `SELECT id, server_id, user_id, org_id, encrypted_token, encrypted_dek, created_at, updated_at FROM mcp_user_credentials WHERE server_id = $1 AND user_id = $2`
	var c domain.MCPUserCredential
	if err := p.pool.QueryRow(ctx, q, serverID, userID).Scan(&c.ID, &c.ServerID, &c.UserID, &c.OrgID, &c.EncryptedToken, &c.EncryptedDEK, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, fmt.Errorf("credential for server %s user %s not found: %w", serverID, userID, err)
	}
	_ = p.mem.SetMCPUserCredential(ctx, &c)
	return &c, nil
}

// -----------------------------------------------------------------------------
// A2A: Agents, Tasks, Events, Publications & Outbox
// -----------------------------------------------------------------------------

func (p *PostgresRepository) CreateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	if agent.ID == "" {
		agent.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_agents (
			id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
			task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
			max_task_iterations, max_task_budget_micros, is_active, is_killed
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	if _, err := p.pool.Exec(ctx, q,
		agent.ID, agent.OrgID, agent.Name, agent.Slug, agent.EndpointURL, agent.AgentCardURL, agent.AgentCardJSON,
		agent.TaskVisibilityMode, agent.AuthType, agent.EncryptedAuthSecret, agent.EncryptedAuthDEK,
		agent.MaxTaskIterations, agent.MaxTaskBudgetMicros, agent.IsActive, agent.IsKilled,
	); err != nil {
		return err
	}
	return p.mem.CreateA2AAgent(ctx, agent)
}

func (p *PostgresRepository) UpdateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	const q = `
		UPDATE a2a_agents SET
			name = $2, slug = $3, endpoint_url = $4, agent_card_url = $5, agent_card_json = $6,
			task_visibility_mode = $7, auth_type = $8, encrypted_auth_secret = $9, encrypted_auth_dek = $10,
			max_task_iterations = $11, max_task_budget_micros = $12, is_active = $13, is_killed = $14,
			updated_at = NOW()
		WHERE id = $1`
	if _, err := p.pool.Exec(ctx, q,
		agent.ID, agent.Name, agent.Slug, agent.EndpointURL, agent.AgentCardURL, agent.AgentCardJSON,
		agent.TaskVisibilityMode, agent.AuthType, agent.EncryptedAuthSecret, agent.EncryptedAuthDEK,
		agent.MaxTaskIterations, agent.MaxTaskBudgetMicros, agent.IsActive, agent.IsKilled,
	); err != nil {
		return err
	}
	if err := p.mem.UpdateA2AAgent(ctx, agent); err != nil {
		_ = p.mem.CreateA2AAgent(ctx, agent)
	}
	return nil
}

func (p *PostgresRepository) GetA2AAgent(ctx context.Context, id string) (*domain.A2AAgent, error) {
	if p.pool == nil {
		return p.mem.GetA2AAgent(ctx, id)
	}
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE id = $1`
	var a domain.A2AAgent
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
		&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
		&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a agent %s not found: %w", id, err)
	}
	_ = p.mem.CreateA2AAgent(ctx, &a)
	return &a, nil
}

func (p *PostgresRepository) GetA2AAgentBySlug(ctx context.Context, orgID, slug string) (*domain.A2AAgent, error) {
	if p.pool == nil {
		return p.mem.GetA2AAgentBySlug(ctx, orgID, slug)
	}
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var a domain.A2AAgent
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(
		&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
		&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
		&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a agent %q not found: %w", slug, err)
	}
	_ = p.mem.CreateA2AAgent(ctx, &a)
	return &a, nil
}

func (p *PostgresRepository) ListA2AAgents(ctx context.Context, orgID string) ([]*domain.A2AAgent, error) {
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE org_id = $1 OR $1 = '' ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListA2AAgents(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.A2AAgent
	for rows.Next() {
		var a domain.A2AAgent
		if err := rows.Scan(
			&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
			&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
			&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
			&a.CreatedAt, &a.UpdatedAt,
		); err == nil {
			out = append(out, &a)
		}
	}
	return out, nil
}

func (p *PostgresRepository) SetA2AAgentKillSwitch(ctx context.Context, id string, killed bool) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_agents SET is_killed = $2, updated_at = NOW() WHERE id = $1`, id, killed)
	_ = p.mem.SetA2AAgentKillSwitch(ctx, id, killed)
	return err
}

func (p *PostgresRepository) CreateA2ATask(ctx context.Context, task *domain.A2ATask) error {
	if task.ID == "" {
		task.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_tasks (
			id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
			state, last_event_seq, input_message_json, output_message_json, total_cost_micros
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	if _, err := p.pool.Exec(ctx, q,
		task.ID, task.AgentID, task.OrgID, task.TeamID, task.VirtualKeyID, task.UserID, task.ClientTaskID,
		task.State, task.LastEventSeq, task.InputMessageJSON, task.OutputMessageJSON, task.TotalCostMicros,
	); err != nil {
		return err
	}
	return p.mem.CreateA2ATask(ctx, task)
}

func (p *PostgresRepository) UpdateA2ATaskState(ctx context.Context, taskID, state string, outputJSON string, costMicros int64) error {
	var completedAt *time.Time
	if state == domain.A2ATaskStateCompleted || state == domain.A2ATaskStateFailed || state == domain.A2ATaskStateCanceled {
		now := time.Now().UTC()
		completedAt = &now
	}
	const q = `
		UPDATE a2a_tasks SET
			state = $2,
			output_message_json = CASE WHEN $3 <> '' THEN $3 ELSE output_message_json END,
			total_cost_micros = total_cost_micros + $4,
			completed_at = COALESCE($5, completed_at),
			updated_at = NOW()
		WHERE id = $1`
	if _, err := p.pool.Exec(ctx, q, taskID, state, outputJSON, costMicros, completedAt); err != nil {
		return err
	}
	_ = p.mem.UpdateA2ATaskState(ctx, taskID, state, outputJSON, costMicros)
	return nil
}

func (p *PostgresRepository) GetA2ATask(ctx context.Context, id string) (*domain.A2ATask, error) {
	if t, err := p.mem.GetA2ATask(ctx, id); err == nil && t != nil {
		return t, nil
	}
	const q = `
		SELECT id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
		       state, last_event_seq, input_message_json, output_message_json, total_cost_micros,
		       created_at, updated_at, completed_at
		FROM a2a_tasks WHERE id = $1`
	var t domain.A2ATask
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&t.ID, &t.AgentID, &t.OrgID, &t.TeamID, &t.VirtualKeyID, &t.UserID, &t.ClientTaskID,
		&t.State, &t.LastEventSeq, &t.InputMessageJSON, &t.OutputMessageJSON, &t.TotalCostMicros,
		&t.CreatedAt, &t.UpdatedAt, &t.CompletedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a task %s not found: %w", id, err)
	}
	_ = p.mem.CreateA2ATask(ctx, &t)
	return &t, nil
}

func (p *PostgresRepository) ListA2ATasks(ctx context.Context, agentID, virtualKeyID string, limit int) ([]*domain.A2ATask, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
		       state, last_event_seq, input_message_json, output_message_json, total_cost_micros,
		       created_at, updated_at, completed_at
		FROM a2a_tasks
		WHERE (agent_id = $1 OR $1 = '') AND (virtual_key_id = $2 OR $2 = '')
		ORDER BY created_at DESC LIMIT $3`
	rows, err := p.pool.Query(ctx, q, agentID, virtualKeyID, limit)
	if err != nil {
		return p.mem.ListA2ATasks(ctx, agentID, virtualKeyID, limit)
	}
	defer rows.Close()

	var out []*domain.A2ATask
	for rows.Next() {
		var t domain.A2ATask
		if err := rows.Scan(
			&t.ID, &t.AgentID, &t.OrgID, &t.TeamID, &t.VirtualKeyID, &t.UserID, &t.ClientTaskID,
			&t.State, &t.LastEventSeq, &t.InputMessageJSON, &t.OutputMessageJSON, &t.TotalCostMicros,
			&t.CreatedAt, &t.UpdatedAt, &t.CompletedAt,
		); err == nil {
			out = append(out, &t)
		}
	}
	return out, nil
}

func (p *PostgresRepository) AppendA2ATaskEvent(ctx context.Context, taskID, eventType, payloadJSON string) (*domain.A2ATaskEvent, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin task event tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Atomic sequence increment with row lock on task:
	var nextSeq int64
	err = tx.QueryRow(ctx, `
		UPDATE a2a_tasks 
		SET last_event_seq = last_event_seq + 1, updated_at = NOW() 
		WHERE id = $1 
		RETURNING last_event_seq
	`, taskID).Scan(&nextSeq)
	if err != nil {
		return nil, fmt.Errorf("increment task event sequence: %w", err)
	}

	eventID := uuid.NewString()
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
		INSERT INTO a2a_task_events (id, task_id, event_seq, event_type, payload_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, eventID, taskID, nextSeq, eventType, payloadJSON, now)
	if err != nil {
		return nil, fmt.Errorf("insert a2a task event: %w", err)
	}

	// Insert into stream publications for background Redis Pub/Sub broadcast
	pubID := uuid.NewString()
	_, err = tx.Exec(ctx, `
		INSERT INTO a2a_stream_publications (id, task_id, event_seq, payload_json, published, created_at)
		VALUES ($1, $2, $3, $4, FALSE, $5)
	`, pubID, taskID, nextSeq, payloadJSON, now)
	if err != nil {
		return nil, fmt.Errorf("insert a2a stream publication: %w", err)
	}

	// Enqueue webhook notification if push config is registered for this task
	var targetURL string
	_ = tx.QueryRow(ctx, `SELECT target_url FROM a2a_push_notification_configs WHERE task_id = $1`, taskID).Scan(&targetURL)
	if targetURL != "" {
		outboxID := uuid.NewString()
		_, _ = tx.Exec(ctx, `
			INSERT INTO a2a_outbox_events (id, task_id, event_type, target_url, payload_json, status, created_at)
			VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		`, outboxID, taskID, eventType, targetURL, payloadJSON, now)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit task event tx: %w", err)
	}

	event := &domain.A2ATaskEvent{
		ID:          eventID,
		TaskID:      taskID,
		EventSeq:    nextSeq,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
		CreatedAt:   now,
	}
	_, _ = p.mem.AppendA2ATaskEvent(ctx, taskID, eventType, payloadJSON)
	return event, nil
}

func (p *PostgresRepository) ListA2ATaskEvents(ctx context.Context, taskID string, afterSeq int64, limit int) ([]*domain.A2ATaskEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	const q = `
		SELECT id, task_id, event_seq, event_type, payload_json, created_at
		FROM a2a_task_events
		WHERE task_id = $1 AND event_seq > $2
		ORDER BY event_seq ASC LIMIT $3`
	rows, err := p.pool.Query(ctx, q, taskID, afterSeq, limit)
	if err != nil {
		return p.mem.ListA2ATaskEvents(ctx, taskID, afterSeq, limit)
	}
	defer rows.Close()

	var out []*domain.A2ATaskEvent
	for rows.Next() {
		var e domain.A2ATaskEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.EventSeq, &e.EventType, &e.PayloadJSON, &e.CreatedAt); err == nil {
			out = append(out, &e)
		}
	}
	return out, nil
}

func (p *PostgresRepository) ClaimPendingA2AStreamPublications(ctx context.Context, batchSize int) ([]*domain.A2AStreamPublication, error) {
	if batchSize <= 0 {
		batchSize = 50
	}
	const q = `
		UPDATE a2a_stream_publications SET
			attempt_count = attempt_count + 1,
			next_attempt_at = NOW() + INTERVAL '5 seconds'
		WHERE id IN (
			SELECT id FROM a2a_stream_publications
			WHERE NOT published AND next_attempt_at <= NOW()
			ORDER BY next_attempt_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, task_id, event_seq, payload_json, published, attempt_count, next_attempt_at, created_at`
	rows, err := p.pool.Query(ctx, q, batchSize)
	if err != nil {
		return p.mem.ClaimPendingA2AStreamPublications(ctx, batchSize)
	}
	defer rows.Close()

	var out []*domain.A2AStreamPublication
	for rows.Next() {
		var pub domain.A2AStreamPublication
		if err := rows.Scan(&pub.ID, &pub.TaskID, &pub.EventSeq, &pub.PayloadJSON, &pub.Published, &pub.AttemptCount, &pub.NextAttemptAt, &pub.CreatedAt); err == nil {
			out = append(out, &pub)
		}
	}
	return out, nil
}

func (p *PostgresRepository) MarkA2AStreamPublicationSuccess(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_stream_publications SET published = TRUE WHERE id = $1`, id)
	_ = p.mem.MarkA2AStreamPublicationSuccess(ctx, id)
	return err
}

func (p *PostgresRepository) CreateA2AOutboxEvent(ctx context.Context, event *domain.A2AOutboxEvent) error {
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_outbox_events (id, task_id, event_type, target_url, payload_json, status)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := p.pool.Exec(ctx, q, event.ID, event.TaskID, event.EventType, event.TargetURL, event.PayloadJSON, event.Status); err != nil {
		return err
	}
	return p.mem.CreateA2AOutboxEvent(ctx, event)
}

func (p *PostgresRepository) ClaimPendingA2AOutboxEvents(ctx context.Context, batchSize int) ([]*domain.A2AOutboxEvent, error) {
	if batchSize <= 0 {
		batchSize = 25
	}
	const q = `
		UPDATE a2a_outbox_events SET
			attempt_count = attempt_count + 1,
			next_attempt_at = NOW() + INTERVAL '10 seconds'
		WHERE id IN (
			SELECT id FROM a2a_outbox_events
			WHERE status = 'pending' AND next_attempt_at <= NOW()
			ORDER BY next_attempt_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, task_id, event_type, target_url, payload_json, status, attempt_count, next_attempt_at, created_at`
	rows, err := p.pool.Query(ctx, q, batchSize)
	if err != nil {
		return p.mem.ClaimPendingA2AOutboxEvents(ctx, batchSize)
	}
	defer rows.Close()

	var out []*domain.A2AOutboxEvent
	for rows.Next() {
		var o domain.A2AOutboxEvent
		if err := rows.Scan(&o.ID, &o.TaskID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.NextAttemptAt, &o.CreatedAt); err == nil {
			out = append(out, &o)
		}
	}
	return out, nil
}

func (p *PostgresRepository) UpdateA2AOutboxEventStatus(ctx context.Context, id, status string) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_outbox_events SET status = $2 WHERE id = $1`, id, status)
	_ = p.mem.UpdateA2AOutboxEventStatus(ctx, id, status)
	return err
}

func (p *PostgresRepository) GetA2AOutboxEvent(ctx context.Context, id string) (*domain.A2AOutboxEvent, error) {
	if ev, err := p.mem.GetA2AOutboxEvent(ctx, id); err == nil && ev != nil {
		return ev, nil
	}
	const q = `SELECT id, task_id, event_type, target_url, payload_json, status, attempt_count, next_attempt_at, created_at FROM a2a_outbox_events WHERE id = $1`
	var o domain.A2AOutboxEvent
	if err := p.pool.QueryRow(ctx, q, id).Scan(&o.ID, &o.TaskID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.NextAttemptAt, &o.CreatedAt); err != nil {
		return nil, fmt.Errorf("outbox event %s not found: %w", id, err)
	}
	return &o, nil
}

func (p *PostgresRepository) SetA2APushNotificationConfig(ctx context.Context, cfg *domain.A2APushNotificationConfig) error {
	if cfg.ID == "" {
		cfg.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_push_notification_configs (id, task_id, target_url, auth_token)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (task_id) DO UPDATE SET
			target_url = EXCLUDED.target_url,
			auth_token = EXCLUDED.auth_token`
	if _, err := p.pool.Exec(ctx, q, cfg.ID, cfg.TaskID, cfg.TargetURL, cfg.AuthToken); err != nil {
		return err
	}
	return p.mem.SetA2APushNotificationConfig(ctx, cfg)
}

func (p *PostgresRepository) GetA2APushNotificationConfig(ctx context.Context, taskID string) (*domain.A2APushNotificationConfig, error) {
	if c, err := p.mem.GetA2APushNotificationConfig(ctx, taskID); err == nil && c != nil {
		return c, nil
	}
	const q = `SELECT id, task_id, target_url, auth_token, created_at FROM a2a_push_notification_configs WHERE task_id = $1`
	var cfg domain.A2APushNotificationConfig
	if err := p.pool.QueryRow(ctx, q, taskID).Scan(&cfg.ID, &cfg.TaskID, &cfg.TargetURL, &cfg.AuthToken, &cfg.CreatedAt); err != nil {
		return nil, fmt.Errorf("push notification config for task %s not found: %w", taskID, err)
	}
	_ = p.mem.SetA2APushNotificationConfig(ctx, &cfg)
	return &cfg, nil
}

// Files Management

func (p *PostgresRepository) CreateFile(ctx context.Context, file *domain.CanonicalFile) error {
	if file.ID == "" {
		file.ID = uuid.NewString()
	}
	if file.CreatedAt.IsZero() {
		file.CreatedAt = time.Now().UTC()
	}
	const q = `
		INSERT INTO files (id, org_id, team_id, user_id, bytes, created_at, filename, purpose, status, content_sha256, storage_path, upstream_provider, upstream_id, expires_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err := p.pool.Exec(ctx, q, file.ID, file.OrgID, file.TeamID, file.UserID, file.Bytes, file.CreatedAt, file.Filename, file.Purpose, file.Status, file.ContentSHA256, file.StoragePath, file.UpstreamProvider, file.UpstreamID, file.ExpiresAt)
	if err != nil {
		return err
	}
	return p.mem.CreateFile(ctx, file)
}

func (p *PostgresRepository) GetFile(ctx context.Context, orgID, fileID string) (*domain.CanonicalFile, error) {
	if f, err := p.mem.GetFile(ctx, orgID, fileID); err == nil && f != nil {
		return f, nil
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), COALESCE(user_id::text, ''), bytes, created_at, filename, purpose, status, content_sha256, storage_path, COALESCE(upstream_provider, ''), COALESCE(upstream_id, ''), expires_at
		FROM files WHERE id = $1 AND ($2 = '' OR org_id = $2)`
	var f domain.CanonicalFile
	if err := p.pool.QueryRow(ctx, q, fileID, orgID).Scan(
		&f.ID, &f.OrgID, &f.TeamID, &f.UserID, &f.Bytes, &f.CreatedAt, &f.Filename, &f.Purpose, &f.Status, &f.ContentSHA256, &f.StoragePath, &f.UpstreamProvider, &f.UpstreamID, &f.ExpiresAt,
	); err != nil {
		return nil, fmt.Errorf("file %s not found: %w", fileID, err)
	}
	_ = p.mem.CreateFile(ctx, &f)
	return &f, nil
}

func (p *PostgresRepository) ListFiles(ctx context.Context, orgID string, purpose string) ([]*domain.CanonicalFile, error) {
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), COALESCE(user_id::text, ''), bytes, created_at, filename, purpose, status, content_sha256, storage_path, COALESCE(upstream_provider, ''), COALESCE(upstream_id, ''), expires_at
		FROM files WHERE ($1 = '' OR org_id = $1) AND ($2 = '' OR purpose = $2)
		ORDER BY created_at DESC`
	rows, err := p.pool.Query(ctx, q, orgID, purpose)
	if err != nil {
		return p.mem.ListFiles(ctx, orgID, purpose)
	}
	defer rows.Close()
	var out []*domain.CanonicalFile
	for rows.Next() {
		var f domain.CanonicalFile
		if err := rows.Scan(
			&f.ID, &f.OrgID, &f.TeamID, &f.UserID, &f.Bytes, &f.CreatedAt, &f.Filename, &f.Purpose, &f.Status, &f.ContentSHA256, &f.StoragePath, &f.UpstreamProvider, &f.UpstreamID, &f.ExpiresAt,
		); err == nil {
			out = append(out, &f)
			_ = p.mem.CreateFile(ctx, &f)
		}
	}
	return out, nil
}

func (p *PostgresRepository) DeleteFile(ctx context.Context, orgID, fileID string) error {
	const q = `DELETE FROM files WHERE id = $1 AND ($2 = '' OR org_id = $2)`
	if _, err := p.pool.Exec(ctx, q, fileID, orgID); err != nil {
		return err
	}
	_ = p.mem.DeleteFile(ctx, orgID, fileID)
	return nil
}

// Batches Management

func (p *PostgresRepository) CreateBatch(ctx context.Context, batch *domain.CanonicalBatch) error {
	if batch.ID == "" {
		batch.ID = uuid.NewString()
	}
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = time.Now().UTC()
	}
	metaJSON, _ := json.Marshal(batch.Metadata)
	countsJSON, _ := json.Marshal(batch.RequestCounts)
	const q = `
		INSERT INTO batches (id, org_id, team_id, input_file_id, output_file_id, error_file_id, endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, estimated_tokens, reserved_cost_micros, upstream_provider, upstream_id)
		VALUES ($1, $2, NULLIF($3, '')::uuid, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`
	_, err := p.pool.Exec(ctx, q, batch.ID, batch.OrgID, batch.TeamID, batch.InputFileID, batch.OutputFileID, batch.ErrorFileID, batch.Endpoint, batch.Status, batch.CompletionWindow, batch.CreatedAt, batch.CompletedAt, metaJSON, countsJSON, batch.EstimatedTokens, batch.ReservedCostMicros, batch.UpstreamProvider, batch.UpstreamID)
	if err != nil {
		return err
	}
	return p.mem.CreateBatch(ctx, batch)
}

func (p *PostgresRepository) GetBatch(ctx context.Context, orgID, batchID string) (*domain.CanonicalBatch, error) {
	if b, err := p.mem.GetBatch(ctx, orgID, batchID); err == nil && b != nil {
		return b, nil
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), input_file_id, COALESCE(output_file_id, ''), COALESCE(error_file_id, ''), endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, estimated_tokens, reserved_cost_micros, COALESCE(upstream_provider, ''), COALESCE(upstream_id, '')
		FROM batches WHERE id = $1 AND ($2 = '' OR org_id = $2::uuid)`
	var b domain.CanonicalBatch
	var metaJSON, countsJSON []byte
	if err := p.pool.QueryRow(ctx, q, batchID, orgID).Scan(
		&b.ID, &b.OrgID, &b.TeamID, &b.InputFileID, &b.OutputFileID, &b.ErrorFileID, &b.Endpoint, &b.Status, &b.CompletionWindow, &b.CreatedAt, &b.CompletedAt, &metaJSON, &countsJSON, &b.EstimatedTokens, &b.ReservedCostMicros, &b.UpstreamProvider, &b.UpstreamID,
	); err != nil {
		return nil, fmt.Errorf("batch %s not found: %w", batchID, err)
	}
	_ = json.Unmarshal(metaJSON, &b.Metadata)
	_ = json.Unmarshal(countsJSON, &b.RequestCounts)
	_ = p.mem.CreateBatch(ctx, &b)
	return &b, nil
}

func (p *PostgresRepository) ListBatches(ctx context.Context, orgID string, limit int) ([]*domain.CanonicalBatch, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), input_file_id, COALESCE(output_file_id, ''), COALESCE(error_file_id, ''), endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, estimated_tokens, reserved_cost_micros, COALESCE(upstream_provider, ''), COALESCE(upstream_id, '')
		FROM batches WHERE ($1 = '' OR org_id = $1::uuid)
		ORDER BY created_at DESC LIMIT $2`
	rows, err := p.pool.Query(ctx, q, orgID, limit)
	if err != nil {
		return p.mem.ListBatches(ctx, orgID, limit)
	}
	defer rows.Close()
	var out []*domain.CanonicalBatch
	for rows.Next() {
		var b domain.CanonicalBatch
		var metaJSON, countsJSON []byte
		if err := rows.Scan(
			&b.ID, &b.OrgID, &b.TeamID, &b.InputFileID, &b.OutputFileID, &b.ErrorFileID, &b.Endpoint, &b.Status, &b.CompletionWindow, &b.CreatedAt, &b.CompletedAt, &metaJSON, &countsJSON, &b.EstimatedTokens, &b.ReservedCostMicros, &b.UpstreamProvider, &b.UpstreamID,
		); err == nil {
			_ = json.Unmarshal(metaJSON, &b.Metadata)
			_ = json.Unmarshal(countsJSON, &b.RequestCounts)
			out = append(out, &b)
			_ = p.mem.CreateBatch(ctx, &b)
		}
	}
	return out, nil
}

func (p *PostgresRepository) UpdateBatchStatus(ctx context.Context, batchID string, status string, outputFileID string, counts domain.BatchCounts, completedAt *time.Time) error {
	countsJSON, _ := json.Marshal(counts)
	const q = `UPDATE batches SET status = $1, output_file_id = COALESCE(NULLIF($2, ''), output_file_id), request_counts = $3, completed_at = $4 WHERE id = $5`
	if _, err := p.pool.Exec(ctx, q, status, outputFileID, countsJSON, completedAt, batchID); err != nil {
		return err
	}
	_ = p.mem.UpdateBatchStatus(ctx, batchID, status, outputFileID, counts, completedAt)
	return nil
}
