package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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
	if p.pool == nil {
		return p.mem.GetMCPToolsetBySlug(ctx, orgID, slug)
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
	if p.pool == nil {
		return p.mem.GetMCPUserCredential(ctx, serverID, userID)
	}
	const q = `SELECT id, server_id, user_id, org_id, encrypted_token, encrypted_dek, created_at, updated_at FROM mcp_user_credentials WHERE server_id = $1 AND user_id = $2`
	var c domain.MCPUserCredential
	if err := p.pool.QueryRow(ctx, q, serverID, userID).Scan(&c.ID, &c.ServerID, &c.UserID, &c.OrgID, &c.EncryptedToken, &c.EncryptedDEK, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, fmt.Errorf("credential for server %s user %s not found: %w", serverID, userID, err)
	}
	_ = p.mem.SetMCPUserCredential(ctx, &c)
	return &c, nil
}

// GetMCPRuntimeSettings returns the active gateway-wide MCP protocol specification settings.
func (p *PostgresRepository) GetMCPRuntimeSettings(ctx context.Context) (*domain.MCPRuntimeSettings, error) {
	if p.pool == nil {
		return p.mem.GetMCPRuntimeSettings(ctx)
	}
	const q = `
		SELECT active_protocol_version, strict_schema_validation, updated_by, updated_at
		FROM mcp_runtime_settings
		WHERE id = 'default'`
	var s domain.MCPRuntimeSettings
	if err := p.pool.QueryRow(ctx, q).Scan(
		&s.ActiveProtocolVersion,
		&s.StrictSchemaValidation,
		&s.UpdatedBy,
		&s.UpdatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return p.mem.GetMCPRuntimeSettings(ctx)
		}
		return nil, fmt.Errorf("get mcp runtime settings: %w", err)
	}
	_ = p.mem.UpdateMCPRuntimeSettings(ctx, &s)
	return &s, nil
}

// UpdateMCPRuntimeSettings persists the active gateway-wide MCP protocol specification settings.
func (p *PostgresRepository) UpdateMCPRuntimeSettings(ctx context.Context, settings *domain.MCPRuntimeSettings) error {
	if settings == nil {
		return fmt.Errorf("mcp runtime settings cannot be nil")
	}
	if p.pool == nil {
		return p.mem.UpdateMCPRuntimeSettings(ctx, settings)
	}
	const q = `
		INSERT INTO mcp_runtime_settings (id, active_protocol_version, strict_schema_validation, updated_by, updated_at)
		VALUES ('default', $1, $2, $3, NOW())
		ON CONFLICT (id) DO UPDATE SET
			active_protocol_version = EXCLUDED.active_protocol_version,
			strict_schema_validation = EXCLUDED.strict_schema_validation,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
		RETURNING updated_at`
	if err := p.pool.QueryRow(
		ctx,
		q,
		settings.ActiveProtocolVersion,
		settings.StrictSchemaValidation,
		settings.UpdatedBy,
	).Scan(&settings.UpdatedAt); err != nil {
		return fmt.Errorf("update mcp runtime settings: %w", err)
	}
	return p.mem.UpdateMCPRuntimeSettings(ctx, settings)
}

// -----------------------------------------------------------------------------
// A2A: Agents, Tasks, Events, Publications & Outbox
// -----------------------------------------------------------------------------

const a2aAgentSelectCols = `id, org_id, name, slug, endpoint_url,
	COALESCE(agent_card_url, ''), COALESCE(agent_card_json, ''), COALESCE(extended_agent_card_json, ''),
	is_public_card, COALESCE(NULLIF(protocol_binding, ''), 'HTTP+JSON'),
	COALESCE(NULLIF(task_visibility_mode, ''), 'key_strict'),
	COALESCE(NULLIF(auth_type, ''), 'none'), COALESCE(NULLIF(auth_header_name, ''), 'Authorization'),
	COALESCE(encrypted_auth_secret, ''), COALESCE(encrypted_auth_dek, ''),
	max_task_iterations, max_task_budget_micros, is_active, is_killed, created_at, updated_at`

func scanA2AAgent(row pgx.Row) (*domain.A2AAgent, error) {
	var a domain.A2AAgent
	err := row.Scan(
		&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL,
		&a.AgentCardURL, &a.AgentCardJSON, &a.ExtendedAgentCardJSON,
		&a.IsPublicCard, &a.ProtocolBinding, &a.TaskVisibilityMode,
		&a.AuthType, &a.AuthHeaderName, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
		&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

const a2aTaskSelectCols = `id, agent_id, org_id, COALESCE(team_id, ''), virtual_key_id, COALESCE(user_id, ''),
	COALESCE(client_task_id, ''), COALESCE(context_id, ''), state, last_event_seq,
	COALESCE(input_message_json, ''), COALESCE(output_message_json, ''),
	COALESCE(status_message_json, ''), status_timestamp,
	COALESCE(history_json, ''), COALESCE(artifacts_json, ''), COALESCE(metadata_json, ''),
	total_cost_micros, created_at, updated_at, completed_at`

func scanA2ATask(row pgx.Row) (*domain.A2ATask, error) {
	var t domain.A2ATask
	err := row.Scan(
		&t.ID, &t.AgentID, &t.OrgID, &t.TeamID, &t.VirtualKeyID, &t.UserID,
		&t.ClientTaskID, &t.ContextID, &t.State, &t.LastEventSeq,
		&t.InputMessageJSON, &t.OutputMessageJSON,
		&t.StatusMessageJSON, &t.StatusTimestamp,
		&t.HistoryJSON, &t.ArtifactsJSON, &t.MetadataJSON,
		&t.TotalCostMicros, &t.CreatedAt, &t.UpdatedAt, &t.CompletedAt,
	)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

const a2aPushConfigSelectCols = `id, task_id, COALESCE(tenant, ''), target_url, COALESCE(token, ''),
	COALESCE(auth_token, ''), COALESCE(encrypted_auth_scheme, ''),
	COALESCE(encrypted_auth_creds, ''), COALESCE(encrypted_auth_dek, ''),
	created_at, updated_at`

func scanA2APushConfig(row pgx.Row) (*domain.A2APushNotificationConfig, error) {
	var cfg domain.A2APushNotificationConfig
	err := row.Scan(
		&cfg.ID, &cfg.TaskID, &cfg.Tenant, &cfg.TargetURL, &cfg.Token,
		&cfg.AuthToken, &cfg.AuthScheme, &cfg.EncryptedAuthCreds, &cfg.EncryptedAuthDEK,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (p *PostgresRepository) CreateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
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
	if p.pool == nil {
		return p.mem.CreateA2AAgent(ctx, agent)
	}
	const q = `
		INSERT INTO a2a_agents (
			id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
			extended_agent_card_json, is_public_card, protocol_binding,
			task_visibility_mode, auth_type, auth_header_name, encrypted_auth_secret, encrypted_auth_dek,
			max_task_iterations, max_task_budget_micros, is_active, is_killed
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`
	if _, err := p.pool.Exec(ctx, q,
		agent.ID, agent.OrgID, agent.Name, agent.Slug, agent.EndpointURL, agent.AgentCardURL, agent.AgentCardJSON,
		agent.ExtendedAgentCardJSON, agent.IsPublicCard, agent.ProtocolBinding,
		agent.TaskVisibilityMode, agent.AuthType, agent.AuthHeaderName, agent.EncryptedAuthSecret, agent.EncryptedAuthDEK,
		agent.MaxTaskIterations, agent.MaxTaskBudgetMicros, agent.IsActive, agent.IsKilled,
	); err != nil {
		return err
	}
	_ = p.mem.CreateA2AAgent(ctx, agent)
	return nil
}

func (p *PostgresRepository) UpdateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	if p.pool == nil {
		return p.mem.UpdateA2AAgent(ctx, agent)
	}
	const q = `
		UPDATE a2a_agents SET
			name = $2, slug = $3, endpoint_url = $4, agent_card_url = $5, agent_card_json = $6,
			extended_agent_card_json = $7, is_public_card = $8, protocol_binding = $9,
			task_visibility_mode = $10, auth_type = $11, auth_header_name = $12,
			encrypted_auth_secret = $13, encrypted_auth_dek = $14,
			max_task_iterations = $15, max_task_budget_micros = $16, is_active = $17, is_killed = $18,
			updated_at = NOW()
		WHERE id = $1`
	if _, err := p.pool.Exec(ctx, q,
		agent.ID, agent.Name, agent.Slug, agent.EndpointURL, agent.AgentCardURL, agent.AgentCardJSON,
		agent.ExtendedAgentCardJSON, agent.IsPublicCard, agent.ProtocolBinding,
		agent.TaskVisibilityMode, agent.AuthType, agent.AuthHeaderName,
		agent.EncryptedAuthSecret, agent.EncryptedAuthDEK,
		agent.MaxTaskIterations, agent.MaxTaskBudgetMicros, agent.IsActive, agent.IsKilled,
	); err != nil {
		return err
	}
	if err := p.mem.UpdateA2AAgent(ctx, agent); err != nil {
		_ = p.mem.CreateA2AAgent(ctx, agent)
	}
	return nil
}

func (p *PostgresRepository) DeleteA2AAgent(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteA2AAgent(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM a2a_agents WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("a2a agent %s not found", id)
	}
	_ = p.mem.DeleteA2AAgent(ctx, id)
	return nil
}

func (p *PostgresRepository) GetA2AAgent(ctx context.Context, id string) (*domain.A2AAgent, error) {
	if p.pool == nil {
		return p.mem.GetA2AAgent(ctx, id)
	}
	const q = `SELECT ` + a2aAgentSelectCols + ` FROM a2a_agents WHERE id = $1`
	a, err := scanA2AAgent(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("a2a agent %s not found: %w", id, err)
	}
	return a, nil
}

func (p *PostgresRepository) GetA2AAgentBySlug(ctx context.Context, orgID, slug string) (*domain.A2AAgent, error) {
	if p.pool == nil {
		return p.mem.GetA2AAgentBySlug(ctx, orgID, slug)
	}
	const q = `SELECT ` + a2aAgentSelectCols + ` FROM a2a_agents WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	a, err := scanA2AAgent(p.pool.QueryRow(ctx, q, orgID, slug))
	if err != nil {
		return nil, fmt.Errorf("a2a agent %q not found: %w", slug, err)
	}
	return a, nil
}

func (p *PostgresRepository) ListA2AAgents(ctx context.Context, orgID string) ([]*domain.A2AAgent, error) {
	if p.pool == nil {
		return p.mem.ListA2AAgents(ctx, orgID)
	}
	const q = `SELECT ` + a2aAgentSelectCols + ` FROM a2a_agents WHERE org_id = $1 OR $1 = '' ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.A2AAgent, 0)
	for rows.Next() {
		a, scanErr := scanA2AAgent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) SetA2AAgentKillSwitch(ctx context.Context, id string, killed bool) error {
	if p.pool == nil {
		return p.mem.SetA2AAgentKillSwitch(ctx, id, killed)
	}
	_, err := p.pool.Exec(ctx, `UPDATE a2a_agents SET is_killed = $2, updated_at = NOW() WHERE id = $1`, id, killed)
	_ = p.mem.SetA2AAgentKillSwitch(ctx, id, killed)
	return err
}

func (p *PostgresRepository) CreateA2ATask(ctx context.Context, task *domain.A2ATask) error {
	if task.ID == "" {
		task.ID = uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.CreateA2ATask(ctx, task)
	}
	const q = `
		INSERT INTO a2a_tasks (
			id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id, context_id,
			state, last_event_seq, input_message_json, output_message_json,
			status_message_json, status_timestamp, history_json, artifacts_json, metadata_json,
			total_cost_micros
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	if _, err := p.pool.Exec(ctx, q,
		task.ID, task.AgentID, task.OrgID, task.TeamID, task.VirtualKeyID, task.UserID, task.ClientTaskID, task.ContextID,
		task.State, task.LastEventSeq, task.InputMessageJSON, task.OutputMessageJSON,
		task.StatusMessageJSON, task.StatusTimestamp, task.HistoryJSON, task.ArtifactsJSON, task.MetadataJSON,
		task.TotalCostMicros,
	); err != nil {
		return err
	}
	_ = p.mem.CreateA2ATask(ctx, task)
	return nil
}

func (p *PostgresRepository) UpdateA2ATask(ctx context.Context, task *domain.A2ATask, costDeltaMicros int64) error {
	if task == nil || task.ID == "" {
		return fmt.Errorf("a2a task is required")
	}
	if p.pool == nil {
		return p.mem.UpdateA2ATask(ctx, task, costDeltaMicros)
	}
	var completedAt *time.Time
	if task.CompletedAt != nil {
		ct := *task.CompletedAt
		completedAt = &ct
	} else if isTerminalA2ADomainState(task.State) {
		now := time.Now().UTC()
		completedAt = &now
	}
	const q = `
		UPDATE a2a_tasks SET
			state = COALESCE(NULLIF($2, ''), state),
			context_id = COALESCE(NULLIF($3, ''), context_id),
			client_task_id = COALESCE(NULLIF($4, ''), client_task_id),
			output_message_json = CASE WHEN $5 <> '' THEN $5 ELSE output_message_json END,
			status_message_json = CASE WHEN $6 <> '' THEN $6 ELSE status_message_json END,
			status_timestamp = COALESCE($7, status_timestamp),
			history_json = CASE WHEN $8 <> '' THEN $8 ELSE history_json END,
			artifacts_json = CASE WHEN $9 <> '' THEN $9 ELSE artifacts_json END,
			metadata_json = CASE WHEN $10 <> '' THEN $10 ELSE metadata_json END,
			total_cost_micros = total_cost_micros + $11,
			completed_at = COALESCE($12, completed_at),
			updated_at = NOW()
		WHERE id = $1
		RETURNING total_cost_micros, updated_at, completed_at`
	if err := p.pool.QueryRow(ctx, q,
		task.ID, task.State, task.ContextID, task.ClientTaskID,
		task.OutputMessageJSON, task.StatusMessageJSON, task.StatusTimestamp,
		task.HistoryJSON, task.ArtifactsJSON, task.MetadataJSON,
		max(costDeltaMicros, int64(0)), completedAt,
	).Scan(&task.TotalCostMicros, &task.UpdatedAt, &task.CompletedAt); err != nil {
		return err
	}
	_ = p.mem.UpdateA2ATask(ctx, task, costDeltaMicros)
	return nil
}

func (p *PostgresRepository) GetA2ATask(ctx context.Context, id string) (*domain.A2ATask, error) {
	if p.pool == nil {
		return p.mem.GetA2ATask(ctx, id)
	}
	const q = `SELECT ` + a2aTaskSelectCols + ` FROM a2a_tasks WHERE id = $1`
	t, err := scanA2ATask(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("a2a task %s not found: %w", id, err)
	}
	return t, nil
}

func (p *PostgresRepository) ListA2ATasks(ctx context.Context, filter domain.A2ATaskListFilter) ([]*domain.A2ATask, int, error) {
	if p.pool == nil {
		return p.mem.ListA2ATasks(ctx, filter)
	}
	var conds []string
	var args []any
	addArg := func(clause string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(clause, len(args)))
	}
	if filter.AgentID != "" {
		addArg("agent_id = $%d", filter.AgentID)
	}
	if filter.OrgID != "" {
		addArg("org_id = $%d", filter.OrgID)
	}
	if filter.VirtualKeyID != "" {
		addArg("virtual_key_id = $%d", filter.VirtualKeyID)
	}
	if filter.ContextID != "" {
		addArg("context_id = $%d", filter.ContextID)
	}
	if filter.State != "" {
		addArg("state = $%d", filter.State)
	}
	if filter.UpdatedAfter != nil {
		addArg("updated_at > $%d", *filter.UpdatedAfter)
	}

	whereSQL := ""
	if len(conds) > 0 {
		whereSQL = "WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	countQ := `SELECT COUNT(*) FROM a2a_tasks ` + whereSQL
	if err := p.pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := max(filter.Offset, 0)
	args = append(args, limit, offset)
	dataQ := `SELECT ` + a2aTaskSelectCols + ` FROM a2a_tasks ` + whereSQL +
		` ORDER BY updated_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args)-1) +
		` OFFSET $` + strconv.Itoa(len(args))

	rows, err := p.pool.Query(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*domain.A2ATask, 0)
	for rows.Next() {
		t, scanErr := scanA2ATask(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (p *PostgresRepository) AppendA2ATaskEvent(ctx context.Context, taskID, eventType, payloadJSON string) (*domain.A2ATaskEvent, error) {
	if p.pool == nil {
		return p.mem.AppendA2ATaskEvent(ctx, taskID, eventType, payloadJSON)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin task event tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var nextSeq int64
	var taskState string
	err = tx.QueryRow(ctx, `
		UPDATE a2a_tasks
		SET last_event_seq = last_event_seq + 1, updated_at = NOW()
		WHERE id = $1
		RETURNING last_event_seq, state
	`, taskID).Scan(&nextSeq, &taskState)
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

	envelopeJSON := buildA2AStreamEnvelope(nextSeq, eventType, taskState, payloadJSON)
	pubID := uuid.NewString()
	_, err = tx.Exec(ctx, `
		INSERT INTO a2a_stream_publications (id, task_id, event_seq, payload_json, published, created_at)
		VALUES ($1, $2, $3, $4, FALSE, $5)
	`, pubID, taskID, nextSeq, envelopeJSON, now)
	if err != nil {
		return nil, fmt.Errorf("insert a2a stream publication: %w", err)
	}

	// Enqueue one outbox event per registered push notification config for this task
	cfgRows, err := tx.Query(ctx, `SELECT id, target_url FROM a2a_push_notification_configs WHERE task_id = $1`, taskID)
	if err != nil {
		return nil, fmt.Errorf("query a2a push configs: %w", err)
	}
	type pushTarget struct {
		id  string
		url string
	}
	var targets []pushTarget
	for cfgRows.Next() {
		var pt pushTarget
		if sErr := cfgRows.Scan(&pt.id, &pt.url); sErr == nil && pt.url != "" {
			targets = append(targets, pt)
		}
	}
	cfgRows.Close()

	for _, pt := range targets {
		outboxID := uuid.NewString()
		if _, err := tx.Exec(ctx, `
			INSERT INTO a2a_outbox_events (id, task_id, push_config_id, event_type, target_url, payload_json, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $7)
		`, outboxID, taskID, pt.id, eventType, pt.url, payloadJSON, now); err != nil {
			return nil, fmt.Errorf("insert a2a outbox event: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit task event tx: %w", err)
	}

	return &domain.A2ATaskEvent{
		ID:          eventID,
		TaskID:      taskID,
		EventSeq:    nextSeq,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
		CreatedAt:   now,
	}, nil
}

func (p *PostgresRepository) ListA2ATaskEvents(ctx context.Context, taskID string, afterSeq int64, limit int) ([]*domain.A2ATaskEvent, error) {
	if p.pool == nil {
		return p.mem.ListA2ATaskEvents(ctx, taskID, afterSeq, limit)
	}
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
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.A2ATaskEvent, 0)
	for rows.Next() {
		var e domain.A2ATaskEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.EventSeq, &e.EventType, &e.PayloadJSON, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) ClaimPendingA2AStreamPublications(ctx context.Context, batchSize int) ([]*domain.A2AStreamPublication, error) {
	if p.pool == nil {
		return p.mem.ClaimPendingA2AStreamPublications(ctx, batchSize)
	}
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
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.A2AStreamPublication, 0)
	for rows.Next() {
		var pub domain.A2AStreamPublication
		if err := rows.Scan(&pub.ID, &pub.TaskID, &pub.EventSeq, &pub.PayloadJSON, &pub.Published, &pub.AttemptCount, &pub.NextAttemptAt, &pub.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &pub)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) MarkA2AStreamPublicationSuccess(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.MarkA2AStreamPublicationSuccess(ctx, id)
	}
	_, err := p.pool.Exec(ctx, `UPDATE a2a_stream_publications SET published = TRUE WHERE id = $1`, id)
	_ = p.mem.MarkA2AStreamPublicationSuccess(ctx, id)
	return err
}

func (p *PostgresRepository) CreateA2AOutboxEvent(ctx context.Context, event *domain.A2AOutboxEvent) error {
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.CreateA2AOutboxEvent(ctx, event)
	}
	const q = `
		INSERT INTO a2a_outbox_events (id, task_id, push_config_id, event_type, target_url, payload_json, status, last_error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := p.pool.Exec(ctx, q, event.ID, event.TaskID, event.PushConfigID, event.EventType, event.TargetURL, event.PayloadJSON, event.Status, event.LastError); err != nil {
		return err
	}
	_ = p.mem.CreateA2AOutboxEvent(ctx, event)
	return nil
}

func (p *PostgresRepository) ClaimPendingA2AOutboxEvents(ctx context.Context, batchSize int) ([]*domain.A2AOutboxEvent, error) {
	if p.pool == nil {
		return p.mem.ClaimPendingA2AOutboxEvents(ctx, batchSize)
	}
	if batchSize <= 0 {
		batchSize = 25
	}
	const q = `
		UPDATE a2a_outbox_events SET
			attempt_count = attempt_count + 1,
			next_attempt_at = NOW() + INTERVAL '10 seconds',
			updated_at = NOW()
		WHERE id IN (
			SELECT id FROM a2a_outbox_events
			WHERE status = 'pending' AND next_attempt_at <= NOW()
			ORDER BY next_attempt_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, task_id, COALESCE(push_config_id, ''), event_type, target_url, payload_json, status, attempt_count, COALESCE(last_error, ''), next_attempt_at, created_at, updated_at`
	rows, err := p.pool.Query(ctx, q, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.A2AOutboxEvent, 0)
	for rows.Next() {
		var o domain.A2AOutboxEvent
		if err := rows.Scan(&o.ID, &o.TaskID, &o.PushConfigID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.LastError, &o.NextAttemptAt, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) UpdateA2AOutboxEvent(ctx context.Context, ev *domain.A2AOutboxEvent) error {
	if ev == nil || ev.ID == "" {
		return fmt.Errorf("outbox event is required")
	}
	if p.pool == nil {
		return p.mem.UpdateA2AOutboxEvent(ctx, ev)
	}
	const q = `
		UPDATE a2a_outbox_events SET
			status = $2,
			attempt_count = $3,
			next_attempt_at = $4,
			last_error = $5,
			updated_at = NOW()
		WHERE id = $1`
	if _, err := p.pool.Exec(ctx, q, ev.ID, ev.Status, ev.AttemptCount, ev.NextAttemptAt, ev.LastError); err != nil {
		return err
	}
	_ = p.mem.UpdateA2AOutboxEvent(ctx, ev)
	return nil
}

func (p *PostgresRepository) UpdateA2AOutboxEventStatus(ctx context.Context, id, status string) error {
	if p.pool == nil {
		return p.mem.UpdateA2AOutboxEventStatus(ctx, id, status)
	}
	_, err := p.pool.Exec(ctx, `UPDATE a2a_outbox_events SET status = $2, updated_at = NOW() WHERE id = $1`, id, status)
	_ = p.mem.UpdateA2AOutboxEventStatus(ctx, id, status)
	return err
}

func (p *PostgresRepository) GetA2AOutboxEvent(ctx context.Context, id string) (*domain.A2AOutboxEvent, error) {
	if p.pool == nil {
		return p.mem.GetA2AOutboxEvent(ctx, id)
	}
	const q = `
		SELECT id, task_id, COALESCE(push_config_id, ''), event_type, target_url, payload_json, status, attempt_count, COALESCE(last_error, ''), next_attempt_at, created_at, updated_at
		FROM a2a_outbox_events WHERE id = $1`
	var o domain.A2AOutboxEvent
	if err := p.pool.QueryRow(ctx, q, id).Scan(&o.ID, &o.TaskID, &o.PushConfigID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.LastError, &o.NextAttemptAt, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, fmt.Errorf("outbox event %s not found: %w", id, err)
	}
	return &o, nil
}

func (p *PostgresRepository) ListA2AOutboxEvents(ctx context.Context, orgID, status string, limit int) ([]*domain.A2AOutboxEvent, error) {
	if p.pool == nil {
		return p.mem.ListA2AOutboxEvents(ctx, orgID, status, limit)
	}
	if limit <= 0 {
		limit = 100
	}
	const q = `
		SELECT o.id, o.task_id, COALESCE(o.push_config_id, ''), o.event_type, o.target_url, o.payload_json,
		       o.status, o.attempt_count, COALESCE(o.last_error, ''), o.next_attempt_at, o.created_at, o.updated_at
		FROM a2a_outbox_events o
		JOIN a2a_tasks t ON t.id = o.task_id
		WHERE ($1 = '' OR t.org_id = $1)
		  AND ($2 = '' OR o.status = $2)
		ORDER BY o.created_at DESC
		LIMIT $3`
	rows, err := p.pool.Query(ctx, q, orgID, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.A2AOutboxEvent, 0)
	for rows.Next() {
		var o domain.A2AOutboxEvent
		if err := rows.Scan(&o.ID, &o.TaskID, &o.PushConfigID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.LastError, &o.NextAttemptAt, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) ReplayA2AOutboxEvent(ctx context.Context, id string) (*domain.A2AOutboxEvent, error) {
	if p.pool == nil {
		return p.mem.ReplayA2AOutboxEvent(ctx, id)
	}
	const q = `
		UPDATE a2a_outbox_events SET
			status = 'pending',
			attempt_count = 0,
			last_error = '',
			next_attempt_at = NOW(),
			updated_at = NOW()
		WHERE id = $1
		RETURNING id, task_id, COALESCE(push_config_id, ''), event_type, target_url, payload_json, status, attempt_count, COALESCE(last_error, ''), next_attempt_at, created_at, updated_at`
	var o domain.A2AOutboxEvent
	if err := p.pool.QueryRow(ctx, q, id).Scan(&o.ID, &o.TaskID, &o.PushConfigID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.LastError, &o.NextAttemptAt, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, fmt.Errorf("outbox event %s not found: %w", id, err)
	}
	_, _ = p.mem.ReplayA2AOutboxEvent(ctx, id)
	return &o, nil
}

func (p *PostgresRepository) SetA2APushNotificationConfig(ctx context.Context, cfg *domain.A2APushNotificationConfig) error {
	if cfg.ID == "" {
		cfg.ID = "push_cfg_" + uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.SetA2APushNotificationConfig(ctx, cfg)
	}
	const q = `
		INSERT INTO a2a_push_notification_configs (
			id, task_id, tenant, target_url, token, auth_token,
			encrypted_auth_scheme, encrypted_auth_creds, encrypted_auth_dek, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (id) DO UPDATE SET
			tenant = EXCLUDED.tenant,
			target_url = EXCLUDED.target_url,
			token = EXCLUDED.token,
			auth_token = EXCLUDED.auth_token,
			encrypted_auth_scheme = EXCLUDED.encrypted_auth_scheme,
			encrypted_auth_creds = EXCLUDED.encrypted_auth_creds,
			encrypted_auth_dek = EXCLUDED.encrypted_auth_dek,
			updated_at = NOW()`
	if _, err := p.pool.Exec(ctx, q,
		cfg.ID, cfg.TaskID, cfg.Tenant, cfg.TargetURL, cfg.Token, cfg.AuthToken,
		cfg.AuthScheme, cfg.EncryptedAuthCreds, cfg.EncryptedAuthDEK,
	); err != nil {
		return err
	}
	_ = p.mem.SetA2APushNotificationConfig(ctx, cfg)
	return nil
}

func (p *PostgresRepository) GetA2APushNotificationConfig(ctx context.Context, taskID, configID string) (*domain.A2APushNotificationConfig, error) {
	if p.pool == nil {
		return p.mem.GetA2APushNotificationConfig(ctx, taskID, configID)
	}
	var q string
	var args []any
	if configID != "" {
		q = `SELECT ` + a2aPushConfigSelectCols + ` FROM a2a_push_notification_configs WHERE task_id = $1 AND id = $2 LIMIT 1`
		args = []any{taskID, configID}
	} else {
		q = `SELECT ` + a2aPushConfigSelectCols + ` FROM a2a_push_notification_configs WHERE task_id = $1 ORDER BY created_at DESC LIMIT 1`
		args = []any{taskID}
	}
	cfg, err := scanA2APushConfig(p.pool.QueryRow(ctx, q, args...))
	if err != nil {
		return nil, fmt.Errorf("push notification config %q for task %s not found: %w", configID, taskID, err)
	}
	return cfg, nil
}

func (p *PostgresRepository) ListA2APushNotificationConfigs(ctx context.Context, taskID string, limit, offset int) ([]*domain.A2APushNotificationConfig, int, error) {
	if p.pool == nil {
		return p.mem.ListA2APushNotificationConfigs(ctx, taskID, limit, offset)
	}
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM a2a_push_notification_configs WHERE task_id = $1`, taskID).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	const q = `SELECT ` + a2aPushConfigSelectCols + ` FROM a2a_push_notification_configs WHERE task_id = $1 ORDER BY created_at DESC, id ASC LIMIT $2 OFFSET $3`
	rows, err := p.pool.Query(ctx, q, taskID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*domain.A2APushNotificationConfig, 0)
	for rows.Next() {
		cfg, scanErr := scanA2APushConfig(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		out = append(out, cfg)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (p *PostgresRepository) DeleteA2APushNotificationConfig(ctx context.Context, taskID, configID string) error {
	if p.pool == nil {
		return p.mem.DeleteA2APushNotificationConfig(ctx, taskID, configID)
	}
	var q string
	var args []any
	if configID != "" {
		q = `DELETE FROM a2a_push_notification_configs WHERE task_id = $1 AND id = $2`
		args = []any{taskID, configID}
	} else {
		q = `DELETE FROM a2a_push_notification_configs WHERE task_id = $1`
		args = []any{taskID}
	}
	tag, err := p.pool.Exec(ctx, q, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("push notification config %q for task %s not found", configID, taskID)
	}
	_ = p.mem.DeleteA2APushNotificationConfig(ctx, taskID, configID)
	return nil
}

func (p *PostgresRepository) PruneExpiredA2ARecords(ctx context.Context, pubBefore, outboxBefore, taskBefore time.Time) (int64, error) {
	if p.pool == nil {
		return p.mem.PruneExpiredA2ARecords(ctx, pubBefore, outboxBefore, taskBefore)
	}
	var total int64

	if !pubBefore.IsZero() {
		tag, err := p.pool.Exec(ctx, `
			DELETE FROM a2a_stream_publications
			WHERE published = TRUE AND created_at < $1`, pubBefore.UTC())
		if err != nil {
			return total, fmt.Errorf("prune a2a_stream_publications: %w", err)
		}
		total += tag.RowsAffected()
	}

	if !outboxBefore.IsZero() {
		tag, err := p.pool.Exec(ctx, `
			DELETE FROM a2a_outbox_events
			WHERE status IN ('sent', 'delivered', 'dead_letter') AND updated_at < $1`, outboxBefore.UTC())
		if err != nil {
			return total, fmt.Errorf("prune a2a_outbox_events: %w", err)
		}
		total += tag.RowsAffected()
	}

	if !taskBefore.IsZero() {
		tag, err := p.pool.Exec(ctx, `
			DELETE FROM a2a_tasks
			WHERE state IN ('completed', 'failed', 'canceled', 'rejected', 'TASK_STATE_COMPLETED', 'TASK_STATE_FAILED', 'TASK_STATE_CANCELED', 'TASK_STATE_REJECTED')
			  AND updated_at < $1`, taskBefore.UTC())
		if err != nil {
			return total, fmt.Errorf("prune a2a_tasks: %w", err)
		}
		total += tag.RowsAffected()
	}

	_, _ = p.mem.PruneExpiredA2ARecords(ctx, pubBefore, outboxBefore, taskBefore)
	return total, nil
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
	if p.pool == nil {
		return p.mem.GetFile(ctx, orgID, fileID)
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
		VALUES ($1, $2, NULLIF($3, ''), $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`
	_, err := p.pool.Exec(ctx, q, batch.ID, batch.OrgID, batch.TeamID, batch.InputFileID, batch.OutputFileID, batch.ErrorFileID, batch.Endpoint, batch.Status, batch.CompletionWindow, batch.CreatedAt, batch.CompletedAt, metaJSON, countsJSON, batch.EstimatedTokens, batch.ReservedCostMicros, batch.UpstreamProvider, batch.UpstreamID)
	if err != nil {
		return err
	}
	return p.mem.CreateBatch(ctx, batch)
}

func (p *PostgresRepository) GetBatch(ctx context.Context, orgID, batchID string) (*domain.CanonicalBatch, error) {
	if p.pool == nil {
		return p.mem.GetBatch(ctx, orgID, batchID)
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), input_file_id, COALESCE(output_file_id, ''), COALESCE(error_file_id, ''), endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, estimated_tokens, reserved_cost_micros, COALESCE(upstream_provider, ''), COALESCE(upstream_id, '')
		FROM batches WHERE id = $1 AND ($2 = '' OR org_id = $2)`
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
		FROM batches WHERE ($1 = '' OR org_id = $1)
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
