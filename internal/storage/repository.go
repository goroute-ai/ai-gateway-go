package storage

import (
	"context"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// SpendSummary aggregates financial metrics per organization, team, model, or provider.
type SpendSummary struct {
	TotalRequests     int64            `json:"total_requests"`
	TotalTokens       int64            `json:"total_tokens"`
	TotalCostMicros   int64            `json:"total_cost_micros"`
	TotalCostUSD      float64          `json:"total_cost_usd"`
	UnpricedRequests  int64            `json:"unpriced_requests"`
	UnpricedTokens    int64            `json:"unpriced_tokens"`
	SpendByProvider   map[string]int64 `json:"spend_by_provider"`
	SpendByModel      map[string]int64 `json:"spend_by_model"`
	SpendByTeam       map[string]int64 `json:"spend_by_team"`
	SpendByVirtualKey map[string]int64 `json:"spend_by_virtual_key"`
}

// Repository defines the persistence contract shared across Control Plane and Data Plane services.
type Repository interface {
	// Health & Connectivity
	Ping(ctx context.Context) error

	// Layer 1: Global Model Catalogue & Versioned Pricing
	UpsertGlobalModel(ctx context.Context, m *domain.GlobalModel) error
	GetGlobalModel(ctx context.Context, id string) (*domain.GlobalModel, error)
	ListGlobalModels(ctx context.Context) ([]*domain.GlobalModel, error)
	UpdateModelPricing(ctx context.Context, modelID string, inputMicros, outputMicros, cachedMicros, reasoningMicros int64, status domain.PricingStatus, provenance, effectiveDate, changedBy string) (*domain.GlobalModel, error)
	ListModelPricingHistory(ctx context.Context, modelID string) ([]*domain.ModelPricingHistory, error)

	// Organizations (Multi-Tenant Root)
	CreateOrganization(ctx context.Context, org *domain.Organization) error
	GetOrganization(ctx context.Context, id string) (*domain.Organization, error)
	ListOrganizations(ctx context.Context) ([]*domain.Organization, error)

	// Layer 2: Organization Provider Subscriptions
	SetOrgProviderSubscription(ctx context.Context, sub *domain.OrgProviderSubscription) error
	GetOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error)

	// Layer 3: Organization Model Availability Policies
	SetOrgModelPolicy(ctx context.Context, pol *domain.OrgModelPolicy) error
	GetOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error)

	// Teams & Users
	CreateTeam(ctx context.Context, team *domain.Team) error
	GetTeam(ctx context.Context, id string) (*domain.Team, error)
	ListTeams(ctx context.Context, orgID string) ([]*domain.Team, error)
	CreateUser(ctx context.Context, user *domain.User) error
	ListUsers(ctx context.Context, orgID string) ([]*domain.User, error)

	// Boundary 1 Auth: Virtual API Keys
	CreateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error
	GetVirtualKeyByHash(ctx context.Context, keyHash string) (*domain.VirtualKey, error)
	GetVirtualKeyByID(ctx context.Context, id string) (*domain.VirtualKey, error)
	ListVirtualKeys(ctx context.Context, orgID string) ([]*domain.VirtualKey, error)
	RevokeVirtualKey(ctx context.Context, id string) error

	// Boundary 2 Auth: Provider Credentials Vault
	CreateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error
	UpdateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error
	GetProviderCredential(ctx context.Context, id string) (*domain.ProviderCredential, error)
	ListProviderCredentials(ctx context.Context, orgID string) ([]*domain.ProviderCredential, error)

	// Layer 4: Model Groups & Deployments
	CreateModelGroup(ctx context.Context, mg *domain.ModelGroup) error
	GetModelGroupByAlias(ctx context.Context, orgID, alias string) (*domain.ModelGroup, error)
	GetModelGroupByID(ctx context.Context, id string) (*domain.ModelGroup, error)
	ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error)
	CreateDeployment(ctx context.Context, dep *domain.Deployment) error
	ListDeploymentsByGroup(ctx context.Context, groupID string) ([]*domain.Deployment, error)
	ListAllDeployments(ctx context.Context) ([]*domain.Deployment, error)
	UpdateDeploymentStatus(ctx context.Context, depID string, status domain.DeploymentStatus) error

	// Security Guardrail Policies
	SetGuardrailPolicy(ctx context.Context, pol *domain.GuardrailPolicy) error
	GetGuardrailPolicy(ctx context.Context, orgID string) (*domain.GuardrailPolicy, error)

	// FinOps Spend & Audit Logging
	EnqueueSpendEvent(ctx context.Context, event domain.SpendEvent) error
	ClaimSpendEvents(ctx context.Context, limit int, lease time.Duration) ([]domain.SpendEvent, error)
	MarkSpendEventDelivered(ctx context.Context, id string) error
	RetrySpendEvent(ctx context.Context, id string, cause error, retryAt time.Time, maxAttempts int) error
	RecordSpendBatch(ctx context.Context, events []domain.SpendEvent) error
	GetSpendSummary(ctx context.Context, orgID string) (*SpendSummary, error)
	ListSpendLogs(ctx context.Context, orgID string, limit int) ([]domain.SpendEvent, error)
	ResetExpiredBudgets(ctx context.Context, now time.Time) (int, error)
	RecordAuditLog(ctx context.Context, log *domain.AuditLog) error
	ListAuditLogs(ctx context.Context, orgID string, limit int) ([]*domain.AuditLog, error)

	// MCP: Servers, Tools, Toolsets & BYOK Credentials
	CreateMCPServer(ctx context.Context, server *domain.MCPServer) error
	UpdateMCPServer(ctx context.Context, server *domain.MCPServer) error
	GetMCPServer(ctx context.Context, id string) (*domain.MCPServer, error)
	GetMCPServerBySlug(ctx context.Context, orgID, slug string) (*domain.MCPServer, error)
	ListMCPServers(ctx context.Context, orgID string) ([]*domain.MCPServer, error)
	DeleteMCPServer(ctx context.Context, id string) error

	UpsertMCPTools(ctx context.Context, serverID, orgID string, tools []*domain.MCPTool) error
	ListMCPTools(ctx context.Context, serverID string) ([]*domain.MCPTool, error)
	GetMCPTool(ctx context.Context, id string) (*domain.MCPTool, error)

	CreateMCPToolset(ctx context.Context, toolset *domain.MCPToolset) error
	GetMCPToolsetBySlug(ctx context.Context, orgID, slug string) (*domain.MCPToolset, error)
	ListMCPToolsets(ctx context.Context, orgID string) ([]*domain.MCPToolset, error)

	SetMCPUserCredential(ctx context.Context, cred *domain.MCPUserCredential) error
	GetMCPUserCredential(ctx context.Context, serverID, userID string) (*domain.MCPUserCredential, error)

	// A2A: Agents, Tasks, Events, Publications & Outbox
	CreateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error
	UpdateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error
	GetA2AAgent(ctx context.Context, id string) (*domain.A2AAgent, error)
	GetA2AAgentBySlug(ctx context.Context, orgID, slug string) (*domain.A2AAgent, error)
	ListA2AAgents(ctx context.Context, orgID string) ([]*domain.A2AAgent, error)
	SetA2AAgentKillSwitch(ctx context.Context, id string, killed bool) error

	CreateA2ATask(ctx context.Context, task *domain.A2ATask) error
	UpdateA2ATaskState(ctx context.Context, taskID, state string, outputJSON string, costMicros int64) error
	GetA2ATask(ctx context.Context, id string) (*domain.A2ATask, error)
	ListA2ATasks(ctx context.Context, agentID, virtualKeyID string, limit int) ([]*domain.A2ATask, error)

	AppendA2ATaskEvent(ctx context.Context, taskID, eventType, payloadJSON string) (*domain.A2ATaskEvent, error)
	ListA2ATaskEvents(ctx context.Context, taskID string, afterSeq int64, limit int) ([]*domain.A2ATaskEvent, error)

	ClaimPendingA2AStreamPublications(ctx context.Context, batchSize int) ([]*domain.A2AStreamPublication, error)
	MarkA2AStreamPublicationSuccess(ctx context.Context, id string) error

	CreateA2AOutboxEvent(ctx context.Context, event *domain.A2AOutboxEvent) error
	ClaimPendingA2AOutboxEvents(ctx context.Context, batchSize int) ([]*domain.A2AOutboxEvent, error)
	GetA2AOutboxEvent(ctx context.Context, id string) (*domain.A2AOutboxEvent, error)
	UpdateA2AOutboxEventStatus(ctx context.Context, id, status string) error

	SetA2APushNotificationConfig(ctx context.Context, cfg *domain.A2APushNotificationConfig) error
	GetA2APushNotificationConfig(ctx context.Context, taskID string) (*domain.A2APushNotificationConfig, error)

	// Files Management (Stateful Tenant Assets)
	CreateFile(ctx context.Context, file *domain.CanonicalFile) error
	GetFile(ctx context.Context, orgID, fileID string) (*domain.CanonicalFile, error)
	ListFiles(ctx context.Context, orgID string, purpose string) ([]*domain.CanonicalFile, error)
	DeleteFile(ctx context.Context, orgID, fileID string) error

	// Batches Management (Asynchronous Batch Processing)
	CreateBatch(ctx context.Context, batch *domain.CanonicalBatch) error
	GetBatch(ctx context.Context, orgID, batchID string) (*domain.CanonicalBatch, error)
	ListBatches(ctx context.Context, orgID string, limit int) ([]*domain.CanonicalBatch, error)
	UpdateBatchStatus(ctx context.Context, batchID string, status string, outputFileID string, counts domain.BatchCounts, completedAt *time.Time) error
}
