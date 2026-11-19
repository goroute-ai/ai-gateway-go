package storage

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// MemoryRepository provides a thread-safe, high-performance in-memory implementation of Repository
// seeded with the default Global Model Catalogue, suitable for standalone execution and fast integration testing.
type MemoryRepository struct {
	mu                             sync.RWMutex
	routingRev                     atomic.Uint64
	globalModels                   map[string]*domain.GlobalModel
	globalModelsByName             map[string]map[domain.ProviderType]map[string]struct{}
	globalModelRevision            uint64
	pricingSummaryRevision         uint64
	pricingSummary                 GlobalModelPricingSummary
	pricingSummaryValid            bool
	pricingSummaryRebuilds         uint64
	orgs                           map[string]*domain.Organization
	orgSubs                        map[string]map[domain.ProviderType]*domain.OrgProviderSubscription
	orgPolicies                    map[string]map[string]*domain.OrgModelPolicy
	teams                          map[string]*domain.Team
	teamMemberships                map[string]*domain.TeamMembership
	teamMembershipsByTuple         map[string]string
	projects                       map[string]*domain.Project
	projectsByTeamName             map[string]string
	users                          map[string]*domain.User
	keysByID                       map[string]*domain.VirtualKey
	keysByHash                     map[string]*domain.VirtualKey
	deprecatedKeyHashes            map[string]*deprecatedKeyHashEntry
	jwtKeyMappings                 map[string]*domain.JWTKeyMapping
	jwtKeyMappingsByTuple          map[string]string
	quotaPolicies                  map[string]*domain.QuotaPolicy
	quotaPoliciesByTuple           map[string]string
	ptuShares                      map[string]*domain.DeploymentPTUShare
	ptuSharesByTuple               map[string]string
	priorityClasses                map[string]*domain.PriorityClass
	priorityClassesByTuple         map[string]string
	budgetWindows                  map[string]*domain.BudgetWindowLimit
	budgetWindowsByTuple           map[string]string
	endUsers                       map[string]*domain.EndUser
	endUsersByTuple                map[string]string
	tags                           map[string]*domain.Tag
	tagsByTuple                    map[string]string
	modelAccessGroups              map[string]*domain.ModelAccessGroup
	modelAccessGroupsByTuple       map[string]string
	modelAccessGroupMembers        map[string]*domain.ModelAccessGroupMember
	modelAccessGroupMembersByTuple map[string]string
	accessGroupRules               map[string]*domain.AccessGroupRule
	credentials                    map[string]*domain.ProviderCredential
	groupsByID                     map[string]*domain.ModelGroup
	deployments                    map[string]*domain.Deployment
	pricingHistory                 map[string][]*domain.ModelPricingHistory
	guardrails                     map[string]*domain.GuardrailPolicy
	guardrailDefs                  map[string]*domain.GuardrailDefinition
	guardrailBindings              map[string]*domain.GuardrailBinding
	spendLogs                      []domain.SpendEvent
	spendOutbox                    map[string]*spendOutboxEntry
	spendLogIDs                    map[string]struct{}
	budgetResetOutbox              map[string]BudgetResetEvent
	auditLogs                      []*domain.AuditLog

	mcpServers       map[string]*domain.MCPServer
	mcpTools         map[string]*domain.MCPTool
	mcpToolsets      map[string]*domain.MCPToolset
	mcpUserCreds     map[string]*domain.MCPUserCredential
	a2aAgents        map[string]*domain.A2AAgent
	a2aTasks         map[string]*domain.A2ATask
	a2aTaskEvents    map[string][]*domain.A2ATaskEvent
	a2aStreamPubs    []*domain.A2AStreamPublication
	a2aOutbox        []*domain.A2AOutboxEvent
	a2aPushConfigs   map[string]*domain.A2APushNotificationConfig
	files            map[string]*domain.CanonicalFile
	batches          map[string]*domain.CanonicalBatch
	userCredentials  map[string]*domain.UserCredential
	operatorSessions map[string]*domain.OperatorSession
}

// RoutingRevision returns the monotonically increasing routing topology revision for MemoryRepository.
func (r *MemoryRepository) RoutingRevision() uint64 {
	if r == nil {
		return 0
	}
	return r.routingRev.Load()
}

type deprecatedKeyHashEntry struct {
	keyHash      string
	virtualKeyID string
	revokeAt     time.Time
	createdAt    time.Time
}

type spendOutboxEntry struct {
	event       domain.SpendEvent
	status      string
	attempts    int
	nextAttempt time.Time
	lockedAt    time.Time
	lastError   string
}

func NewMemoryRepository() *MemoryRepository {
	r := &MemoryRepository{
		globalModels:                   make(map[string]*domain.GlobalModel),
		globalModelsByName:             make(map[string]map[domain.ProviderType]map[string]struct{}),
		orgs:                           make(map[string]*domain.Organization),
		orgSubs:                        make(map[string]map[domain.ProviderType]*domain.OrgProviderSubscription),
		orgPolicies:                    make(map[string]map[string]*domain.OrgModelPolicy),
		teams:                          make(map[string]*domain.Team),
		teamMemberships:                make(map[string]*domain.TeamMembership),
		teamMembershipsByTuple:         make(map[string]string),
		projects:                       make(map[string]*domain.Project),
		projectsByTeamName:             make(map[string]string),
		users:                          make(map[string]*domain.User),
		keysByID:                       make(map[string]*domain.VirtualKey),
		keysByHash:                     make(map[string]*domain.VirtualKey),
		deprecatedKeyHashes:            make(map[string]*deprecatedKeyHashEntry),
		jwtKeyMappings:                 make(map[string]*domain.JWTKeyMapping),
		jwtKeyMappingsByTuple:          make(map[string]string),
		quotaPolicies:                  make(map[string]*domain.QuotaPolicy),
		quotaPoliciesByTuple:           make(map[string]string),
		ptuShares:                      make(map[string]*domain.DeploymentPTUShare),
		ptuSharesByTuple:               make(map[string]string),
		priorityClasses:                make(map[string]*domain.PriorityClass),
		priorityClassesByTuple:         make(map[string]string),
		budgetWindows:                  make(map[string]*domain.BudgetWindowLimit),
		budgetWindowsByTuple:           make(map[string]string),
		endUsers:                       make(map[string]*domain.EndUser),
		endUsersByTuple:                make(map[string]string),
		tags:                           make(map[string]*domain.Tag),
		tagsByTuple:                    make(map[string]string),
		modelAccessGroups:              make(map[string]*domain.ModelAccessGroup),
		modelAccessGroupsByTuple:       make(map[string]string),
		modelAccessGroupMembers:        make(map[string]*domain.ModelAccessGroupMember),
		modelAccessGroupMembersByTuple: make(map[string]string),
		accessGroupRules:               make(map[string]*domain.AccessGroupRule),
		credentials:                    make(map[string]*domain.ProviderCredential),
		groupsByID:                     make(map[string]*domain.ModelGroup),
		deployments:                    make(map[string]*domain.Deployment),
		pricingHistory:                 make(map[string][]*domain.ModelPricingHistory),
		guardrails:                     make(map[string]*domain.GuardrailPolicy),
		guardrailDefs:                  make(map[string]*domain.GuardrailDefinition),
		guardrailBindings:              make(map[string]*domain.GuardrailBinding),
		spendOutbox:                    make(map[string]*spendOutboxEntry),
		spendLogIDs:                    make(map[string]struct{}),
		budgetResetOutbox:              make(map[string]BudgetResetEvent),
		files:                          make(map[string]*domain.CanonicalFile),
		batches:                        make(map[string]*domain.CanonicalBatch),
		mcpServers:                     make(map[string]*domain.MCPServer),
		mcpTools:                       make(map[string]*domain.MCPTool),
		mcpToolsets:                    make(map[string]*domain.MCPToolset),
		mcpUserCreds:                   make(map[string]*domain.MCPUserCredential),
		a2aAgents:                      make(map[string]*domain.A2AAgent),
		a2aTasks:                       make(map[string]*domain.A2ATask),
		a2aTaskEvents:                  make(map[string][]*domain.A2ATaskEvent),
		a2aPushConfigs:                 make(map[string]*domain.A2APushNotificationConfig),
		userCredentials:                make(map[string]*domain.UserCredential),
		operatorSessions:               make(map[string]*domain.OperatorSession),
	}
	r.seedDefaultGlobalCatalogue()
	return r
}

// Ping verifies repository health (always succeeds for in-memory).
func (r *MemoryRepository) Ping(ctx context.Context) error {
	return nil
}

func (r *MemoryRepository) seedDefaultGlobalCatalogue() {
	now := time.Now().UTC()
	defaults := []*domain.GlobalModel{
		{
			ID: "openai/gpt-4.1", Provider: domain.ProviderOpenAI, ModelName: "gpt-4.1", DisplayName: "OpenAI GPT-4.1",
			MaxInputTokens: 1047576, MaxOutputTokens: 32768, SupportsStreaming: true, SupportsTools: true, SupportsVision: true,
			InputCostMicrosPer1M: 2000000, OutputCostMicrosPer1M: 8000000, CachedInputCostMicrosPer1M: 500000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "openai/gpt-4.1-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4.1-mini", DisplayName: "OpenAI GPT-4.1 Mini",
			MaxInputTokens: 1047576, MaxOutputTokens: 32768, SupportsStreaming: true, SupportsTools: true, SupportsVision: true,
			InputCostMicrosPer1M: 400000, OutputCostMicrosPer1M: 1600000, CachedInputCostMicrosPer1M: 100000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "openai/o3-mini", Provider: domain.ProviderOpenAI, ModelName: "o3-mini", DisplayName: "OpenAI o3-mini Reasoning",
			MaxInputTokens: 200000, MaxOutputTokens: 100000, SupportsStreaming: true, SupportsTools: true, SupportsReasoning: true,
			InputCostMicrosPer1M: 1100000, OutputCostMicrosPer1M: 4400000, CachedInputCostMicrosPer1M: 550000, ReasoningCostMicrosPer1M: 4400000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "openai/text-embedding-3-small", Provider: domain.ProviderOpenAI, ModelName: "text-embedding-3-small", DisplayName: "OpenAI Text Embedding 3 Small",
			MaxInputTokens: 8191, MaxOutputTokens: 1536, SupportsEmbeddings: true,
			InputCostMicrosPer1M: 20000, LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "anthropic/claude-sonnet-4-20250514", Provider: domain.ProviderAnthropic, ModelName: "claude-sonnet-4-20250514", DisplayName: "Anthropic Claude Sonnet 4",
			MaxInputTokens: 200000, MaxOutputTokens: 64000, SupportsStreaming: true, SupportsTools: true, SupportsVision: true, SupportsReasoning: true,
			InputCostMicrosPer1M: 3000000, OutputCostMicrosPer1M: 15000000, CachedInputCostMicrosPer1M: 300000, ReasoningCostMicrosPer1M: 15000000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "anthropic/claude-3-5-haiku-latest", Provider: domain.ProviderAnthropic, ModelName: "claude-3-5-haiku-latest", DisplayName: "Anthropic Claude 3.5 Haiku",
			MaxInputTokens: 200000, MaxOutputTokens: 8192, SupportsStreaming: true, SupportsTools: true, SupportsVision: false,
			Capabilities: domain.ModelCapabilities{
				Streaming: domain.CapabilitySupported,
				Tools:     domain.CapabilitySupported,
				Vision:    domain.CapabilityUnsupported,
			},
			InputCostMicrosPer1M: 800000, OutputCostMicrosPer1M: 4000000, CachedInputCostMicrosPer1M: 80000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "anthropic/claude-haiku-4-5-20251001", Provider: domain.ProviderAnthropic, ModelName: "claude-haiku-4-5-20251001", DisplayName: "Anthropic Claude Haiku 4.5",
			MaxInputTokens: 200000, MaxOutputTokens: 64000, SupportsStreaming: true, SupportsTools: true, SupportsVision: true, SupportsReasoning: true,
			InputCostMicrosPer1M: 800000, OutputCostMicrosPer1M: 4000000, CachedInputCostMicrosPer1M: 80000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "gemini/gemini-2.5-pro", Provider: domain.ProviderGemini, ModelName: "gemini-2.5-pro", DisplayName: "Google Gemini 2.5 Pro",
			MaxInputTokens: 1048576, MaxOutputTokens: 65536, SupportsStreaming: true, SupportsTools: true, SupportsVision: true, SupportsReasoning: true,
			InputCostMicrosPer1M: 1250000, OutputCostMicrosPer1M: 10000000, CachedInputCostMicrosPer1M: 312500, ReasoningCostMicrosPer1M: 10000000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "gemini/gemini-2.5-flash", Provider: domain.ProviderGemini, ModelName: "gemini-2.5-flash", DisplayName: "Google Gemini 2.5 Flash",
			MaxInputTokens: 1048576, MaxOutputTokens: 65536, SupportsStreaming: true, SupportsTools: true, SupportsVision: true,
			InputCostMicrosPer1M: 150000, OutputCostMicrosPer1M: 600000, CachedInputCostMicrosPer1M: 37500,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "gemini/gemini-2.5-flash-lite", Provider: domain.ProviderGemini, ModelName: "gemini-2.5-flash-lite", DisplayName: "Google Gemini 2.5 Flash Lite",
			MaxInputTokens: 1048576, MaxOutputTokens: 65536, SupportsStreaming: true, SupportsTools: true, SupportsVision: true,
			InputCostMicrosPer1M: 75000, OutputCostMicrosPer1M: 300000, CachedInputCostMicrosPer1M: 18750,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "gemini/text-embedding-004", Provider: domain.ProviderGemini, ModelName: "text-embedding-004", DisplayName: "Google Gemini Text Embedding 004",
			MaxInputTokens: 2048, MaxOutputTokens: 768, SupportsEmbeddings: true,
			InputCostMicrosPer1M: 10000, LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "mistral/mistral-large-latest", Provider: domain.ProviderMistral, ModelName: "mistral-large-latest", DisplayName: "Mistral Large",
			MaxInputTokens: 128000, MaxOutputTokens: 32768, SupportsStreaming: true, SupportsTools: true,
			InputCostMicrosPer1M: 2000000, OutputCostMicrosPer1M: 6000000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "mistral/mistral-embed", Provider: domain.ProviderMistral, ModelName: "mistral-embed", DisplayName: "Mistral Embed",
			MaxInputTokens: 8192, MaxOutputTokens: 1024, SupportsEmbeddings: true,
			InputCostMicrosPer1M: 100000, LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "ollama/llama3.3", Provider: domain.ProviderOllama, ModelName: "llama3.3", DisplayName: "Ollama Llama 3.3 (Local)",
			MaxInputTokens: 128000, MaxOutputTokens: 8192, SupportsStreaming: true, SupportsTools: true,
			InputCostMicrosPer1M: 0, OutputCostMicrosPer1M: 0,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "ollama/llama3.2:1b", Provider: domain.ProviderOllama, ModelName: "llama3.2:1b", DisplayName: "Ollama Llama 3.2 1B (Local)",
			MaxInputTokens: 128000, MaxOutputTokens: 4096, SupportsStreaming: true, SupportsTools: true,
			InputCostMicrosPer1M: 0, OutputCostMicrosPer1M: 0,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
	}

	for _, m := range defaults {
		m.SupportsInference = true
		if m.PricingVersion <= 0 {
			m.PricingVersion = 1
		}
		m.PricingStatus = domain.PricingStatusVerified
		m.PricingProvenanceSource = "official-vendor-pricing-2025"
		m.PricingEffectiveDate = "2025-05-01"
		r.globalModels[m.ID] = m
		r.addGlobalModelNameIndex(m)
		r.pricingHistory[m.ID] = []*domain.ModelPricingHistory{
			{
				ID:                         uuid.NewString(),
				GlobalModelID:              m.ID,
				PricingVersion:             m.PricingVersion,
				PricingStatus:              m.PricingStatus,
				PricingProvenanceSource:    m.PricingProvenanceSource,
				InputCostMicrosPer1M:       m.InputCostMicrosPer1M,
				OutputCostMicrosPer1M:      m.OutputCostMicrosPer1M,
				CachedInputCostMicrosPer1M: m.CachedInputCostMicrosPer1M,
				ReasoningCostMicrosPer1M:   m.ReasoningCostMicrosPer1M,
				ChangedBy:                  "system-seed",
				EffectiveFrom:              now,
			},
		}
	}
}

func (r *MemoryRepository) UpsertGlobalModel(ctx context.Context, m *domain.GlobalModel) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m.ID == "" {
		m.ID = fmt.Sprintf("%s/%s", m.Provider, m.ModelName)
	}
	if m.PricingVersion <= 0 {
		if prev, ok := r.globalModels[m.ID]; ok && prev.PricingVersion > 0 {
			m.PricingVersion = prev.PricingVersion
		} else {
			m.PricingVersion = 1
		}
	}
	now := time.Now().UTC()
	if m.DiscoveredAt.IsZero() {
		m.DiscoveredAt = now
	}
	m.UpdatedAt = now
	if previous := r.globalModels[m.ID]; previous != nil && (previous.ModelName != m.ModelName || previous.Provider != m.Provider) {
		r.removeGlobalModelNameIndex(previous)
	}
	cp := cloneGlobalModel(m)
	cp.PricingStatus = domain.ResolvePricingStatus(m)
	r.globalModels[cp.ID] = cp
	r.addGlobalModelNameIndex(cp)
	r.globalModelRevision++
	r.routingRev.Add(1)
	if len(r.pricingHistory[cp.ID]) == 0 {
		r.pricingHistory[cp.ID] = []*domain.ModelPricingHistory{
			{
				ID:                         uuid.NewString(),
				GlobalModelID:              cp.ID,
				PricingVersion:             cp.PricingVersion,
				InputCostMicrosPer1M:       cp.InputCostMicrosPer1M,
				OutputCostMicrosPer1M:      cp.OutputCostMicrosPer1M,
				CachedInputCostMicrosPer1M: cp.CachedInputCostMicrosPer1M,
				ReasoningCostMicrosPer1M:   cp.ReasoningCostMicrosPer1M,
				ChangedBy:                  "discovery",
				EffectiveFrom:              now,
			},
		}
	}
	return nil
}

func (r *MemoryRepository) addGlobalModelNameIndex(m *domain.GlobalModel) {
	if m == nil || m.ModelName == "" {
		return
	}
	byProvider := r.globalModelsByName[m.ModelName]
	if byProvider == nil {
		byProvider = make(map[domain.ProviderType]map[string]struct{})
		r.globalModelsByName[m.ModelName] = byProvider
	}
	ids := byProvider[m.Provider]
	if ids == nil {
		ids = make(map[string]struct{})
		byProvider[m.Provider] = ids
	}
	ids[m.ID] = struct{}{}
}

func (r *MemoryRepository) removeGlobalModelNameIndex(m *domain.GlobalModel) {
	if m == nil {
		return
	}
	byProvider := r.globalModelsByName[m.ModelName]
	ids := byProvider[m.Provider]
	delete(ids, m.ID)
	if len(ids) == 0 {
		delete(byProvider, m.Provider)
	}
	if len(byProvider) == 0 {
		delete(r.globalModelsByName, m.ModelName)
	}
}

func (r *MemoryRepository) UpdateModelPricing(ctx context.Context, modelID string, inputMicros, outputMicros, cachedMicros, reasoningMicros int64, status domain.PricingStatus, provenance, effectiveDate, changedBy string) (*domain.GlobalModel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	gm, ok := r.globalModels[modelID]
	if !ok {
		for _, m := range r.globalModels {
			if m.ModelName == modelID {
				gm = m
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("global model %q not found", modelID)
	}
	now := time.Now().UTC()
	gm.PricingVersion++
	gm.InputCostMicrosPer1M = inputMicros
	gm.OutputCostMicrosPer1M = outputMicros
	if cachedMicros >= 0 {
		gm.CachedInputCostMicrosPer1M = cachedMicros
	}
	if reasoningMicros >= 0 {
		gm.ReasoningCostMicrosPer1M = reasoningMicros
	}
	if status != "" {
		gm.PricingStatus = status
	} else {
		gm.PricingStatus = domain.PricingStatusVerified
	}
	if provenance != "" {
		gm.PricingProvenanceSource = provenance
	}
	if effectiveDate != "" {
		gm.PricingEffectiveDate = effectiveDate
	}
	gm.UpdatedAt = now
	r.globalModelRevision++
	if changedBy == "" {
		changedBy = "admin"
	}
	r.pricingHistory[gm.ID] = append(r.pricingHistory[gm.ID], &domain.ModelPricingHistory{
		ID:                         uuid.NewString(),
		GlobalModelID:              gm.ID,
		PricingVersion:             gm.PricingVersion,
		InputCostMicrosPer1M:       gm.InputCostMicrosPer1M,
		OutputCostMicrosPer1M:      gm.OutputCostMicrosPer1M,
		CachedInputCostMicrosPer1M: gm.CachedInputCostMicrosPer1M,
		ReasoningCostMicrosPer1M:   gm.ReasoningCostMicrosPer1M,
		PricingStatus:              gm.PricingStatus,
		PricingProvenanceSource:    gm.PricingProvenanceSource,
		ChangedBy:                  changedBy,
		EffectiveFrom:              now,
	})
	cp := *gm
	return &cp, nil
}

func (r *MemoryRepository) ListModelPricingHistory(ctx context.Context, modelID string) ([]*domain.ModelPricingHistory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hist := r.pricingHistory[modelID]
	if len(hist) == 0 {
		for _, m := range r.globalModels {
			if m.ModelName == modelID {
				hist = r.pricingHistory[m.ID]
				break
			}
		}
	}
	out := make([]*domain.ModelPricingHistory, 0, len(hist))
	for _, h := range hist {
		cp := *h
		out = append(out, &cp)
	}
	return out, nil
}

func cloneGlobalModel(m *domain.GlobalModel) *domain.GlobalModel {
	if m == nil {
		return nil
	}
	cp := *m
	if len(m.SupportedOperations) > 0 {
		cp.SupportedOperations = make([]domain.OperationType, len(m.SupportedOperations))
		copy(cp.SupportedOperations, m.SupportedOperations)
	}
	if len(m.ModalityPricingJSON) > 0 {
		cp.ModalityPricingJSON = make(map[string]any, len(m.ModalityPricingJSON))
		for k, v := range m.ModalityPricingJSON {
			cp.ModalityPricingJSON[k] = v
		}
	}
	if m.DeprecationDate != nil {
		dt := *m.DeprecationDate
		cp.DeprecationDate = &dt
	}
	return &cp
}

func (r *MemoryRepository) GetGlobalModel(ctx context.Context, id string) (*domain.GlobalModel, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if m, ok := r.globalModels[id]; ok {
		return cloneGlobalModel(m), nil
	}
	// Also allow lookup by raw model_name
	for _, m := range r.globalModels {
		if m.ModelName == id {
			return cloneGlobalModel(m), nil
		}
	}
	return nil, fmt.Errorf("global model %q not found", id)
}

func (r *MemoryRepository) ListGlobalModels(ctx context.Context) ([]*domain.GlobalModel, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.GlobalModel, 0, len(r.globalModels))
	for _, m := range r.globalModels {
		out = append(out, cloneGlobalModel(m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListGlobalModelsByName returns indexed model-name matches without cloning or
// sorting the full catalogue. An empty provider selects matches from all providers.
func (r *MemoryRepository) ListGlobalModelsByName(ctx context.Context, provider domain.ProviderType, modelName string) ([]*domain.GlobalModel, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	byProvider := r.globalModelsByName[modelName]
	var count int
	if provider != "" {
		count = len(byProvider[provider])
	} else {
		for _, ids := range byProvider {
			count += len(ids)
		}
	}
	out := make([]*domain.GlobalModel, 0, count)
	appendIDs := func(ids map[string]struct{}) {
		for id := range ids {
			if model := r.globalModels[id]; model != nil {
				out = append(out, cloneGlobalModel(model))
			}
		}
	}
	if provider != "" {
		appendIDs(byProvider[provider])
	} else {
		for _, ids := range byProvider {
			appendIDs(ids)
		}
	}
	return out, nil
}

// GlobalModelCatalogSize returns the current projected catalog size in O(1).
func (r *MemoryRepository) GlobalModelCatalogSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.globalModels)
}

// GetGlobalModelPricingSummary returns the maximum verified/custom token rates
// across the catalog. The summary is rebuilt only after a catalog or pricing
// mutation, and a defensive value copy is returned to callers.
func (r *MemoryRepository) GetGlobalModelPricingSummary(ctx context.Context) (GlobalModelPricingSummary, error) {
	if err := ctx.Err(); err != nil {
		return GlobalModelPricingSummary{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pricingSummaryValid && r.pricingSummaryRevision == r.globalModelRevision {
		cached := r.pricingSummary
		cached.Rebuilt = false
		return cached, nil
	}
	summary := GlobalModelPricingSummary{CatalogSize: len(r.globalModels), Rebuilt: true}
	for _, gm := range r.globalModels {
		if gm == nil {
			continue
		}
		status := domain.ResolvePricingStatus(gm)
		if status != domain.PricingStatusVerified && status != domain.PricingStatusCustom {
			continue
		}
		summary.PricedModelCount++
		summary.HasPricedModels = true
		if gm.InputCostMicrosPer1M > summary.InputCostMicrosPer1M {
			summary.InputCostMicrosPer1M = gm.InputCostMicrosPer1M
		}
		if gm.CachedInputCostMicrosPer1M > summary.CachedInputCostMicrosPer1M {
			summary.CachedInputCostMicrosPer1M = gm.CachedInputCostMicrosPer1M
		}
		if gm.CacheWriteCostMicrosPer1M > summary.CacheWriteCostMicrosPer1M {
			summary.CacheWriteCostMicrosPer1M = gm.CacheWriteCostMicrosPer1M
		}
		if gm.OutputCostMicrosPer1M > summary.OutputCostMicrosPer1M {
			summary.OutputCostMicrosPer1M = gm.OutputCostMicrosPer1M
		}
		if gm.ReasoningCostMicrosPer1M > summary.ReasoningCostMicrosPer1M {
			summary.ReasoningCostMicrosPer1M = gm.ReasoningCostMicrosPer1M
		}
		if gm.MaxOutputTokens > summary.MaxOutputTokens {
			summary.MaxOutputTokens = gm.MaxOutputTokens
		}
	}
	r.pricingSummary = summary
	r.pricingSummaryRevision = r.globalModelRevision
	r.pricingSummaryValid = true
	r.pricingSummaryRebuilds++
	return summary, nil
}

// PricingSummaryRebuilds reports how many full summary scans were needed.
func (r *MemoryRepository) PricingSummaryRebuilds() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pricingSummaryRebuilds
}

func resolveBudgetResetSchedule(period domain.BudgetResetPeriod, existing *time.Time, now time.Time) (domain.BudgetResetPeriod, *time.Time) {
	if period == "" {
		period = domain.BudgetResetMonthly
	}
	if period == domain.BudgetResetNever {
		return period, nil
	}
	if existing != nil {
		t := existing.UTC()
		return period, &t
	}
	var next time.Time
	switch period {
	case domain.BudgetResetDaily:
		next = now.UTC().Add(24 * time.Hour)
	case domain.BudgetResetMonthly:
		next = now.UTC().AddDate(0, 1, 0)
	default:
		return period, nil
	}
	return period, &next
}

func advanceBudgetResetAt(period domain.BudgetResetPeriod, current *time.Time) *time.Time {
	if current == nil {
		return nil
	}
	switch period {
	case domain.BudgetResetDaily:
		next := current.UTC().Add(24 * time.Hour)
		return &next
	case domain.BudgetResetMonthly:
		next := current.UTC().AddDate(0, 1, 0)
		return &next
	case domain.BudgetResetNever:
		return nil
	default:
		return nil
	}
}

func cloneTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	cp := *t
	return &cp
}

func cloneOrganization(org *domain.Organization) *domain.Organization {
	if org == nil {
		return nil
	}
	cp := *org
	cp.MaxConcurrentRequests = org.MaxConcurrentRequests
	cp.BudgetFallbacks = domain.CloneBudgetFallbacks(org.BudgetFallbacks)
	cp.BudgetResetAt = cloneTimePtr(org.BudgetResetAt)
	cp.TempBudgetExpiresAt = cloneTimePtr(org.TempBudgetExpiresAt)
	cp.KeyExpiryAlertDays = slices.Clone(org.KeyExpiryAlertDays)
	if len(org.Metadata) > 0 {
		cp.Metadata = make(map[string]string, len(org.Metadata))
		for k, v := range org.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

func (r *MemoryRepository) CreateOrganization(ctx context.Context, org *domain.Organization) error {
	if org.SelfServeBudgetPolicy == "" {
		org.SelfServeBudgetPolicy = domain.SelfServeBudgetDisabled
	} else {
		p := domain.SelfServeBudgetPolicy(strings.ToLower(strings.TrimSpace(string(org.SelfServeBudgetPolicy))))
		if !p.IsValid() {
			return fmt.Errorf("invalid self_serve_budget_policy %q", org.SelfServeBudgetPolicy)
		}
		org.SelfServeBudgetPolicy = p
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if org.ID == "" {
		org.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	org.BudgetResetPeriod, org.BudgetResetAt = resolveBudgetResetSchedule(org.BudgetResetPeriod, org.BudgetResetAt, now)
	org.CreatedAt = now
	org.UpdatedAt = now
	r.orgs[org.ID] = cloneOrganization(org)
	return nil
}

func (r *MemoryRepository) GetOrganization(ctx context.Context, id string) (*domain.Organization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	org, ok := r.orgs[id]
	if !ok {
		return nil, fmt.Errorf("organization %q not found", id)
	}
	return cloneOrganization(org), nil
}

func (r *MemoryRepository) ListOrganizations(ctx context.Context) ([]*domain.Organization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Organization, 0, len(r.orgs))
	for _, o := range r.orgs {
		out = append(out, cloneOrganization(o))
	}
	return out, nil
}

func (r *MemoryRepository) UpdateOrganization(ctx context.Context, org *domain.Organization) error {
	if org == nil || org.ID == "" {
		return fmt.Errorf("organization id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.orgs[org.ID]
	if !ok {
		return fmt.Errorf("organization %q %w", org.ID, ErrNotFound)
	}
	if org.SelfServeBudgetPolicy == "" {
		org.SelfServeBudgetPolicy = existing.SelfServeBudgetPolicy
		if org.SelfServeBudgetPolicy == "" {
			org.SelfServeBudgetPolicy = domain.SelfServeBudgetDisabled
		}
	} else {
		p := domain.SelfServeBudgetPolicy(strings.ToLower(strings.TrimSpace(string(org.SelfServeBudgetPolicy))))
		if !p.IsValid() {
			return fmt.Errorf("invalid self_serve_budget_policy %q", org.SelfServeBudgetPolicy)
		}
		org.SelfServeBudgetPolicy = p
	}
	now := time.Now().UTC()
	if org.CreatedAt.IsZero() {
		org.CreatedAt = existing.CreatedAt
	}
	org.BudgetResetPeriod, org.BudgetResetAt = resolveBudgetResetSchedule(org.BudgetResetPeriod, org.BudgetResetAt, now)
	org.UpdatedAt = now
	r.orgs[org.ID] = cloneOrganization(org)
	return nil
}

func (r *MemoryRepository) SetOrgProviderSubscription(ctx context.Context, sub *domain.OrgProviderSubscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.orgSubs[sub.OrgID] == nil {
		r.orgSubs[sub.OrgID] = make(map[domain.ProviderType]*domain.OrgProviderSubscription)
	}
	if sub.SubscribedAt.IsZero() {
		sub.SubscribedAt = time.Now().UTC()
	}
	cp := *sub
	r.orgSubs[sub.OrgID][sub.Provider] = &cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	subs := r.orgSubs[orgID]
	out := make([]*domain.OrgProviderSubscription, 0, len(subs))
	for _, s := range subs {
		cp := *s
		out = append(out, &cp)
	}
	return out, nil
}

func (r *MemoryRepository) SetOrgModelPolicy(ctx context.Context, pol *domain.OrgModelPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.orgPolicies[pol.OrgID] == nil {
		r.orgPolicies[pol.OrgID] = make(map[string]*domain.OrgModelPolicy)
	}
	if pol.ApprovedAt.IsZero() {
		pol.ApprovedAt = time.Now().UTC()
	}
	cp := *pol
	r.orgPolicies[pol.OrgID][pol.GlobalModelID] = &cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pols := r.orgPolicies[orgID]
	out := make([]*domain.OrgModelPolicy, 0, len(pols))
	for _, p := range pols {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}

func cloneTeam(team *domain.Team) *domain.Team {
	if team == nil {
		return nil
	}
	cp := *team
	cp.MaxConcurrentRequests = team.MaxConcurrentRequests
	cp.BudgetFallbacks = domain.CloneBudgetFallbacks(team.BudgetFallbacks)
	cp.BudgetResetAt = cloneTimePtr(team.BudgetResetAt)
	cp.TempBudgetExpiresAt = cloneTimePtr(team.TempBudgetExpiresAt)
	cp.AllowedModels = slices.Clone(team.AllowedModels)
	cp.AllowedMCPServers = slices.Clone(team.AllowedMCPServers)
	cp.AllowedA2AAgents = slices.Clone(team.AllowedA2AAgents)
	cp.AllowedClientApps = slices.Clone(team.AllowedClientApps)
	cp.DefaultMemberAllowedModels = slices.Clone(team.DefaultMemberAllowedModels)
	cp.TeamMemberPermissions = slices.Clone(team.TeamMemberPermissions)
	cp.AllowedRoutingTags = slices.Clone(team.AllowedRoutingTags)
	return &cp
}

func (r *MemoryRepository) CreateTeam(ctx context.Context, team *domain.Team) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if team.ID == "" {
		team.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	team.BudgetResetPeriod, team.BudgetResetAt = resolveBudgetResetSchedule(team.BudgetResetPeriod, team.BudgetResetAt, now)
	team.CreatedAt = now
	team.UpdatedAt = now
	cp := cloneTeam(team)
	r.teams[cp.ID] = cp
	return nil
}

func (r *MemoryRepository) UpdateTeam(ctx context.Context, team *domain.Team) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if team == nil || team.ID == "" {
		return fmt.Errorf("team id is required")
	}
	existing, ok := r.teams[team.ID]
	if !ok {
		return fmt.Errorf("team %q %w", team.ID, ErrNotFound)
	}
	now := time.Now().UTC()
	if team.OrgID == "" {
		team.OrgID = existing.OrgID
	}
	if team.CreatedAt.IsZero() {
		team.CreatedAt = existing.CreatedAt
	}
	team.BudgetResetPeriod, team.BudgetResetAt = resolveBudgetResetSchedule(team.BudgetResetPeriod, team.BudgetResetAt, now)
	team.UpdatedAt = now
	cp := cloneTeam(team)
	r.teams[cp.ID] = cp
	return nil
}

func (r *MemoryRepository) GetTeam(ctx context.Context, id string) (*domain.Team, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.teams[id]
	if !ok {
		return nil, fmt.Errorf("team %q %w", id, ErrNotFound)
	}
	return cloneTeam(t), nil
}

func (r *MemoryRepository) GetTeamByName(ctx context.Context, orgID, name string) (*domain.Team, error) {
	orgID = strings.TrimSpace(orgID)
	name = strings.TrimSpace(name)
	if orgID == "" || name == "" {
		return nil, fmt.Errorf("team with org_id %q and name %q %w", orgID, name, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, t := range r.teams {
		if t.OrgID == orgID && t.Name == name {
			return cloneTeam(t), nil
		}
	}
	return nil, fmt.Errorf("team with org_id %q and name %q %w", orgID, name, ErrNotFound)
}

func (r *MemoryRepository) ListTeams(ctx context.Context, orgID string) ([]*domain.Team, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Team
	for _, t := range r.teams {
		if orgID == "" || t.OrgID == orgID {
			out = append(out, cloneTeam(t))
		}
	}
	return out, nil
}

func (r *MemoryRepository) DeleteTeam(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.teams[id]; !ok {
		return fmt.Errorf("team %q %w", id, ErrNotFound)
	}
	for _, share := range r.ptuShares {
		if share != nil && share.TeamID == id {
			return fmt.Errorf("team %q cannot be deleted while it holds active PTU shares: %w", id, ErrTeamHasActivePTUShares)
		}
	}
	delete(r.teams, id)
	for mID, m := range r.teamMemberships {
		if m.TeamID == id {
			delete(r.teamMembershipsByTuple, teamMembershipTupleKey(m.TeamID, m.UserID))
			delete(r.teamMemberships, mID)
		}
	}
	for pID, p := range r.projects {
		if p.TeamID == id {
			delete(r.projectsByTeamName, projectNameTupleKey(p.TeamID, p.Name))
			delete(r.projects, pID)
			for _, vk := range r.keysByID {
				if vk.ProjectID == pID {
					vk.ProjectID = ""
				}
			}
		}
	}
	return nil
}

func cloneUser(user *domain.User) *domain.User {
	if user == nil {
		return nil
	}
	cp := *user
	cp.BudgetFallbacks = domain.CloneBudgetFallbacks(user.BudgetFallbacks)
	cp.BudgetResetAt = cloneTimePtr(user.BudgetResetAt)
	cp.TempBudgetExpiresAt = cloneTimePtr(user.TempBudgetExpiresAt)
	return &cp
}

func (r *MemoryRepository) CreateUser(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if user.IsActive && strings.TrimSpace(user.SCIMExternalID) == "" {
		user.SCIMActive = true
	}
	now := time.Now().UTC()
	user.BudgetResetPeriod, user.BudgetResetAt = resolveBudgetResetSchedule(user.BudgetResetPeriod, user.BudgetResetAt, now)
	user.CreatedAt = now
	user.UpdatedAt = now
	cp := cloneUser(user)
	r.users[cp.ID] = cp
	return nil
}

func (r *MemoryRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user == nil || user.ID == "" {
		return fmt.Errorf("user id is required")
	}
	existing, ok := r.users[user.ID]
	if !ok {
		return fmt.Errorf("user %q %w", user.ID, ErrNotFound)
	}
	now := time.Now().UTC()
	if user.OrgID == "" {
		user.OrgID = existing.OrgID
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = existing.CreatedAt
	}
	user.BudgetResetPeriod, user.BudgetResetAt = resolveBudgetResetSchedule(user.BudgetResetPeriod, user.BudgetResetAt, now)
	user.UpdatedAt = now
	cp := cloneUser(user)
	r.users[cp.ID] = cp
	return nil
}

func (r *MemoryRepository) GetUser(ctx context.Context, id string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[id]
	if !ok {
		return nil, fmt.Errorf("user %q %w", id, ErrNotFound)
	}
	return cloneUser(u), nil
}

func (r *MemoryRepository) GetUserByOIDCSubject(ctx context.Context, subject string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.OIDCSubject != "" && u.OIDCSubject == subject {
			return cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("user with oidc_subject %q not found", subject)
}

func (r *MemoryRepository) ListUsers(ctx context.Context, orgID string) ([]*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.User
	for _, u := range r.users {
		if orgID == "" || u.OrgID == orgID {
			out = append(out, cloneUser(u))
		}
	}
	return out, nil
}

func (r *MemoryRepository) DeleteUser(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[id]; !ok {
		return fmt.Errorf("user %q %w", id, ErrNotFound)
	}
	delete(r.users, id)
	for mID, m := range r.teamMemberships {
		if m.UserID == id {
			delete(r.teamMembershipsByTuple, teamMembershipTupleKey(m.TeamID, m.UserID))
			delete(r.teamMemberships, mID)
		}
	}
	delete(r.userCredentials, id)
	for sessID, sess := range r.operatorSessions {
		if sess != nil && sess.UserID == id {
			delete(r.operatorSessions, sessID)
		}
	}
	return nil
}

func (r *MemoryRepository) UpsertTeamMembership(_ context.Context, m *domain.TeamMembership) error {
	if err := normalizeTeamMembership(m); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	tupleKey := teamMembershipTupleKey(m.TeamID, m.UserID)
	if existingID, ok := r.teamMembershipsByTuple[tupleKey]; ok {
		existing := r.teamMemberships[existingID]
		m.ID = existing.ID
		m.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > m.SpentMicros {
			m.SpentMicros = existing.SpentMicros
		}
		m.UpdatedAt = now
		r.teamMemberships[existing.ID] = cloneTeamMembership(m)
		return nil
	}

	if m.ID == "" {
		m.ID = uuid.NewString()
	} else if _, exists := r.teamMemberships[m.ID]; exists {
		return fmt.Errorf("team membership %q already exists: %w", m.ID, ErrConflict)
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	m.UpdatedAt = now
	r.teamMemberships[m.ID] = cloneTeamMembership(m)
	r.teamMembershipsByTuple[tupleKey] = m.ID
	return nil
}

func (r *MemoryRepository) GetTeamMembership(_ context.Context, teamID, userID string) (*domain.TeamMembership, error) {
	teamID = strings.TrimSpace(teamID)
	userID = strings.TrimSpace(userID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.teamMembershipsByTuple[teamMembershipTupleKey(teamID, userID)]
	if !ok {
		return nil, fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
	}
	m, ok := r.teamMemberships[id]
	if !ok {
		return nil, fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
	}
	return cloneTeamMembership(m), nil
}

func (r *MemoryRepository) ListTeamMemberships(_ context.Context, orgID, teamID, userID string) ([]*domain.TeamMembership, error) {
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)
	userID = strings.TrimSpace(userID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.TeamMembership
	for _, m := range r.teamMemberships {
		if orgID != "" && m.OrgID != orgID {
			continue
		}
		if teamID != "" && m.TeamID != teamID {
			continue
		}
		if userID != "" && m.UserID != userID {
			continue
		}
		out = append(out, cloneTeamMembership(m))
	}
	sortTeamMemberships(out)
	return out, nil
}

func (r *MemoryRepository) DeleteTeamMembership(_ context.Context, teamID, userID string) error {
	teamID = strings.TrimSpace(teamID)
	userID = strings.TrimSpace(userID)
	r.mu.Lock()
	defer r.mu.Unlock()
	tupleKey := teamMembershipTupleKey(teamID, userID)
	id, ok := r.teamMembershipsByTuple[tupleKey]
	if !ok {
		return fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
	}
	delete(r.teamMembershipsByTuple, tupleKey)
	delete(r.teamMemberships, id)
	return nil
}

func (r *MemoryRepository) BulkSyncTeamMemberships(_ context.Context, orgID, teamID string, upserts []*domain.TeamMembership, removeUserIDs []string) ([]*domain.TeamMembership, int, error) {
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	var results []*domain.TeamMembership
	for _, entry := range upserts {
		if entry == nil {
			continue
		}
		m := cloneTeamMembership(entry)
		m.OrgID = orgID
		m.TeamID = teamID
		if err := normalizeTeamMembership(m); err != nil {
			return nil, 0, err
		}
		tupleKey := teamMembershipTupleKey(m.TeamID, m.UserID)
		if existingID, ok := r.teamMembershipsByTuple[tupleKey]; ok {
			existing := r.teamMemberships[existingID]
			m.ID = existing.ID
			m.CreatedAt = existing.CreatedAt
			if existing.SpentMicros > m.SpentMicros {
				m.SpentMicros = existing.SpentMicros
			}
			m.UpdatedAt = now
		} else {
			if m.ID == "" {
				m.ID = uuid.NewString()
			}
			if m.CreatedAt.IsZero() {
				m.CreatedAt = now
			}
			m.UpdatedAt = now
			r.teamMembershipsByTuple[tupleKey] = m.ID
		}
		stored := cloneTeamMembership(m)
		r.teamMemberships[stored.ID] = stored
		results = append(results, cloneTeamMembership(stored))
	}

	var removed int
	for _, rawUID := range removeUserIDs {
		uid := strings.TrimSpace(rawUID)
		if uid == "" {
			continue
		}
		tupleKey := teamMembershipTupleKey(teamID, uid)
		if existingID, ok := r.teamMembershipsByTuple[tupleKey]; ok {
			delete(r.teamMembershipsByTuple, tupleKey)
			delete(r.teamMemberships, existingID)
			removed++
		}
	}
	return results, removed, nil
}

func (r *MemoryRepository) RotateKEKsTransactionally(_ context.Context, rewrap func(batch KEKRotationBatch) (KEKRotationBatch, error)) (KEKRotationSummary, error) {
	var summary KEKRotationSummary
	if rewrap == nil {
		return summary, fmt.Errorf("rewrap callback is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	batch := KEKRotationBatch{
		Credentials:       make([]*domain.ProviderCredential, 0, len(r.credentials)),
		MCPServers:        make([]*domain.MCPServer, 0, len(r.mcpServers)),
		A2AAgents:         make([]*domain.A2AAgent, 0, len(r.a2aAgents)),
		Guardrails:        make([]*domain.GuardrailDefinition, 0, len(r.guardrailDefs)),
		StagedVirtualKeys: make([]*domain.VirtualKey, 0),
	}
	for _, c := range r.credentials {
		if c == nil || len(c.EncryptedDEK) == 0 {
			continue
		}
		cp := *c
		cp.EncryptedAPIKey = slices.Clone(c.EncryptedAPIKey)
		cp.DataNonce = slices.Clone(c.DataNonce)
		cp.EncryptedDEK = slices.Clone(c.EncryptedDEK)
		cp.DEKNonce = slices.Clone(c.DEKNonce)
		batch.Credentials = append(batch.Credentials, &cp)
	}
	for _, s := range r.mcpServers {
		if s == nil || strings.TrimSpace(s.EncryptedAuthDEK) == "" {
			continue
		}
		cp := *s
		batch.MCPServers = append(batch.MCPServers, &cp)
	}
	for _, a := range r.a2aAgents {
		if a == nil || strings.TrimSpace(a.EncryptedAuthDEK) == "" {
			continue
		}
		cp := *a
		batch.A2AAgents = append(batch.A2AAgents, &cp)
	}
	for _, g := range r.guardrailDefs {
		if g == nil || strings.TrimSpace(g.EncryptedDEK) == "" {
			continue
		}
		batch.Guardrails = append(batch.Guardrails, cloneGuardrailDefinition(g))
	}
	for _, vk := range r.keysByID {
		if vk == nil || strings.TrimSpace(vk.StagedKeyDEK) == "" {
			continue
		}
		batch.StagedVirtualKeys = append(batch.StagedVirtualKeys, cloneVirtualKey(vk))
	}

	updated, err := rewrap(batch)
	if err != nil {
		return KEKRotationSummary{}, err
	}

	now := time.Now().UTC()
	for _, c := range updated.Credentials {
		if c == nil || c.ID == "" {
			continue
		}
		if _, ok := r.credentials[c.ID]; ok {
			cp := *c
			cp.UpdatedAt = now
			cp.DecryptedAPIKey = ""
			r.credentials[c.ID] = &cp
			summary.CredentialsRewrapped++
		}
	}
	for _, s := range updated.MCPServers {
		if s == nil || s.ID == "" {
			continue
		}
		if existing, ok := r.mcpServers[s.ID]; ok {
			cp := *existing
			cp.EncryptedAuthDEK = s.EncryptedAuthDEK
			cp.ConfigVersion++
			cp.UpdatedAt = now
			r.mcpServers[s.ID] = &cp
			summary.MCPServersRewrapped++
		}
	}
	for _, a := range updated.A2AAgents {
		if a == nil || a.ID == "" {
			continue
		}
		if existing, ok := r.a2aAgents[a.ID]; ok {
			cp := *existing
			cp.EncryptedAuthDEK = a.EncryptedAuthDEK
			cp.UpdatedAt = now
			r.a2aAgents[a.ID] = &cp
			summary.A2AAgentsRewrapped++
		}
	}
	for _, g := range updated.Guardrails {
		if g != nil && g.ID != "" {
			if existing, ok := r.guardrailDefs[g.ID]; ok {
				cp := cloneGuardrailDefinition(existing)
				cp.EncryptedDEK = g.EncryptedDEK
				cp.UpdatedAt = now
				r.guardrailDefs[g.ID] = cp
				summary.GuardrailsRewrapped++
			}
		}
	}
	for _, vk := range updated.StagedVirtualKeys {
		if vk == nil || vk.ID == "" {
			continue
		}
		if existing, ok := r.keysByID[vk.ID]; ok {
			cp := cloneVirtualKey(existing)
			cp.StagedKeyDEK = vk.StagedKeyDEK
			r.keysByID[vk.ID] = cp
			if cp.KeyHash != "" {
				r.keysByHash[cp.KeyHash] = cp
			}
			summary.StagedVirtualKeysRewrapped++
		}
	}
	return summary, nil
}

func (r *MemoryRepository) CreateProject(_ context.Context, p *domain.Project) error {
	if err := normalizeProject(p); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := projectNameTupleKey(p.TeamID, p.Name)
	if _, exists := r.projectsByTeamName[tupleKey]; exists {
		return fmt.Errorf("project %q already exists in team %q: %w", p.Name, p.TeamID, ErrConflict)
	}
	if p.ID == "" {
		p.ID = uuid.NewString()
	} else if _, exists := r.projects[p.ID]; exists {
		return fmt.Errorf("project %q already exists: %w", p.ID, ErrConflict)
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	r.projects[p.ID] = cloneProject(p)
	r.projectsByTeamName[tupleKey] = p.ID
	return nil
}

func (r *MemoryRepository) GetProject(_ context.Context, id string) (*domain.Project, error) {
	id = strings.TrimSpace(id)
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.projects[id]
	if !ok {
		return nil, fmt.Errorf("project %q %w", id, ErrNotFound)
	}
	return cloneProject(p), nil
}

func (r *MemoryRepository) ListProjects(_ context.Context, orgID, teamID string) ([]*domain.Project, error) {
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Project
	for _, p := range r.projects {
		if orgID != "" && p.OrgID != orgID {
			continue
		}
		if teamID != "" && p.TeamID != teamID {
			continue
		}
		out = append(out, cloneProject(p))
	}
	sortProjects(out)
	return out, nil
}

func (r *MemoryRepository) UpdateProject(_ context.Context, p *domain.Project) error {
	if err := normalizeProject(p); err != nil {
		return err
	}
	if p.ID == "" {
		return fmt.Errorf("project id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.projects[p.ID]
	if !ok {
		return fmt.Errorf("project %q %w", p.ID, ErrNotFound)
	}
	newTupleKey := projectNameTupleKey(p.TeamID, p.Name)
	if otherID, exists := r.projectsByTeamName[newTupleKey]; exists && otherID != p.ID {
		return fmt.Errorf("project %q already exists in team %q: %w", p.Name, p.TeamID, ErrConflict)
	}
	oldTupleKey := projectNameTupleKey(existing.TeamID, existing.Name)
	if oldTupleKey != newTupleKey {
		delete(r.projectsByTeamName, oldTupleKey)
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = existing.CreatedAt
	}
	p.UpdatedAt = time.Now().UTC()
	r.projects[p.ID] = cloneProject(p)
	r.projectsByTeamName[newTupleKey] = p.ID
	return nil
}

func (r *MemoryRepository) DeleteProject(_ context.Context, id string) error {
	id = strings.TrimSpace(id)
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.projects[id]
	if !ok {
		return fmt.Errorf("project %q %w", id, ErrNotFound)
	}
	delete(r.projectsByTeamName, projectNameTupleKey(p.TeamID, p.Name))
	delete(r.projects, id)
	for _, vk := range r.keysByID {
		if vk.ProjectID == id {
			vk.ProjectID = ""
		}
	}
	return nil
}

func (r *MemoryRepository) GetUserByOrgAndOIDCSubject(ctx context.Context, orgID, subject string) (*domain.User, error) {
	return r.GetUserByOIDCIdentity(ctx, orgID, "", subject)
}

func (r *MemoryRepository) GetUserByOIDCIdentity(_ context.Context, orgID, issuer, subject string) (*domain.User, error) {
	if subject == "" || (orgID == "" && issuer != "") {
		return nil, fmt.Errorf("user with org_id %q issuer %q and oidc_subject %q %w", orgID, issuer, subject, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matched *domain.User
	for _, u := range r.users {
		if (orgID == "" || u.OrgID == orgID) && u.OIDCIssuer == issuer && u.OIDCSubject == subject {
			if matched != nil {
				return nil, fmt.Errorf("multiple users share oidc identity: %w", ErrConflict)
			}
			matched = cloneUser(u)
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("user with org_id %q issuer %q and oidc_subject %q %w", orgID, issuer, subject, ErrNotFound)
	}
	return matched, nil
}

func (r *MemoryRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("user with email %q %w", email, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if strings.EqualFold(u.Email, email) {
			return cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("user with email %q %w", email, ErrNotFound)
}

func (r *MemoryRepository) GetUserBySCIMExternalID(ctx context.Context, orgID, externalID string) (*domain.User, error) {
	orgID = strings.TrimSpace(orgID)
	externalID = strings.TrimSpace(externalID)
	if orgID == "" || externalID == "" {
		return nil, fmt.Errorf("user with org_id %q and scim_external_id %q %w", orgID, externalID, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.OrgID == orgID && u.SCIMExternalID == externalID {
			return cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("user with org_id %q and scim_external_id %q %w", orgID, externalID, ErrNotFound)
}

func (r *MemoryRepository) GetOrCreateUserByOIDCSubject(ctx context.Context, user *domain.User) (*domain.User, bool, error) {
	if user == nil || strings.TrimSpace(user.OrgID) == "" {
		return nil, false, fmt.Errorf("org_id is required to provision user")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if user.OIDCSubject != "" {
		for _, u := range r.users {
			if u.OrgID == user.OrgID && u.OIDCIssuer == user.OIDCIssuer && u.OIDCSubject == user.OIDCSubject {
				cp := *u
				return &cp, false, nil
			}
		}
	}
	if user.Email != "" {
		for _, u := range r.users {
			if strings.EqualFold(u.Email, user.Email) {
				if u.OrgID != user.OrgID {
					return nil, false, fmt.Errorf("email %q already belongs to another organization: %w", user.Email, ErrConflict)
				}
				if u.OIDCIssuer != "" || user.OIDCIssuer != "" || (u.OIDCSubject != "" && user.OIDCSubject != "" && u.OIDCSubject != user.OIDCSubject) {
					return nil, false, fmt.Errorf("email %q is bound to another OIDC identity: %w", user.Email, ErrConflict)
				}
				cp := *u
				return &cp, false, nil
			}
		}
	}

	cp := *user
	if cp.ID == "" {
		cp.ID = uuid.NewString()
	}
	if cp.IsActive && strings.TrimSpace(cp.SCIMExternalID) == "" {
		cp.SCIMActive = true
	}
	now := time.Now().UTC()
	cp.BudgetResetPeriod, cp.BudgetResetAt = resolveBudgetResetSchedule(cp.BudgetResetPeriod, cp.BudgetResetAt, now)
	cp.CreatedAt = now
	cp.UpdatedAt = now
	r.users[cp.ID] = &cp
	out := cp
	return &out, true, nil
}

func jwtMappingTupleKey(issuer, claimName, claimValue string) string {
	return issuer + "\x00" + claimName + "\x00" + claimValue
}

func (r *MemoryRepository) CreateJWTKeyMapping(ctx context.Context, mapping *domain.JWTKeyMapping) error {
	if mapping == nil {
		return fmt.Errorf("jwt key mapping is required")
	}
	if strings.TrimSpace(mapping.OrgID) == "" ||
		strings.TrimSpace(mapping.Issuer) == "" ||
		strings.TrimSpace(mapping.ClaimName) == "" ||
		strings.TrimSpace(mapping.ClaimValue) == "" ||
		strings.TrimSpace(mapping.VirtualKeyID) == "" {
		return fmt.Errorf("org_id, issuer, claim_name, claim_value, and virtual_key_id are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := jwtMappingTupleKey(mapping.Issuer, mapping.ClaimName, mapping.ClaimValue)
	if _, exists := r.jwtKeyMappingsByTuple[tupleKey]; exists {
		return fmt.Errorf("jwt key mapping already exists for (%s, %s, %s): %w", mapping.Issuer, mapping.ClaimName, mapping.ClaimValue, ErrConflict)
	}
	if mapping.ID == "" {
		mapping.ID = uuid.NewString()
	}
	if mapping.CreatedAt.IsZero() {
		mapping.CreatedAt = time.Now().UTC()
	}
	cp := *mapping
	r.jwtKeyMappings[cp.ID] = &cp
	r.jwtKeyMappingsByTuple[tupleKey] = cp.ID
	return nil
}

func (r *MemoryRepository) GetJWTKeyMapping(ctx context.Context, id string) (*domain.JWTKeyMapping, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.jwtKeyMappings[id]
	if !ok {
		return nil, fmt.Errorf("jwt key mapping %q %w", id, ErrNotFound)
	}
	cp := *m
	return &cp, nil
}

func (r *MemoryRepository) ListJWTKeyMappings(ctx context.Context, orgID string) ([]*domain.JWTKeyMapping, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.JWTKeyMapping
	for _, m := range r.jwtKeyMappings {
		if orgID == "" || m.OrgID == orgID {
			cp := *m
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (r *MemoryRepository) DeleteJWTKeyMapping(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.jwtKeyMappings[id]
	if !ok {
		return fmt.Errorf("jwt key mapping %q %w", id, ErrNotFound)
	}
	delete(r.jwtKeyMappingsByTuple, jwtMappingTupleKey(m.Issuer, m.ClaimName, m.ClaimValue))
	delete(r.jwtKeyMappings, id)
	return nil
}

func (r *MemoryRepository) ResolveJWTKeyMapping(ctx context.Context, issuer, claimName, claimValue string) (*domain.JWTKeyMapping, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.jwtKeyMappingsByTuple[jwtMappingTupleKey(issuer, claimName, claimValue)]
	if !ok {
		return nil, fmt.Errorf("jwt key mapping %w", ErrNotFound)
	}
	m, ok := r.jwtKeyMappings[id]
	if !ok {
		return nil, fmt.Errorf("jwt key mapping %w", ErrNotFound)
	}
	cp := *m
	return &cp, nil
}

func (r *MemoryRepository) UpsertQuotaPolicy(_ context.Context, policy *domain.QuotaPolicy) error {
	now := time.Now().UTC()
	if err := normalizeQuotaPolicy(policy, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := quotaPolicyTupleKey(policy.OrgID, policy.ScopeType, policy.ScopeID, policy.ModelPattern)
	if existingID, ok := r.quotaPoliciesByTuple[tupleKey]; ok {
		existing := r.quotaPolicies[existingID]
		policy.ID = existing.ID
		policy.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > policy.SpentMicros {
			policy.SpentMicros = existing.SpentMicros
		}
		policy.UpdatedAt = now
		r.quotaPolicies[existing.ID] = policy.Clone()
		return nil
	}

	if policy.ID == "" {
		policy.ID = uuid.NewString()
	} else if _, exists := r.quotaPolicies[policy.ID]; exists {
		return fmt.Errorf("quota policy %q already exists: %w", policy.ID, ErrConflict)
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	r.quotaPolicies[policy.ID] = policy.Clone()
	r.quotaPoliciesByTuple[tupleKey] = policy.ID
	return nil
}

func (r *MemoryRepository) GetQuotaPolicy(_ context.Context, id string) (*domain.QuotaPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.quotaPolicies[id]
	if !ok {
		return nil, fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	return p.Clone(), nil
}

func (r *MemoryRepository) ListQuotaPolicies(_ context.Context, filter QuotaPolicyFilter) ([]*domain.QuotaPolicy, error) {
	orgID := strings.TrimSpace(filter.OrgID)
	scopeType := domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(filter.ScopeType))))
	scopeID := strings.TrimSpace(filter.ScopeID)
	modelPattern := strings.TrimSpace(filter.ModelPattern)

	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*domain.QuotaPolicy
	for _, p := range r.quotaPolicies {
		if orgID != "" && p.OrgID != orgID {
			continue
		}
		if scopeType != "" && p.ScopeType != scopeType {
			continue
		}
		if scopeID != "" && p.ScopeID != scopeID {
			continue
		}
		if modelPattern != "" && p.ModelPattern != modelPattern {
			continue
		}
		if filter.ActiveOnly && !p.IsActive {
			continue
		}
		out = append(out, p.Clone())
	}
	sortQuotaPolicies(out)
	return out, nil
}

func (r *MemoryRepository) DeleteQuotaPolicy(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.quotaPolicies[id]
	if !ok {
		return fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	delete(r.quotaPoliciesByTuple, quotaPolicyTupleKey(p.OrgID, p.ScopeType, p.ScopeID, p.ModelPattern))
	delete(r.quotaPolicies, id)
	return nil
}

func (r *MemoryRepository) IncrementQuotaPolicySpend(_ context.Context, id string, deltaMicros int64) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("quota policy id is required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.quotaPolicies[id]
	if !ok {
		return fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	p.SpentMicros += deltaMicros
	p.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) UpsertDeploymentPTUShare(_ context.Context, share *domain.DeploymentPTUShare) error {
	now := time.Now().UTC()
	if err := normalizePTUShare(share, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := ptuShareTupleKey(share.DeploymentID, share.TeamID)
	if existingID, ok := r.ptuSharesByTuple[tupleKey]; ok {
		existing := r.ptuShares[existingID]
		share.ID = existing.ID
		share.CreatedAt = existing.CreatedAt
		share.UpdatedAt = now
		r.ptuShares[existing.ID] = share.Clone()
		r.routingRev.Add(1)
		return nil
	}

	if share.ID == "" {
		share.ID = uuid.NewString()
	} else if _, exists := r.ptuShares[share.ID]; exists {
		return fmt.Errorf("deployment PTU share %q already exists: %w", share.ID, ErrConflict)
	}
	r.ptuShares[share.ID] = share.Clone()
	r.ptuSharesByTuple[tupleKey] = share.ID
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) ListDeploymentPTUShares(_ context.Context, deploymentID string) ([]*domain.DeploymentPTUShare, error) {
	deploymentID = strings.TrimSpace(deploymentID)
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*domain.DeploymentPTUShare
	for _, s := range r.ptuShares {
		if deploymentID != "" && s.DeploymentID != deploymentID {
			continue
		}
		out = append(out, s.Clone())
	}
	sortPTUShares(out)
	return out, nil
}

func (r *MemoryRepository) DeleteDeploymentPTUShare(_ context.Context, deploymentID, teamID string) error {
	deploymentID = strings.TrimSpace(deploymentID)
	teamID = strings.TrimSpace(teamID)
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := ptuShareTupleKey(deploymentID, teamID)
	id, ok := r.ptuSharesByTuple[tupleKey]
	if !ok {
		return fmt.Errorf("deployment PTU share (%s, %s) %w", deploymentID, teamID, ErrNotFound)
	}
	delete(r.ptuSharesByTuple, tupleKey)
	delete(r.ptuShares, id)
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) HasTeamPTUShares(_ context.Context, teamID string) (bool, error) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return false, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.ptuShares {
		if s != nil && s.TeamID == teamID {
			return true, nil
		}
	}
	return false, nil
}

func (r *MemoryRepository) UpsertPriorityClass(_ context.Context, pc *domain.PriorityClass) error {
	now := time.Now().UTC()
	if err := normalizePriorityClass(pc, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := priorityClassTupleKey(pc.OrgID, pc.Name)
	if existingID, ok := r.priorityClassesByTuple[tupleKey]; ok {
		existing := r.priorityClasses[existingID]
		pc.ID = existing.ID
		pc.CreatedAt = existing.CreatedAt
		r.priorityClasses[existing.ID] = pc.Clone()
		r.routingRev.Add(1)
		return nil
	}

	if pc.ID == "" {
		pc.ID = uuid.NewString()
	} else if _, exists := r.priorityClasses[pc.ID]; exists {
		return fmt.Errorf("priority class %q already exists: %w", pc.ID, ErrConflict)
	}
	r.priorityClasses[pc.ID] = pc.Clone()
	r.priorityClassesByTuple[tupleKey] = pc.ID
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) ListPriorityClasses(_ context.Context, orgID string) ([]*domain.PriorityClass, error) {
	orgID = strings.TrimSpace(orgID)
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*domain.PriorityClass
	for _, pc := range r.priorityClasses {
		if orgID != "" && pc.OrgID != orgID {
			continue
		}
		out = append(out, pc.Clone())
	}
	sortPriorityClasses(out)
	return out, nil
}

func (r *MemoryRepository) UpsertBudgetWindowLimit(_ context.Context, limit *domain.BudgetWindowLimit) error {
	now := time.Now().UTC()
	hasExplicitReset := limit != nil && !limit.WindowResetAt.IsZero()
	if err := normalizeBudgetWindowLimit(limit, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := budgetWindowTupleKey(limit.OrgID, limit.ScopeType, limit.ScopeID, limit.WindowType)
	if existingID, ok := r.budgetWindowsByTuple[tupleKey]; ok {
		existing := r.budgetWindows[existingID]
		limit.ID = existing.ID
		limit.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > limit.SpentMicros {
			limit.SpentMicros = existing.SpentMicros
		}
		if !hasExplicitReset {
			limit.WindowResetAt = existing.WindowResetAt
		}
		limit.UpdatedAt = now
		r.budgetWindows[existing.ID] = limit.Clone()
		return nil
	}

	if limit.ID == "" {
		limit.ID = uuid.NewString()
	} else if _, exists := r.budgetWindows[limit.ID]; exists {
		return fmt.Errorf("budget window limit %q already exists: %w", limit.ID, ErrConflict)
	}
	if limit.CreatedAt.IsZero() {
		limit.CreatedAt = now
	}
	limit.UpdatedAt = now
	r.budgetWindows[limit.ID] = limit.Clone()
	r.budgetWindowsByTuple[tupleKey] = limit.ID
	return nil
}

func (r *MemoryRepository) ListBudgetWindowLimits(_ context.Context, filter BudgetWindowFilter) ([]*domain.BudgetWindowLimit, error) {
	orgID := strings.TrimSpace(filter.OrgID)
	scopeType := domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(filter.ScopeType))))
	scopeID := strings.TrimSpace(filter.ScopeID)
	windowType := domain.BudgetWindowType(strings.ToLower(strings.TrimSpace(string(filter.WindowType))))

	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)
	var out []*domain.BudgetWindowLimit
	for _, bw := range r.budgetWindows {
		if orgID != "" && bw.OrgID != orgID {
			continue
		}
		if scopeType != "" && bw.ScopeType != scopeType {
			continue
		}
		if scopeID != "" && bw.ScopeID != scopeID {
			continue
		}
		if windowType != "" && bw.WindowType != windowType {
			continue
		}
		cp := bw.Clone()
		if !filter.SkipRollingSpend && cp.WindowType == domain.BudgetWindowRolling24h {
			recent := r.rollingWindowSpendLocked(cp, cutoff)
			if cp.RollingHoldExpiresAt != nil && now.Before(cp.RollingHoldExpiresAt.UTC()) && cp.RollingHoldMicros > 0 {
				recent += cp.RollingHoldMicros
			}
			cp.SpentMicros = recent
		}
		out = append(out, cp)
	}
	sortBudgetWindowLimits(out)
	return out, nil
}

func (r *MemoryRepository) matchesRollingSpendEventLocked(ev domain.SpendEvent, orgID string, scopeType domain.QuotaScopeType, scopeID string) bool {
	if ev.OrgID != orgID || ev.CostMicros <= 0 {
		return false
	}
	switch scopeType {
	case domain.QuotaScopeOrg:
		return true
	case domain.QuotaScopeTeam:
		return ev.TeamID == scopeID
	case domain.QuotaScopeUser:
		return ev.UserID == scopeID
	case domain.QuotaScopeKey:
		return ev.VirtualKeyID == scopeID
	case domain.QuotaScopeTeamMember:
		return ev.TeamID != "" && ev.UserID != "" && ev.TeamID+":"+ev.UserID == scopeID
	case domain.QuotaScopeProject:
		projID := strings.TrimSpace(ev.ProjectID)
		if projID == "" {
			if vk, ok := r.keysByID[ev.VirtualKeyID]; ok {
				projID = strings.TrimSpace(vk.ProjectID)
			}
		}
		return projID != "" && projID == scopeID
	case domain.QuotaScopeEndUser:
		return ev.EndUserID == scopeID
	case domain.QuotaScopeTag:
		for _, t := range ev.Tags {
			if strings.TrimSpace(t) == scopeID {
				return true
			}
		}
		return false
	case domain.QuotaScopeModelAccessGroup:
		for _, magID := range ev.ModelAccessGroupIDs {
			if strings.TrimSpace(magID) == scopeID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (r *MemoryRepository) rollingWindowSpendLocked(bw *domain.BudgetWindowLimit, cutoff time.Time) int64 {
	if bw == nil {
		return 0
	}
	var sum int64
	for _, ev := range r.spendLogs {
		if !ev.CreatedAt.UTC().After(cutoff) {
			continue
		}
		if r.matchesRollingSpendEventLocked(ev, bw.OrgID, bw.ScopeType, bw.ScopeID) {
			sum += ev.CostMicros
		}
	}
	return sum
}

func (r *MemoryRepository) ListRollingWindowHistory(_ context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, now time.Time) ([]domain.RollingSpendEntry, error) {
	orgID = strings.TrimSpace(orgID)
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if orgID == "" || scopeID == "" || !scopeType.IsValid() {
		return nil, nil
	}
	nowUTC := now.UTC()
	if nowUTC.IsZero() {
		nowUTC = time.Now().UTC()
	}
	cutoff := nowUTC.Add(-24 * time.Hour)

	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []domain.RollingSpendEntry
	for _, ev := range r.spendLogs {
		if !ev.CreatedAt.UTC().After(cutoff) {
			continue
		}
		if r.matchesRollingSpendEventLocked(ev, orgID, scopeType, scopeID) {
			out = append(out, domain.RollingSpendEntry{
				ID:           "db:" + ev.ID,
				TimestampMs:  ev.CreatedAt.UTC().UnixMilli(),
				AmountMicros: ev.CostMicros,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TimestampMs != out[j].TimestampMs {
			return out[i].TimestampMs < out[j].TimestampMs
		}
		return out[i].ID < out[j].ID
	})

	if bwID, ok := r.budgetWindowsByTuple[budgetWindowTupleKey(orgID, scopeType, scopeID, domain.BudgetWindowRolling24h)]; ok {
		if bw := r.budgetWindows[bwID]; bw != nil && bw.RollingHoldMicros > 0 && bw.RollingHoldExpiresAt != nil && bw.RollingHoldExpiresAt.UTC().After(nowUTC) {
			out = append(out, domain.RollingSpendEntry{
				ID:           "hold:" + bw.ID,
				TimestampMs:  bw.RollingHoldExpiresAt.UTC().Add(-24 * time.Hour).UnixMilli(),
				AmountMicros: bw.RollingHoldMicros,
			})
		}
	}
	return out, nil
}

func (r *MemoryRepository) incrementBudgetWindowSpendLocked(orgID string, scopeType domain.QuotaScopeType, scopeID string, deltaMicros int64, now time.Time, includeRollingHold bool) {
	if orgID == "" || scopeID == "" || deltaMicros <= 0 {
		return
	}
	nowUTC := now.UTC()
	for _, bw := range r.budgetWindows {
		if bw.OrgID == orgID && bw.ScopeType == scopeType && bw.ScopeID == scopeID {
			if bw.WindowType == domain.BudgetWindowRolling24h {
				if includeRollingHold {
					if bw.RollingHoldExpiresAt == nil || !nowUTC.Before(bw.RollingHoldExpiresAt.UTC()) {
						bw.RollingHoldMicros = deltaMicros
					} else {
						bw.RollingHoldMicros += deltaMicros
					}
					exp := nowUTC.Add(24 * time.Hour)
					bw.RollingHoldExpiresAt = &exp
					bw.UpdatedAt = nowUTC
				}
				continue
			}
			bw.SpentMicros += deltaMicros
			bw.UpdatedAt = nowUTC
		}
	}
}

func (r *MemoryRepository) IncrementBudgetWindowSpend(_ context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, deltaMicros int64) error {
	orgID = strings.TrimSpace(orgID)
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if orgID == "" || !scopeType.IsValid() || scopeID == "" {
		return fmt.Errorf("org_id, valid scope_type, and scope_id are required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if deltaMicros == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.incrementBudgetWindowSpendLocked(orgID, scopeType, scopeID, deltaMicros, time.Now().UTC(), true)
	return nil
}

func (r *MemoryRepository) ResetExpiredBudgetWindows(ctx context.Context, now time.Time) (int, error) {
	reset, err := r.ResetExpiredBudgetWindowsWithResults(ctx, now)
	return len(reset), err
}

func (r *MemoryRepository) ResetExpiredBudgetWindowsWithResults(_ context.Context, now time.Time) ([]*domain.BudgetWindowLimit, error) {
	nowUTC := now.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	var reset []*domain.BudgetWindowLimit
	for _, bw := range r.budgetWindows {
		if bw.WindowType == domain.BudgetWindowRolling24h {
			continue
		}
		if !nowUTC.Before(bw.WindowResetAt) {
			bw.SpentMicros = 0
			bw.WindowResetAt = advanceBudgetWindowResetAt(bw.WindowType, bw.WindowResetAt, nowUTC)
			bw.UpdatedAt = nowUTC
			reset = append(reset, bw.Clone())
		}
	}
	sortBudgetWindowLimits(reset)
	return reset, nil
}

func (r *MemoryRepository) SetTempBudgetBoost(_ context.Context, scopeType domain.QuotaScopeType, scopeID string, increaseMicros int64, expiresAt *time.Time) error {
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return fmt.Errorf("scope_id is required")
	}
	if increaseMicros < 0 {
		return fmt.Errorf("temp_budget_increase_micros must be non-negative")
	}
	now := time.Now().UTC()
	exp := cloneTimePtr(expiresAt)
	if exp != nil {
		u := exp.UTC()
		exp = &u
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	switch scopeType {
	case domain.QuotaScopeKey:
		vk, ok := r.keysByID[scopeID]
		if !ok {
			return fmt.Errorf("virtual key %q %w", scopeID, ErrNotFound)
		}
		vk.TempBudgetIncreaseMicros = increaseMicros
		vk.TempBudgetExpiresAt = exp
		vk.UpdatedAt = now
	case domain.QuotaScopeTeam:
		t, ok := r.teams[scopeID]
		if !ok {
			return fmt.Errorf("team %q %w", scopeID, ErrNotFound)
		}
		t.TempBudgetIncreaseMicros = increaseMicros
		t.TempBudgetExpiresAt = exp
		t.UpdatedAt = now
	case domain.QuotaScopeUser:
		u, ok := r.users[scopeID]
		if !ok {
			return fmt.Errorf("user %q %w", scopeID, ErrNotFound)
		}
		u.TempBudgetIncreaseMicros = increaseMicros
		u.TempBudgetExpiresAt = exp
		u.UpdatedAt = now
	case domain.QuotaScopeOrg:
		o, ok := r.orgs[scopeID]
		if !ok {
			return fmt.Errorf("organization %q %w", scopeID, ErrNotFound)
		}
		o.TempBudgetIncreaseMicros = increaseMicros
		o.TempBudgetExpiresAt = exp
		o.UpdatedAt = now
	default:
		return fmt.Errorf("unsupported temp budget scope_type %q", scopeType)
	}
	return nil
}

func cloneAccessGroupRule(rule *domain.AccessGroupRule) *domain.AccessGroupRule {
	if rule == nil {
		return nil
	}
	cp := *rule
	if rule.AllowedModels != nil {
		cp.AllowedModels = slices.Clone(rule.AllowedModels)
	} else {
		cp.AllowedModels = []string{}
	}
	return &cp
}

func (r *MemoryRepository) CreateAccessGroupRule(ctx context.Context, rule *domain.AccessGroupRule) error {
	if rule == nil {
		return fmt.Errorf("access group rule is required")
	}
	if strings.TrimSpace(rule.OrgID) == "" ||
		strings.TrimSpace(rule.Name) == "" ||
		strings.TrimSpace(rule.Attribute) == "" ||
		strings.TrimSpace(string(rule.Operator)) == "" ||
		strings.TrimSpace(rule.Value) == "" {
		return fmt.Errorf("org_id, name, attribute, operator, and value are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	if _, exists := r.accessGroupRules[rule.ID]; exists {
		return fmt.Errorf("access group rule %q already exists: %w", rule.ID, ErrConflict)
	}
	now := time.Now().UTC()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	if rule.UpdatedAt.IsZero() {
		rule.UpdatedAt = rule.CreatedAt
	}
	if rule.AllowedModels == nil {
		rule.AllowedModels = []string{}
	}
	r.accessGroupRules[rule.ID] = cloneAccessGroupRule(rule)
	return nil
}

func (r *MemoryRepository) GetAccessGroupRule(ctx context.Context, id string) (*domain.AccessGroupRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.accessGroupRules[id]
	if !ok {
		return nil, fmt.Errorf("access group rule %q %w", id, ErrNotFound)
	}
	return cloneAccessGroupRule(rule), nil
}

func (r *MemoryRepository) ListAccessGroupRules(ctx context.Context, orgID string, activeOnly bool) ([]*domain.AccessGroupRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.AccessGroupRule
	for _, rule := range r.accessGroupRules {
		if orgID != "" && rule.OrgID != orgID {
			continue
		}
		if activeOnly && !rule.IsActive {
			continue
		}
		out = append(out, cloneAccessGroupRule(rule))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (r *MemoryRepository) DeleteAccessGroupRule(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.accessGroupRules[id]; !ok {
		return fmt.Errorf("access group rule %q %w", id, ErrNotFound)
	}
	delete(r.accessGroupRules, id)
	return nil
}

func cloneVirtualKey(vk *domain.VirtualKey) *domain.VirtualKey {
	if vk == nil {
		return nil
	}
	cp := *vk
	cp.RawKey = ""
	cp.BudgetFallbacks = domain.CloneBudgetFallbacks(vk.BudgetFallbacks)
	cp.AllowedModels = slices.Clone(vk.AllowedModels)
	cp.AllowedEndpoints = slices.Clone(vk.AllowedEndpoints)
	cp.AllowedMCPServers = slices.Clone(vk.AllowedMCPServers)
	cp.AllowedA2AAgents = slices.Clone(vk.AllowedA2AAgents)
	cp.AllowedClientApps = slices.Clone(vk.AllowedClientApps)
	cp.AllowedRoutingTags = slices.Clone(vk.AllowedRoutingTags)
	cp.Tags = slices.Clone(vk.Tags)
	cp.ExpiryAlertSentDays = slices.Clone(vk.ExpiryAlertSentDays)
	cp.BudgetResetAt = cloneTimePtr(vk.BudgetResetAt)
	cp.TempBudgetExpiresAt = cloneTimePtr(vk.TempBudgetExpiresAt)
	cp.KeyRotationAt = cloneTimePtr(vk.KeyRotationAt)
	cp.StagedCreatedAt = cloneTimePtr(vk.StagedCreatedAt)
	cp.LastRotatedAt = cloneTimePtr(vk.LastRotatedAt)
	cp.ExpiresAt = cloneTimePtr(vk.ExpiresAt)
	cp.RevokedAt = cloneTimePtr(vk.RevokedAt)
	if len(vk.Metadata) > 0 {
		cp.Metadata = make(map[string]string, len(vk.Metadata))
		for k, v := range vk.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

func (r *MemoryRepository) CreateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if vk.ID == "" {
		vk.ID = uuid.NewString()
	}
	if vk.KeyType == "" {
		vk.KeyType = domain.KeyTypeDefault
	}
	now := time.Now().UTC()
	vk.BudgetResetPeriod, vk.BudgetResetAt = resolveBudgetResetSchedule(vk.BudgetResetPeriod, vk.BudgetResetAt, now)
	vk.CreatedAt = now
	vk.UpdatedAt = now
	cp := cloneVirtualKey(vk)
	r.keysByID[cp.ID] = cp
	r.keysByHash[cp.KeyHash] = cp
	return nil
}

func (r *MemoryRepository) UpdateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if vk == nil || vk.ID == "" {
		return fmt.Errorf("virtual key id is required")
	}
	existing, ok := r.keysByID[vk.ID]
	if !ok {
		return fmt.Errorf("virtual key %q %w", vk.ID, ErrNotFound)
	}
	now := time.Now().UTC()
	if vk.OrgID == "" {
		vk.OrgID = existing.OrgID
	}
	if vk.KeyHash == "" {
		vk.KeyHash = existing.KeyHash
	}
	if vk.KeyPrefix == "" {
		vk.KeyPrefix = existing.KeyPrefix
	}
	if vk.KeyType == "" {
		if existing.KeyType != "" {
			vk.KeyType = existing.KeyType
		} else {
			vk.KeyType = domain.KeyTypeDefault
		}
	}
	if vk.CreatedAt.IsZero() {
		vk.CreatedAt = existing.CreatedAt
	}
	if existing.KeyHash != "" && existing.KeyHash != vk.KeyHash {
		delete(r.keysByHash, existing.KeyHash)
	}
	vk.BudgetResetPeriod, vk.BudgetResetAt = resolveBudgetResetSchedule(vk.BudgetResetPeriod, vk.BudgetResetAt, now)
	vk.UpdatedAt = now
	cp := cloneVirtualKey(vk)
	r.keysByID[cp.ID] = cp
	r.keysByHash[cp.KeyHash] = cp
	return nil
}

func (r *MemoryRepository) GetVirtualKeyByHash(ctx context.Context, keyHash string) (*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vk, ok := r.keysByHash[keyHash]
	if !ok {
		return nil, fmt.Errorf("virtual key not found")
	}
	return cloneVirtualKey(vk), nil
}

func (r *MemoryRepository) GetVirtualKeyByID(ctx context.Context, id string) (*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vk, ok := r.keysByID[id]
	if !ok {
		return nil, fmt.Errorf("virtual key %q not found", id)
	}
	return cloneVirtualKey(vk), nil
}

func (r *MemoryRepository) ListVirtualKeys(ctx context.Context, orgID string) ([]*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if orgID == "" || vk.OrgID == orgID {
			out = append(out, cloneVirtualKey(vk))
		}
	}
	return out, nil
}

func (r *MemoryRepository) ListVirtualKeysByUserID(ctx context.Context, orgID, userID string) ([]*domain.VirtualKey, error) {
	orgID = strings.TrimSpace(orgID)
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if (orgID == "" || vk.OrgID == orgID) && vk.UserID == userID {
			out = append(out, cloneVirtualKey(vk))
		}
	}
	return out, nil
}

func (r *MemoryRepository) RevokeVirtualKey(ctx context.Context, id string) error {
	return r.RevokeVirtualKeyWithActor(ctx, id, "")
}

func (r *MemoryRepository) RevokeVirtualKeyWithActor(_ context.Context, id, revokedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[id]
	if !ok {
		return fmt.Errorf("virtual key %q %w", id, ErrNotFound)
	}
	now := time.Now().UTC()
	vk.IsActive = false
	vk.RevokedAt = &now
	vk.RevokedBy = strings.TrimSpace(revokedBy)
	vk.UpdatedAt = now
	return nil
}

func (r *MemoryRepository) UnblockVirtualKey(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[id]
	if !ok {
		return fmt.Errorf("virtual key %q %w", id, ErrNotFound)
	}
	vk.IsActive = true
	vk.RevokedAt = nil
	vk.RevokedBy = ""
	vk.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) GetVirtualKeyAuthBundleByHash(_ context.Context, keyHash string, now time.Time) (*VirtualKeyAuthBundle, error) {
	keyHash = strings.TrimSpace(keyHash)
	if keyHash == "" {
		return nil, fmt.Errorf("virtual key %w", ErrNotFound)
	}
	nowUTC := now.UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()

	var (
		vk         *domain.VirtualKey
		deprecated bool
		revokeAt   time.Time
	)
	if found, ok := r.keysByHash[keyHash]; ok && found != nil {
		vk = found
	} else if entry, ok := r.deprecatedKeyHashes[keyHash]; ok && entry != nil && nowUTC.Before(entry.revokeAt) {
		if target, exists := r.keysByID[entry.virtualKeyID]; exists && target != nil {
			vk = target
			deprecated = true
			revokeAt = entry.revokeAt
		}
	}
	if vk == nil {
		return nil, fmt.Errorf("virtual key %w", ErrNotFound)
	}

	bundle := &VirtualKeyAuthBundle{
		Key:                   cloneVirtualKey(vk),
		Deprecated:            deprecated,
		DeprecatedKeyRevokeAt: revokeAt,
	}
	if org, ok := r.orgs[vk.OrgID]; ok && org != nil {
		bundle.Org = cloneOrganization(org)
	}
	if vk.TeamID != "" {
		if team, ok := r.teams[vk.TeamID]; ok && team != nil {
			bundle.Team = cloneTeam(team)
		}
	}
	if vk.ProjectID != "" {
		if proj, ok := r.projects[vk.ProjectID]; ok && proj != nil {
			bundle.Project = cloneProject(proj)
		}
	}
	if vk.UserID != "" {
		if user, ok := r.users[vk.UserID]; ok && user != nil {
			bundle.User = cloneUser(user)
		}
		if vk.TeamID != "" {
			if tmID, ok := r.teamMembershipsByTuple[teamMembershipTupleKey(vk.TeamID, vk.UserID)]; ok {
				if tm, exists := r.teamMemberships[tmID]; exists && tm != nil {
					bundle.TeamMembership = cloneTeamMembership(tm)
				}
			}
		}
	}
	return bundle, nil
}

func (r *MemoryRepository) ListVirtualKeysFiltered(_ context.Context, filter VirtualKeyFilter) ([]*domain.VirtualKey, int, error) {
	nowUTC := time.Now().UTC()
	statusFilter := strings.ToLower(strings.TrimSpace(filter.Status))
	search := strings.ToLower(strings.TrimSpace(filter.Search))

	r.mu.RLock()
	defer r.mu.RUnlock()

	matched := make([]*domain.VirtualKey, 0)
	for _, vk := range r.keysByID {
		if vk == nil {
			continue
		}
		if filter.OrgID != "" && vk.OrgID != filter.OrgID {
			continue
		}
		if filter.TeamID != "" && vk.TeamID != filter.TeamID {
			continue
		}
		if filter.UserID != "" && vk.UserID != filter.UserID {
			continue
		}
		if filter.ProjectID != "" && vk.ProjectID != filter.ProjectID {
			continue
		}
		expired := vk.ExpiresAt != nil && !nowUTC.Before(vk.ExpiresAt.UTC())
		switch statusFilter {
		case "active":
			if !vk.IsActive || expired {
				continue
			}
		case "revoked":
			if vk.IsActive {
				continue
			}
		case "expired":
			if !expired {
				continue
			}
		}
		if search != "" {
			if !strings.Contains(strings.ToLower(vk.ID), search) &&
				!strings.Contains(strings.ToLower(vk.KeyPrefix), search) &&
				!strings.Contains(strings.ToLower(vk.Name), search) {
				continue
			}
		}
		matched = append(matched, cloneVirtualKey(vk))
	}
	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].CreatedAt.After(matched[j].CreatedAt)
		}
		return matched[i].ID < matched[j].ID
	})
	total := len(matched)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*domain.VirtualKey{}, total, nil
	}
	end := total
	if filter.Limit > 0 && offset+filter.Limit < end {
		end = offset + filter.Limit
	}
	return matched[offset:end], total, nil
}

func (r *MemoryRepository) BulkUpdateVirtualKeys(_ context.Context, orgID string, ids []string, patch VirtualKeyBulkPatch) ([]*domain.VirtualKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	var updated []*domain.VirtualKey
	for _, id := range ids {
		vk, ok := r.keysByID[id]
		if !ok || vk == nil {
			return nil, fmt.Errorf("virtual key %q %w", id, ErrNotFound)
		}
		if orgID != "" && vk.OrgID != orgID {
			return nil, fmt.Errorf("virtual key %q %w", id, ErrNotFound)
		}
		if patch.IsActive != nil {
			vk.IsActive = *patch.IsActive
			if !vk.IsActive {
				t := now
				vk.RevokedAt = &t
				vk.RevokedBy = strings.TrimSpace(patch.RevokedBy)
				for h, entry := range r.deprecatedKeyHashes {
					if entry != nil && entry.virtualKeyID == vk.ID {
						delete(r.deprecatedKeyHashes, h)
					}
				}
			} else {
				vk.RevokedAt = nil
				vk.RevokedBy = ""
			}
		}
		if patch.MaxBudgetMicros != nil {
			vk.MaxBudgetMicros = *patch.MaxBudgetMicros
		}
		if patch.RPMLimit != nil {
			vk.RPMLimit = *patch.RPMLimit
		}
		if patch.TPMLimit != nil {
			vk.TPMLimit = *patch.TPMLimit
		}
		if patch.AllowedModels != nil {
			vk.AllowedModels = slices.Clone(patch.AllowedModels)
		}
		vk.UpdatedAt = now
		updated = append(updated, cloneVirtualKey(vk))
	}
	return updated, nil
}

func (r *MemoryRepository) ResetEntitySpend(_ context.Context, scope EntitySpendScope, orgID, entityID, secondaryID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	switch scope {
	case EntitySpendScopeKey:
		vk, ok := r.keysByID[entityID]
		if !ok || vk == nil || (orgID != "" && vk.OrgID != orgID) {
			return fmt.Errorf("virtual key %q %w", entityID, ErrNotFound)
		}
		vk.SpentMicros = 0
		vk.UpdatedAt = now
		return nil
	case EntitySpendScopeTeamMember:
		id, ok := r.teamMembershipsByTuple[teamMembershipTupleKey(entityID, secondaryID)]
		if !ok {
			return fmt.Errorf("team membership (%q, %q) %w", entityID, secondaryID, ErrNotFound)
		}
		m, ok := r.teamMemberships[id]
		if !ok || m == nil || (orgID != "" && m.OrgID != orgID) {
			return fmt.Errorf("team membership (%q, %q) %w", entityID, secondaryID, ErrNotFound)
		}
		m.SpentMicros = 0
		m.UpdatedAt = now
		return nil
	default:
		return fmt.Errorf("unsupported spend reset scope %q", scope)
	}
}

func (r *MemoryRepository) SumChildKeyThroughput(_ context.Context, orgID, teamID, excludeKeyID string) (int, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var rpmSum, tpmSum int
	for _, vk := range r.keysByID {
		if vk == nil || !vk.IsActive {
			continue
		}
		if excludeKeyID != "" && vk.ID == excludeKeyID {
			continue
		}
		if orgID != "" && vk.OrgID != orgID {
			continue
		}
		if teamID != "" {
			if vk.TeamID != teamID {
				continue
			}
		}
		rpmSum += vk.RPMLimit
		tpmSum += vk.TPMLimit
	}
	return rpmSum, tpmSum, nil
}

func (r *MemoryRepository) ListVirtualKeysExpiringBefore(_ context.Context, cutoff time.Time, limit int) ([]*domain.VirtualKey, error) {
	cutoffUTC := cutoff.UTC()
	nowUTC := time.Now().UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if vk == nil || !vk.IsActive || vk.ExpiresAt == nil {
			continue
		}
		expUTC := vk.ExpiresAt.UTC()
		if expUTC.After(nowUTC) && !expUTC.After(cutoffUTC) {
			out = append(out, cloneVirtualKey(vk))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ExpiresAt.Before(*out[j].ExpiresAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *MemoryRepository) MarkVirtualKeyExpiryAlertSent(_ context.Context, keyID string, alertDay int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[keyID]
	if !ok || vk == nil {
		return fmt.Errorf("virtual key %q %w", keyID, ErrNotFound)
	}
	if !slices.Contains(vk.ExpiryAlertSentDays, alertDay) {
		vk.ExpiryAlertSentDays = append(vk.ExpiryAlertSentDays, alertDay)
	}
	return nil
}

func (r *MemoryRepository) MarkVirtualKeyRotated(_ context.Context, keyID string, rotatedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[keyID]
	if !ok || vk == nil {
		return fmt.Errorf("virtual key %q %w", keyID, ErrNotFound)
	}
	ts := rotatedAt.UTC()
	vk.LastRotatedAt = &ts
	vk.RotationCount++
	vk.UpdatedAt = ts
	return nil
}

func (r *MemoryRepository) AddDeprecatedVirtualKeyHash(ctx context.Context, keyHash, virtualKeyID string, revokeAt time.Time) error {
	keyHash = strings.TrimSpace(keyHash)
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if keyHash == "" || virtualKeyID == "" {
		return fmt.Errorf("key_hash and virtual_key_id are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.keysByID[virtualKeyID]; !ok {
		return fmt.Errorf("virtual key %q %w", virtualKeyID, ErrNotFound)
	}
	if r.deprecatedKeyHashes == nil {
		r.deprecatedKeyHashes = make(map[string]*deprecatedKeyHashEntry)
	}
	r.deprecatedKeyHashes[keyHash] = &deprecatedKeyHashEntry{
		keyHash:      keyHash,
		virtualKeyID: virtualKeyID,
		revokeAt:     revokeAt.UTC(),
		createdAt:    time.Now().UTC(),
	}
	return nil
}

func (r *MemoryRepository) GetActiveDeprecatedVirtualKey(ctx context.Context, keyHash string, now time.Time) (*domain.VirtualKey, time.Time, error) {
	keyHash = strings.TrimSpace(keyHash)
	if keyHash == "" {
		return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
	}
	nowUTC := now.UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.deprecatedKeyHashes[keyHash]
	if !ok || entry == nil || !nowUTC.Before(entry.revokeAt) {
		return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
	}
	vk, ok := r.keysByID[entry.virtualKeyID]
	if !ok || vk == nil {
		return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
	}
	return cloneVirtualKey(vk), entry.revokeAt, nil
}

func (r *MemoryRepository) DeleteExpiredDeprecatedVirtualKeyHashes(ctx context.Context, now time.Time) (int64, error) {
	nowUTC := now.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	var deleted int64
	for h, entry := range r.deprecatedKeyHashes {
		if entry == nil || !nowUTC.Before(entry.revokeAt) {
			delete(r.deprecatedKeyHashes, h)
			deleted++
		}
	}
	return deleted, nil
}

func (r *MemoryRepository) ListDeprecatedVirtualKeyHashesByKeyID(_ context.Context, virtualKeyID string) ([]string, error) {
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if virtualKeyID == "" {
		return nil, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var hashes []string
	for h, entry := range r.deprecatedKeyHashes {
		if entry != nil && entry.virtualKeyID == virtualKeyID {
			hashes = append(hashes, h)
		}
	}
	sort.Strings(hashes)
	return hashes, nil
}

func (r *MemoryRepository) DeleteDeprecatedVirtualKeyHashesByKeyID(ctx context.Context, virtualKeyID string) ([]string, error) {
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if virtualKeyID == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var hashes []string
	for h, entry := range r.deprecatedKeyHashes {
		if entry != nil && entry.virtualKeyID == virtualKeyID {
			hashes = append(hashes, h)
			delete(r.deprecatedKeyHashes, h)
		}
	}
	sort.Strings(hashes)
	return hashes, nil
}

func (r *MemoryRepository) ListVirtualKeysDueForRotation(ctx context.Context, now time.Time, limit int) ([]*domain.VirtualKey, error) {
	nowUTC := now.UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var due []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if vk == nil || !vk.IsActive {
			continue
		}
		if vk.ExpiresAt != nil && !nowUTC.Before(*vk.ExpiresAt) {
			continue
		}
		if vk.RotationIntervalSec <= 0 || vk.KeyRotationAt == nil {
			continue
		}
		if !vk.KeyRotationAt.UTC().After(nowUTC) {
			due = append(due, cloneVirtualKey(vk))
		}
	}
	sort.Slice(due, func(i, j int) bool {
		ti, tj := due[i].KeyRotationAt.UTC(), due[j].KeyRotationAt.UTC()
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return due[i].ID < due[j].ID
	})
	if limit > 0 && len(due) > limit {
		due = due[:limit]
	}
	return due, nil
}

func (r *MemoryRepository) CreateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cred.ID == "" {
		cred.ID = uuid.NewString()
	}
	if cred.KeyVersion <= 0 {
		cred.KeyVersion = 1
	}
	now := time.Now().UTC()
	cred.CreatedAt = now
	cred.UpdatedAt = now
	cp := *cred
	cp.DecryptedAPIKey = "" // Never store plaintext key in repository
	r.credentials[cp.ID] = &cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) UpdateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cred == nil || cred.ID == "" {
		return fmt.Errorf("credential id is required")
	}
	if _, ok := r.credentials[cred.ID]; !ok {
		return fmt.Errorf("provider credential %q not found", cred.ID)
	}
	cred.UpdatedAt = time.Now().UTC()
	cp := *cred
	cp.DecryptedAPIKey = ""
	r.credentials[cp.ID] = &cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetProviderCredential(ctx context.Context, id string) (*domain.ProviderCredential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.credentials[id]
	if !ok {
		return nil, fmt.Errorf("provider credential %q not found", id)
	}
	cp := *c
	return &cp, nil
}

func (r *MemoryRepository) ListProviderCredentials(ctx context.Context, orgID string) ([]*domain.ProviderCredential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.ProviderCredential
	for _, c := range r.credentials {
		if orgID == "" || c.OrgID == orgID {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func cloneFallbackTargets(src []domain.FallbackTarget) []domain.FallbackTarget {
	if src == nil {
		return nil
	}
	out := make([]domain.FallbackTarget, len(src))
	for i, ft := range src {
		out[i] = ft
		if ft.Overrides != nil {
			out[i].Overrides = maps.Clone(ft.Overrides)
		}
	}
	return out
}

func cloneModelGroup(mg *domain.ModelGroup) *domain.ModelGroup {
	if mg == nil {
		return nil
	}
	cp := *mg
	if mg.FallbackGroupIDs != nil {
		cp.FallbackGroupIDs = slices.Clone(mg.FallbackGroupIDs)
	}
	cp.ContextWindowFallbacks = cloneFallbackTargets(mg.ContextWindowFallbacks)
	cp.ContentPolicyFallbacks = cloneFallbackTargets(mg.ContentPolicyFallbacks)
	cp.FallbackTargets = cloneFallbackTargets(mg.FallbackTargets)
	cp.SaturationFallbacks = cloneFallbackTargets(mg.SaturationFallbacks)
	if mg.RetryPolicy != nil {
		rp := *mg.RetryPolicy
		cp.RetryPolicy = &rp
	}
	if mg.CooldownPolicy != nil {
		cd := *mg.CooldownPolicy
		if mg.CooldownPolicy.AllowedFails != nil {
			cd.AllowedFails = maps.Clone(mg.CooldownPolicy.AllowedFails)
		}
		cp.CooldownPolicy = &cd
	}
	return &cp
}

func cloneDeployment(d *domain.Deployment) *domain.Deployment {
	if d == nil {
		return nil
	}
	cp := *d
	if d.Tags != nil {
		cp.Tags = slices.Clone(d.Tags)
	}
	return &cp
}

func (r *MemoryRepository) CreateModelGroup(ctx context.Context, mg *domain.ModelGroup) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mg.ID == "" {
		mg.ID = uuid.NewString()
	}
	if mg.RoutingStrategy == "" {
		mg.RoutingStrategy = domain.StrategyWeightedShuffle
	}
	now := time.Now().UTC()
	mg.CreatedAt = now
	mg.UpdatedAt = now
	cp := cloneModelGroup(mg)
	r.groupsByID[cp.ID] = cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetModelGroupByAlias(ctx context.Context, orgID, alias string) (*domain.ModelGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, mg := range r.groupsByID {
		if mg.OrgID == orgID && mg.Alias == alias && mg.IsActive {
			return cloneModelGroup(mg), nil
		}
	}
	return nil, fmt.Errorf("model group %q not found for org %q", alias, orgID)
}

func (r *MemoryRepository) GetModelGroupByID(ctx context.Context, id string) (*domain.ModelGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mg, ok := r.groupsByID[id]
	if !ok {
		return nil, fmt.Errorf("model group %q not found", id)
	}
	return cloneModelGroup(mg), nil
}

func (r *MemoryRepository) ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.ModelGroup
	for _, mg := range r.groupsByID {
		if orgID == "" || mg.OrgID == orgID {
			out = append(out, cloneModelGroup(mg))
		}
	}
	return out, nil
}

func (r *MemoryRepository) UpdateModelGroup(ctx context.Context, mg *domain.ModelGroup) error {
	if mg == nil || strings.TrimSpace(mg.ID) == "" {
		return fmt.Errorf("model group id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.groupsByID[mg.ID]
	if !ok {
		return fmt.Errorf("model group %q %w", mg.ID, ErrNotFound)
	}
	if mg.OrgID == "" {
		mg.OrgID = existing.OrgID
	}
	for id, other := range r.groupsByID {
		if id != mg.ID && other.OrgID == mg.OrgID && other.Alias == mg.Alias {
			return fmt.Errorf("model group alias %q already exists in organization: %w", mg.Alias, ErrConflict)
		}
	}
	if mg.RoutingStrategy == "" {
		mg.RoutingStrategy = domain.StrategyWeightedShuffle
	}
	if mg.CreatedAt.IsZero() {
		mg.CreatedAt = existing.CreatedAt
	}
	mg.UpdatedAt = time.Now().UTC()
	r.groupsByID[mg.ID] = cloneModelGroup(mg)
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) DeleteModelGroup(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.groupsByID[id]; !ok {
		return fmt.Errorf("model group %q %w", id, ErrNotFound)
	}
	delete(r.groupsByID, id)
	for depID, dep := range r.deployments {
		if dep != nil && dep.ModelGroupID == id {
			delete(r.deployments, depID)
		}
	}
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) CreateDeployment(ctx context.Context, dep *domain.Deployment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if dep.ID == "" {
		dep.ID = uuid.NewString()
	}
	if dep.Status == "" {
		dep.Status = domain.DeploymentStatusActive
	}
	if dep.Weight <= 0 {
		dep.Weight = 100
	}
	now := time.Now().UTC()
	dep.CreatedAt = now
	dep.UpdatedAt = now
	cp := cloneDeployment(dep)
	r.deployments[cp.ID] = cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetDeployment(ctx context.Context, id string) (*domain.Deployment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.deployments[id]
	if !ok {
		return nil, fmt.Errorf("deployment %q %w", id, ErrNotFound)
	}
	cp := cloneDeployment(d)
	if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
		cp.GlobalModel = cloneGlobalModel(gm)
	}
	if cred, ok := r.credentials[cp.CredentialID]; ok {
		credCopy := *cred
		cp.Credential = &credCopy
	}
	return cp, nil
}

func (r *MemoryRepository) UpdateDeployment(ctx context.Context, dep *domain.Deployment) error {
	if dep == nil || strings.TrimSpace(dep.ID) == "" {
		return fmt.Errorf("deployment id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.deployments[dep.ID]
	if !ok {
		return fmt.Errorf("deployment %q %w", dep.ID, ErrNotFound)
	}
	if dep.ModelGroupID == "" {
		dep.ModelGroupID = existing.ModelGroupID
	}
	if dep.GlobalModelID == "" {
		dep.GlobalModelID = existing.GlobalModelID
	}
	if dep.CredentialID == "" {
		dep.CredentialID = existing.CredentialID
	}
	if dep.Status == "" {
		dep.Status = existing.Status
	}
	if dep.Weight <= 0 {
		dep.Weight = 100
	}
	if dep.CreatedAt.IsZero() {
		dep.CreatedAt = existing.CreatedAt
	}
	dep.UpdatedAt = time.Now().UTC()
	cp := cloneDeployment(dep)
	if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
		cp.GlobalModel = cloneGlobalModel(gm)
		dep.GlobalModel = cloneGlobalModel(gm)
	}
	if cred, ok := r.credentials[cp.CredentialID]; ok {
		credCopy := *cred
		cp.Credential = &credCopy
		credCopy2 := *cred
		dep.Credential = &credCopy2
	}
	r.deployments[dep.ID] = cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) DeleteDeployment(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.deployments[id]; !ok {
		return fmt.Errorf("deployment %q %w", id, ErrNotFound)
	}
	delete(r.deployments, id)
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) ListDeploymentsByGroup(ctx context.Context, groupID string) ([]*domain.Deployment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Deployment
	for _, d := range r.deployments {
		if d.ModelGroupID == groupID {
			cp := cloneDeployment(d)
			if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
				cp.GlobalModel = cloneGlobalModel(gm)
			}
			if cred, ok := r.credentials[cp.CredentialID]; ok {
				credCopy := *cred
				cp.Credential = &credCopy
			}
			out = append(out, cp)
		}
	}
	return out, nil
}

func (r *MemoryRepository) ListAllDeployments(ctx context.Context) ([]*domain.Deployment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Deployment
	for _, d := range r.deployments {
		cp := cloneDeployment(d)
		if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
			cp.GlobalModel = cloneGlobalModel(gm)
		}
		if cred, ok := r.credentials[cp.CredentialID]; ok {
			credCopy := *cred
			cp.Credential = &credCopy
		}
		out = append(out, cp)
	}
	return out, nil
}

func (r *MemoryRepository) SetGuardrailPolicy(ctx context.Context, pol *domain.GuardrailPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pol == nil || pol.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail policy")
	}
	pol.UpdatedAt = time.Now().UTC()
	cp := *pol
	r.guardrails[pol.OrgID] = &cp
	return nil
}

func (r *MemoryRepository) GetGuardrailPolicy(ctx context.Context, orgID string) (*domain.GuardrailPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pol, ok := r.guardrails[orgID]
	if !ok {
		return nil, nil
	}
	cp := *pol
	return &cp, nil
}

func (r *MemoryRepository) UpdateDeploymentStatus(ctx context.Context, depID string, status domain.DeploymentStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	dep, ok := r.deployments[depID]
	if !ok {
		return fmt.Errorf("deployment %q not found", depID)
	}
	dep.Status = status
	dep.UpdatedAt = time.Now().UTC()
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) EnqueueSpendEvent(ctx context.Context, ev domain.SpendEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	if ev.PricingStatus == "" {
		ev.PricingStatus = domain.PricingStatusUnrecorded
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, delivered := r.spendLogIDs[ev.ID]; !delivered {
		if _, exists := r.spendOutbox[ev.ID]; !exists {
			r.spendOutbox[ev.ID] = &spendOutboxEntry{event: ev, status: "pending", nextAttempt: time.Now().UTC()}
		}
	}
	return nil
}

func (r *MemoryRepository) ClaimSpendEvents(ctx context.Context, limit int, lease time.Duration) ([]domain.SpendEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if lease <= 0 {
		lease = time.Minute
	}
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.spendOutbox))
	for id, e := range r.spendOutbox {
		if e.status == "pending" && !e.nextAttempt.After(now) || e.status == "processing" && e.lockedAt.Add(lease).Before(now) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]domain.SpendEvent, 0, len(ids))
	for _, id := range ids {
		e := r.spendOutbox[id]
		e.status = "processing"
		e.lockedAt = now
		e.attempts++
		ev := e.event
		ev.OutboxAttempt = e.attempts
		out = append(out, ev)
	}
	return out, nil
}

func (r *MemoryRepository) MarkSpendEventDelivered(ctx context.Context, id string) error {
	return r.MarkSpendEventsDelivered(ctx, []string{id})
}

func (r *MemoryRepository) MarkSpendEventsDelivered(ctx context.Context, ids []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		delete(r.spendOutbox, id)
	}
	return nil
}

func (r *MemoryRepository) CountPendingSpendEvents(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var count int64
	for _, e := range r.spendOutbox {
		if e.status == "pending" || e.status == "processing" {
			count++
		}
	}
	return count, nil
}

func (r *MemoryRepository) PruneDeliveredSpendEvents(ctx context.Context, _ time.Time, _ int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	// MemoryRepository deletes delivered events immediately upon acknowledgement.
	return 0, nil
}

func (r *MemoryRepository) RetrySpendEvent(ctx context.Context, id string, cause error, retryAt time.Time, maxAttempts int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.spendOutbox[id]; e != nil {
		if maxAttempts > 0 && e.attempts >= maxAttempts {
			e.status = "dead_letter"
		} else {
			e.status = "pending"
			e.nextAttempt = retryAt
		}
		e.lockedAt = time.Time{}
		if cause != nil {
			e.lastError = cause.Error()
		}
	}
	return nil
}

func (r *MemoryRepository) RecordSpendBatch(ctx context.Context, events []domain.SpendEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range events {
		if ev.ID == "" {
			ev.ID = uuid.NewString()
		}
		if ev.CreatedAt.IsZero() {
			ev.CreatedAt = time.Now().UTC()
		}
		if ev.PricingStatus == "" {
			ev.PricingStatus = domain.PricingStatusUnrecorded
		}
		if _, exists := r.spendLogIDs[ev.ID]; exists {
			continue
		}
		projectID := strings.TrimSpace(ev.ProjectID)
		if vk, ok := r.keysByID[ev.VirtualKeyID]; ok {
			vk.SpentMicros += ev.CostMicros
			if projectID == "" {
				projectID = strings.TrimSpace(vk.ProjectID)
			}
		}
		ev.ProjectID = projectID
		r.spendLogIDs[ev.ID] = struct{}{}
		r.spendLogs = append(r.spendLogs, ev)

		if ev.TeamID != "" {
			if t, ok := r.teams[ev.TeamID]; ok {
				t.SpentMicros += ev.CostMicros
			}
		}
		if ev.UserID != "" {
			if u, ok := r.users[ev.UserID]; ok {
				u.SpentMicros += ev.CostMicros
			}
		}
		if ev.OrgID != "" {
			if o, ok := r.orgs[ev.OrgID]; ok {
				o.SpentMicros += ev.CostMicros
			}
		}
		if projectID != "" {
			if p, ok := r.projects[projectID]; ok {
				p.SpentMicros += ev.CostMicros
				p.UpdatedAt = ev.CreatedAt
			}
		}
		if ev.TeamID != "" && ev.UserID != "" {
			if mID, ok := r.teamMembershipsByTuple[teamMembershipTupleKey(ev.TeamID, ev.UserID)]; ok {
				if m, exists := r.teamMemberships[mID]; exists {
					m.SpentMicros += ev.CostMicros
					m.UpdatedAt = ev.CreatedAt
				}
			}
		}
		seenPolicies := make(map[string]struct{}, len(ev.MatchedQuotaPolicyIDs))
		for _, qpID := range ev.MatchedQuotaPolicyIDs {
			qpID = strings.TrimSpace(qpID)
			if qpID == "" {
				continue
			}
			if _, dup := seenPolicies[qpID]; dup {
				continue
			}
			seenPolicies[qpID] = struct{}{}
			if qp, ok := r.quotaPolicies[qpID]; ok {
				qp.SpentMicros += ev.CostMicros
				qp.UpdatedAt = ev.CreatedAt
			}
		}
		if ev.CostMicros > 0 && ev.OrgID != "" {
			r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeOrg, ev.OrgID, ev.CostMicros, ev.CreatedAt, false)
			if ev.TeamID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeTeam, ev.TeamID, ev.CostMicros, ev.CreatedAt, false)
			}
			if ev.UserID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeUser, ev.UserID, ev.CostMicros, ev.CreatedAt, false)
			}
			if ev.VirtualKeyID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeKey, ev.VirtualKeyID, ev.CostMicros, ev.CreatedAt, false)
			}
			if projectID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeProject, projectID, ev.CostMicros, ev.CreatedAt, false)
			}
			if ev.TeamID != "" && ev.UserID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeTeamMember, ev.TeamID+":"+ev.UserID, ev.CostMicros, ev.CreatedAt, false)
			}
			if ev.EndUserID != "" {
				if euID, ok := r.endUsersByTuple[endUserTupleKey(ev.OrgID, ev.EndUserID)]; ok {
					if eu, exists := r.endUsers[euID]; exists {
						eu.SpentMicros += ev.CostMicros
						eu.UpdatedAt = ev.CreatedAt
					}
				}
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeEndUser, ev.EndUserID, ev.CostMicros, ev.CreatedAt, false)
			}
			for _, tagName := range ev.Tags {
				tagName = strings.TrimSpace(tagName)
				if tagName == "" {
					continue
				}
				if tID, ok := r.tagsByTuple[tagTupleKey(ev.OrgID, tagName)]; ok {
					if t, exists := r.tags[tID]; exists {
						t.SpentMicros += ev.CostMicros
						t.UpdatedAt = ev.CreatedAt
					}
				}
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeTag, tagName, ev.CostMicros, ev.CreatedAt, false)
			}
			seenMAGs := make(map[string]struct{}, len(ev.ModelAccessGroupIDs))
			for _, magID := range ev.ModelAccessGroupIDs {
				magID = strings.TrimSpace(magID)
				if magID == "" {
					continue
				}
				if _, dup := seenMAGs[magID]; dup {
					continue
				}
				seenMAGs[magID] = struct{}{}
				if g, exists := r.modelAccessGroups[magID]; exists && g.OrgID == ev.OrgID {
					g.SpentMicros += ev.CostMicros
					g.UpdatedAt = ev.CreatedAt
				}
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeModelAccessGroup, magID, ev.CostMicros, ev.CreatedAt, false)
			}
		}
	}
	return nil
}

func (r *MemoryRepository) GetSpendSummary(ctx context.Context, orgID string) (*SpendSummary, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	for _, ev := range r.spendLogs {
		if orgID != "" && ev.OrgID != orgID {
			continue
		}
		sum.TotalRequests++
		sum.TotalTokens += int64(ev.Usage.TotalTokens)
		sum.TotalCostMicros += ev.CostMicros
		if ev.PricingStatus == domain.PricingStatusUnknown || ev.PricingStatus == domain.PricingStatusUnrecorded {
			sum.UnpricedRequests++
			sum.UnpricedTokens += int64(ev.Usage.TotalTokens)
		}
		sum.SpendByProvider[string(ev.Provider)] += ev.CostMicros
		sum.SpendByModel[ev.ResolvedModel] += ev.CostMicros
		if ev.TeamID != "" {
			sum.SpendByTeam[ev.TeamID] += ev.CostMicros
		}
		if ev.UserID != "" {
			sum.SpendByUser[ev.UserID] += ev.CostMicros
		}
		if ev.VirtualKeyID != "" {
			sum.SpendByVirtualKey[ev.VirtualKeyID] += ev.CostMicros
		}
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0
	return sum, nil
}

func (r *MemoryRepository) ListSpendLogs(ctx context.Context, orgID string, limit int) ([]domain.SpendEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	var out []domain.SpendEvent
	for i := len(r.spendLogs) - 1; i >= 0 && len(out) < limit; i-- {
		ev := r.spendLogs[i]
		if orgID == "" || ev.OrgID == orgID {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (r *MemoryRepository) GetTeamSpendSummary(ctx context.Context, orgID, teamID string) (*SpendSummary, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	for _, ev := range r.spendLogs {
		if orgID != "" && ev.OrgID != orgID {
			continue
		}
		if ev.TeamID != teamID {
			continue
		}
		sum.TotalRequests++
		sum.TotalTokens += int64(ev.Usage.TotalTokens)
		sum.TotalCostMicros += ev.CostMicros
		if ev.PricingStatus == domain.PricingStatusUnknown || ev.PricingStatus == domain.PricingStatusUnrecorded {
			sum.UnpricedRequests++
			sum.UnpricedTokens += int64(ev.Usage.TotalTokens)
		}
		sum.SpendByProvider[string(ev.Provider)] += ev.CostMicros
		sum.SpendByModel[ev.ResolvedModel] += ev.CostMicros
		if ev.TeamID != "" {
			sum.SpendByTeam[ev.TeamID] += ev.CostMicros
		}
		if ev.UserID != "" {
			sum.SpendByUser[ev.UserID] += ev.CostMicros
		}
		if ev.VirtualKeyID != "" {
			sum.SpendByVirtualKey[ev.VirtualKeyID] += ev.CostMicros
		}
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0
	return sum, nil
}

func (r *MemoryRepository) ListTeamSpendLogs(ctx context.Context, orgID, teamID string, limit int) ([]domain.SpendEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	out := make([]domain.SpendEvent, 0)
	for i := len(r.spendLogs) - 1; i >= 0 && len(out) < limit; i-- {
		ev := r.spendLogs[i]
		if (orgID == "" || ev.OrgID == orgID) && ev.TeamID == teamID {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (r *MemoryRepository) ResetExpiredBudgets(ctx context.Context, now time.Time) (int, error) {
	res, err := r.ResetExpiredBudgetsWithIDs(ctx, now)
	return res.Total(), err
}

func (r *MemoryRepository) ResetExpiredBudgetsWithIDs(ctx context.Context, now time.Time) (BudgetResetResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var res BudgetResetResult

	for _, o := range r.orgs {
		if o.BudgetResetAt != nil && !now.Before(*o.BudgetResetAt) &&
			(o.BudgetResetPeriod == domain.BudgetResetDaily || o.BudgetResetPeriod == domain.BudgetResetMonthly) {
			o.SpentMicros = 0
			o.BudgetResetAt = advanceBudgetResetAt(o.BudgetResetPeriod, o.BudgetResetAt)
			res.OrgIDs = append(res.OrgIDs, o.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "org", EntityID: o.ID, OrgID: o.ID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	for _, t := range r.teams {
		if t.BudgetResetAt != nil && !now.Before(*t.BudgetResetAt) &&
			(t.BudgetResetPeriod == domain.BudgetResetDaily || t.BudgetResetPeriod == domain.BudgetResetMonthly) {
			t.SpentMicros = 0
			t.BudgetResetAt = advanceBudgetResetAt(t.BudgetResetPeriod, t.BudgetResetAt)
			res.TeamIDs = append(res.TeamIDs, t.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "team", EntityID: t.ID, OrgID: t.OrgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	for _, u := range r.users {
		if u.BudgetResetAt != nil && !now.Before(*u.BudgetResetAt) &&
			(u.BudgetResetPeriod == domain.BudgetResetDaily || u.BudgetResetPeriod == domain.BudgetResetMonthly) {
			u.SpentMicros = 0
			u.BudgetResetAt = advanceBudgetResetAt(u.BudgetResetPeriod, u.BudgetResetAt)
			res.UserIDs = append(res.UserIDs, u.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "user", EntityID: u.ID, OrgID: u.OrgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	for _, vk := range r.keysByID {
		if vk.BudgetResetAt != nil && !now.Before(*vk.BudgetResetAt) &&
			(vk.BudgetResetPeriod == domain.BudgetResetDaily || vk.BudgetResetPeriod == domain.BudgetResetMonthly) {
			vk.SpentMicros = 0
			vk.BudgetResetAt = advanceBudgetResetAt(vk.BudgetResetPeriod, vk.BudgetResetAt)
			res.VirtualKeyIDs = append(res.VirtualKeyIDs, vk.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "key", EntityID: vk.ID, OrgID: vk.OrgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	return res, nil
}

func (r *MemoryRepository) ListPendingBudgetResets(ctx context.Context, limit int) ([]BudgetResetEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 250
	}
	out := make([]BudgetResetEvent, 0, min(limit, len(r.budgetResetOutbox)))
	for _, ev := range r.budgetResetOutbox {
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (r *MemoryRepository) MarkBudgetResetsDelivered(ctx context.Context, ids []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		delete(r.budgetResetOutbox, id)
	}
	return nil
}

func (r *MemoryRepository) RecordAuditLog(ctx context.Context, log *domain.AuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if log.ID == "" {
		log.ID = uuid.NewString()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	cp := *log
	cp.Details = cloneAnyMap(log.Details)
	cp.BeforeValue = cloneAnyMap(log.BeforeValue)
	cp.AfterValue = cloneAnyMap(log.AfterValue)
	r.auditLogs = append(r.auditLogs, &cp)
	return nil
}

func (r *MemoryRepository) ListAuditLogs(ctx context.Context, orgID string, limit int) ([]*domain.AuditLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	var out []*domain.AuditLog
	for i := len(r.auditLogs) - 1; i >= 0 && len(out) < limit; i-- {
		l := r.auditLogs[i]
		if orgID == "" || l.OrgID == orgID {
			cp := *l
			cp.Details = cloneAnyMap(l.Details)
			cp.BeforeValue = cloneAnyMap(l.BeforeValue)
			cp.AfterValue = cloneAnyMap(l.AfterValue)
			out = append(out, &cp)
		}
	}
	return out, nil
}

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

// -----------------------------------------------------------------------------
// Guardrail Definitions Registry & Hierarchical Bindings
// -----------------------------------------------------------------------------

func cloneAnyValue(v any) any {
	switch tv := v.(type) {
	case map[string]any:
		return cloneAnyMap(tv)
	case []any:
		return cloneAnySlice(tv)
	case []string:
		return slices.Clone(tv)
	default:
		return v
	}
}

func cloneAnySlice(src []any) []any {
	if src == nil {
		return nil
	}
	dst := make([]any, len(src))
	for i, v := range src {
		dst[i] = cloneAnyValue(v)
	}
	return dst
}

func cloneAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = cloneAnyValue(v)
	}
	return dst
}

func cloneGuardrailDefinition(def *domain.GuardrailDefinition) *domain.GuardrailDefinition {
	if def == nil {
		return nil
	}
	cp := *def
	if def.EventHooks != nil {
		cp.EventHooks = slices.Clone(def.EventHooks)
	}
	if def.StreamScopeByHook != nil {
		cp.StreamScopeByHook = make(domain.StreamScopeByHook, len(def.StreamScopeByHook))
		for k, v := range def.StreamScopeByHook {
			cp.StreamScopeByHook[k] = v
		}
	}
	if def.ModeRule != nil {
		mr := &domain.GuardrailModeRule{}
		if def.ModeRule.Default != nil {
			mr.Default = slices.Clone(def.ModeRule.Default)
		}
		if def.ModeRule.Tags != nil {
			mr.Tags = make(map[string][]domain.GuardrailHook, len(def.ModeRule.Tags))
			for tag, hooks := range def.ModeRule.Tags {
				mr.Tags[tag] = slices.Clone(hooks)
			}
		}
		cp.ModeRule = mr
	}
	if def.EnabledRoles != nil {
		cp.EnabledRoles = slices.Clone(def.EnabledRoles)
	}
	cp.Config = cloneAnyMap(def.Config)
	cp.GuardrailInfo = cloneAnyMap(def.GuardrailInfo)
	return &cp
}

func cloneGuardrailBinding(b *domain.GuardrailBinding) *domain.GuardrailBinding {
	if b == nil {
		return nil
	}
	cp := *b
	cp.ParamOverrides = cloneAnyMap(b.ParamOverrides)
	return &cp
}

func normalizeGuardrailDefinition(def *domain.GuardrailDefinition) error {
	if def == nil {
		return fmt.Errorf("guardrail definition is required")
	}
	if def.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail definition")
	}
	if def.Name == "" {
		return fmt.Errorf("name is required for guardrail definition")
	}
	if def.Provider == "" {
		return fmt.Errorf("provider is required for guardrail definition")
	}
	if def.Status == "" {
		def.Status = domain.GuardrailStatusActive
	} else if !def.Status.IsValid() {
		return fmt.Errorf("invalid guardrail status %q", def.Status)
	}
	if def.StreamScope == "" {
		def.StreamScope = domain.StreamScopeBoth
	} else if !def.StreamScope.IsValid() {
		return fmt.Errorf("invalid stream_scope %q", def.StreamScope)
	}
	for hook, scope := range def.StreamScopeByHook {
		if !hook.IsValid() {
			return fmt.Errorf("invalid guardrail hook %q", hook)
		}
		if scope != "" && !scope.IsValid() {
			return fmt.Errorf("invalid stream_scope %q for hook %q", scope, hook)
		}
	}
	for _, hook := range def.EventHooks {
		if !hook.IsValid() {
			return fmt.Errorf("invalid guardrail hook %q", hook)
		}
	}
	if def.TimeoutMs < 0 {
		def.TimeoutMs = 0
	}
	if def.Weight <= 0 {
		def.Weight = 1
	}
	return nil
}

func sortGuardrailDefinitions(defs []*domain.GuardrailDefinition) {
	sort.Slice(defs, func(i, j int) bool {
		if defs[i].Precedence != defs[j].Precedence {
			return defs[i].Precedence < defs[j].Precedence
		}
		if !defs[i].CreatedAt.Equal(defs[j].CreatedAt) {
			return defs[i].CreatedAt.Before(defs[j].CreatedAt)
		}
		return defs[i].ID < defs[j].ID
	})
}

func sortGuardrailBindings(bindings []*domain.GuardrailBinding) {
	sort.Slice(bindings, func(i, j int) bool {
		if !bindings[i].CreatedAt.Equal(bindings[j].CreatedAt) {
			return bindings[i].CreatedAt.Before(bindings[j].CreatedAt)
		}
		return bindings[i].ID < bindings[j].ID
	})
}

func (r *MemoryRepository) CreateGuardrailDefinition(ctx context.Context, def *domain.GuardrailDefinition) error {
	if err := normalizeGuardrailDefinition(def); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if def.ID == "" {
		def.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if def.CreatedAt.IsZero() {
		def.CreatedAt = now
	}
	if def.UpdatedAt.IsZero() {
		def.UpdatedAt = now
	}
	r.guardrailDefs[def.ID] = cloneGuardrailDefinition(def)
	return nil
}

func (r *MemoryRepository) GetGuardrailDefinition(ctx context.Context, id string) (*domain.GuardrailDefinition, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.guardrailDefs[id]
	if !ok {
		return nil, fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	return cloneGuardrailDefinition(def), nil
}

func (r *MemoryRepository) ListGuardrailDefinitions(ctx context.Context, orgID string, status domain.GuardrailStatus, name string) ([]*domain.GuardrailDefinition, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.GuardrailDefinition
	for _, def := range r.guardrailDefs {
		if orgID != "" && def.OrgID != orgID {
			continue
		}
		if status != "" && def.Status != status {
			continue
		}
		if name != "" && def.Name != name {
			continue
		}
		out = append(out, cloneGuardrailDefinition(def))
	}
	sortGuardrailDefinitions(out)
	return out, nil
}

func (r *MemoryRepository) UpdateGuardrailDefinition(ctx context.Context, def *domain.GuardrailDefinition) error {
	if def == nil || def.ID == "" {
		return fmt.Errorf("guardrail definition id is required")
	}
	if err := normalizeGuardrailDefinition(def); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.guardrailDefs[def.ID]
	if !ok || existing.OrgID != def.OrgID {
		return fmt.Errorf("guardrail definition %q %w", def.ID, ErrNotFound)
	}
	def.CreatedAt = existing.CreatedAt
	def.UpdatedAt = time.Now().UTC()
	cp := cloneGuardrailDefinition(def)
	if cp.EncryptedSecrets == "" && cp.EncryptedDEK == "" {
		cp.EncryptedSecrets = existing.EncryptedSecrets
		cp.EncryptedDEK = existing.EncryptedDEK
	}
	r.guardrailDefs[def.ID] = cp
	if def.Name != existing.Name {
		for _, b := range r.guardrailBindings {
			if b.GuardrailID == def.ID {
				b.GuardrailName = def.Name
			}
		}
	}
	return nil
}

func (r *MemoryRepository) DeleteGuardrailDefinition(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.guardrailDefs[id]; !ok {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	delete(r.guardrailDefs, id)
	for bid, b := range r.guardrailBindings {
		if b.GuardrailID == id {
			delete(r.guardrailBindings, bid)
		}
	}
	return nil
}

func (r *MemoryRepository) CreateGuardrailBinding(ctx context.Context, binding *domain.GuardrailBinding) error {
	if binding == nil {
		return fmt.Errorf("guardrail binding is required")
	}
	if binding.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail binding")
	}
	if binding.GuardrailID == "" {
		return fmt.Errorf("guardrail_id is required for guardrail binding")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	def, ok := r.guardrailDefs[binding.GuardrailID]
	if !ok || def.OrgID != binding.OrgID {
		return fmt.Errorf("guardrail definition %q %w", binding.GuardrailID, ErrNotFound)
	}
	if binding.GuardrailName == "" {
		binding.GuardrailName = def.Name
	}
	if binding.ID == "" {
		binding.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if binding.CreatedAt.IsZero() {
		binding.CreatedAt = now
	}
	if binding.UpdatedAt.IsZero() {
		binding.UpdatedAt = now
	}
	r.guardrailBindings[binding.ID] = cloneGuardrailBinding(binding)
	return nil
}

func (r *MemoryRepository) GetGuardrailBinding(ctx context.Context, id string) (*domain.GuardrailBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.guardrailBindings[id]
	if !ok {
		return nil, fmt.Errorf("guardrail binding %q %w", id, ErrNotFound)
	}
	return cloneGuardrailBinding(b), nil
}

func matchesGuardrailBindingFilter(b *domain.GuardrailBinding, filter GuardrailBindingFilter) bool {
	if filter.OrgID != "" && b.OrgID != filter.OrgID {
		return false
	}
	if filter.GuardrailID != "" && b.GuardrailID != filter.GuardrailID {
		return false
	}
	if filter.GuardrailName != "" && b.GuardrailName != filter.GuardrailName {
		return false
	}
	if filter.TeamID != "" && b.TeamID != filter.TeamID {
		return false
	}
	if filter.VirtualKeyID != "" && b.VirtualKeyID != filter.VirtualKeyID {
		return false
	}
	if filter.EndUserID != "" && b.EndUserID != filter.EndUserID {
		return false
	}
	if filter.ModelGroupID != "" && b.ModelGroupID != filter.ModelGroupID {
		return false
	}
	if filter.Tag != "" && b.Tag != filter.Tag {
		return false
	}
	return true
}

func (r *MemoryRepository) ListGuardrailBindings(ctx context.Context, filter GuardrailBindingFilter) ([]*domain.GuardrailBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.GuardrailBinding
	for _, b := range r.guardrailBindings {
		if matchesGuardrailBindingFilter(b, filter) {
			out = append(out, cloneGuardrailBinding(b))
		}
	}
	sortGuardrailBindings(out)
	return out, nil
}

func (r *MemoryRepository) UpdateGuardrailBinding(ctx context.Context, binding *domain.GuardrailBinding) error {
	if binding == nil || binding.ID == "" {
		return fmt.Errorf("guardrail binding id is required")
	}
	if binding.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail binding")
	}
	if binding.GuardrailID == "" {
		return fmt.Errorf("guardrail_id is required for guardrail binding")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.guardrailBindings[binding.ID]
	if !ok || existing.OrgID != binding.OrgID {
		return fmt.Errorf("guardrail binding %q %w", binding.ID, ErrNotFound)
	}
	def, ok := r.guardrailDefs[binding.GuardrailID]
	if !ok || def.OrgID != binding.OrgID {
		return fmt.Errorf("guardrail definition %q %w", binding.GuardrailID, ErrNotFound)
	}
	if binding.GuardrailName == "" {
		binding.GuardrailName = def.Name
	}
	binding.CreatedAt = existing.CreatedAt
	binding.UpdatedAt = time.Now().UTC()
	r.guardrailBindings[binding.ID] = cloneGuardrailBinding(binding)
	return nil
}

func (r *MemoryRepository) DeleteGuardrailBinding(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.guardrailBindings[id]; !ok {
		return fmt.Errorf("guardrail binding %q %w", id, ErrNotFound)
	}
	delete(r.guardrailBindings, id)
	return nil
}

func (r *MemoryRepository) ListEffectiveGuardrailsForOrg(ctx context.Context, orgID string) (*EffectiveGuardrails, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	activeIDs := make(map[string]struct{})
	var defs []*domain.GuardrailDefinition
	for _, def := range r.guardrailDefs {
		if def.OrgID == orgID && def.Status == domain.GuardrailStatusActive {
			activeIDs[def.ID] = struct{}{}
			defs = append(defs, cloneGuardrailDefinition(def))
		}
	}
	sortGuardrailDefinitions(defs)

	var bindings []*domain.GuardrailBinding
	for _, b := range r.guardrailBindings {
		if b.OrgID == orgID {
			if _, ok := activeIDs[b.GuardrailID]; ok {
				bindings = append(bindings, cloneGuardrailBinding(b))
			}
		}
	}
	sortGuardrailBindings(bindings)

	return &EffectiveGuardrails{
		Definitions: defs,
		Bindings:    bindings,
	}, nil
}

func (r *MemoryRepository) RotateGuardrailSecrets(ctx context.Context, orgID, id, encryptedSecrets, encryptedDEK string) error {
	if id == "" {
		return fmt.Errorf("guardrail definition id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	def, ok := r.guardrailDefs[id]
	if !ok || (orgID != "" && def.OrgID != orgID) {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	def.EncryptedSecrets = encryptedSecrets
	def.EncryptedDEK = encryptedDEK
	def.UpdatedAt = time.Now().UTC()
	return nil
}

func cloneUserCredential(cred *domain.UserCredential) *domain.UserCredential {
	if cred == nil {
		return nil
	}
	cp := *cred
	if cred.LockedUntil != nil {
		t := *cred.LockedUntil
		cp.LockedUntil = &t
	}
	return &cp
}

func cloneOperatorSession(sess *domain.OperatorSession) *domain.OperatorSession {
	if sess == nil {
		return nil
	}
	cp := *sess
	if sess.RevokedAt != nil {
		t := *sess.RevokedAt
		cp.RevokedAt = &t
	}
	return &cp
}

func (r *MemoryRepository) UpsertUserPassword(ctx context.Context, userID, passwordHash string, resetRequired bool) error {
	userID = strings.TrimSpace(userID)
	passwordHash = strings.TrimSpace(passwordHash)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if passwordHash == "" {
		return fmt.Errorf("password_hash is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.userCredentials[userID] = &domain.UserCredential{
		UserID:                userID,
		PasswordHash:          passwordHash,
		PasswordResetRequired: resetRequired,
		FailedAttempts:        0,
		LockedUntil:           nil,
		UpdatedAt:             time.Now().UTC(),
	}
	return nil
}

func (r *MemoryRepository) GetUserCredential(ctx context.Context, userID string) (*domain.UserCredential, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	cred, ok := r.userCredentials[userID]
	if !ok || cred == nil {
		return nil, fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	return cloneUserCredential(cred), nil
}

func (r *MemoryRepository) UpdateUserLoginFailure(ctx context.Context, userID string, failedAttempts int, lockedUntil *time.Time) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cred, ok := r.userCredentials[userID]
	if !ok || cred == nil {
		return fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	cred.FailedAttempts = failedAttempts
	if lockedUntil != nil {
		t := lockedUntil.UTC()
		cred.LockedUntil = &t
	} else {
		cred.LockedUntil = nil
	}
	cred.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) CreateOperatorSession(ctx context.Context, session *domain.OperatorSession) error {
	if session == nil {
		return fmt.Errorf("operator session is required")
	}
	if strings.TrimSpace(session.UserID) == "" ||
		strings.TrimSpace(session.OrgID) == "" ||
		strings.TrimSpace(session.Role) == "" ||
		strings.TrimSpace(session.CSRFToken) == "" ||
		session.ExpiresAt.IsZero() {
		return fmt.Errorf("user_id, org_id, role, csrf_token, and expires_at are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.TrimSpace(session.ID) == "" {
		session.ID = uuid.NewString()
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now().UTC()
	}
	r.operatorSessions[session.ID] = cloneOperatorSession(session)
	return nil
}

func (r *MemoryRepository) GetOperatorSession(ctx context.Context, id string) (*domain.OperatorSession, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	sess, ok := r.operatorSessions[id]
	if !ok || sess == nil {
		return nil, fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	return cloneOperatorSession(sess), nil
}

func (r *MemoryRepository) RevokeOperatorSession(ctx context.Context, id string, revokedAt time.Time) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("operator session id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	} else {
		revokedAt = revokedAt.UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.operatorSessions[id]
	if !ok || sess == nil {
		return fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	if sess.RevokedAt == nil {
		t := revokedAt
		sess.RevokedAt = &t
	}
	return nil
}

func (r *MemoryRepository) RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	} else {
		revokedAt = revokedAt.UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sess := range r.operatorSessions {
		if sess != nil && sess.UserID == userID && sess.RevokedAt == nil {
			t := revokedAt
			sess.RevokedAt = &t
		}
	}
	return nil
}
