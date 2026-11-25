package storage

import (
	"context"
	"fmt"
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
	auditObserver                  func(*domain.AuditLog)
	guardrailBindings              map[string]*domain.GuardrailBinding
	spendLogs                      []domain.SpendEvent
	spendOutbox                    map[string]*spendOutboxEntry
	spendLogIDs                    map[string]struct{}
	budgetResetOutbox              map[string]BudgetResetEvent
	auditLogs                      []*domain.AuditLog

	mcpServers        map[string]*domain.MCPServer
	mcpTools          map[string]*domain.MCPTool
	mcpToolsets       map[string]*domain.MCPToolset
	mcpUserCreds      map[string]*domain.MCPUserCredential
	mcpRuntimeSetting *domain.MCPRuntimeSettings
	a2aAgents         map[string]*domain.A2AAgent
	a2aTasks          map[string]*domain.A2ATask
	a2aTaskEvents     map[string][]*domain.A2ATaskEvent
	a2aStreamPubs     []*domain.A2AStreamPublication
	a2aOutbox         []*domain.A2AOutboxEvent
	a2aPushConfigs    map[string]*domain.A2APushNotificationConfig
	files             map[string]*domain.CanonicalFile
	batches           map[string]*domain.CanonicalBatch
	operatorSessions  map[string]*domain.OperatorSession
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

// NewMemoryRepository creates an initialized, thread-safe in-memory Repository
// seeded with the embedded global model catalog.
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
			ID: "groq/llama-3.1-8b-instant", Provider: domain.ProviderGroq, ModelName: "llama-3.1-8b-instant", DisplayName: "Groq Llama 3.1 8B Instant",
			MaxInputTokens: 131072, MaxOutputTokens: 8192, SupportsStreaming: true, SupportsTools: true,
			InputCostMicrosPer1M: 50000, OutputCostMicrosPer1M: 80000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "groq/whisper-large-v3-turbo", Provider: domain.ProviderGroq, ModelName: "whisper-large-v3-turbo", DisplayName: "Groq Whisper Large v3 Turbo",
			MaxInputTokens: 448, MaxOutputTokens: 448,
			Capabilities:                domain.ModelCapabilities{AudioSTT: domain.CapabilitySupported},
			SupportedOperations:         []domain.OperationType{domain.OperationAudioSTT},
			AudioSTTCostMicrosPerSecond: 11,
			LifecycleStatus:             domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "openrouter/openai/gpt-4o-mini", Provider: domain.ProviderOpenRouter, ModelName: "openai/gpt-4o-mini", DisplayName: "OpenRouter OpenAI GPT-4o Mini",
			MaxInputTokens: 128000, MaxOutputTokens: 16384, SupportsStreaming: true, SupportsTools: true, SupportsVision: true,
			InputCostMicrosPer1M: 150000, OutputCostMicrosPer1M: 600000,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "ollama/qwen2.5:0.5b", Provider: domain.ProviderOllama, ModelName: "qwen2.5:0.5b", DisplayName: "Ollama Qwen 2.5 0.5B",
			MaxInputTokens: 32768, MaxOutputTokens: 8192, SupportsStreaming: true, SupportsTools: true,
			Capabilities:         domain.ModelCapabilities{Streaming: domain.CapabilitySupported, Tools: domain.CapabilitySupported, StructuredOutputs: domain.CapabilitySupported},
			SupportedOperations:  []domain.OperationType{domain.OperationChat, domain.OperationCompletion},
			InputCostMicrosPer1M: 0, OutputCostMicrosPer1M: 0,
			LifecycleStatus: domain.ModelStatusActive, DiscoveredAt: now, UpdatedAt: now,
		},
		{
			ID: "ollama/all-minilm:latest", Provider: domain.ProviderOllama, ModelName: "all-minilm:latest", DisplayName: "Ollama All-MiniLM Embeddings",
			MaxInputTokens: 512, MaxOutputTokens: 384, SupportsEmbeddings: true,
			Capabilities:         domain.ModelCapabilities{Embeddings: domain.CapabilitySupported},
			SupportedOperations:  []domain.OperationType{domain.OperationEmbedding},
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
	// Also allow lookup by raw model_name for bare single-segment names.
	// Guard against slash-delimited canonical IDs (e.g. "openai/gpt-4o-mini")
	// matching OpenRouter entries whose ModelName is also "openai/gpt-4o-mini".
	if !strings.Contains(id, "/") {
		for _, m := range r.globalModels {
			if m.ModelName == id {
				return cloneGlobalModel(m), nil
			}
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
