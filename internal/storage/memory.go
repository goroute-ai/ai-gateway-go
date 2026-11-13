package storage

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// MemoryRepository provides a thread-safe, high-performance in-memory implementation of Repository
// seeded with the default Global Model Catalogue, suitable for standalone execution and fast integration testing.
type MemoryRepository struct {
	mu                     sync.RWMutex
	globalModels           map[string]*domain.GlobalModel
	globalModelsByName     map[string]map[domain.ProviderType]map[string]struct{}
	globalModelRevision    uint64
	pricingSummaryRevision uint64
	pricingSummary         GlobalModelPricingSummary
	pricingSummaryValid    bool
	pricingSummaryRebuilds uint64
	orgs                   map[string]*domain.Organization
	orgSubs                map[string]map[domain.ProviderType]*domain.OrgProviderSubscription
	orgPolicies            map[string]map[string]*domain.OrgModelPolicy
	teams                  map[string]*domain.Team
	users                  map[string]*domain.User
	keysByID               map[string]*domain.VirtualKey
	keysByHash             map[string]*domain.VirtualKey
	credentials            map[string]*domain.ProviderCredential
	groupsByID             map[string]*domain.ModelGroup
	deployments            map[string]*domain.Deployment
	pricingHistory         map[string][]*domain.ModelPricingHistory
	guardrails             map[string]*domain.GuardrailPolicy
	spendLogs              []domain.SpendEvent
	spendOutbox            map[string]*spendOutboxEntry
	spendLogIDs            map[string]struct{}
	budgetResetOutbox      map[string]BudgetResetEvent
	auditLogs              []*domain.AuditLog

	mcpServers     map[string]*domain.MCPServer
	mcpTools       map[string]*domain.MCPTool
	mcpToolsets    map[string]*domain.MCPToolset
	mcpUserCreds   map[string]*domain.MCPUserCredential
	a2aAgents      map[string]*domain.A2AAgent
	a2aTasks       map[string]*domain.A2ATask
	a2aTaskEvents  map[string][]*domain.A2ATaskEvent
	a2aStreamPubs  []*domain.A2AStreamPublication
	a2aOutbox      []*domain.A2AOutboxEvent
	a2aPushConfigs map[string]*domain.A2APushNotificationConfig
	files          map[string]*domain.CanonicalFile
	batches        map[string]*domain.CanonicalBatch
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
		globalModels:       make(map[string]*domain.GlobalModel),
		globalModelsByName: make(map[string]map[domain.ProviderType]map[string]struct{}),
		orgs:               make(map[string]*domain.Organization),
		orgSubs:            make(map[string]map[domain.ProviderType]*domain.OrgProviderSubscription),
		orgPolicies:        make(map[string]map[string]*domain.OrgModelPolicy),
		teams:              make(map[string]*domain.Team),
		users:              make(map[string]*domain.User),
		keysByID:           make(map[string]*domain.VirtualKey),
		keysByHash:         make(map[string]*domain.VirtualKey),
		credentials:        make(map[string]*domain.ProviderCredential),
		groupsByID:         make(map[string]*domain.ModelGroup),
		deployments:        make(map[string]*domain.Deployment),
		pricingHistory:     make(map[string][]*domain.ModelPricingHistory),
		guardrails:         make(map[string]*domain.GuardrailPolicy),
		spendOutbox:        make(map[string]*spendOutboxEntry),
		spendLogIDs:        make(map[string]struct{}),
		budgetResetOutbox:  make(map[string]BudgetResetEvent),
		files:              make(map[string]*domain.CanonicalFile),
		batches:            make(map[string]*domain.CanonicalBatch),
		mcpServers:         make(map[string]*domain.MCPServer),
		mcpTools:           make(map[string]*domain.MCPTool),
		mcpToolsets:        make(map[string]*domain.MCPToolset),
		mcpUserCreds:       make(map[string]*domain.MCPUserCredential),
		a2aAgents:          make(map[string]*domain.A2AAgent),
		a2aTasks:           make(map[string]*domain.A2ATask),
		a2aTaskEvents:      make(map[string][]*domain.A2ATaskEvent),
		a2aPushConfigs:     make(map[string]*domain.A2APushNotificationConfig),
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

func (r *MemoryRepository) CreateOrganization(ctx context.Context, org *domain.Organization) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if org.ID == "" {
		org.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	org.CreatedAt = now
	org.UpdatedAt = now
	cp := *org
	r.orgs[cp.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetOrganization(ctx context.Context, id string) (*domain.Organization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	org, ok := r.orgs[id]
	if !ok {
		return nil, fmt.Errorf("organization %q not found", id)
	}
	cp := *org
	return &cp, nil
}

func (r *MemoryRepository) ListOrganizations(ctx context.Context) ([]*domain.Organization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Organization, 0, len(r.orgs))
	for _, o := range r.orgs {
		cp := *o
		out = append(out, &cp)
	}
	return out, nil
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
	cp := *team
	cp.AllowedModels = slices.Clone(team.AllowedModels)
	cp.AllowedMCPServers = slices.Clone(team.AllowedMCPServers)
	cp.AllowedA2AAgents = slices.Clone(team.AllowedA2AAgents)
	cp.AllowedClientApps = slices.Clone(team.AllowedClientApps)
	return &cp
}

func (r *MemoryRepository) CreateTeam(ctx context.Context, team *domain.Team) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if team.ID == "" {
		team.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	team.CreatedAt = now
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

func (r *MemoryRepository) CreateUser(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	user.CreatedAt = now
	user.UpdatedAt = now
	cp := *user
	r.users[cp.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetUserByOIDCSubject(ctx context.Context, subject string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.OIDCSubject != "" && u.OIDCSubject == subject {
			cp := *u
			return &cp, nil
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
			cp := *u
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *MemoryRepository) CreateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if vk.ID == "" {
		vk.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	vk.CreatedAt = now
	vk.UpdatedAt = now
	cp := *vk
	cp.RawKey = "" // Never persist raw key in storage
	r.keysByID[cp.ID] = &cp
	r.keysByHash[cp.KeyHash] = &cp
	return nil
}

func (r *MemoryRepository) GetVirtualKeyByHash(ctx context.Context, keyHash string) (*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vk, ok := r.keysByHash[keyHash]
	if !ok {
		return nil, fmt.Errorf("virtual key not found")
	}
	cp := *vk
	return &cp, nil
}

func (r *MemoryRepository) GetVirtualKeyByID(ctx context.Context, id string) (*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vk, ok := r.keysByID[id]
	if !ok {
		return nil, fmt.Errorf("virtual key %q not found", id)
	}
	cp := *vk
	return &cp, nil
}

func (r *MemoryRepository) ListVirtualKeys(ctx context.Context, orgID string) ([]*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if orgID == "" || vk.OrgID == orgID {
			cp := *vk
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *MemoryRepository) RevokeVirtualKey(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[id]
	if !ok {
		return fmt.Errorf("virtual key %q not found", id)
	}
	vk.IsActive = false
	vk.UpdatedAt = time.Now().UTC()
	return nil
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
	cp := *mg
	r.groupsByID[cp.ID] = &cp
	return nil
}

func (r *MemoryRepository) GetModelGroupByAlias(ctx context.Context, orgID, alias string) (*domain.ModelGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, mg := range r.groupsByID {
		if mg.OrgID == orgID && mg.Alias == alias && mg.IsActive {
			cp := *mg
			return &cp, nil
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
	cp := *mg
	return &cp, nil
}

func (r *MemoryRepository) ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.ModelGroup
	for _, mg := range r.groupsByID {
		if orgID == "" || mg.OrgID == orgID {
			cp := *mg
			out = append(out, &cp)
		}
	}
	return out, nil
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
	cp := *dep
	r.deployments[cp.ID] = &cp
	return nil
}

func (r *MemoryRepository) ListDeploymentsByGroup(ctx context.Context, groupID string) ([]*domain.Deployment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Deployment
	for _, d := range r.deployments {
		if d.ModelGroupID == groupID {
			cp := *d
			if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
				gmCopy := *gm
				cp.GlobalModel = &gmCopy
			}
			if cred, ok := r.credentials[cp.CredentialID]; ok {
				credCopy := *cred
				cp.Credential = &credCopy
			}
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *MemoryRepository) ListAllDeployments(ctx context.Context) ([]*domain.Deployment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Deployment
	for _, d := range r.deployments {
		cp := *d
		if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
			gmCopy := *gm
			cp.GlobalModel = &gmCopy
		}
		if cred, ok := r.credentials[cp.CredentialID]; ok {
			credCopy := *cred
			cp.Credential = &credCopy
		}
		out = append(out, &cp)
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
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.spendOutbox, id)
	return nil
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
		r.spendLogIDs[ev.ID] = struct{}{}
		r.spendLogs = append(r.spendLogs, ev)

		if vk, ok := r.keysByID[ev.VirtualKeyID]; ok {
			vk.SpentMicros += ev.CostMicros
		}
		if ev.TeamID != "" {
			if t, ok := r.teams[ev.TeamID]; ok {
				t.SpentMicros += ev.CostMicros
			}
		}
		if ev.OrgID != "" {
			if o, ok := r.orgs[ev.OrgID]; ok {
				o.SpentMicros += ev.CostMicros
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

func (r *MemoryRepository) ResetExpiredBudgets(ctx context.Context, now time.Time) (int, error) {
	res, err := r.ResetExpiredBudgetsWithIDs(ctx, now)
	return res.Total(), err
}

func (r *MemoryRepository) ResetExpiredBudgetsWithIDs(ctx context.Context, now time.Time) (BudgetResetResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var res BudgetResetResult

	advance := func(period domain.BudgetResetPeriod, from time.Time) time.Time {
		if period == domain.BudgetResetDaily {
			return from.Add(24 * time.Hour)
		}
		return from.AddDate(0, 1, 0)
	}

	for _, o := range r.orgs {
		if o.BudgetResetAt != nil && !now.Before(*o.BudgetResetAt) && o.BudgetResetPeriod != domain.BudgetResetNever {
			o.SpentMicros = 0
			next := advance(o.BudgetResetPeriod, now)
			o.BudgetResetAt = &next
			res.OrgIDs = append(res.OrgIDs, o.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "org", EntityID: o.ID, OrgID: o.ID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	for _, t := range r.teams {
		if t.BudgetResetAt != nil && !now.Before(*t.BudgetResetAt) && t.BudgetResetPeriod != domain.BudgetResetNever {
			t.SpentMicros = 0
			next := advance(t.BudgetResetPeriod, now)
			t.BudgetResetAt = &next
			res.TeamIDs = append(res.TeamIDs, t.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "team", EntityID: t.ID, OrgID: t.OrgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	for _, vk := range r.keysByID {
		if vk.BudgetResetAt != nil && !now.Before(*vk.BudgetResetAt) && vk.BudgetResetPeriod != domain.BudgetResetNever {
			vk.SpentMicros = 0
			next := advance(vk.BudgetResetPeriod, now)
			vk.BudgetResetAt = &next
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
