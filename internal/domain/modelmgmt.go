package domain

import "time"

// ModelLifecycleStatus tracks the lifecycle stage of a model in the Global Catalogue.
type ModelLifecycleStatus string

const (
	ModelStatusDiscovered ModelLifecycleStatus = "discovered"
	ModelStatusActive     ModelLifecycleStatus = "active"
	ModelStatusPreview    ModelLifecycleStatus = "preview"
	ModelStatusDeprecated ModelLifecycleStatus = "deprecated"
	ModelStatusRetired    ModelLifecycleStatus = "retired"
)

// RoutingStrategy defines how Stage 2 Load Balancer selects among healthy deployments.
type RoutingStrategy string

const (
	StrategyWeightedShuffle    RoutingStrategy = "weighted-shuffle"
	StrategyLeastBusy          RoutingStrategy = "least-busy"
	StrategyLatencyBased       RoutingStrategy = "latency-based"
	StrategyUsageBasedHeadroom RoutingStrategy = "usage-based-headroom"
	StrategyLowestCost         RoutingStrategy = "lowest-cost"
)

// DeploymentStatus represents the operational health of a model deployment.
type DeploymentStatus string

const (
	DeploymentStatusActive   DeploymentStatus = "active"
	DeploymentStatusCooldown DeploymentStatus = "cooldown"
	DeploymentStatusDisabled DeploymentStatus = "disabled"
)

// GlobalModel represents Layer 1 of Model Management: the Global Model Catalogue.
type GlobalModel struct {
	ID                         string               `json:"id"` // e.g. "openai/gpt-4.1"
	Provider                   ProviderType         `json:"provider"`
	ModelName                  string               `json:"model_name"` // e.g. "gpt-4.1"
	DisplayName                string               `json:"display_name"`
	MaxInputTokens             int                  `json:"max_input_tokens"`
	MaxOutputTokens            int                  `json:"max_output_tokens"`
	SupportsStreaming          bool                 `json:"supports_streaming"`
	SupportsTools              bool                 `json:"supports_tools"`
	SupportsVision             bool                 `json:"supports_vision"`
	SupportsReasoning          bool                 `json:"supports_reasoning"`
	SupportsEmbeddings         bool                 `json:"supports_embeddings"`
	InputCostMicrosPer1M       int64                `json:"input_cost_micros_per_1m"`
	OutputCostMicrosPer1M      int64                `json:"output_cost_micros_per_1m"`
	CachedInputCostMicrosPer1M int64                `json:"cached_input_cost_micros_per_1m"`
	ReasoningCostMicrosPer1M   int64                `json:"reasoning_cost_micros_per_1m"`
	PricingVersion             int                  `json:"pricing_version"`
	LifecycleStatus            ModelLifecycleStatus `json:"lifecycle_status"`
	DeprecationDate            *time.Time           `json:"deprecation_date,omitempty"`
	DiscoveredAt               time.Time            `json:"discovered_at"`
	UpdatedAt                  time.Time            `json:"updated_at"`
}

// ModelPricingHistory tracks versioned pricing changes for a GlobalModel over time.
type ModelPricingHistory struct {
	ID                         string    `json:"id"`
	GlobalModelID              string    `json:"global_model_id"`
	PricingVersion             int       `json:"pricing_version"`
	InputCostMicrosPer1M       int64     `json:"input_cost_micros_per_1m"`
	OutputCostMicrosPer1M      int64     `json:"output_cost_micros_per_1m"`
	CachedInputCostMicrosPer1M int64     `json:"cached_input_cost_micros_per_1m"`
	ReasoningCostMicrosPer1M   int64     `json:"reasoning_cost_micros_per_1m"`
	ChangedBy                  string    `json:"changed_by"`
	EffectiveFrom              time.Time `json:"effective_from"`
}

// DiscoveredModel is returned by ProviderAdapter.ListModels() during automated discovery.
type DiscoveredModel struct {
	Provider    ProviderType
	ModelName   string
	DisplayName string
	CreatedAt   int64
}

// OrgProviderSubscription represents Layer 2 of Model Management: Tenant Vendor Entitlements.
type OrgProviderSubscription struct {
	OrgID         string       `json:"org_id"`
	Provider      ProviderType `json:"provider"`
	IsEnabled     bool         `json:"is_enabled"`
	AutoEnableNew bool         `json:"auto_enable_new"`
	SubscribedAt  time.Time    `json:"subscribed_at"`
}

// OrgModelPolicy represents Layer 3 of Model Management: Tenant Model Approval.
type OrgModelPolicy struct {
	OrgID         string    `json:"org_id"`
	GlobalModelID string    `json:"global_model_id"`
	IsEnabled     bool      `json:"is_enabled"`
	ApprovedBy    string    `json:"approved_by"`
	ApprovedAt    time.Time `json:"approved_at"`
}

// ProviderCredential represents Boundary 2 encrypted credentials in the Vault.
type ProviderCredential struct {
	ID              string            `json:"id"`
	OrgID           string            `json:"org_id"`
	Provider        ProviderType      `json:"provider"`
	Name            string            `json:"name"`
	BaseURL         string            `json:"base_url"`
	EncryptedAPIKey []byte            `json:"-"`
	DataNonce       []byte            `json:"-"`
	EncryptedDEK    []byte            `json:"-"`
	DEKNonce        []byte            `json:"-"`
	DecryptedAPIKey string            `json:"-"` // Populated in memory only when needed by adapter
	KeyVersion      int               `json:"key_version"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
	LastRotatedAt   *time.Time        `json:"last_rotated_at,omitempty"`
	LastValidatedAt *time.Time        `json:"last_validated_at,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	IsActive        bool              `json:"is_active"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// GuardrailAction specifies how the gateway responds when a security guardrail is triggered.
type GuardrailAction string

const (
	GuardrailActionBlock  GuardrailAction = "block"
	GuardrailActionRedact GuardrailAction = "redact"
	GuardrailActionAudit  GuardrailAction = "audit"
)

// GuardrailPolicy defines per-organization security, PII redaction, and prompt-injection rules.
type GuardrailPolicy struct {
	OrgID                 string          `json:"org_id"`
	EnablePromptInjection bool            `json:"enable_prompt_injection"`
	PromptInjectionAction GuardrailAction `json:"prompt_injection_action"`
	EnablePIIDetection    bool            `json:"enable_pii_detection"`
	PIIAction             GuardrailAction `json:"pii_action"`
	EnableSecretDetection bool            `json:"enable_secret_detection"`
	SecretAction          GuardrailAction `json:"secret_action"`
	BlockedKeywords       []string        `json:"blocked_keywords,omitempty"`
	RedactOutputPII       bool            `json:"redact_output_pii"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

// ModelGroup represents a logical routing target (e.g. "gpt-4.1", "fast", "reasoning", "auto").
type ModelGroup struct {
	ID               string          `json:"id"`
	OrgID            string          `json:"org_id"`
	Alias            string          `json:"alias"`
	Description      string          `json:"description,omitempty"`
	RoutingStrategy  RoutingStrategy `json:"routing_strategy"`
	FallbackGroupIDs []string        `json:"fallback_group_ids,omitempty"`
	MaxRetries       int             `json:"max_retries"`
	CooldownSeconds  int             `json:"cooldown_seconds"`
	FailureThreshold int             `json:"failure_threshold"`
	IsActive         bool            `json:"is_active"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// Deployment represents Layer 4 of Model Management: a concrete physical endpoint inside a ModelGroup.
type Deployment struct {
	ID             string           `json:"id"`
	ModelGroupID   string           `json:"model_group_id"`
	GlobalModelID  string           `json:"global_model_id"`
	CredentialID   string           `json:"credential_id"`
	DeploymentName string           `json:"deployment_name"`
	Region         string           `json:"region"`
	Weight         int              `json:"weight"`
	RPMCapacity    int              `json:"rpm_capacity"`
	TPMCapacity    int              `json:"tpm_capacity"`
	TimeoutMs      int              `json:"timeout_ms"`
	Priority       int              `json:"priority"`
	Status         DeploymentStatus `json:"status"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	// Hydrated associations for hot-path execution
	GlobalModel *GlobalModel        `json:"global_model,omitempty"`
	Credential  *ProviderCredential `json:"credential,omitempty"`
}
