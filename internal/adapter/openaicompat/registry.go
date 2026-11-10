package openaicompat

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/azure"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// ProfileRegistry manages certified and custom OpenAI-compatible dialect profiles.
type ProfileRegistry struct {
	mu         sync.RWMutex
	profiles   map[domain.ProviderType]*DialectProfile
	httpClient *http.Client
	ssrfPolicy *network.Policy
}

// NewProfileRegistry initializes the registry with the Launch Set certified profiles.
func NewProfileRegistry(httpClient *http.Client, policy *network.Policy) *ProfileRegistry {
	if policy == nil {
		policy, _ = network.NewPolicy(config.OutboundSSRFConfig{})
	}
	if httpClient == nil {
		httpClient = network.NewHTTPClient(policy)
	}

	reg := &ProfileRegistry{
		profiles:   make(map[domain.ProviderType]*DialectProfile),
		httpClient: httpClient,
		ssrfPolicy: policy,
	}

	reg.registerLaunchSet()
	reg.registerBuiltinProfiles()
	return reg
}

func (r *ProfileRegistry) registerLaunchSet() {
	// 1. Groq Profile
	r.profiles[domain.ProviderType("groq")] = &DialectProfile{
		ID:                 domain.ProviderType("groq"),
		DisplayName:        "Groq Fast Inference",
		DefaultBaseURL:     "https://api.groq.com/openai/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.groq.com/openai/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings: map[string]string{
			"max_completion_tokens": "max_tokens",
		},
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
		ModelOverrides: []ModelDialectOverride{
			{
				ModelPattern: `(?i).*distill.*`,
				Capabilities: domain.ModelCapabilities{
					Tools: domain.CapabilityUnsupported,
				},
				Constraints: DialectConstraints{
					RejectsCustomTemperature: true,
				},
			},
		},
	}

	// 2. DeepSeek Profile
	r.profiles[domain.ProviderType("deepseek")] = &DialectProfile{
		ID:                    domain.ProviderType("deepseek"),
		DisplayName:           "DeepSeek AI",
		DefaultBaseURL:        "https://api.deepseek.com/v1",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.deepseek.com/v1"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    true,
		ExtractReasoningDelta: true,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
		},
		ModelOverrides: []ModelDialectOverride{
			{
				ModelPattern: `(?i).*(reasoner|r1).*`,
				Constraints: DialectConstraints{
					RejectsCustomTemperature: true,
					RejectsTopP:              true,
				},
			},
		},
	}

	// 3. Together AI Profile
	togetherTempRange := [2]float64{0.0, 1.0}
	r.profiles[domain.ProviderType("together")] = &DialectProfile{
		ID:                 domain.ProviderType("together"),
		DisplayName:        "Together AI",
		DefaultBaseURL:     "https://api.together.xyz/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.together.xyz/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings: map[string]string{
			"max_completion_tokens": "max_tokens",
		},
		Constraints: DialectConstraints{
			SupportedTemperature: &togetherTempRange,
		},
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 4. Azure OpenAI Profile
	r.profiles[domain.ProviderType("azure")] = &DialectProfile{
		ID:                 domain.ProviderType("azure"),
		DisplayName:        "Microsoft Azure OpenAI",
		DefaultBaseURL:     "", // Configured per deployment
		EndpointStrategy:   &azure.AzureEndpointStrategy{},
		AuthStrategy:       &azure.AzureAuthStrategy{},
		SupportsListModels: false, // Model listing probe unsupported on inference keys
		ParamMappings: map[string]string{
			"max_tokens": "max_completion_tokens",
		},
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
		},
	}
}

// Get looks up a certified or registered custom profile.
// Strict bounded resolution: if the provider is unknown, it returns nil and false.
func (r *ProfileRegistry) Get(provider domain.ProviderType) (*DialectProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[provider]
	return p, ok
}

// CreateAdapter returns a new Adapter for the given provider, or error if not registered.
func (r *ProfileRegistry) CreateAdapter(provider domain.ProviderType) (adapter.ProviderAdapter, error) {
	r.mu.RLock()
	profile, ok := r.profiles[provider]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no provider adapter registered for %q", provider)
	}

	return NewAdapter(profile, r.httpClient), nil
}

var idPattern = regexp.MustCompile(`^[a-z0-9_\-]+$`)

// RegisterCustom registers a custom OpenAI-compatible profile after SSRF and syntax validation.
func (r *ProfileRegistry) RegisterCustom(cfg config.CustomProviderConfig) error {
	id := strings.ToLower(strings.TrimSpace(cfg.ID))
	if !idPattern.MatchString(id) {
		return fmt.Errorf("invalid custom provider id %q: must be alphanumeric or hyphen/underscore", id)
	}

	rawURL := strings.TrimSpace(cfg.BaseURL)
	if rawURL == "" {
		return fmt.Errorf("custom provider %q requires a non-empty base_url", id)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("custom provider %q base_url must have http or https scheme", id)
	}

	// Validate target against SSRF policy
	if err := r.ssrfPolicy.ValidateURL(parsed); err != nil {
		return fmt.Errorf("custom provider %q base_url rejected by outbound network policy: %w", id, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.profiles[domain.ProviderType(id)] = &DialectProfile{
		ID:                 domain.ProviderType(id),
		DisplayName:        cfg.DisplayName,
		DefaultBaseURL:     rawURL,
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: rawURL},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		DefaultHeaders:     cfg.DefaultHeaders,
		SupportsListModels: cfg.SupportsListModels,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilityState(cfg.SupportsTools),
			Streaming:         domain.CapabilityState(cfg.SupportsStreaming),
			StructuredOutputs: domain.CapabilityState(cfg.SupportsStructuredOutputs),
		},
	}

	return nil
}

// DynamicResolver adapts ProfileRegistry into a DynamicAdapterResolver for adapter.Registry.
func (r *ProfileRegistry) DynamicResolver() func(p domain.ProviderType) (adapter.ProviderAdapter, bool) {
	return func(p domain.ProviderType) (adapter.ProviderAdapter, bool) {
		adp, err := r.CreateAdapter(p)
		if err != nil {
			return nil, false
		}
		return adp, true
	}
}
