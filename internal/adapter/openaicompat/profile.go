package openaicompat

import (
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// DialectConstraints specifies numeric or policy constraints enforced by a provider dialect.
type DialectConstraints struct {
	SupportedTemperature     *[2]float64 `json:"supported_temperature,omitempty"`      // e.g. [0.0, 1.0] for Together AI
	RejectsCustomTemperature bool        `json:"rejects_custom_temperature,omitempty"` // e.g. true for reasoning models
	RejectsTopP              bool        `json:"rejects_top_p,omitempty"`              // e.g. true for reasoning models
	MaxOutputTokensCeiling   int         `json:"max_output_tokens_ceiling,omitempty"`
}

// ModelDialectOverride allows per-model overrides within a provider.
type ModelDialectOverride struct {
	ModelPattern       string                   `json:"model_pattern"` // regex pattern e.g. ".*reasoner.*" or ".*distill.*"
	Constraints        DialectConstraints      `json:"constraints"`
	Capabilities       domain.ModelCapabilities `json:"capabilities"`
	ParamMappings      map[string]string        `json:"param_mappings,omitempty"`
}

// DialectProfile encapsulates all configuration, mapping rules, transport, and capabilities for an OpenAI-compatible provider.
type DialectProfile struct {
	ID                         domain.ProviderType      `json:"id"`
	DisplayName                string                   `json:"display_name"`
	DefaultBaseURL             string                   `json:"default_base_url"`
	EndpointStrategy           adapter.EndpointStrategy `json:"-"`
	AuthStrategy               adapter.AuthStrategy     `json:"-"`
	DefaultHeaders             map[string]string        `json:"default_headers,omitempty"`
	SupportsListModels         bool                     `json:"supports_list_models"` // true if upstream implements GET /models
	ParamMappings              map[string]string        `json:"param_mappings,omitempty"` // e.g. "max_completion_tokens" -> "max_tokens"
	Constraints                DialectConstraints      `json:"constraints"`
	ModelOverrides             []ModelDialectOverride   `json:"model_overrides,omitempty"`
	DefaultCapabilities        domain.ModelCapabilities `json:"default_capabilities"`
	ExtractReasoningDelta      bool                     `json:"extract_reasoning_delta"`       // e.g. true for DeepSeek R1 delta.reasoning_content
	ConvertContentListToString bool                     `json:"convert_content_list_to_string"` // e.g. true if provider requires flat string messages
}
