package openaicompat

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// RequestValidator validates an incoming CanonicalChatRequest against a DialectProfile's capabilities and constraints.
type RequestValidator struct {
	profile *DialectProfile
}

func NewRequestValidator(profile *DialectProfile) *RequestValidator {
	return &RequestValidator{profile: profile}
}

// ValidateAndResolveConstraints inspects the request and model, returning the effective constraints and model capabilities.
// It enforces the practical tri-state capability rule:
// - CapabilityUnsupported: Rejects immediately with HTTP 400 capability_unsupported.
// - CapabilityUnknown: Passes through without modification, delegating processing to upstream.
// - CapabilitySupported: Validated and permitted.
func (v *RequestValidator) ValidateAndResolveConstraints(req *domain.CanonicalChatRequest, model string) (*DialectConstraints, *domain.ModelCapabilities, error) {
	effectiveConstraints := v.profile.Constraints
	effectiveCapabilities := v.profile.DefaultCapabilities

	// Apply any matching per-model overrides
	for _, override := range v.profile.ModelOverrides {
		if matched, _ := regexp.MatchString(override.ModelPattern, model); matched {
			if override.Constraints.RejectsCustomTemperature {
				effectiveConstraints.RejectsCustomTemperature = true
			}
			if override.Constraints.RejectsTopP {
				effectiveConstraints.RejectsTopP = true
			}
			if override.Constraints.SupportedTemperature != nil {
				effectiveConstraints.SupportedTemperature = override.Constraints.SupportedTemperature
			}
			if override.Constraints.MaxOutputTokensCeiling > 0 {
				effectiveConstraints.MaxOutputTokensCeiling = override.Constraints.MaxOutputTokensCeiling
			}
			if override.Capabilities.Tools != "" {
				effectiveCapabilities.Tools = override.Capabilities.Tools
			}
			if override.Capabilities.Streaming != "" {
				effectiveCapabilities.Streaming = override.Capabilities.Streaming
			}
			if override.Capabilities.StructuredOutputs != "" {
				effectiveCapabilities.StructuredOutputs = override.Capabilities.StructuredOutputs
			}
			if override.Capabilities.Reasoning != "" {
				effectiveCapabilities.Reasoning = override.Capabilities.Reasoning
			}
			if override.Capabilities.Embeddings != "" {
				effectiveCapabilities.Embeddings = override.Capabilities.Embeddings
			}
		}
	}

	// 1. Validate Known Capability Rejections (Fail-Closed on CapabilityUnsupported)
	if len(req.Tools) > 0 && effectiveCapabilities.Tools == domain.CapabilityUnsupported {
		return nil, nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "capability_unsupported",
			Message:    fmt.Sprintf("Provider/model %q does not support tool calling (tools parameter is unsupported)", model),
		}
	}

	if req.Stream && effectiveCapabilities.Streaming == domain.CapabilityUnsupported {
		return nil, nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "capability_unsupported",
			Message:    fmt.Sprintf("Provider/model %q does not support streaming responses", model),
		}
	}

	if req.ResponseFormat != nil && effectiveCapabilities.StructuredOutputs == domain.CapabilityUnsupported {
		return nil, nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "capability_unsupported",
			Message:    fmt.Sprintf("Provider/model %q does not support response_format (structured outputs)", model),
		}
	}

	// 2. Validate Parameter Constraints
	if effectiveConstraints.RejectsCustomTemperature && req.Temperature != nil {
		return nil, nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "unsupported_parameter",
			Message:    fmt.Sprintf("Model %q rejects custom temperature parameter; omit temperature for this model", model),
		}
	}

	if effectiveConstraints.RejectsTopP && req.TopP != nil {
		return nil, nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "unsupported_parameter",
			Message:    fmt.Sprintf("Model %q rejects custom top_p parameter; omit top_p for this model", model),
		}
	}

	if effectiveConstraints.SupportedTemperature != nil && req.Temperature != nil {
		min := effectiveConstraints.SupportedTemperature[0]
		max := effectiveConstraints.SupportedTemperature[1]
		if *req.Temperature < min || *req.Temperature > max {
			return nil, nil, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "unsupported_parameter",
				Message:    fmt.Sprintf("Model %q requires temperature in range [%.1f, %.1f], got %.2f", model, min, max, *req.Temperature),
			}
		}
	}

	return &effectiveConstraints, &effectiveCapabilities, nil
}
