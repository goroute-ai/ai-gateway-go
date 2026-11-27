package adapter

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// OperationType identifies which LLM endpoint is being invoked.
type OperationType string

const (
	OperationChatCompletion OperationType = "chat_completion"
	OperationEmbeddings     OperationType = "embeddings"
	OperationListModels     OperationType = "list_models"
)

// EndpointStrategy defines how target URLs are constructed for a provider.
type EndpointStrategy interface {
	BuildURL(dep *domain.Deployment, op OperationType) (string, error)
}

// AuthStrategy defines how authentication headers and credentials are applied to upstream requests.
type AuthStrategy interface {
	ApplyAuth(req *http.Request, cred *domain.ProviderCredential) error
}

// StandardOpenAIEndpointStrategy builds URLs for standard OpenAI-compatible endpoints.
type StandardOpenAIEndpointStrategy struct {
	DefaultBaseURL string
	SSRFPolicy     *network.Policy
}

func (s *StandardOpenAIEndpointStrategy) BuildURL(dep *domain.Deployment, op OperationType) (string, error) {
	rawOverride := ""
	if dep != nil && dep.Credential != nil {
		rawOverride = dep.Credential.BaseURL
	}
	base, err := ValidateAndResolveBaseURL(rawOverride, s.DefaultBaseURL, s.SSRFPolicy)
	if err != nil {
		return "", err
	}
	if base == "" {
		depID := ""
		if dep != nil {
			depID = dep.ID
		}
		return "", fmt.Errorf("no base URL configured for deployment %q", depID)
	}

	switch op {
	case OperationChatCompletion:
		return base + "/chat/completions", nil
	case OperationEmbeddings:
		return base + "/embeddings", nil
	case OperationListModels:
		return base + "/models", nil
	default:
		return "", fmt.Errorf("unsupported operation %q for standard OpenAI endpoint strategy", op)
	}
}

// BearerAuthStrategy applies standard `Authorization: Bearer <token>` using `cred.DecryptedAPIKey`.
type BearerAuthStrategy struct{}

func (s *BearerAuthStrategy) ApplyAuth(req *http.Request, cred *domain.ProviderCredential) error {
	if cred == nil {
		return fmt.Errorf("nil provider credential")
	}
	// Apply safe custom headers first so vault-decrypted Authorization always takes precedence.
	ApplySafeCustomHeaders(req, cred.Headers)
	apiKey := strings.TrimSpace(cred.DecryptedAPIKey)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return nil
}

// HeaderAuthStrategy applies a custom header (e.g. `api-subscription-key: <token>`) using `cred.DecryptedAPIKey`.
type HeaderAuthStrategy struct {
	HeaderName string
}

func (s *HeaderAuthStrategy) ApplyAuth(req *http.Request, cred *domain.ProviderCredential) error {
	if cred == nil {
		return fmt.Errorf("nil provider credential")
	}
	ApplySafeCustomHeaders(req, cred.Headers)
	apiKey := strings.TrimSpace(cred.DecryptedAPIKey)
	if apiKey != "" && strings.TrimSpace(s.HeaderName) != "" {
		req.Header.Set(s.HeaderName, apiKey)
	}
	return nil
}
