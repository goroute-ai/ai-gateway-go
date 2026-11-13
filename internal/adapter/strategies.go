package adapter

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
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
}

func (s *StandardOpenAIEndpointStrategy) BuildURL(dep *domain.Deployment, op OperationType) (string, error) {
	base := ""
	if dep != nil && dep.Credential != nil && strings.TrimSpace(dep.Credential.BaseURL) != "" {
		base = strings.TrimSpace(dep.Credential.BaseURL)
	} else if strings.TrimSpace(s.DefaultBaseURL) != "" {
		base = strings.TrimSpace(s.DefaultBaseURL)
	}

	if base == "" {
		return "", fmt.Errorf("no base URL configured for deployment %q", dep.ID)
	}
	base = strings.TrimRight(base, "/")

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
	apiKey := strings.TrimSpace(cred.DecryptedAPIKey)
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	// Inject any custom static headers configured for this credential
	for k, v := range cred.Headers {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
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
	apiKey := strings.TrimSpace(cred.DecryptedAPIKey)
	if apiKey != "" && strings.TrimSpace(s.HeaderName) != "" {
		req.Header.Set(s.HeaderName, apiKey)
	}
	for k, v := range cred.Headers {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
	}
	return nil
}
