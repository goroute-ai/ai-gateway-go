package azure

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// AzureEndpointMode specifies whether Azure uses the modern /openai/v1 format or legacy deployment paths.
type AzureEndpointMode string

const (
	AzureEndpointModeStandardV1       AzureEndpointMode = "v1"
	AzureEndpointModeLegacyDeployment AzureEndpointMode = "legacy_deployment"
)

// AzureEndpointStrategy constructs URLs for Azure OpenAI Service backends.
type AzureEndpointStrategy struct {
	Mode AzureEndpointMode
}

func (s *AzureEndpointStrategy) BuildURL(dep *domain.Deployment, op adapter.OperationType) (string, error) {
	if dep == nil || dep.Credential == nil {
		return "", fmt.Errorf("nil deployment or credential for Azure OpenAI")
	}

	baseURL := strings.TrimSpace(dep.Credential.BaseURL)
	if baseURL == "" {
		return "", fmt.Errorf("azure openai requires an explicit base_url on provider credential")
	}
	baseURL = strings.TrimRight(baseURL, "/")

	// Mode determination:
	// If mode is explicit, use it. Otherwise, if baseURL ends with /openai/v1 or /v1, use StandardV1.
	mode := s.Mode
	if mode == "" {
		if strings.HasSuffix(baseURL, "/openai/v1") || strings.HasSuffix(baseURL, "/v1") {
			mode = AzureEndpointModeStandardV1
		} else {
			// Check if mode header is passed
			if m := dep.Credential.Headers["azure_endpoint_mode"]; m != "" {
				mode = AzureEndpointMode(m)
			} else {
				mode = AzureEndpointModeLegacyDeployment
			}
		}
	}

	if mode == AzureEndpointModeStandardV1 {
		// Modern Azure OpenAI v1 endpoint:
		// e.g. https://my-resource.openai.azure.com/openai/v1/chat/completions
		prefix := baseURL
		if !strings.HasSuffix(prefix, "/openai/v1") {
			prefix += "/openai/v1"
		}
		switch op {
		case adapter.OperationChatCompletion:
			return prefix + "/chat/completions", nil
		case adapter.OperationEmbeddings:
			return prefix + "/embeddings", nil
		case adapter.OperationListModels:
			return prefix + "/models", nil
		default:
			return "", fmt.Errorf("unsupported Azure OpenAI v1 operation %q", op)
		}
	}

	// Legacy Azure Deployment Mode:
	// Requires explicit deployment name and explicit api-version
	deploymentName := strings.TrimSpace(dep.Credential.AzureDeploymentName)
	if deploymentName == "" && dep.Credential.Headers != nil {
		if d := dep.Credential.Headers["azure_deployment_name"]; d != "" {
			deploymentName = strings.TrimSpace(d)
		} else if d := dep.Credential.Headers["deployment_name"]; d != "" {
			deploymentName = strings.TrimSpace(d)
		}
	}

	if deploymentName == "" {
		return "", fmt.Errorf("azure legacy deployment mode requires an explicit azure_deployment_name")
	}

	apiVersion := strings.TrimSpace(dep.Credential.APIVersion)
	if apiVersion == "" && dep.Credential.Headers != nil {
		apiVersion = strings.TrimSpace(dep.Credential.Headers["api-version"])
	}
	if apiVersion == "" {
		return "", fmt.Errorf("azure legacy deployment mode requires an explicit api-version (e.g. 2024-10-21)")
	}

	var opPath string
	switch op {
	case adapter.OperationChatCompletion:
		opPath = "chat/completions"
	case adapter.OperationEmbeddings:
		opPath = "embeddings"
	default:
		return "", fmt.Errorf("unsupported Azure legacy operation %q (model listing unsupported on legacy deployment endpoint)", op)
	}

	return fmt.Sprintf("%s/openai/deployments/%s/%s?api-version=%s",
		baseURL,
		url.PathEscape(deploymentName),
		opPath,
		url.QueryEscape(apiVersion),
	), nil
}

// AzureAuthStrategy applies authentication to Azure OpenAI requests.
// Supports both Azure API keys (`api-key: <key>`) and Microsoft Entra ID Bearer tokens (`Authorization: Bearer <token>`).
type AzureAuthStrategy struct{}

func (s *AzureAuthStrategy) ApplyAuth(req *http.Request, cred *domain.ProviderCredential) error {
	if cred == nil {
		return fmt.Errorf("nil provider credential for Azure OpenAI")
	}

	rawKey := strings.TrimSpace(cred.DecryptedAPIKey)
	if rawKey == "" {
		return fmt.Errorf("empty DecryptedAPIKey for Azure OpenAI")
	}

	// If the key starts with "Bearer ", treat as Microsoft Entra ID OAuth2 token
	if strings.HasPrefix(rawKey, "Bearer ") {
		req.Header.Set("Authorization", rawKey)
	} else {
		// Standard Azure API key
		req.Header.Set("api-key", rawKey)
	}

	// Inject other custom headers from credential (except control values like api-version and azure_deployment_name)
	for k, v := range cred.Headers {
		kLower := strings.ToLower(k)
		if kLower == "api-version" || kLower == "azure_deployment_name" || kLower == "azure_endpoint_mode" {
			continue
		}
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
	}

	return nil
}
