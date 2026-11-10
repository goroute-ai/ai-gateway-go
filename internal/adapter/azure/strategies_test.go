package azure

import (
	"net/http"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestAzureEndpointStrategy_StandardV1(t *testing.T) {
	strat := &AzureEndpointStrategy{Mode: AzureEndpointModeStandardV1}

	dep := &domain.Deployment{
		ID: "dep-azure-v1",
		Credential: &domain.ProviderCredential{
			BaseURL: "https://my-resource.openai.azure.com",
		},
	}

	chatURL, err := strat.BuildURL(dep, adapter.OperationChatCompletion)
	if err != nil {
		t.Fatalf("unexpected error for chat: %v", err)
	}
	expectedChat := "https://my-resource.openai.azure.com/openai/v1/chat/completions"
	if chatURL != expectedChat {
		t.Fatalf("expected %q, got %q", expectedChat, chatURL)
	}

	embURL, err := strat.BuildURL(dep, adapter.OperationEmbeddings)
	if err != nil {
		t.Fatalf("unexpected error for embeddings: %v", err)
	}
	expectedEmb := "https://my-resource.openai.azure.com/openai/v1/embeddings"
	if embURL != expectedEmb {
		t.Fatalf("expected %q, got %q", expectedEmb, embURL)
	}

	modelsURL, err := strat.BuildURL(dep, adapter.OperationListModels)
	if err != nil {
		t.Fatalf("unexpected error for models: %v", err)
	}
	expectedModels := "https://my-resource.openai.azure.com/openai/v1/models"
	if modelsURL != expectedModels {
		t.Fatalf("expected %q, got %q", expectedModels, modelsURL)
	}
}

func TestAzureEndpointStrategy_LegacyDeployment(t *testing.T) {
	strat := &AzureEndpointStrategy{Mode: AzureEndpointModeLegacyDeployment}

	// 1. Missing deployment name fails
	depNoName := &domain.Deployment{
		ID: "dep-no-name",
		Credential: &domain.ProviderCredential{
			BaseURL: "https://my-resource.openai.azure.com",
			Headers: map[string]string{"api-version": "2024-10-21"},
		},
	}
	if _, err := strat.BuildURL(depNoName, adapter.OperationChatCompletion); err == nil {
		t.Fatal("expected error when azure_deployment_name is missing")
	}

	// 2. Missing api-version fails (no silent default to deprecated preview)
	depNoVersion := &domain.Deployment{
		ID: "dep-no-ver",
		Credential: &domain.ProviderCredential{
			BaseURL: "https://my-resource.openai.azure.com",
			Headers: map[string]string{"azure_deployment_name": "my-gpt4-dep"},
		},
	}
	if _, err := strat.BuildURL(depNoVersion, adapter.OperationChatCompletion); err == nil {
		t.Fatal("expected error when api-version is missing in legacy mode")
	}

	// 3. Valid legacy deployment URL
	depValid := &domain.Deployment{
		ID: "dep-valid",
		Credential: &domain.ProviderCredential{
			BaseURL: "https://my-resource.openai.azure.com",
			Headers: map[string]string{
				"azure_deployment_name": "gpt-4o-prod",
				"api-version":           "2024-10-21",
			},
		},
	}
	url, err := strat.BuildURL(depValid, adapter.OperationChatCompletion)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "https://my-resource.openai.azure.com/openai/deployments/gpt-4o-prod/chat/completions?api-version=2024-10-21"
	if url != expected {
		t.Fatalf("expected %q, got %q", expected, url)
	}
}

func TestAzureAuthStrategy(t *testing.T) {
	strat := &AzureAuthStrategy{}

	// 1. Standard API Key
	reqKey, _ := http.NewRequest("POST", "https://example.com", nil)
	credKey := &domain.ProviderCredential{
		DecryptedAPIKey: "secret-azure-api-key-12345",
	}
	if err := strat.ApplyAuth(reqKey, credKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqKey.Header.Get("api-key") != "secret-azure-api-key-12345" {
		t.Fatalf("expected api-key header, got %q", reqKey.Header.Get("api-key"))
	}
	if reqKey.Header.Get("Authorization") != "" {
		t.Fatalf("expected no Authorization header for standard key, got %q", reqKey.Header.Get("Authorization"))
	}

	// 2. Entra ID Bearer Token
	reqBearer, _ := http.NewRequest("POST", "https://example.com", nil)
	credBearer := &domain.ProviderCredential{
		DecryptedAPIKey: "Bearer eyJhbGciOi...",
	}
	if err := strat.ApplyAuth(reqBearer, credBearer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqBearer.Header.Get("Authorization") != "Bearer eyJhbGciOi..." {
		t.Fatalf("expected Authorization Bearer header, got %q", reqBearer.Header.Get("Authorization"))
	}
	if reqBearer.Header.Get("api-key") != "" {
		t.Fatalf("expected no api-key header for bearer token, got %q", reqBearer.Header.Get("api-key"))
	}
}
