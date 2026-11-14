package openaicompat_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/azure"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openaicompat"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func loopbackTestPolicy(t *testing.T) *network.Policy {
	t.Helper()
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("build loopback test policy: %v", err)
	}
	return pol
}

func TestOpenAICompat_ProfileRegistryEnforcesSSRFPolicyAcrossOperations(t *testing.T) {
	ctx := context.Background()

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":"test-model"}]}`))
	}))
	defer upstream.Close()

	strictPol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
		BlockedIPs:           []string{"169.254.169.254"},
	})
	if err != nil {
		t.Fatalf("new strict policy: %v", err)
	}

	reg := openaicompat.NewProfileRegistry(upstream.Client(), strictPol)
	err = reg.RegisterCustomWithOptions(config.CustomProviderConfig{
		ID:                 "custom-ssrf-test",
		DisplayName:        "Custom SSRF Test",
		BaseURL:            "https://api.example.com/v1",
		SupportsListModels: true,
	}, openaicompat.CustomProfileOptions{
		SupportedOperations: &openaicompat.ProviderOperations{
			Chat:        true,
			Completion:  true,
			Embeddings:  true,
			Rerank:      true,
			Moderations: true,
			AudioTTS:    true,
		},
	})
	if err != nil {
		t.Fatalf("register custom profile: %v", err)
	}

	rawCustom, err := reg.CreateAdapter(domain.ProviderType("custom-ssrf-test"))
	if err != nil {
		t.Fatalf("create custom adapter: %v", err)
	}
	customAdp := rawCustom.(*openaicompat.Adapter)

	rawGroq, err := reg.CreateAdapter(domain.ProviderType("groq"))
	if err != nil {
		t.Fatalf("create groq adapter: %v", err)
	}
	groqAdp := rawGroq.(*openaicompat.Adapter)

	badURLs := []string{
		"http://169.254.169.254/latest/meta-data",
		upstream.URL + "/v1",
		"https://user:pass@api.example.com/v1",
		"https://api.example.com/v1?secret=1",
	}

	for _, bad := range badURLs {
		cred := &domain.ProviderCredential{
			BaseURL:         bad,
			DecryptedAPIKey: "sk-test",
		}
		dep := &domain.Deployment{
			ID:             "dep-bad",
			DeploymentName: "test-model",
			Credential:     cred,
		}

		if _, err := customAdp.ListModels(ctx, cred); err == nil {
			t.Fatalf("expected custom ListModels to reject %q", bad)
		}
		if _, err := groqAdp.ListModels(ctx, cred); err == nil {
			t.Fatalf("expected built-in groq ListModels to reject %q", bad)
		}
		if _, err := groqAdp.ChatCompletion(ctx, dep, &domain.CanonicalChatRequest{
			Model:    "llama-3.1-8b-instant",
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		}); err == nil {
			t.Fatalf("expected built-in groq ChatCompletion to reject %q", bad)
		}
		if _, err := customAdp.Embeddings(ctx, dep, &domain.CanonicalEmbeddingRequest{
			Model: "test-embed",
			Input: []string{"hello"},
		}); err == nil {
			t.Fatalf("expected Embeddings to reject %q", bad)
		}
		if _, err := customAdp.Rerank(ctx, dep, &domain.CanonicalRerankRequest{
			Model:     "test-rerank",
			Query:     "q",
			Documents: []domain.RerankDocument{{Text: "d1"}},
		}); err == nil {
			t.Fatalf("expected Rerank (resolveEndpointBase) to reject %q", bad)
		}
		if _, _, err := customAdp.GenerateSpeech(ctx, dep, &domain.CanonicalAudioSpeechRequest{
			Model: "tts-1",
			Input: "hello",
			Voice: "alloy",
		}); err == nil {
			t.Fatalf("expected GenerateSpeech (resolveEndpointBase) to reject %q", bad)
		}
	}

	// Azure strategy via ProfileRegistry must also enforce strict SSRF policy
	rawAzure, err := reg.CreateAdapter(domain.ProviderType("azure"))
	if err != nil {
		t.Fatalf("create azure adapter: %v", err)
	}
	azureAdp := rawAzure.(*openaicompat.Adapter)
	if _, err := azureAdp.ChatCompletion(ctx, &domain.Deployment{
		ID:             "dep-az-bad",
		DeploymentName: "gpt-4o",
		Credential: &domain.ProviderCredential{
			BaseURL:             "http://169.254.169.254/openai/v1",
			DecryptedAPIKey:     "az-key",
			AzureDeploymentName: "gpt-4o",
			APIVersion:          "2024-10-21",
		},
	}, &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}); err == nil {
		t.Fatalf("expected Azure ChatCompletion to reject metadata IP BaseURL")
	}

	if hits := upstreamHits.Load(); hits != 0 {
		t.Fatalf("expected 0 requests to reach loopback server under strict SSRF policy, got %d", hits)
	}
}

func TestOpenAICompat_RegistryClonesProfilePolicyWithoutRaceOrTemplateMutation(t *testing.T) {
	ctx := context.Background()

	var seenPath atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":"groq-model"}]}`))
	}))
	defer upstream.Close()

	strictPol, _ := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: false, AllowInsecureHTTP: false})
	loopbackPol, _ := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})

	strictReg := openaicompat.NewProfileRegistry(upstream.Client(), strictPol)
	loopbackReg := openaicompat.NewProfileRegistry(upstream.Client(), loopbackPol)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			adp, err := strictReg.CreateAdapter(domain.ProviderType("groq"))
			if err != nil {
				t.Errorf("strict CreateAdapter: %v", err)
				return
			}
			if _, err := adp.ListModels(ctx, &domain.ProviderCredential{
				BaseURL:         upstream.URL + "/openai/v1",
				DecryptedAPIKey: "sk-test",
			}); err == nil {
				t.Errorf("expected strict registry adapter to block loopback URL")
			}
		}()
		go func() {
			defer wg.Done()
			adp, err := loopbackReg.CreateAdapter(domain.ProviderType("groq"))
			if err != nil {
				t.Errorf("loopback CreateAdapter: %v", err)
				return
			}
			models, err := adp.ListModels(ctx, &domain.ProviderCredential{
				BaseURL:         upstream.URL + "/openai/v1?ignored_query=1",
				DecryptedAPIKey: "sk-test",
			})
			if err == nil {
				t.Errorf("expected query parameter in BaseURL to be rejected, got %d models", len(models))
			}
		}()
	}
	wg.Wait()

	// Valid loopback BaseURL with trailing slash must succeed on loopback registry and break taint via clean canonical path
	loopAdp, err := loopbackReg.CreateAdapter(domain.ProviderType("groq"))
	if err != nil {
		t.Fatalf("loopback CreateAdapter: %v", err)
	}
	models, err := loopAdp.ListModels(ctx, &domain.ProviderCredential{
		BaseURL:         upstream.URL + "/openai/v1/",
		DecryptedAPIKey: "sk-test",
	})
	if err != nil || len(models) != 1 {
		t.Fatalf("expected loopback ListModels to return 1 model, got %d, err=%v", len(models), err)
	}
	if got, _ := seenPath.Load().(string); got != "/openai/v1/models" {
		t.Fatalf("expected canonical request path /openai/v1/models, got %q", got)
	}

	// Verify AzureEndpointStrategy directly rejects private/syntax errors when policy is attached
	azStrat := &azure.AzureEndpointStrategy{SSRFPolicy: strictPol}
	if _, err := azStrat.BuildURL(&domain.Deployment{
		ID: "az-1",
		Credential: &domain.ProviderCredential{
			BaseURL: "https://user:pass@my-res.openai.azure.com/openai/v1",
		},
	}, adapter.OperationChatCompletion); err == nil {
		t.Fatalf("expected AzureEndpointStrategy to reject embedded credentials in BaseURL")
	}
}
