package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhase4_ImageEndpoints(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock upstream OpenAI images server
	imgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/images/generations":
		case "/v1/images/edits", "/v1/images/variations":
			require.Contains(t, r.Header.Get("Content-Type"), "multipart/form-data")
			file, _, err := r.FormFile("image")
			require.NoError(t, err)
			imageBytes, err := io.ReadAll(file)
			_ = file.Close()
			require.NoError(t, err)
			require.Equal(t, []byte("\x89PNG\r\n\x1a\nsource"), imageBytes)
			if r.URL.Path == "/v1/images/edits" {
				assert.Equal(t, "make it blue", r.FormValue("prompt"))
			}
		default:
			t.Fatalf("unexpected image endpoint %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{
			"created": 1700000000,
			"data": [
				{
					"url": "https://oaidalleapiprodscus.blob.core.windows.net/private/generated-image-1.png",
					"revised_prompt": "A digital painting of a majestic mountain with snow."
				}
			]
		}`)
	}))
	defer imgSrv.Close()

	gw, err := server.New(cfg, repo, nil, imgSrv.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-images", Name: "Images Org", Slug: "images-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Issue Virtual Key
	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "images-key",
	})
	keyReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_secret_key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)
	require.NotEmpty(t, issuedKey.RawKey)

	// Create Credential
	var cred domain.ProviderCredential
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-images",
		"base_url": imgSrv.URL + "/v1",
		"api_key":  "sk-openai-images",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	_ = json.Unmarshal(credRec.Body.Bytes(), &cred)

	// Create Image Model (dall-e-3, base $0.040 = 40,000 µ$, HD $0.080 = 80,000 µ$)
	imgGM := &domain.GlobalModel{
		ID:                  "openai/dall-e-3",
		Provider:            domain.ProviderOpenAI,
		ModelName:           "dall-e-3",
		DisplayName:         "DALL-E 3",
		SupportsInference:   true,
		LifecycleStatus:     domain.ModelStatusActive,
		PricingStatus:       domain.PricingStatusVerified,
		ImageCostMicrosBase: 40000,
		ImageCostMicrosHD:   80000,
		Capabilities: domain.ModelCapabilities{
			ImageGen: domain.CapabilitySupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, imgGM))

	imgMG := &domain.ModelGroup{
		ID:              "mg-dall-e-3",
		OrgID:           org.ID,
		Alias:           "dall-e-3",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, imgMG))

	imgDep := &domain.Deployment{
		ID:             "dep-dall-e-3",
		ModelGroupID:   imgMG.ID,
		GlobalModelID:  imgGM.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-img-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    imgGM,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, imgDep))

	t.Run("TestImageGenerationBaseQuality", func(t *testing.T) {
		payload := map[string]any{
			"model":   "dall-e-3",
			"prompt":  "A majestic snow-capped mountain at sunrise",
			"quality": "standard",
			"size":    "1024x1024",
			"n":       1,
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "Response: %s", rec.Body.String())
		assert.Equal(t, "40000", rec.Header().Get("X-Gateway-Cost-Micros"))

		var resp domain.CanonicalImageResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, int64(1700000000), resp.Created)
		assert.Len(t, resp.Data, 1)
		assert.Contains(t, resp.Data[0].URL, "generated-image-1.png")
		assert.Equal(t, "A digital painting of a majestic mountain with snow.", resp.Data[0].RevisedPrompt)
	})

	t.Run("TestImageGenerationHDQuality", func(t *testing.T) {
		payload := map[string]any{
			"model":   "dall-e-3",
			"prompt":  "A futuristic cyberpunk neon city at night",
			"quality": "hd",
			"size":    "1024x1792",
			"n":       1,
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/images/generations", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "80000", rec.Header().Get("X-Gateway-Cost-Micros"))
	})

	for _, path := range []string{"/v1/images/edits", "/v1/images/variations"} {
		t.Run(path, func(t *testing.T) {
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			part, err := writer.CreateFormFile("image", "source.png")
			require.NoError(t, err)
			_, _ = part.Write([]byte("\x89PNG\r\n\x1a\nsource"))
			_ = writer.WriteField("model", "dall-e-3")
			if path == "/v1/images/edits" {
				_ = writer.WriteField("prompt", "make it blue")
			}
			_ = writer.Close()
			req, _ := http.NewRequest(http.MethodPost, path, body)
			req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
			req.Header.Set("Content-Type", writer.FormDataContentType())
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, "Response: %s", rec.Body.String())
		})
	}
}
