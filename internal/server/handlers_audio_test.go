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

func TestPhase3_AudioEndpoints(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock upstream audio server
	audioSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/audio/transcriptions", "/v1/audio/translations":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"text": "The quick brown fox jumps over the lazy dog.",
				"duration": 3.5,
				"language": "english"
			}`)
		case "/v1/audio/speech":
			w.Header().Set("Content-Type", "audio/mpeg")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("fake-mp3-audio-bytes-stream"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer audioSrv.Close()

	gw, err := server.New(cfg, repo, nil, audioSrv.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-audio", Name: "Audio Org", Slug: "audio-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Issue Virtual Key
	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "audio-key",
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
		"name":     "openai-audio",
		"base_url": audioSrv.URL + "/v1",
		"api_key":  "sk-openai-audio",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	_ = json.Unmarshal(credRec.Body.Bytes(), &cred)

	// 1. Audio STT Model (whisper-1, $0.006 / min = $0.0001 / sec = 100 micros/sec)
	sttGM := &domain.GlobalModel{
		ID:                          "openai/whisper-1",
		Provider:                    domain.ProviderOpenAI,
		ModelName:                   "whisper-1",
		DisplayName:                 "Whisper 1",
		SupportsInference:           true,
		LifecycleStatus:             domain.ModelStatusActive,
		PricingStatus:               domain.PricingStatusVerified,
		AudioSTTCostMicrosPerSecond: 100, // 100 micros / sec
		Capabilities: domain.ModelCapabilities{
			AudioSTT: domain.CapabilitySupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, sttGM))

	sttMG := &domain.ModelGroup{
		ID:              "mg-whisper-1",
		OrgID:           org.ID,
		Alias:           "whisper-1",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, sttMG))

	sttDep := &domain.Deployment{
		ID:             "dep-whisper-1",
		ModelGroupID:   sttMG.ID,
		GlobalModelID:  sttGM.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-stt-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    sttGM,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, sttDep))

	// 2. Audio TTS Model (tts-1, $15.00 / 1M chars = 15 micros / 1K chars)
	ttsGm := &domain.GlobalModel{
		ID:                           "openai/tts-1",
		Provider:                     domain.ProviderOpenAI,
		ModelName:                    "tts-1",
		DisplayName:                  "TTS 1",
		SupportsInference:            true,
		LifecycleStatus:              domain.ModelStatusActive,
		PricingStatus:                domain.PricingStatusVerified,
		AudioTTSCostMicrosPer1KChars: 15,
		Capabilities: domain.ModelCapabilities{
			AudioTTS: domain.CapabilitySupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, ttsGm))

	ttsMG := &domain.ModelGroup{
		ID:              "mg-tts-1",
		OrgID:           org.ID,
		Alias:           "tts-1",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, ttsMG))

	ttsDep := &domain.Deployment{
		ID:             "dep-tts-1",
		ModelGroupID:   ttsMG.ID,
		GlobalModelID:  ttsGm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-tts-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    ttsGm,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, ttsDep))

	t.Run("TestAudioTranscription", func(t *testing.T) {
		bodyBuf := &bytes.Buffer{}
		mpWriter := multipart.NewWriter(bodyBuf)
		_ = mpWriter.WriteField("model", "whisper-1")
		_ = mpWriter.WriteField("language", "en")
		filePart, err := mpWriter.CreateFormFile("file", "test.mp3")
		require.NoError(t, err)
		_, _ = filePart.Write([]byte("fake-audio-bytes-data"))
		require.NoError(t, mpWriter.Close())

		req, _ := http.NewRequest(http.MethodPost, "/v1/audio/transcriptions", bodyBuf)
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", mpWriter.FormDataContentType())

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "Response: %s", rec.Body.String())
		// 3.5s * 100 micros/sec = 350 micros (calculated with durationMs 3500)
		assert.Equal(t, "350", rec.Header().Get("X-Gateway-Cost-Micros"))

		var resp map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, "The quick brown fox jumps over the lazy dog.", resp["text"])
		assert.Equal(t, 3.5, resp["duration"])
	})

	t.Run("TestAudioSpeech", func(t *testing.T) {
		payload := map[string]any{
			"model": "tts-1",
			"input": "Antigravity gateway speech synthesis is running smoothly.",
			"voice": "alloy",
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/v1/audio/speech", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "audio/mpeg", rec.Header().Get("Content-Type"))
		bodyBytes, err := io.ReadAll(rec.Body)
		require.NoError(t, err)
		assert.Equal(t, "fake-mp3-audio-bytes-stream", string(bodyBytes))
	})
}
