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
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhase5_FilesAndBatches(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock upstream server for batch request execution
	chatSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{
			"id": "chatcmpl-batch-exec",
			"model": "gpt-4.1-mini",
			"choices": [
				{"index": 0, "message": {"role": "assistant", "content": "Batch line answer"}, "finish_reason": "stop"}
			],
			"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
		}`)
	}))
	defer chatSrv.Close()

	gw, err := server.New(cfg, repo, nil, chatSrv.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-stateful", Name: "Stateful Org", Slug: "stateful-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Issue Virtual Key
	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "stateful-key",
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
		"name":     "openai-batch",
		"base_url": chatSrv.URL + "/v1",
		"api_key":  "sk-openai-batch",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	_ = json.Unmarshal(credRec.Body.Bytes(), &cred)

	// Model setup for batch chat execution
	gm := &domain.GlobalModel{
		ID:                "openai/gpt-4.1-mini",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4.1-mini",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	mg := &domain.ModelGroup{
		ID:              "mg-batch-mini",
		OrgID:           org.ID,
		Alias:           "gpt-4.1-mini",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))

	dep := &domain.Deployment{
		ID:             "dep-batch-mini",
		ModelGroupID:   mg.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-batch-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    gm,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	var uploadedFile domain.CanonicalFile

	// 1. Test POST /v1/files (upload JSONL batch file)
	t.Run("TestUploadFile", func(t *testing.T) {
		bodyBuf := &bytes.Buffer{}
		mpWriter := multipart.NewWriter(bodyBuf)
		_ = mpWriter.WriteField("purpose", "batch")
		part, err := mpWriter.CreateFormFile("file", "batch_input.jsonl")
		require.NoError(t, err)

		jsonlContent := `{"custom_id": "req-1", "method": "POST", "url": "/v1/chat/completions", "body": {"model": "gpt-4.1-mini", "messages": [{"role": "user", "content": "Hello 1"}]}}` + "\n" +
			`{"custom_id": "req-2", "method": "POST", "url": "/v1/chat/completions", "body": {"model": "gpt-4.1-mini", "messages": [{"role": "user", "content": "Hello 2"}]}}` + "\n"

		_, _ = part.Write([]byte(jsonlContent))
		require.NoError(t, mpWriter.Close())

		req, _ := http.NewRequest(http.MethodPost, "/v1/files", bodyBuf)
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", mpWriter.FormDataContentType())

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusCreated, rec.Code, "Response: %s", rec.Body.String())
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &uploadedFile))
		assert.NotEmpty(t, uploadedFile.ID)
		assert.Equal(t, "batch_input.jsonl", uploadedFile.Filename)
		assert.Equal(t, "batch", uploadedFile.Purpose)
		assert.Greater(t, uploadedFile.Bytes, int64(0))
	})

	// 2. Test GET /v1/files and GET /v1/files/{file_id}
	t.Run("TestListAndGetFile", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/v1/files", nil)
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var listResp map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))
		files := listResp["data"].([]any)
		assert.Len(t, files, 1)

		// Get single file
		req2, _ := http.NewRequest(http.MethodGet, "/v1/files/"+uploadedFile.ID, nil)
		req2.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)

		require.Equal(t, http.StatusOK, rec2.Code)
		var singleFile domain.CanonicalFile
		require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &singleFile))
		assert.Equal(t, uploadedFile.ID, singleFile.ID)
	})

	// 3. Test GET /v1/files/{file_id}/content
	t.Run("TestGetFileContent", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/v1/files/"+uploadedFile.ID+"/content", nil)
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		bodyBytes, err := io.ReadAll(rec.Body)
		require.NoError(t, err)
		assert.Contains(t, string(bodyBytes), "req-1")
		assert.Contains(t, string(bodyBytes), "req-2")
	})

	var createdBatch domain.CanonicalBatch

	// 4. Test POST /v1/batches
	t.Run("TestCreateBatch", func(t *testing.T) {
		payload := map[string]any{
			"input_file_id":     uploadedFile.ID,
			"endpoint":          "/v1/chat/completions",
			"completion_window": "24h",
			"metadata": map[string]any{
				"experiment": "batch-parity-test",
			},
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusCreated, rec.Code, "Response: %s", rec.Body.String())
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createdBatch))
		assert.NotEmpty(t, createdBatch.ID)
		assert.Equal(t, uploadedFile.ID, createdBatch.InputFileID)
	})

	// 5. Test GET /v1/batches and GET /v1/batches/{batch_id} after background completion
	t.Run("TestGetBatchAndResults", func(t *testing.T) {
		// Wait brief moment for background batch worker to process 2 lines
		time.Sleep(50 * time.Millisecond)

		req, _ := http.NewRequest(http.MethodGet, "/v1/batches/"+createdBatch.ID, nil)
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)

		var latestBatch domain.CanonicalBatch
		require.Eventually(t, func() bool {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				return false
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &latestBatch)
			return latestBatch.Status == "completed"
		}, 2*time.Second, 20*time.Millisecond)

		assert.Equal(t, "completed", latestBatch.Status)
		assert.Equal(t, 2, latestBatch.RequestCounts.Total)
		assert.Equal(t, 2, latestBatch.RequestCounts.Completed)
		assert.NotEmpty(t, latestBatch.OutputFileID)

		// Download batch output file content
		outReq, _ := http.NewRequest(http.MethodGet, "/v1/files/"+latestBatch.OutputFileID+"/content", nil)
		outReq.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		outRec := httptest.NewRecorder()
		handler.ServeHTTP(outRec, outReq)
		require.Equal(t, http.StatusOK, outRec.Code)
		assert.Contains(t, outRec.Body.String(), "Batch line answer")
	})

	// 6. Identical file uploads remain independently deletable.
	t.Run("TestUploadIdenticalFiles", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("file", "duplicate.jsonl")
		require.NoError(t, err)
		jsonlContent := `{"custom_id": "req-1", "method": "POST", "url": "/v1/chat/completions", "body": {"model": "gpt-4.1-mini", "messages": [{"role": "user", "content": "Hello 1"}]}}` + "\n" +
			`{"custom_id": "req-2", "method": "POST", "url": "/v1/chat/completions", "body": {"model": "gpt-4.1-mini", "messages": [{"role": "user", "content": "Hello 2"}]}}` + "\n"
		_, _ = part.Write([]byte(jsonlContent))
		_ = writer.WriteField("purpose", "batch")
		_ = writer.Close()

		req, _ := http.NewRequest(http.MethodPost, "/v1/files", body)
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusCreated, rec.Code)
		var dupFile domain.CanonicalFile
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &dupFile))
		assert.NotEqual(t, uploadedFile.ID, dupFile.ID)
		assert.Equal(t, uploadedFile.ContentSHA256, dupFile.ContentSHA256)
		assert.NotEqual(t, uploadedFile.StoragePath, dupFile.StoragePath)
	})

	// 7. Test POST /v1/batches/{batch_id}/cancel
	t.Run("TestCancelBatch", func(t *testing.T) {
		cancelReq, _ := http.NewRequest(http.MethodPost, "/v1/batches/"+createdBatch.ID+"/cancel", nil)
		cancelReq.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		cancelRec := httptest.NewRecorder()
		handler.ServeHTTP(cancelRec, cancelReq)
		require.Equal(t, http.StatusOK, cancelRec.Code)

		var cancelledBatch domain.CanonicalBatch
		require.NoError(t, json.Unmarshal(cancelRec.Body.Bytes(), &cancelledBatch))
		assert.Equal(t, "cancelled", cancelledBatch.Status)
	})

	// 8. Test DELETE /v1/files/{file_id}
	t.Run("TestDeleteFile", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, "/v1/files/"+uploadedFile.ID, nil)
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var delResp map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &delResp))
		assert.Equal(t, true, delResp["deleted"])
	})
}
