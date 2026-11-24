package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
)

const maxBatchJSONLRecordBytes = 4 << 20
const maxBatchOutputBytes = 512 << 20

type createBatchPayload struct {
	InputFileID      string         `json:"input_file_id"`
	Endpoint         string         `json:"endpoint"`
	CompletionWindow string         `json:"completion_window"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// handleCreateBatch serves `POST /v1/batches` and `POST /batches`.
func (s *GatewayServer) handleCreateBatch(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Missing virtual key identity context",
		})
		return
	}

	var payload createBatchPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse batch request: " + err.Error(),
		})
		return
	}

	if strings.TrimSpace(payload.InputFileID) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_input_file_id",
			Message:    "input_file_id is required",
		})
		return
	}

	if strings.TrimSpace(payload.Endpoint) == "" {
		payload.Endpoint = "/v1/chat/completions"
	}
	if strings.TrimSpace(payload.CompletionWindow) == "" {
		payload.CompletionWindow = "24h"
	}
	if payload.Endpoint != "/v1/chat/completions" && payload.Endpoint != "/chat/completions" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "unsupported_batch_endpoint", Message: "Only chat completions batch requests are currently supported"})
		return
	}
	if payload.CompletionWindow != "24h" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "unsupported_completion_window", Message: "completion_window must be 24h"})
		return
	}
	logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
		Provider: "batches",
		Model:    payload.Endpoint,
	})

	// 1. Verify input file belongs to tenant
	inputFile, err := s.repo.GetFile(r.Context(), idCtx.OrgID, payload.InputFileID)
	if err != nil || inputFile == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "file_not_found",
			Message:    fmt.Sprintf("Input file %s not found for this organization", payload.InputFileID),
		})
		return
	}
	if inputFile.Purpose != "batch" || inputFile.Status != "uploaded" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_batch_input_file", Message: "input_file_id must reference an uploaded file with purpose 'batch'"})
		return
	}

	est, err := s.estimateBatchInput(r.Context(), idCtx, inputFile.StoragePath)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	batchID := "batch-" + uuid.NewString()
	if s.limiter != nil {
		if err := s.limiter.AcquireBatchEnqueuedTokens(r.Context(), idCtx, batchID, est.estimatedTokens); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	}

	var releaseBudget func(actualTokens int, overrideCostMicros int64)
	var batchRLMeta *domain.RateLimitHeaderMetadata
	if identityHasBudget(idCtx) && s.limiter != nil {
		rawRelease, meta, err := s.limiter.AcquireWithBudgetAndMeta(r.Context(), idCtx, 1, est.reservedCostMicros, batchID)
		if err != nil {
			_ = s.limiter.ReleaseBatchEnqueuedTokens(context.Background(), idCtx, batchID)
			domain.WriteHTTPError(w, err)
			return
		}
		batchRLMeta = meta
		releaseBudget = s.wrapBudgetRelease(context.Background(), idCtx, batchID, rawRelease)
	} else if s.limiter != nil {
		rawRel, meta, err := s.limiter.AcquireWithMeta(r.Context(), idCtx, 1)
		if err != nil {
			_ = s.limiter.ReleaseBatchEnqueuedTokens(context.Background(), idCtx, batchID)
			domain.WriteHTTPError(w, err)
			return
		}
		batchRLMeta = meta
		rawRel(1)
	}
	domain.WriteRateLimitHeaders(w, batchRLMeta)

	rollbackBatchQuotas := func() {
		if releaseBudget != nil {
			releaseBudget(-1, -1)
		}
		if s.limiter != nil {
			_ = s.limiter.ReleaseBatchEnqueuedTokens(context.Background(), idCtx, batchID)
		}
	}

	batch := &domain.CanonicalBatch{
		ID:                 batchID,
		OrgID:              idCtx.OrgID,
		TeamID:             idCtx.TeamID,
		InputFileID:        inputFile.ID,
		Endpoint:           payload.Endpoint,
		Status:             "validating",
		CompletionWindow:   payload.CompletionWindow,
		CreatedAt:          time.Now().UTC(),
		Metadata:           payload.Metadata,
		EstimatedTokens:    est.estimatedTokens,
		ReservedCostMicros: est.reservedCostMicros,
		RequestCounts: domain.BatchCounts{
			Total:     0,
			Completed: 0,
			Failed:    0,
		},
	}

	if err := s.repo.CreateBatch(r.Context(), batch); err != nil {
		rollbackBatchQuotas()
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "db_error",
			Message:    "Failed to create batch: " + err.Error(),
		})
		return
	}

	respBytes, err := json.Marshal(batch)
	if err != nil {
		rollbackBatchQuotas()
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "marshal_error",
			Message:    "Failed to encode batch response",
		})
		return
	}

	// Launch background processor only after snapshotting the initial batch response
	// so background field mutations cannot race with JSON serialization.
	quotaHeaders := cloneBatchRoutingHeaders(r.Header)
	batchCtx := context.Background()
	if idCtx != nil {
		batchCtx = auth.WithIdentity(batchCtx, idCtx)
	}
	go s.processBatchAsync(batchCtx, idCtx, batch, inputFile, releaseBudget, quotaHeaders)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(respBytes)
}

// handleListBatches serves `GET /v1/batches` and `GET /batches`.
func (s *GatewayServer) handleListBatches(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Missing virtual key identity context",
		})
		return
	}

	batches, err := s.repo.ListBatches(r.Context(), idCtx.OrgID, 100)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "db_error",
			Message:    err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":   batches,
		"object": "list",
	})
}

// handleGetBatch serves `GET /v1/batches/{batch_id}` and `GET /batches/{batch_id}`.
func (s *GatewayServer) handleGetBatch(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Missing virtual key identity context",
		})
		return
	}

	batchID := chi.URLParam(r, "batch_id")
	b, err := s.repo.GetBatch(r.Context(), idCtx.OrgID, batchID)
	if err != nil || b == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "batch_not_found",
			Message:    fmt.Sprintf("Batch %s not found", batchID),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b)
}

// handleCancelBatch serves `POST /v1/batches/{batch_id}/cancel` and `POST /batches/{batch_id}/cancel`.
func (s *GatewayServer) handleCancelBatch(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Missing virtual key identity context",
		})
		return
	}

	batchID := chi.URLParam(r, "batch_id")
	b, err := s.repo.GetBatch(r.Context(), idCtx.OrgID, batchID)
	if err != nil || b == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "batch_not_found",
			Message:    fmt.Sprintf("Batch %s not found", batchID),
		})
		return
	}

	now := time.Now().UTC()
	b.Status = "cancelled"
	b.CompletedAt = &now
	if err := s.repo.UpdateBatchStatus(r.Context(), batchID, "cancelled", "", b.RequestCounts, &now); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "batch_update_failed", Message: "Failed to persist batch cancellation"})
		return
	}
	if s.limiter != nil {
		if relErr := s.limiter.ReleaseBatchEnqueuedTokens(r.Context(), idCtx, b.ID); relErr != nil {
			logger.Warn("Failed to release batch enqueued token hold on cancel", "batch_id", b.ID, "error", relErr.Error())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b)
}

type batchInputEstimate struct {
	validRequests      int
	estimatedTokens    int64
	reservedCostMicros int64
}

func (s *GatewayServer) resolveModelMaxOutputTokens(ctx context.Context, orgID, model string) int {
	if s == nil || s.repo == nil {
		return 0
	}
	if gm, _, err := s.resolveMatchedVerifiedModel(ctx, orgID, model); err == nil && gm != nil && gm.MaxOutputTokens > 0 {
		return gm.MaxOutputTokens
	}
	_, bareModel, canonicalID := config.ParseProviderModel(model)
	models, err := s.budgetModelCandidates(ctx, "", model)
	if err != nil {
		return 0
	}
	maxOut := 0
	for _, gm := range models {
		if gm == nil {
			continue
		}
		if gm.ID == model || gm.ID == canonicalID || gm.ModelName == model || (bareModel != "" && gm.ModelName == bareModel) {
			if gm.MaxOutputTokens > maxOut {
				maxOut = gm.MaxOutputTokens
			}
		}
	}
	return maxOut
}

func (s *GatewayServer) estimateBatchInput(ctx context.Context, idCtx *domain.IdentityContext, storagePath string) (batchInputEstimate, error) {
	diskFile, err := os.Open(storagePath)
	if err != nil {
		return batchInputEstimate{}, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_batch_input_file",
			Message:    "Failed to open batch input file: " + err.Error(),
		}
	}
	defer diskFile.Close()

	const maxInt64 = int64(^uint64(0) >> 1)
	scanner := bufio.NewScanner(diskFile)
	scanner.Buffer(make([]byte, 64*1024), maxBatchJSONLRecordBytes)

	var est batchInputEstimate
	modelMaxOutCache := make(map[string]int)
	budgeted := identityHasBudget(idCtx)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var item struct {
			CustomID string                      `json:"custom_id"`
			Method   string                      `json:"method"`
			URL      string                      `json:"url"`
			Body     domain.CanonicalChatRequest `json:"body"`
		}
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		est.validRequests++

		reqModel := strings.TrimSpace(item.Body.Model)
		if reqModel == "" {
			reqModel = "auto"
		}
		reqMaxOut := 0
		if item.Body.MaxTokens != nil {
			if *item.Body.MaxTokens < 0 {
				return batchInputEstimate{}, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "invalid_max_tokens",
					Message:    "max_tokens in batch request cannot be negative",
				}
			}
			reqMaxOut = *item.Body.MaxTokens
		}

		inputTokens := ratelimit.EstimateRequestTokens(&item.Body)
		effMaxOut := reqMaxOut
		if effMaxOut == 0 {
			cachedOut, ok := modelMaxOutCache[reqModel]
			if !ok {
				cachedOut = s.resolveModelMaxOutputTokens(ctx, idCtx.OrgID, reqModel)
				modelMaxOutCache[reqModel] = cachedOut
			}
			effMaxOut = cachedOut
		}

		lineTokens := int64(inputTokens) + int64(effMaxOut)
		if lineTokens > maxInt64-est.estimatedTokens {
			return batchInputEstimate{}, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "batch_token_estimate_overflow",
				Message:    "Batch total estimated tokens exceed supported range",
			}
		}
		est.estimatedTokens += lineTokens

		if budgeted {
			budgetInputTokens := inputTokens
			if encoded, encodeErr := json.Marshal(item.Body); encodeErr != nil {
				return batchInputEstimate{}, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeBudgetExceeded,
					Code:       "budget_estimate_unavailable",
					Message:    "A safe upper-bound cost could not be calculated before dispatch",
				}
			} else if len(encoded) > budgetInputTokens {
				budgetInputTokens = len(encoded)
			}

			lineCost, costErr := s.tokenBudgetUpperBound(ctx, idCtx.OrgID, reqModel, budgetInputTokens, reqMaxOut)
			if costErr != nil {
				if errors.Is(costErr, errBudgetPricingUnverified) {
					return batchInputEstimate{}, &domain.GatewayError{
						StatusCode: http.StatusForbidden,
						Type:       domain.ErrorTypeBudgetExceeded,
						Code:       "pricing_unknown_budget_restricted",
						Message:    "Budgeted requests require known model pricing",
					}
				}
				return batchInputEstimate{}, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeBudgetExceeded,
					Code:       "budget_estimate_unavailable",
					Message:    "A safe upper-bound cost could not be calculated before dispatch",
				}
			}
			if lineCost > maxInt64-est.reservedCostMicros {
				return batchInputEstimate{}, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeBudgetExceeded,
					Code:       "budget_estimate_unavailable",
					Message:    "Batch upper-bound budget estimate exceeds supported range",
				}
			}
			est.reservedCostMicros += lineCost
		}
	}

	if scanner.Err() != nil {
		return batchInputEstimate{}, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_batch_input_file",
			Message:    "Failed to scan batch input file: " + scanner.Err().Error(),
		}
	}
	if est.validRequests == 0 {
		return batchInputEstimate{}, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_batch_input_file",
			Message:    "Batch input file contains no valid JSONL requests",
		}
	}
	return est, nil
}

// The batch holds legacy budgets and enqueued tokens at submission. Each item
// acquires its model and window descriptors immediately before provider dispatch.
func (s *GatewayServer) acquireBatchItemQuota(ctx context.Context, id *domain.IdentityContext, req *domain.CanonicalChatRequest, requestID string) (func(int, int, int64), error) {
	if s.limiter == nil {
		return func(int, int, int64) {}, nil
	}
	desc, err := s.buildExtendedQuotaDescriptors(ctx, id, req.Model, s.nowUTC())
	if err != nil {
		return nil, descriptorLookupError(err)
	}
	if len(desc) == 0 {
		return func(int, int, int64) {}, nil
	}
	estInput := ratelimit.EstimateRequestTokens(req)
	requestedOutput := 0
	if req.MaxTokens != nil {
		requestedOutput = *req.MaxTokens
	}
	estOutput := requestedOutput
	if estOutput == 0 {
		estOutput = s.resolveModelMaxOutputTokens(ctx, id.OrgID, req.Model)
	}
	var reserve int64
	if descriptorsHaveBudget(desc) {
		body, err := json.Marshal(req)
		if err != nil {
			return nil, requestBudgetEstimateError(err)
		}
		reserve, err = s.tokenBudgetUpperBound(ctx, id.OrgID, req.Model, max(estInput, len(body)), requestedOutput)
		if err != nil {
			return nil, requestBudgetEstimateError(err)
		}
	}
	release, err := s.reserveExtendedQuota(ctx, id.OrgID, requestID, estInput, estOutput, reserve, desc)
	if err != nil {
		return nil, err
	}
	stopRenewer := s.startReservationLeaseRenewerWithDescriptors(ctx, &domain.IdentityContext{OrgID: id.OrgID}, desc, requestID)
	return func(input, output int, cost int64) {
		stopRenewer()
		release(input, output, cost)
	}, nil
}

func (s *GatewayServer) processBatchAsync(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	batch *domain.CanonicalBatch,
	inputFile *domain.CanonicalFile,
	releaseBudget func(actualTokens int, overrideCostMicros int64),
	quotaHeaders http.Header,
) {
	totalActualTokens := 0
	totalCostMicros := int64(0)
	defer func() {
		if s.limiter != nil {
			_ = s.limiter.ReleaseBatchEnqueuedTokens(context.Background(), idCtx, batch.ID)
		}
		if releaseBudget != nil {
			if s.spendWorker != nil {
				releaseBudget(-1, -1)
			} else if totalActualTokens > 0 || totalCostMicros > 0 {
				releaseBudget(totalActualTokens, totalCostMicros)
			} else {
				releaseBudget(-1, -1)
			}
		}
	}()

	now := time.Now().UTC()
	_ = s.repo.UpdateBatchStatus(ctx, batch.ID, "in_progress", "", batch.RequestCounts, nil)

	if batch.CompletionWindow == "24h" && !batch.CreatedAt.IsZero() && now.Sub(batch.CreatedAt) > 24*time.Hour {
		_ = s.repo.UpdateBatchStatus(ctx, batch.ID, "expired", "", batch.RequestCounts, &now)
		return
	}

	diskFile, err := os.Open(inputFile.StoragePath)
	if err != nil {
		_ = s.repo.UpdateBatchStatus(ctx, batch.ID, "failed", "", batch.RequestCounts, &now)
		return
	}
	defer diskFile.Close()

	outBuf := &bytes.Buffer{}
	scanner := bufio.NewScanner(diskFile)
	scanner.Buffer(make([]byte, 64*1024), maxBatchJSONLRecordBytes)
	counts := domain.BatchCounts{}
	outputOverflow := false
	var spendPersistErr error
	appendOutput := func(line []byte) bool {
		if outBuf.Len()+len(line)+1 > maxBatchOutputBytes {
			outputOverflow = true
			return false
		}
		_, _ = outBuf.Write(line)
		_ = outBuf.WriteByte('\n')
		return true
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 1. Check if batch has been cancelled
		currBatch, getErr := s.repo.GetBatch(ctx, batch.OrgID, batch.ID)
		if getErr == nil && currBatch != nil && currBatch.Status == "cancelled" {
			logger.Info("Batch processing aborted due to cancellation", "batch_id", batch.ID)
			return
		}

		counts.Total++

		var item struct {
			CustomID string                      `json:"custom_id"`
			Method   string                      `json:"method"`
			URL      string                      `json:"url"`
			Body     domain.CanonicalChatRequest `json:"body"`
		}
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			counts.Failed++
			continue
		}

		// 2. Check model-scope authorization and custom authorizer for this line item
		if err := s.rbac.AuthorizeRequestedModel(idCtx, item.Body.Model); err != nil {
			counts.Failed++
			errItem := map[string]any{
				"id":        "batch_req_" + uuid.NewString(),
				"custom_id": item.CustomID,
				"response":  map[string]any{"status_code": http.StatusForbidden},
				"error": map[string]any{
					"message": err.Error(),
					"code":    "model_not_permitted",
				},
			}
			eb, _ := json.Marshal(errItem)
			if !appendOutput(eb) {
				break
			}
			continue
		}
		if s.customAuthorizer != nil {
			itemMethod := strings.TrimSpace(item.Method)
			if itemMethod == "" {
				itemMethod = http.MethodPost
			}
			itemPath := strings.TrimSpace(item.URL)
			if itemPath == "" {
				itemPath = "/v1/chat/completions"
			}
			if err := s.evaluateCustomAuthorizer(ctx, &auth.AuthzRequest{
				Identity:     idCtx,
				Action:       auth.AuthzActionInference,
				ResourceType: "model",
				ResourceID:   item.Body.Model,
				Model:        item.Body.Model,
				HTTPMethod:   itemMethod,
				HTTPPath:     itemPath,
			}); err != nil {
				counts.Failed++
				errCode := "custom_authorization_denied"
				statusCode := http.StatusForbidden
				var gwErr *domain.GatewayError
				if errors.As(err, &gwErr) && gwErr != nil {
					if gwErr.Code != "" {
						errCode = gwErr.Code
					}
					if gwErr.StatusCode > 0 {
						statusCode = gwErr.StatusCode
					}
				}
				if !appendOutput(marshalBatchErrorEntry(item.CustomID, statusCode, errCode, err.Error())) {
					break
				}
				continue
			}
		}
		itemReq := (&http.Request{Header: quotaHeaders.Clone()}).WithContext(ctx)
		if gwErr := s.applyChatRoutingHints(itemReq, idCtx, &item.Body); gwErr != nil {
			counts.Failed++
			code := gwErr.Code
			if code == "" {
				code = "invalid_routing_hints"
			}
			if !appendOutput(marshalBatchErrorEntry(item.CustomID, gwErr.StatusCode, code, gwErr.Message)) {
				break
			}
			continue
		}
		origItemModel := item.Body.Model
		prc, _, guardrailErr := s.evaluateChatInputGuardrails(ctx, nil, itemReq, idCtx, &item.Body, "batch_item")
		if guardrailErr != nil {
			counts.Failed++
			status, code, msg := http.StatusBadRequest, "guardrail_rejected", "Request rejected by organization guardrail policy"
			var gwErr *domain.GatewayError
			if errors.As(guardrailErr, &gwErr) {
				if gwErr.StatusCode != 0 {
					status = gwErr.StatusCode
				}
				if gwErr.Code != "" {
					code = gwErr.Code
				}
				if gwErr.StatusCode < http.StatusInternalServerError && gwErr.Message != "" {
					msg = gwErr.Message
				}
			}
			if !appendOutput(marshalBatchErrorEntry(item.CustomID, status, code, msg)) {
				break
			}
			continue
		}

		itemCtx, quotaState := withRequestQuotaState(ctx, itemReq, idCtx, item.Body.User, item.Body.Metadata, item.Body.GoRouteExtensions)
		itemRequestID := "batch_item_" + uuid.NewString()
		item.Body.RequestID = itemRequestID
		prc.RequestID = itemRequestID
		releaseItemQuota, quotaErr := s.acquireBatchItemQuota(itemCtx, idCtx, &item.Body, itemRequestID)
		if quotaErr != nil {
			counts.Failed++
			status, code := http.StatusServiceUnavailable, "quota_policy_unavailable"
			var gwErr *domain.GatewayError
			if errors.As(quotaErr, &gwErr) {
				status, code = gwErr.StatusCode, gwErr.Code
			}
			if !appendOutput(marshalBatchErrorEntryWithID(itemRequestID, item.CustomID, status, code, quotaErr.Error())) {
				break
			}
			continue
		}

		spendRequestID := batch.ID + "_" + item.CustomID
		quotaState.SettlementRequestID = spendRequestID
		resp, meta, err := s.executeBatchItemChat(itemCtx, ctx, idCtx, prc, &item.Body)
		if err != nil {
			releaseItemQuota(-1, -1, -1)
			counts.Failed++
			status := 0
			code, msg := "batch_request_failed", err.Error()
			var gwErr *domain.GatewayError
			if errors.As(err, &gwErr) && gwErr.StatusCode != 0 {
				status = gwErr.StatusCode
				if gwErr.Code != "" {
					code = gwErr.Code
				}
				if gwErr.Message != "" {
					msg = gwErr.Message
				}
			}
			if !appendOutput(marshalBatchErrorEntry(item.CustomID, status, code, msg)) {
				break
			}
		} else {
			var gm *domain.GlobalModel
			var depID string
			var pricingVer int
			if meta != nil && meta.WinningDeployment != nil {
				depID = meta.WinningDeployment.ID
				gm = meta.WinningDeployment.GlobalModel
				if gm != nil {
					pricingVer = gm.PricingVersion
				}
			}
			costMicros := finops.CalculateCostMicros(gm, resp.Usage)
			releaseItemQuota(resp.Usage.PromptTokens, resp.Usage.CompletionTokens, costMicros)
			totalActualTokens += resp.Usage.TotalTokens
			totalCostMicros += costMicros
			_, sanitizeErr := s.evaluateChatOutputGuardrails(itemCtx, nil, prc, resp, "batch_item")
			if sanitizeErr == nil {
				s.GuardrailPipeline().EvaluateLoggingOnly(itemCtx, prc, &item.Body, resp)
			}
			status := http.StatusOK
			if sanitizeErr != nil {
				status = http.StatusServiceUnavailable
				var gwErr *domain.GatewayError
				if errors.As(sanitizeErr, &gwErr) && gwErr.StatusCode != 0 {
					status = gwErr.StatusCode
				}
			}
			if s.spendWorker != nil {
				spendPersistErr = s.spendWorker.Record(itemCtx, enrichSpendEventFromContext(itemCtx, domain.SpendEvent{
					ID:             "sp_" + uuid.NewString(),
					RequestID:      spendRequestID,
					OrgID:          idCtx.OrgID,
					TeamID:         idCtx.TeamID,
					ProjectID:      idCtx.ProjectID,
					UserID:         idCtx.UserID,
					VirtualKeyID:   idCtx.VirtualKeyID,
					Endpoint:       "/v1/batches",
					Modality:       domain.ModalityBatch,
					RequestedModel: origItemModel,
					ResolvedModel:  resp.Model,
					DeploymentID:   depID,
					PricingVersion: pricingVer,
					Usage:          resp.Usage,
					CostMicros:     costMicros,
					StatusCode:     status,
					CreatedAt:      time.Now().UTC(),
				}))
				if spendPersistErr != nil {
					counts.Failed++
					break
				}
			}
			if sanitizeErr != nil {
				counts.Failed++
				code, msg := "guardrail_policy_unavailable", "Response withheld by organization guardrail policy"
				var gwErr *domain.GatewayError
				if errors.As(sanitizeErr, &gwErr) {
					if gwErr.Code != "" {
						code = gwErr.Code
					}
					if gwErr.StatusCode < http.StatusInternalServerError && gwErr.Message != "" {
						msg = gwErr.Message
					}
				}
				if !appendOutput(marshalBatchErrorEntry(item.CustomID, status, code, msg)) {
					break
				}
				continue
			}
			counts.Completed++
			succItem := map[string]any{
				"id":        "batch_req_" + uuid.NewString(),
				"custom_id": item.CustomID,
				"response": map[string]any{
					"status_code": 200,
					"request_id":  resp.ID,
					"body":        resp,
				},
				"error": nil,
			}
			sb, _ := json.Marshal(succItem)
			if !appendOutput(sb) {
				break
			}
		}
	}
	if scanner.Err() != nil || outputOverflow || spendPersistErr != nil {
		finishedAt := time.Now().UTC()
		message := "batch input contains a JSONL record larger than the supported limit"
		if scanner.Err() != nil {
			message = "failed to scan batch input: " + scanner.Err().Error()
		} else if spendPersistErr != nil {
			message = "failed to persist spend event: " + spendPersistErr.Error()
		}
		_ = s.repo.UpdateBatchStatus(ctx, batch.ID, "failed", "", counts, &finishedAt)
		logger.Error("Batch processing failed", "batch_id", batch.ID, "error", message)
		return
	}

	// Create Output File
	outBytes := outBuf.Bytes()
	outHasher := sha256.New()
	outHasher.Write(outBytes)
	outSHA := hex.EncodeToString(outHasher.Sum(nil))

	outID := "file-" + uuid.NewString()
	outPath := filepath.Join(getStorageDir(), outID)
	if err := os.WriteFile(outPath, outBytes, 0600); err != nil {
		finishedAt := time.Now().UTC()
		_ = s.repo.UpdateBatchStatus(ctx, batch.ID, "failed", "", counts, &finishedAt)
		logger.Error("Failed to persist batch output", "batch_id", batch.ID, "error", err)
		return
	}

	outFile := &domain.CanonicalFile{
		ID:            outID,
		OrgID:         batch.OrgID,
		TeamID:        batch.TeamID,
		Bytes:         int64(len(outBytes)),
		CreatedAt:     time.Now().UTC(),
		Filename:      batch.ID + "_output.jsonl",
		Purpose:       "batch_output",
		Status:        "processed",
		ContentSHA256: outSHA,
		StoragePath:   outPath,
	}
	if err := s.repo.CreateFile(ctx, outFile); err != nil {
		_ = os.Remove(outPath)
		finishedAt := time.Now().UTC()
		_ = s.repo.UpdateBatchStatus(ctx, batch.ID, "failed", "", counts, &finishedAt)
		logger.Error("Failed to persist batch output metadata", "batch_id", batch.ID, "error", err)
		return
	}

	finishedAt := time.Now().UTC()
	if cur, curErr := s.repo.GetBatch(ctx, batch.OrgID, batch.ID); curErr == nil && cur != nil && cur.Status == "cancelled" {
		_ = os.Remove(outPath)
		return
	}
	batch.Status = "completed"
	batch.OutputFileID = outID
	batch.RequestCounts = counts
	batch.CompletedAt = &finishedAt
	if err := s.repo.UpdateBatchStatus(ctx, batch.ID, "completed", outID, counts, &finishedAt); err != nil {
		logger.Error("Failed to persist batch completion", "batch_id", batch.ID, "error", err)
		return
	}

	logger.Info("Batch processing completed",
		"component", "batches",
		"batch_id", batch.ID,
		"total", counts.Total,
		"completed", counts.Completed,
		"failed", counts.Failed,
	)
}

func (s *GatewayServer) executeBatchItemChat(
	itemCtx context.Context,
	baseCtx context.Context,
	idCtx *domain.IdentityContext,
	prc guardrails.PipelineRequestContext,
	body *domain.CanonicalChatRequest,
) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
	upstreamCtx, duringHandle, duringInitErr := s.startDuringCallGuardrails(itemCtx, prc, body)
	if duringInitErr != nil {
		return nil, nil, duringInitErr
	}
	if duringHandle != nil {
		defer duringHandle.Close()
	}
	resp, meta, err := s.reliability.ExecuteChat(upstreamCtx, idCtx, body)
	if _, duringErr := duringHandle.Wait(baseCtx); duringErr != nil {
		return nil, meta, duringErr
	}
	return resp, meta, err
}

func cloneBatchRoutingHeaders(src http.Header) http.Header {
	out := make(http.Header)
	if src == nil {
		return out
	}
	allowed := map[string]bool{
		"X-Gateway-Session-Id":              true,
		"X-Gateway-Client-App":              true,
		"X-Gateway-Tags":                    true,
		"X-Gateway-Allowed-Region":          true,
		"X-Gateway-Preferred-Deployment-Id": true,
		"X-Gateway-Priority":                true,
		"X-Gateway-Hedge-After-Ms":          true,
		"X-Gateway-Drop-Params":             true,
		"X-Gateway-Routing-Strategy":        true,
	}
	for k, vals := range src {
		ck := http.CanonicalHeaderKey(k)
		if allowed[ck] || strings.HasPrefix(strings.ToLower(k), "x-gateway-tag-") {
			for _, v := range vals {
				out.Add(k, v)
			}
		}
	}
	return out
}

func marshalBatchErrorEntry(customID string, status int, code, message string) []byte {
	return marshalBatchErrorEntryWithID("batch_req_"+uuid.NewString(), customID, status, code, message)
}

func marshalBatchErrorEntryWithID(id, customID string, status int, code, message string) []byte {
	var respObj any
	if status > 0 {
		respObj = map[string]any{"status_code": status}
	}
	b, _ := json.Marshal(map[string]any{
		"id":        id,
		"custom_id": customID,
		"response":  respObj,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
	return b
}
