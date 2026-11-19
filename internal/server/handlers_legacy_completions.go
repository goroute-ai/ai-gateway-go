package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

// handleLegacyCompletions serves `POST /v1/completions` and `POST /completions`.
func (s *GatewayServer) handleLegacyCompletions(w http.ResponseWriter, r *http.Request) {
	reqID := gatewayRequestID(r)
	w.Header().Set("X-Gateway-Request-Id", reqID)
	traceID := observability.TraceFromContext(r.Context()).TraceID

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

	var req domain.CanonicalCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse Completion request body: " + err.Error(),
		})
		return
	}
	req.RequestID = reqID
	req.Model = strings.TrimSpace(req.Model)

	if req.Model == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_model",
			Message:    "model parameter is required",
		})
		return
	}
	if len(req.Prompt.Strings) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_prompt",
			Message:    "prompt parameter cannot be empty",
		})
		return
	}

	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, req.Model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}
	guardedPrompts, err := s.guardrailTextValues(r.Context(), idCtx.OrgID, req.Prompt.Strings...)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	req.Prompt.Strings = guardedPrompts

	// Estimate each prompt with the model-family tokenizer profile and framing.
	estTokens := ratelimit.EstimateTextInputsTokens(req.Model, req.Prompt.Strings, 4)
	totalPromptChars := 0
	for _, prompt := range req.Prompt.Strings {
		totalPromptChars += len(prompt)
	}
	maxOutput := 0
	if req.MaxTokens != nil {
		maxOutput = *req.MaxTokens
	}
	qCtx, _ := withRequestQuotaState(r.Context(), r, idCtx, req.User, req.Metadata, req.GoRouteExtensions)
	r = r.WithContext(qCtx)
	origRequestedModel := req.Model
	acq, err := s.acquireQuotaWithBudgetPolicy(r.Context(), idCtx, req.Model, estTokens, totalPromptChars, maxOutput, reqID)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}
	if acq.FallbackApplied && acq.EffectiveModel != "" {
		req.Model = acq.EffectiveModel
	}
	applyBudgetPolicyHeaders(w, origRequestedModel, acq)
	releaseQuota := acq.ReleaseQuota
	releaseUsage := acq.ReleaseUsage

	if req.Stream {
		s.handleLegacyCompletionsStream(w, r, idCtx, &req, reqID, traceID, estTokens, releaseUsage)
		return
	}

	quotaSettlement := &postDispatchSettlement{
		idCtx:          idCtx,
		reqID:          reqID,
		traceID:        traceID,
		endpoint:       r.URL.Path,
		modality:       domain.ModalityCompletion,
		requestedModel: origRequestedModel,
		estTokens:      estTokens,
		reqCtx:         r.Context(),
		releaseQuota:   releaseQuota,
		releaseUsage:   releaseUsage,
	}
	defer s.settleQuotaOnReturn(quotaSettlement)

	cacheHeader := r.Header.Get("X-Gateway-Cache-Control")
	var cacheKey string
	if s.respCache != nil && s.respCache.IsCompletionCacheable(&req, cacheHeader) {
		cacheKey = s.respCache.ComputeCompletionKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), &req)
		if cacheKey != "" {
			if cachedResp, hit := s.respCache.GetCompletion(r.Context(), cacheKey); hit {
				for i := range cachedResp.Choices {
					var sanitizeErr error
					cachedResp.Choices[i].Text, sanitizeErr = s.sanitizeGuardrailText(r.Context(), idCtx.OrgID, cachedResp.Choices[i].Text)
					if sanitizeErr != nil {
						quotaSettlement.actualTokensReconciled = true
						releaseUsage(0, 0, -2)
						domain.WriteHTTPError(w, sanitizeErr)
						return
					}
				}
				quotaSettlement.actualTokensReconciled = true
				releaseUsage(0, 0, -2)
				s.collector.Record(observability.RequestObservation{
					Provider:   string(cachedResp.Provider),
					Model:      cachedResp.Model,
					StatusCode: http.StatusOK,
					CacheHit:   true,
				})
				logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
					Model:            cachedResp.Model,
					Provider:         string(cachedResp.Provider),
					PromptTokens:     cachedResp.Usage.PromptTokens,
					CompletionTokens: cachedResp.Usage.CompletionTokens,
					CostMicros:       0,
					CacheHit:         true,
				})
				w.Header().Set("X-Gateway-Cache", "HIT")
				w.Header().Set("X-Gateway-Provider", string(cachedResp.Provider))
				w.Header().Set("X-Gateway-Model", cachedResp.Model)
				w.Header().Set("X-Gateway-Cost-Micros", "0")
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(cachedResp)
				return
			}
		}
		w.Header().Set("X-Gateway-Cache", "MISS")
	}

	upstreamCtx := quotaSettlement.trackDispatch(r.Context())
	resp, meta, err := s.reliability.ExecuteCompletion(upstreamCtx, idCtx, &req)
	quotaSettlement.meta = meta
	quotaSettlement.dispatchErr = err
	if err != nil {
		s.collector.Record(observability.RequestObservation{
			StatusCode: http.StatusBadGateway,
		})
		domain.WriteHTTPError(w, err)
		return
	}
	for i := range resp.Choices {
		resp.Choices[i].Text, err = s.sanitizeGuardrailText(r.Context(), idCtx.OrgID, resp.Choices[i].Text)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	}
	if cacheKey != "" {
		s.respCache.SetCompletionWithMeta(r.Context(), cacheKey, idCtx.OrgID, resp)
	}

	var gm *domain.GlobalModel
	var depID, depName string
	var pricingVer int
	if meta != nil && meta.WinningDeployment != nil {
		depID = meta.WinningDeployment.ID
		depName = meta.WinningDeployment.DeploymentName
		gm = meta.WinningDeployment.GlobalModel
		if gm != nil {
			pricingVer = gm.PricingVersion
		}
	}

	costMicros := finops.CalculateCostMicros(gm, resp.Usage)
	quotaSettlement.actualTokensReconciled = true
	releaseUsage(resp.Usage.PromptTokens, resp.Usage.CompletionTokens, costMicros)
	pricingStatus := domain.ResolvePricingStatus(gm)

	s.collector.Record(observability.RequestObservation{
		Provider:         string(resp.Provider),
		DeploymentID:     depID,
		DeploymentName:   depName,
		Model:            resp.Model,
		StatusCode:       http.StatusOK,
		LatencyMs:        meta.LatencyMs,
		RoutingMicros:    meta.RoutingMicros,
		PromptTokens:     resp.Usage.PromptTokens,
		CompletionTokens: resp.Usage.CompletionTokens,
		CostMicros:       costMicros,
	})
	logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
		Model:            resp.Model,
		Provider:         string(resp.Provider),
		PromptTokens:     resp.Usage.PromptTokens,
		CompletionTokens: resp.Usage.CompletionTokens,
		CostMicros:       costMicros,
		CacheHit:         false,
	})

	w.Header().Set("X-Gateway-Provider", string(resp.Provider))
	w.Header().Set("X-Gateway-Model", resp.Model)
	w.Header().Set("X-Gateway-Cost-Micros", strconv.FormatInt(costMicros, 10))
	w.Header().Set("X-Gateway-Pricing-Status", string(pricingStatus))
	setRoutingTelemetryHeaders(w, meta)
	w.Header().Set("Content-Type", "application/json")

	var provenance string
	if gm != nil {
		provenance = gm.PricingProvenanceSource
	}

	if !s.persistSpendEvent(w, r, domain.SpendEvent{
		RequestID:               reqID,
		TraceID:                 traceID,
		OrgID:                   idCtx.OrgID,
		TeamID:                  idCtx.TeamID,
		UserID:                  idCtx.UserID,
		VirtualKeyID:            idCtx.VirtualKeyID,
		Endpoint:                r.URL.Path,
		RequestedModel:          req.Model,
		ResolvedModel:           resp.Model,
		Provider:                resp.Provider,
		DeploymentID:            depID,
		PricingVersion:          pricingVer,
		PricingStatus:           pricingStatus,
		PricingProvenanceSource: provenance,
		Usage:                   resp.Usage,
		CostMicros:              costMicros,
		LatencyMs:               meta.LatencyMs,
		StatusCode:              http.StatusOK,
		Modality:                domain.ModalityCompletion,
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	_ = json.NewEncoder(w).Encode(resp)

	logger.InfoContext(r.Context(), "Completion request completed",
		slog.String("component", "inference"),
		slog.String("request_id", reqID),
		slog.String("provider", string(resp.Provider)),
		slog.String("model", resp.Model),
		slog.Int("prompt_tokens", resp.Usage.PromptTokens),
		slog.Int("completion_tokens", resp.Usage.CompletionTokens),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}

func (s *GatewayServer) handleLegacyCompletionsStream(
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalCompletionRequest,
	reqID string,
	traceID string,
	estTokens int,
	releaseUsage func(actualInput, actualOutput int, overrideCostMicros int64),
) {
	releaseQuota := func(tok int) {
		if tok < 0 {
			releaseUsage(-1, -1, -1)
			return
		}
		releaseUsage(tok, 0, -2)
	}
	prc := buildGuardrailRequestContext(r, idCtx, &domain.CanonicalChatRequest{
		Model:  req.Model,
		Stream: true,
	})
	streamSession, policyErr := s.newStreamGuardrailSession(r.Context(), prc, nil)
	if policyErr != nil {
		releaseQuota(-1)
		domain.WriteHTTPError(w, policyErr)
		return
	}
	defer streamSession.Close()
	sseWriter, err := sse.NewWriter(w)
	if err != nil {
		releaseQuota(-1)
		domain.WriteHTTPError(w, err)
		return
	}

	streamCacheHeader := streamCacheControlHeader(r)
	var streamCacheKey string
	if s.respCache != nil && s.respCache.IsCompletionStreamCacheable(req, streamCacheHeader) {
		streamCacheKey = s.respCache.ComputeCompletionKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), req)
	}
	if streamCacheKey != "" {
		if cachedChunks, hit := s.respCache.GetStreamChunks(r.Context(), streamCacheKey); hit {
			resolvedModel, provider, cachedGM := s.resolveCachedStreamModelMeta(r.Context(), idCtx.OrgID, req.Model, cachedChunks)
			cachePricingStatus := domain.ResolvePricingStatus(cachedGM)
			w.Header().Set("X-Gateway-Cache", "HIT")
			if provider != "" {
				w.Header().Set("X-Gateway-Provider", string(provider))
			}
			if resolvedModel != "" {
				w.Header().Set("X-Gateway-Model", resolvedModel)
			}
			w.Header().Set("X-Gateway-Cost-Micros", "0")
			w.Header().Set("X-Gateway-Pricing-Status", string(cachePricingStatus))

			replayStarted := time.Now()
			var guardrailRedacted bool
			var guardrailBlocked bool
			var writeErr error
			for i := range cachedChunks {
				chunk := cloneSingleStreamChunk(cachedChunks[i])
				if len(chunk.Choices) > 0 {
					delta := &chunk.Choices[0].Delta
					if delta.Content != "" {
						processed, procErr := streamSession.ProcessText(r.Context(), delta.Content)
						if procErr != nil {
							if streamSession.Blocked() {
								guardrailBlocked = true
								if streamSession.Redacted() {
									guardrailRedacted = true
								}
							} else {
								writeErr = procErr
							}
							break
						}
						delta.Content = processed
						if delta.Content == "" && delta.ReasoningContent == "" && len(delta.ToolCalls) == 0 && chunk.Choices[0].FinishReason == nil && chunk.Usage == nil {
							continue
						}
					}
				}
				if writeErr = sseWriter.WriteChunk(&chunk); writeErr != nil {
					break
				}
			}
			if writeErr != nil {
				releaseQuota(0)
				s.collector.RecordStream(time.Since(replayStarted), 0, true)
				if !sseWriter.Started() {
					domain.WriteHTTPError(w, writeErr)
				} else {
					_ = sseWriter.WriteError(writeErr)
				}
				return
			}
			rem, flushErr := streamSession.Flush(r.Context(), nil)
			if streamSession.Redacted() {
				guardrailRedacted = true
			}
			if flushErr != nil || streamSession.Blocked() {
				guardrailBlocked = true
			}
			if guardrailBlocked {
				releaseQuota(0)
				s.collector.RecordStream(time.Since(replayStarted), 0, true)
				s.collector.Record(observability.RequestObservation{
					Provider:          string(provider),
					Model:             resolvedModel,
					StatusCode:        http.StatusBadGateway,
					GuardrailBlocked:  true,
					GuardrailRedacted: guardrailRedacted,
				})
				errOut := flushErr
				if errOut == nil {
					errOut = guardrailStreamBlockedError()
				}
				_ = sseWriter.WriteError(errOut)
				return
			}
			if rem != "" {
				if flushWriteErr := sseWriter.WriteChunk(&domain.CanonicalStreamChunk{
					ID:      "cmpl-" + reqID,
					Object:  "text_completion",
					Created: time.Now().Unix(),
					Model:   resolvedModel,
					Choices: []domain.CanonicalStreamChoice{{
						Index: 0,
						Delta: domain.CanonicalStreamDelta{Content: rem},
					}},
				}); flushWriteErr != nil {
					releaseQuota(0)
					_ = sseWriter.WriteError(flushWriteErr)
					return
				}
			}
			releaseQuota(0)
			usageVal := extractStreamChunksUsage(cachedChunks, estTokens)
			s.collector.RecordStream(time.Since(replayStarted), 0, false)
			s.collector.Record(observability.RequestObservation{
				Provider:          string(provider),
				Model:             resolvedModel,
				StatusCode:        http.StatusOK,
				CacheHit:          true,
				GuardrailRedacted: guardrailRedacted,
			})
			logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
				Model:            resolvedModel,
				Provider:         string(provider),
				PromptTokens:     usageVal.PromptTokens,
				CompletionTokens: usageVal.CompletionTokens,
				CostMicros:       0,
				CacheHit:         true,
			})
			var cacheProvenance string
			if cachedGM != nil {
				cacheProvenance = cachedGM.PricingProvenanceSource
			}
			if s.spendWorker != nil {
				if err := s.spendWorker.Record(r.Context(), enrichSpendEventFromContext(r.Context(), domain.SpendEvent{
					RequestID:               reqID,
					TraceID:                 traceID,
					OrgID:                   idCtx.OrgID,
					TeamID:                  idCtx.TeamID,
					UserID:                  idCtx.UserID,
					VirtualKeyID:            idCtx.VirtualKeyID,
					Endpoint:                r.URL.Path,
					RequestedModel:          req.Model,
					ResolvedModel:           resolvedModel,
					Provider:                provider,
					PricingStatus:           cachePricingStatus,
					PricingProvenanceSource: cacheProvenance,
					Usage:                   usageVal,
					CostMicros:              0,
					StatusCode:              http.StatusOK,
					CacheHit:                true,
					IsStream:                true,
					CreatedAt:               time.Now().UTC(),
				})); err != nil {
					_ = sseWriter.WriteError(&domain.GatewayError{
						StatusCode: http.StatusServiceUnavailable,
						Type:       domain.ErrorTypeServer,
						Code:       "spend_persistence_unavailable",
						Message:    "unable to persist request accounting",
					})
					return
				}
			}
			_ = sseWriter.WriteDone()
			return
		}
		w.Header().Set("X-Gateway-Cache", "MISS")
	}

	streamStarted := time.Now()
	ch, meta, err := s.reliability.ExecuteCompletionStream(r.Context(), idCtx, req)
	setRoutingTelemetryHeaders(w, meta)
	if err != nil {
		releaseQuota(-1)
		statusCode := http.StatusBadGateway
		if gwErr, ok := err.(*domain.GatewayError); ok && gwErr.StatusCode > 0 {
			statusCode = gwErr.StatusCode
		}
		var depID, depName string
		var provider domain.ProviderType
		var latMs, routeMicros int64
		var retries int
		var fb bool
		if meta != nil {
			latMs = meta.LatencyMs
			routeMicros = meta.RoutingMicros
			retries = meta.RetryCount
			fb = meta.FallbackAttempted
			if meta.WinningDeployment != nil {
				depID = meta.WinningDeployment.ID
				depName = meta.WinningDeployment.DeploymentName
				if meta.WinningDeployment.GlobalModel != nil {
					provider = meta.WinningDeployment.GlobalModel.Provider
				}
			}
		}
		s.collector.RecordStream(time.Since(streamStarted), 0, true)
		s.collector.Record(observability.RequestObservation{
			Provider:          string(provider),
			DeploymentID:      depID,
			DeploymentName:    depName,
			Model:             req.Model,
			StatusCode:        statusCode,
			LatencyMs:         latMs,
			RoutingMicros:     routeMicros,
			FallbackAttempted: fb,
			RetryCount:        retries,
		})
		domain.WriteHTTPError(w, err)
		return
	}

	var usage *domain.TokenUsage
	var guardrailRedacted bool
	var guardrailBlocked bool
	var writeErr error
	var sanitizedChunks []domain.CanonicalStreamChunk
	sawTerminalChunk := false
	for chunk := range ch {
		if isTerminalStreamChunk(&chunk) {
			sawTerminalChunk = true
		}
		if chunk.Usage != nil {
			u := *chunk.Usage
			usage = &u
		}
		c := cloneSingleStreamChunk(chunk)
		if len(c.Choices) > 0 {
			delta := &c.Choices[0].Delta
			if delta.Content != "" {
				processed, procErr := streamSession.ProcessText(r.Context(), delta.Content)
				if procErr != nil {
					if streamSession.Blocked() {
						guardrailBlocked = true
						if streamSession.Redacted() {
							guardrailRedacted = true
						}
					} else {
						writeErr = procErr
					}
					break
				}
				delta.Content = processed
				if delta.Content == "" && delta.ReasoningContent == "" && len(delta.ToolCalls) == 0 && c.Choices[0].FinishReason == nil && c.Usage == nil {
					continue
				}
			}
		}
		if writeErr = sseWriter.WriteChunk(&c); writeErr != nil {
			break
		}
		if streamCacheKey != "" {
			sanitizedChunks = appendStreamChunkBeforeTerminal(sanitizedChunks, c)
		}
	}
	if writeErr != nil {
		releaseQuota(-1)
		s.collector.RecordStream(time.Since(streamStarted), 0, true)
		if !sseWriter.Started() {
			domain.WriteHTTPError(w, writeErr)
		} else {
			_ = sseWriter.WriteError(writeErr)
		}
		return
	}

	rem, flushErr := streamSession.Flush(r.Context(), nil)
	if streamSession.Redacted() {
		guardrailRedacted = true
	}
	if flushErr != nil || streamSession.Blocked() {
		guardrailBlocked = true
	}
	if guardrailBlocked {
		releaseQuota(-1)
		var depID, depName string
		var provider domain.ProviderType
		resolvedModel := req.Model
		var latMs, ttftMs, routeMicros int64
		var retries int
		var fb bool
		if meta != nil {
			latMs = meta.LatencyMs
			ttftMs = meta.TTFTMs
			routeMicros = meta.RoutingMicros
			retries = meta.RetryCount
			fb = meta.FallbackAttempted
			if meta.WinningDeployment != nil {
				depID = meta.WinningDeployment.ID
				depName = meta.WinningDeployment.DeploymentName
				if meta.WinningDeployment.GlobalModel != nil {
					provider = meta.WinningDeployment.GlobalModel.Provider
					resolvedModel = meta.WinningDeployment.GlobalModel.ModelName
				}
			}
		}
		var streamTTFT time.Duration
		if ttftMs > 0 {
			streamTTFT = time.Duration(ttftMs) * time.Millisecond
		}
		s.collector.RecordStream(time.Since(streamStarted), streamTTFT, true)
		s.collector.Record(observability.RequestObservation{
			Provider:          string(provider),
			DeploymentID:      depID,
			DeploymentName:    depName,
			Model:             resolvedModel,
			StatusCode:        http.StatusBadGateway,
			LatencyMs:         latMs,
			TTFTMs:            ttftMs,
			RoutingMicros:     routeMicros,
			FallbackAttempted: fb,
			RetryCount:        retries,
			GuardrailBlocked:  true,
			GuardrailRedacted: guardrailRedacted,
		})
		errOut := flushErr
		if errOut == nil {
			errOut = guardrailStreamBlockedError()
		}
		_ = sseWriter.WriteError(errOut)
		return
	}
	if rem != "" {
		flushChunk := domain.CanonicalStreamChunk{
			ID:      "cmpl-" + reqID,
			Object:  "text_completion",
			Created: time.Now().Unix(),
			Model:   req.Model,
			Choices: []domain.CanonicalStreamChoice{{
				Index: 0,
				Delta: domain.CanonicalStreamDelta{Content: rem},
			}},
		}
		if flushWriteErr := sseWriter.WriteChunk(&flushChunk); flushWriteErr != nil {
			releaseQuota(-1)
			_ = sseWriter.WriteError(flushWriteErr)
			return
		}
		if streamCacheKey != "" {
			sanitizedChunks = appendStreamChunkBeforeTerminal(sanitizedChunks, flushChunk)
		}
	}

	var usageVal domain.TokenUsage
	totalTok := 0
	if usage != nil {
		usageVal = *usage
		totalTok = usage.TotalTokens
	}
	if totalTok == 0 {
		usageVal.PromptTokens = estTokens
		usageVal.TotalTokens = estTokens
		totalTok = estTokens
	}

	var gm *domain.GlobalModel
	var depID, depName string
	var provider domain.ProviderType
	var pricingVer int
	resolvedModel := req.Model
	var latMs, ttftMs, routeMicros int64
	var retries int
	var fb bool
	if meta != nil {
		latMs = meta.LatencyMs
		ttftMs = meta.TTFTMs
		routeMicros = meta.RoutingMicros
		retries = meta.RetryCount
		fb = meta.FallbackAttempted
		if meta.WinningDeployment != nil {
			depID = meta.WinningDeployment.ID
			depName = meta.WinningDeployment.DeploymentName
			gm = meta.WinningDeployment.GlobalModel
			if gm != nil {
				provider = gm.Provider
				resolvedModel = gm.ModelName
				pricingVer = gm.PricingVersion
			}
		}
	}
	if streamCacheKey != "" && !guardrailBlocked && sawTerminalChunk && len(sanitizedChunks) > 0 {
		finalizeStreamChunksForCache(sanitizedChunks, resolvedModel, usageVal)
		s.respCache.SetStreamChunks(r.Context(), streamCacheKey, idCtx.OrgID, resolvedModel, sanitizedChunks)
	}
	costMicros := finops.CalculateCostMicros(gm, usageVal)
	releaseUsage(usageVal.PromptTokens, usageVal.CompletionTokens, costMicros)

	var streamTTFT time.Duration
	if ttftMs > 0 {
		streamTTFT = time.Duration(ttftMs) * time.Millisecond
	}
	s.collector.RecordStream(time.Since(streamStarted), streamTTFT, false)
	s.collector.Record(observability.RequestObservation{
		Provider:          string(provider),
		DeploymentID:      depID,
		DeploymentName:    depName,
		Model:             resolvedModel,
		StatusCode:        http.StatusOK,
		LatencyMs:         latMs,
		TTFTMs:            ttftMs,
		RoutingMicros:     routeMicros,
		PromptTokens:      usageVal.PromptTokens,
		CompletionTokens:  usageVal.CompletionTokens,
		CostMicros:        costMicros,
		FallbackAttempted: fb,
		RetryCount:        retries,
		GuardrailRedacted: guardrailRedacted,
	})
	logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
		Model:            resolvedModel,
		Provider:         string(provider),
		PromptTokens:     usageVal.PromptTokens,
		CompletionTokens: usageVal.CompletionTokens,
		CostMicros:       costMicros,
		CacheHit:         false,
	})

	var provenance string
	if gm != nil {
		provenance = gm.PricingProvenanceSource
	}
	if s.spendWorker != nil {
		if err := s.spendWorker.Record(r.Context(), enrichSpendEventFromContext(r.Context(), domain.SpendEvent{
			RequestID:               reqID,
			TraceID:                 traceID,
			OrgID:                   idCtx.OrgID,
			TeamID:                  idCtx.TeamID,
			UserID:                  idCtx.UserID,
			VirtualKeyID:            idCtx.VirtualKeyID,
			Endpoint:                r.URL.Path,
			RequestedModel:          req.Model,
			ResolvedModel:           resolvedModel,
			Provider:                provider,
			DeploymentID:            depID,
			PricingVersion:          pricingVer,
			PricingStatus:           domain.ResolvePricingStatus(gm),
			PricingProvenanceSource: provenance,
			Usage:                   usageVal,
			CostMicros:              costMicros,
			LatencyMs:               latMs,
			TTFTMs:                  ttftMs,
			StatusCode:              http.StatusOK,
			IsStream:                true,
			FallbackAttempted:       fb,
			RetryCount:              retries,
			CreatedAt:               time.Now().UTC(),
		})); err != nil {
			_ = sseWriter.WriteError(&domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "spend_persistence_unavailable",
				Message:    "unable to persist request accounting",
			})
			return
		}
	}

	_ = sseWriter.WriteDone()
	logger.InfoContext(r.Context(), "Completion stream completed",
		slog.String("component", "inference"),
		slog.String("request_id", reqID),
		slog.String("provider", string(provider)),
		slog.String("requested_model", req.Model),
		slog.String("resolved_model", resolvedModel),
		slog.Int("prompt_tokens", usageVal.PromptTokens),
		slog.Int("completion_tokens", usageVal.CompletionTokens),
		slog.Int("total_tokens", totalTok),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", latMs),
		slog.Bool("stream", true),
	)
}
