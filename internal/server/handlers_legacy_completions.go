package server

import (
	"context"
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
	"github.com/goroute-ai/ai-gateway-go/internal/router"
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
	if gwErr := decodeBoundedJSON(w, r, maxChatCompletionBodyBytes, &req, "Failed to parse Completion request body"); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
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

	// 1. RBAC Model Allowlist + Custom Authorizer Check
	if err := s.authorizeInferenceModel(r.Context(), idCtx, req.Model, r.Method, r.URL.Path); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}
	if gwErr := s.applyRoutingHints(r, idCtx, &req.GoRouteExtensions); gwErr != nil {
		s.collector.Record(admissionFailureObservation(gwErr))
		domain.WriteHTTPError(w, gwErr)
		return
	}
	guardedPrompts, err := s.evaluateNonChatTextGuardrails(r.Context(), w, r, idCtx, &req.Model, req.GoRouteExtensions, "completion", req.Prompt.Strings...)
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

	cacheOpts := requestCacheOptions(r)
	var cacheKey string
	if s.respCache != nil && s.respCache.IsCompletionCacheable(&req, cacheOpts) {
		cacheKey = s.respCache.ComputeCompletionKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), &req)
		if cacheKey != "" {
			cacheSpanCtx, cacheSpan := observability.StartCacheLookupSpan(r.Context(), s.tracer, s.respCache.Type(), req.Model)
			cachedResp, hit := s.respCache.GetCompletion(cacheSpanCtx, idCtx.OrgID, cacheKey)
			hitType := ""
			if hit {
				hitType = "exact"
			}
			observability.FinishCacheLookupSpan(cacheSpan, hit, hitType, 0, nil)
			if hit {
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
				setCacheHitHeaders(w, "exact", 0)
				w.Header().Set("X-Gateway-Provider", string(cachedResp.Provider))
				w.Header().Set("X-Gateway-Model", cachedResp.Model)
				w.Header().Set("X-Gateway-Cost-Micros", "0")
				w.Header().Set("Content-Type", "application/json")
				if !s.recordCacheHitSpendAudit(w, r, idCtx, "/v1/completions", domain.ModalityCompletion, origRequestedModel, reqID, traceID, cachedResp.Provider, cachedResp.Model, cachedResp.Usage) {
					return
				}
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
		s.emitRoutingTelemetryAndDebugHeaders(w, r, meta)
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
		s.respCache.SetCompletionWithMeta(r.Context(), cacheKey, idCtx.OrgID, resp, origRequestedModel)
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
	s.emitRoutingTelemetryAndDebugHeaders(w, r, meta)
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
	streamSession, policyErr := s.newStreamGuardrailSession(r.Context(), prc)
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

	streamStarted := time.Now()
	onSelected := func(dep *domain.Deployment) {
		setPreStreamSelectedHeaders(w, dep, sseWriter.Started())
	}
	upstreamCtx := attachStreamDroppedParamsObserver(r.Context(), w, sseWriter.Started)
	ch, meta, err := s.reliability.ExecuteCompletionStreamWithCallback(upstreamCtx, idCtx, req, onSelected)
	s.emitRoutingTelemetryAndDebugHeaders(w, r, meta)
	if err != nil {
		s.writeLegacyStreamExecError(w, req.Model, streamStarted, meta, err, sseWriter, releaseQuota)
		return
	}

	var usage *domain.TokenUsage
	var guardrailRedacted, guardrailBlocked bool
	var writeErr error
	for chunk := range ch {
		if chunk.Usage != nil {
			u := *chunk.Usage
			usage = &u
		}
		_, blocked, redacted, cerr := writeFilteredLegacyStreamChunk(r.Context(), streamSession, sseWriter, chunk)
		if redacted {
			guardrailRedacted = true
		}
		if blocked {
			guardrailBlocked = true
			break
		}
		if cerr != nil {
			writeErr = cerr
			break
		}
	}
	if writeErr != nil {
		releaseQuota(-1)
		s.collector.RecordStream(time.Since(streamStarted), 0, true)
		writeLegacyStreamTransportError(w, sseWriter, writeErr)
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
		s.writeLegacyStreamGuardrailBlock(req.Model, streamStarted, meta, flushErr, guardrailRedacted, sseWriter, releaseQuota)
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
	}

	s.finalizeLegacyStreamSuccess(
		r, idCtx, req, reqID, traceID, estTokens,
		streamStarted, meta, usage, guardrailRedacted,
		sseWriter, releaseUsage,
	)
}

func writeFilteredLegacyStreamChunk(
	ctx context.Context,
	streamSession *streamGuardrailSession,
	sseWriter *sse.Writer,
	raw domain.CanonicalStreamChunk,
) (emitted *domain.CanonicalStreamChunk, guardrailBlocked, guardrailRedacted bool, writeErr error) {
	c := cloneSingleStreamChunk(raw)
	if len(c.Choices) > 0 {
		delta := &c.Choices[0].Delta
		if delta.Content != "" {
			processed, procErr := streamSession.ProcessText(ctx, delta.Content)
			if procErr != nil {
				if streamSession.Blocked() {
					return nil, true, streamSession.Redacted(), nil
				}
				return nil, false, false, procErr
			}
			delta.Content = processed
			if delta.Content == "" && delta.ReasoningContent == "" && len(delta.ToolCalls) == 0 && c.Choices[0].FinishReason == nil && c.Usage == nil {
				return nil, false, false, nil
			}
		}
	}
	if err := sseWriter.WriteChunk(&c); err != nil {
		return nil, false, false, err
	}
	return &c, false, false, nil
}

func writeLegacyStreamTransportError(w http.ResponseWriter, sseWriter *sse.Writer, writeErr error) {
	if !sseWriter.Started() {
		domain.WriteHTTPError(w, writeErr)
	} else {
		_ = sseWriter.WriteError(writeErr)
	}
}

type legacyStreamMetaSnapshot struct {
	gm            *domain.GlobalModel
	depID         string
	depName       string
	provider      domain.ProviderType
	pricingVer    int
	resolvedModel string
	latMs         int64
	ttftMs        int64
	routeMicros   int64
	retries       int
	fb            bool
}

func extractLegacyStreamMeta(requestedModel string, meta *router.ExecutionMeta) legacyStreamMetaSnapshot {
	snap := legacyStreamMetaSnapshot{resolvedModel: requestedModel}
	if meta == nil {
		return snap
	}
	snap.latMs = meta.LatencyMs
	snap.ttftMs = meta.TTFTMs
	snap.routeMicros = meta.RoutingMicros
	snap.retries = meta.RetryCount
	snap.fb = meta.FallbackAttempted
	if meta.WinningDeployment != nil {
		snap.depID = meta.WinningDeployment.ID
		snap.depName = meta.WinningDeployment.DeploymentName
		snap.gm = meta.WinningDeployment.GlobalModel
		if snap.gm != nil {
			snap.provider = snap.gm.Provider
			snap.resolvedModel = snap.gm.ModelName
			snap.pricingVer = snap.gm.PricingVersion
		}
	}
	return snap
}

func (s *GatewayServer) writeLegacyStreamExecError(
	w http.ResponseWriter,
	requestedModel string,
	streamStarted time.Time,
	meta *router.ExecutionMeta,
	err error,
	_ *sse.Writer,
	releaseQuota func(int),
) {
	releaseQuota(-1)
	statusCode := http.StatusBadGateway
	if gwErr, ok := err.(*domain.GatewayError); ok && gwErr.StatusCode > 0 {
		statusCode = gwErr.StatusCode
	}
	snap := extractLegacyStreamMeta(requestedModel, meta)
	s.collector.RecordStream(time.Since(streamStarted), 0, true)
	s.collector.Record(observability.RequestObservation{
		Provider:          string(snap.provider),
		DeploymentID:      snap.depID,
		DeploymentName:    snap.depName,
		Model:             requestedModel,
		StatusCode:        statusCode,
		LatencyMs:         snap.latMs,
		RoutingMicros:     snap.routeMicros,
		FallbackAttempted: snap.fb,
		RetryCount:        snap.retries,
	})
	domain.WriteHTTPError(w, err)
}

func (s *GatewayServer) writeLegacyStreamGuardrailBlock(
	requestedModel string,
	streamStarted time.Time,
	meta *router.ExecutionMeta,
	flushErr error,
	guardrailRedacted bool,
	sseWriter *sse.Writer,
	releaseQuota func(int),
) {
	releaseQuota(-1)
	snap := extractLegacyStreamMeta(requestedModel, meta)
	var streamTTFT time.Duration
	if snap.ttftMs > 0 {
		streamTTFT = time.Duration(snap.ttftMs) * time.Millisecond
	}
	s.collector.RecordStream(time.Since(streamStarted), streamTTFT, true)
	s.collector.Record(observability.RequestObservation{
		Provider:          string(snap.provider),
		DeploymentID:      snap.depID,
		DeploymentName:    snap.depName,
		Model:             snap.resolvedModel,
		StatusCode:        http.StatusBadGateway,
		LatencyMs:         snap.latMs,
		TTFTMs:            snap.ttftMs,
		RoutingMicros:     snap.routeMicros,
		FallbackAttempted: snap.fb,
		RetryCount:        snap.retries,
		GuardrailBlocked:  true,
		GuardrailRedacted: guardrailRedacted,
	})
	errOut := flushErr
	if errOut == nil {
		errOut = guardrailStreamBlockedError()
	}
	_ = sseWriter.WriteError(errOut)
}

func (s *GatewayServer) finalizeLegacyStreamSuccess(
	r *http.Request,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalCompletionRequest,
	reqID string,
	traceID string,
	estTokens int,
	streamStarted time.Time,
	meta *router.ExecutionMeta,
	usage *domain.TokenUsage,
	guardrailRedacted bool,
	sseWriter *sse.Writer,
	releaseUsage func(actualInput, actualOutput int, overrideCostMicros int64),
) {
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

	snap := extractLegacyStreamMeta(req.Model, meta)
	costMicros := finops.CalculateCostMicros(snap.gm, usageVal)
	releaseUsage(usageVal.PromptTokens, usageVal.CompletionTokens, costMicros)

	var streamTTFT time.Duration
	if snap.ttftMs > 0 {
		streamTTFT = time.Duration(snap.ttftMs) * time.Millisecond
	}
	s.collector.RecordStream(time.Since(streamStarted), streamTTFT, false)
	s.collector.Record(observability.RequestObservation{
		Provider:          string(snap.provider),
		DeploymentID:      snap.depID,
		DeploymentName:    snap.depName,
		Model:             snap.resolvedModel,
		StatusCode:        http.StatusOK,
		LatencyMs:         snap.latMs,
		TTFTMs:            snap.ttftMs,
		RoutingMicros:     snap.routeMicros,
		PromptTokens:      usageVal.PromptTokens,
		CompletionTokens:  usageVal.CompletionTokens,
		CostMicros:        costMicros,
		FallbackAttempted: snap.fb,
		RetryCount:        snap.retries,
		GuardrailRedacted: guardrailRedacted,
	})
	logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
		Model:            snap.resolvedModel,
		Provider:         string(snap.provider),
		PromptTokens:     usageVal.PromptTokens,
		CompletionTokens: usageVal.CompletionTokens,
		CostMicros:       costMicros,
		CacheHit:         false,
	})

	var provenance string
	if snap.gm != nil {
		provenance = snap.gm.PricingProvenanceSource
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
			ResolvedModel:           snap.resolvedModel,
			Provider:                snap.provider,
			DeploymentID:            snap.depID,
			PricingVersion:          snap.pricingVer,
			PricingStatus:           domain.ResolvePricingStatus(snap.gm),
			PricingProvenanceSource: provenance,
			Usage:                   usageVal,
			CostMicros:              costMicros,
			LatencyMs:               snap.latMs,
			TTFTMs:                  snap.ttftMs,
			StatusCode:              http.StatusOK,
			IsStream:                true,
			FallbackAttempted:       snap.fb,
			RetryCount:              snap.retries,
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
		slog.String("provider", string(snap.provider)),
		slog.String("requested_model", req.Model),
		slog.String("resolved_model", snap.resolvedModel),
		slog.Int("prompt_tokens", usageVal.PromptTokens),
		slog.Int("completion_tokens", usageVal.CompletionTokens),
		slog.Int("total_tokens", totalTok),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", snap.latMs),
		slog.Bool("stream", true),
	)
}
