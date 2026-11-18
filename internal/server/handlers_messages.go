package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
)

type anthropicMessagesPayload struct {
	Model             string                    `json:"model"`
	Messages          []anthropicMsg            `json:"messages"`
	System            any                       `json:"system,omitempty"`
	MaxTokens         int                       `json:"max_tokens"`
	Temperature       *float64                  `json:"temperature,omitempty"`
	TopP              *float64                  `json:"top_p,omitempty"`
	TopK              *int                      `json:"top_k,omitempty"`
	Stream            bool                      `json:"stream,omitempty"`
	StopSequences     []string                  `json:"stop_sequences,omitempty"`
	Tools             []anthropicToolDef        `json:"tools,omitempty"`
	ToolChoice        any                       `json:"tool_choice,omitempty"`
	Thinking          map[string]any            `json:"thinking,omitempty"`
	GoRouteExtensions *domain.GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

type anthropicMsg struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

type anthropicToolDef struct {
	Name         string               `json:"name"`
	Description  string               `json:"description,omitempty"`
	InputSchema  map[string]any       `json:"input_schema"`
	CacheControl *domain.CacheControl `json:"cache_control,omitempty"`
}

// handleAnthropicMessages serves `POST /v1/messages` and `POST /anthropic/v1/messages`.
func (s *GatewayServer) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	reqID := gatewayRequestID(r)
	w.Header().Set("X-Gateway-Request-Id", reqID)
	traceID := observability.TraceFromContext(r.Context()).TraceID

	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteAnthropicHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Missing virtual key identity context",
		})
		return
	}

	var payload anthropicMessagesPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		domain.WriteAnthropicHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse Anthropic Messages request: " + err.Error(),
		})
		return
	}

	payload.Model = strings.TrimSpace(payload.Model)
	if payload.Model == "" {
		domain.WriteAnthropicHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_model",
			Message:    "model parameter is required",
		})
		return
	}

	if len(payload.Messages) == 0 {
		domain.WriteAnthropicHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_messages",
			Message:    "messages array cannot be empty",
		})
		return
	}

	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, payload.Model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteAnthropicHTTPError(w, err)
		return
	}

	// 2. Translate Anthropic Messages payload into CanonicalChatRequest
	chatReq := domain.CanonicalChatRequest{
		RequestID:         reqID,
		Model:             payload.Model,
		Stream:            payload.Stream,
		Temperature:       payload.Temperature,
		TopP:              payload.TopP,
		Stop:              payload.StopSequences,
		GoRouteExtensions: payload.GoRouteExtensions,
	}
	if payload.MaxTokens > 0 {
		chatReq.MaxTokens = &payload.MaxTokens
	}
	s.applyChatRoutingHints(r, &chatReq)

	// Translate System
	if payload.System != nil {
		sysText, sysCC := parseAnthropicSystemWithCache(payload.System)
		if sysText != "" {
			chatReq.Messages = append(chatReq.Messages, domain.CanonicalMessage{
				Role:         "system",
				Content:      sysText,
				CacheControl: sysCC,
			})
		}
	}

	// Translate Messages
	for _, m := range payload.Messages {
		convMsgs := parseAnthropicMessage(m)
		chatReq.Messages = append(chatReq.Messages, convMsgs...)
	}

	// Translate Tools
	for _, t := range payload.Tools {
		chatReq.Tools = append(chatReq.Tools, domain.CanonicalTool{
			Type:         "function",
			CacheControl: t.CacheControl,
			Function: domain.CanonicalFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.InputSchema,
			},
		})
	}
	prc, _, err := s.evaluateChatInputGuardrails(r.Context(), w, r, idCtx, &chatReq, "messages")
	if err != nil {
		domain.WriteAnthropicHTTPError(w, err)
		return
	}

	// 3. Rate Limiting Quota
	estTokens := ratelimit.EstimateRequestTokens(&chatReq)
	budgetInputTokens := estTokens
	if s.requestHasBudget(r.Context(), idCtx, chatReq.Model) {
		if encoded, encodeErr := json.Marshal(chatReq); encodeErr != nil {
			domain.WriteAnthropicHTTPError(w, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"})
			return
		} else if len(encoded) > budgetInputTokens {
			budgetInputTokens = len(encoded)
		}
	}
	acq, err := s.acquireQuotaWithBudgetPolicy(r.Context(), idCtx, chatReq.Model, estTokens, budgetInputTokens, payload.MaxTokens, reqID)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteAnthropicHTTPError(w, err)
		return
	}
	if acq.FallbackApplied && acq.EffectiveModel != "" {
		chatReq.Model = acq.EffectiveModel
	}
	applyBudgetPolicyHeaders(w, payload.Model, acq)
	releaseQuota := acq.ReleaseQuota
	releaseUsage := acq.ReleaseUsage

	// 4. Dispatch Execution
	if payload.Stream {
		s.streamAnthropicMessages(w, r, idCtx, prc, &chatReq, estTokens, releaseQuota, releaseUsage, traceID, reqID)
		return
	}
	quotaSettlement := &postDispatchSettlement{
		idCtx:          idCtx,
		reqID:          reqID,
		traceID:        traceID,
		endpoint:       r.URL.Path,
		modality:       domain.ModalityChat,
		requestedModel: payload.Model,
		estTokens:      estTokens,
		isStream:       false,
		reqCtx:         r.Context(),
		releaseQuota:   releaseQuota,
		releaseUsage:   releaseUsage,
	}
	defer s.settleQuotaOnReturn(quotaSettlement)

	var cacheKey string
	if s.respCache != nil && s.respCache.IsCacheable(&chatReq, r.Header.Get("X-Gateway-Cache-Control")) {
		cacheKey = s.respCache.ComputeKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), &chatReq)
		if cacheKey != "" {
			if cachedResp, hit := s.respCache.Get(r.Context(), cacheKey); hit {
				_, sanitizeErr := s.evaluateChatOutputGuardrails(r.Context(), w, prc, cachedResp, "messages")
				if sanitizeErr != nil {
					quotaSettlement.actualTokensReconciled = true
					releaseQuota(0, -2)
					domain.WriteAnthropicHTTPError(w, sanitizeErr)
					return
				}
				s.GuardrailPipeline().EvaluateLoggingOnly(r.Context(), prc, &chatReq, cachedResp)
				quotaSettlement.actualTokensReconciled = true
				releaseQuota(0, -2)
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
				w.Header().Set("X-Gateway-Provider", string(cachedResp.Provider))
				w.Header().Set("X-Gateway-Cache", "HIT")
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(toAnthropicResponse(cachedResp, reqID))
				return
			}
		}
	}

	upstreamCtx, duringHandle, duringInitErr := s.startDuringCallGuardrails(r.Context(), prc, &chatReq)
	if duringInitErr != nil {
		domain.WriteAnthropicHTTPError(w, duringInitErr)
		return
	}
	if duringHandle != nil {
		defer duringHandle.Close()
	}

	quotaSettlement.upstreamDispatched = true
	resp, meta, err := s.reliability.ExecuteChat(upstreamCtx, idCtx, &chatReq)
	quotaSettlement.meta = meta
	quotaSettlement.dispatchErr = err
	if duringOut, duringErr := duringHandle.Wait(r.Context()); duringErr != nil {
		if quotaSettlement.dispatchErr == nil {
			quotaSettlement.dispatchErr = duringErr
		}
		s.recordDuringCallBlock(r.Context(), w, prc, duringOut, duringErr, "messages")
		domain.WriteAnthropicHTTPError(w, duringErr)
		return
	}
	if err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusBadGateway})
		domain.WriteAnthropicHTTPError(w, err)
		return
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
	pricingStatus := domain.ResolvePricingStatus(gm)

	quotaSettlement.actualTokensReconciled = true
	if releaseUsage != nil {
		releaseUsage(resp.Usage.PromptTokens, resp.Usage.CompletionTokens, costMicros)
	} else {
		releaseQuota(resp.Usage.TotalTokens, -2)
	}
	if _, sanitizeErr := s.evaluateChatOutputGuardrails(r.Context(), w, prc, resp, "messages"); sanitizeErr != nil {
		domain.WriteAnthropicHTTPError(w, sanitizeErr)
		return
	}
	s.GuardrailPipeline().EvaluateLoggingOnly(r.Context(), prc, &chatReq, resp)
	if cacheKey != "" {
		s.respCache.SetWithMeta(r.Context(), cacheKey, idCtx.OrgID, resp)
		w.Header().Set("X-Gateway-Cache", "MISS")
	}

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

	// Convert CanonicalChatResponse to Anthropic JSON response
	anthropicResp := toAnthropicResponse(resp, reqID)

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
		RequestedModel:          payload.Model,
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
		Modality:                domain.ModalityChat,
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	_ = json.NewEncoder(w).Encode(anthropicResp)

	logger.InfoContext(r.Context(), "Anthropic Messages request completed",
		slog.String("component", "messages_bridge"),
		slog.String("request_id", reqID),
		slog.String("provider", string(resp.Provider)),
		slog.String("model", resp.Model),
		slog.Int("prompt_tokens", resp.Usage.PromptTokens),
		slog.Int("completion_tokens", resp.Usage.CompletionTokens),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}

func (s *GatewayServer) streamAnthropicMessages(
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	prc guardrails.PipelineRequestContext,
	chatReq *domain.CanonicalChatRequest,
	estTokens int,
	releaseQuota func(int, int64),
	releaseUsage func(int, int, int64),
	traceID, reqID string,
) {
	quotaSettlement := &postDispatchSettlement{
		idCtx:          idCtx,
		reqID:          reqID,
		traceID:        traceID,
		endpoint:       r.URL.Path,
		modality:       domain.ModalityChat,
		requestedModel: chatReq.Model,
		estTokens:      estTokens,
		isStream:       true,
		reqCtx:         r.Context(),
		releaseQuota:   releaseQuota,
		releaseUsage:   releaseUsage,
	}
	defer s.settleQuotaOnReturn(quotaSettlement)

	upstreamCtx, duringHandle, duringInitErr := s.startDuringCallGuardrails(r.Context(), prc, chatReq)
	if duringInitErr != nil {
		domain.WriteAnthropicHTTPError(w, duringInitErr)
		return
	}
	streamSession, sessionErr := s.newStreamGuardrailSession(r.Context(), prc, duringHandle)
	if sessionErr != nil {
		if duringHandle != nil {
			duringHandle.Close()
		}
		domain.WriteAnthropicHTTPError(w, sessionErr)
		return
	}
	defer streamSession.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		domain.WriteAnthropicHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "streaming_not_supported",
			Message:    "ResponseWriter does not support SSE flushing",
		})
		return
	}

	streamCacheHeader := streamCacheControlHeader(r)
	var streamCacheKey string
	var cachedStreamChunks []domain.CanonicalStreamChunk
	var streamCacheHit bool
	if s.respCache != nil && s.respCache.IsStreamCacheable(chatReq, streamCacheHeader) {
		streamCacheKey = s.respCache.ComputeKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), chatReq)
		if streamCacheKey != "" {
			cachedStreamChunks, streamCacheHit = s.respCache.GetStreamChunks(r.Context(), streamCacheKey)
			if streamCacheHit {
				w.Header().Set("X-Gateway-Cache", "HIT")
				w.Header().Set("X-Gateway-Cost-Micros", "0")
			} else {
				w.Header().Set("X-Gateway-Cache", "MISS")
			}
		}
	}

	startSSE := func() {
		if streamSession.SSEStarted() {
			return
		}
		streamSession.MarkSSEStarted()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		// Send message_start
		fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":%q,\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":%d,\"output_tokens\":0}}}\n\n",
			reqID, chatReq.Model, estTokens)
		// Send content_block_start
		fmt.Fprintf(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		flusher.Flush()
	}
	if !streamSession.HasDuringCall() {
		startSSE()
	}

	var outputTokens int
	var winningDep *domain.Deployment

	emitDelta := func(txt string) {
		if txt == "" {
			return
		}
		outputTokens++
		deltaBytes, _ := json.Marshal(map[string]any{
			"type":  "content_block_delta",
			"index": 0,
			"delta": map[string]string{
				"type": "text_delta",
				"text": txt,
			},
		})
		fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", string(deltaBytes))
		flusher.Flush()
	}

	var sanitizedChunks []domain.CanonicalStreamChunk
	sawTerminalChunk := false

	onChunk := func(chunk *domain.CanonicalStreamChunk) error {
		if chunk == nil {
			return nil
		}
		if checkErr := streamSession.CheckBeforeFirstEmit(r.Context()); checkErr != nil {
			return checkErr
		}
		startSSE()
		if isTerminalStreamChunk(chunk) {
			sawTerminalChunk = true
		}
		c := cloneSingleStreamChunk(*chunk)
		hasContent := false
		for i := range c.Choices {
			if len(c.Choices[i].Delta.ToolCalls) > 0 {
				filteredTC, tcErr := streamSession.ProcessToolCalls(r.Context(), c.Choices[i].Delta.ToolCalls)
				if tcErr != nil {
					return tcErr
				}
				c.Choices[i].Delta.ToolCalls = filteredTC
				if len(filteredTC) > 0 {
					hasContent = true
				}
			}
			if c.Choices[i].Delta.Content != "" {
				txt, procErr := streamSession.ProcessText(r.Context(), c.Choices[i].Delta.Content)
				if procErr != nil {
					return procErr
				}
				c.Choices[i].Delta.Content = txt
				if txt != "" {
					hasContent = true
					emitDelta(txt)
				}
			}
		}
		if !streamCacheHit && streamCacheKey != "" {
			if hasContent || isTerminalStreamChunk(&c) || c.Usage != nil {
				sanitizedChunks = appendStreamChunkBeforeTerminal(sanitizedChunks, c)
			}
		}
		return nil
	}

	streamStarted := time.Now()
	var usage *domain.TokenUsage
	var meta *router.ExecutionMeta
	var err error
	if streamCacheHit {
		for i := range cachedStreamChunks {
			if err = onChunk(&cachedStreamChunks[i]); err != nil {
				break
			}
		}
		u := extractStreamChunksUsage(cachedStreamChunks, estTokens)
		usage = &u
	} else {
		quotaSettlement.upstreamDispatched = true
		usage, meta, err = s.reliability.ExecuteStream(upstreamCtx, idCtx, chatReq, onChunk, func(dep *domain.Deployment) {
			winningDep = dep
			quotaSettlement.selectedDep = dep
			if !streamSession.SSEStarted() && dep != nil && dep.GlobalModel != nil {
				if dep.GlobalModel.Provider != "" {
					w.Header().Set("X-Gateway-Provider", string(dep.GlobalModel.Provider))
				}
				if dep.GlobalModel.ModelName != "" {
					w.Header().Set("X-Gateway-Model", dep.GlobalModel.ModelName)
				}
				w.Header().Set("X-Gateway-Pricing-Status", string(domain.ResolvePricingStatus(dep.GlobalModel)))
			}
		})
	}
	if !streamSession.SSEStarted() {
		if duringOut, duringErr := streamSession.WaitDuring(r.Context()); duringErr != nil {
			s.recordDuringCallBlock(r.Context(), w, prc, duringOut, duringErr, "messages")
			err = duringErr
		}
	} else if duringErr := duringHandle.Blocked(); duringErr != nil && err == nil {
		err = duringErr
	}
	flushDelta, flushErr := streamSession.Flush(r.Context(), err)
	if err == nil && flushErr != nil {
		err = flushErr
	}
	quotaSettlement.meta = meta
	quotaSettlement.dispatchErr = err
	var streamTTFT time.Duration
	if meta != nil && meta.TTFTMs > 0 {
		streamTTFT = time.Duration(meta.TTFTMs) * time.Millisecond
	}
	s.collector.RecordStream(time.Since(streamStarted), streamTTFT, err != nil)
	setRoutingTelemetryHeaders(w, meta)

	if err != nil {
		isBlocked := streamSession.Blocked()
		errType := "api_error"
		errCode := "stream_error"
		statusCode := http.StatusBadGateway
		if gwErr, ok := err.(*domain.GatewayError); ok {
			if gwErr.Code != "" {
				errCode = gwErr.Code
			}
			if gwErr.StatusCode > 0 {
				statusCode = gwErr.StatusCode
			}
		}
		if isBlocked {
			errType = "guardrail_blocked"
			errCode = "guardrail_blocked"
		}
		s.collector.Record(observability.RequestObservation{
			Model:             chatReq.Model,
			StatusCode:        statusCode,
			GuardrailBlocked:  isBlocked,
			GuardrailRedacted: streamSession.Redacted(),
		})
		if !streamSession.SSEStarted() {
			domain.WriteAnthropicHTTPError(w, err)
			return
		}
		errBytes, _ := json.Marshal(map[string]any{
			"type": "error",
			"error": map[string]string{
				"type":    errType,
				"code":    errCode,
				"message": err.Error(),
			},
		})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(errBytes))
		flusher.Flush()
		return
	}
	startSSE()
	s.GuardrailPipeline().EvaluateLoggingOnly(r.Context(), prc, chatReq, nil)
	if flushDelta != "" {
		emitDelta(flushDelta)
		if !streamCacheHit && streamCacheKey != "" {
			sanitizedChunks = appendStreamChunkBeforeTerminal(sanitizedChunks, domain.CanonicalStreamChunk{
				ID:      reqID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   chatReq.Model,
				Choices: []domain.CanonicalStreamChoice{{
					Index: 0,
					Delta: domain.CanonicalStreamDelta{Role: "assistant", Content: flushDelta},
				}},
			})
		}
	}

	totalTokens := estTokens + outputTokens
	if usage != nil && usage.TotalTokens > 0 {
		totalTokens = usage.TotalTokens
		outputTokens = usage.CompletionTokens
	}
	finalUsage := domain.TokenUsage{
		PromptTokens:     estTokens,
		CompletionTokens: outputTokens,
		TotalTokens:      totalTokens,
	}
	var gm *domain.GlobalModel
	var depID string
	var provider domain.ProviderType
	var pricingVer int
	resolvedModel := chatReq.Model
	if chatReq.ResolvedModel != "" {
		resolvedModel = chatReq.ResolvedModel
	}
	var costMicros int64
	var latMs int64
	if streamCacheHit {
		quotaSettlement.actualTokensReconciled = true
		releaseQuota(0, -2)
		resolvedModel, provider, gm = s.resolveCachedStreamModelMeta(r.Context(), idCtx.OrgID, chatReq.Model, cachedStreamChunks)
		costMicros = 0
		s.collector.Record(observability.RequestObservation{
			Provider:          string(provider),
			Model:             resolvedModel,
			StatusCode:        http.StatusOK,
			CacheHit:          true,
			GuardrailRedacted: streamSession.Redacted(),
		})
	} else {
		if winningDep == nil && meta != nil && meta.WinningDeployment != nil {
			winningDep = meta.WinningDeployment
		}
		if winningDep != nil {
			depID = winningDep.ID
			gm = winningDep.GlobalModel
			if gm != nil {
				provider = gm.Provider
				pricingVer = gm.PricingVersion
				if gm.ModelName != "" {
					resolvedModel = gm.ModelName
				}
			}
		}
		if meta != nil {
			latMs = meta.LatencyMs
		}
		costMicros = finops.CalculateCostMicros(gm, finalUsage)
		quotaSettlement.actualTokensReconciled = true
		if releaseUsage != nil {
			releaseUsage(finalUsage.PromptTokens, finalUsage.CompletionTokens, costMicros)
		} else {
			releaseQuota(totalTokens, -2)
		}
		if streamCacheKey != "" && !streamSession.Blocked() && sawTerminalChunk && len(sanitizedChunks) > 0 {
			finalizeStreamChunksForCache(sanitizedChunks, resolvedModel, finalUsage)
			s.respCache.SetStreamChunks(r.Context(), streamCacheKey, idCtx.OrgID, resolvedModel, sanitizedChunks)
		}
	}
	logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
		Model:            resolvedModel,
		Provider:         string(provider),
		PromptTokens:     finalUsage.PromptTokens,
		CompletionTokens: finalUsage.CompletionTokens,
		CostMicros:       costMicros,
		CacheHit:         streamCacheHit,
	})

	if s.spendWorker != nil {
		if err := s.spendWorker.Record(r.Context(), domain.SpendEvent{
			RequestID:      reqID,
			TraceID:        traceID,
			OrgID:          idCtx.OrgID,
			TeamID:         idCtx.TeamID,
			UserID:         idCtx.UserID,
			VirtualKeyID:   idCtx.VirtualKeyID,
			Endpoint:       r.URL.Path,
			RequestedModel: chatReq.Model,
			ResolvedModel:  resolvedModel,
			Provider:       provider,
			DeploymentID:   depID,
			PricingVersion: pricingVer,
			Usage:          finalUsage,
			CostMicros:     costMicros,
			LatencyMs:      latMs,
			StatusCode:     http.StatusOK,
			CacheHit:       streamCacheHit,
			IsStream:       true,
			Modality:       domain.ModalityChat,
			CreatedAt:      time.Now().UTC(),
		}); err != nil {
			fmt.Fprintf(w, "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"server_error\",\"message\":\"unable to persist request accounting\"}}\n\n")
			flusher.Flush()
			return
		}
	}
	fmt.Fprintf(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	fmt.Fprintf(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":%d}}\n\n", outputTokens)
	fmt.Fprintf(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	flusher.Flush()
}

func parseCacheControlBlock(block map[string]any) *domain.CacheControl {
	raw, ok := block["cache_control"].(map[string]any)
	if !ok {
		return nil
	}
	ccType, _ := raw["type"].(string)
	if ccType == "" {
		return nil
	}
	ttl, _ := raw["ttl"].(string)
	return &domain.CacheControl{Type: ccType, TTL: ttl}
}

func parseAnthropicSystem(sys any) string {
	txt, _ := parseAnthropicSystemWithCache(sys)
	return txt
}

func parseAnthropicSystemWithCache(sys any) (string, *domain.CacheControl) {
	switch v := sys.(type) {
	case string:
		return v, nil
	case []any:
		var sb strings.Builder
		var lastCC *domain.CacheControl
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					if sb.Len() > 0 {
						sb.WriteString("\n\n")
					}
					sb.WriteString(t)
				}
				if cc := parseCacheControlBlock(m); cc != nil {
					lastCC = cc
				}
			}
		}
		return sb.String(), lastCC
	default:
		return "", nil
	}
}

func parseAnthropicMessage(m anthropicMsg) []domain.CanonicalMessage {
	switch v := m.Content.(type) {
	case string:
		return []domain.CanonicalMessage{{
			Role:    m.Role,
			Content: v,
		}}
	case []any:
		var textParts []string
		var parts []domain.ContentPart
		var toolCalls []domain.CanonicalToolCall
		var separateToolResults []domain.CanonicalMessage
		var msgCC *domain.CacheControl

		for _, item := range v {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			cc := parseCacheControlBlock(block)
			if cc != nil {
				msgCC = cc
			}
			blockType, _ := block["type"].(string)
			switch blockType {
			case "text":
				if txt, ok := block["text"].(string); ok {
					textParts = append(textParts, txt)
					parts = append(parts, domain.ContentPart{Type: "text", Text: txt, CacheControl: cc})
				}
			case "image":
				if src, ok := block["source"].(map[string]any); ok {
					srcType, _ := src["type"].(string)
					if srcType == "url" {
						if u, _ := src["url"].(string); u != "" {
							parts = append(parts, domain.ContentPart{
								Type:         "image_url",
								ImageURL:     &domain.ImageURL{URL: u},
								CacheControl: cc,
							})
						}
					} else {
						mediaType, _ := src["media_type"].(string)
						data, _ := src["data"].(string)
						url := fmt.Sprintf("data:%s;base64,%s", mediaType, data)
						parts = append(parts, domain.ContentPart{
							Type:         "image_url",
							ImageURL:     &domain.ImageURL{URL: url},
							CacheControl: cc,
						})
					}
				}
			case "document":
				if src, ok := block["source"].(map[string]any); ok {
					srcType, _ := src["type"].(string)
					mediaType, _ := src["media_type"].(string)
					if mediaType == "" {
						mediaType = "application/pdf"
					}
					doc := &domain.DocumentPart{MimeType: mediaType}
					if srcType == "url" {
						doc.URL, _ = src["url"].(string)
					} else {
						doc.Data, _ = src["data"].(string)
					}
					if doc.Data != "" || doc.URL != "" {
						parts = append(parts, domain.ContentPart{
							Type:         "document",
							Document:     doc,
							CacheControl: cc,
						})
					}
				}
			case "tool_use":
				callID, _ := block["id"].(string)
				name, _ := block["name"].(string)
				input := block["input"]
				argBytes, _ := json.Marshal(input)
				toolCalls = append(toolCalls, domain.CanonicalToolCall{
					ID:   callID,
					Type: "function",
					Function: domain.CanonicalFunctionCall{
						Name:      name,
						Arguments: string(argBytes),
					},
				})
			case "tool_result":
				toolUseID, _ := block["tool_use_id"].(string)
				content := block["content"]
				contentStr := ""
				switch cv := content.(type) {
				case string:
					contentStr = cv
				default:
					b, _ := json.Marshal(cv)
					contentStr = string(b)
				}
				separateToolResults = append(separateToolResults, domain.CanonicalMessage{
					Role:         "tool",
					ToolCallID:   toolUseID,
					Content:      contentStr,
					CacheControl: cc,
				})
			}
		}

		var out []domain.CanonicalMessage
		if len(separateToolResults) > 0 {
			out = append(out, separateToolResults...)
		}
		if len(textParts) > 0 || len(parts) > 0 || len(toolCalls) > 0 {
			out = append(out, domain.CanonicalMessage{
				Role:         m.Role,
				Content:      strings.Join(textParts, "\n\n"),
				Parts:        parts,
				ToolCalls:    toolCalls,
				CacheControl: msgCC,
			})
		}
		return out
	default:
		return nil
	}
}

func toAnthropicResponse(resp *domain.CanonicalChatResponse, reqID string) map[string]any {
	var contentBlocks []map[string]any
	stopReason := "end_turn"

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		if choice.Message.Content != "" {
			contentBlocks = append(contentBlocks, map[string]any{
				"type": "text",
				"text": choice.Message.Content,
			})
		}
		for _, tc := range choice.Message.ToolCalls {
			var inputMap map[string]any
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &inputMap)
			if inputMap == nil {
				inputMap = map[string]any{}
			}
			contentBlocks = append(contentBlocks, map[string]any{
				"type":  "tool_use",
				"id":    tc.ID,
				"name":  tc.Function.Name,
				"input": inputMap,
			})
			stopReason = "tool_use"
		}
		switch choice.FinishReason {
		case "length":
			stopReason = "max_tokens"
		case "tool_calls":
			stopReason = "tool_use"
		case "content_filter":
			stopReason = "stop_sequence"
		}
	}

	return map[string]any{
		"id":            "msg_" + strings.TrimPrefix(resp.ID, "chatcmpl-"),
		"type":          "message",
		"role":          "assistant",
		"model":         resp.Model,
		"content":       contentBlocks,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage": map[string]int{
			"input_tokens":  resp.Usage.PromptTokens,
			"output_tokens": resp.Usage.CompletionTokens,
		},
	}
}
