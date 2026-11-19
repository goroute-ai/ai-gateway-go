package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
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

func admissionFailureObservation(err error) observability.RequestObservation {
	statusCode := http.StatusTooManyRequests
	var gatewayErr *domain.GatewayError
	if errors.As(err, &gatewayErr) && gatewayErr.StatusCode >= http.StatusBadRequest {
		statusCode = gatewayErr.StatusCode
	}
	return observability.RequestObservation{
		StatusCode:  statusCode,
		RateLimited: statusCode == http.StatusTooManyRequests,
	}
}

var knownChatRequestFields = map[string]struct{}{
	"request_id":         {},
	"model":              {},
	"resolved_model":     {},
	"messages":           {},
	"tools":              {},
	"tool_choice":        {},
	"temperature":        {},
	"top_p":              {},
	"max_tokens":         {},
	"stop":               {},
	"stream":             {},
	"stream_options":     {},
	"response_format":    {},
	"reasoning_effort":   {},
	"user":               {},
	"metadata":           {},
	"extra_params":       {},
	"goroute_extensions": {},
	"extra_body":         {},
}

var protectedExtraParamFields = map[string]struct{}{
	"request_id":     {},
	"model":          {},
	"resolved_model": {},
	"messages":       {},
	"stream":         {},
	"stream_options": {},
}

const maxChatCompletionBodyBytes int64 = 10 << 20

// decodeChatCompletionRequest decodes a ChatCompletion JSON body into dst and unpacks
// extra_body and unknown top-level fields into dst.ExtraParams without clobbering core fields.
func decodeChatCompletionRequest(body io.Reader, dst *domain.CanonicalChatRequest) error {
	dec := json.NewDecoder(body)
	first, err := dec.Token()
	if err != nil {
		return err
	}
	fields := make(map[string]json.RawMessage)
	if first != nil {
		objectStart, ok := first.(json.Delim)
		if !ok || objectStart != '{' {
			return fmt.Errorf("ChatCompletion request must be a JSON object")
		}
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok {
				return fmt.Errorf("ChatCompletion request object contains a non-string key")
			}
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return err
			}
			if name == "extra_body" {
				fields[name] = raw
				continue
			}
			known, err := decodeChatCanonicalField(name, raw, dst)
			if err != nil {
				return fmt.Errorf("decode %s: %w", name, err)
			}
			if !known {
				fields[name] = raw
			}
		}
		if _, err := dec.Token(); err != nil { // closing brace
			return err
		}
	} else {
		// encoding/json accepts null into a struct and leaves it unchanged.
		// Keep that compatibility while still rejecting scalar and array bodies.
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			if err == nil {
				return fmt.Errorf("request body must contain one JSON value")
			}
			return err
		}
		return nil
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request body must contain one JSON value")
		}
		return err
	}

	// Unknown parameters are decoded only once into their generic
	// representation, avoiding a second full parse into map[string]any.
	mergeExtra := func(k string, v any) {
		if _, protected := protectedExtraParamFields[k]; protected {
			return
		}
		if dst.ExtraParams == nil {
			dst.ExtraParams = make(map[string]any)
		}
		if _, exists := dst.ExtraParams[k]; !exists {
			dst.ExtraParams[k] = v
		}
	}

	for k, raw := range fields {
		if k == "extra_body" {
			var extraBody map[string]json.RawMessage
			if err := json.Unmarshal(raw, &extraBody); err != nil {
				// Match the previous decoder's behavior: non-object extra_body values
				// are ignored, while malformed JSON is rejected by the top-level parse.
				extraBody = nil
			}
			for key, rawValue := range extraBody {
				v, err := decodeChatExtraValue(rawValue)
				if err != nil {
					return fmt.Errorf("decode extra_body.%s: %w", key, err)
				}
				mergeExtra(key, v)
			}
			continue
		}
		if _, known := knownChatRequestFields[k]; known {
			continue
		}
		v, err := decodeChatExtraValue(raw)
		if err != nil {
			return fmt.Errorf("decode extra parameter %s: %w", k, err)
		}
		mergeExtra(k, v)
	}
	return nil
}

func decodeChatCanonicalField(name string, raw json.RawMessage, dst *domain.CanonicalChatRequest) (bool, error) {
	var target any
	switch strings.ToLower(name) {
	case "request_id":
		target = &dst.RequestID
	case "model":
		target = &dst.Model
	case "resolved_model":
		target = &dst.ResolvedModel
	case "messages":
		target = &dst.Messages
	case "tools":
		target = &dst.Tools
	case "tool_choice":
		target = &dst.ToolChoice
	case "temperature":
		target = &dst.Temperature
	case "top_p":
		target = &dst.TopP
	case "max_tokens":
		target = &dst.MaxTokens
	case "stop":
		target = &dst.Stop
	case "stream":
		target = &dst.Stream
	case "stream_options":
		target = &dst.StreamOptions
	case "response_format":
		target = &dst.ResponseFormat
	case "reasoning_effort":
		target = &dst.ReasoningEffort
	case "user":
		target = &dst.User
	case "metadata":
		target = &dst.Metadata
	case "extra_params":
		target = &dst.ExtraParams
	case "goroute_extensions":
		target = &dst.GoRouteExtensions
	default:
		return false, nil
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return true, err
	}
	return true, nil
}

func decodeChatExtraValue(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// handleChatCompletions serves `POST /v1/chat/completions` (both synchronous JSON and SSE streaming).
func (s *GatewayServer) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
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

	var chatReq domain.CanonicalChatRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxChatCompletionBodyBytes)
	if err := decodeChatCompletionRequest(r.Body, &chatReq); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusRequestEntityTooLarge,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "request_body_too_large",
				Message:    fmt.Sprintf("ChatCompletion request body exceeds the %d byte limit", maxChatCompletionBodyBytes),
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse ChatCompletion request body: " + err.Error(),
		})
		return
	}
	chatReq.RequestID = reqID
	if strings.TrimSpace(chatReq.Model) == "" {
		chatReq.Model = "auto"
	}
	if len(chatReq.Messages) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_messages",
			Message:    "messages array cannot be empty",
		})
		return
	}
	if gwErr := s.applyChatRoutingHints(r, idCtx, &chatReq); gwErr != nil {
		s.collector.Record(admissionFailureObservation(gwErr))
		domain.WriteHTTPError(w, gwErr)
		return
	}

	// 1. RBAC Model Allowlist Check (Key & Team level)
	if err := s.rbac.AuthorizeRequestedModel(idCtx, chatReq.Model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}

	// 1b. Pre-Flight Model-Specific BPE Token Estimate & Request Validation (Parameters, Capabilities & Context Window Limits)
	estTokens := ratelimit.EstimateRequestTokens(&chatReq)
	w.Header().Set("X-Gateway-Token-Estimate", strconv.Itoa(estTokens))

	if err := s.validator.ValidateChatRequest(r.Context(), idCtx.OrgID, &chatReq, estTokens); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusBadRequest})
		domain.WriteHTTPError(w, err)
		return
	}

	// 1c. Security Guardrails Evaluation (Layer 0 Engine + Layer 1 pre_call Pipeline)
	prc, guardrailRedacted, err := s.evaluateChatInputGuardrails(r.Context(), w, r, idCtx, &chatReq, "chat_completion")
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	// A2A OpenAI Compatibility Bridge (BL-06): route model: "a2a/{slug}" directly to A2A bridge
	// after RBAC, request validation, and input guardrails have been enforced.
	if strings.HasPrefix(chatReq.Model, "a2a/") {
		agentSlug := strings.TrimPrefix(chatReq.Model, "a2a/")
		if s.a2aBridge != nil {
			s.a2aBridge.HandleChatCompletion(w, r, idCtx, agentSlug, &chatReq)
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "a2a_bridge_disabled",
			Message:    "A2A OpenAI compatibility bridge is disabled",
		})
		return
	}

	// 2. Atomic Rate Limit / Budget Check
	qCtx, _ := withRequestQuotaState(r.Context(), r, idCtx, chatReq.User, chatReq.Metadata, chatReq.GoRouteExtensions)
	r = r.WithContext(qCtx)
	maxOutput := 0
	if chatReq.MaxTokens != nil {
		maxOutput = *chatReq.MaxTokens
	}
	budgetInputTokens := estTokens
	if s.requestHasBudget(r.Context(), idCtx, chatReq.Model) {
		if encoded, encodeErr := json.Marshal(chatReq); encodeErr != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"})
			return
		} else if len(encoded) > budgetInputTokens {
			budgetInputTokens = len(encoded)
		}
	}
	origRequestedModel := chatReq.Model
	acq, err := s.acquireQuotaWithBudgetPolicy(r.Context(), idCtx, chatReq.Model, estTokens, budgetInputTokens, maxOutput, reqID)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}
	if acq.FallbackApplied && acq.EffectiveModel != "" {
		chatReq.Model = acq.EffectiveModel
	}
	applyBudgetPolicyHeaders(w, origRequestedModel, acq)
	releaseQuota := acq.ReleaseQuota
	releaseUsage := acq.ReleaseUsage
	quotaSettlement := &postDispatchSettlement{
		idCtx:          idCtx,
		reqID:          reqID,
		traceID:        traceID,
		endpoint:       "/v1/chat/completions",
		modality:       domain.ModalityChat,
		requestedModel: origRequestedModel,
		estTokens:      estTokens,
		isStream:       chatReq.Stream,
		reqCtx:         r.Context(),
		releaseQuota:   releaseQuota,
		releaseUsage:   releaseUsage,
	}
	defer s.settleQuotaOnReturn(quotaSettlement)

	// 3. Exact-Match Response Cache Check (Non-Streaming Deterministic Requests)
	cacheHeader := r.Header.Get("X-Gateway-Cache-Control")
	var cacheKey string
	if s.respCache.IsCacheable(&chatReq, cacheHeader) {
		cacheKey = s.respCache.ComputeKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), &chatReq)
		if cacheKey != "" {
			if cachedResp, hit := s.respCache.Get(r.Context(), cacheKey); hit {
				redacted, sanitizeErr := s.evaluateChatOutputGuardrails(r.Context(), w, prc, cachedResp, "chat_completion")
				if sanitizeErr != nil {
					domain.WriteHTTPError(w, sanitizeErr)
					return
				}
				if redacted {
					guardrailRedacted = true
				}
				s.GuardrailPipeline().EvaluateLoggingOnly(r.Context(), prc, &chatReq, cachedResp)
				quotaSettlement.actualTokensReconciled = true
				releaseQuota(0, -2)
				s.collector.Record(observability.RequestObservation{
					Provider:          string(cachedResp.Provider),
					Model:             cachedResp.Model,
					StatusCode:        http.StatusOK,
					CacheHit:          true,
					GuardrailRedacted: guardrailRedacted || redacted,
				})
				logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
					Model:            cachedResp.Model,
					Provider:         string(cachedResp.Provider),
					PromptTokens:     cachedResp.Usage.PromptTokens,
					CompletionTokens: cachedResp.Usage.CompletionTokens,
					CostMicros:       0,
					CacheHit:         true,
				})
				cachedGM, _ := s.repo.GetGlobalModel(r.Context(), string(cachedResp.Provider)+"/"+cachedResp.Model)
				if cachedGM == nil {
					cachedGM, _ = s.repo.GetGlobalModel(r.Context(), cachedResp.Model)
				}
				cachePricingStatus := domain.ResolvePricingStatus(cachedGM)
				var cacheProvenance string
				if cachedGM != nil {
					cacheProvenance = cachedGM.PricingProvenanceSource
				}

				w.Header().Set("X-Gateway-Cache", "HIT")
				w.Header().Set("X-Gateway-Provider", string(cachedResp.Provider))
				w.Header().Set("X-Gateway-Model", cachedResp.Model)
				w.Header().Set("X-Gateway-Cost-Micros", "0")
				w.Header().Set("X-Gateway-Pricing-Status", string(cachePricingStatus))
				w.Header().Set("Content-Type", "application/json")

				if !s.persistSpendEvent(w, r, domain.SpendEvent{
					RequestID:               reqID,
					TraceID:                 traceID,
					OrgID:                   idCtx.OrgID,
					TeamID:                  idCtx.TeamID,
					UserID:                  idCtx.UserID,
					VirtualKeyID:            idCtx.VirtualKeyID,
					Endpoint:                "/v1/chat/completions",
					RequestedModel:          origRequestedModel,
					ResolvedModel:           cachedResp.Model,
					Provider:                cachedResp.Provider,
					PricingStatus:           cachePricingStatus,
					PricingProvenanceSource: cacheProvenance,
					Usage:                   cachedResp.Usage,
					CostMicros:              0,
					StatusCode:              http.StatusOK,
					CacheHit:                true,
					CreatedAt:               time.Now().UTC(),
				}) {
					return
				}
				_ = json.NewEncoder(w).Encode(cachedResp)
				logger.InfoContext(r.Context(), "Inference request served from cache",
					slog.String("component", "inference"),
					slog.String("request_id", reqID),
					slog.String("provider", string(cachedResp.Provider)),
					slog.String("model", cachedResp.Model),
					slog.Bool("cache_hit", true),
				)
				return
			}
		}

		w.Header().Set("X-Gateway-Cache", "MISS")
	}

	// 4. Streaming SSE Execution Path
	if chatReq.Stream {
		upstreamCtx, duringHandle, duringInitErr := s.startDuringCallGuardrails(r.Context(), prc, &chatReq)
		if duringInitErr != nil {
			domain.WriteHTTPError(w, duringInitErr)
			return
		}
		streamSession, sessionErr := s.newStreamGuardrailSession(r.Context(), prc, duringHandle)
		if sessionErr != nil {
			if duringHandle != nil {
				duringHandle.Close()
			}
			domain.WriteHTTPError(w, sessionErr)
			return
		}
		defer streamSession.Close()

		sseWriter, err := sse.NewWriter(w)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}

		streamCacheHeader := streamCacheControlHeader(r)
		var streamCacheKey string
		if s.respCache != nil && s.respCache.IsStreamCacheable(&chatReq, streamCacheHeader) {
			streamCacheKey = s.respCache.ComputeKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), &chatReq)
		}

		var sanitizedChunks []domain.CanonicalStreamChunk
		sawTerminalChunk := false
		collectSanitized := true

		writeChunk := func(chunk *domain.CanonicalStreamChunk) error {
			if chunk == nil {
				return nil
			}
			if checkErr := streamSession.CheckBeforeFirstEmit(r.Context()); checkErr != nil {
				return checkErr
			}
			if isTerminalStreamChunk(chunk) {
				sawTerminalChunk = true
			}
			c := cloneSingleStreamChunk(*chunk)
			if len(c.Choices) > 0 {
				delta := &c.Choices[0].Delta
				if len(delta.ToolCalls) > 0 {
					filteredTC, tcErr := streamSession.ProcessToolCalls(r.Context(), delta.ToolCalls)
					if tcErr != nil {
						return tcErr
					}
					delta.ToolCalls = filteredTC
				}
				if delta.Content != "" {
					processed, procErr := streamSession.ProcessText(r.Context(), delta.Content)
					if procErr != nil {
						return procErr
					}
					delta.Content = processed
					if delta.Content == "" && delta.ReasoningContent == "" && len(delta.ToolCalls) == 0 && c.Choices[0].FinishReason == nil && c.Usage == nil {
						return nil
					}
				}
			}
			if err := sseWriter.WriteChunk(&c); err != nil {
				return err
			}
			streamSession.MarkSSEStarted()
			if collectSanitized && streamCacheKey != "" {
				sanitizedChunks = appendStreamChunkBeforeTerminal(sanitizedChunks, c)
			}
			return nil
		}

		if streamCacheKey != "" {
			if cachedChunks, hit := s.respCache.GetStreamChunks(r.Context(), streamCacheKey); hit {
				collectSanitized = false
				resolvedModel, provider, cachedGM := s.resolveCachedStreamModelMeta(r.Context(), idCtx.OrgID, chatReq.Model, cachedChunks)
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
				var replayErr error
				for i := range cachedChunks {
					if replayErr = writeChunk(&cachedChunks[i]); replayErr != nil {
						break
					}
				}
				if !sseWriter.Started() {
					if _, duringErr := streamSession.WaitDuring(r.Context()); duringErr != nil && replayErr == nil {
						replayErr = duringErr
					}
				}
				replayFlushRem, flushErr := streamSession.Flush(r.Context(), replayErr)
				if replayErr == nil && flushErr != nil {
					replayErr = flushErr
				}
				if streamSession.Redacted() {
					guardrailRedacted = true
				}
				if replayErr != nil {
					streamGuardrailBlocked := streamSession.Blocked()
					legacyStreamBlocked := streamSession.redactor != nil && streamSession.redactor.Blocked()
					statusCode := http.StatusBadGateway
					if gwErr, ok := replayErr.(*domain.GatewayError); ok && gwErr.StatusCode > 0 {
						statusCode = gwErr.StatusCode
					}
					s.collector.RecordStream(time.Since(replayStarted), 0, true)
					s.collector.Record(observability.RequestObservation{
						Provider:          string(provider),
						Model:             resolvedModel,
						StatusCode:        statusCode,
						GuardrailBlocked:  streamGuardrailBlocked,
						GuardrailRedacted: guardrailRedacted,
					})
					if !sseWriter.Started() && !legacyStreamBlocked {
						domain.WriteHTTPError(w, replayErr)
					} else {
						_ = sseWriter.WriteError(replayErr)
					}
					return
				}
				if replayFlushRem != "" {
					if writeErr := sseWriter.WriteChunk(&domain.CanonicalStreamChunk{
						ID:      "chatcmpl-" + reqID,
						Object:  "chat.completion.chunk",
						Created: time.Now().Unix(),
						Model:   resolvedModel,
						Choices: []domain.CanonicalStreamChoice{{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{Role: "assistant", Content: replayFlushRem},
						}},
					}); writeErr != nil {
						_ = sseWriter.WriteError(writeErr)
						return
					}
				}
				quotaSettlement.actualTokensReconciled = true
				releaseQuota(0, -2)
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
						Endpoint:                "/v1/chat/completions",
						RequestedModel:          origRequestedModel,
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
						_ = sseWriter.WriteError(&domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "spend_persistence_unavailable", Message: "unable to persist request accounting"})
						return
					}
				}
				s.GuardrailPipeline().EvaluateLoggingOnly(r.Context(), prc, &chatReq, nil)
				_ = sseWriter.WriteDone()
				return
			}
			w.Header().Set("X-Gateway-Cache", "MISS")
		}

		var usage *domain.TokenUsage
		var meta *router.ExecutionMeta
		streamStarted := time.Now()

		onSelected := func(dep *domain.Deployment) {
			quotaSettlement.selectedDep = dep
			setPreStreamSelectedHeaders(w, dep, sseWriter.Started())
		}

		upstreamCtx = attachStreamDroppedParamsObserver(upstreamCtx, w, sseWriter.Started)
		upstreamCtx = quotaSettlement.trackDispatch(upstreamCtx)
		if s.orchestrator != nil && len(chatReq.Tools) > 0 {
			usage, meta, err = s.orchestrator.ExecuteStreamLoop(upstreamCtx, idCtx, &chatReq, writeChunk, onSelected)
		} else {
			usage, meta, err = s.reliability.ExecuteStream(upstreamCtx, idCtx, &chatReq, writeChunk, onSelected)
		}
		if !sseWriter.Started() {
			if duringOut, duringErr := streamSession.WaitDuring(r.Context()); duringErr != nil {
				s.recordDuringCallBlock(r.Context(), w, prc, duringOut, duringErr, "chat_completion")
				err = duringErr
			}
		} else if duringErr := duringHandle.Blocked(); duringErr != nil && err == nil {
			err = duringErr
		}
		streamFlushRem, flushErr := streamSession.Flush(r.Context(), err)
		if err == nil && flushErr != nil {
			err = flushErr
		}
		quotaSettlement.meta = meta
		quotaSettlement.dispatchErr = err
		if streamSession.Redacted() {
			guardrailRedacted = true
		}
		streamGuardrailBlocked := streamSession.Blocked()
		legacyStreamBlocked := streamSession.redactor != nil && streamSession.redactor.Blocked()
		var streamTTFT time.Duration
		if meta != nil && meta.TTFTMs > 0 {
			streamTTFT = time.Duration(meta.TTFTMs) * time.Millisecond
		}
		s.collector.RecordStream(time.Since(streamStarted), streamTTFT, err != nil)
		s.emitRoutingTelemetryAndDebugHeaders(w, r, meta)
		if err != nil {
			statusCode := http.StatusBadGateway
			if gwErr, ok := err.(*domain.GatewayError); ok && gwErr.StatusCode > 0 {
				statusCode = gwErr.StatusCode
			}
			var depID, depName string
			var provider domain.ProviderType
			if meta != nil && meta.WinningDeployment != nil {
				depID = meta.WinningDeployment.ID
				depName = meta.WinningDeployment.DeploymentName
				if meta.WinningDeployment.GlobalModel != nil {
					provider = meta.WinningDeployment.GlobalModel.Provider
				}
			}
			var latMs, routeMicros int64
			var retries int
			var fb bool
			if meta != nil {
				latMs = meta.LatencyMs
				routeMicros = meta.RoutingMicros
				retries = meta.RetryCount
				fb = meta.FallbackAttempted
			}
			s.collector.Record(observability.RequestObservation{
				Provider:          string(provider),
				DeploymentID:      depID,
				DeploymentName:    depName,
				Model:             chatReq.Model,
				StatusCode:        statusCode,
				LatencyMs:         latMs,
				RoutingMicros:     routeMicros,
				FallbackAttempted: fb,
				RetryCount:        retries,
				GuardrailBlocked:  streamGuardrailBlocked,
				GuardrailRedacted: guardrailRedacted,
			})
			if !sseWriter.Started() && !legacyStreamBlocked {
				domain.WriteHTTPError(w, err)
			} else {
				// Mid-stream failure or stream output guardrail block:
				// emit structured error SSE event before [DONE] instead of restarting stream.
				_ = sseWriter.WriteError(err)
			}
			return
		}
		if streamFlushRem != "" {
			flushChunk := domain.CanonicalStreamChunk{
				ID:      "chatcmpl-" + reqID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   chatReq.Model,
				Choices: []domain.CanonicalStreamChoice{{
					Index: 0,
					Delta: domain.CanonicalStreamDelta{Role: "assistant", Content: streamFlushRem},
				}},
			}
			if writeErr := sseWriter.WriteChunk(&flushChunk); writeErr != nil {
				quotaSettlement.dispatchErr = writeErr
				_ = sseWriter.WriteError(writeErr)
				return
			}
			if streamCacheKey != "" {
				sanitizedChunks = appendStreamChunkBeforeTerminal(sanitizedChunks, flushChunk)
			}
		}
		totalTok := 0
		var usageVal domain.TokenUsage
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
		resolvedModel := chatReq.Model
		if meta != nil && meta.WinningDeployment != nil {
			depID = meta.WinningDeployment.ID
			depName = meta.WinningDeployment.DeploymentName
			gm = meta.WinningDeployment.GlobalModel
			if gm != nil {
				provider = gm.Provider
				resolvedModel = gm.ModelName
				pricingVer = gm.PricingVersion
			}
		}
		if streamCacheKey != "" && !streamGuardrailBlocked && sawTerminalChunk && len(sanitizedChunks) > 0 {
			finalizeStreamChunksForCache(sanitizedChunks, resolvedModel, usageVal)
			s.respCache.SetStreamChunks(r.Context(), streamCacheKey, idCtx.OrgID, resolvedModel, sanitizedChunks)
		}
		costMicros := finops.CalculateCostMicros(gm, usageVal)
		quotaSettlement.actualTokensReconciled = true
		if releaseUsage != nil {
			releaseUsage(usageVal.PromptTokens, usageVal.CompletionTokens, costMicros)
		} else {
			releaseQuota(totalTok, -2)
		}
		s.collector.Record(observability.RequestObservation{
			Provider:          string(provider),
			DeploymentID:      depID,
			DeploymentName:    depName,
			Model:             resolvedModel,
			StatusCode:        http.StatusOK,
			LatencyMs:         meta.LatencyMs,
			TTFTMs:            meta.TTFTMs,
			RoutingMicros:     meta.RoutingMicros,
			PromptTokens:      usageVal.PromptTokens,
			CompletionTokens:  usageVal.CompletionTokens,
			CostMicros:        costMicros,
			FallbackAttempted: meta.FallbackAttempted,
			RetryCount:        meta.RetryCount,
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
				Endpoint:                "/v1/chat/completions",
				RequestedModel:          origRequestedModel,
				ResolvedModel:           resolvedModel,
				Provider:                provider,
				DeploymentID:            depID,
				PricingVersion:          pricingVer,
				PricingStatus:           domain.ResolvePricingStatus(gm),
				PricingProvenanceSource: provenance,
				Usage:                   usageVal,
				CostMicros:              costMicros,
				LatencyMs:               meta.LatencyMs,
				TTFTMs:                  meta.TTFTMs,
				StatusCode:              http.StatusOK,
				IsStream:                true,
				FallbackAttempted:       meta.FallbackAttempted,
				RetryCount:              meta.RetryCount,
				CreatedAt:               time.Now().UTC(),
			})); err != nil {
				_ = sseWriter.WriteError(&domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "spend_persistence_unavailable", Message: "unable to persist request accounting"})
				return
			}
		}
		s.GuardrailPipeline().EvaluateLoggingOnly(r.Context(), prc, &chatReq, nil)
		_ = sseWriter.WriteDone()
		logger.InfoContext(r.Context(), "Streaming inference completed",
			slog.String("component", "inference"),
			slog.String("request_id", reqID),
			slog.String("provider", string(provider)),
			slog.String("requested_model", chatReq.Model),
			slog.String("resolved_model", resolvedModel),
			slog.Int("prompt_tokens", usageVal.PromptTokens),
			slog.Int("completion_tokens", usageVal.CompletionTokens),
			slog.Int("total_tokens", totalTok),
			slog.Int64("cost_micros", costMicros),
			slog.Int64("latency_ms", meta.LatencyMs),
			slog.Int64("ttft_ms", meta.TTFTMs),
			slog.Bool("stream", true),
			slog.Bool("fallback_attempted", meta.FallbackAttempted),
			slog.Int("retry_count", meta.RetryCount),
			slog.Bool("guardrail_redacted", guardrailRedacted),
		)
		return
	}

	// 5. Synchronous JSON Execution Path
	upstreamCtx, duringHandle, duringInitErr := s.startDuringCallGuardrails(r.Context(), prc, &chatReq)
	if duringInitErr != nil {
		domain.WriteHTTPError(w, duringInitErr)
		return
	}
	if duringHandle != nil {
		defer duringHandle.Close()
	}

	var resp *domain.CanonicalChatResponse
	var meta *router.ExecutionMeta

	upstreamCtx = quotaSettlement.trackDispatch(upstreamCtx)
	if s.orchestrator != nil && len(chatReq.Tools) > 0 {
		resp, meta, err = s.orchestrator.ExecuteLoop(upstreamCtx, idCtx, &chatReq)
	} else {
		resp, meta, err = s.reliability.ExecuteChat(upstreamCtx, idCtx, &chatReq)
	}
	quotaSettlement.meta = meta
	quotaSettlement.dispatchErr = err
	if duringOut, duringErr := duringHandle.Wait(r.Context()); duringErr != nil {
		if quotaSettlement.dispatchErr == nil {
			quotaSettlement.dispatchErr = duringErr
		}
		s.recordDuringCallBlock(r.Context(), w, prc, duringOut, duringErr, "chat_completion")
		domain.WriteHTTPError(w, duringErr)
		return
	}
	if err != nil {
		statusCode := http.StatusBadGateway
		if gwErr, ok := err.(*domain.GatewayError); ok && gwErr.StatusCode > 0 {
			statusCode = gwErr.StatusCode
		}
		var latMs, routeMicros int64
		var retries int
		var fb bool
		if meta != nil {
			latMs = meta.LatencyMs
			routeMicros = meta.RoutingMicros
			retries = meta.RetryCount
			fb = meta.FallbackAttempted
		}
		s.collector.Record(observability.RequestObservation{
			Model:             chatReq.Model,
			StatusCode:        statusCode,
			LatencyMs:         latMs,
			RoutingMicros:     routeMicros,
			FallbackAttempted: fb,
			RetryCount:        retries,
			GuardrailRedacted: guardrailRedacted,
		})
		s.emitRoutingTelemetryAndDebugHeaders(w, r, meta)
		domain.WriteHTTPError(w, err)
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
	if pricingVer <= 0 {
		pricingVer = 1
	}
	costMicros := finops.CalculateCostMicros(gm, resp.Usage)

	quotaSettlement.actualTokensReconciled = true
	if releaseUsage != nil {
		releaseUsage(resp.Usage.PromptTokens, resp.Usage.CompletionTokens, costMicros)
	} else {
		releaseQuota(resp.Usage.TotalTokens, -2)
	}

	// Output Guardrail Evaluation (Layer 0 Engine + Layer 1 post_call Pipeline)
	redacted, guardrailOutputErr := s.evaluateChatOutputGuardrails(r.Context(), w, prc, resp, "chat_completion")
	if redacted {
		guardrailRedacted = true
	}

	if cacheKey != "" && guardrailOutputErr == nil {
		s.respCache.SetWithMeta(r.Context(), cacheKey, idCtx.OrgID, resp)
	}
	responseStatus := http.StatusOK
	if guardrailOutputErr != nil {
		responseStatus = http.StatusServiceUnavailable
		if gwErr, ok := guardrailOutputErr.(*domain.GatewayError); ok && gwErr.StatusCode > 0 {
			responseStatus = gwErr.StatusCode
		}
	}

	s.collector.Record(observability.RequestObservation{
		Provider:          string(resp.Provider),
		DeploymentID:      depID,
		DeploymentName:    depName,
		Model:             resp.Model,
		StatusCode:        responseStatus,
		LatencyMs:         meta.LatencyMs,
		TTFTMs:            meta.TTFTMs,
		RoutingMicros:     meta.RoutingMicros,
		PromptTokens:      resp.Usage.PromptTokens,
		CompletionTokens:  resp.Usage.CompletionTokens,
		CostMicros:        costMicros,
		FallbackAttempted: meta.FallbackAttempted,
		RetryCount:        meta.RetryCount,
		GuardrailRedacted: guardrailRedacted,
	})
	logger.SetInferenceMeta(r.Context(), logger.InferenceMeta{
		Model:            resp.Model,
		Provider:         string(resp.Provider),
		PromptTokens:     resp.Usage.PromptTokens,
		CompletionTokens: resp.Usage.CompletionTokens,
		CostMicros:       costMicros,
		CacheHit:         false,
	})

	pricingStatus := domain.ResolvePricingStatus(gm)

	w.Header().Set("X-Gateway-Provider", string(resp.Provider))
	w.Header().Set("X-Gateway-Model", resp.Model)
	w.Header().Set("X-Gateway-Cost-Micros", strconv.FormatInt(costMicros, 10))
	w.Header().Set("X-Gateway-Pricing-Version", strconv.Itoa(pricingVer))
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
		Endpoint:                "/v1/chat/completions",
		RequestedModel:          origRequestedModel,
		ResolvedModel:           resp.Model,
		Provider:                resp.Provider,
		DeploymentID:            depID,
		PricingVersion:          pricingVer,
		PricingStatus:           pricingStatus,
		PricingProvenanceSource: provenance,
		Usage:                   resp.Usage,
		CostMicros:              costMicros,
		LatencyMs:               meta.LatencyMs,
		TTFTMs:                  meta.TTFTMs,
		StatusCode:              responseStatus,
		IsStream:                false,
		FallbackAttempted:       meta.FallbackAttempted,
		RetryCount:              meta.RetryCount,
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	if guardrailOutputErr != nil {
		domain.WriteHTTPError(w, guardrailOutputErr)
		return
	}
	s.GuardrailPipeline().EvaluateLoggingOnly(r.Context(), prc, &chatReq, resp)
	_ = json.NewEncoder(w).Encode(resp)
	logger.InfoContext(r.Context(), "Inference completed",
		slog.String("component", "inference"),
		slog.String("request_id", reqID),
		slog.String("provider", string(resp.Provider)),
		slog.String("requested_model", chatReq.Model),
		slog.String("resolved_model", resp.Model),
		slog.Int("prompt_tokens", resp.Usage.PromptTokens),
		slog.Int("completion_tokens", resp.Usage.CompletionTokens),
		slog.Int("total_tokens", resp.Usage.TotalTokens),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
		slog.Bool("stream", false),
		slog.Bool("fallback_attempted", meta.FallbackAttempted),
		slog.Int("retry_count", meta.RetryCount),
		slog.Bool("guardrail_redacted", guardrailRedacted),
	)
}

// handleEmbeddings serves `POST /v1/embeddings`.
func (s *GatewayServer) handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	reqID := gatewayRequestID(r)
	w.Header().Set("X-Gateway-Request-Id", reqID)
	traceID := observability.TraceFromContext(r.Context()).TraceID

	idCtx := auth.IdentityFromContext(r.Context())

	var raw struct {
		Model             string                    `json:"model"`
		Input             any                       `json:"input"`
		EncodingFormat    string                    `json:"encoding_format,omitempty"`
		Dimensions        *int                      `json:"dimensions,omitempty"`
		InputType         string                    `json:"input_type,omitempty"`
		User              string                    `json:"user,omitempty"`
		Metadata          map[string]string         `json:"metadata,omitempty"`
		GoRouteExtensions *domain.GoRouteExtensions `json:"goroute_extensions,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    err.Error(),
		})
		return
	}

	var inputs []string
	switch v := raw.Input.(type) {
	case string:
		inputs = []string{v}
	case []any:
		for _, item := range v {
			inputs = append(inputs, fmt.Sprintf("%v", item))
		}
	}
	if len(inputs) == 0 || raw.Model == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_embedding_request",
			Message:    "model and input are required",
		})
		return
	}
	if err := s.rbac.AuthorizeRequestedModel(idCtx, raw.Model); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if gwErr := s.applyRoutingHints(r, idCtx, &raw.GoRouteExtensions); gwErr != nil {
		s.collector.Record(admissionFailureObservation(gwErr))
		domain.WriteHTTPError(w, gwErr)
		return
	}
	guardedInputs, guardrailErr := s.evaluateNonChatTextGuardrails(r.Context(), w, r, idCtx, &raw.Model, raw.GoRouteExtensions, "embeddings", inputs...)
	if guardrailErr != nil {
		domain.WriteHTTPError(w, guardrailErr)
		return
	}
	inputs = guardedInputs

	estTokens := ratelimit.EstimateTextInputsTokens(raw.Model, inputs, 4)
	inputByteBound := 0
	for _, input := range inputs {
		inputByteBound += len(input)
	}
	origRequestedModel := raw.Model
	qCtx, _ := withRequestQuotaState(r.Context(), r, idCtx, raw.User, raw.Metadata, raw.GoRouteExtensions)
	r = r.WithContext(qCtx)
	acq, err := s.acquireQuotaWithBudgetPolicy(r.Context(), idCtx, raw.Model, estTokens, inputByteBound, -1, reqID)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}
	if acq.FallbackApplied && acq.EffectiveModel != "" {
		raw.Model = acq.EffectiveModel
	}
	applyBudgetPolicyHeaders(w, origRequestedModel, acq)
	releaseQuota := acq.ReleaseQuota
	releaseUsage := acq.ReleaseUsage
	quotaSettlement := &postDispatchSettlement{
		idCtx:          idCtx,
		reqID:          reqID,
		traceID:        traceID,
		endpoint:       "/v1/embeddings",
		modality:       domain.ModalityEmbedding,
		requestedModel: origRequestedModel,
		estTokens:      estTokens,
		reqCtx:         r.Context(),
		releaseQuota:   releaseQuota,
		releaseUsage:   releaseUsage,
	}
	defer s.settleQuotaOnReturn(quotaSettlement)

	embReq := &domain.CanonicalEmbeddingRequest{
		RequestID:         reqID,
		Model:             raw.Model,
		Input:             inputs,
		EncodingFormat:    raw.EncodingFormat,
		Dimensions:        raw.Dimensions,
		InputType:         raw.InputType,
		User:              raw.User,
		GoRouteExtensions: raw.GoRouteExtensions,
	}

	cacheHeader := r.Header.Get("X-Gateway-Cache-Control")
	var cacheKey string
	if s.respCache != nil && s.respCache.IsEmbeddingCacheable(embReq, cacheHeader) {
		cacheKey = s.respCache.ComputeEmbeddingKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), embReq)
		if cacheKey != "" {
			if cachedResp, hit := s.respCache.GetEmbedding(r.Context(), cacheKey); hit {
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
	resp, meta, err := s.reliability.ExecuteEmbeddings(upstreamCtx, idCtx, embReq)
	quotaSettlement.meta = meta
	quotaSettlement.dispatchErr = err
	if err != nil {
		s.emitRoutingTelemetryAndDebugHeaders(w, r, meta)
		domain.WriteHTTPError(w, err)
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

	quotaSettlement.actualTokensReconciled = true
	if releaseUsage != nil {
		releaseUsage(resp.Usage.PromptTokens, resp.Usage.CompletionTokens, costMicros)
	} else {
		releaseQuota(resp.Usage.TotalTokens, -2)
	}
	if cacheKey != "" {
		s.respCache.SetEmbeddingWithMeta(r.Context(), cacheKey, idCtx.OrgID, resp)
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

	pricingStatus := domain.ResolvePricingStatus(gm)

	w.Header().Set("X-Gateway-Provider", string(resp.Provider))
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
		Endpoint:                "/v1/embeddings",
		RequestedModel:          origRequestedModel,
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
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
	logger.InfoContext(r.Context(), "Embeddings request completed",
		slog.String("component", "inference"),
		slog.String("request_id", reqID),
		slog.String("provider", string(resp.Provider)),
		slog.String("model", resp.Model),
		slog.Int("prompt_tokens", resp.Usage.PromptTokens),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}

// handleListModels serves `GET /v1/models`, filtered by the caller's Organization Subscriptions, Policies, and Key Scopes.
func (s *GatewayServer) handleListModels(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	list, err := s.modelMgmt.ListVisibleModelsForIdentity(r.Context(), idCtx)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}

// cacheAllowedModelScope returns a deterministic scope string representing the
// identity's effective allowed-model constraint for cache key isolation.
func cacheAllowedModelScope(idCtx *domain.IdentityContext) string {
	if idCtx == nil {
		return ""
	}
	var parts []string
	switch {
	case idCtx.KeyAllowedModels != nil:
		sorted := make([]string, len(idCtx.KeyAllowedModels))
		copy(sorted, idCtx.KeyAllowedModels)
		sort.Strings(sorted)
		parts = append(parts, "key:"+strings.Join(sorted, ","))
	case idCtx.TeamAllowedModels != nil:
		sorted := make([]string, len(idCtx.TeamAllowedModels))
		copy(sorted, idCtx.TeamAllowedModels)
		sort.Strings(sorted)
		parts = append(parts, "team:"+strings.Join(sorted, ","))
	}
	if len(idCtx.ProjectAllowedModels) > 0 {
		sorted := make([]string, len(idCtx.ProjectAllowedModels))
		copy(sorted, idCtx.ProjectAllowedModels)
		sort.Strings(sorted)
		parts = append(parts, "proj:"+strings.Join(sorted, ","))
	}
	if len(idCtx.TeamMemberAllowedModels) > 0 {
		sorted := make([]string, len(idCtx.TeamMemberAllowedModels))
		copy(sorted, idCtx.TeamMemberAllowedModels)
		sort.Strings(sorted)
		parts = append(parts, "tm:"+strings.Join(sorted, ","))
	}
	if len(idCtx.DynamicAllowedModels) > 0 {
		sorted := make([]string, len(idCtx.DynamicAllowedModels))
		copy(sorted, idCtx.DynamicAllowedModels)
		sort.Strings(sorted)
		parts = append(parts, "dyn:"+strings.Join(sorted, ","))
	}
	return strings.Join(parts, "|")
}

// streamCacheControlHeader combines Cache-Control and X-Gateway-Cache-Control
// request headers so stream caching honors explicit opt-in via either header.
func streamCacheControlHeader(r *http.Request) string {
	cc := strings.TrimSpace(r.Header.Get("Cache-Control"))
	xcc := strings.TrimSpace(r.Header.Get("X-Gateway-Cache-Control"))
	switch {
	case cc != "" && xcc != "":
		return cc + ", " + xcc
	case cc != "":
		return cc
	default:
		return xcc
	}
}

func isTerminalStreamChunk(chunk *domain.CanonicalStreamChunk) bool {
	if chunk == nil {
		return false
	}
	for _, ch := range chunk.Choices {
		if ch.FinishReason != nil && strings.TrimSpace(*ch.FinishReason) != "" {
			return true
		}
	}
	return false
}

func cloneSingleStreamChunk(ch domain.CanonicalStreamChunk) domain.CanonicalStreamChunk {
	out := ch
	if ch.Usage != nil {
		u := *ch.Usage
		out.Usage = &u
	}
	if ch.Choices != nil {
		choices := make([]domain.CanonicalStreamChoice, len(ch.Choices))
		for i, c := range ch.Choices {
			choices[i] = c
			if c.FinishReason != nil {
				fr := *c.FinishReason
				choices[i].FinishReason = &fr
			}
			if c.Delta.ToolCalls != nil {
				tcs := make([]domain.CanonicalToolCall, len(c.Delta.ToolCalls))
				for j, tc := range c.Delta.ToolCalls {
					tcs[j] = tc
					if tc.Index != nil {
						idx := *tc.Index
						tcs[j].Index = &idx
					}
				}
				choices[i].Delta.ToolCalls = tcs
			}
		}
		out.Choices = choices
	}
	return out
}

func appendStreamChunkBeforeTerminal(chunks []domain.CanonicalStreamChunk, next domain.CanonicalStreamChunk) []domain.CanonicalStreamChunk {
	if isTerminalStreamChunk(&next) || len(chunks) == 0 {
		return append(chunks, next)
	}
	for i := len(chunks) - 1; i >= 0; i-- {
		if isTerminalStreamChunk(&chunks[i]) {
			out := make([]domain.CanonicalStreamChunk, 0, len(chunks)+1)
			out = append(out, chunks[:i]...)
			out = append(out, next)
			out = append(out, chunks[i:]...)
			return out
		}
	}
	return append(chunks, next)
}

func finalizeStreamChunksForCache(chunks []domain.CanonicalStreamChunk, resolvedModel string, usageVal domain.TokenUsage) {
	if len(chunks) == 0 {
		return
	}
	hasUsage := false
	for i := range chunks {
		if chunks[i].Model == "" && resolvedModel != "" {
			chunks[i].Model = resolvedModel
		}
		if chunks[i].Usage != nil && (chunks[i].Usage.TotalTokens > 0 || chunks[i].Usage.PromptTokens > 0 || chunks[i].Usage.CompletionTokens > 0) {
			hasUsage = true
		}
	}
	if !hasUsage && (usageVal.TotalTokens > 0 || usageVal.PromptTokens > 0 || usageVal.CompletionTokens > 0) {
		u := usageVal
		chunks[len(chunks)-1].Usage = &u
	}
}

func extractStreamChunksUsage(chunks []domain.CanonicalStreamChunk, fallbackPromptTokens int) domain.TokenUsage {
	for i := len(chunks) - 1; i >= 0; i-- {
		if chunks[i].Usage != nil && (chunks[i].Usage.TotalTokens > 0 || chunks[i].Usage.PromptTokens > 0 || chunks[i].Usage.CompletionTokens > 0) {
			return *chunks[i].Usage
		}
	}
	return domain.TokenUsage{
		PromptTokens: fallbackPromptTokens,
		TotalTokens:  fallbackPromptTokens,
	}
}

func (s *GatewayServer) resolveCachedStreamModelMeta(ctx context.Context, orgID, requestedModel string, chunks []domain.CanonicalStreamChunk) (resolvedModel string, provider domain.ProviderType, gm *domain.GlobalModel) {
	resolvedModel = requestedModel
	for _, ch := range chunks {
		if ch.Model != "" {
			resolvedModel = ch.Model
			break
		}
	}
	if s.repo == nil {
		return resolvedModel, "", nil
	}
	if m, _ := s.repo.GetGlobalModel(ctx, resolvedModel); m != nil {
		return resolvedModel, m.Provider, m
	}
	if grp, _ := s.repo.GetModelGroupByAlias(ctx, orgID, requestedModel); grp != nil {
		if deps, _ := s.repo.ListDeploymentsByGroup(ctx, grp.ID); len(deps) > 0 && deps[0].GlobalModel != nil {
			m := deps[0].GlobalModel
			if resolvedModel == "" {
				resolvedModel = m.ModelName
			}
			return resolvedModel, m.Provider, m
		}
	}
	if models, _ := s.repo.ListGlobalModels(ctx); len(models) > 0 {
		for _, m := range models {
			if m != nil && (m.ModelName == resolvedModel || m.ID == resolvedModel) {
				return resolvedModel, m.Provider, m
			}
		}
	}
	return resolvedModel, "", nil
}

func isAllASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func appendUniqueRoutingTag(tags []string, tag string) []string {
	for _, existing := range tags {
		if strings.EqualFold(strings.TrimSpace(existing), tag) {
			return tags
		}
	}
	return append(tags, tag)
}

func (s *GatewayServer) applyChatRoutingHints(r *http.Request, idCtx *domain.IdentityContext, chatReq *domain.CanonicalChatRequest) *domain.GatewayError {
	if chatReq == nil {
		return nil
	}
	return s.applyRoutingHints(r, idCtx, &chatReq.GoRouteExtensions)
}

func (s *GatewayServer) applyRoutingHints(r *http.Request, idCtx *domain.IdentityContext, extPtr **domain.GoRouteExtensions) *domain.GatewayError {
	defaultPriority := 0
	allowStrategyOverride := false
	if s != nil && s.cfg != nil {
		if s.cfg.Router.Scheduler.Enabled {
			defaultPriority = s.cfg.Router.Scheduler.DefaultPriority
		}
		allowStrategyOverride = s.cfg.Router.AllowStrategyOverride
	}
	applyRoutingHintHeadersToExtensions(r, extPtr, defaultPriority)
	return enforceRoutingHintPoliciesOnExtensions(idCtx, extPtr, allowStrategyOverride)
}

func applyRoutingHintHeaders(r *http.Request, chatReq *domain.CanonicalChatRequest, defaultPriority int) {
	if chatReq == nil {
		return
	}
	applyRoutingHintHeadersToExtensions(r, &chatReq.GoRouteExtensions, defaultPriority)
}

func applyRoutingHintHeadersToExtensions(r *http.Request, extPtr **domain.GoRouteExtensions, defaultPriority int) {
	if r == nil || extPtr == nil {
		return
	}
	ensureExt := func() *domain.GoRouteExtensions {
		if *extPtr == nil {
			*extPtr = &domain.GoRouteExtensions{}
		}
		return *extPtr
	}

	if v := strings.TrimSpace(r.Header.Get("X-Gateway-Allowed-Region")); v != "" {
		ext := ensureExt()
		if strings.TrimSpace(ext.AllowedRegion) == "" {
			ext.AllowedRegion = v
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Gateway-Session-Id")); v != "" {
		ext := ensureExt()
		if strings.TrimSpace(ext.SessionID) == "" {
			ext.SessionID = v
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Gateway-Preferred-Deployment-Id")); v != "" {
		ext := ensureExt()
		if strings.TrimSpace(ext.PreferredDeploymentID) == "" {
			ext.PreferredDeploymentID = v
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Gateway-Priority")); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			ext := ensureExt()
			if ext.Priority == 0 {
				ext.Priority = p
			}
		}
	} else if defaultPriority > 0 && (*extPtr == nil || (*extPtr).Priority == 0) {
		ext := ensureExt()
		ext.Priority = defaultPriority
	}
	if v := strings.TrimSpace(r.Header.Get("X-Gateway-Hedge-After-Ms")); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			ext := ensureExt()
			if ext.HedgeAfterMs == 0 {
				ext.HedgeAfterMs = ms
			}
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Gateway-Drop-Params")); v != "" {
		if drop, err := strconv.ParseBool(v); err == nil {
			ext := ensureExt()
			if ext.DropUnsupportedParams == nil {
				ext.DropUnsupportedParams = &drop
			}
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Gateway-Routing-Strategy")); v != "" {
		ext := ensureExt()
		if strings.TrimSpace(ext.RoutingStrategy) == "" {
			ext.RoutingStrategy = v
		}
	}

	for _, raw := range r.Header.Values("X-Gateway-Tags") {
		for _, part := range strings.Split(raw, ",") {
			if tag := strings.TrimSpace(part); tag != "" {
				ext := ensureExt()
				ext.Tags = appendUniqueRoutingTag(ext.Tags, tag)
			}
		}
	}

	var tagHeaderKeys []string
	for k := range r.Header {
		if len(k) > len("X-Gateway-Tag-") && strings.EqualFold(k[:len("X-Gateway-Tag-")], "X-Gateway-Tag-") {
			tagHeaderKeys = append(tagHeaderKeys, k)
		}
	}
	sort.Strings(tagHeaderKeys)
	for _, k := range tagHeaderKeys {
		suffix := strings.ToLower(strings.TrimSpace(k[len("X-Gateway-Tag-"):]))
		for _, raw := range r.Header.Values(k) {
			for _, part := range strings.Split(raw, ",") {
				item := strings.TrimSpace(part)
				if item == "" {
					continue
				}
				ext := ensureExt()
				if strings.HasPrefix(item, "&") || strings.HasPrefix(item, "!") || strings.Contains(item, ":") || suffix == "" || isAllASCIIDigits(suffix) {
					ext.Tags = appendUniqueRoutingTag(ext.Tags, item)
					continue
				}
				if !strings.EqualFold(suffix, item) {
					ext.Tags = appendUniqueRoutingTag(ext.Tags, suffix+":"+item)
				}
				ext.Tags = appendUniqueRoutingTag(ext.Tags, item)
			}
		}
	}
}

func enforceRoutingHintPolicies(idCtx *domain.IdentityContext, chatReq *domain.CanonicalChatRequest, allowStrategyOverride bool) *domain.GatewayError {
	if chatReq == nil {
		return nil
	}
	return enforceRoutingHintPoliciesOnExtensions(idCtx, &chatReq.GoRouteExtensions, allowStrategyOverride)
}

func enforceRoutingHintPoliciesOnExtensions(idCtx *domain.IdentityContext, extPtr **domain.GoRouteExtensions, allowStrategyOverride bool) *domain.GatewayError {
	if extPtr == nil {
		return nil
	}
	ext := *extPtr
	minRank := effectiveMinPriorityRank(idCtx)
	if ext != nil && ext.Priority < 0 {
		ext.Priority = 0
	}
	if minRank > 0 {
		if ext == nil {
			ext = &domain.GoRouteExtensions{}
			*extPtr = ext
		}
		if ext.Priority < minRank {
			ext.Priority = minRank
		}
	}

	if idCtx != nil && ext != nil && len(ext.Tags) > 0 {
		for _, raw := range ext.Tags {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			base := trimmed
			if strings.HasPrefix(base, "&") || strings.HasPrefix(base, "!") {
				base = strings.TrimSpace(base[1:])
			}
			if base == "" {
				continue
			}
			if len(idCtx.KeyAllowedRoutingTags) > 0 && !routingTagMatchesAllowlist(base, idCtx.KeyAllowedRoutingTags) {
				return &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "routing_tag_not_allowed",
					Message:    fmt.Sprintf("Routing tag %q is not permitted by virtual key allowed_routing_tags policy", trimmed),
				}
			}
			if len(idCtx.TeamAllowedRoutingTags) > 0 && !routingTagMatchesAllowlist(base, idCtx.TeamAllowedRoutingTags) {
				return &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "routing_tag_not_allowed",
					Message:    fmt.Sprintf("Routing tag %q is not permitted by team allowed_routing_tags policy", trimmed),
				}
			}
		}
	}

	if ext != nil && strings.TrimSpace(ext.RoutingStrategy) != "" {
		if !allowStrategyOverride {
			ext.RoutingStrategy = ""
		} else {
			rawStrat := strings.TrimSpace(ext.RoutingStrategy)
			normalized := domain.NormalizeRoutingStrategy(domain.RoutingStrategy(rawStrat))
			if !domain.IsValidRoutingStrategy(normalized) {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "invalid_routing_strategy",
					Message:    fmt.Sprintf("Unsupported routing_strategy override %q", ext.RoutingStrategy),
				}
			}
			ext.RoutingStrategy = string(normalized)
		}
	}
	return nil
}

func effectiveMinPriorityRank(idCtx *domain.IdentityContext) int {
	if idCtx == nil {
		return 0
	}
	floor := idCtx.KeyMinPriorityRank
	if idCtx.TeamMinPriorityRank > floor {
		floor = idCtx.TeamMinPriorityRank
	}
	if floor < 0 {
		return 0
	}
	return floor
}

func routingTagMatchesAllowlist(base string, allowlist []string) bool {
	for _, pat := range allowlist {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if pat == "*" {
			return true
		}
		if strings.HasSuffix(pat, "*") {
			prefix := pat[:len(pat)-1]
			if len(base) >= len(prefix) && strings.EqualFold(base[:len(prefix)], prefix) {
				return true
			}
			continue
		}
		if !strings.Contains(base, "*") && strings.EqualFold(base, pat) {
			return true
		}
	}
	return false
}

func setRoutingTelemetryHeaders(w http.ResponseWriter, meta *router.ExecutionMeta) {
	if w == nil || meta == nil {
		return
	}
	w.Header().Set("X-Gateway-Latency-Ms", strconv.FormatInt(meta.LatencyMs, 10))
	w.Header().Set("X-Gateway-Routing-Micros", strconv.FormatInt(meta.RoutingMicros, 10))
	w.Header().Set("X-Gateway-Retry-Count", strconv.Itoa(meta.RetryCount))
	w.Header().Set("X-Gateway-Fallback-Attempted", strconv.FormatBool(meta.FallbackAttempted))
	w.Header().Set("X-Gateway-Tier-Stepdowns", strconv.Itoa(meta.TierStepdowns))
	if meta.WinningDeployment != nil && meta.WinningDeployment.ID != "" {
		w.Header().Set("X-Gateway-Deployment-Id", meta.WinningDeployment.ID)
	}
	if len(meta.DroppedParams) > 0 {
		w.Header().Set("X-Gateway-Dropped-Params", strings.Join(meta.DroppedParams, ","))
	}
	routeReason := strings.TrimSpace(meta.FallbackReason)
	if routeReason == "" && meta.RouteDecision != nil {
		routeReason = strings.TrimSpace(meta.RouteDecision.Reason)
	}
	if routeReason != "" {
		w.Header().Set("X-Gateway-Route-Reason", routeReason)
	}
	if meta.StreamContinued {
		w.Header().Set("X-Gateway-Stream-Continued", "true")
	}
}

func (s *GatewayServer) setDebugRoutingHeaders(w http.ResponseWriter, r *http.Request, meta *router.ExecutionMeta) {
	if s == nil || s.cfg == nil || !s.cfg.Router.DebugRoutingHeaders || w == nil || r == nil || meta == nil {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Gateway-Debug-Routing")), "true") {
		return
	}
	if len(meta.FallbackErrors) > 0 {
		w.Header().Set("X-Gateway-Fallback-Errors", strings.Join(meta.FallbackErrors, "; "))
	}
}

func (s *GatewayServer) emitRoutingTelemetryAndDebugHeaders(w http.ResponseWriter, r *http.Request, meta *router.ExecutionMeta) {
	setRoutingTelemetryHeaders(w, meta)
	s.setDebugRoutingHeaders(w, r, meta)
}

func setPreStreamSelectedHeaders(w http.ResponseWriter, dep *domain.Deployment, sseStarted bool) {
	if w == nil || sseStarted || dep == nil {
		return
	}
	if dep.ID != "" {
		w.Header().Set("X-Gateway-Deployment-Id", dep.ID)
	}
	if dep.GlobalModel != nil {
		if dep.GlobalModel.Provider != "" {
			w.Header().Set("X-Gateway-Provider", string(dep.GlobalModel.Provider))
		}
		if dep.GlobalModel.ModelName != "" {
			w.Header().Set("X-Gateway-Model", dep.GlobalModel.ModelName)
		}
		status := domain.ResolvePricingStatus(dep.GlobalModel)
		w.Header().Set("X-Gateway-Pricing-Status", string(status))
	}
}

func attachStreamDroppedParamsObserver(ctx context.Context, w http.ResponseWriter, sseStarted func() bool) context.Context {
	if w == nil {
		return ctx
	}
	return router.WithDroppedParamsObserver(ctx, func(params []string) {
		if sseStarted != nil && sseStarted() {
			return
		}
		if len(params) > 0 {
			w.Header().Set("X-Gateway-Dropped-Params", strings.Join(params, ","))
		} else {
			w.Header().Del("X-Gateway-Dropped-Params")
		}
	})
}
