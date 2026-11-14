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

	// 1c. Security Guardrails Evaluation (Prompt Injection, Secret/PII Redaction & Blocked Keywords)
	grRes, err := s.guardrails.EvaluateInput(r.Context(), idCtx.OrgID, &chatReq)
	guardrailRedacted := false
	if grRes != nil && len(grRes.Violations) > 0 {
		guardrailRedacted = grRes.Redacted
		w.Header().Set("X-Gateway-Guardrail-Action", string(grRes.AppliedAction))
		_ = s.repo.RecordAuditLog(r.Context(), &domain.AuditLog{
			OrgID:      idCtx.OrgID,
			ActorID:    idCtx.VirtualKeyID,
			Action:     "guardrail.triggered",
			Resource:   "chat_completion",
			ResourceID: reqID,
			Details: map[string]any{
				"action":     grRes.AppliedAction,
				"violations": grRes.Violations,
				"redacted":   grRes.Redacted,
				"trace_id":   traceID,
			},
		})
	}
	if err != nil {
		status := http.StatusBadRequest
		if ge, ok := err.(*domain.GatewayError); ok && ge.StatusCode != 0 {
			status = ge.StatusCode
		}
		s.collector.Record(observability.RequestObservation{
			StatusCode:       status,
			GuardrailBlocked: true,
		})
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
	maxOutput := 0
	if chatReq.MaxTokens != nil {
		maxOutput = *chatReq.MaxTokens
	}
	budgetInputTokens := estTokens
	if identityHasBudget(idCtx) {
		if encoded, encodeErr := json.Marshal(chatReq); encodeErr != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"})
			return
		} else if len(encoded) > budgetInputTokens {
			budgetInputTokens = len(encoded)
		}
	}
	releaseQuota, err := s.acquireRequestQuotaWithBound(r.Context(), idCtx, chatReq.Model, estTokens, budgetInputTokens, maxOutput, reqID)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}
	actualTokensReconciled := false
	defer func() {
		if !actualTokensReconciled {
			releaseQuota(-1)
		}
	}()

	// 3. Exact-Match Response Cache Check (Non-Streaming Deterministic Requests)
	cacheHeader := r.Header.Get("X-Gateway-Cache-Control")
	var cacheKey string
	if s.respCache.IsCacheable(&chatReq, cacheHeader) {
		cacheKey = s.respCache.ComputeKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), &chatReq)
		if cacheKey != "" {
			if cachedResp, hit := s.respCache.Get(r.Context(), cacheKey); hit {
				redacted, sanitizeErr := s.guardrails.SanitizeOutputStrict(r.Context(), idCtx.OrgID, cachedResp)
				if sanitizeErr != nil {
					domain.WriteHTTPError(w, sanitizeErr)
					return
				}
				if redacted {
					w.Header().Set("X-Gateway-Output-Redacted", "true")
				}
				actualTokensReconciled = true
				releaseQuota(0)
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
					RequestedModel:          chatReq.Model,
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
		policy, policyErr := s.guardrails.Policy(r.Context(), idCtx.OrgID)
		if policyErr != nil {
			domain.WriteHTTPError(w, policyErr)
			return
		}
		streamRedactor := s.guardrails.NewStreamRedactor(policy)
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
			if isTerminalStreamChunk(chunk) {
				sawTerminalChunk = true
			}
			c := cloneSingleStreamChunk(*chunk)
			if streamRedactor != nil && len(c.Choices) > 0 {
				if streamRedactor.Blocked() {
					return guardrailStreamBlockedError()
				}
				delta := &c.Choices[0].Delta
				if delta.Content != "" {
					delta.Content = streamRedactor.Process(delta.Content)
					if streamRedactor.Blocked() {
						return guardrailStreamBlockedError()
					}
					if delta.Content == "" && delta.ReasoningContent == "" && len(delta.ToolCalls) == 0 && c.Choices[0].FinishReason == nil && c.Usage == nil {
						return nil
					}
				}
			}
			if err := sseWriter.WriteChunk(&c); err != nil {
				return err
			}
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
				var replayFlushRem string
				if replayErr == nil && streamRedactor != nil {
					replayFlushRem = streamRedactor.Flush()
					if streamRedactor.Redacted() {
						guardrailRedacted = true
					}
					if streamRedactor.Blocked() {
						replayErr = guardrailStreamBlockedError()
					}
				} else if streamRedactor != nil {
					if streamRedactor.Blocked() {
						_ = streamRedactor.Flush()
					}
					if streamRedactor.Redacted() {
						guardrailRedacted = true
					}
				}
				if replayErr != nil {
					streamGuardrailBlocked := streamRedactor != nil && streamRedactor.Blocked()
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
					if !sseWriter.Started() && !streamGuardrailBlocked {
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
				actualTokensReconciled = true
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
					if err := s.spendWorker.Record(r.Context(), domain.SpendEvent{
						RequestID:               reqID,
						TraceID:                 traceID,
						OrgID:                   idCtx.OrgID,
						TeamID:                  idCtx.TeamID,
						UserID:                  idCtx.UserID,
						VirtualKeyID:            idCtx.VirtualKeyID,
						Endpoint:                "/v1/chat/completions",
						RequestedModel:          chatReq.Model,
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
					}); err != nil {
						_ = sseWriter.WriteError(&domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "spend_persistence_unavailable", Message: "unable to persist request accounting"})
						return
					}
				}
				_ = sseWriter.WriteDone()
				return
			}
			w.Header().Set("X-Gateway-Cache", "MISS")
		}

		var usage *domain.TokenUsage
		var meta *router.ExecutionMeta
		streamStarted := time.Now()

		onSelected := func(dep *domain.Deployment) {
			if !sseWriter.Started() && dep != nil && dep.GlobalModel != nil {
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

		if s.orchestrator != nil && len(chatReq.Tools) > 0 {
			usage, meta, err = s.orchestrator.ExecuteStreamLoop(r.Context(), idCtx, &chatReq, writeChunk, onSelected)
		} else {
			usage, meta, err = s.reliability.ExecuteStream(r.Context(), idCtx, &chatReq, writeChunk, onSelected)
		}
		var streamFlushRem string
		if err == nil && streamRedactor != nil {
			streamFlushRem = streamRedactor.Flush()
			if streamRedactor.Redacted() {
				guardrailRedacted = true
			}
			if streamRedactor.Blocked() {
				err = guardrailStreamBlockedError()
			}
		} else if streamRedactor != nil {
			if streamRedactor.Blocked() {
				_ = streamRedactor.Flush()
			}
			if streamRedactor.Redacted() {
				guardrailRedacted = true
			}
		}
		streamGuardrailBlocked := streamRedactor != nil && streamRedactor.Blocked()
		var streamTTFT time.Duration
		if meta != nil && meta.TTFTMs > 0 {
			streamTTFT = time.Duration(meta.TTFTMs) * time.Millisecond
		}
		s.collector.RecordStream(time.Since(streamStarted), streamTTFT, err != nil)
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
			if !sseWriter.Started() && !streamGuardrailBlocked {
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
		actualTokensReconciled = true
		releaseQuota(totalTok)

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
			if err := s.spendWorker.Record(r.Context(), domain.SpendEvent{
				RequestID:               reqID,
				TraceID:                 traceID,
				OrgID:                   idCtx.OrgID,
				TeamID:                  idCtx.TeamID,
				UserID:                  idCtx.UserID,
				VirtualKeyID:            idCtx.VirtualKeyID,
				Endpoint:                "/v1/chat/completions",
				RequestedModel:          chatReq.Model,
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
			}); err != nil {
				_ = sseWriter.WriteError(&domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "spend_persistence_unavailable", Message: "unable to persist request accounting"})
				return
			}
		}
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
	var resp *domain.CanonicalChatResponse
	var meta *router.ExecutionMeta

	if s.orchestrator != nil && len(chatReq.Tools) > 0 {
		resp, meta, err = s.orchestrator.ExecuteLoop(r.Context(), idCtx, &chatReq)
	} else {
		resp, meta, err = s.reliability.ExecuteChat(r.Context(), idCtx, &chatReq)
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
		domain.WriteHTTPError(w, err)
		return
	}

	actualTokensReconciled = true
	releaseQuota(resp.Usage.TotalTokens)

	// Output Guardrail PII sanitization (if enabled on the organization)
	redacted, guardrailOutputErr := s.guardrails.SanitizeOutputStrict(r.Context(), idCtx.OrgID, resp)
	if redacted {
		guardrailRedacted = true
		w.Header().Set("X-Gateway-Output-Redacted", "true")
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

	if cacheKey != "" && guardrailOutputErr == nil {
		s.respCache.SetWithMeta(r.Context(), cacheKey, idCtx.OrgID, resp)
	}
	responseStatus := http.StatusOK
	if guardrailOutputErr != nil {
		responseStatus = http.StatusServiceUnavailable
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
	if meta != nil {
		w.Header().Set("X-Gateway-Latency-Ms", strconv.FormatInt(meta.LatencyMs, 10))
		w.Header().Set("X-Gateway-Routing-Micros", strconv.FormatInt(meta.RoutingMicros, 10))
		w.Header().Set("X-Gateway-Fallback-Attempted", strconv.FormatBool(meta.FallbackAttempted))
		if meta.RouteDecision != nil {
			w.Header().Set("X-Gateway-Route-Reason", meta.RouteDecision.Reason)
		}
	}
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
		RequestedModel:          chatReq.Model,
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
		Model          string `json:"model"`
		Input          any    `json:"input"`
		EncodingFormat string `json:"encoding_format,omitempty"`
		Dimensions     *int   `json:"dimensions,omitempty"`
		InputType      string `json:"input_type,omitempty"`
		User           string `json:"user,omitempty"`
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
	guardedInputs, guardrailErr := s.guardrailTextValues(r.Context(), idCtx.OrgID, inputs...)
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
	releaseQuota, err := s.acquireRequestQuotaWithBound(r.Context(), idCtx, raw.Model, estTokens, inputByteBound, -1, reqID)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	embReq := &domain.CanonicalEmbeddingRequest{
		RequestID:      reqID,
		Model:          raw.Model,
		Input:          inputs,
		EncodingFormat: raw.EncodingFormat,
		Dimensions:     raw.Dimensions,
		InputType:      raw.InputType,
		User:           raw.User,
	}

	cacheHeader := r.Header.Get("X-Gateway-Cache-Control")
	var cacheKey string
	if s.respCache != nil && s.respCache.IsEmbeddingCacheable(embReq, cacheHeader) {
		cacheKey = s.respCache.ComputeEmbeddingKeyWithScope(idCtx.OrgID, idCtx.TeamID, cacheAllowedModelScope(idCtx), embReq)
		if cacheKey != "" {
			if cachedResp, hit := s.respCache.GetEmbedding(r.Context(), cacheKey); hit {
				releaseQuota(0)
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

	resp, meta, err := s.reliability.ExecuteEmbeddings(r.Context(), idCtx, embReq)
	if err != nil {
		releaseQuota(-1)
		domain.WriteHTTPError(w, err)
		return
	}
	releaseQuota(resp.Usage.TotalTokens)
	if cacheKey != "" {
		s.respCache.SetEmbeddingWithMeta(r.Context(), cacheKey, idCtx.OrgID, resp)
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
		RequestedModel:          raw.Model,
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
	var prefix string
	var models []string
	switch {
	case idCtx.KeyAllowedModels != nil:
		prefix = "key:"
		models = idCtx.KeyAllowedModels
	case idCtx.TeamAllowedModels != nil:
		prefix = "team:"
		models = idCtx.TeamAllowedModels
	default:
		return ""
	}
	sorted := make([]string, len(models))
	copy(sorted, models)
	sort.Strings(sorted)
	return prefix + strings.Join(sorted, ",")
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
