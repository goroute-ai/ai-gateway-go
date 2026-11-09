package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
)

// handleChatCompletions serves `POST /v1/chat/completions` (both synchronous JSON and SSE streaming).
func (s *GatewayServer) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "req_" + uuid.NewString()
	}
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
	if err := json.NewDecoder(r.Body).Decode(&chatReq); err != nil {
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

	// A2A OpenAI Compatibility Bridge (BL-06): route model: "a2a/{slug}" directly to A2A bridge
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
		s.collector.Record(observability.RequestObservation{
			StatusCode:       http.StatusBadRequest,
			GuardrailBlocked: true,
		})
		domain.WriteHTTPError(w, err)
		return
	}

	// 2. Atomic Rate Limit / Budget Check
	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, estTokens)
	if err != nil {
		s.collector.Record(observability.RequestObservation{
			StatusCode:  http.StatusTooManyRequests,
			RateLimited: true,
		})
		domain.WriteHTTPError(w, err)
		return
	}
	actualTokensReconciled := false
	defer func() {
		if !actualTokensReconciled {
			releaseQuota(0)
		}
	}()

	// 3. Exact-Match Response Cache Check (Non-Streaming Deterministic Requests)
	cacheHeader := r.Header.Get("X-Gateway-Cache-Control")
	var cacheKey string
	if s.respCache.IsCacheable(&chatReq, cacheHeader) {
		cacheKey = s.respCache.ComputeKey(idCtx.OrgID, &chatReq)
		if cachedResp, hit := s.respCache.Get(r.Context(), cacheKey); hit {
			actualTokensReconciled = true
			releaseQuota(0)
			s.collector.Record(observability.RequestObservation{
				Provider:          string(cachedResp.Provider),
				Model:             cachedResp.Model,
				StatusCode:        http.StatusOK,
				CacheHit:          true,
				GuardrailRedacted: guardrailRedacted,
			})
			w.Header().Set("X-Gateway-Cache", "HIT")
			w.Header().Set("X-Gateway-Provider", string(cachedResp.Provider))
			w.Header().Set("X-Gateway-Model", cachedResp.Model)
			w.Header().Set("X-Gateway-Cost-Micros", "0")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cachedResp)

			s.spendWorker.Enqueue(domain.SpendEvent{
				RequestID:      reqID,
				TraceID:        traceID,
				OrgID:          idCtx.OrgID,
				TeamID:         idCtx.TeamID,
				UserID:         idCtx.UserID,
				VirtualKeyID:   idCtx.VirtualKeyID,
				Endpoint:       "/v1/chat/completions",
				RequestedModel: chatReq.Model,
				ResolvedModel:  cachedResp.Model,
				Provider:       cachedResp.Provider,
				Usage:          cachedResp.Usage,
				CostMicros:     0,
				StatusCode:     http.StatusOK,
				CacheHit:       true,
				CreatedAt:      time.Now().UTC(),
			})
			logger.InfoContext(r.Context(), "Inference request served from cache",
				slog.String("component", "inference"),
				slog.String("request_id", reqID),
				slog.String("provider", string(cachedResp.Provider)),
				slog.String("model", cachedResp.Model),
				slog.Bool("cache_hit", true),
			)
			return
		}
		w.Header().Set("X-Gateway-Cache", "MISS")
	}

	// 4. Streaming SSE Execution Path
	if chatReq.Stream {
		sseWriter, err := sse.NewWriter(w)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}

		var usage *domain.TokenUsage
		var meta *router.ExecutionMeta

		if s.orchestrator != nil && len(chatReq.Tools) > 0 {
			usage, meta, err = s.orchestrator.ExecuteStreamLoop(r.Context(), idCtx, &chatReq, func(chunk *domain.CanonicalStreamChunk) error {
				return sseWriter.WriteChunk(chunk)
			})
		} else {
			usage, meta, err = s.reliability.ExecuteStream(r.Context(), idCtx, &chatReq, func(chunk *domain.CanonicalStreamChunk) error {
				return sseWriter.WriteChunk(chunk)
			})
		}
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
				GuardrailRedacted: guardrailRedacted,
			})
			if !sseWriter.Started() {
				domain.WriteHTTPError(w, err)
			} else {
				// Mid-stream failure after HTTP 200 and initial chunks were committed:
				// emit structured error SSE event before [DONE] instead of restarting stream.
				_ = sseWriter.WriteError(err)
			}
			return
		}
		_ = sseWriter.WriteDone()

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
		s.spendWorker.Enqueue(domain.SpendEvent{
			RequestID:         reqID,
			TraceID:           traceID,
			OrgID:             idCtx.OrgID,
			TeamID:            idCtx.TeamID,
			UserID:            idCtx.UserID,
			VirtualKeyID:      idCtx.VirtualKeyID,
			Endpoint:          "/v1/chat/completions",
			RequestedModel:    chatReq.Model,
			ResolvedModel:     resolvedModel,
			Provider:          provider,
			DeploymentID:      depID,
			PricingVersion:    pricingVer,
			Usage:             usageVal,
			CostMicros:        costMicros,
			LatencyMs:         meta.LatencyMs,
			TTFTMs:            meta.TTFTMs,
			StatusCode:        http.StatusOK,
			IsStream:          true,
			FallbackAttempted: meta.FallbackAttempted,
			RetryCount:        meta.RetryCount,
			CreatedAt:         time.Now().UTC(),
		})
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
	if s.guardrails.SanitizeOutput(r.Context(), idCtx.OrgID, resp) {
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

	if cacheKey != "" {
		s.respCache.SetWithMeta(r.Context(), cacheKey, idCtx.OrgID, resp)
	}

	s.collector.Record(observability.RequestObservation{
		Provider:          string(resp.Provider),
		DeploymentID:      depID,
		DeploymentName:    depName,
		Model:             resp.Model,
		StatusCode:        http.StatusOK,
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

	w.Header().Set("X-Gateway-Provider", string(resp.Provider))
	w.Header().Set("X-Gateway-Model", resp.Model)
	w.Header().Set("X-Gateway-Cost-Micros", strconv.FormatInt(costMicros, 10))
	w.Header().Set("X-Gateway-Pricing-Version", strconv.Itoa(pricingVer))
	if meta != nil {
		w.Header().Set("X-Gateway-Latency-Ms", strconv.FormatInt(meta.LatencyMs, 10))
		w.Header().Set("X-Gateway-Routing-Micros", strconv.FormatInt(meta.RoutingMicros, 10))
		w.Header().Set("X-Gateway-Fallback-Attempted", strconv.FormatBool(meta.FallbackAttempted))
		if meta.RouteDecision != nil {
			w.Header().Set("X-Gateway-Route-Reason", meta.RouteDecision.Reason)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	s.spendWorker.Enqueue(domain.SpendEvent{
		RequestID:         reqID,
		TraceID:           traceID,
		OrgID:             idCtx.OrgID,
		TeamID:            idCtx.TeamID,
		UserID:            idCtx.UserID,
		VirtualKeyID:      idCtx.VirtualKeyID,
		Endpoint:          "/v1/chat/completions",
		RequestedModel:    chatReq.Model,
		ResolvedModel:     resp.Model,
		Provider:          resp.Provider,
		DeploymentID:      depID,
		PricingVersion:    pricingVer,
		Usage:             resp.Usage,
		CostMicros:        costMicros,
		LatencyMs:         meta.LatencyMs,
		TTFTMs:            meta.TTFTMs,
		StatusCode:        http.StatusOK,
		IsStream:          false,
		FallbackAttempted: meta.FallbackAttempted,
		RetryCount:        meta.RetryCount,
		CreatedAt:         time.Now().UTC(),
	})
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
	reqID := "req_" + uuid.NewString()
	w.Header().Set("X-Gateway-Request-Id", reqID)
	traceID := observability.TraceFromContext(r.Context()).TraceID

	idCtx := auth.IdentityFromContext(r.Context())

	var raw struct {
		Model          string `json:"model"`
		Input          any    `json:"input"`
		EncodingFormat string `json:"encoding_format,omitempty"`
		Dimensions     *int   `json:"dimensions,omitempty"`
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

	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, len(inputs)*16)
	if err != nil {
		s.collector.Record(observability.RequestObservation{
			StatusCode:  http.StatusTooManyRequests,
			RateLimited: true,
		})
		domain.WriteHTTPError(w, err)
		return
	}

	embReq := &domain.CanonicalEmbeddingRequest{
		RequestID:      reqID,
		Model:          raw.Model,
		Input:          inputs,
		EncodingFormat: raw.EncodingFormat,
		Dimensions:     raw.Dimensions,
		User:           raw.User,
	}
	resp, meta, err := s.reliability.ExecuteEmbeddings(r.Context(), idCtx, embReq)
	if err != nil {
		releaseQuota(0)
		domain.WriteHTTPError(w, err)
		return
	}
	releaseQuota(resp.Usage.TotalTokens)

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

	w.Header().Set("X-Gateway-Provider", string(resp.Provider))
	w.Header().Set("X-Gateway-Cost-Micros", strconv.FormatInt(costMicros, 10))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	s.spendWorker.Enqueue(domain.SpendEvent{
		RequestID:      reqID,
		TraceID:        traceID,
		OrgID:          idCtx.OrgID,
		TeamID:         idCtx.TeamID,
		UserID:         idCtx.UserID,
		VirtualKeyID:   idCtx.VirtualKeyID,
		Endpoint:       "/v1/embeddings",
		RequestedModel: raw.Model,
		ResolvedModel:  resp.Model,
		Provider:       resp.Provider,
		DeploymentID:   depID,
		PricingVersion: pricingVer,
		Usage:          resp.Usage,
		CostMicros:     costMicros,
		LatencyMs:      meta.LatencyMs,
		StatusCode:     http.StatusOK,
		CreatedAt:      time.Now().UTC(),
	})
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
