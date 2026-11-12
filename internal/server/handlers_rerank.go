package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
)

// handleRerank serves `POST /v1/rerank`, `POST /rerank`, and `POST /v2/rerank`.
func (s *GatewayServer) handleRerank(w http.ResponseWriter, r *http.Request) {
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

	var req domain.CanonicalRerankRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse Rerank request body: " + err.Error(),
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
	if strings.TrimSpace(req.Query) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_query",
			Message:    "query parameter cannot be empty",
		})
		return
	}
	if len(req.Documents) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_documents",
			Message:    "documents array cannot be empty",
		})
		return
	}
	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, req.Model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}
	guardedQuery, guardrailErr := s.guardrailTextValues(r.Context(), idCtx.OrgID, req.Query)
	if guardrailErr != nil {
		domain.WriteHTTPError(w, guardrailErr)
		return
	}
	req.Query = guardedQuery[0]
	for i := range req.Documents {
		guardedText, err := s.guardrailTextValues(r.Context(), idCtx.OrgID, req.Documents[i].Text)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		req.Documents[i].Text = guardedText[0]
		if req.Documents[i].Raw != nil {
			updated, err := s.guardrailInputValue(r.Context(), idCtx.OrgID, req.Documents[i].Raw)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			req.Documents[i].Raw = updated.(map[string]any)
		}
	}

	// 2. Rate Limiting Quota Acquire (1 search unit per ~100 docs or min 1)
	quotaTokens := len(req.Documents) * 20
	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, quotaTokens)
	if err != nil {
		s.collector.Record(observability.RequestObservation{
			StatusCode:  http.StatusTooManyRequests,
			RateLimited: true,
		})
		domain.WriteHTTPError(w, err)
		return
	}

	resp, meta, err := s.reliability.ExecuteRerank(r.Context(), idCtx, &req)
	if err != nil {
		releaseQuota(0)
		s.collector.Record(observability.RequestObservation{
			StatusCode: http.StatusBadGateway,
		})
		domain.WriteHTTPError(w, err)
		return
	}
	releaseQuota(resp.Usage.TotalTokens)
	for i := range resp.Results {
		if resp.Results[i].Document == nil {
			continue
		}
		updated, _, sanitizeErr := s.sanitizeGuardrailValue(r.Context(), idCtx.OrgID, resp.Results[i].Document)
		if sanitizeErr != nil {
			domain.WriteHTTPError(w, sanitizeErr)
			return
		}
		resp.Results[i].Document = updated.(map[string]any)
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

	searchUnits := resp.Usage.SearchUnits
	if searchUnits <= 0 {
		searchUnits = 1
	}
	costMicros := finops.CalculateRerankCostMicros(gm, searchUnits)
	pricingStatus := domain.ResolvePricingStatus(gm)

	s.collector.Record(observability.RequestObservation{
		Provider:       string(resp.Provider),
		DeploymentID:   depID,
		DeploymentName: depName,
		Model:          resp.Model,
		StatusCode:     http.StatusOK,
		LatencyMs:      meta.LatencyMs,
		RoutingMicros:  meta.RoutingMicros,
		CostMicros:     costMicros,
	})

	w.Header().Set("X-Gateway-Provider", string(resp.Provider))
	w.Header().Set("X-Gateway-Cost-Micros", strconv.FormatInt(costMicros, 10))
	w.Header().Set("X-Gateway-Pricing-Status", string(pricingStatus))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	var provenance string
	if gm != nil {
		provenance = gm.PricingProvenanceSource
	}

	s.spendWorker.Enqueue(domain.SpendEvent{
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
		CostMicros:              costMicros,
		LatencyMs:               meta.LatencyMs,
		StatusCode:              http.StatusOK,
		Modality:                domain.ModalityRerank,
		ModalityUnits:           map[string]any{"search_units": searchUnits},
		CreatedAt:               time.Now().UTC(),
	})

	logger.InfoContext(r.Context(), "Rerank request completed",
		slog.String("component", "inference"),
		slog.String("request_id", reqID),
		slog.String("provider", string(resp.Provider)),
		slog.String("model", resp.Model),
		slog.Int("search_units", searchUnits),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}
