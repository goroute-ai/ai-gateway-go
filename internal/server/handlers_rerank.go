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

	// 2. Rate Limiting Quota Acquire (1 search unit per ~100 docs or min 1)
	quotaTokens := len(req.Documents) * 20
	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, quotaTokens)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
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
