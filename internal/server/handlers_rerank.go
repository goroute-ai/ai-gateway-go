package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

// handleRerank serves `POST /v1/rerank`, `POST /rerank`, and `POST /v2/rerank`.
func (s *GatewayServer) handleRerank(w http.ResponseWriter, r *http.Request) {
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
	if gwErr := s.applyRoutingHints(r, idCtx, &req.GoRouteExtensions); gwErr != nil {
		s.collector.Record(admissionFailureObservation(gwErr))
		domain.WriteHTTPError(w, gwErr)
		return
	}
	var texts []string
	var setters []func(string)
	appendTextField := func(val string, set func(string)) {
		if val == "" {
			return
		}
		texts = append(texts, val)
		setters = append(setters, set)
	}
	appendTextField(req.Query, func(v string) { req.Query = v })
	for i := range req.Documents {
		idx := i
		appendTextField(req.Documents[idx].Text, func(v string) { req.Documents[idx].Text = v })
		if req.Documents[idx].Raw != nil {
			collectRerankValueStrings(req.Documents[idx].Raw, &texts, &setters)
		}
	}
	guardedTexts, guardrailErr := s.evaluateNonChatTextGuardrails(r.Context(), w, r, idCtx, &req.Model, req.GoRouteExtensions, "rerank", texts...)
	if guardrailErr != nil {
		domain.WriteHTTPError(w, guardrailErr)
		return
	}
	for i, set := range setters {
		if i < len(guardedTexts) {
			set(guardedTexts[i])
		}
	}

	// Account for query and document lengths, including structured documents.
	quotaTokens := ratelimit.EstimateRerankTokens(req.Model, req.Query, req.Documents)
	quotaCtx, _ := withRequestQuotaState(r.Context(), r, idCtx, "", nil, req.GoRouteExtensions)
	r = r.WithContext(quotaCtx)
	releaseQuota, err := s.acquireModalityBudgetWithHeaders(w, r.Context(), idCtx, req.Model, quotaTokens, reqID, func(gm *domain.GlobalModel) (int64, bool) {
		return finops.EstimateRerankCostUpperBound(gm, len(req.Documents))
	})
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	resp, meta, err := s.reliability.ExecuteRerank(r.Context(), idCtx, &req)
	if err != nil {
		releaseQuota(-1, -1)
		s.emitRoutingTelemetryAndDebugHeaders(w, r, meta)
		s.collector.Record(observability.RequestObservation{
			StatusCode: http.StatusBadGateway,
		})
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

	searchUnits := resp.Usage.SearchUnits
	if searchUnits <= 0 {
		searchUnits = 1
	}
	costMicros := finops.CalculateRerankCostMicros(gm, searchUnits)
	releaseQuota(resp.Usage.TotalTokens, costMicros)
	var outputErr error
	for i := range resp.Results {
		if resp.Results[i].Document == nil {
			continue
		}
		updated, _, sanitizeErr := s.sanitizeGuardrailValue(r.Context(), idCtx.OrgID, resp.Results[i].Document)
		if sanitizeErr != nil {
			outputErr = sanitizeErr
			break
		}
		resp.Results[i].Document = updated.(map[string]any)
	}
	status := modalityResponseStatus(outputErr)
	pricingStatus := domain.ResolvePricingStatus(gm)

	s.collector.Record(observability.RequestObservation{
		Provider:       string(resp.Provider),
		DeploymentID:   depID,
		DeploymentName: depName,
		Model:          resp.Model,
		StatusCode:     status,
		LatencyMs:      meta.LatencyMs,
		RoutingMicros:  meta.RoutingMicros,
		CostMicros:     costMicros,
	})

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
		StatusCode:              status,
		Modality:                domain.ModalityRerank,
		ModalityUnits:           map[string]any{"search_units": searchUnits},
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	if outputErr != nil {
		domain.WriteHTTPError(w, outputErr)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)

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

func collectRerankValueStrings(raw any, texts *[]string, setters *[]func(string)) {
	switch v := raw.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			key := k
			switch child := v[key].(type) {
			case string:
				if child == "" {
					continue
				}
				*texts = append(*texts, child)
				*setters = append(*setters, func(next string) { v[key] = next })
			default:
				collectRerankValueStrings(child, texts, setters)
			}
		}
	case []any:
		for i := range v {
			idx := i
			switch child := v[idx].(type) {
			case string:
				if child == "" {
					continue
				}
				*texts = append(*texts, child)
				*setters = append(*setters, func(next string) { v[idx] = next })
			default:
				collectRerankValueStrings(child, texts, setters)
			}
		}
	case []string:
		for i := range v {
			idx := i
			if v[idx] == "" {
				continue
			}
			*texts = append(*texts, v[idx])
			*setters = append(*setters, func(next string) { v[idx] = next })
		}
	}
}
