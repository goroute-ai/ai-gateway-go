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
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

// handleModerations serves `POST /v1/moderations` and `POST /moderations`.
func (s *GatewayServer) handleModerations(w http.ResponseWriter, r *http.Request) {
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

	var raw struct {
		Model string `json:"model"`
		Input any    `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse Moderation request body: " + err.Error(),
		})
		return
	}

	var inputs []string
	switch v := raw.Input.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			inputs = []string{v}
		}
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok && strings.TrimSpace(str) != "" {
				inputs = append(inputs, str)
			} else {
				inputs = append(inputs, fmt.Sprintf("%v", item))
			}
		}
	case []string:
		inputs = v
	}

	if len(inputs) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_input",
			Message:    "input parameter cannot be empty",
		})
		return
	}

	model := strings.TrimSpace(raw.Model)
	if model == "" {
		model = "omni-moderation-latest"
	}

	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}
	guardedInputs, guardrailErr := s.guardrailTextValues(r.Context(), idCtx.OrgID, inputs...)
	if guardrailErr != nil {
		domain.WriteHTTPError(w, guardrailErr)
		return
	}
	inputs = guardedInputs

	// Estimate the actual text volume, not only the number of input elements.
	estTokens := ratelimit.EstimateTextInputsTokens(model, inputs, 4)
	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, estTokens)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	modReq := &domain.CanonicalModerationRequest{
		RequestID: reqID,
		Model:     model,
		Input:     inputs,
	}

	resp, meta, err := s.reliability.ExecuteModeration(r.Context(), idCtx, modReq)
	if err != nil {
		releaseQuota(-1)
		s.collector.Record(observability.RequestObservation{
			StatusCode: http.StatusBadGateway,
		})
		domain.WriteHTTPError(w, err)
		return
	}
	releaseQuota(estTokens)

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

	costMicros := int64(0) // Standard provider moderations are currently zero-cost
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
		RequestedModel:          model,
		ResolvedModel:           resp.Model,
		Provider:                resp.Provider,
		DeploymentID:            depID,
		PricingVersion:          pricingVer,
		PricingStatus:           pricingStatus,
		PricingProvenanceSource: provenance,
		CostMicros:              costMicros,
		LatencyMs:               meta.LatencyMs,
		StatusCode:              http.StatusOK,
		Modality:                domain.ModalityModeration,
		ModalityUnits:           map[string]any{"input_items": len(inputs)},
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	_ = json.NewEncoder(w).Encode(resp)

	logger.InfoContext(r.Context(), "Moderation request completed",
		slog.String("component", "inference"),
		slog.String("request_id", reqID),
		slog.String("provider", string(resp.Provider)),
		slog.String("model", resp.Model),
		slog.Int("input_count", len(inputs)),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}
