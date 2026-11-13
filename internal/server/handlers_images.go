package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

const maxImageUploadBytes = 20 << 20
const maxImagesPerRequest = 10

func readImageMultipart(w http.ResponseWriter, r *http.Request, requirePrompt bool) (imageData []byte, imageName string, maskData []byte, maskName string, err error) {
	r.Body = http.MaxBytesReader(w, r.Body, 2*maxImageUploadBytes+(1<<20))
	if err = r.ParseMultipartForm(1 << 20); err != nil {
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	image, imageHeader, openErr := r.FormFile("image")
	if openErr != nil {
		err = fmt.Errorf("image is required in 'image' form field")
		return
	}
	defer image.Close()
	imageData, err = io.ReadAll(io.LimitReader(image, maxImageUploadBytes+1))
	if err != nil {
		return
	}
	if len(imageData) > maxImageUploadBytes {
		err = fmt.Errorf("image exceeds maximum size of %d bytes", maxImageUploadBytes)
		return
	}
	if !bytes.HasPrefix(imageData, []byte("\x89PNG\r\n\x1a\n")) {
		err = fmt.Errorf("image must be a PNG file")
		return
	}
	imageName = filepath.Base(imageHeader.Filename)
	if requirePrompt && strings.TrimSpace(r.FormValue("prompt")) == "" {
		err = fmt.Errorf("prompt is required for image edits")
		return
	}
	if mask, maskHeader, maskErr := r.FormFile("mask"); maskErr == nil {
		defer mask.Close()
		maskData, err = io.ReadAll(io.LimitReader(mask, maxImageUploadBytes+1))
		if err != nil {
			return
		}
		if len(maskData) > maxImageUploadBytes {
			err = fmt.Errorf("mask exceeds maximum size of %d bytes", maxImageUploadBytes)
			return
		}
		if !bytes.HasPrefix(maskData, []byte("\x89PNG\r\n\x1a\n")) {
			err = fmt.Errorf("mask must be a PNG file")
			return
		}
		maskName = filepath.Base(maskHeader.Filename)
	}
	return
}

// handleImageGenerations serves `POST /v1/images/generations` and `POST /images/generations`.
func (s *GatewayServer) handleImageGenerations(w http.ResponseWriter, r *http.Request) {
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

	var req domain.CanonicalImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse Image Generation request body: " + err.Error(),
		})
		return
	}

	req.RequestID = reqID
	req.Model = strings.TrimSpace(req.Model)
	if req.Model == "" {
		req.Model = "dall-e-3"
	}
	if strings.TrimSpace(req.Prompt) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_prompt",
			Message:    "prompt parameter cannot be empty",
		})
		return
	}
	if req.N <= 0 {
		req.N = 1
	}
	if req.N > maxImagesPerRequest {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_image_count", Message: fmt.Sprintf("n must be between 1 and %d", maxImagesPerRequest)})
		return
	}

	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, req.Model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}
	guardedPrompt, guardrailErr := s.guardrailTextValues(r.Context(), idCtx.OrgID, req.Prompt)
	if guardrailErr != nil {
		domain.WriteHTTPError(w, guardrailErr)
		return
	}
	req.Prompt = guardedPrompt[0]

	// Include the prompt size as well as each generated image's work allowance.
	estTokens := ratelimit.EstimateImageGenerationTokens(req.Model, req.Prompt, req.N)
	releaseQuota, err := s.acquireModalityBudget(r.Context(), idCtx, req.Model, estTokens, reqID, func(gm *domain.GlobalModel) (int64, bool) {
		return finops.EstimateImageCostUpperBound(gm, req.Quality, req.Size, req.N)
	})
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	resp, meta, err := s.reliability.ExecuteImage(r.Context(), idCtx, &req)
	if err != nil {
		releaseQuota(-1)
		s.collector.Record(observability.RequestObservation{
			StatusCode: http.StatusBadGateway,
		})
		domain.WriteHTTPError(w, err)
		return
	}

	releaseQuota(estTokens)
	for i := range resp.Data {
		resp.Data[i].RevisedPrompt, err = s.sanitizeGuardrailText(r.Context(), idCtx.OrgID, resp.Data[i].RevisedPrompt)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
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

	numImages := len(resp.Data)
	if numImages <= 0 {
		numImages = req.N
	}
	costMicros := finops.CalculateImageCostMicros(gm, req.Quality, req.Size, numImages)
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
		Modality:                domain.ModalityImage,
		ModalityUnits: map[string]any{
			"images_count": numImages,
			"quality":      req.Quality,
			"size":         req.Size,
		},
		CreatedAt: time.Now().UTC(),
	}) {
		return
	}
	_ = json.NewEncoder(w).Encode(resp)

	logger.InfoContext(r.Context(), "Image generation completed",
		slog.String("component", "images"),
		slog.String("request_id", reqID),
		slog.String("model", resp.Model),
		slog.Int("count", numImages),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}

// handleImageEdits serves `POST /v1/images/edits` and `POST /images/edits`.
func (s *GatewayServer) handleImageEdits(w http.ResponseWriter, r *http.Request) {
	reqID := gatewayRequestID(r)
	w.Header().Set("X-Gateway-Request-Id", reqID)

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

	imageData, imageName, maskData, maskName, err := readImageMultipart(w, r, true)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_multipart",
			Message:    "Invalid image edit upload: " + err.Error(),
		})
		return
	}

	prompt := strings.TrimSpace(r.FormValue("prompt"))
	if prompt == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_prompt",
			Message:    "Field 'prompt' is required for image edits",
		})
		return
	}

	model := strings.TrimSpace(r.FormValue("model"))
	if model == "" {
		model = "dall-e-2"
	}

	if err := s.rbac.AuthorizeRequestedModel(idCtx, model); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	guardedPrompt, guardrailErr := s.guardrailTextValues(r.Context(), idCtx.OrgID, prompt)
	if guardrailErr != nil {
		domain.WriteHTTPError(w, guardrailErr)
		return
	}
	prompt = guardedPrompt[0]

	n := 1
	if nStr := r.FormValue("n"); nStr != "" {
		parsed, parseErr := strconv.Atoi(nStr)
		if parseErr != nil || parsed < 1 || parsed > maxImagesPerRequest {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_image_count", Message: fmt.Sprintf("n must be between 1 and %d", maxImagesPerRequest)})
			return
		}
		n = parsed
	}

	size := r.FormValue("size")
	if size == "" {
		size = "1024x1024"
	}

	req := domain.CanonicalImageRequest{
		RequestID:     reqID,
		Model:         model,
		Prompt:        prompt,
		N:             n,
		Size:          size,
		Operation:     "edit",
		ImageData:     imageData,
		ImageFilename: imageName,
		MaskData:      maskData,
		MaskFilename:  maskName,
	}
	estTokens := ratelimit.EstimateImageGenerationTokens(req.Model, req.Prompt, req.N)
	releaseQuota, err := s.acquireModalityBudget(r.Context(), idCtx, req.Model, estTokens, reqID, func(gm *domain.GlobalModel) (int64, bool) {
		return finops.EstimateImageCostUpperBound(gm, "standard", req.Size, req.N)
	})
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	resp, meta, err := s.reliability.ExecuteImage(r.Context(), idCtx, &req)
	if err != nil {
		releaseQuota(-1)
		domain.WriteHTTPError(w, err)
		return
	}
	releaseQuota(estTokens)
	for i := range resp.Data {
		resp.Data[i].RevisedPrompt, err = s.sanitizeGuardrailText(r.Context(), idCtx.OrgID, resp.Data[i].RevisedPrompt)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	}

	var gm *domain.GlobalModel
	var depID string
	var pricingVer int
	if meta != nil && meta.WinningDeployment != nil {
		depID = meta.WinningDeployment.ID
		gm = meta.WinningDeployment.GlobalModel
		if gm != nil {
			pricingVer = gm.PricingVersion
		}
	}

	numImages := len(resp.Data)
	if numImages <= 0 {
		numImages = n
	}
	costMicros := finops.CalculateImageCostMicros(gm, "standard", size, numImages)
	pricingStatus := domain.ResolvePricingStatus(gm)
	var provenance string
	if gm != nil {
		provenance = gm.PricingProvenanceSource
	}
	if !s.persistSpendEvent(w, r, domain.SpendEvent{
		ID:                      "sp_" + uuid.NewString(),
		RequestID:               reqID,
		OrgID:                   idCtx.OrgID,
		TeamID:                  idCtx.TeamID,
		UserID:                  idCtx.UserID,
		VirtualKeyID:            idCtx.VirtualKeyID,
		Endpoint:                "/v1/images/edits",
		Provider:                resp.Provider,
		RequestedModel:          model,
		ResolvedModel:           resp.Model,
		DeploymentID:            depID,
		PricingVersion:          pricingVer,
		PricingStatus:           pricingStatus,
		PricingProvenanceSource: provenance,
		CostMicros:              costMicros,
		StatusCode:              http.StatusOK,
		Modality:                domain.ModalityImage,
		ModalityUnits:           map[string]any{"images_count": numImages, "quality": "standard", "size": size},
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleImageVariations serves `POST /v1/images/variations` and `POST /images/variations`.
func (s *GatewayServer) handleImageVariations(w http.ResponseWriter, r *http.Request) {
	reqID := gatewayRequestID(r)
	w.Header().Set("X-Gateway-Request-Id", reqID)

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

	imageData, imageName, _, _, err := readImageMultipart(w, r, false)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_multipart",
			Message:    "Invalid image variation upload: " + err.Error(),
		})
		return
	}

	model := strings.TrimSpace(r.FormValue("model"))
	if model == "" {
		model = "dall-e-2"
	}

	if err := s.rbac.AuthorizeRequestedModel(idCtx, model); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	n := 1
	if nStr := r.FormValue("n"); nStr != "" {
		parsed, parseErr := strconv.Atoi(nStr)
		if parseErr != nil || parsed < 1 || parsed > maxImagesPerRequest {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_image_count", Message: fmt.Sprintf("n must be between 1 and %d", maxImagesPerRequest)})
			return
		}
		n = parsed
	}

	size := r.FormValue("size")
	if size == "" {
		size = "1024x1024"
	}

	req := domain.CanonicalImageRequest{
		RequestID:     reqID,
		Model:         model,
		Prompt:        "Image variation",
		N:             n,
		Size:          size,
		Operation:     "variation",
		ImageData:     imageData,
		ImageFilename: imageName,
	}
	estTokens := ratelimit.EstimateImageGenerationTokens(req.Model, req.Prompt, req.N)
	releaseQuota, err := s.acquireModalityBudget(r.Context(), idCtx, req.Model, estTokens, reqID, func(gm *domain.GlobalModel) (int64, bool) {
		return finops.EstimateImageCostUpperBound(gm, "standard", req.Size, req.N)
	})
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	resp, meta, err := s.reliability.ExecuteImage(r.Context(), idCtx, &req)
	if err != nil {
		releaseQuota(-1)
		domain.WriteHTTPError(w, err)
		return
	}
	releaseQuota(estTokens)
	for i := range resp.Data {
		resp.Data[i].RevisedPrompt, err = s.sanitizeGuardrailText(r.Context(), idCtx.OrgID, resp.Data[i].RevisedPrompt)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	}

	var gm *domain.GlobalModel
	var depID string
	var pricingVer int
	if meta != nil && meta.WinningDeployment != nil {
		depID = meta.WinningDeployment.ID
		gm = meta.WinningDeployment.GlobalModel
		if gm != nil {
			pricingVer = gm.PricingVersion
		}
	}

	numImages := len(resp.Data)
	if numImages <= 0 {
		numImages = n
	}
	costMicros := finops.CalculateImageCostMicros(gm, "standard", size, numImages)
	pricingStatus := domain.ResolvePricingStatus(gm)
	var provenance string
	if gm != nil {
		provenance = gm.PricingProvenanceSource
	}
	if !s.persistSpendEvent(w, r, domain.SpendEvent{
		ID:                      "sp_" + uuid.NewString(),
		RequestID:               reqID,
		OrgID:                   idCtx.OrgID,
		TeamID:                  idCtx.TeamID,
		UserID:                  idCtx.UserID,
		VirtualKeyID:            idCtx.VirtualKeyID,
		Endpoint:                "/v1/images/variations",
		Provider:                resp.Provider,
		RequestedModel:          model,
		ResolvedModel:           resp.Model,
		DeploymentID:            depID,
		PricingVersion:          pricingVer,
		PricingStatus:           pricingStatus,
		PricingProvenanceSource: provenance,
		CostMicros:              costMicros,
		StatusCode:              http.StatusOK,
		Modality:                domain.ModalityImage,
		ModalityUnits:           map[string]any{"images_count": numImages, "quality": "standard", "size": size},
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
