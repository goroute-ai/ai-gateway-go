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
)

const maxImageUploadBytes = 20 << 20

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
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "img_" + uuid.NewString()
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

	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, req.Model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}

	// 2. Rate Limiting Quota Acquire (100 tokens estimate per generated image)
	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, req.N*100)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	resp, meta, err := s.reliability.ExecuteImage(r.Context(), idCtx, &req)
	if err != nil {
		releaseQuota(0)
		s.collector.Record(observability.RequestObservation{
			StatusCode: http.StatusBadGateway,
		})
		domain.WriteHTTPError(w, err)
		return
	}
	releaseQuota(req.N * 100)

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
		Modality:                domain.ModalityImage,
		ModalityUnits: map[string]any{
			"images_count": numImages,
			"quality":      req.Quality,
			"size":         req.Size,
		},
		CreatedAt: time.Now().UTC(),
	})

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
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "img_edit_" + uuid.NewString()
	}
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

	n := 1
	if nStr := r.FormValue("n"); nStr != "" {
		if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
			n = parsed
		}
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

	resp, meta, err := s.reliability.ExecuteImage(r.Context(), idCtx, &req)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
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

	costMicros := finops.CalculateImageCostMicros(gm, "standard", size, n)
	if s.spendWorker != nil {
		s.spendWorker.Enqueue(domain.SpendEvent{
			ID:             "sp_" + uuid.NewString(),
			RequestID:      reqID,
			OrgID:          idCtx.OrgID,
			TeamID:         idCtx.TeamID,
			UserID:         idCtx.UserID,
			VirtualKeyID:   idCtx.VirtualKeyID,
			Endpoint:       "/v1/images/edits",
			Modality:       domain.ModalityImage,
			RequestedModel: model,
			ResolvedModel:  resp.Model,
			DeploymentID:   depID,
			PricingVersion: pricingVer,
			CostMicros:     costMicros,
			StatusCode:     http.StatusOK,
			CreatedAt:      time.Now().UTC(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleImageVariations serves `POST /v1/images/variations` and `POST /images/variations`.
func (s *GatewayServer) handleImageVariations(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "img_var_" + uuid.NewString()
	}
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
		if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
			n = parsed
		}
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

	resp, meta, err := s.reliability.ExecuteImage(r.Context(), idCtx, &req)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
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

	costMicros := finops.CalculateImageCostMicros(gm, "standard", size, n)
	if s.spendWorker != nil {
		s.spendWorker.Enqueue(domain.SpendEvent{
			ID:             "sp_" + uuid.NewString(),
			RequestID:      reqID,
			OrgID:          idCtx.OrgID,
			TeamID:         idCtx.TeamID,
			UserID:         idCtx.UserID,
			VirtualKeyID:   idCtx.VirtualKeyID,
			Endpoint:       "/v1/images/variations",
			Modality:       domain.ModalityImage,
			RequestedModel: model,
			ResolvedModel:  resp.Model,
			DeploymentID:   depID,
			PricingVersion: pricingVer,
			CostMicros:     costMicros,
			StatusCode:     http.StatusOK,
			CreatedAt:      time.Now().UTC(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
