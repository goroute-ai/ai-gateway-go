package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
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

const maxAudioUploadBytes = 25 * 1024 * 1024 // 25 MB

// handleAudioTranscriptions serves `POST /v1/audio/transcriptions` and `POST /audio/transcriptions`.
func (s *GatewayServer) handleAudioTranscriptions(w http.ResponseWriter, r *http.Request) {
	s.processAudioSTT(w, r, false)
}

// handleAudioTranslations serves `POST /v1/audio/translations` and `POST /audio/translations`.
func (s *GatewayServer) handleAudioTranslations(w http.ResponseWriter, r *http.Request) {
	s.processAudioSTT(w, r, true)
}

func (s *GatewayServer) processAudioSTT(w http.ResponseWriter, r *http.Request, isTranslation bool) {
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		prefix := "stt_"
		if isTranslation {
			prefix = "stt_translation_"
		}
		reqID = prefix + uuid.NewString()
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

	if r.ContentLength > maxAudioUploadBytes {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "file_too_large",
			Message:    fmt.Sprintf("Audio upload exceeds maximum allowed limit of %d bytes", maxAudioUploadBytes),
		})
		return
	}

	// Limit reader to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxAudioUploadBytes)
	if err := r.ParseMultipartForm(maxAudioUploadBytes); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_multipart_body",
			Message:    "Failed to parse multipart form: " + err.Error(),
		})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_file",
			Message:    "audio file is required in 'file' form field",
		})
		return
	}
	defer file.Close()

	model := strings.TrimSpace(r.FormValue("model"))
	if model == "" {
		model = "whisper-1"
	}

	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}

	// 2. Retryable Disk Spooling
	tmpFile, err := os.CreateTemp("", "gw-audio-*.tmp")
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "spool_creation_failed",
			Message:    "Failed to create temporary audio spool: " + err.Error(),
		})
		return
	}
	spoolPath := tmpFile.Name()
	defer os.Remove(spoolPath)

	if _, err := io.Copy(tmpFile, file); err != nil {
		_ = tmpFile.Close()
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "spool_write_failed",
			Message:    "Failed to write audio spool: " + err.Error(),
		})
		return
	}
	_ = tmpFile.Close() // Close so readers can open concurrently

	// Audio tokenization varies by provider. Use the upload size and optional
	// prompt for a conservative preflight estimate rather than a fixed allowance.
	estTokens := ratelimit.EstimateAudioUploadTokens(model, header.Size, r.FormValue("prompt"))
	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, estTokens)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	sttReq := domain.CanonicalAudioTranscriptionRequest{
		RequestID:      reqID,
		Model:          model,
		FileName:       header.Filename,
		SpoolFilePath:  spoolPath,
		Language:       r.FormValue("language"),
		Prompt:         r.FormValue("prompt"),
		ResponseFormat: r.FormValue("response_format"),
	}

	resp, meta, err := s.reliability.ExecuteAudioTranscription(r.Context(), idCtx, &sttReq)
	if err != nil {
		releaseQuota(0)
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusBadGateway})
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

	costMicros := finops.CalculateAudioSTTCostMicros(gm, resp.DurationMs)
	pricingStatus := domain.ResolvePricingStatus(gm)

	s.collector.Record(observability.RequestObservation{
		Provider:       string(meta.WinningDeployment.GlobalModel.Provider),
		DeploymentID:   depID,
		DeploymentName: depName,
		Model:          model,
		StatusCode:     http.StatusOK,
		LatencyMs:      meta.LatencyMs,
		RoutingMicros:  meta.RoutingMicros,
		CostMicros:     costMicros,
	})

	w.Header().Set("X-Gateway-Provider", string(meta.WinningDeployment.GlobalModel.Provider))
	w.Header().Set("X-Gateway-Cost-Micros", strconv.FormatInt(costMicros, 10))
	w.Header().Set("X-Gateway-Pricing-Status", string(pricingStatus))

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
		ResolvedModel:           sttReq.ResolvedModel,
		Provider:                meta.WinningDeployment.GlobalModel.Provider,
		DeploymentID:            depID,
		PricingVersion:          pricingVer,
		PricingStatus:           pricingStatus,
		PricingProvenanceSource: provenance,
		CostMicros:              costMicros,
		LatencyMs:               meta.LatencyMs,
		StatusCode:              http.StatusOK,
		Modality:                domain.ModalityAudioSTT,
		ModalityUnits:           map[string]any{"duration_ms": resp.DurationMs},
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	if sttReq.ResponseFormat == "text" {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(resp.Text))
	} else {
		w.Header().Set("Content-Type", "application/json")
		if resp.Raw != nil {
			_ = json.NewEncoder(w).Encode(resp.Raw)
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"text": resp.Text, "duration_ms": resp.DurationMs})
		}
	}

	logger.InfoContext(r.Context(), "Audio transcription completed",
		slog.String("component", "audio"),
		slog.String("request_id", reqID),
		slog.String("model", model),
		slog.Int64("duration_ms", resp.DurationMs),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}

// handleAudioSpeech serves `POST /v1/audio/speech` and `POST /audio/speech`.
func (s *GatewayServer) handleAudioSpeech(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "tts_" + uuid.NewString()
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

	var raw domain.CanonicalAudioSpeechRequest
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse speech request: " + err.Error(),
		})
		return
	}
	raw.RequestID = reqID
	raw.Model = strings.TrimSpace(raw.Model)
	if raw.Model == "" {
		raw.Model = "tts-1"
	}
	if strings.TrimSpace(raw.Input) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_input",
			Message:    "input text cannot be empty",
		})
		return
	}
	if raw.Voice == "" {
		raw.Voice = "alloy"
	}

	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, raw.Model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}

	// TTS quota follows the target model's text token profile.
	estTokens := ratelimit.EstimateTextTokens(raw.Input, ratelimit.ResolveTokenizerProfile(raw.Model))
	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, estTokens)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	stream, contentType, meta, err := s.reliability.ExecuteAudioSpeech(r.Context(), idCtx, &raw)
	if err != nil {
		releaseQuota(0)
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusBadGateway})
		domain.WriteHTTPError(w, err)
		return
	}
	defer stream.Close()
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

	costMicros := finops.CalculateAudioTTSCostMicros(gm, len(raw.Input))
	pricingStatus := domain.ResolvePricingStatus(gm)

	s.collector.Record(observability.RequestObservation{
		Provider:       string(meta.WinningDeployment.GlobalModel.Provider),
		DeploymentID:   depID,
		DeploymentName: depName,
		Model:          raw.Model,
		StatusCode:     http.StatusOK,
		LatencyMs:      meta.LatencyMs,
		RoutingMicros:  meta.RoutingMicros,
		CostMicros:     costMicros,
	})

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Gateway-Provider", string(meta.WinningDeployment.GlobalModel.Provider))
	w.Header().Set("X-Gateway-Cost-Micros", strconv.FormatInt(costMicros, 10))
	w.Header().Set("X-Gateway-Pricing-Status", string(pricingStatus))

	streamBytes, readErr := io.ReadAll(stream)
	if readErr != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadGateway, Type: domain.ErrorTypeUpstream, Code: "audio_stream_read_failed", Message: "unable to read upstream audio response"})
		return
	}

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
		RequestedModel:          raw.Model,
		ResolvedModel:           raw.ResolvedModel,
		Provider:                meta.WinningDeployment.GlobalModel.Provider,
		DeploymentID:            depID,
		PricingVersion:          pricingVer,
		PricingStatus:           pricingStatus,
		PricingProvenanceSource: provenance,
		CostMicros:              costMicros,
		LatencyMs:               meta.LatencyMs,
		StatusCode:              http.StatusOK,
		Modality:                domain.ModalityAudioTTS,
		ModalityUnits:           map[string]any{"character_count": len(raw.Input)},
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	_, _ = w.Write(streamBytes)

	logger.InfoContext(r.Context(), "Audio speech synthesis completed",
		slog.String("component", "audio"),
		slog.String("request_id", reqID),
		slog.String("model", raw.Model),
		slog.Int("character_count", len(raw.Input)),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}
