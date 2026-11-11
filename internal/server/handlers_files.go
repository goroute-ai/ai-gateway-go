package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const maxFileUploadBytes = 512 * 1024 * 1024 // 512 MB

func (s *GatewayServer) maxFileStorageBytesPerOrg() int64 {
	if s.cfg == nil {
		return 0
	}
	return s.cfg.Server.MaxFileStorageBytesPerOrg
}

func (s *GatewayServer) orgUsedFileBytes(ctx context.Context, orgID string) (int64, error) {
	files, err := s.repo.ListFiles(ctx, orgID, "")
	if err != nil {
		return 0, err
	}
	var total int64
	for _, f := range files {
		if f != nil && f.Bytes > 0 {
			total += f.Bytes
		}
	}
	return total, nil
}

func (s *GatewayServer) reserveOrgUploadBytes(ctx context.Context, orgID string, expectedBytes int64) (int64, error) {
	maxBytes := s.maxFileStorageBytesPerOrg()
	if maxBytes <= 0 {
		return 0, nil
	}
	if expectedBytes < 0 {
		expectedBytes = 0
	}

	used, err := s.orgUsedFileBytes(ctx, orgID)
	if err != nil {
		return 0, err
	}

	s.uploadInFlightMu.Lock()
	defer s.uploadInFlightMu.Unlock()
	if s.uploadInFlight == nil {
		s.uploadInFlight = make(map[string]int64)
	}
	inFlight := s.uploadInFlight[orgID]
	if used+inFlight+expectedBytes > maxBytes {
		return 0, fmt.Errorf("organization file storage quota exceeded (%d / %d bytes)", used+inFlight+expectedBytes, maxBytes)
	}
	if expectedBytes > 0 {
		s.uploadInFlight[orgID] = inFlight + expectedBytes
	}
	return expectedBytes, nil
}

func (s *GatewayServer) releaseOrgUploadBytes(orgID string, reserved int64) {
	if reserved <= 0 {
		return
	}
	s.uploadInFlightMu.Lock()
	defer s.uploadInFlightMu.Unlock()
	if cur := s.uploadInFlight[orgID] - reserved; cur > 0 {
		s.uploadInFlight[orgID] = cur
	} else {
		delete(s.uploadInFlight, orgID)
	}
}

func getStorageDir() string {
	dir := os.Getenv("GOROUTE_FILES_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "goroute-files")
	}
	_ = os.MkdirAll(dir, 0700)
	_ = os.Chmod(dir, 0700)
	return dir
}

// handleUploadFile serves `POST /v1/files` and `POST /files`.
func (s *GatewayServer) handleUploadFile(w http.ResponseWriter, r *http.Request) {
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

	if s.uploadSem != nil {
		select {
		case s.uploadSem <- struct{}{}:
			defer func() { <-s.uploadSem }()
		default:
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusTooManyRequests,
				Type:       domain.ErrorTypeRateLimit,
				Code:       "upload_concurrency_limit",
				Message:    "Too many concurrent file uploads; please retry shortly",
			})
			return
		}
	}

	if r.ContentLength > maxFileUploadBytes {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "file_too_large",
			Message:    fmt.Sprintf("File exceeds maximum upload limit of %d bytes", maxFileUploadBytes),
		})
		return
	}

	reservedBytes, err := s.reserveOrgUploadBytes(r.Context(), idCtx.OrgID, r.ContentLength)
	if err != nil {
		status := http.StatusRequestEntityTooLarge
		errType := domain.ErrorTypeInvalidRequest
		code := "storage_quota_exceeded"
		if !strings.Contains(err.Error(), "quota exceeded") {
			status = http.StatusInternalServerError
			errType = domain.ErrorTypeServer
			code = "db_error"
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: status,
			Type:       errType,
			Code:       code,
			Message:    err.Error(),
		})
		return
	}
	defer func() {
		s.releaseOrgUploadBytes(idCtx.OrgID, reservedBytes)
	}()

	r.Body = http.MaxBytesReader(w, r.Body, maxFileUploadBytes)
	if err := r.ParseMultipartForm(32 * 1024 * 1024); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_multipart",
			Message:    "Failed to parse multipart form: " + err.Error(),
		})
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_file",
			Message:    "file is required in 'file' form field",
		})
		return
	}
	defer file.Close()

	purpose := strings.TrimSpace(r.FormValue("purpose"))
	if purpose == "" {
		purpose = "batch"
	}

	// Re-check quota with actual part size when Content-Length was unknown/chunked.
	if reservedBytes == 0 && header.Size > 0 {
		extraReserved, qErr := s.reserveOrgUploadBytes(r.Context(), idCtx.OrgID, header.Size)
		if qErr != nil {
			status := http.StatusRequestEntityTooLarge
			errType := domain.ErrorTypeInvalidRequest
			code := "storage_quota_exceeded"
			if !strings.Contains(qErr.Error(), "quota exceeded") {
				status = http.StatusInternalServerError
				errType = domain.ErrorTypeServer
				code = "db_error"
			}
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: status,
				Type:       errType,
				Code:       code,
				Message:    qErr.Error(),
			})
			return
		}
		reservedBytes += extraReserved
	}

	fileID := "file-" + uuid.NewString()
	storagePath := filepath.Join(getStorageDir(), fileID)

	dst, err := os.OpenFile(storagePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    "Failed to create file on disk: " + err.Error(),
		})
		return
	}
	defer dst.Close()

	hasher := sha256.New()
	mw := io.MultiWriter(dst, hasher)
	written, err := io.Copy(mw, file)
	if err != nil {
		_ = os.Remove(storagePath)
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "write_error",
			Message:    "Failed to write file contents: " + err.Error(),
		})
		return
	}
	if err := dst.Sync(); err != nil {
		_ = os.Remove(storagePath)
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "write_error", Message: "Failed to sync uploaded file to storage"})
		return
	}

	contentSHA := hex.EncodeToString(hasher.Sum(nil))

	fileRecord := &domain.CanonicalFile{
		ID:            fileID,
		OrgID:         idCtx.OrgID,
		TeamID:        idCtx.TeamID,
		UserID:        idCtx.UserID,
		Bytes:         written,
		CreatedAt:     time.Now().UTC(),
		Filename:      header.Filename,
		Purpose:       purpose,
		Status:        "uploaded",
		ContentSHA256: contentSHA,
		StoragePath:   storagePath,
	}

	if err := s.repo.CreateFile(r.Context(), fileRecord); err != nil {
		_ = os.Remove(storagePath)
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "db_error",
			Message:    "Failed to store file record: " + err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(fileRecord)
}

// handleListFiles serves `GET /v1/files` and `GET /files`.
func (s *GatewayServer) handleListFiles(w http.ResponseWriter, r *http.Request) {
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

	purpose := r.URL.Query().Get("purpose")
	files, err := s.repo.ListFiles(r.Context(), idCtx.OrgID, purpose)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "db_error",
			Message:    err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":   files,
		"object": "list",
	})
}

// handleGetFile serves `GET /v1/files/{file_id}` and `GET /files/{file_id}`.
func (s *GatewayServer) handleGetFile(w http.ResponseWriter, r *http.Request) {
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

	fileID := chi.URLParam(r, "file_id")
	f, err := s.repo.GetFile(r.Context(), idCtx.OrgID, fileID)
	if err != nil || f == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "file_not_found",
			Message:    fmt.Sprintf("File %s not found or not accessible", fileID),
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f)
}

// handleGetFileContent serves `GET /v1/files/{file_id}/content` and `GET /files/{file_id}/content`.
func (s *GatewayServer) handleGetFileContent(w http.ResponseWriter, r *http.Request) {
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

	fileID := chi.URLParam(r, "file_id")
	f, err := s.repo.GetFile(r.Context(), idCtx.OrgID, fileID)
	if err != nil || f == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "file_not_found",
			Message:    fmt.Sprintf("File %s not found", fileID),
		})
		return
	}

	diskFile, err := os.Open(f.StoragePath)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "read_error",
			Message:    "Failed to read file from storage: " + err.Error(),
		})
		return
	}
	defer diskFile.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", f.Filename))
	_, _ = io.Copy(w, diskFile)
}

// handleDeleteFile serves `DELETE /v1/files/{file_id}` and `DELETE /files/{file_id}`.
func (s *GatewayServer) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
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

	fileID := chi.URLParam(r, "file_id")
	f, err := s.repo.GetFile(r.Context(), idCtx.OrgID, fileID)
	if err != nil || f == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "file_not_found",
			Message:    fmt.Sprintf("File %s not found", fileID),
		})
		return
	}
	activeBatches, err := s.repo.ListBatches(r.Context(), idCtx.OrgID, 1000)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusInternalServerError, Type: domain.ErrorTypeServer, Code: "db_error", Message: "Failed to check file references"})
		return
	}
	for _, batch := range activeBatches {
		if batch.InputFileID == fileID && (batch.Status == "validating" || batch.Status == "in_progress") {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusConflict, Type: domain.ErrorTypeInvalidRequest, Code: "file_in_use", Message: "File is referenced by an active batch"})
			return
		}
	}

	if err := s.repo.DeleteFile(r.Context(), idCtx.OrgID, fileID); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "db_error",
			Message:    "Failed to delete file metadata: " + err.Error(),
		})
		return
	}
	if err := os.Remove(f.StoragePath); err != nil && !os.IsNotExist(err) {
		// Metadata deletion succeeded, so leave the file hidden and let storage
		// reconciliation remove this orphan rather than returning a false failure.
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":      fileID,
		"object":  "file",
		"deleted": true,
	})
}
