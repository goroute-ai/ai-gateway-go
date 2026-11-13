package server

import (
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

	if r.ContentLength > maxFileUploadBytes {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "file_too_large",
			Message:    fmt.Sprintf("File exceeds maximum upload limit of %d bytes", maxFileUploadBytes),
		})
		return
	}

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
