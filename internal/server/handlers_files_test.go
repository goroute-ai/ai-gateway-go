package server

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func newMultipartFileRequest(t *testing.T, fieldContent []byte, chunked bool) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "sample.jsonl")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(fieldContent); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := mw.WriteField("purpose", "batch"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/files", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if chunked {
		req.ContentLength = -1
	}
	idCtx := &domain.IdentityContext{
		OrgID:        "org_file_test",
		VirtualKeyID: "vk_file_test",
		Role:         domain.RoleDeveloper,
	}
	return req.WithContext(auth.WithIdentity(req.Context(), idCtx))
}

func TestHandleUploadFile_OrgStorageQuota(t *testing.T) {
	t.Setenv("GOROUTE_FILES_DIR", t.TempDir())
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Server.MaxFileStorageBytesPerOrg = 450
	cfg.Server.MaxConcurrentFileUploads = 2

	srv, err := New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// First upload succeeds (small payload + multipart overhead <= 300 bytes).
	req1 := newMultipartFileRequest(t, []byte(`{"prompt":"hi"}`), false)
	rec1 := httptest.NewRecorder()
	srv.handleUploadFile(rec1, req1)
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first upload expected 201, got %d: %s", rec1.Code, rec1.Body.String())
	}

	var created domain.CanonicalFile
	if err := json.Unmarshal(rec1.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode first response: %v", err)
	}

	// Second upload with known Content-Length exceeding remaining quota fails with 413.
	req2 := newMultipartFileRequest(t, bytes.Repeat([]byte("a"), 450), false)
	rec2 := httptest.NewRecorder()
	srv.handleUploadFile(rec2, req2)
	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("second upload expected 413, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "storage_quota_exceeded") {
		t.Fatalf("expected storage_quota_exceeded error, got: %s", rec2.Body.String())
	}

	// Third upload with unknown Content-Length (-1) exceeding quota also fails with 413.
	req3 := newMultipartFileRequest(t, bytes.Repeat([]byte("b"), 440), true)
	rec3 := httptest.NewRecorder()
	srv.handleUploadFile(rec3, req3)
	if rec3.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked upload expected 413, got %d: %s", rec3.Code, rec3.Body.String())
	}

	files, err := repo.ListFiles(context.Background(), "org_file_test", "")
	if err != nil || len(files) != 1 || files[0].ID != created.ID {
		t.Fatalf("expected only 1 persisted file, got %+v (err=%v)", files, err)
	}
}

func TestHandleUploadFile_ConcurrencyLimit(t *testing.T) {
	t.Setenv("GOROUTE_FILES_DIR", t.TempDir())
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Server.MaxConcurrentFileUploads = 1

	srv, err := New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// Occupy the single upload slot.
	srv.uploadSem <- struct{}{}
	defer func() { <-srv.uploadSem }()

	req := newMultipartFileRequest(t, []byte(`{"prompt":"blocked"}`), false)
	rec := httptest.NewRecorder()
	srv.handleUploadFile(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when upload concurrency limit reached, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upload_concurrency_limit") {
		t.Fatalf("expected upload_concurrency_limit error, got: %s", rec.Body.String())
	}
}
