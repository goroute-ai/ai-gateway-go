package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCheckDataPlaneRouteCoverage_RepoParity(t *testing.T) {
	root := filepath.Join("..", "..")
	specBytes, err := os.ReadFile(filepath.Join(root, "docs", "openapi", "gateway.openapi.yaml"))
	if err != nil {
		t.Fatalf("read gateway.openapi.yaml: %v", err)
	}
	var doc struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(specBytes, &doc); err != nil {
		t.Fatalf("unmarshal gateway.openapi.yaml: %v", err)
	}

	serverFile := filepath.Join(root, "internal", "server", "server.go")
	if err := checkDataPlaneRouteCoverage(serverFile, doc.Paths); err != nil {
		t.Fatalf("expected /v1 and /admin/v1 route parity, got error: %v", err)
	}
}

func TestCheckRouteGroupCoverage_DetectsMissingAndStaleAdminRoutes(t *testing.T) {
	tmpDir := t.TempDir()
	serverFile := filepath.Join(tmpDir, "server.go")
	src := `package server

import "github.com/go-chi/chi/v5"

func register(r chi.Router) {
	r.Route("/v1", func(v1 chi.Router) {
		v1.Get("/models", nil)
	})
	r.Route("/admin/v1", func(adm chi.Router) {
		adm.Get("/users", nil)
		adm.Post("/users", nil)
	})
}
`
	if err := os.WriteFile(serverFile, []byte(src), 0o600); err != nil {
		t.Fatalf("write temp server.go: %v", err)
	}

	t.Run("missing registered operation", func(t *testing.T) {
		specPaths := map[string]any{
			"/v1/models": map[string]any{
				"get": map[string]any{},
			},
			"/admin/v1/users": map[string]any{
				"get": map[string]any{},
			},
		}
		err := checkDataPlaneRouteCoverage(serverFile, specPaths)
		if err == nil {
			t.Fatal("expected mismatch error for undocumented POST /admin/v1/users, got nil")
		}
		if !strings.Contains(err.Error(), "post /admin/v1/users") {
			t.Fatalf("expected missing operation post /admin/v1/users in error, got: %v", err)
		}
	})

	t.Run("stale documented operation", func(t *testing.T) {
		specPaths := map[string]any{
			"/v1/models": map[string]any{
				"get": map[string]any{},
			},
			"/admin/v1/users": map[string]any{
				"get":  map[string]any{},
				"post": map[string]any{},
			},
			"/admin/v1/ghost": map[string]any{
				"delete": map[string]any{},
			},
		}
		err := checkDataPlaneRouteCoverage(serverFile, specPaths)
		if err == nil {
			t.Fatal("expected mismatch error for stale DELETE /admin/v1/ghost, got nil")
		}
		if !strings.Contains(err.Error(), "delete /admin/v1/ghost") {
			t.Fatalf("expected stale operation delete /admin/v1/ghost in error, got: %v", err)
		}
	})
}
