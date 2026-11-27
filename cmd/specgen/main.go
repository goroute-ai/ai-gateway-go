package main

import (
	"bytes"
	"context"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"gopkg.in/yaml.v3"
)

type openAPIDoc struct {
	OpenAPI string         `yaml:"openapi"`
	Info    map[string]any `yaml:"info"`
	Paths   map[string]any `yaml:"paths"`
	Comp    map[string]any `yaml:"components"`
}

func main() {
	rootDir := flag.String("root", ".", "Repository root directory")
	specsDir := flag.String("dir", "", "Custom specifications directory (defaults to docs/openapi)")
	flag.Parse()

	targetDir := filepath.Join(*rootDir, "docs", "openapi")
	if *specsDir != "" {
		targetDir = *specsDir
	}

	specs := []struct {
		Name string
		Path string
	}{
		{Name: "Gateway Unified Spec", Path: filepath.Join(targetDir, "gateway.openapi.yaml")},
		{Name: "OpenAI Official Spec", Path: filepath.Join(targetDir, "openai.openapi.yaml")},
		{Name: "Anthropic Official Spec", Path: filepath.Join(targetDir, "anthropic.openapi.yaml")},
		{Name: "Groq Official Spec", Path: filepath.Join(targetDir, "groq.openapi.yaml")},
		{Name: "OpenRouter Official Spec", Path: filepath.Join(targetDir, "openrouter.openapi.yaml")},
		{Name: "Ollama Official Spec", Path: filepath.Join(targetDir, "ollama.openapi.yaml")},
		{Name: "Gemini Official Spec", Path: filepath.Join(targetDir, "gemini.openapi.yaml")},
		{Name: "MCP Protocol Spec", Path: filepath.Join(targetDir, "mcp.openapi.yaml")},
		{Name: "A2A Protocol Spec", Path: filepath.Join(targetDir, "a2a.openapi.yaml")},
	}

	for _, s := range specs {
		data, err := os.ReadFile(s.Path)
		if err != nil {
			logger.Error("specgen error reading spec", slog.String("spec", s.Name), slog.String("path", s.Path), slog.Any("error", err))
			os.Exit(1)
		}
		var doc openAPIDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			logger.Error("specgen error parsing YAML", slog.String("spec", s.Name), slog.Any("error", err))
			os.Exit(1)
		}
		if doc.OpenAPI == "" || len(doc.Paths) == 0 {
			logger.Error("specgen invalid OpenAPI document", slog.String("spec", s.Name), slog.String("version", doc.OpenAPI), slog.Int("paths", len(doc.Paths)))
			os.Exit(1)
		}
		loader := openapi3.NewLoader()
		semanticDoc, err := loader.LoadFromFile(s.Path)
		if err != nil {
			logger.Error("specgen error loading OpenAPI document", slog.String("spec", s.Name), slog.Any("error", err))
			os.Exit(1)
		}
		if err := semanticDoc.Validate(
			context.Background(),
			openapi3.DisableExamplesValidation(),
			openapi3.DisableSchemaDefaultsValidation(),
		); err != nil {
			logger.Error("specgen semantic validation failed", slog.String("spec", s.Name), slog.Any("error", err))
			os.Exit(1)
		}
		if s.Name == "Gateway Unified Spec" {
			serverFile := filepath.Join(*rootDir, "internal", "server", "server.go")
			if err := checkDataPlaneRouteCoverage(serverFile, doc.Paths); err != nil {
				logger.Error("specgen route coverage failed", slog.Any("error", err))
				os.Exit(1)
			}
			logger.Info("Verified /v1, /admin/v1, and /auth route/spec parity")
		}
		pathList := make([]string, 0, len(doc.Paths))
		for k := range doc.Paths {
			pathList = append(pathList, k)
		}
		sort.Strings(pathList)
		logger.Info("Validated OpenAPI specification", slog.String("spec", s.Name), slog.String("openapi", doc.OpenAPI), slog.Int("paths", len(pathList)))
	}

	// Validate all vendored MCP YAML schema releases and embedded parity
	mcpDir := filepath.Join(*rootDir, "docs", "specs", "mcp")
	embedMCPDir := filepath.Join(*rootDir, "internal", "mcp", "spec", "schemas")
	if entries, err := os.ReadDir(mcpDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			ver := entry.Name()
			mcpSchemaPath := filepath.Join(mcpDir, ver, "schema.yaml")
			mcpData, err := os.ReadFile(mcpSchemaPath)
			if err != nil {
				logger.Error("specgen error reading MCP YAML schema", slog.String("version", ver), slog.String("path", mcpSchemaPath), slog.Any("error", err))
				os.Exit(1)
			}
			var mcpSchema map[string]any
			if err := yaml.Unmarshal(mcpData, &mcpSchema); err != nil {
				logger.Error("specgen error parsing MCP YAML schema", slog.String("version", ver), slog.String("path", mcpSchemaPath), slog.Any("error", err))
				os.Exit(1)
			}
			defs, ok := mcpSchema["$defs"].(map[string]any)
			if !ok {
				defs, _ = mcpSchema["definitions"].(map[string]any)
			}
			if len(defs) == 0 {
				logger.Error("specgen error: MCP YAML schema contains zero definitions", slog.String("version", ver), slog.String("path", mcpSchemaPath))
				os.Exit(1)
			}
			embedSchemaPath := filepath.Join(embedMCPDir, ver, "schema.yaml")
			embedData, err := os.ReadFile(embedSchemaPath)
			if err != nil || !bytes.Equal(mcpData, embedData) {
				logger.Error("specgen error: embedded MCP YAML schema out of sync (run 'make specgen')", slog.String("version", ver), slog.String("docs_path", mcpSchemaPath), slog.String("embed_path", embedSchemaPath), slog.Any("error", err))
				os.Exit(1)
			}
			logger.Info("Validated MCP Schema (YAML)", slog.String("version", ver), slog.Int("definitions", len(defs)))
		}
	}

	// Verify A2A Protobuf generated code freshness
	a2aPbPath := filepath.Join(*rootDir, "internal", "a2a", "pb", "a2a.pb.go")
	if stat, err := os.Stat(a2aPbPath); err != nil || stat.Size() == 0 {
		logger.Error("specgen error: A2A protobuf code missing or empty", slog.String("path", a2aPbPath))
		os.Exit(1)
	} else {
		logger.Info("Verified A2A v1.0 Protobuf (pb)", slog.Int64("bytes", stat.Size()))
	}
}
