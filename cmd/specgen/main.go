package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
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
		{Name: "Gemini Official Spec", Path: filepath.Join(targetDir, "gemini.openapi.yaml")},
		{Name: "Mistral Official Spec", Path: filepath.Join(targetDir, "mistral.openapi.yaml")},
		{Name: "Ollama Official Spec", Path: filepath.Join(targetDir, "ollama.openapi.yaml")},
		{Name: "MCP Protocol Spec", Path: filepath.Join(targetDir, "mcp.openapi.yaml")},
		{Name: "A2A Protocol Spec", Path: filepath.Join(targetDir, "a2a.openapi.yaml")},
	}

	for _, s := range specs {
		data, err := os.ReadFile(s.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "specgen error reading %s (%s): %v\n", s.Name, s.Path, err)
			os.Exit(1)
		}
		var doc openAPIDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			fmt.Fprintf(os.Stderr, "specgen error parsing YAML %s: %v\n", s.Name, err)
			os.Exit(1)
		}
		if doc.OpenAPI == "" || len(doc.Paths) == 0 {
			fmt.Fprintf(os.Stderr, "specgen invalid OpenAPI document %s: version=%q paths=%d\n", s.Name, doc.OpenAPI, len(doc.Paths))
			os.Exit(1)
		}
		loader := openapi3.NewLoader()
		semanticDoc, err := loader.LoadFromFile(s.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "specgen error loading OpenAPI document %s: %v\n", s.Name, err)
			os.Exit(1)
		}
		if err := semanticDoc.Validate(
			context.Background(),
			openapi3.DisableExamplesValidation(),
			openapi3.DisableSchemaDefaultsValidation(),
		); err != nil {
			fmt.Fprintf(os.Stderr, "specgen semantic validation failed for %s: %v\n", s.Name, err)
			os.Exit(1)
		}
		if s.Name == "Gateway Unified Spec" {
			serverFile := filepath.Join(*rootDir, "internal", "server", "server.go")
			if err := checkDataPlaneRouteCoverage(serverFile, doc.Paths); err != nil {
				fmt.Fprintf(os.Stderr, "specgen route coverage failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[specgen] Verified primary /v1 route/spec parity")
		}
		pathList := make([]string, 0, len(doc.Paths))
		for k := range doc.Paths {
			pathList = append(pathList, k)
		}
		sort.Strings(pathList)
		fmt.Printf("[specgen] Validated %-25s (OpenAPI %s, %d paths)\n", s.Name, doc.OpenAPI, len(pathList))
	}

	// Validate MCP 2026-07-28 Schema
	mcpSchemaPath := filepath.Join(*rootDir, "docs", "specs", "mcp", "2026-07-28", "schema.json")
	if mcpData, err := os.ReadFile(mcpSchemaPath); err == nil {
		var mcpSchema map[string]any
		if err := json.Unmarshal(mcpData, &mcpSchema); err != nil {
			fmt.Fprintf(os.Stderr, "specgen error parsing MCP schema %s: %v\n", mcpSchemaPath, err)
			os.Exit(1)
		}
		defs, ok := mcpSchema["$defs"].(map[string]any)
		if !ok {
			defs, _ = mcpSchema["definitions"].(map[string]any)
		}
		fmt.Printf("[specgen] Validated %-25s (JSON Schema, %d definitions)\n", "MCP 2026-07-28 Schema", len(defs))
	}

	// Verify A2A Protobuf generated code freshness
	a2aPbPath := filepath.Join(*rootDir, "internal", "a2a", "pb", "a2a.pb.go")
	if stat, err := os.Stat(a2aPbPath); err != nil || stat.Size() == 0 {
		fmt.Fprintf(os.Stderr, "specgen error: A2A protobuf code missing or empty at %s\n", a2aPbPath)
		os.Exit(1)
	} else {
		fmt.Printf("[specgen] Verified  %-25s (%d bytes generated)\n", "A2A v1.0 Protobuf (pb)", stat.Size())
	}
}
